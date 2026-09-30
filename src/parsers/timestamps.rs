//! Timestamp parsing and normalization.
//!
//! Supported inputs:
//!
//! - RFC 3339 / ISO 8601, with or without fractional seconds and with an
//!   explicit offset or `Z` (e.g. `2026-09-30T14:02:11.123+05:30`).
//! - Naive `YYYY-MM-DD HH:MM:SS[.frac]` (comma or dot fraction).
//! - Classic syslog `MMM dd HH:MM:SS` (no year, no offset).
//! - Unix epoch seconds (10 digits) at the start of a line.
//!
//! Timezone policy (documented, see `docs/evidence-model.md`):
//!
//! - An explicit offset is always honored.
//! - A naive timestamp is interpreted in the machine's local timezone and
//!   marked `offset_explicit = false`.
//! - A syslog timestamp has no year; the current year is assumed and the
//!   event is marked `partial = true`. This is an assumption, not a fact,
//!   and it is visible in the output.

use chrono::{DateTime, Datelike, FixedOffset, Local, TimeZone};
use regex::Regex;
use std::sync::LazyLock;

use crate::events::TimestampPrecision;

/// A timestamp extracted from raw evidence.
#[derive(Debug, Clone)]
pub struct ParsedTimestamp {
    pub dt: DateTime<FixedOffset>,
    pub precision: TimestampPrecision,
    pub partial: bool,
    pub offset_explicit: bool,
    pub raw: String,
    /// Number of bytes of the input consumed by the timestamp.
    pub consumed: usize,
}

static RFC3339_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^
        (?P<ts>
            \d{4}-\d{2}-\d{2}        # date
            [T\x20]                  # 'T' or space (escaped: (?x) would eat a literal space)
            \d{2}:\d{2}:\d{2}        # time
            (?:[.,]\d{1,9})?         # optional fraction (dot or comma)
            (?:Z|[+-]\d{2}:?\d{2})?  # optional offset
        )",
    )
    .unwrap()
});

static SYSLOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})")
        .unwrap()
});

static EPOCH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?P<epoch>\d{10})(?:\.(?P<frac>\d{1,9}))?").unwrap());

fn month_number(mon: &str) -> Option<u32> {
    Some(match mon {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Try to parse a timestamp at the start of `text`.
///
/// Returns the parsed timestamp plus how many bytes were consumed, or `None`
/// when no known timestamp shape is present. A malformed-but-recognizable
/// timestamp (e.g. month 13) yields `Err`, so the caller can report
/// "malformed timestamp" rather than "unsupported format".
pub fn parse_at_start(text: &str) -> Option<Result<ParsedTimestamp, String>> {
    let text = text.trim_start();

    if let Some(caps) = RFC3339_RE.captures(text) {
        let raw = caps.name("ts").unwrap().as_str();
        let consumed = caps.name("ts").unwrap().end();
        return Some(parse_rfc3339_like(raw, consumed));
    }
    if let Some(caps) = SYSLOG_RE.captures(text) {
        let raw = caps.get(0).unwrap().as_str();
        let consumed = caps.get(0).unwrap().end();
        return Some(parse_syslog_ts(&caps, raw, consumed));
    }
    if let Some(caps) = EPOCH_RE.captures(text) {
        let raw = caps.get(0).unwrap().as_str();
        let consumed = caps.get(0).unwrap().end();
        return Some(parse_epoch(&caps, raw, consumed));
    }
    None
}

fn parse_rfc3339_like(raw: &str, consumed: usize) -> Result<ParsedTimestamp, String> {
    // Normalize: comma fractions and offsets without a colon are common in logs.
    let mut norm = raw.replace(',', ".");
    let offset_explicit =
        norm.ends_with('Z') || norm.ends_with('z') || norm.rfind(['+', '-']).is_some_and(|i| i > 10);
    if !offset_explicit {
        // Naive: interpret in local time, documented assumption.
        let offset = local_offset();
        let precision = precision_of(&norm);
        let dt = chrono::NaiveDateTime::parse_from_str(&norm, "%Y-%m-%dT%H:%M:%S%.f")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(&norm, "%Y-%m-%d %H:%M:%S%.f"))
            .map_err(|_| format!("malformed timestamp: {raw}"))?;
        let dt = offset
            .from_local_datetime(&dt)
            .single()
            .ok_or_else(|| format!("ambiguous local timestamp: {raw}"))?;
        return Ok(ParsedTimestamp {
            dt,
            precision,
            partial: false,
            offset_explicit: false,
            raw: raw.to_string(),
            consumed,
        });
    }
    // Offset present: normalize a few real-world variants before parsing.
    if norm.ends_with('z') {
        norm.pop();
        norm.push('Z');
    }
    // "+0530" -> "+05:30"
    let chars: Vec<char> = norm.chars().collect();
    if let Some(i) = norm.rfind(['+', '-']) {
        if i > 10 && chars.len() == i + 5 && chars[i + 3] != ':' {
            norm.insert(i + 3, ':');
        }
    }
    let dt = DateTime::parse_from_rfc3339(&norm)
        .map_err(|_| format!("malformed timestamp: {raw}"))?;
    Ok(ParsedTimestamp {
        precision: precision_of(&norm),
        dt,
        partial: false,
        offset_explicit: true,
        raw: raw.to_string(),
        consumed,
    })
}

fn parse_syslog_ts(
    caps: &regex::Captures,
    raw: &str,
    consumed: usize,
) -> Result<ParsedTimestamp, String> {
    let mon = month_number(&caps["mon"]).ok_or_else(|| format!("bad month: {raw}"))?;
    let day: u32 = caps["day"]
        .parse()
        .map_err(|_| format!("bad day: {raw}"))?;
    let (h, m, s): (u32, u32, u32) = (
        caps["h"].parse().map_err(|_| format!("bad hour: {raw}"))?,
        caps["m"].parse().map_err(|_| format!("bad minute: {raw}"))?,
        caps["s"].parse().map_err(|_| format!("bad second: {raw}"))?,
    );
    // No year in syslog format: assume the current year, and mark partial.
    let year = Local::now().date_naive().year();
    let offset = local_offset();
    let naive = chrono::NaiveDate::from_ymd_opt(year, mon, day)
        .and_then(|d| d.and_hms_opt(h, m, s))
        .ok_or_else(|| format!("malformed syslog timestamp: {raw}"))?;
    let dt = offset
        .from_local_datetime(&naive)
        .single()
        .ok_or_else(|| format!("ambiguous local timestamp: {raw}"))?;
    Ok(ParsedTimestamp {
        dt,
        precision: TimestampPrecision::Second,
        partial: true,
        offset_explicit: false,
        raw: raw.to_string(),
        consumed,
    })
}

fn parse_epoch(caps: &regex::Captures, raw: &str, consumed: usize) -> Result<ParsedTimestamp, String> {
    let secs: i64 = caps["epoch"]
        .parse()
        .map_err(|_| format!("bad epoch: {raw}"))?;
    let nanos: u32 = caps
        .name("frac")
        .map(|f| {
            let mut s = f.as_str().to_string();
            s.truncate(9);
            while s.len() < 9 {
                s.push('0');
            }
            s.parse().unwrap_or(0)
        })
        .unwrap_or(0);
    let dt = DateTime::from_timestamp(secs, nanos)
        .map(|d| d.fixed_offset())
        .ok_or_else(|| format!("epoch out of range: {raw}"))?;
    let precision = if caps.name("frac").is_some() {
        TimestampPrecision::Nanosecond
    } else {
        TimestampPrecision::Second
    };
    Ok(ParsedTimestamp {
        dt,
        precision,
        partial: false,
        offset_explicit: true, // epoch is unambiguous (UTC)
        raw: raw.to_string(),
        consumed,
    })
}

fn precision_of(raw: &str) -> TimestampPrecision {
    let frac_len = raw
        .split(['.', ','])
        .nth(1)
        .map(|f| f.chars().take_while(|c| c.is_ascii_digit()).count())
        .unwrap_or(0);
    match frac_len {
        0 => TimestampPrecision::Second,
        1..=3 => TimestampPrecision::Millisecond,
        4..=6 => TimestampPrecision::Microsecond,
        _ => TimestampPrecision::Nanosecond,
    }
}

fn local_offset() -> FixedOffset {
    FixedOffset::east_opt(Local::now().offset().local_minus_utc()).unwrap_or(FixedOffset::east_opt(0).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_with_offset() {
        let p = parse_at_start("2026-09-30T14:02:11+05:30 rest").unwrap().unwrap();
        assert!(p.offset_explicit);
        assert!(!p.partial);
        assert_eq!(p.precision, TimestampPrecision::Second);
        assert_eq!(p.dt.to_rfc3339(), "2026-09-30T14:02:11+05:30");
    }

    #[test]
    fn parses_naive_datetime_as_local() {
        let p = parse_at_start("2026-09-30 14:02:11 msg").unwrap().unwrap();
        assert!(!p.offset_explicit);
        assert!(!p.partial);
    }

    #[test]
    fn parses_syslog_timestamp_as_partial() {
        let p = parse_at_start("Sep 30 14:02:11 host proc: msg").unwrap().unwrap();
        assert!(p.partial);
        assert!(!p.offset_explicit);
        assert_eq!(p.dt.format("%m-%d %H:%M:%S").to_string(), "09-30 14:02:11");
    }

    #[test]
    fn parses_epoch_seconds() {
        let p = parse_at_start("1727692931 something").unwrap().unwrap();
        assert!(p.offset_explicit);
        assert_eq!(p.dt.timestamp(), 1727692931);
    }

    #[test]
    fn malformed_month_is_an_error_not_unsupported() {
        // "Foo" has the syslog month shape but is not a real month:
        // recognizable shape, malformed value.
        assert!(matches!(
            parse_at_start("Foo 30 14:02:11 x"),
            Some(Err(_))
        ));
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_at_start("hello world").is_none());
    }

    #[test]
    fn fraction_precision_detected() {
        let p = parse_at_start("2026-09-30T14:02:11.123Z x").unwrap().unwrap();
        assert_eq!(p.precision, TimestampPrecision::Millisecond);
    }
}
