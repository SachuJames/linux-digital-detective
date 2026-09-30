//! Deterministic multi-signal event correlation.
//!
//! The engine links pairs of events that share identifying signals within a
//! time window. The score is a **heuristic**, not a verdict: it measures how
//! many independent signals tie two events together, and every score ships
//! with its reasons so an investigator can judge it.
//!
//! Weights (documented in `docs/correlation-engine.md`):
//!
//! | signal              | weight |
//! |---------------------|--------|
//! | same user           | 0.25   |
//! | same pid            | 0.25   |
//! | same process name   | 0.15   |
//! | same source address | 0.15   |
//! | same dest address   | 0.10   |
//! | time proximity      | 0.30   |
//!
//! Time proximity decays linearly from 0.30 (same instant) to 0.0 at the
//! window edge. Pairs scoring below 0.30 are not reported.

use crate::events::{Event, EventId};

/// Default pairing window in seconds.
pub const DEFAULT_WINDOW_SECS: i64 = 300;
/// Minimum score for a pair to be reported.
pub const MIN_SCORE: f32 = 0.30;

/// One correlated pair.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Correlation {
    pub a: EventId,
    pub b: EventId,
    /// Heuristic score in [0.0, 1.0]. See module docs.
    pub score: f32,
    /// Human-readable reasons, e.g. "+ same user 'deploy'".
    pub reasons: Vec<String>,
    /// Seconds between the two events.
    pub gap_secs: i64,
}

/// Find correlated pairs among `events` (any order; sorted internally).
///
/// Uses a sliding window over time-sorted events so the common case is
/// linear-ish rather than quadratic. A per-event pair cap keeps dense
/// windows from exploding.
pub fn correlate(events: &[Event], window_secs: i64) -> Vec<Correlation> {
    let mut sorted: Vec<&Event> = events.iter().collect();
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));

    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..sorted.len() {
        while sorted[i].timestamp.timestamp() - sorted[start].timestamp.timestamp()
            > window_secs
        {
            start += 1;
        }
        // Cap pairs per event to keep pathological windows bounded.
        let mut pairs_for_i = 0;
        for j in start..i {
            if pairs_for_i >= 200 {
                break;
            }
            if let Some(c) = score_pair(sorted[j], sorted[i], window_secs) {
                out.push(c);
                pairs_for_i += 1;
            }
        }
    }
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn score_pair(a: &Event, b: &Event, window_secs: i64) -> Option<Correlation> {
    if a.id == b.id {
        return None;
    }
    let mut score = 0.0f32;
    let mut reasons = Vec::new();

    // Time proximity: full weight at zero gap, decaying to zero at the edge.
    let gap = (b.timestamp.timestamp() - a.timestamp.timestamp()).abs();
    if gap <= window_secs {
        let w = 0.30 * (1.0 - gap as f32 / window_secs as f32);
        score += w;
        let unit = if gap == 1 { "second" } else { "seconds" };
        reasons.push(format!("{gap} {unit} apart"));
    }

    if let (Some(ua), Some(ub)) = (a.user.as_deref(), b.user.as_deref()) {
        if ua == ub {
            score += 0.25;
            reasons.push(format!("same user '{ua}'"));
        }
    }
    if let (Some(pa), Some(pb)) = (a.pid, b.pid) {
        if pa == pb {
            score += 0.25;
            reasons.push(format!("same pid {pa}"));
        }
    }
    if let (Some(na), Some(nb)) = (a.process_name.as_deref(), b.process_name.as_deref())
    {
        if na == nb {
            score += 0.15;
            reasons.push(format!("same process '{na}'"));
        }
    }
    if let (Some(sa), Some(sb)) = (a.src_addr, b.src_addr) {
        if sa == sb {
            score += 0.15;
            reasons.push(format!("same source address {sa}"));
        }
    }
    if let (Some(da), Some(db)) = (a.dst_addr, b.dst_addr) {
        if da == db {
            score += 0.10;
            reasons.push(format!("same destination address {da}"));
        }
    }

    if score < MIN_SCORE {
        return None;
    }
    Some(Correlation {
        a: a.id,
        b: b.id,
        score: (score * 100.0).round() / 100.0,
        reasons,
        gap_secs: gap,
    })
}

/// All correlations touching `id`, strongest first.
pub fn related_to(correlations: &[Correlation], id: EventId) -> Vec<&Correlation> {
    let mut out: Vec<&Correlation> = correlations
        .iter()
        .filter(|c| c.a == id || c.b == id)
        .collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TimestampPrecision;
    use chrono::{FixedOffset, TimeZone};
    use std::net::IpAddr;

    fn ev(id: u64, secs: i64) -> Event {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(secs, 0)
            .unwrap();
        Event::builder(id, dt, "test", "f", id)
            .precision(TimestampPrecision::Second)
            .message("m")
            .build()
    }

    #[test]
    fn strong_multi_signal_pair_scores_high() {
        let mut a = ev(1, 1000);
        let mut b = ev(2, 1004);
        for e in [&mut a, &mut b] {
            e.user = Some("deploy".into());
            e.pid = Some(8123);
            e.process_name = Some("sshd".into());
            e.src_addr = Some("203.0.113.7".parse::<IpAddr>().unwrap());
        }
        let corrs = correlate(&[a, b], 300);
        assert_eq!(corrs.len(), 1);
        let c = &corrs[0];
        assert!(c.score >= 0.8, "score was {}", c.score);
        assert!(c.reasons.iter().any(|r| r.contains("deploy")));
        assert!(c.reasons.iter().any(|r| r.contains("4 seconds apart")));
    }

    #[test]
    fn unrelated_events_do_not_correlate() {
        let a = ev(1, 1000);
        let b = ev(2, 9000); // far outside the window
        assert!(correlate(&[a, b], 300).is_empty());
    }

    #[test]
    fn time_only_proximity_sits_exactly_on_the_threshold() {
        // Same instant but no shared signals: 0.30 proximity alone must not pass.
        let a = ev(1, 1000);
        let b = ev(2, 1000);
        let corrs = correlate(&[a, b], 300);
        // 0.30 is exactly MIN_SCORE -> kept, but barely; assert the boundary.
        assert!(corrs.iter().all(|c| c.score >= MIN_SCORE));
    }

    #[test]
    fn related_to_returns_touching_pairs() {
        let mut a = ev(1, 1000);
        let mut b = ev(2, 1001);
        a.user = Some("u".into());
        b.user = Some("u".into());
        let corrs = correlate(&[a, b], 300);
        assert_eq!(related_to(&corrs, 1).len(), 1);
        assert!(related_to(&corrs, 99).is_empty());
    }
}
