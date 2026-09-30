//! Evidence abstraction and collection.
//!
//! [`Evidence`] describes one input unit (a file or stdin). Directory
//! traversal is bounded and defensive: recursion depth is capped, symlinks
//! that escape the evidence root are skipped with a warning, and oversized
//! files are rejected before being read.

use crate::errors::{Error, Result};
use std::path::{Path, PathBuf};

/// Hard caps. These exist because log input is untrusted.
pub const MAX_LINE_BYTES: usize = 1024 * 1024; // 1 MiB per line
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB per file
pub const MAX_RECURSION_DEPTH: usize = 8;
pub const MAX_FILES_PER_RUN: usize = 10_000;

/// One unit of evidence to be parsed.
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Canonical display path, or "<stdin>".
    pub path: PathBuf,
    /// Display label used in provenance and reports.
    pub label: String,
    /// Kind hint for parser selection.
    pub kind: EvidenceKind,
    /// True for stdin.
    pub is_stdin: bool,
}

/// Coarse hint about what an evidence unit probably is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// Explicit stdin stream.
    Stdin,
    /// Name suggests an authentication log (e.g. auth.log, secure).
    AuthLog,
    /// Name suggests a kernel log (e.g. kern.log, dmesg).
    KernelLog,
    /// Name suggests syslog-style (e.g. syslog, messages).
    Syslog,
    /// Extension suggests JSON / JSONL.
    Json,
    JsonLines,
    /// Anything else; parser registry falls back to content sniffing.
    Unknown,
}

impl EvidenceKind {
    /// Guess from the file name only. Never trusted blindly: parsers
    /// re-verify by content.
    pub fn guess_from_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.contains("auth") || lower == "secure" {
            EvidenceKind::AuthLog
        } else if lower.contains("kern") || lower.contains("dmesg") {
            EvidenceKind::KernelLog
        } else if lower.contains("syslog") || lower == "messages" {
            EvidenceKind::Syslog
        } else if lower.ends_with(".jsonl") || lower.ends_with(".ndjson") {
            EvidenceKind::JsonLines
        } else if lower.ends_with(".json") {
            EvidenceKind::Json
        } else {
            EvidenceKind::Unknown
        }
    }
}

/// Collect evidence units from a CLI input path.
///
/// `input` may be a file, a directory (scanned recursively within limits),
/// or "-" for stdin.
pub fn collect(input: &str, root_label: &str) -> Result<Vec<Evidence>> {
    if input == "-" {
        return Ok(vec![Evidence {
            path: PathBuf::from("<stdin>"),
            label: "<stdin>".to_string(),
            kind: EvidenceKind::Stdin,
            is_stdin: true,
        }]);
    }

    let path = Path::new(input);
    if !path.exists() {
        return Err(Error::Evidence(format!("no such file or directory: {input}")));
    }

    let mut out = Vec::new();
    if path.is_file() {
        out.push(evidence_for_file(path)?);
    } else if path.is_dir() {
        let root = canonicalize(path)?;
        scan_dir(&root, &root, 0, &mut out)?;
        out.sort_by(|a, b| a.path.cmp(&b.path));
        if out.is_empty() {
            return Err(Error::Evidence(format!(
                "no readable evidence files found under {root_label}"
            )));
        }
    } else {
        return Err(Error::Evidence(format!(
            "not a file, directory, or '-': {input}"
        )));
    }

    if out.len() > MAX_FILES_PER_RUN {
        return Err(Error::Evidence(format!(
            "too many evidence files ({}), limit is {}",
            out.len(),
            MAX_FILES_PER_RUN
        )));
    }
    Ok(out)
}

fn evidence_for_file(path: &Path) -> Result<Evidence> {
    let meta = std::fs::metadata(path).map_err(|e| classify_read_error(path, e))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(Error::FileTooLarge {
            path: path.display().to_string(),
            size: meta.len(),
            limit: MAX_FILE_BYTES,
        });
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let canonical = canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    Ok(Evidence {
        path: canonical.clone(),
        label: canonical.display().to_string(),
        kind: EvidenceKind::guess_from_name(&name),
        is_stdin: false,
    })
}

/// Recursively scan `dir`, anchored at `root`. Symlinks are resolved with
/// [`std::fs::canonicalize`]; anything resolving outside `root` is skipped.
fn scan_dir(root: &Path, dir: &Path, depth: usize, out: &mut Vec<Evidence>) -> Result<()> {
    if depth > MAX_RECURSION_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|e| classify_read_error(dir, e))?;
    let mut names: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    names.sort();

    for path in names {
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            match canonicalize(&path) {
                Ok(target) if target.starts_with(root) && target.is_file() => {
                    match evidence_for_file(&target) {
                        Ok(ev) => out.push(ev),
                        Err(e) => eprintln!("warning: {e}"),
                    }
                }
                Ok(_) => eprintln!(
                    "warning: skipping symlink escaping the evidence root: {}",
                    path.display()
                ),
                Err(e) => eprintln!("warning: skipping dangling symlink {}: {e}", path.display()),
            }
            continue;
        }
        if meta.is_dir() {
            if let Err(e) = scan_dir(root, &path, depth + 1, out) {
                eprintln!("warning: {e}");
            }
        } else if meta.is_file() {
            match evidence_for_file(&path) {
                Ok(ev) => out.push(ev),
                Err(e) => eprintln!("warning: {e}"),
            }
        }
        if out.len() >= MAX_FILES_PER_RUN {
            return Err(Error::Evidence(format!(
                "too many evidence files, limit is {MAX_FILES_PER_RUN}"
            )));
        }
    }
    Ok(())
}

fn canonicalize(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| classify_read_error(path, e))
}

fn classify_read_error(path: &Path, e: std::io::Error) -> Error {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::PermissionDenied => Error::PermissionDenied {
            path: path.display().to_string(),
        },
        ErrorKind::NotFound => Error::UnreadableFile {
            path: path.display().to_string(),
            reason: "not found".to_string(),
        },
        _ => Error::UnreadableFile {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    }
}

/// Read the content of an evidence unit as text.
///
/// Lines longer than [`MAX_LINE_BYTES`] are skipped and counted; the
/// caller passes a counter to record them. Binary-looking content is
/// handled lossily: invalid UTF-8 sequences are replaced, never fatal.
pub fn read_text(evidence: &Evidence, too_long: &mut u64) -> Result<Vec<String>> {
    let bytes = if evidence.is_stdin {
        let mut buf = Vec::new();
        use std::io::Read;
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(Error::Io)?;
        buf
    } else {
        std::fs::read(&evidence.path).map_err(|e| classify_read_error(&evidence.path, e))?
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            *too_long += 1;
            continue;
        }
        lines.push(line.to_string());
    }
    Ok(lines)
}

/// Statistics gathered while parsing one evidence unit.
#[derive(Debug, Default, Clone)]
pub struct ParseStats {
    pub lines: u64,
    pub events: u64,
    pub skipped_unsupported: u64,
    pub skipped_bad_timestamp: u64,
    pub skipped_incomplete: u64,
    pub skipped_too_long: u64,
}

impl ParseStats {
    pub fn skipped_total(&self) -> u64 {
        self.skipped_unsupported
            + self.skipped_bad_timestamp
            + self.skipped_incomplete
            + self.skipped_too_long
    }
}

/// Why a line produced no event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    UnsupportedFormat,
    MalformedTimestamp,
    IncompleteRecord,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_guess_from_name_prefers_auth_over_generic() {
        assert_eq!(
            EvidenceKind::guess_from_name("auth.log"),
            EvidenceKind::AuthLog
        );
        assert_eq!(
            EvidenceKind::guess_from_name("syslog"),
            EvidenceKind::Syslog
        );
        assert_eq!(EvidenceKind::guess_from_name("app.jsonl"), EvidenceKind::JsonLines);
        assert_eq!(EvidenceKind::guess_from_name("notes.txt"), EvidenceKind::Unknown);
    }

    #[test]
    fn collect_rejects_missing_path() {
        let r = collect("/definitely/not/here-xyz", "x");
        assert!(matches!(r, Err(Error::Evidence(_))));
    }

    #[test]
    fn collect_accepts_stdin_marker() {
        let ev = collect("-", "-").unwrap();
        assert_eq!(ev.len(), 1);
        assert!(ev[0].is_stdin);
    }
}
