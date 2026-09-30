//! Read-only Linux introspection helpers.
//!
//! Everything here only *reads*. When an interface needs privileges the
//! process does not have, the helpers return a descriptive error instead
//! of attempting any form of escalation.

use crate::errors::{Error, Result};

/// Read a small proc/sys file as a string.
///
/// Fails safely with [`Error::PermissionDenied`] or
/// [`Error::LinuxInterface`] rather than escalating.
pub fn read_proc_file(path: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied {
            path: path.to_string(),
        },
        std::io::ErrorKind::NotFound => {
            Error::LinuxInterface(format!("{path} not present"))
        }
        _ => Error::UnreadableFile {
            path: path.to_string(),
            reason: e.to_string(),
        },
    })
}

/// Best-effort hostname for live-collected events.
pub fn hostname() -> Option<String> {
    read_proc_file("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True when running with uid 0.
pub fn is_root() -> bool {
    // No libc dependency: read it from /proc/self/status.
    read_proc_file("/proc/self/status").ok().is_some_and(|s| {
        s.lines().any(|l| {
            l.starts_with("Uid:")
                && l.split_whitespace().nth(1).is_some_and(|uid| uid == "0")
        })
    })
}

/// Strip ANSI escape sequences and control characters from text that will
/// be printed to the terminal. Log content is untrusted; a malicious line
/// must not be able to repaint the user's terminal.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume CSI sequences: ESC [ ... final byte (@-~).
            if chars.peek() == Some(&'[') {
                chars.next();
                for c2 in chars.by_ref() {
                    if ('@'..='~').contains(&c2) {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_self_is_readable() {
        // /proc/self/status is readable by any user on a normal system.
        let r = read_proc_file("/proc/self/status");
        assert!(
            r.is_ok(),
            "expected /proc/self/status to be readable: {r:?}"
        );
    }

    #[test]
    fn missing_proc_file_reports_interface_not_io() {
        let r = read_proc_file("/proc/definitely-not-here-xyz");
        assert!(matches!(r, Err(Error::LinuxInterface(_))));
    }

    #[test]
    fn sanitize_strips_csi_sequences() {
        let evil = "ok\x1b[2J\x1b[31mred\x1b[0m done\x07";
        assert_eq!(sanitize_for_terminal(evil), "okred done");
    }

    #[test]
    fn sanitize_keeps_newlines_and_tabs() {
        assert_eq!(sanitize_for_terminal("a\nb\tc"), "a\nb\tc");
    }
}
