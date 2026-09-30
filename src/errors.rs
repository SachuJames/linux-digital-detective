//! Error types for linux-digital-detective.
//!
//! Errors are explicit and actionable. Each variant carries enough context
//! for the CLI layer to render a helpful message and pick an exit code.

use thiserror::Error;

/// Top-level error type used across the application.
#[derive(Debug, Error)]
pub enum Error {
    /// The user asked for something unsupported (bad flag, bad value).
    #[error("usage error: {0}")]
    Usage(String),

    /// The evidence could not be used (missing, empty, unreadable, malformed).
    #[error("evidence error: {0}")]
    Evidence(String),

    /// A file could not be read at all.
    #[error("could not read {path}: {reason}")]
    UnreadableFile { path: String, reason: String },

    /// Read access was denied; fail safely with a hint instead of escalating.
    #[error("permission denied reading {path}; read access is required (the tool never escalates privileges itself)")]
    PermissionDenied { path: String },

    /// A file exceeded the configured size cap.
    #[error("file too large ({size} bytes, limit is {limit} bytes): {path}")]
    FileTooLarge { path: String, size: u64, limit: u64 },

    /// A single line exceeded the configured line-length cap.
    #[error("line too long (over {limit} bytes), skipped: {path} line {line}")]
    LineTooLong {
        path: String,
        line: u64,
        limit: usize,
    },

    /// Configuration file problems.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An operation needs privileges the process does not have.
    #[error("privileged operation unavailable: {0}")]
    Privilege(String),

    /// The Linux interface needed is not present on this machine.
    #[error("linux interface unavailable: {0}")]
    LinuxInterface(String),

    /// I/O errors we did not classify more specifically.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON deserialization errors.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Process exit codes used by the CLI.
///
/// - `0`: the command completed successfully (findings are not failures).
/// - `1`: reserved for unexpected internal failures.
/// - `2`: usage or configuration error.
/// - `3`: evidence error (unreadable input, no parseable evidence, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    Internal = 1,
    Usage = 2,
    Evidence = 3,
}

impl From<Error> for ExitCode {
    fn from(err: Error) -> Self {
        match err {
            Error::Usage(_) | Error::Config(_) => ExitCode::Usage,
            Error::Evidence(_)
            | Error::UnreadableFile { .. }
            | Error::PermissionDenied { .. }
            | Error::FileTooLarge { .. } => ExitCode::Evidence,
            // Line-too-long and transient I/O are reported but do not fail the run;
            // they surface as skipped-line statistics instead.
            Error::LineTooLong { .. } | Error::Io(_) | Error::Json(_) => ExitCode::Internal,
            Error::Privilege(_) | Error::LinuxInterface(_) => ExitCode::Evidence,
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
