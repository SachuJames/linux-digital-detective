//! Optional user configuration.
//!
//! Configuration is never required. When `~/.config/linux-digital-detective/config.toml`
//! (or the path passed with `--config`) exists, it can adjust thresholds and
//! defaults. Everything falls back to documented defaults.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Default evidence directories scanned when no input is given.
    pub evidence_dirs: Vec<PathBuf>,
    /// Rule thresholds.
    pub rules: RuleConfig,
    /// Output preferences.
    pub output: OutputConfig,
    /// Safety limits (see `crate::evidence` for hard caps).
    pub limits: LimitConfig,
}

/// Tunables for the built-in rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    /// AUTH-001: minimum failed attempts before a later success is noteworthy.
    pub auth_failure_threshold: usize,
    /// Maximum gap between the first failure and the success.
    pub auth_window_secs: i64,
    /// Minimum repeated connection attempts to flag.
    pub connection_attempt_threshold: usize,
    /// Window for repeated connection attempts.
    pub connection_window_secs: i64,
    /// How soon after a login a process spawn is "shortly after".
    pub login_process_window_secs: i64,
    /// Directories considered normal homes for executables.
    pub trusted_exec_dirs: Vec<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            auth_failure_threshold: 3,
            auth_window_secs: 900,
            connection_attempt_threshold: 10,
            connection_window_secs: 300,
            login_process_window_secs: 120,
            trusted_exec_dirs: vec![
                "/usr/bin".into(),
                "/usr/sbin".into(),
                "/bin".into(),
                "/sbin".into(),
                "/usr/local/bin".into(),
                "/usr/local/sbin".into(),
                "/opt".into(),
                "/snap".into(),
            ],
        }
    }
}

/// Output preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub format: String,
    pub color: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "text".into(),
            color: true,
        }
    }
}

/// Soft limits a user may lower (never raise above hard caps).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitConfig {
    pub max_file_bytes: u64,
    pub max_line_bytes: usize,
    pub max_recursion_depth: usize,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: crate::evidence::MAX_FILE_BYTES,
            max_line_bytes: crate::evidence::MAX_LINE_BYTES,
            max_recursion_depth: crate::evidence::MAX_RECURSION_DEPTH,
        }
    }
}

/// Load configuration from an explicit path, or the default location.
///
/// Missing file = defaults. Unparseable file = error naming the problem.
pub fn load(explicit: Option<&str>) -> Result<Config> {
    let path: Option<PathBuf> = match explicit {
        Some(p) => Some(PathBuf::from(p)),
        None => default_path(),
    };
    let Some(path) = path else {
        return Ok(Config::default());
    };
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        Error::Config(format!("could not read {}: {e}", path.display()))
    })?;
    let cfg: Config = toml::from_str(&text).map_err(|e| {
        Error::Config(format!("could not parse {}: {e}", path.display()))
    })?;
    cfg.validate()?;
    Ok(cfg)
}

fn default_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("linux-digital-detective")
            .join("config.toml"),
    )
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.limits.max_file_bytes > crate::evidence::MAX_FILE_BYTES {
            return Err(Error::Config(format!(
                "limits.max_file_bytes may not exceed the hard cap of {}",
                crate::evidence::MAX_FILE_BYTES
            )));
        }
        if self.limits.max_line_bytes > crate::evidence::MAX_LINE_BYTES {
            return Err(Error::Config(format!(
                "limits.max_line_bytes may not exceed the hard cap of {}",
                crate::evidence::MAX_LINE_BYTES
            )));
        }
        if self.limits.max_recursion_depth > crate::evidence::MAX_RECURSION_DEPTH {
            return Err(Error::Config(format!(
                "limits.max_recursion_depth may not exceed the hard cap of {}",
                crate::evidence::MAX_RECURSION_DEPTH
            )));
        }
        Ok(())
    }

    /// Render a documented example configuration.
    pub fn example() -> String {
        toml::to_string_pretty(&Config::default()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_file_yields_defaults() {
        let cfg = load(Some("/definitely/not/here-xyz.toml")).unwrap();
        assert_eq!(cfg.rules.auth_failure_threshold, 3);
    }

    #[test]
    fn user_cannot_raise_limits_above_hard_caps() {
        let mut cfg = Config::default();
        cfg.limits.max_file_bytes = u64::MAX;
        assert!(cfg.validate().is_err());
    }
}
