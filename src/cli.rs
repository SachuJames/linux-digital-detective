//! Command-line interface definition (clap).
//!
//! The binary is called `lddetective`, not `ldd`: `ldd` is the standard
//! Linux tool that prints shared-library dependencies, and shadowing it on
//! PATH would be hostile.

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "lddetective",
    version,
    about = "Local-first Linux incident investigation and evidence correlation",
    long_about = "Reconstruct what happened on a Linux system from local logs and \
                  evidence. Parses evidence, normalizes events, orders them \
                  chronologically, correlates related events, and reports \
                  noteworthy sequences. Everything runs locally; no network, \
                  no accounts, no telemetry."
)]
pub struct Cli {
    #[arg(long, global = true, help = "Suppress informational output")]
    pub quiet: bool,

    #[arg(long, global = true, help = "Verbose output")]
    pub verbose: bool,

    #[arg(long, global = true, help = "Disable colored output")]
    pub no_color: bool,

    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Config file (default: ~/.config/linux-digital-detective/config.toml)"
    )]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Parse evidence and print a summary of what was found
    Analyze(AnalyzeArgs),
    /// Print the chronological event timeline, with optional filters
    Timeline(TimelineArgs),
    /// Print the full investigation report
    Report(ReportArgs),
    /// Show per-file evidence details (parsers used, statistics)
    Inspect(InspectArgs),
    /// Watch the live system (read-only) and stream observed changes
    Live(LiveArgs),
    /// List the built-in detection rules
    Rules(RulesArgs),
    /// Print version information
    Version,
}

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Evidence file, directory, or '-' for stdin
    pub input: String,
    #[arg(long, value_name = "FORMAT", help = "Output format: text, json")]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct TimelineArgs {
    /// Evidence file, directory, or '-' for stdin
    pub input: String,
    #[arg(long, value_name = "TIME", help = "Only events at or after this time")]
    pub from: Option<String>,
    #[arg(long, value_name = "TIME", help = "Only events at or before this time")]
    pub to: Option<String>,
    #[arg(
        long,
        value_name = "LEVEL",
        help = "Minimum severity: debug, info, notice, warning, error, critical"
    )]
    pub severity: Option<String>,
    #[arg(
        long,
        value_name = "TYPE",
        help = "Event type (repeatable): auth, process, privilege, network, kernel, service, application, system, snapshot"
    )]
    pub r#type: Vec<String>,
    #[arg(long, value_name = "NAME", help = "Process name substring filter")]
    pub process: Option<String>,
    #[arg(long, value_name = "PATH", help = "Source path substring filter")]
    pub source: Option<String>,
    #[arg(
        long,
        value_name = "FORMAT",
        help = "Output format: text, json, jsonl, csv"
    )]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Evidence file, directory, or '-' for stdin
    pub input: String,
    #[arg(
        long,
        value_name = "FORMAT",
        help = "Output format: text, json, jsonl, csv"
    )]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Evidence file, directory, or '-' for stdin
    pub input: String,
    #[arg(long, value_name = "FORMAT", help = "Output format: text, json")]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct LiveArgs {
    #[arg(long, default_value = "2", help = "Seconds between snapshots")]
    pub interval: u64,
    #[arg(
        long,
        value_name = "SECS",
        help = "Stop after this many seconds (default: run until interrupted)"
    )]
    pub duration: Option<u64>,
    #[arg(long, value_name = "FORMAT", help = "Output format: text, json")]
    pub format: Option<String>,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub action: RulesAction,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List built-in detection rules
    List,
}
