//! linux-digital-detective: a local-first Linux incident investigation tool.
//!
//! The library is organized in layers:
//!
//! ```text
//! evidence -> parsers -> events -> timeline -> correlation -> rules -> reporting
//!                              collectors (live, read-only)
//! ```
//!
//! See `docs/architecture.md` for the full picture.

pub mod analysis;
pub mod cli;
pub mod collectors;
pub mod config;
pub mod correlation;
pub mod errors;
pub mod events;
pub mod evidence;
pub mod linux;
pub mod parsers;
pub mod reporting;
pub mod rules;
pub mod storage;
pub mod timeline;
