#![allow(unused_assignments)]
//! # freakre-scanner
//!
//! Core scanning engine for FreakRE — orchestrates all analysis modules
//! (PE parsing, entropy, imports, backdoor detection, shellcode, YARA-lite,
//! cross-references, CFG analysis, and function signatures) into a unified
//! scan report with weighted signal correlation.
//!
//! ## Usage as a library
//!
//! ```rust,no_run
//! use freakre_scanner::Scanner;
//! use std::path::Path;
//!
//! let scanner = Scanner::new();
//! let report = scanner.scan_file(Path::new("test.exe"));
//! println!("Verdict: {}", report.verdict);
//! println!("Suspicion score: {:.2}", report.suspicion_score);
//! ```
//!
//! ## CLI usage
//!
//! Enable the `cli` feature (default) to get the `bibleteks` binary:
//!
//! ```bash
//! cargo run --features cli -- /path/to/scan --rules rules.yar
//! ```

pub mod output;
pub mod report;
pub mod scanner;

pub use report::*;
pub use scanner::{Scanner, ScoringConfig};


