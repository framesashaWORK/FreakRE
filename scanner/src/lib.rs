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

pub mod filetype;
pub mod output;
pub mod packers;
pub mod report;
pub mod scanner;
pub mod scoring;

#[cfg(feature = "decompiler")]
pub mod decompile_api;
pub mod decompile_pyc;
pub use filetype::{detect_file_type, hex_md5, hex_sha256};
pub use packers::{detect_packers, match_packer};
pub use report::*;
pub use scanner::{AnalysisProfile, Scanner};
pub use scoring::{
    calculate_suspicion_score, calculate_suspicion_score_with_config, ScoringConfig,
};
