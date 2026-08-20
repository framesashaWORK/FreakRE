#![allow(dead_code, unused_assignments)]
//! # shellcode-analyzer
//!
//! Raw shellcode detection and API hash resolution for malware analysis.
//! Detects embedded shellcode blobs in binary data and resolves
//! Windows API hashes used by position-independent code.

mod detector;
mod api_hashes;
mod report;

pub use detector::{detect_shellcode, ShellcodeConfig};
pub use api_hashes::{resolve_api_hash, ApiHashType, ResolvedApi};
pub use report::{ShellcodeReport, ShellcodeFinding, ShellcodeVerdict};


