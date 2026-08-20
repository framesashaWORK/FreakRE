//! Shellcode analysis report types.

use std::fmt;

/// A single shellcode detection finding.
#[derive(Debug, Clone)]
pub struct ShellcodeFinding {
    /// Human-readable description of what was detected.
    pub description: String,
    /// Evidence details (offsets, pattern names, resolved APIs).
    pub evidence: Vec<String>,
    /// Byte offset in the scanned data where this was found.
    pub offset: usize,
    /// Confidence score [0.0 – 1.0].
    pub confidence: f64,
}

impl fmt::Display for ShellcodeFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:.0}%] {} @ 0x{:X}",
            self.confidence * 100.0,
            self.description,
            self.offset
        )
    }
}

/// Overall shellcode detection verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeVerdict {
    /// No shellcode indicators found.
    NoShellcode,
    /// Some suspicious patterns but not conclusive.
    Suspicious,
    /// Strong indicators of embedded shellcode.
    ShellcodeLikely,
}

impl fmt::Display for ShellcodeVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoShellcode => write!(f, "NO_SHELLCODE"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::ShellcodeLikely => write!(f, "SHELLCODE_LIKELY"),
        }
    }
}

/// Complete shellcode analysis report.
#[derive(Debug, Clone)]
pub struct ShellcodeReport {
    /// All findings, sorted by confidence (highest first).
    pub findings: Vec<ShellcodeFinding>,
    /// Overall verdict.
    pub verdict: ShellcodeVerdict,
    /// Total number of resolved API hashes found.
    pub total_api_hashes_found: usize,
}

impl ShellcodeReport {
    /// One-line summary for CLI output.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return "No shellcode indicators found".to_string();
        }
        format!(
            "{} finding(s), {} API hashes resolved, verdict={}",
            self.findings.len(),
            self.total_api_hashes_found,
            self.verdict
        )
    }
}
