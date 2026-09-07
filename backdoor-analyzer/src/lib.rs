#![allow(unused_assignments)]
//! # backdoor-analyzer
//!
//! Dedicated backdoor detection engine for the bibleteks scanner.
//! Analyzes PE imports, strings, entropy patterns, and structural indicators
//! to identify 27 categories of backdoor behavior.

mod analyzer;
pub mod correlation;
pub mod platform;
pub mod report;
pub mod rules;

pub use analyzer::analyze_backdoors;
pub use correlation::{correlate_function_evidence, FunctionEvidence};
pub use platform::{detect_platform_tactics, PlatformFinding, PlatformTactic};
pub use report::{
    BackdoorFinding, BackdoorReport, BackdoorSeverity, BackdoorVerdict, ConfidenceLevel,
    EvidenceRecord, EvidenceSource, FindingExplanation,
};
pub use rules::BackdoorRuleId;
