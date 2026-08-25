#![allow(unused_assignments)]
//! # backdoor-analyzer
//!
//! Dedicated backdoor detection engine for the bibleteks scanner.
//! Analyzes PE imports, strings, entropy patterns, and structural indicators
//! to identify 12 categories of backdoor behavior.

pub mod rules;
pub mod report;
mod analyzer;

pub use report::{BackdoorReport, BackdoorFinding, BackdoorSeverity, BackdoorVerdict};
pub use analyzer::analyze_backdoors;
pub use rules::BackdoorRuleId;


