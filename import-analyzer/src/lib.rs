#![allow(dead_code, unused_assignments)]
//! # import-analyzer
//!
//! Security-oriented PE import table analyzer for malware detection.
//!
//! ## Features
//!
//! - Parses Import Directory Table (IDT) and Import Lookup Table (ILT/IAT)
//! - Detects suspicious API combinations (process injection, persistence, evasion)
//! - Identifies known malware-relevant DLLs and functions
//! - Supports both PE32 and PE32+ formats
//! - Returns structured analysis results with confidence scoring

pub mod parser;
pub mod rules;
pub mod types;

pub use parser::ImportAnalyzer;
pub use rules::{RuleMatch, SuspicionLevel};
pub use types::{AnalysisReport, ImportDescriptor, ImportedFunction, ImportedModule};
