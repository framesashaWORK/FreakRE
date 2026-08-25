#![allow(dead_code, unused_assignments)]
//! # yara-lite
//!
//! Lightweight YARA-compatible pattern matching engine for malware analysis.
//!
//! ## Supported YARA subset
//!
//! - **Hex patterns**: `{ 4D 5A ?? 90 ?A B? }` with single-byte and nibble wildcards
//! - **Text patterns**: `"string"` with `nocase`, `wide`, `ascii`, `fullword` modifiers
//! - **Regex patterns**: `/pattern/` with optional `nocase`
//! - **Conditions**: `all of them`, `any of them`, `N of them`, `$s at <offset>`,
//!   `$s in (<start>..<end>)`, `#s > N`, `filesize < N`, boolean operators (`and`, `or`, `not`)
//!
//! ## Example
//!
//! ```rust
//! use yara_lite::{parse_rules, compile_rule, Scanner};
//!
//! let rules_text = r#"
//!     rule detect_mz {
//!         strings:
//!             $mz = { 4D 5A }
//!         condition:
//!             $mz at 0
//!     }
//! "#;
//!
//! let parsed = parse_rules(rules_text).unwrap();
//! let compiled: Vec<_> = parsed.iter().map(|r| compile_rule(r).unwrap()).collect();
//! let scanner = Scanner::new(compiled).unwrap();
//!
//! let data = b"\x4D\x5A\x90\x00";
//! let result = scanner.scan(data);
//! assert!(result.matched_rules.contains(&"detect_mz".to_string()));
//! ```

pub mod ast;
pub mod compiler;
pub mod parser;
pub mod scanner;

// Re-exports for convenience
pub use compiler::{compile_rule, CompiledRule};
pub use parser::{parse_rule, parse_rules};
pub use scanner::{Match, MAX_COLLECTED_MATCHES, ScanResult, Scanner};


