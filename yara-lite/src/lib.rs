#![allow(dead_code, unused_assignments)]
//! # yara-lite
//!
//! Lightweight YARA-compatible pattern matching engine for malware analysis.
//!
//! ## Supported YARA subset
//!
//! - **Hex patterns**: `{ 4D 5A ?? 90 ?A B? }` with single-byte and nibble wildcards
//! - **Text patterns**: `"string"` with `nocase`, `wide`, `ascii`, `fullword`,
//!   `xor`, and `base64` modifiers
//! - **Regex patterns**: `/pattern/` with optional `nocase`
//! - **Conditions**:
//!   - `all of them`, `any of them`, `N of them`, `N of ($a, $b)`, `N of ($a*)`
//!     (wildcard prefix sets)
//!   - `$s at <offset>`, `$s in (<start>..<end>)`, `#s > N`
//!   - `filesize < N` (with `KB`/`MB`/`GB` suffixes), `entrypoint`
//!   - boolean operators (`and`, `or`, `not`)
//!   - integer comparisons with `+ - * / &`, parentheses, and float literals
//!   - `for any/all/N of ($set) : ( ... )` with `$` referring to the current
//!     string; `for any i in (a..b) : ( ... )` with the loop variable bound
//!     (`@s[i]`, `#s`, arithmetic)
//!   - `$s matches /regex/` (real DoS-protected regex engine)
//!   - `$s contains "..."`, `$s == "..."`
//!   - `uint8/16/32`, `int8/16/32` reads
//!   - `math.entropy(off, len) > 7.0`, `math.hash(off, len)`
//!   - PE module: `pe.machine`, `pe.timestamp`, `pe.entry_point`,
//!     `pe.subsystem`, `pe.characteristics`, `pe.number_of_sections`,
//!     `pe.is_pe()`, `pe.imports("dll")`, `pe.imports("dll", "func")`,
//!     `pe.sections("name")`, and symbolic constants
//!     (`pe.MACHINE_I386`, `pe.SUBSYSTEM_WINDOWS_GUI`, `pe.DLL`, ...)
//! - **Rule modifiers**: `private rule` (matched but unreported),
//!   `global rule` (must match for any other rule to match)
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
pub use scanner::{Match, ScanResult, Scanner, MAX_COLLECTED_MATCHES};
