#![allow(dead_code, unused_assignments)]
//! # bibleteks-decompiler — IR to C Pseudocode Decompiler
//!
//! Decompiles bibleteks-ir back into readable C-like pseudocode.
//!
//! ## Pipeline
//!
//! ```text
//! IR (SSA) → Structured AST → C Pseudocode
//! ```
//!
//! ## Features
//!
//! - **Control flow structuring**: Recover if/else, while, for, switch
//! - **Type-aware output**: Use inferred types in output
//! - **Variable naming**: Generate meaningful names when possible
//! - **Expression simplification**: Combine simple operations

pub mod ast;
pub mod ir_to_ast;
pub mod ast_to_c;
pub mod structuring;
pub mod decompile;

pub use decompile::{decompile_function, DecompilerConfig, DecompileError};


