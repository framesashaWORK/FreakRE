#![allow(dead_code, unused_assignments)]
//! # freakre-decompiler — IR to C Pseudocode Decompiler
//!
//! Decompiles freakre-ir back into readable C-like pseudocode.
//!
//! ## Pipeline
//!
//! ```text
//! IR (SSA) → Structured AST → C Pseudocode
//! ```
//!
//! ## Features
//!
//! - **Control flow structuring**: Recover if/else, while, do-while, for, switch/case
//! - **Break/continue recovery**: Correct loop exit and continuation detection
//! - **Try-catch blocks**: Exception handler region detection
//! - **Nested structures**: Arbitrary depth with proper scoping
//! - **Type-aware output**: Use inferred types in output
//! - **Variable naming**: Generate meaningful names when possible
//! - **Expression simplification**: Combine simple operations

pub mod ast;
pub mod fold_flags;
pub mod ir_to_ast;
pub mod ast_to_c;
pub mod structuring;
pub mod decompile;
pub mod simplify;
pub mod types;
pub mod interproc;
pub mod patterns;
pub mod stack_vars;

use freakre_ir::BlockId;

/// Public loop description returned by the legacy CFG analysis API.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub header: BlockId,
    pub back_edge_from: BlockId,
}

/// Public if-else description returned by the legacy CFG analysis API.
#[derive(Debug, Clone)]
pub struct IfElsePattern {
    pub cond_block: BlockId,
    pub then_block: BlockId,
    pub else_block: BlockId,
}

pub use decompile::{decompile_function, DecompilerConfig, DecompileError};


