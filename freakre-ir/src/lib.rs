#![allow(dead_code, unused_assignments)]
//! # freakre-ir — Universal Intermediate Representation
//!
//! A platform-independent IR for binary analysis, inspired by Ghidra P-code
//! and LLVM IR. Designed to be:
//!
//! - **Architecture-agnostic**: A single IR representation for x86, ARM, MIPS, etc.
//! - **SSA-form ready**: Built-in support for Static Single Assignment form
//! - **Serialisable**: Full JSON/bincode serialisation support
//! - **Analysis-friendly**: Designed for data flow, control flow, and type analysis
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │  x86 bytes  │     │  ARM bytes  │     │  MIPS bytes │
//! └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
//!        │                   │                   │
//!        ▼                   ▼                   ▼
//!   ┌─────────┐         ┌─────────┐         ┌─────────┐
//!   │x86 Lift │         │ARM Lift │         │MIPS Lift│
//!   └────┬────┘         └────┬────┘         └────┬────┘
//!        │                   │                   │
//!        └───────────┬───────┴───────────────────┘
//!                    ▼
//!          ┌──────────────────┐
//!          │  Universal IR    │
//!          │  (this crate)    │
//!          └────────┬─────────┘
//!                   │
//!       ┌───────────┼────────────┐
//!       ▼           ▼            ▼
//!   ┌────────┐  ┌────────┐  ┌────────┐
//!   │  Data  │  │Control │  │  Type  │
//!   │  Flow  │  │  Flow  │  │Propag. │
//!   └────────┘  └────────┘  └────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust
//! use freakre_ir::{IrFunction, IrBlock, IrInst, OpCode, Value, Ty};
//!
//! let mut func = IrFunction::new("main", 0x401000);
//! let entry = func.add_block("entry");
//!
//! // v0 = LOAD(rsp + 8, i64)
//! let v0 = func.alloc_var(Ty::Int(64));
//! let base_reg = Value::Register { name: "rsp".into(), ty: Ty::Int(64) };
//! let offset = Value::Const(8);
//! let addr = func.alloc_var(Ty::Int(64));
//! func.push_inst(entry, IrInst::Binary {
//!     dst: addr.clone(),
//!     op: OpCode::Add,
//!     lhs: base_reg,
//!     rhs: offset,
//! });
//! func.push_inst(entry, IrInst::Load {
//!     dst: v0.clone(),
//!     addr,
//!     size: 8,
//! });
//! ```

pub mod arch;
pub mod arm_lifter;
pub mod ir;
pub mod lifter;
pub mod mips_lifter;
pub mod optimize;
pub mod riscv_lifter;
pub mod sccp;
pub mod ssa;
pub mod types;
pub mod validator;
pub mod x86_lifter;

pub use ir::*;
pub use lifter::{Lifter, LifterError};
pub use ssa::{
    from_ssa, remove_trivial_phis, to_ssa, BaseVar, Phi, SsaBlock, SsaError, SsaFunction, SsaInst,
    SsaVal, VersionedVar,
};
pub use types::Ty;
