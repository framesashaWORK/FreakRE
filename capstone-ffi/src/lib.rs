#![allow(dead_code, unused_assignments)]
//! # capstone-ffi
//!
//! **Optional precise-disassembly engine** for freakRE: multi-architecture
//! disassembly on top of the system Capstone library, exposed through an
//! engine-neutral trait so nothing downstream has to know Capstone exists.
//!
//! Also provides a unified legacy API ([`Disassembler`]) for x86/x64 with a
//! built-in LDE fallback.
//!
//! ## Hybrid disassembly strategy
//!
//! freakRE uses two complementary engines:
//!
//! 1. **Native engine (default, offline)** — `freakre-x86`. Pure-Rust,
//!    zero external dependencies, always available. This crate does NOT
//!    depend on or modify it; it simply defines [`PreciseEngine`] so the
//!    native engine can implement the same contract without pulling in
//!    any capstone type.
//!
//! 2. **Capstone engine (optional, precise, cross-arch)** — this crate.
//!    Enabled *at build time* purely by the presence of system libcapstone:
//!    `build.rs` probes `CAPSTONE_LIB_DIR`, pkg-config, and common Windows
//!    install paths. When found it emits `cfg(capstone_available)` and the
//!    real FFI backend ([`CapstoneEngine`]) is compiled in; when absent
//!    (e.g. default Windows builds) **all FFI code is compiled out** and
//!    only [`StubEngine`] remains, which fails with
//!    [`EngineError::Unavailable`] instead of breaking builds or linking.
//!
//! | build                     | [`best_engine_for`] returns   |
//! |---------------------------|-------------------------------|
//! | libcapstone found         | [`CapstoneEngine`]            |
//! | libcapstone NOT found     | [`StubEngine`]                |
//!
//! ## How downstream should feature-gate
//!
//! Dependents never reference backend types directly. Ask for
//! [`best_engine_for`] (or [`best_engine`] for the x86-64 default) and
//! treat [`EngineError::Unavailable`] as "precise mode not built in":
//!
//! ```rust
//! use capstone_ffi::{best_engine_for, Arch, EngineError, Mode, PreciseEngine};
//!
//! let engine = best_engine_for(Arch::X86, Mode::Mode64);
//! match engine.disasm(&[0x55, 0x48, 0x89, 0xE5], 0x1000, 10) {
//!     Ok(instrs) => {
//!         for i in instrs {
//!             println!("{:#x}: {} {}", i.address, i.mnemonic, i.op_str);
//!         }
//!     }
//!     Err(EngineError::Unavailable) => {
//!         // Built without system libcapstone — fall back to the native
//!         // freakre-x86 engine or skip precise analysis entirely.
//!     }
//!     Err(other) => eprintln!("engine error: {other}"),
//! }
//! ```
//!
//! Code that needs the concrete capstone backend (syntax selection, group
//! tags, detail mode) must be cfg-gated with the same flag build.rs emits:
//!
//! ```rust,ignore
//! #[cfg(capstone_available)]
//! use capstone_ffi::{CapstoneEngine, Syntax};
//!
//! #[cfg(capstone_available)]
//! fn att_disasm() -> capstone_ffi::Result<Vec<capstone_ffi::Instr>> {
//!     let eng = CapstoneEngine::with_syntax(Arch::X86, Mode::Mode64, Syntax::Att)?;
//!     Ok(eng.disasm(&[0x48, 0x89, 0xE5], 0x1000, 1)?)
//! }
//! ```
//!
//! The trait itself ([`PreciseEngine`]) is intentionally plain — no
//! capstone types leak through it — precisely so the native `freakre-x86`
//! engine can implement it too.

pub mod arch;
pub mod engine;
pub mod error;
pub mod instruction;
pub mod disassembler;

#[cfg(capstone_available)]
pub mod capstone_bindings;

pub use arch::{Arch, Mode, Endian};
pub use error::DisasmError;
pub use instruction::{Instruction, InstructionKind, Operand, RegId, reg_name_to_id};
pub use disassembler::Disassembler;

// Engine-neutral precise-disassembly facade.
#[cfg(capstone_available)]
pub use engine::CapstoneEngine;
pub use engine::{
    best_engine, best_engine_for, try_best_engine_for, EngineError, Instr, PreciseEngine,
    StubEngine, Syntax,
};

/// Result type for disassembly operations
pub type Result<T> = std::result::Result<T, DisasmError>;
