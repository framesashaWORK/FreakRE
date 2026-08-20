#![allow(dead_code, unused_assignments)]
//! # capstone-ffi
//!
//! Multi-architecture disassembly framework built on top of Capstone.
//! Provides a unified Rust API for disassembling machine code across
//! x86, x64, ARM, ARM64, MIPS, PowerPC, SPARC, and RISC-V architectures.
//!
//! ## Example
//!
//! ```rust
//! use capstone_ffi::{Disassembler, Arch, Mode};
//!
//! let disasm = Disassembler::new(Arch::X86, Mode::Mode64).unwrap();
//! let code = [0x55, 0x48, 0x89, 0xe5]; // push rbp; mov rbp, rsp
//! let instructions = disasm.disassemble(&code, 0x1000);
//!
//! for inst in instructions {
//!     println!("0x{:X}: {} {}", inst.address, inst.mnemonic, inst.operands);
//! }
//! ```

pub mod arch;
pub mod error;
pub mod instruction;
pub mod disassembler;

#[cfg(capstone_available)]
pub mod capstone_bindings;

pub use arch::{Arch, Mode, Endian};
pub use error::DisasmError;
pub use instruction::{Instruction, Operand, RegId};
pub use disassembler::Disassembler;

/// Result type for disassembly operations
pub type Result<T> = std::result::Result<T, DisasmError>;


