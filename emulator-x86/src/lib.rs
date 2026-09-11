//! # emulator-x86 — mini-emulator over freakre-ir lifted code
//!
//! Interprets [`freakre_ir::IrFunction`] CFGs produced by the x86 lifter,
//! aimed at unpacker stubs / XOR decoders / pure-computation payloads.
//! Not a full ISA simulator: it executes *lifted IR*, conservatively, with
//! hard budgets and no panics on adversarial input.
//!
//! ## Pipeline
//!
//! ```text
//! x86 bytes ──X86Lifter──▶ IrFunction (block CFG) ──Emulator::run──▶ EmuResult
//!                                                        │
//!                              sparse memory + EmuEnv hooks + trace ring
//! ```
//!
//! ## Supported constructs (honest matrix)
//!
//! **IR instructions**
//! - `Nop`
//! - `Binary` with ops: `Add Sub Mul Div Mod And Or Xor Shl Shr Sar Rol Ror
//!   Eq Ne LtU LeU GtU GeU LtS LeS GtS GeS Copy` (`Div`/`Mod` guarded:
//!   zero divisor → `Unsupported`, never a panic)
//! - `Unary` with ops: `Copy Zext Sext Trunc Not Neg`
//! - `Load` / `Store` for sizes 1/2/4/8 bytes (little-endian)
//! - `Branch` / `CBranch` over block IDs
//! - `Call` — recorded ([`CallRecord`]), callee stubbed with RAX=0,
//!   execution continues at the fall-through
//! - `Return` — clean exit, value written to RAX
//! - `Syscall` — delegated to [`EmuEnv::syscall`] (result → RAX)
//!
//! **Refused (safe stop via [`ExitReason::Unsupported`])**
//! - `IndirectBranch`, `Phi`
//! - float ops (`FloatToFloat`, `FloatAdd`, ...)
//! - any load/store larger than 8 bytes (i.e. 16-byte SSE moves)
//!
//! ## State model
//!
//! - 16 canonical 64-bit GPR slots; every alias view (`eax/al/ah/r8d/...`)
//!   reads/writes through parent-slot masking. Narrow writes merge into the
//!   parent; 32-bit writes zero-extend (x86-64 rule); flags live in named
//!   bool slots (`flag_zf/cf/sf/of/pf`).
//! - Sparse paged memory: untouched reads are zeros; every store is folded
//!   into a merged written-region list reported in [`EmuResult`].
//! - Hard guards: step budget and a 64 MiB default memory budget, both map
//!   to [`ExitReason::BudgetExhausted`].
//!
//! ## Known limitations (by design)
//!
//! - The interpreter runs the *statically lifted* IR. Self-modifying code
//!   that rewrites its own instruction bytes will show up in write tracking
//!   and in subsequent data loads, but control flow is **not** re-lifted.
//! - Source addresses on traces/errors are approximate (per-block start,
//!   derived from lifter labels), not per-instruction RIP.
//! - No segment registers, no interrupts/exceptions, no precise EFLAGS
//!   beyond zf/cf/sf/of/pf as computed by the lifter.

pub mod decrypt;
pub mod emu_resolve;
pub mod env;
pub mod exec;
pub mod memory;
pub mod state;

pub use decrypt::{recover_written_strings, RecoveredString, MAX_REGION_SCAN};
pub use env::{DefaultEnv, EmuEnv, SyscallRecord};
pub use exec::{
    block_address, block_coverage, BudgetKind, CallRecord, EmuResult, Emulator, ExitReason,
    StepError, TraceEntry, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_TRACE_CAPACITY,
};
pub use memory::{MemRegion, MemStatus, Memory};
pub use state::{Machine, RegRef};

use freakre_ir::lifter::Lifter;

/// Error raised by the one-shot convenience runner.
#[derive(Debug)]
pub enum RunImageError {
    /// Lifting failed before execution could start.
    Lift(freakre_ir::LifterError),
    /// `entry_offset != 0` but no lifted block starts there.
    NoEntryBlock { addr: u64 },
}

impl std::fmt::Display for RunImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunImageError::Lift(e) => write!(f, "lift failed: {e}"),
            RunImageError::NoEntryBlock { addr } => {
                write!(f, "no lifted block at entry address 0x{addr:X}")
            }
        }
    }
}

impl std::error::Error for RunImageError {}

/// Lift x86-64 `code` at `base` and emulate from `base + entry_offset`.
///
/// Zero-config path using [`DefaultEnv`] (zeros read, writes tracked,
/// syscalls logged) and default budgets (see [`DEFAULT_MAX_MEMORY_BYTES`]).
/// For seeded registers/memory use [`Emulator`] directly.
///
/// ```no_run
/// use emulator_x86::run_image;
///
/// // mov eax, 2; add eax, 3; ret
/// let code = [0xB8, 0x02, 0x00, 0x00, 0x00,
///             0x83, 0xC0, 0x03,
///             0xC3];
/// let res = run_image(&code, 0x1000, 0, 10_000).unwrap();
/// assert_eq!(res.exit_reason, emulator_x86::ExitReason::Return);
/// assert_eq!(res.registers["rax"], 5);
/// ```
pub fn run_image(
    code: &[u8],
    base: u64,
    entry_offset: u64,
    max_steps: u64,
) -> Result<EmuResult, RunImageError> {
    let lifter = freakre_ir::x86_lifter::X86Lifter::new(true);
    let func = lifter
        .lift_function(code, base, "image")
        .map_err(RunImageError::Lift)?;
    if entry_offset != 0 {
        let want = base.wrapping_add(entry_offset);
        let found = func
            .blocks
            .iter()
            .any(|b| !b.insts.is_empty() && block_address(&b.label, base) == Some(want));
        if !found {
            return Err(RunImageError::NoEntryBlock { addr: want });
        }
    }
    let mut emu = Emulator::new(DefaultEnv::new());
    Ok(emu.run(&func, base, entry_offset, max_steps))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_add_three() {
        let code = [
            0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0x83, 0xC0, 0x03, // add eax, 3
            0xC3, // ret
        ];
        let res = run_image(&code, 0x1000, 0, 1_000).unwrap();
        assert_eq!(res.exit_reason, ExitReason::Return);
        assert_eq!(res.registers["rax"], 5);
    }
}
