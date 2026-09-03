//! Engine-neutral precise-disassembly facade.
//!
//! This module defines the public contract that decouples the rest of
//! freakRE from Capstone:
//!
//! * [`PreciseEngine`] — object-safe trait every precise backend can
//!   implement (the native `freakre-x86` engine can adopt it without
//!   depending on any capstone type).
//! * [`Instr`] / [`EngineError`] — plain, engine-neutral result types.
//!   No capstone types are ever exposed publicly.
//! * [`StubEngine`] — inert placeholder returned when the crate is built
//!   **without** system libcapstone; every call fails with
//!   [`EngineError::Unavailable`] so dependents can feature-gate cleanly
//!   at runtime instead of failing to compile.
//! * [`best_engine`] / [`best_engine_for`] — pick the best available
//!   backend for the current build configuration.
//!
//! ## cfg strategy
//!
//! | build.rs outcome            | compiled in                                   |
//! |-----------------------------|-----------------------------------------------|
//! | libcapstone found           | [`CapstoneEngine`] (real FFI)                 |
//! | libcapstone NOT found       | only [`StubEngine`] (`Err(Unavailable)`)      |
//!
//! The switch is a single build-time cfg — `capstone_available` — emitted
//! by `build.rs`; all FFI code is compiled out when it is absent, which is
//! what makes Windows builds link-free and hermetic.

use crate::arch::{Arch, Mode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Engine-neutral types ────────────────────────────────────────────

/// Errors reported by any [`PreciseEngine`] implementation.
#[derive(Debug, Error)]
pub enum EngineError {
    /// No precise-disassembly backend exists in this build
    /// (crate was compiled without system libcapstone and no other
    /// engine was installed). Dependents should treat this as the
    /// "feature not built in" signal.
    #[error("precise-disassembly engine unavailable: built without system libcapstone")]
    Unavailable,

    /// Backend initialization failed (e.g. `cs_open` rejected the
    /// arch/mode pair or the linked library is broken).
    #[error("engine initialization failed: {0}")]
    Init(String),

    /// The requested architecture/mode combination has no mapping into
    /// this backend's constants.
    #[error("unsupported arch/mode combination: {0} / {1:?}")]
    Unsupported(Arch, Mode),

    /// Disassembly itself failed after successful initialization.
    #[error("disassembly failed: {0}")]
    Disasm(String),

    /// Internal invariant violation detected by the safety audit layer
    /// (indicates an ABI/layout mismatch with the linked C library).
    #[error("internal engine violation: {0}")]
    Internal(String),
}

/// A disassembled instruction, expressed entirely in engine-neutral terms.
///
/// Address/size/bytes plus textual mnemonic and operand string. `groups`
/// carries coarse classification tags ("jump", "call", "ret", ...) when the
/// backend runs with detail enabled. `branch_target` holds the resolved
/// absolute target for direct branches/calls (Capstone renders it in
/// `op_str`; parsed here so callers don't re-parse strings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instr {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Encoded length in bytes.
    pub size: usize,
    /// Raw bytes (clamped to the real size).
    #[serde(default)]
    pub bytes: Vec<u8>,
    /// Mnemonic without operands (e.g. `"mov"`).
    pub mnemonic: String,
    /// Operand string as rendered by the engine (e.g. `"rbp, rsp"`).
    pub op_str: String,
    /// Coarse instruction groups (may be empty).
    pub groups: Vec<String>,
    /// Resolved direct branch/call target (absolute VA), if any.
    #[serde(default)]
    pub branch_target: Option<u64>,
}

impl Instr {
    /// Convert into the legacy rich [`crate::instruction::Instruction`].
    /// Re-parses `op_str` with the shared operand parser and maps groups
    /// to [`crate::instruction::InstructionKind`].
    pub fn to_instruction(&self) -> crate::instruction::Instruction {
        use crate::instruction::{Instruction, InstructionKind};
        let kind = if self.groups.iter().any(|g| g == "ret") {
            InstructionKind::Return
        } else if self.groups.iter().any(|g| g == "call") {
            InstructionKind::Call
        } else if self.groups.iter().any(|g| g == "jump") {
            let m = self.mnemonic.to_ascii_lowercase();
            if m == "jmp" || m == "b" || m == "bx" {
                InstructionKind::UnconditionalJump
            } else {
                InstructionKind::ConditionalBranch
            }
        } else {
            InstructionKind::Normal
        };
        #[cfg(capstone_available)]
        let operand_list = crate::capstone_bindings::parse_operands(&self.op_str);
        #[cfg(not(capstone_available))]
        let operand_list = Vec::new();
        Instruction {
            address: self.address,
            size: self.size,
            bytes: self.bytes.clone(),
            mnemonic: self.mnemonic.clone(),
            operands: self.op_str.clone(),
            operand_list,
            kind,
            groups: self.groups.clone(),
            branch_target: self.branch_target,
        }
    }
}

/// Object-safe contract for precise multi-architecture disassemblers.
///
/// Implementors own their architecture/mode selection; it is fixed at
/// construction time and not part of the per-call signature. This keeps
/// the trait usable by backends that are not Capstone (e.g. the native
/// `freakre-x86` engine) and trivially feature-gatable downstream.
pub trait PreciseEngine {
    /// Disassemble at most `count` instructions starting at virtual
    /// address `va`.
    ///
    /// Semantics:
    /// * Decoding stops at the first undecodable byte or end of buffer;
    ///   successfully decoded prefix instructions are still returned
    ///   (`Ok`). An `Err` is reserved for engine-level failures.
    /// * `count == 0` means "decode until stop condition" (Capstone
    ///   convention, preserved here).
    /// * An empty input yields `Ok(vec![])` on working engines and
    ///   `Err(EngineError::Unavailable)` on [`StubEngine`].
    fn disasm(
        &self,
        code: &[u8],
        va: u64,
        count: usize,
    ) -> Result<Vec<Instr>, EngineError>;
}

// ─── Backend selection ───────────────────────────────────────────────

/// Returns the best available precise engine for x86-64.
///
/// Equivalent to `best_engine_for(Arch::X86, Mode::Mode64)` — the most
/// common default for RE workloads.
pub fn best_engine() -> Box<dyn PreciseEngine> {
    best_engine_for(Arch::X86, Mode::Mode64)
}

/// Try to build the best precise engine, preserving the real error.
///
/// Unlike [`best_engine_for`] this does NOT swallow `Init`/`Unsupported`
/// failures — use it when you need to log *why* precise mode is missing.
pub fn try_best_engine_for(arch: Arch, mode: Mode) -> Result<Box<dyn PreciseEngine>, EngineError> {
    #[cfg(capstone_available)]
    {
        match crate::engine::capstone_backend::CapstoneEngine::new(arch, mode) {
            Ok(e) => return Ok(Box::new(e)),
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(capstone_available))]
    {
        let _ = (arch, mode);
        Err(EngineError::Unavailable)
    }
}

/// Returns the best available precise engine for `arch`/`mode`.
///
/// * With libcapstone present at build time → [`CapstoneEngine`].
/// * Without → [`StubEngine`]; calls fail with
///   [`EngineError::Unavailable`] so callers can degrade gracefully.
///
/// Construction failures (broken install / unsupported combo) also fall
/// back to [`StubEngine`] instead of panicking; use
/// [`try_best_engine_for`] when the underlying cause matters.
pub fn best_engine_for(arch: Arch, mode: Mode) -> Box<dyn PreciseEngine> {
    match try_best_engine_for(arch, mode) {
        Ok(e) => e,
        Err(_) => Box::new(StubEngine),
    }
}

// ─── Stub backend ────────────────────────────────────────────────────

/// Inert engine used when no real backend is available.
///
/// Every method returns [`EngineError::Unavailable`]. This type always
/// exists (it contains nothing platform-specific), but [`best_engine`]
/// only ever returns it when the crate was built without libcapstone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StubEngine;

impl PreciseEngine for StubEngine {
    fn disasm(
        &self,
        _code: &[u8],
        _va: u64,
        _count: usize,
    ) -> Result<Vec<Instr>, EngineError> {
        Err(EngineError::Unavailable)
    }
}

// ─── Real Capstone backend ───────────────────────────────────────────

#[cfg(capstone_available)]
pub mod capstone_backend {
    //! Safe Capstone-backed [`PreciseEngine`]. Compiled only when
    //! `build.rs` emitted `cfg(capstone_available)`.
    //!
    //! # unsafe audit (task contract)
    //!
    //! * All FFI is declared once in [`crate::capstone_bindings`]; this
    //!   module owns the only safe wrapper for the *engine* path.
    //! * `cs_disasm` results are wrapped in [`InsnGuard`], whose `Drop`
    //!   calls `cs_free(ptr, count)` **exactly once** — even on early
    //!   returns or panics between allocation and conversion. The guard
    //!   nulls its fields after freeing as defense-in-depth.
    //! * The insn array length is validated against `code.len()` before
    //!   a slice view is formed (each decoded insn consumes ≥ 1 byte, so
    //!   a larger count means ABI corruption, not a valid buffer).
    //! * Per-insn field reads are bounds-checked: `insn.size` must fit
    //!   inside the fixed `bytes[24]` array or we abort the batch with
    //!   [`EngineError::Internal`] instead of reading OOB.
    //! * No Rust closures cross the FFI boundary, therefore no unwind
    //!   can propagate into C code. Allocation happens strictly outside
    //!   extern calls.

    use super::{EngineError, Instr, PreciseEngine};
    use crate::arch::{Arch, Endian, Mode};
    use crate::capstone_bindings::{
        cstr_to_string, cs_close, cs_disasm, cs_free, cs_open, cs_option, parse_branch_target,
        CsHandle, CsInsn, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_PRIVILEGE,
        CS_GRP_RET, CS_OPT_DETAIL, CS_OPT_OFF, CS_OPT_ON, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT,
        CS_OPT_SYNTAX_INTEL, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS, CS_ARCH_PPC, CS_ARCH_SPARC,
        CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN, CS_MODE_MICRO, CS_MODE_THUMB,
    };
    use crate::engine::Syntax;

    // NOTE: capstone v5 exposes `cs_dispose` for individually malloc'd
    // instructions; it is declared in `crate::capstone_bindings` for
    // completeness. Arrays produced by `cs_disasm` are freed with
    // `cs_free` on BOTH v4 and v5, which is the only allocation this
    // engine makes, so the guard below uses `cs_free`.

    /// Generic group table (capstone.h `cs_group_type`) mapped to stable
    /// engine-neutral tag names.
    const GROUP_TABLE: [(u8, &str); 6] = [
        (CS_GRP_JUMP, "jump"),
        (CS_GRP_CALL, "call"),
        (CS_GRP_RET, "ret"),
        (CS_GRP_INT, "int"),
        (CS_GRP_IRET, "iret"),
        (CS_GRP_PRIVILEGE, "privilege"),
    ];

    /// RAII owner of one `cs_disasm` result array.
    ///
    /// Frees the array exactly once via `Drop`; never frees twice because
    /// the pointer/count are zeroed immediately after `cs_free`.
    struct InsnGuard {
        ptr: *mut CsInsn,
        count: usize,
    }

    impl InsnGuard {
        fn slice(&self) -> Option<&[CsInsn]> {
            if self.ptr.is_null() || self.count == 0 {
                return None;
            }
            // Caller must have validated count <= code.len() beforehand;
            // this forms the only raw-parts view in the module.
            Some(unsafe { std::slice::from_raw_parts(self.ptr, self.count) })
        }
    }

    impl Drop for InsnGuard {
        fn drop(&mut self) {
            if !self.ptr.is_null() && self.count > 0 {
                unsafe { cs_free(self.ptr, self.count) };
                self.ptr = std::ptr::null_mut();
                self.count = 0;
            }
        }
    }

    /// Precise multi-architecture disassembler backed by the system
    /// libcapstone.
    ///
    /// * Intel syntax by default; ATT selectable via [`Syntax`]
    ///   (x86 only — other arches ignore the setting).
    /// * Detail mode OFF by default for speed; enable with
    ///   [`CapstoneEngine::with_detail`] to populate [`Instr::groups`].
    ///
    /// Not `Send`/`Sync`: capstone handles are not thread-safe for
    /// concurrent disassembly. Wrap in a `Mutex` if sharing is needed.
    pub struct CapstoneEngine {
        handle: CsHandle,
        want_groups: bool,
        _arch: Arch,
        _mode: Mode,
    }

    impl CapstoneEngine {
        /// Create an Intel-syntax engine with detail mode off.
        pub fn new(arch: Arch, mode: Mode) -> Result<Self, EngineError> {
            Self::with_options(arch, mode, arch.default_endian(), Syntax::default(), false)
        }

        /// Create an engine with an explicit x86 output syntax
        /// (Intel default, ATT optional). Detail mode stays off.
        pub fn with_syntax(arch: Arch, mode: Mode, syntax: Syntax) -> Result<Self, EngineError> {
            Self::with_options(arch, mode, arch.default_endian(), syntax, false)
        }

        /// Fully explicit constructor.
        pub fn with_options(
            arch: Arch,
            mode: Mode,
            endian: Endian,
            syntax: Syntax,
            detail_groups: bool,
        ) -> Result<Self, EngineError> {
            Self::validate(arch, mode)?;

            let cs_arch = match arch {
                Arch::X86 => CS_ARCH_X86,
                Arch::ARM => CS_ARCH_ARM,
                Arch::ARM64 => CS_ARCH_ARM64,
                Arch::MIPS => CS_ARCH_MIPS,
                Arch::PPC => CS_ARCH_PPC,
                Arch::SPARC => CS_ARCH_SPARC,
                // No RISCV mode constants exist in our binding table;
                // opening with x86-style mode bits would be UB.
                Arch::RISCV => return Err(EngineError::Unsupported(arch, mode)),
            };

            let mut cs_mode: u32 = match mode {
                Mode::Mode16 => CS_MODE_16,
                Mode::Mode32 => CS_MODE_32,
                Mode::Mode64 => CS_MODE_64,
                Mode::Thumb => CS_MODE_THUMB,
                Mode::Arm => CS_MODE_ARM,
                Mode::MicroMips => CS_MODE_MICRO | CS_MODE_32,
            };
            match endian {
                Endian::Little => cs_mode |= CS_MODE_LITTLE_ENDIAN,
                Endian::Big => cs_mode |= CS_MODE_BIG_ENDIAN,
            }

            let mut handle: CsHandle = std::ptr::null_mut();
            // FFI: cs_open writes exactly one handle on success.
            let err = unsafe { cs_open(cs_arch, cs_mode, &mut handle) };
            if err != 0 || handle.is_null() {
                return Err(EngineError::Init(format!(
                    "cs_open failed (err={err}) for {arch} / {mode:?}"
                )));
            }

            // Runtime layout check: our hand-written CsInsn must match the
            // linked library's cs_insn or field reads would be garbage.
            // Capstone 4.x/5.x cs_insn is 240–256 bytes on 64-bit targets.
            let actual = std::mem::size_of::<CsInsn>();
            if !(240..=256).contains(&actual) {
                unsafe { cs_close(&mut handle) };
                return Err(EngineError::Init(format!(
                    "cs_insn layout mismatch: expected 240-256 bytes, got {actual} \
                     (rebuild against matching capstone headers)"
                )));
            }

            let mut engine = Self {
                handle,
                want_groups: false,
                _arch: arch,
                _mode: mode,
            };

            // Detail mode off by default (speed); toggled explicitly.
            engine.apply_detail(detail_groups);
            // Syntax is meaningful only for x86; applying it elsewhere
            // would just error out inside capstone.
            if arch == Arch::X86 {
                let value = match syntax {
                    Syntax::Intel => CS_OPT_SYNTAX_INTEL,
                    Syntax::Att => CS_OPT_SYNTAX_ATT,
                };
                unsafe { cs_option(engine.handle, CS_OPT_SYNTAX, value) };
            }
            Ok(engine)
        }

        /// Enable/disable detail mode post-construction. When enabled,
        /// subsequent `disasm` calls populate [`Instr::groups`].
        /// Infallible: on unsupported option values groups stay empty.
        pub fn with_detail(mut self, on: bool) -> Self {
            self.apply_detail(on);
            self
        }

        fn apply_detail(&mut self, on: bool) {
            self.want_groups = on;
            let value = if on { CS_OPT_ON } else { CS_OPT_OFF };
            unsafe { cs_option(self.handle, CS_OPT_DETAIL, value) };
        }

        /// Single source of truth: [`Arch::supports_mode`]. RISCV stays
        /// rejected until real `CS_MODE_RISCV*` constants exist.
        fn validate(arch: Arch, mode: Mode) -> Result<(), EngineError> {
            if arch.supports_mode(mode) {
                Ok(())
            } else {
                Err(EngineError::Unsupported(arch, mode))
            }
        }

        /// Query capstone's generic group membership for one instruction.
        /// Only called when detail mode is ON (queries otherwise read
        /// uninitialized detail pointers inside capstone).
        fn collect_groups(&self, insn: &CsInsn) -> Vec<String> {
            if !self.want_groups {
                return Vec::new();
            }
            GROUP_TABLE
                .iter()
                .filter(|(group, _)| {
                    // FFI: pure predicate over valid (handle, insn) pair.
                    unsafe { cs_insn_group(self.handle, insn, *group) }
                })
                .map(|(_, name)| (*name).to_string())
                .collect()
        }
    }

    impl Drop for CapstoneEngine {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { cs_close(&mut self.handle) };
                self.handle = std::ptr::null_mut();
            }
        }
    }

    impl PreciseEngine for CapstoneEngine {
        fn disasm(
            &self,
            code: &[u8],
            va: u64,
            count: usize,
        ) -> Result<Vec<Instr>, EngineError> {
            if code.is_empty() {
                return Ok(Vec::new());
            }
            // OOM guard: Capstone allocates the whole array up front.
            // 16k instructions is plenty for one UI page / CFG chunk;
            // callers needing more should page the input.
            const MAX_BATCH: usize = 16_384;
            let count = if count == 0 { 0 } else { count.min(MAX_BATCH) };

            let mut raw: *mut CsInsn = std::ptr::null_mut();
            // FFI: allocates the insn array; ownership transfers to us on
            // count > 0. On count == 0 nothing is allocated.
            let n = unsafe {
                cs_disasm(self.handle, code.as_ptr(), code.len(), va, count, &mut raw)
            };
            if n == 0 {
                // Stop condition hit immediately: invalid byte or end of
                // input. Not an engine failure — an empty prefix is fine.
                return Ok(Vec::new());
            }
            if raw.is_null() {
                return Err(EngineError::Internal(
                    "cs_disasm returned count > 0 with NULL array".to_string(),
                ));
            }

            // Guard takes sole ownership BEFORE anything that could fail.
            let guard = InsnGuard { ptr: raw, count: n };

            // ABI sanity: every decoded instruction consumes >= 1 byte of
            // input, so n can never legitimately exceed code.len().
            if n > code.len() {
                return Err(EngineError::Internal(format!(
                    "cs_disasm reported {n} instructions for {} bytes of input \
                     (ABI mismatch)",
                    code.len()
                )));
            }

            let slice = guard.slice().ok_or_else(|| {
                EngineError::Internal("insn array vanished inside guard".to_string())
            })?;

            let mut out = Vec::with_capacity(n);
            for insn in slice.iter() {
                let size = usize::from(insn.size);
                // Bounds-check every derived access against the fixed-size
                // byte array; refuse silently-wrong data instead of OOB.
                if size == 0 || size > insn.bytes.len() {
                    return Err(EngineError::Internal(format!(
                        "cs_insn size {} outside 1..={} at {:#x}",
                        insn.size,
                        insn.bytes.len(),
                        insn.address
                    )));
                }
                let mnemonic = cstr_to_string(&insn.mnemonic);
                let op_str = cstr_to_string(&insn.op_str);
                let groups = self.collect_groups(insn);
                let kind = crate::capstone_bindings::classify_by_groups(
                    self.handle,
                    insn as *const CsInsn,
                    &mnemonic,
                );
                let branch_target = parse_branch_target(kind, &op_str);
                out.push(Instr {
                    address: insn.address,
                    size,
                    bytes: insn.bytes[..size].to_vec(),
                    mnemonic,
                    op_str,
                    groups,
                    branch_target,
                });
            }
            // guard.drop() frees the array exactly once here.
            Ok(out)
        }
    }
}

#[cfg(capstone_available)]
pub use capstone_backend::CapstoneEngine;

// ─── x86 output syntax selector ──────────────────────────────────────

/// Text rendering syntax for x86 output (Intel by default).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Syntax {
    /// `mov rbp, rsp` — destination first (default).
    #[default]
    Intel,
    /// `mov %rsp, %rbp` — source first (GNU/AT&T style).
    Att,
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof the error type is trait-object friendly and
    /// standard-error compatible (downstream feature-gating ergonomics).
    #[test]
    fn engine_error_is_std_error_send_sync() {
        fn assert_bounds<T: std::error::Error + Send + Sync + 'static>() {}
        assert_bounds::<EngineError>();
        let boxed: Box<dyn std::error::Error> = Box::new(EngineError::Unavailable);
        assert!(!boxed.to_string().is_empty());
    }

    /// cfg-independent smoke test: best_engine() always yields something
    /// callable. Empty input is Ok(empty) on real engines and
    /// Err(Unavailable) on the stub.
    #[test]
    fn best_engine_callable_on_every_config() {
        let engine = best_engine();
        match engine.disasm(&[], 0x1000, 8) {
            Ok(v) => assert!(v.is_empty()),
            Err(EngineError::Unavailable) => {}
            Err(other) => panic!("unexpected engine error: {other}"),
        }
    }

    // ---- Stub path (this is what compiles/runs on Windows CI) ----

    #[cfg(not(capstone_available))]
    mod stub_path {
        use super::*;

        #[test]
        fn stub_returns_unavailable_shape() {
            let err = StubEngine.disasm(&[0x90], 0x1000, 4).unwrap_err();
            assert!(matches!(err, EngineError::Unavailable));
        }

        #[test]
        fn best_engine_is_stub_without_capstone() {
            let engine = best_engine();
            let err = engine.disasm(&[0x55, 0x48, 0x89, 0xE5], 0x1000, 10).unwrap_err();
            assert!(matches!(err, EngineError::Unavailable));
            assert!(err.to_string().contains("unavailable"));
        }

        #[test]
        fn stub_ignores_all_inputs_deterministically() {
            for input in [&[][..], &[0xC3][..], &[0x00; 32][..]] {
                let r = StubEngine.disasm(input, 0, 0);
                assert!(matches!(r, Err(EngineError::Unavailable)));
            }
        }
    }

    // ---- Real-engine path (runs on Linux CI where libcapstone exists) ----

    #[cfg(capstone_available)]
    mod capstone_path {
        use super::*;
        use crate::engine::capstone_backend::CapstoneEngine;

        #[test]
        fn x86_64_prologue_roundtrip() {
            let e = CapstoneEngine::new(Arch::X86, Mode::Mode64).unwrap();
            let insns = e.disasm(&[0x55, 0x48, 0x89, 0xE5], 0x1000, 10).unwrap();
            assert_eq!(insns.len(), 2);
            assert_eq!(insns[0].address, 0x1000);
            assert_eq!(insns[0].size, 1);
            assert_eq!(insns[0].mnemonic, "push");
            assert_eq!(insns[0].op_str, "rbp");
            assert_eq!(insns[1].address, 0x1001);
            assert_eq!(insns[1].size, 3);
            assert_eq!(insns[1].mnemonic, "mov");
            assert_eq!(insns[1].op_str, "rbp, rsp"); // Intel default
        }

        #[test]
        fn x86_64_syscall_roundtrip() {
            let e = CapstoneEngine::new(Arch::X86, Mode::Mode64).unwrap();
            let insns = e.disasm(&[0x0F, 0x05], 0x401000, 4).unwrap();
            assert_eq!(insns.len(), 1);
            assert_eq!(insns[0].mnemonic, "syscall");
            assert_eq!(insns[0].op_str, "");
            assert_eq!(insns[0].size, 2);
        }

        #[test]
        fn arm_branch_roundtrip() {
            // FE FF FF EA = `b #-8` (infinite loop) in ARM state, LE.
            let e = CapstoneEngine::new(Arch::ARM, Mode::Arm)
                .unwrap()
                .with_detail(true);
            let insns = e.disasm(&[0xFE, 0xFF, 0xFF, 0xEA], 0x8000, 4).unwrap();
            assert_eq!(insns.len(), 1);
            assert_eq!(insns[0].mnemonic, "b");
            assert_eq!(insns[0].size, 4);
            assert!(insns[0].op_str.contains("#-8"), "op_str={}", insns[0].op_str);
            assert!(insns[0].groups.iter().any(|g| g == "jump"));
        }

        #[test]
        fn att_syntax_flips_operands() {
            let att = CapstoneEngine::with_syntax(Arch::X86, Mode::Mode64, Syntax::Att).unwrap();
            let insns = att.disasm(&[0x48, 0x89, 0xE5], 0, 1).unwrap();
            assert_eq!(insns.len(), 1);
            let op = &insns[0].op_str;
            assert!(op.contains("%rsp") && op.contains("%rbp"), "op_str={op}");
            assert!(op.find("%rsp") < op.find("%rbp"), "ATT order expected: {op}");
            assert!(!insns[0].mnemonic.starts_with('#'));
        }

        #[test]
        fn count_limit_respected() {
            let e = CapstoneEngine::new(Arch::X86, Mode::Mode64).unwrap();
            let code = [0x90; 4];
            assert_eq!(e.disasm(&code, 0, 2).unwrap().len(), 2);
            assert_eq!(e.disasm(&code, 0, 0).unwrap().len(), 4); // 0 = all
        }

        #[test]
        fn truncated_input_yields_empty_prefix_not_error() {
            let e = CapstoneEngine::new(Arch::X86, Mode::Mode64).unwrap();
            // Incomplete ModR/M and invalid opcode both decode zero insns.
            assert!(e.disasm(&[0x48, 0x89], 0, 8).unwrap().is_empty());
            assert!(e.disasm(&[0xFF, 0xFF, 0xFF], 0, 8).unwrap().is_empty());
        }

        #[test]
        fn detail_off_leaves_groups_empty() {
            let e = CapstoneEngine::new(Arch::X86, Mode::Mode64).unwrap(); // detail OFF
            let ret = e.disasm(&[0xC3], 0, 1).unwrap();
            assert_eq!(ret[0].mnemonic, "ret");
            assert!(ret[0].groups.is_empty());
        }

        #[test]
        fn unsupported_combo_rejected_upfront() {
            // RISCV has no mode constants in the hand-written table.
            assert!(matches!(
                CapstoneEngine::new(Arch::RISCV, Mode::Mode64),
                Err(EngineError::Unsupported(Arch::RISCV, Mode::Mode64))
            ));
            assert!(matches!(
                CapstoneEngine::new(Arch::ARM64, Mode::Arm),
                Err(EngineError::Unsupported(_, _))
            ));
        }

        #[test]
        fn many_instruction_batch_stays_bounded() {
            let e = CapstoneEngine::new(Arch::X86, Mode::Mode32).unwrap();
            let code = [0x90; 256];
            let insns = e.disasm(&code, 0x400000, 0).unwrap();
            assert_eq!(insns.len(), 256);
            assert!(insns.windows(2).all(|w| w[1].address == w[0].address + w[0].size as u64));
        }
    }
}
