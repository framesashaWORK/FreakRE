//! Lifter trait — converts machine code into IR.
//!
//! Each architecture implements the `Lifter` trait, translating its
//! instruction set into the universal IR.

use crate::ir::{IrFunction, IrProgram};
use thiserror::Error;

/// Errors that can occur during lifting.
#[derive(Debug, Error)]
pub enum LifterError {
    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("Invalid instruction at offset 0x{0:X}: {1}")]
    InvalidInstruction(u64, String),

    #[error("Unsupported instruction: {0}")]
    UnsupportedInstruction(String),

    #[error("Lifting failed at offset 0x{0:X}")]
    LiftFailed(u64),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for architecture-specific lifters.
///
/// A lifter translates machine code (bytes) into IR functions.
/// Each architecture implements this trait with its own semantics.
pub trait Lifter: Send + Sync {
    /// Architecture name (e.g., "x86", "arm64").
    fn arch_name(&self) -> &str;

    /// Lift a code region into a single IR function.
    ///
    /// `code` is the raw machine code bytes.
    /// `base_address` is the virtual address of the first byte.
    /// `function_name` is the name to assign to the resulting function.
    fn lift_function(
        &self,
        code: &[u8],
        base_address: u64,
        function_name: &str,
    ) -> Result<IrFunction, LifterError>;

    /// Lift an entire binary into an IR program.
    ///
    /// This is a convenience method that lifts all executable sections.
    /// Default implementation lifts a single function; override for
    /// multi-function binaries.
    fn lift_program(&self, code: &[u8], base_address: u64) -> Result<IrProgram, LifterError> {
        let func = self.lift_function(code, base_address, "_start")?;
        let mut program = IrProgram::new();
        program.add_function(func);
        Ok(program)
    }

    /// Maximum number of instructions to lift per function (safety limit).
    fn max_instructions(&self) -> usize {
        100_000
    }
}

/// Clamp a caller-supplied base address so that `base + offset` for any
/// `offset <= code_len` — plus the small per-instruction displacements added
/// downstream (`address + 4`, `address + insn_len`, …) — can never overflow
/// `u64`.
///
/// `base_address` is public-API input; a hostile value near `u64::MAX` would
/// otherwise panic every `base + offset` site in debug builds. Legitimate
/// bases are unaffected (`min` is a no-op for them).
pub(crate) fn clamp_base_address(base_address: u64, code_len: usize) -> u64 {
    // 64 KiB of headroom covers all downstream `address + small_const`
    // displacements (they are byte-to-single-KB instruction immediates).
    const HEADROOM: u64 = 64 * 1024;
    let max_base = u64::MAX
        .saturating_sub(code_len as u64)
        .saturating_sub(HEADROOM);
    base_address.min(max_base)
}

/// Registry of available lifters.
///
/// Use this to get the appropriate lifter for a given architecture.
pub struct LifterRegistry;

impl LifterRegistry {
    /// Get a lifter for the specified architecture.
    ///
    /// Currently implemented: x86, x86_64, arm32, arm64.
    /// Other architectures have prologue detection in func-finder
    /// but IR lifters are not yet implemented.
    pub fn get(arch: &str) -> Option<Box<dyn Lifter>> {
        match arch.to_lowercase().as_str() {
            "x86" | "x86_32" | "i386" => Some(Box::new(crate::x86_lifter::X86Lifter::new(false))),
            "x86_64" | "x64" | "amd64" => Some(Box::new(crate::x86_lifter::X86Lifter::new(true))),
            "arm" | "arm32" | "armv7" => {
                Some(Box::new(crate::arm_lifter::ArmLifter::new(false, false)))
            }
            "arm32_thumb" | "thumb" => {
                Some(Box::new(crate::arm_lifter::ArmLifter::new(false, true)))
            }
            "arm64" | "aarch64" | "armv8" => {
                Some(Box::new(crate::arm_lifter::ArmLifter::new(true, false)))
            }
            "mips" | "mips32" | "mips32le" => {
                Some(Box::new(crate::mips_lifter::MipsLifter::new(false)))
            }
            "mips64" | "mips64le" => Some(Box::new(crate::mips_lifter::MipsLifter::new(true))),
            "mips32be" => Some(Box::new(crate::mips_lifter::MipsLifter::new(false))),
            "mips64be" => Some(Box::new(crate::mips_lifter::MipsLifter::new(true))),
            "riscv32" | "riscv" => Some(Box::new(crate::riscv_lifter::RiscvLifter::new(false))),
            "riscv64" => Some(Box::new(crate::riscv_lifter::RiscvLifter::new(true))),
            _ => None,
        }
    }

    /// List architectures with implemented IR lifters.
    pub fn supported_architectures() -> Vec<&'static str> {
        vec![
            "x86",
            "x86_64",
            "arm32",
            "arm32_thumb",
            "arm64",
            "mips32",
            "mips64",
            "riscv32",
            "riscv64",
        ]
    }

    /// List all architectures with at least prologue detection.
    pub fn all_detectable_architectures() -> Vec<&'static str> {
        vec![
            "x86",
            "x86_64",
            "arm32",
            "arm32_thumb",
            "arm64",
            "arm64be",
            "mips32le",
            "mips32be",
            "mips64le",
            "mips64be",
            "riscv32",
            "riscv64",
            "ppc32",
            "ppc64",
            "ppc64le",
            "sparc32",
            "sparc64",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_x86() {
        assert!(LifterRegistry::get("x86").is_some());
        assert!(LifterRegistry::get("x86_64").is_some());
        assert!(LifterRegistry::get("amd64").is_some());
        assert!(LifterRegistry::get("unknown").is_none());
    }

    #[test]
    fn test_clamp_base_address() {
        // Legitimate bases pass through untouched.
        assert_eq!(super::clamp_base_address(0x1400_1000, 0x200), 0x1400_1000);
        assert_eq!(super::clamp_base_address(0, 0), 0);
        // Hostile base near u64::MAX is clamped so base + len + 64K fits.
        let clamped = super::clamp_base_address(u64::MAX, 8);
        assert!(clamped.checked_add(8 + 64 * 1024).is_some());
    }
}
