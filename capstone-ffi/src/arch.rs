//! Architecture and mode definitions for multi-arch disassembly.

use serde::{Deserialize, Serialize};

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    /// x86 (32-bit and 64-bit)
    X86,
    /// ARM (32-bit, ARM and Thumb modes)
    ARM,
    /// ARM 64-bit (AArch64)
    ARM64,
    /// MIPS (32-bit and 64-bit)
    MIPS,
    /// PowerPC (32-bit and 64-bit)
    PPC,
    /// SPARC (32-bit and 64-bit)
    SPARC,
    /// RISC-V (32-bit and 64-bit)
    RISCV,
}

/// CPU mode / bitness for a given architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// 16-bit mode (x86 only)
    Mode16,
    /// 32-bit mode
    Mode32,
    /// 64-bit mode
    Mode64,
    /// ARM Thumb mode (ARM only)
    Thumb,
    /// ARM mode (ARM only)
    Arm,
    /// MicroMIPS mode (MIPS only)
    MicroMips,
}

/// Byte order / endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

impl Arch {
    /// Default mode for this architecture.
    pub fn default_mode(&self) -> Mode {
        match self {
            Arch::X86 => Mode::Mode64,
            Arch::ARM => Mode::Arm,
            Arch::ARM64 => Mode::Mode64,
            Arch::MIPS => Mode::Mode32,
            Arch::PPC => Mode::Mode64,
            Arch::SPARC => Mode::Mode64,
            Arch::RISCV => Mode::Mode64,
        }
    }

    /// Default endianness for this architecture.
    pub fn default_endian(&self) -> Endian {
        match self {
            Arch::X86 | Arch::ARM | Arch::ARM64 | Arch::RISCV => Endian::Little,
            Arch::MIPS | Arch::PPC | Arch::SPARC => Endian::Big,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::ARM => "ARM",
            Arch::ARM64 => "AArch64",
            Arch::MIPS => "MIPS",
            Arch::PPC => "PowerPC",
            Arch::SPARC => "SPARC",
            Arch::RISCV => "RISC-V",
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Mode16 => write!(f, "16-bit"),
            Mode::Mode32 => write!(f, "32-bit"),
            Mode::Mode64 => write!(f, "64-bit"),
            Mode::Thumb => write!(f, "Thumb"),
            Mode::Arm => write!(f, "ARM"),
            Mode::MicroMips => write!(f, "MicroMIPS"),
        }
    }
}
