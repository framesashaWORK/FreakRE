//! # Architecture Registry for FreakRE IR
//!
//! Defines all supported architectures and their properties.
//! Each architecture can provide a lifter to convert native instructions → IR.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported target architectures (25 total)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    // ─── x86 family ──────────────────────────────────────
    X86,          // 32-bit x86 (IA-32)
    X86_64,       // 64-bit x86 (AMD64/Intel 64)

    // ─── ARM family ──────────────────────────────────────
    Arm32,        // ARM 32-bit (ARMv7-A, ARMv8-A AArch32)
    Arm32Thumb,   // ARM Thumb/Thumb-2 mode
    Arm64,        // AArch64 / ARMv8-A 64-bit
    Arm64BE,      // AArch64 big-endian (rare but exists)

    // ─── MIPS family ─────────────────────────────────────
    Mips32LE,     // MIPS32 little-endian
    Mips32BE,     // MIPS32 big-endian
    Mips64LE,     // MIPS64 little-endian
    Mips64BE,     // MIPS64 big-endian

    // ─── RISC-V ──────────────────────────────────────────
    RiscV32,      // RV32I/M/A/F/C
    RiscV64,      // RV64I/M/A/F/D/C

    // ─── PowerPC ─────────────────────────────────────────
    Ppc32,        // PowerPC 32-bit (big-endian)
    Ppc64,        // PowerPC 64-bit (big-endian)
    Ppc64LE,      // PowerPC 64-bit little-endian (POWER8+)

    // ─── SPARC ───────────────────────────────────────────
    Sparc32,      // SPARC V8/V9 32-bit
    Sparc64,      // SPARC V9 64-bit

    // ─── Lightweight / Bytecode VMs ─────────────────────
    Ebpf,         // Linux eBPF (stack-based VM, 64 fixed instructions)
    Wasm32,       // WebAssembly 32-bit (stack-based VM)
    Wasm64,       // WebAssembly 64-bit (memory64 proposal)
    Dalvik,       // Android Dalvik VM (register-based, 16-bit regs)
    Chip8,        // CHIP-8 toy VM (35 opcodes, simplest possible)

    // ─── Microcontrollers / Embedded ─────────────────────
    Avr,          // Atmel AVR 8-bit (Arduino Uno, ATmega)
    Msp430,       // TI MSP430 16-bit RISC MCU
    Mos6502,      // MOS Technology 6502 (NES, C64, Apple II)
}

impl Arch {
    /// Human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            Arch::X86 => "x86 (IA-32)",
            Arch::X86_64 => "x86-64 (AMD64)",
            Arch::Arm32 => "ARM32",
            Arch::Arm32Thumb => "ARM32 Thumb",
            Arch::Arm64 => "AArch64",
            Arch::Arm64BE => "AArch64 BE",
            Arch::Mips32LE => "MIPS32 LE",
            Arch::Mips32BE => "MIPS32 BE",
            Arch::Mips64LE => "MIPS64 LE",
            Arch::Mips64BE => "MIPS64 BE",
            Arch::RiscV32 => "RISC-V 32",
            Arch::RiscV64 => "RISC-V 64",
            Arch::Ppc32 => "PowerPC 32",
            Arch::Ppc64 => "PowerPC 64",
            Arch::Ppc64LE => "PowerPC 64 LE",
            Arch::Sparc32 => "SPARC 32",
            Arch::Sparc64 => "SPARC 64",
            Arch::Ebpf => "eBPF",
            Arch::Wasm32 => "WebAssembly 32",
            Arch::Wasm64 => "WebAssembly 64",
            Arch::Dalvik => "Dalvik (Android)",
            Arch::Chip8 => "CHIP-8",
            Arch::Avr => "AVR 8-bit",
            Arch::Msp430 => "MSP430 16-bit",
            Arch::Mos6502 => "MOS 6502",
        }
    }

    /// Is this a 64-bit architecture?
    pub fn is_64bit(&self) -> bool {
        matches!(self,
            Arch::X86_64 | Arch::Arm64 | Arch::Arm64BE |
            Arch::Mips64LE | Arch::Mips64BE |
            Arch::RiscV64 | Arch::Ppc64 | Arch::Ppc64LE |
            Arch::Sparc64 | Arch::Wasm64 | Arch::Ebpf
        )
    }

    /// Is this little-endian?
    pub fn is_little_endian(&self) -> bool {
        matches!(self,
            Arch::X86 | Arch::X86_64 |
            Arch::Arm32 | Arch::Arm32Thumb | Arch::Arm64 |
            Arch::Mips32LE | Arch::Mips64LE |
            Arch::RiscV32 | Arch::RiscV64 |
            Arch::Ppc64LE |
            Arch::Ebpf | Arch::Wasm32 | Arch::Wasm64 |
            Arch::Dalvik | Arch::Chip8 |
            Arch::Avr | Arch::Msp430 | Arch::Mos6502
        )
    }

    /// Default pointer size in bytes
    pub fn pointer_size(&self) -> usize {
        match self {
            Arch::Avr | Arch::Mos6502 | Arch::Chip8 => 2,
            Arch::Msp430 | Arch::Dalvik => 2,
            _ if self.is_64bit() => 8,
            _ => 4,
        }
    }

    /// Instruction alignment (minimum address increment)
    pub fn instruction_alignment(&self) -> usize {
        match self {
            Arch::Arm32 | Arch::Arm64 | Arch::Arm64BE => 4,
            Arch::Arm32Thumb => 2,
            Arch::Mips32LE | Arch::Mips32BE | Arch::Mips64LE | Arch::Mips64BE => 4,
            Arch::RiscV32 | Arch::RiscV64 => 2, // compressed instructions
            Arch::Ppc32 | Arch::Ppc64 | Arch::Ppc64LE => 4,
            Arch::Sparc32 | Arch::Sparc64 => 4,
            Arch::Ebpf => 8,     // eBPF instructions are 8 bytes
            Arch::Wasm32 | Arch::Wasm64 => 1, // variable-length
            Arch::Dalvik => 2,   // Dalvik instructions are 16-bit aligned
            Arch::Chip8 => 2,    // CHIP-8 instructions are 2 bytes
            Arch::Avr => 2,      // AVR most instructions are 16-bit (some 32-bit)
            Arch::Msp430 => 2,   // MSP430 instructions are 16-bit aligned
            Arch::Mos6502 => 1,  // 6502 variable-length (1-3 bytes)
            _ => 1, // x86 variable-length
        }
    }

    /// Does this arch have fixed-length instructions?
    pub fn is_fixed_length(&self) -> bool {
        !matches!(self, Arch::X86 | Arch::X86_64 | Arch::Wasm32 | Arch::Wasm64 | Arch::Mos6502)
    }

    /// Fixed instruction length in bytes (None for variable-length)
    pub fn instruction_length(&self) -> Option<usize> {
        if self.is_fixed_length() {
            Some(self.instruction_alignment())
        } else {
            None
        }
    }

    /// Number of general-purpose registers
    pub fn num_gpr(&self) -> usize {
        match self {
            Arch::X86 => 8,
            Arch::X86_64 => 16,
            Arch::Arm32 | Arch::Arm32Thumb => 16,
            Arch::Arm64 | Arch::Arm64BE => 31, // x0-x30 (SP is separate)
            Arch::Mips32LE | Arch::Mips32BE => 32,
            Arch::Mips64LE | Arch::Mips64BE => 32,
            Arch::RiscV32 | Arch::RiscV64 => 32,
            Arch::Ppc32 => 32,
            Arch::Ppc64 | Arch::Ppc64LE => 32,
            Arch::Sparc32 => 32, // 8 global + 8 out + 8 local + 8 in (windowed)
            Arch::Sparc64 => 32,
            Arch::Ebpf => 11,    // R0-R10 (R10 is read-only frame pointer)
            Arch::Wasm32 | Arch::Wasm64 => 0, // stack-based, no GPRs
            Arch::Dalvik => 16,  // v0-v15 per method (register windowing)
            Arch::Chip8 => 16,   // V0-VF
            Arch::Avr => 32,     // r0-r31
            Arch::Msp430 => 16,  // R0-R15
            Arch::Mos6502 => 6,  // A, X, Y, S, P, PC
        }
    }

    /// Try to detect architecture from ELF e_machine field
    pub fn from_elf_machine(machine: u16) -> Option<Self> {
        match machine {
            0x03 => Some(Arch::X86),
            0x3E => Some(Arch::X86_64),
            0x28 => Some(Arch::Arm32),
            0xB7 => Some(Arch::Arm64),
            0x08 => Some(Arch::Mips32BE), // or LE depending on EI_DATA
            0xF3 => Some(Arch::RiscV32), // RISC-V; distinguish 32/64 by ELF class (EI_CLASS)
            // Note: RiscV64 shares e_machine=0xF3 with RiscV32.
            // Callers should check EI_CLASS to differentiate.
            // This match arm intentionally returns RiscV32 as default;
            // use from_elf_machine_with_class() for accurate detection.
            0x14 => Some(Arch::Ppc32),
            0x15 => Some(Arch::Ppc64),
            0x02 => Some(Arch::Sparc32),
            0x2B => Some(Arch::Sparc64),
            0xF7 => Some(Arch::Ebpf),    // EM_BPF (eBPF)
            0x53 => Some(Arch::Avr),     // EM_AVR
            0x69 => Some(Arch::Msp430),  // EM_MSP430
            _ => None,
        }
    }

    /// Try to detect from Mach-O cpu_type
    pub fn from_macho_cputype(cpu_type: u32) -> Option<Self> {
        const CPU_TYPE_X86: u32 = 7;
        const CPU_TYPE_X86_64: u32 = 0x01000007;
        const CPU_TYPE_ARM: u32 = 12;
        const CPU_TYPE_ARM64: u32 = 0x0100000C;
        const CPU_TYPE_POWERPC: u32 = 18;
        const CPU_TYPE_POWERPC64: u32 = 0x01000012;
        const CPU_TYPE_SPARC: u32 = 14;

        match cpu_type {
            CPU_TYPE_X86 => Some(Arch::X86),
            CPU_TYPE_X86_64 => Some(Arch::X86_64),
            CPU_TYPE_ARM => Some(Arch::Arm32),
            CPU_TYPE_ARM64 => Some(Arch::Arm64),
            CPU_TYPE_POWERPC => Some(Arch::Ppc32),
            CPU_TYPE_POWERPC64 => Some(Arch::Ppc64),
            CPU_TYPE_SPARC => Some(Arch::Sparc32),
            _ => None,
        }
    }

    /// Try to detect from PE Machine field
    pub fn from_pe_machine(machine: u16) -> Option<Self> {
        match machine {
            0x014C => Some(Arch::X86),       // IMAGE_FILE_MACHINE_I386
            0x8664 => Some(Arch::X86_64),    // IMAGE_FILE_MACHINE_AMD64
            0x01C0 => Some(Arch::Arm32),     // IMAGE_FILE_MACHINE_ARM
            0xAA64 => Some(Arch::Arm64),     // IMAGE_FILE_MACHINE_ARM64
            0x0166 => Some(Arch::Mips32LE),  // IMAGE_FILE_MACHINE_R4000
            0x01F0 => Some(Arch::Ppc32),     // IMAGE_FILE_MACHINE_POWERPC
            0x0200 => Some(Arch::Sparc32),   // IMAGE_FILE_MACHINE_SPARC (unofficial)
            _ => None,
        }
    }

    /// Is this a bytecode/VM architecture (not native CPU)?
    pub fn is_bytecode(&self) -> bool {
        matches!(self,
            Arch::Ebpf | Arch::Wasm32 | Arch::Wasm64 |
            Arch::Dalvik | Arch::Chip8
        )
    }

    /// Is this a microcontroller/embedded architecture?
    pub fn is_embedded(&self) -> bool {
        matches!(self,
            Arch::Avr | Arch::Msp430 | Arch::Mos6502 | Arch::Chip8
        )
    }

    /// Try to detect from magic bytes
    pub fn from_magic(magic: &[u8]) -> Option<Self> {
        if magic.len() < 4 {
            return None;
        }
        // WebAssembly magic: \0asm
        if magic.starts_with(b"\x00asm") {
            return Some(Arch::Wasm32);
        }
        // eBPF programs don't have standard magic, but ELF eBPF does
        // CHIP-8 programs don't have magic either
        None
    }

    /// All supported architectures
    pub fn all() -> &'static [Arch] {
        &[
            Arch::X86, Arch::X86_64,
            Arch::Arm32, Arch::Arm32Thumb, Arch::Arm64, Arch::Arm64BE,
            Arch::Mips32LE, Arch::Mips32BE, Arch::Mips64LE, Arch::Mips64BE,
            Arch::RiscV32, Arch::RiscV64,
            Arch::Ppc32, Arch::Ppc64, Arch::Ppc64LE,
            Arch::Sparc32, Arch::Sparc64,
            // Lightweight / VM
            Arch::Ebpf, Arch::Wasm32, Arch::Wasm64, Arch::Dalvik, Arch::Chip8,
            // Embedded
            Arch::Avr, Arch::Msp430, Arch::Mos6502,
        ]
    }

    /// Lightweight architectures only (easy to analyse)
    pub fn lightweight() -> &'static [Arch] {
        &[
            Arch::Ebpf, Arch::Wasm32, Arch::Wasm64,
            Arch::Dalvik, Arch::Chip8,
            Arch::Avr, Arch::Msp430, Arch::Mos6502,
        ]
    }

    /// Check if a lifter is implemented for this architecture
    pub fn has_lifter(&self) -> bool {
        matches!(self,
            Arch::X86 | Arch::X86_64 |
            Arch::Arm32 | Arch::Arm32Thumb | Arch::Arm64 |
            Arch::Mips32LE | Arch::Mips32BE | Arch::Mips64LE | Arch::Mips64BE |
            Arch::RiscV32 | Arch::RiscV64
        )
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_architectures_count() {
        assert_eq!(Arch::all().len(), 25);
    }

    #[test]
    fn test_lightweight_architectures() {
        let light = Arch::lightweight();
        assert_eq!(light.len(), 8);
        for arch in light {
            assert!(arch.is_bytecode() || arch.is_embedded());
        }
    }

    #[test]
    fn test_pointer_sizes() {
        assert_eq!(Arch::X86.pointer_size(), 4);
        assert_eq!(Arch::X86_64.pointer_size(), 8);
        assert_eq!(Arch::Arm32.pointer_size(), 4);
        assert_eq!(Arch::Arm64.pointer_size(), 8);
        assert_eq!(Arch::RiscV64.pointer_size(), 8);
        assert_eq!(Arch::Ebpf.pointer_size(), 8);
        assert_eq!(Arch::Wasm32.pointer_size(), 4);
        assert_eq!(Arch::Chip8.pointer_size(), 2);
        assert_eq!(Arch::Mos6502.pointer_size(), 2);
    }

    #[test]
    fn test_endianness() {
        assert!(Arch::X86.is_little_endian());
        assert!(Arch::X86_64.is_little_endian());
        assert!(!Arch::Mips32BE.is_little_endian());
        assert!(Arch::Mips32LE.is_little_endian());
        assert!(!Arch::Ppc32.is_little_endian());
        assert!(Arch::Ppc64LE.is_little_endian());
        assert!(Arch::Ebpf.is_little_endian());
        assert!(Arch::Wasm32.is_little_endian());
    }

    #[test]
    fn test_fixed_length() {
        assert!(!Arch::X86.is_fixed_length());
        assert!(!Arch::X86_64.is_fixed_length());
        assert!(Arch::Arm32.is_fixed_length());
        assert!(Arch::Arm64.is_fixed_length());
        assert!(Arch::Mips32LE.is_fixed_length());
        assert!(Arch::RiscV32.is_fixed_length());
        assert!(Arch::Ebpf.is_fixed_length());
        assert!(!Arch::Wasm32.is_fixed_length());
        assert!(Arch::Chip8.is_fixed_length());
        assert!(!Arch::Mos6502.is_fixed_length());
    }

    #[test]
    fn test_bytecode_detection() {
        assert!(Arch::Ebpf.is_bytecode());
        assert!(Arch::Wasm32.is_bytecode());
        assert!(Arch::Dalvik.is_bytecode());
        assert!(Arch::Chip8.is_bytecode());
        assert!(!Arch::X86.is_bytecode());
        assert!(!Arch::Avr.is_bytecode());
    }

    #[test]
    fn test_embedded_detection() {
        assert!(Arch::Avr.is_embedded());
        assert!(Arch::Msp430.is_embedded());
        assert!(Arch::Mos6502.is_embedded());
        assert!(Arch::Chip8.is_embedded());
        assert!(!Arch::X86.is_embedded());
        assert!(!Arch::Ebpf.is_embedded());
    }

    #[test]
    fn test_pe_machine_detection() {
        assert_eq!(Arch::from_pe_machine(0x014C), Some(Arch::X86));
        assert_eq!(Arch::from_pe_machine(0x8664), Some(Arch::X86_64));
        assert_eq!(Arch::from_pe_machine(0xAA64), Some(Arch::Arm64));
        assert_eq!(Arch::from_pe_machine(0xFFFF), None);
    }

    #[test]
    fn test_elf_machine_detection() {
        assert_eq!(Arch::from_elf_machine(0x03), Some(Arch::X86));
        assert_eq!(Arch::from_elf_machine(0x3E), Some(Arch::X86_64));
        assert_eq!(Arch::from_elf_machine(0xB7), Some(Arch::Arm64));
        assert_eq!(Arch::from_elf_machine(0xF7), Some(Arch::Ebpf));
        assert_eq!(Arch::from_elf_machine(0x53), Some(Arch::Avr));
        assert_eq!(Arch::from_elf_machine(0x69), Some(Arch::Msp430));
    }

    #[test]
    fn test_wasm_magic_detection() {
        assert_eq!(Arch::from_magic(b"\x00asm\x01\x00\x00\x00"), Some(Arch::Wasm32));
        assert_eq!(Arch::from_magic(b"\x7fELF"), None);
        assert_eq!(Arch::from_magic(b"MZ"), None);
    }

    #[test]
    fn test_display_names() {
        assert_eq!(Arch::X86_64.display_name(), "x86-64 (AMD64)");
        assert_eq!(Arch::Arm64.display_name(), "AArch64");
        assert_eq!(Arch::RiscV64.display_name(), "RISC-V 64");
        assert_eq!(Arch::Ebpf.display_name(), "eBPF");
        assert_eq!(Arch::Wasm32.display_name(), "WebAssembly 32");
        assert_eq!(Arch::Dalvik.display_name(), "Dalvik (Android)");
        assert_eq!(Arch::Chip8.display_name(), "CHIP-8");
        assert_eq!(Arch::Avr.display_name(), "AVR 8-bit");
        assert_eq!(Arch::Msp430.display_name(), "MSP430 16-bit");
        assert_eq!(Arch::Mos6502.display_name(), "MOS 6502");
    }

    #[test]
    fn test_register_counts() {
        assert_eq!(Arch::Ebpf.num_gpr(), 11);
        assert_eq!(Arch::Wasm32.num_gpr(), 0); // stack-based
        assert_eq!(Arch::Dalvik.num_gpr(), 16);
        assert_eq!(Arch::Chip8.num_gpr(), 16);
        assert_eq!(Arch::Avr.num_gpr(), 32);
        assert_eq!(Arch::Msp430.num_gpr(), 16);
        assert_eq!(Arch::Mos6502.num_gpr(), 6);
    }

    #[test]
    fn test_has_lifter_matches_registry() {
        // Thumb has a registry-backed lifter and must be reported as such.
        assert!(Arch::Arm32Thumb.has_lifter());
        assert!(Arch::Arm32.has_lifter());
        assert!(Arch::Arm64.has_lifter());
        assert!(!Arch::Arm64BE.has_lifter());
        use crate::lifter::LifterRegistry;
        assert!(LifterRegistry::get("arm32_thumb").is_some());
        for key in LifterRegistry::supported_architectures() {
            assert!(
                LifterRegistry::get(key).is_some(),
                "registry advertises {} but get() fails",
                key
            );
        }
    }
}
