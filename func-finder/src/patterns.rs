//! Function prologue and epilogue patterns for various architectures

use crate::Architecture;

/// A byte pattern with wildcards
#[derive(Clone, Debug)]
pub struct BytePattern {
    /// Pattern bytes (None = wildcard)
    pub bytes: Vec<Option<u8>>,
    /// Mask for which bytes must match
    pub mask: Vec<bool>,
    /// Human-readable description
    pub description: &'static str,
    /// Confidence boost when matched (0.0 - 1.0)
    pub confidence: f32,
}

impl BytePattern {
    pub fn new(bytes: &[u8], description: &'static str, confidence: f32) -> Self {
        Self {
            bytes: bytes.iter().map(|&b| Some(b)).collect(),
            mask: vec![true; bytes.len()],
            description,
            confidence,
        }
    }

    pub fn with_wildcards(pattern: &[(u8, bool)], description: &'static str, confidence: f32) -> Self {
        Self {
            bytes: pattern.iter().map(|(b, _)| Some(*b)).collect(),
            mask: pattern.iter().map(|(_, m)| *m).collect(),
            description,
            confidence,
        }
    }

    /// Check if pattern matches at offset
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }

        for (i, (pattern_byte, &must_match)) in self.bytes.iter().zip(self.mask.iter()).enumerate() {
            if must_match {
                if let Some(pb) = pattern_byte {
                    if data[offset + i] != *pb {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Prologue patterns for x86 (32-bit)
pub fn x86_prologues() -> Vec<BytePattern> {
    vec![
        // push ebp; mov ebp, esp (classic)
        BytePattern::new(&[0x55, 0x89, 0xE5], "push ebp; mov ebp, esp", 0.95),
        // push ebp (alone, common start)
        BytePattern::new(&[0x55], "push ebp", 0.3),
        // sub esp, N (frameless function)
        BytePattern::with_wildcards(
            &[(0x83, true), (0xEC, true), (0x00, false)],
            "sub esp, imm8",
            0.4,
        ),
        // sub esp, N (32-bit imm)
        BytePattern::with_wildcards(
            &[(0x81, true), (0xEC, true), (0x00, false), (0x00, false), (0x00, false), (0x00, false)],
            "sub esp, imm32",
            0.4,
        ),
        // int 3 padding followed by code
        BytePattern::new(&[0xCC, 0x55, 0x89, 0xE5], "int3 + prologue", 0.98),
        // mov edi, edi; push ebp (hotpatch prologue)
        BytePattern::new(&[0x8B, 0xFF, 0x55, 0x8B, 0xEC], "hotpatch prologue", 0.95),
    ]
}

/// Epilogue patterns for x86
pub fn x86_epilogues() -> Vec<BytePattern> {
    vec![
        // ret
        BytePattern::new(&[0xC3], "ret", 0.5),
        // ret N
        BytePattern::with_wildcards(
            &[(0xC2, true), (0x00, false), (0x00, false)],
            "ret N",
            0.5,
        ),
        // pop ebp; ret
        BytePattern::new(&[0x5D, 0xC3], "pop ebp; ret", 0.8),
        // leave; ret
        BytePattern::new(&[0xC9, 0xC3], "leave; ret", 0.9),
        // pop ebp; ret N
        BytePattern::with_wildcards(
            &[(0x5D, true), (0xC2, true), (0x00, false), (0x00, false)],
            "pop ebp; ret N",
            0.85,
        ),
    ]
}

/// Prologue patterns for x86_64
pub fn x86_64_prologues() -> Vec<BytePattern> {
    vec![
        // push rbp; mov rbp, rsp (System V + Win64 common)
        BytePattern::new(&[0x55, 0x48, 0x89, 0xE5], "push rbp; mov rbp, rsp", 0.95),
        // push rbp alone
        BytePattern::new(&[0x55], "push rbp", 0.3),
        // sub rsp, N
        BytePattern::with_wildcards(
            &[(0x48, true), (0x83, true), (0xEC, true), (0x00, false)],
            "sub rsp, imm8",
            0.4,
        ),
        // sub rsp, N (32-bit imm)
        BytePattern::with_wildcards(
            &[(0x48, true), (0x81, true), (0xEC, true), (0x00, false), (0x00, false), (0x00, false), (0x00, false)],
            "sub rsp, imm32",
            0.4,
        ),
        // endbr64 (CET-enabled binaries, modern)
        BytePattern::new(&[0xF3, 0x0F, 0x1E, 0xFA], "endbr64", 0.9),
        // endbr64 + push rbp
        BytePattern::new(&[0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5], "endbr64 + prologue", 0.99),
        // int3 padding + prologue
        BytePattern::new(&[0xCC, 0x55, 0x48, 0x89, 0xE5], "int3 + prologue", 0.98),
    ]
}

/// Epilogue patterns for x86_64
pub fn x86_64_epilogues() -> Vec<BytePattern> {
    vec![
        // ret
        BytePattern::new(&[0xC3], "ret", 0.5),
        // pop rbp; ret
        BytePattern::new(&[0x5D, 0xC3], "pop rbp; ret", 0.8),
        // leave; ret
        BytePattern::new(&[0xC9, 0xC3], "leave; ret", 0.9),
        // ret N
        BytePattern::with_wildcards(
            &[(0xC2, true), (0x00, false), (0x00, false)],
            "ret N",
            0.5,
        ),
    ]
}

/// Prologue patterns for ARM (32-bit)
pub fn arm_prologues() -> Vec<BytePattern> {
    // ARM is little-endian by default, instructions are 4 bytes
    vec![
        // push {fp, lr}; add fp, sp, #4 (classic)
        // Little-endian: E5 2D 48 08 (push) + 08 40 A0 E1 (add)
        BytePattern::new(&[0x08, 0x48, 0x2D, 0xE9, 0x04, 0xB0, 0x8D, 0xE2], "push {fp, lr}", 0.95),
        // push {r4-rN, lr}
        BytePattern::with_wildcards(
            &[
                (0x00, false), (0x40, true), (0x2D, true), (0xE9, true), // push {regs, lr}
            ],
            "push {regs, lr}",
            0.7,
        ),
    ]
}

/// Prologue patterns for ARM64
pub fn arm64_prologues() -> Vec<BytePattern> {
    vec![
        // stp x29, x30, [sp, #-N]! (save fp and lr)
        BytePattern::with_wildcards(
            &[
                (0xFD, true), (0x7B, true), (0x00, false), (0xA9, true),
            ],
            "stp x29, x30, [sp]",
            0.9,
        ),
        // sub sp, sp, #N (allocate frame)
        BytePattern::with_wildcards(
            &[
                (0xFF, true), (0x03, true), (0x00, false), (0xD1, true),
            ],
            "sub sp, sp, imm",
            0.5,
        ),
    ]
}

/// Prologue patterns for MIPS (little-endian)
pub fn mips_prologues() -> Vec<BytePattern> {
    vec![
        // addiu sp, sp, -N (LE: 0x27BDxxxx)
        BytePattern::new(&[0xBD, 0x27], "addiu sp,sp,-N (LE)", 0.7),
        // sw ra, N(sp) (LE: 0xAFBFxxxx)
        BytePattern::new(&[0xBF, 0xAF], "sw ra,N(sp) (LE)", 0.8),
    ]
}

/// Epilogue patterns for MIPS (little-endian)
pub fn mips_epilogues() -> Vec<BytePattern> {
    vec![
        // jr ra (LE: 0x03E00008)
        BytePattern::new(&[0x08, 0x00, 0xE0, 0x03], "jr ra (LE)", 0.9),
    ]
}

/// Get prologue patterns for an architecture
pub fn prologues_for_arch(arch: Architecture) -> Vec<BytePattern> {
    match arch {
        Architecture::X86 => x86_prologues(),
        Architecture::X86_64 => x86_64_prologues(),
        Architecture::Arm | Architecture::Arm32 | Architecture::Arm32Thumb => arm_prologues(),
        Architecture::Arm64 | Architecture::Arm64BE => arm64_prologues(),
        Architecture::Mips | Architecture::MipsEl
        | Architecture::Mips32LE | Architecture::Mips32BE
        | Architecture::Mips64LE | Architecture::Mips64BE => mips_prologues(),
        // RISC-V, PPC, SPARC: return empty for now
        Architecture::RiscV32 | Architecture::RiscV64
        | Architecture::Ppc32 | Architecture::Ppc64 | Architecture::Ppc64LE
        | Architecture::Sparc32 | Architecture::Sparc64 => vec![],
    }
}

/// Get epilogue patterns for an architecture
pub fn epilogues_for_arch(arch: Architecture) -> Vec<BytePattern> {
    match arch {
        Architecture::X86 => x86_epilogues(),
        Architecture::X86_64 => x86_64_epilogues(),
        Architecture::Mips | Architecture::MipsEl
        | Architecture::Mips32LE | Architecture::Mips32BE
        | Architecture::Mips64LE | Architecture::Mips64BE => mips_epilogues(),
        // ARM, RISC-V, PPC, SPARC epilogues: TODO
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_prologue_match() {
        let patterns = x86_prologues();
        let data = [0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10]; // push ebp; mov ebp, esp; sub esp, 0x10

        assert!(patterns[0].matches(&data, 0));
    }

    #[test]
    fn test_x86_64_prologue_match() {
        let patterns = x86_64_prologues();
        let data = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];

        assert!(patterns[0].matches(&data, 0));
    }

    #[test]
    fn test_wildcard_pattern() {
        let pattern = BytePattern::with_wildcards(
            &[(0x83, true), (0xEC, true), (0x00, false)],
            "sub esp, imm8",
            0.4,
        );

        let data = [0x83, 0xEC, 0x10]; // sub esp, 0x10
        assert!(pattern.matches(&data, 0));

        let data2 = [0x83, 0xEC, 0xFF]; // sub esp, 0xFF
        assert!(pattern.matches(&data2, 0));
    }
}
