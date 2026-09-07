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

    pub fn with_wildcards(
        pattern: &[(u8, bool)],
        description: &'static str,
        confidence: f32,
    ) -> Self {
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

        for (i, (pattern_byte, &must_match)) in self.bytes.iter().zip(self.mask.iter()).enumerate()
        {
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
        //
        // NOTE: deliberately NO single-byte patterns (lone `push ebp`, `push rdi`,
        // `push rbx`, `enter`, ...) here. A bare 0x55/0x53/0x57 byte occurs
        // constantly inside instruction streams and data, producing thousands of
        // bogus candidates that poison both prologue counts and recursive-descent
        // seeding. Only multi-byte, validated sequences are accepted.
        BytePattern::new(&[0x55, 0x89, 0xE5], "push ebp; mov ebp, esp", 0.95),
        // sub esp, N (frameless function)
        BytePattern::with_wildcards(
            &[(0x83, true), (0xEC, true), (0x00, false)],
            "sub esp, imm8",
            0.4,
        ),
        // sub esp, N (32-bit imm)
        BytePattern::with_wildcards(
            &[
                (0x81, true),
                (0xEC, true),
                (0x00, false),
                (0x00, false),
                (0x00, false),
                (0x00, false),
            ],
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
        BytePattern::with_wildcards(&[(0xC2, true), (0x00, false), (0x00, false)], "ret N", 0.5),
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
        //
        // NOTE: no single-byte `push rbp` (0x55) fallback — see x86_prologues().
        BytePattern::new(&[0x55, 0x48, 0x89, 0xE5], "push rbp; mov rbp, rsp", 0.95),
        // sub rsp, N
        BytePattern::with_wildcards(
            &[(0x48, true), (0x83, true), (0xEC, true), (0x00, false)],
            "sub rsp, imm8",
            0.4,
        ),
        // sub rsp, N (32-bit imm)
        BytePattern::with_wildcards(
            &[
                (0x48, true),
                (0x81, true),
                (0xEC, true),
                (0x00, false),
                (0x00, false),
                (0x00, false),
                (0x00, false),
            ],
            "sub rsp, imm32",
            0.4,
        ),
        // endbr64 (CET-enabled binaries, modern)
        BytePattern::new(&[0xF3, 0x0F, 0x1E, 0xFA], "endbr64", 0.9),
        // endbr64 + push rbp
        BytePattern::new(
            &[0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5],
            "endbr64 + prologue",
            0.99,
        ),
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
        BytePattern::with_wildcards(&[(0xC2, true), (0x00, false), (0x00, false)], "ret N", 0.5),
    ]
}

/// Prologue patterns for ARM (32-bit)
pub fn arm_prologues() -> Vec<BytePattern> {
    // ARM is little-endian by default, instructions are 4 bytes
    vec![
        // push {fp, lr}; add fp, sp, #4 (classic)
        // Little-endian: E5 2D 48 08 (push) + 08 40 A0 E1 (add)
        BytePattern::new(
            &[0x08, 0x48, 0x2D, 0xE9, 0x04, 0xB0, 0x8D, 0xE2],
            "push {fp, lr}",
            0.95,
        ),
        // push {r4-rN, lr}
        BytePattern::with_wildcards(
            &[
                (0x00, false),
                (0x40, true),
                (0x2D, true),
                (0xE9, true), // push {regs, lr}
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
            &[(0xFD, true), (0x7B, true), (0x00, false), (0xA9, true)],
            "stp x29, x30, [sp]",
            0.9,
        ),
        // sub sp, sp, #N (allocate frame)
        BytePattern::with_wildcards(
            &[(0xFF, true), (0x03, true), (0x00, false), (0xD1, true)],
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
        Architecture::Mips
        | Architecture::MipsEl
        | Architecture::Mips32LE
        | Architecture::Mips32BE
        | Architecture::Mips64LE
        | Architecture::Mips64BE => mips_prologues(),
        // RISC-V, PPC, SPARC: return empty for now
        Architecture::RiscV32
        | Architecture::RiscV64
        | Architecture::Ppc32
        | Architecture::Ppc64
        | Architecture::Ppc64LE
        | Architecture::Sparc32
        | Architecture::Sparc64 => vec![],
    }
}

/// Epilogue patterns for ARM (32-bit, little-endian; includes Thumb-2 short encodings).
///
/// Byte order is little-endian: for an instruction word `W`, bytes are stored
/// lowest halfword first. The masked `pop {regs, pc}` pattern requires the top
/// register-list byte to be exactly `0x80` (PC set, no high registers other
/// than via the dedicated `pop {fp, pc}` literal), because `BytePattern`
/// supports only whole-byte wildcards.
pub fn arm_epilogues() -> Vec<BytePattern> {
    vec![
        // pop {r0-r7 regs..., pc}: LDMIA sp!, {reglist} = 0xE8BD8xxx (low byte wildcard)
        BytePattern::with_wildcards(
            &[(0x00, false), (0x80, true), (0xBD, true), (0xE8, true)],
            "pop {regs, pc}",
            0.85,
        ),
        // pop {fp, pc}: 0xE8BD8800 -> LE bytes 00 88 BD E8
        BytePattern::new(&[0x00, 0x88, 0xBD, 0xE8], "pop {fp, pc}", 0.85),
        // bx lr: 0xE12FFF1E
        BytePattern::new(&[0x1E, 0xFF, 0x2F, 0xE1], "bx lr", 0.9),
        // bx lr (Thumb): 0x4770
        BytePattern::new(&[0x70, 0x47], "bx lr (thumb)", 0.65),
        // pop {regs, pc} (Thumb): 0xBDxx
        BytePattern::with_wildcards(
            &[(0x00, false), (0xBD, true)],
            "pop {regs, pc} (thumb)",
            0.55,
        ),
    ]
}

/// Epilogue patterns for ARM64 (little-endian)
pub fn arm64_epilogues() -> Vec<BytePattern> {
    vec![
        // ret: 0xD65F03C0
        BytePattern::new(&[0xC0, 0x03, 0x5F, 0xD6], "ret", 0.95),
    ]
}

/// Epilogue patterns for RISC-V (little-endian)
pub fn riscv_epilogues() -> Vec<BytePattern> {
    vec![
        // ret = jalr x0, ra, 0 = 0x00008067
        BytePattern::new(&[0x67, 0x80, 0x00, 0x00], "ret (jalr x0, ra)", 0.9),
        // c.ret / c.jr ra = 0x8082
        BytePattern::new(&[0x82, 0x80], "c.ret", 0.7),
    ]
}

/// Epilogue patterns for PowerPC (both byte orders; fixed 4-byte instructions)
pub fn ppc_epilogues() -> Vec<BytePattern> {
    vec![
        // blr = 0x4E800020 (big-endian storage)
        BytePattern::new(&[0x4E, 0x80, 0x00, 0x20], "blr (BE)", 0.9),
        // blr (little-endian storage, PPC64LE)
        BytePattern::new(&[0x20, 0x00, 0x80, 0x4E], "blr (LE)", 0.9),
    ]
}

/// Epilogue patterns for SPARC (big-endian instruction words, standard SPARC layout)
pub fn sparc_epilogues() -> Vec<BytePattern> {
    vec![
        // retl = jmpl %o7+8, %g0 = 0x81C3E008
        BytePattern::new(&[0x81, 0xC3, 0xE0, 0x08], "retl", 0.85),
        // ret = jmpl %i7+8, %g0 = 0x81C7E008
        BytePattern::new(&[0x81, 0xC7, 0xE0, 0x08], "ret", 0.85),
    ]
}

/// Get epilogue patterns for an architecture.
///
/// Returns verified byte patterns for x86, x86_64, MIPS (LE), ARM32/Thumb (LE),
/// ARM64 (LE), RISC-V (LE), PowerPC (BE and LE) and SPARC (BE instruction words).
/// Architectures without a verified encoding yield an empty list.
pub fn epilogues_for_arch(arch: Architecture) -> Vec<BytePattern> {
    match arch {
        Architecture::X86 => x86_epilogues(),
        Architecture::X86_64 => x86_64_epilogues(),
        Architecture::Arm | Architecture::Arm32 | Architecture::Arm32Thumb => arm_epilogues(),
        Architecture::Arm64 | Architecture::Arm64BE => arm64_epilogues(),
        Architecture::Mips
        | Architecture::MipsEl
        | Architecture::Mips32LE
        | Architecture::Mips32BE
        | Architecture::Mips64LE
        | Architecture::Mips64BE => mips_epilogues(),
        Architecture::RiscV32 | Architecture::RiscV64 => riscv_epilogues(),
        Architecture::Ppc32 | Architecture::Ppc64 | Architecture::Ppc64LE => ppc_epilogues(),
        Architecture::Sparc32 | Architecture::Sparc64 => sparc_epilogues(),
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

    #[test]
    fn no_single_byte_prologue_patterns() {
        // Single-byte "prologues" (0x55 push rbp/ebp, 0x53 push rbx, 0x57 push rdi,
        // 0xC8 enter) match thousands of mid-instruction/data locations and must
        // never be used as function seeds.
        for arch in [Architecture::X86, Architecture::X86_64] {
            for pattern in prologues_for_arch(arch) {
                assert!(
                    pattern.len() >= 2,
                    "{} prologue '{}' is only {} byte(s) long",
                    arch.as_str(),
                    pattern.description,
                    pattern.len()
                );
            }
        }
    }

    #[test]
    fn test_arm_epilogue_pop_pc() {
        let patterns = epilogues_for_arch(Architecture::Arm32);
        assert!(!patterns.is_empty());

        // pop {r4-r7, pc} = 0xE8BD80F0 -> LE F0 80 BD E8
        let data = [0xF0, 0x80, 0xBD, 0xE8];
        assert!(patterns.iter().any(|p| p.matches(&data, 0)));

        // pop {fp, pc} = 0xE8BD8800 -> LE 00 88 BD E8
        let data2 = [0x00, 0x88, 0xBD, 0xE8];
        assert!(patterns.iter().any(|p| p.matches(&data2, 0)));

        // bx lr
        let data3 = [0x1E, 0xFF, 0x2F, 0xE1];
        assert!(patterns.iter().any(|p| p.matches(&data3, 0)));
    }

    #[test]
    fn test_arm64_epilogue_ret() {
        let patterns = epilogues_for_arch(Architecture::Arm64);
        let data = [0xC0, 0x03, 0x5F, 0xD6]; // ret
        assert!(patterns.iter().any(|p| p.matches(&data, 0)));
    }

    #[test]
    fn test_riscv_epilogue_ret() {
        let patterns = epilogues_for_arch(Architecture::RiscV64);
        let data = [0x67, 0x80, 0x00, 0x00]; // ret = jalr x0, ra
        assert!(patterns.iter().any(|p| p.matches(&data, 0)));
    }

    #[test]
    fn test_ppc_epilogue_blr() {
        let patterns_be = epilogues_for_arch(Architecture::Ppc64);
        let data = [0x4E, 0x80, 0x00, 0x20]; // blr (BE)
        assert!(patterns_be.iter().any(|p| p.matches(&data, 0)));

        let patterns_le = epilogues_for_arch(Architecture::Ppc64LE);
        let data_le = [0x20, 0x00, 0x80, 0x4E]; // blr (LE)
        assert!(patterns_le.iter().any(|p| p.matches(&data_le, 0)));
    }

    #[test]
    fn test_sparc_epilogue_retl() {
        let patterns = epilogues_for_arch(Architecture::Sparc32);
        let data = [0x81, 0xC3, 0xE0, 0x08]; // retl
        assert!(patterns.iter().any(|p| p.matches(&data, 0)));
    }
}
