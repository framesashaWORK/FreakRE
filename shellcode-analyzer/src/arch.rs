//! Architecture auto-detection for raw / embedded shellcode.
//!
//! Sniffs the binary for the first bytes that disambiguate between
//! x86, x86_64, ARM (32-bit LE/BE) and AArch64. The detector scores
//! each candidate on specific instruction-level indicators and returns
//! the most likely architecture with a confidence value.

use serde::{Deserialize, Serialize};

/// Detected architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X86,
    X86_64,
    ArmLe,
    ArmBe,
    AArch64Le,
    AArch64Be,
    Unknown,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::ArmLe => write!(f, "ARM-LE"),
            Self::ArmBe => write!(f, "ARM-BE"),
            Self::AArch64Le => write!(f, "AArch64-LE"),
            Self::AArch64Be => write!(f, "AArch64-BE"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl Arch {
    pub fn bitness(self) -> u8 {
        match self {
            Self::X86 | Self::ArmLe | Self::ArmBe => 32,
            Self::X86_64 | Self::AArch64Le | Self::AArch64Be => 64,
            Self::Unknown => 0,
        }
    }
    pub fn is_little_endian(self) -> Option<bool> {
        match self {
            Self::X86 | Self::X86_64 | Self::ArmLe | Self::AArch64Le => Some(true),
            Self::ArmBe | Self::AArch64Be => Some(false),
            Self::Unknown => None,
        }
    }
}

/// Result of architecture detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchDetection {
    pub arch: Arch,
    pub confidence: f32,
    /// Why the detector picked this architecture.
    pub indicators: Vec<String>,
}

/// Detect architecture of a raw binary blob.
pub fn detect_architecture(data: &[u8]) -> ArchDetection {
    if data.is_empty() {
        return ArchDetection { arch: Arch::Unknown, confidence: 0.0, indicators: vec![] };
    }
    let mut scores: Vec<(Arch, f32, String)> = Vec::new();

    // ─── x86_64 REX prefix 0x48..0x4F followed by common instructions ─
    let mut x64_indicators = 0;
    for w in data.windows(3) {
        if (0x48..=0x4F).contains(&w[0]) && matches!(w[1], 0x89 | 0x8B | 0x83 | 0x81
            | 0xC7 | 0xB8 | 0x31 | 0x33 | 0x29 | 0x01)
        {
            x64_indicators += 1;
        }
    }
    if x64_indicators >= 2 {
        scores.push((Arch::X86_64, 0.6 + 0.05 * x64_indicators as f32,
            format!("{} REX-prefixed 64-bit instructions", x64_indicators)));
    }

    // ─── x86 INT 0x2E, sysenter, classic opcodes without REX ─────────
    let mut x86_indicators = 0;
    for w in data.windows(2) {
        if w == [0xCD, 0x2E] || w == [0x0F, 0x34] {
            x86_indicators += 2;
        }
    }
    if x86_indicators > 0 {
        scores.push((Arch::X86, 0.3 + 0.1 * x86_indicators as f32,
            format!("{} x86-only syscall patterns", x86_indicators)));
    }

    // ─── AArch64 LE: top 16 bits of each 32-bit word look like real insns ─
    // A64 encoding: bits [28:25] != 0b1111 (top bit reserved pattern).
    // Heuristic: scan 4-byte little-endian words; look for prevalence of
    // common A64 instruction patterns.
    let aarch64_le = score_aarch64_le(data);
    if aarch64_le.0 > 0.0 {
        scores.push((Arch::AArch64Le, aarch64_le.0, aarch64_le.1));
    }
    let aarch64_be = score_aarch64_be(data);
    if aarch64_be.0 > 0.0 {
        scores.push((Arch::AArch64Be, aarch64_be.0, aarch64_be.1));
    }

    // ─── ARM LE: 4-byte little-endian words; bits[27:25] cond; LDR/STR pattern
    let arm_le = score_arm_le(data);
    if arm_le.0 > 0.0 {
        scores.push((Arch::ArmLe, arm_le.0, arm_le.1));
    }
    let arm_be = score_arm_be(data);
    if arm_be.0 > 0.0 {
        scores.push((Arch::ArmBe, arm_be.0, arm_be.1));
    }

    if scores.is_empty() {
        return ArchDetection { arch: Arch::Unknown, confidence: 0.0,
            indicators: vec!["no clear instruction pattern detected".into()] };
    }
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let (arch, conf, ind) = scores.remove(0);
    ArchDetection { arch, confidence: conf.min(1.0), indicators: vec![ind] }
}

fn score_aarch64_le(data: &[u8]) -> (f32, String) {
    let mut hits = 0usize;
    let mut p = 0;
    let n = data.len() & !3;
    while p + 4 <= n {
        let w = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        // Common A64 patterns: B/BL (top 6 bits 0b000101), ADR/ADRP (top 3 bits 0b001/100),
        // LDR/STR (size bits 11/10), STP/LDP (101010011x)
        let top = (w >> 26) & 0x3F;
        let _top7 = (w >> 25) & 0x7F;
        if matches!(top, 0x05 | 0x25) { hits += 1; }        // B / BL
        if (w >> 24) & 0x9F == 0x10 { hits += 1; }         // ADR/ADRP family
        if (w >> 22) & 0x3FF == 0x3E5 || (w >> 22) & 0x3FF == 0x3E4 { hits += 1; } // LDR/STR (32-bit)
        if (w >> 25) & 0x7F == 0x53 { hits += 1; }          // STP/LDP
        if w & 0xFFFF_0000 == 0xD65F_0000 { hits += 1; }    // RET
        p += 4;
    }
    if hits < 4 { return (0.0, String::new()); }
    (0.5 + (hits as f32 / 64.0).min(0.4), format!("{} AArch64-LE instruction candidates", hits))
}

fn score_aarch64_be(data: &[u8]) -> (f32, String) {
    let mut hits = 0usize;
    let mut p = 0;
    let n = data.len() & !3;
    while p + 4 <= n {
        let w = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        let top = (w >> 26) & 0x3F;
        if matches!(top, 0x05 | 0x25) { hits += 1; }
        if (w >> 24) & 0x9F == 0x10 { hits += 1; }
        if w & 0xFFFF_0000 == 0xD65F_0000 { hits += 1; }
        p += 4;
    }
    if hits < 4 { return (0.0, String::new()); }
    (0.5 + (hits as f32 / 64.0).min(0.4), format!("{} AArch64-BE instruction candidates", hits))
}

fn score_arm_le(data: &[u8]) -> (f32, String) {
    let mut hits = 0usize;
    let mut p = 0;
    let n = data.len() & !3;
    while p + 4 <= n {
        let w = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        // Cond field: bits 31..28. Common: 0xE (always), 0x0 (eq), 0xA (ge), 0xD (le).
        // Top 4 bits = cond, must not be 0xF (UNPREDICTABLE / unavailable).
        let cond = (w >> 28) & 0xF;
        if cond == 0xF { p += 4; continue; }
        let top5 = (w >> 25) & 0x7F;
        // LDR/STR: top 5 bits 010xx; BX/BLX: 0x12FFF1x
        if matches!(top5, 0x10..=0x13) { hits += 1; }
        if w & 0x0FFF_FFF0 == 0x012F_FF10 || w & 0x0FFF_FFF0 == 0x012F_FF30 { hits += 1; }
        p += 4;
    }
    if hits < 4 { return (0.0, String::new()); }
    (0.4 + (hits as f32 / 80.0).min(0.3), format!("{} ARM-LE instruction candidates", hits))
}

fn score_arm_be(data: &[u8]) -> (f32, String) {
    let mut hits = 0usize;
    let mut p = 0;
    let n = data.len() & !3;
    while p + 4 <= n {
        let w = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        let cond = (w >> 28) & 0xF;
        if cond == 0xF { p += 4; continue; }
        let top5 = (w >> 25) & 0x7F;
        if matches!(top5, 0x10..=0x13) { hits += 1; }
        p += 4;
    }
    if hits < 4 { return (0.0, String::new()); }
    (0.4 + (hits as f32 / 80.0).min(0.3), format!("{} ARM-BE instruction candidates", hits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_64() {
        // mov rax, rbx ; mov rcx, rdx ; mov rdi, rsi
        let data = [0x48, 0x89, 0xD8, 0x48, 0x89, 0xD1, 0x48, 0x89, 0xF7];
        let d = detect_architecture(&data);
        assert_eq!(d.arch, Arch::X86_64);
    }

    #[test]
    fn test_aarch64_le() {
        // Several B/RET instructions in A64-LE
        let mut data = Vec::new();
        for _ in 0..32 {
            data.extend_from_slice(&0xD65F03C0u32.to_le_bytes()); // RET
        }
        let d = detect_architecture(&data);
        assert_eq!(d.arch, Arch::AArch64Le);
    }

    #[test]
    fn test_empty() {
        let d = detect_architecture(&[]);
        assert_eq!(d.arch, Arch::Unknown);
    }
}
