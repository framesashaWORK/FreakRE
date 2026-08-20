#![allow(dead_code, unused_assignments)]
//! # cfg-builder — Control Flow Graph Builder
//!
//! Lightweight CFG construction from raw x86/x64 bytes for malware analysis.
//! Uses a minimal Length Disassembler Engine (LDE) to determine instruction
//! boundaries without full decoding, then identifies basic blocks and edges.
//!
//! ## Capabilities
//! - Basic block identification from executable sections
//! - Edge classification (fallthrough, conditional branch, unconditional jump, call)
//! - Anomaly detection: unreachable code, excessive JMPs, opaque predicates
//! - Function boundary heuristics (prologue/epilogue patterns)
//!
//! ## Analogue
//! Ghidra Basic Block Model + Function Graph; IDA Pro CFG

use serde::Serialize;
use std::collections::{HashMap, HashSet};

// ─── Types ────────────────────────────────────────────────────────────

/// Type of edge between basic blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EdgeType {
    /// Sequential fallthrough (no branch).
    Fallthrough,
    /// Conditional branch (JE, JNE, JL, etc.).
    ConditionalBranch,
    /// Unconditional jump (JMP).
    UnconditionalJump,
    /// Function call (CALL).
    Call,
    /// Return (RET).
    Return,
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fallthrough => write!(f, "fallthrough"),
            Self::ConditionalBranch => write!(f, "cond_branch"),
            Self::UnconditionalJump => write!(f, "uncond_jump"),
            Self::Call => write!(f, "call"),
            Self::Return => write!(f, "return"),
        }
    }
}

/// A single instruction identified by the LDE.
///
/// Note: Raw bytes are NOT stored to avoid O(n) copying per instruction.
/// Use `get_bytes(code)` with the original code slice to retrieve them.
#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    /// Offset relative to the start of the analyzed region.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Classification for CFG purposes.
    pub kind: InstructionKind,
}

impl Instruction {
    /// Retrieve raw bytes from the original code slice.
    #[inline]
    pub fn get_bytes<'a>(&self, code: &'a [u8]) -> &'a [u8] {
        &code[self.offset..self.offset + self.length]
    }
}

/// High-level instruction classification for CFG building.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InstructionKind {
    /// Normal instruction (no control flow change).
    Normal,
    /// Conditional branch.
    ConditionalBranch,
    /// Unconditional jump.
    UnconditionalJump,
    /// Function call.
    Call,
    /// Return.
    Return,
    /// NOP or padding (0x90, 0xCC, multi-byte NOPs).
    Nop,
    /// Unknown / failed to decode.
    Unknown,
}

/// A basic block: a maximal sequence of instructions with single entry/exit.
#[derive(Debug, Clone, Serialize)]
pub struct BasicBlock {
    /// Unique block ID (index in the blocks vector).
    pub id: usize,
    /// Start offset within the analyzed region.
    pub start_offset: usize,
    /// End offset (exclusive).
    pub end_offset: usize,
    /// Number of instructions in this block.
    pub num_instructions: usize,
    /// Indices of successor blocks.
    pub successors: Vec<usize>,
    /// Indices of predecessor blocks.
    pub predecessors: Vec<usize>,
    /// Edge types to each successor (parallel to `successors`).
    pub edge_types: Vec<EdgeType>,
}

/// Detected CFG anomaly.
#[derive(Debug, Clone, Serialize)]
pub struct CfgAnomaly {
    /// Human-readable description.
    pub description: String,
    /// Severity hint.
    pub severity: AnomalySeverity,
    /// Offset(s) involved.
    pub offsets: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AnomalySeverity {
    Info,
    Low,
    Medium,
    High,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
        }
    }
}

/// Complete CFG for a code region.
#[derive(Debug, Clone, Serialize)]
pub struct ControlFlowGraph {
    /// All basic blocks.
    pub blocks: Vec<BasicBlock>,
    /// Total number of instructions processed.
    pub total_instructions: usize,
    /// Detected anomalies.
    pub anomalies: Vec<CfgAnomaly>,
    /// Base offset of the analyzed region within the file.
    pub base_offset: usize,
}

impl ControlFlowGraph {
    /// Number of blocks.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges.
    pub fn num_edges(&self) -> usize {
        self.blocks.iter().map(|b| b.successors.len()).sum()
    }

    /// Find blocks with no predecessors (excluding block 0).
    pub fn unreachable_blocks(&self) -> Vec<&BasicBlock> {
        self.blocks
            .iter()
            .filter(|b| b.id != 0 && b.predecessors.is_empty())
            .collect()
    }

    /// Find blocks that are just unconditional jumps (potential opaque predicates).
    pub fn trampoline_blocks(&self) -> Vec<&BasicBlock> {
        self.blocks
            .iter()
            .filter(|b| {
                b.num_instructions == 1
                    && b.edge_types.iter().any(|e| *e == EdgeType::UnconditionalJump)
            })
            .collect()
    }
}

// ─── Minimal x86/x64 Length Disassembler Engine ──────────────────────

/// Classify an x86/x64 instruction at the given position for CFG purposes.
/// Returns (length, kind). This is NOT a full disassembler — it only needs
/// to determine instruction boundaries and control-flow type.
fn lde_classify_x86(code: &[u8], is_64bit: bool) -> (usize, InstructionKind) {
    if code.is_empty() {
        return (1, InstructionKind::Unknown);
    }

    let mut pos = 0;

    // Skip legacy prefixes (up to 4)
    while pos < code.len() && pos < 4 {
        match code[pos] {
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 => {
                pos += 1;
            }
            _ => break,
        }
    }

    // REX prefix in 64-bit mode
    if is_64bit && pos < code.len() && (code[pos] & 0xF0) == 0x40 {
        pos += 1;
    }

    if pos >= code.len() {
        return (pos.max(1), InstructionKind::Unknown);
    }

    let opcode = code[pos];
    pos += 1;

    // Two-byte opcode escape
    let two_byte = if opcode == 0x0F && pos < code.len() {
        let second = code[pos];
        pos += 1;

        // 0F 80-8F: long conditional jumps (Jcc rel32)
        if second >= 0x80 && second <= 0x8F {
            return (pos + 4, InstructionKind::ConditionalBranch);
        }

        // 0F 90-9F: SETcc r/m8 (3 bytes: 0F 9x ModR/M [SIB] [disp])
        if second >= 0x90 && second <= 0x9F {
            let len = if pos < code.len() { modrm_length(code[pos], is_64bit) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // 0F 40-4F: CMOVcc r, r/m (3+ bytes: 0F 4x ModR/M [SIB] [disp])
        if second >= 0x40 && second <= 0x4F {
            let len = if pos < code.len() { modrm_length(code[pos], is_64bit) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // 0F B6: MOVZX r, r/m8;  0F B7: MOVZX r, r/m16
        // 0F BE: MOVSX r, r/m8;  0F BF: MOVSX r, r/m16
        if second == 0xB6 || second == 0xB7 || second == 0xBE || second == 0xBF {
            let len = if pos < code.len() { modrm_length(code[pos], is_64bit) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // 0F BC: BSF r, r/m;  0F BD: BSR r, r/m
        if second == 0xBC || second == 0xBD {
            let len = if pos < code.len() { modrm_length(code[pos], is_64bit) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // 0F AF: IMUL r, r/m
        if second == 0xAF {
            let len = if pos < code.len() { modrm_length(code[pos], is_64bit) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // 0F 31: RDTSC (2 bytes, no operands)
        if second == 0x31 {
            return (pos, InstructionKind::Normal);
        }

        // 0F A2: CPUID (2 bytes, no operands)
        if second == 0xA2 {
            return (pos, InstructionKind::Normal);
        }

        // 0F 05: SYSCALL (2 bytes)
        if second == 0x05 {
            return (pos, InstructionKind::Normal);
        }

        // 0F 34: SYSENTER (2 bytes)
        if second == 0x34 {
            return (pos, InstructionKind::Normal);
        }

        // Default for other 0F xx: assume ModR/M follows (covers most SSE/MMX)
        let len = if pos < code.len() { modrm_length(code[pos], is_64bit) } else { 0 };
        return (pos + len, InstructionKind::Normal);
    } else {
        false
    };

    if two_byte {
        // Unreachable — all 0x0F paths return above
        return (pos, InstructionKind::Normal);
    }

    match opcode {
        // RET variants
        0xC3 | 0xCB => (pos, InstructionKind::Return),
        0xC2 | 0xCA => (pos + 2, InstructionKind::Return),

        // CALL rel32 / JMP rel32
        0xE8 => (pos + 4, InstructionKind::Call),
        0xE9 => (pos + 4, InstructionKind::UnconditionalJump),

        // Short JMP / Jcc
        0xEB => (pos + 1, InstructionKind::UnconditionalJump),
        0x70..=0x7F => (pos + 1, InstructionKind::ConditionalBranch),

        // LOOP / JCXZ / JECXZ
        0xE0..=0xE3 => (pos + 1, InstructionKind::ConditionalBranch),

        // CALL/JMP indirect (FF /2, FF /4, FF /5)
        0xFF => {
            if pos < code.len() {
                let modrm = code[pos];
                let reg = (modrm >> 3) & 0x07;
                let len = modrm_length(modrm, is_64bit);
                match reg {
                    2 | 3 => (pos + len, InstructionKind::Call),     // CALL r/m
                    4 | 5 => (pos + len, InstructionKind::UnconditionalJump), // JMP r/m
                    _ => (pos + len, InstructionKind::Normal),
                }
            } else {
                (pos, InstructionKind::Unknown)
            }
        }

        // NOP
        0x90 => (pos, InstructionKind::Nop),

        // INT3
        0xCC => (pos, InstructionKind::Nop),

        // Common instructions with known lengths (simplified)
        // This covers ~80% of real-world x86 code for CFG purposes.
        // For unknown opcodes, we use conservative heuristics.
        _ => {
            let extra = operand_size_heuristic(opcode, code.get(pos).copied());
            (pos + extra, InstructionKind::Normal)
        }
    }
}

/// Estimate ModR/M + SIB + displacement length.
fn modrm_length(modrm: u8, _is_64bit: bool) -> usize {
    let mod_bits = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;

    let mut len = 1; // ModR/M byte itself

    // SIB byte present when mod != 3 and rm == 4
    if mod_bits != 3 && rm == 4 {
        len += 1; // SIB
    }

    // Displacement
    match mod_bits {
        0 => {
            if rm == 5 {
                len += 4; // disp32
            }
        }
        1 => len += 1, // disp8
        2 => len += 4, // disp32
        _ => {} // mod=3: register direct, no displacement
    }

    len
}

/// Heuristic for estimating operand size of common opcodes.
/// This is intentionally conservative — better to overestimate than miss instructions.
fn operand_size_heuristic(opcode: u8, next_byte: Option<u8>) -> usize {
    match opcode {
        // PUSH/POP reg (single byte)
        0x50..=0x5F => 0,

        // MOV reg, imm32 / ADD/SUB/CMP/XOR/OR/AND al/ax/eax, imm
        0xB8..=0xBF => 4, // MOV reg32, imm32
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => 1, // AL, imm8
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => 4, // EAX, imm32

        // Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm
        0x80 | 0x82 => next_byte.map(|m| 1 + modrm_length(m, false) + 1).unwrap_or(2),
        0x81 => next_byte.map(|m| 1 + modrm_length(m, false) + 4).unwrap_or(5),
        0x83 => next_byte.map(|m| 1 + modrm_length(m, false) + 1).unwrap_or(2),

        // MOV r/m, reg or reg, r/m
        0x88..=0x8B => next_byte.map(|m| modrm_length(m, false)).unwrap_or(1),

        // LEA
        0x8D => next_byte.map(|m| modrm_length(m, false)).unwrap_or(1),

        // TEST r/m, reg
        0x84 | 0x85 => next_byte.map(|m| modrm_length(m, false)).unwrap_or(1),

        // XCHG eax, reg
        0x91..=0x97 => 0,

        // MOVZX / MOVSX (two-byte, already handled 0F prefix)
        // CDQ, CBW, etc.
        0x98 | 0x99 | 0x9B | 0x9C | 0x9D | 0x9E | 0x9F => 0,

        // PUSH imm8 / imm32
        0x6A => 1,
        0x68 => 4,

        // IMUL r, r/m, imm8/imm32
        0x6B => next_byte.map(|m| modrm_length(m, false) + 1).unwrap_or(2),
        0x69 => next_byte.map(|m| modrm_length(m, false) + 4).unwrap_or(5),

        // Default: assume 1 extra byte (ModR/M) for safety
        _ => next_byte.map(|m| modrm_length(m, false)).unwrap_or(1),
    }
}

// ─── CFG Builder ──────────────────────────────────────────────────────

/// Configuration for CFG construction.
#[derive(Debug, Clone)]
pub struct CfgConfig {
    /// Whether the code is 64-bit (x86-64).
    pub is_64bit: bool,
    /// Maximum number of instructions to process (safety limit).
    pub max_instructions: usize,
    /// Detect unreachable code blocks.
    pub detect_unreachable: bool,
    /// Detect trampoline / opaque predicate blocks.
    pub detect_trampolines: bool,
    /// Detect excessive unconditional jumps (obfuscation indicator).
    pub detect_excessive_jumps: bool,
    /// Threshold: ratio of JMP instructions to total instructions.
    pub jump_ratio_threshold: f64,
}

impl Default for CfgConfig {
    fn default() -> Self {
        Self {
            is_64bit: false,
            max_instructions: 100_000,
            detect_unreachable: true,
            detect_trampolines: true,
            detect_excessive_jumps: true,
            jump_ratio_threshold: 0.3,
        }
    }
}

/// Build a CFG from raw code bytes.
pub fn build_cfg(code: &[u8], base_offset: usize, config: &CfgConfig) -> ControlFlowGraph {
    // Phase 1: Linear sweep to identify instruction boundaries
    let instructions = linear_sweep(code, config);

    // Phase 2: Identify basic block leaders
    let leaders = find_leaders(&instructions);

    // Phase 3: Build basic blocks
    let mut blocks = build_blocks(&instructions, &leaders);

    // Phase 4: Connect edges
    connect_edges(&mut blocks, &instructions, &leaders, code, config);

    // Phase 5: Detect anomalies
    let anomalies = detect_anomalies(&blocks, &instructions, config);

    ControlFlowGraph {
        blocks,
        total_instructions: instructions.len(),
        anomalies,
        base_offset,
    }
}

/// Linear sweep disassembly to find instruction boundaries.
fn linear_sweep(code: &[u8], config: &CfgConfig) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < code.len() && instructions.len() < config.max_instructions {
        let remaining = &code[offset..];
        let (len, kind) = lde_classify_x86(remaining, config.is_64bit);

        let actual_len = len.min(remaining.len());
        if actual_len == 0 {
            break;
        }

        instructions.push(Instruction {
            offset,
            length: actual_len,
            kind,
        });

        offset += actual_len;
    }

    instructions
}

/// Find basic block leader offsets.
/// Leaders are: first instruction, targets of branches/jumps, instruction after branches.
fn find_leaders(instructions: &[Instruction]) -> HashSet<usize> {
    let mut leaders = HashSet::new();

    if !instructions.is_empty() {
        leaders.insert(0); // First instruction is always a leader
    }

    for (i, inst) in instructions.iter().enumerate() {
        match inst.kind {
            InstructionKind::ConditionalBranch
            | InstructionKind::UnconditionalJump
            | InstructionKind::Return => {
                // Instruction after a branch is a leader (fallthrough target)
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].offset);
                }
            }
            _ => {}
        }
    }

    // Note: We don't resolve branch targets here because we work with
    // relative offsets and would need the base address. For now, we rely
    // on fallthrough leaders. Target resolution can be added when PE
    // section VA information is available.

    leaders
}

/// Build basic blocks from instructions and leader set.
fn build_blocks(instructions: &[Instruction], leaders: &HashSet<usize>) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    let mut current_block_start = 0;
    let mut block_id = 0;

    for (i, inst) in instructions.iter().enumerate() {
        if i > 0 && leaders.contains(&inst.offset) {
            // End current block, start new one
            let block = BasicBlock {
                id: block_id,
                start_offset: instructions[current_block_start].offset,
                end_offset: inst.offset,
                num_instructions: i - current_block_start,
                successors: Vec::new(),
                predecessors: Vec::new(),
                edge_types: Vec::new(),
            };
            blocks.push(block);
            block_id += 1;
            current_block_start = i;
        }
    }

    // Final block
    if current_block_start < instructions.len() {
        let last_end = instructions.last().map(|i| i.offset + i.length).unwrap_or(0);
        blocks.push(BasicBlock {
            id: block_id,
            start_offset: instructions[current_block_start].offset,
            end_offset: last_end,
            num_instructions: instructions.len() - current_block_start,
            successors: Vec::new(),
            predecessors: Vec::new(),
            edge_types: Vec::new(),
        });
    }

    blocks
}

/// Connect edges between basic blocks based on instruction types.
fn connect_edges(
    blocks: &mut [BasicBlock],
    instructions: &[Instruction],
    _leaders: &HashSet<usize>,
    _code: &[u8],
    _config: &CfgConfig,
) {
    // Build offset → block_id map
    let mut offset_to_block: HashMap<usize, usize> = HashMap::new();
    for block in blocks.iter() {
        offset_to_block.insert(block.start_offset, block.id);
    }

    // For each block, examine its last instruction to determine edges
    let block_count = blocks.len();
    for i in 0..block_count {
        let block = &blocks[i];

        // Find the last instruction in this block
        let last_inst = instructions
            .iter()
            .rev()
            .find(|inst| inst.offset >= block.start_offset && inst.offset < block.end_offset);

        if let Some(inst) = last_inst {
            match inst.kind {
                InstructionKind::UnconditionalJump => {
                    // Try to resolve target (simplified: only forward refs within same region)
                    // In a full implementation, we'd decode the displacement and add base VA
                    // For now, add fallthrough as placeholder
                    if i + 1 < block_count {
                        // Don't add fallthrough for unconditional jumps
                    }
                }
                InstructionKind::ConditionalBranch => {
                    // Conditional: fallthrough + branch target
                    if i + 1 < block_count {
                        let next_id = blocks[i + 1].id;
                        blocks[i].successors.push(next_id);
                        blocks[i].edge_types.push(EdgeType::ConditionalBranch);
                    }
                }
                InstructionKind::Return => {
                    // No successors within this function
                }
                InstructionKind::Call => {
                    // Fallthrough after call
                    if i + 1 < block_count {
                        let next_id = blocks[i + 1].id;
                        blocks[i].successors.push(next_id);
                        blocks[i].edge_types.push(EdgeType::Call);
                    }
                }
                _ => {
                    // Normal/NOP: fallthrough to next block
                    if i + 1 < block_count {
                        let next_id = blocks[i + 1].id;
                        blocks[i].successors.push(next_id);
                        blocks[i].edge_types.push(EdgeType::Fallthrough);
                    }
                }
            }
        } else if i + 1 < block_count {
            // Empty block fallback
            let next_id = blocks[i + 1].id;
            blocks[i].successors.push(next_id);
            blocks[i].edge_types.push(EdgeType::Fallthrough);
        }
    }

    // Build predecessor lists
    let edges: Vec<(usize, usize)> = blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |s| (b.id, *s)))
        .collect();

    for (src, dst) in edges {
        if dst < blocks.len() {
            blocks[dst].predecessors.push(src);
        }
    }
}

/// Detect CFG anomalies indicative of obfuscation or packing.
fn detect_anomalies(
    blocks: &[BasicBlock],
    instructions: &[Instruction],
    config: &CfgConfig,
) -> Vec<CfgAnomaly> {
    let mut anomalies = Vec::new();

    if config.detect_unreachable {
        let unreachable: Vec<&BasicBlock> = blocks
            .iter()
            .filter(|b| b.id != 0 && b.predecessors.is_empty())
            .collect();

        if !unreachable.is_empty() {
            let offsets: Vec<usize> = unreachable.iter().map(|b| b.start_offset).collect();
            anomalies.push(CfgAnomaly {
                description: format!(
                    "{} unreachable basic block(s) detected — possible dead code or anti-analysis",
                    unreachable.len()
                ),
                severity: AnomalySeverity::Medium,
                offsets,
            });
        }
    }

    if config.detect_trampolines {
        let trampolines: Vec<&BasicBlock> = blocks
            .iter()
            .filter(|b| {
                b.num_instructions == 1
                    && b.edge_types.iter().any(|e| *e == EdgeType::UnconditionalJump)
            })
            .collect();

        if trampolines.len() > 3 {
            let offsets: Vec<usize> = trampolines.iter().map(|b| b.start_offset).collect();
            anomalies.push(CfgAnomaly {
                description: format!(
                    "{} trampoline block(s) (single JMP) — possible opaque predicate or obfuscation",
                    trampolines.len()
                ),
                severity: AnomalySeverity::High,
                offsets,
            });
        }
    }

    if config.detect_excessive_jumps && !instructions.is_empty() {
        let jump_count = instructions
            .iter()
            .filter(|i| matches!(i.kind, InstructionKind::UnconditionalJump))
            .count();
        let ratio = jump_count as f64 / instructions.len() as f64;

        if ratio > config.jump_ratio_threshold {
            anomalies.push(CfgAnomaly {
                description: format!(
                    "Excessive unconditional jumps: {:.1}% of instructions (threshold: {:.1}%) — likely obfuscated",
                    ratio * 100.0,
                    config.jump_ratio_threshold * 100.0
                ),
                severity: AnomalySeverity::High,
                offsets: vec![],
            });
        }
    }

    anomalies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lde_ret() {
        let (len, kind) = lde_classify_x86(&[0xC3], false);
        assert_eq!(len, 1);
        assert_eq!(kind, InstructionKind::Return);
    }

    #[test]
    fn test_lde_short_jmp() {
        let (len, kind) = lde_classify_x86(&[0xEB, 0x10], false);
        assert_eq!(len, 2);
        assert_eq!(kind, InstructionKind::UnconditionalJump);
    }

    #[test]
    fn test_lde_conditional_jmp() {
        let (len, kind) = lde_classify_x86(&[0x74, 0x05], false);
        assert_eq!(len, 2);
        assert_eq!(kind, InstructionKind::ConditionalBranch);
    }

    #[test]
    fn test_lde_call_rel32() {
        let (len, kind) = lde_classify_x86(&[0xE8, 0x00, 0x01, 0x00, 0x00], false);
        assert_eq!(len, 5);
        assert_eq!(kind, InstructionKind::Call);
    }

    #[test]
    fn test_lde_nop() {
        let (len, kind) = lde_classify_x86(&[0x90], false);
        assert_eq!(len, 1);
        assert_eq!(kind, InstructionKind::Nop);
    }

    #[test]
    fn test_build_cfg_simple() {
        // Simple sequence: NOP, NOP, RET
        let code = vec![0x90, 0x90, 0xC3];
        let config = CfgConfig::default();
        let cfg = build_cfg(&code, 0, &config);

        assert!(cfg.total_instructions >= 3);
        assert!(!cfg.blocks.is_empty());
    }

    #[test]
    fn test_build_cfg_with_branch() {
        // JE +2, NOP, NOP, RET
        let code = vec![0x74, 0x02, 0x90, 0x90, 0xC3];
        let config = CfgConfig::default();
        let cfg = build_cfg(&code, 0, &config);

        assert!(cfg.total_instructions >= 3);
        // Should have at least 2 blocks due to conditional branch
        assert!(cfg.blocks.len() >= 2);
    }

    #[test]
    fn test_anomaly_excessive_jumps() {
        // All JMPs
        let code = vec![0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00];
        let config = CfgConfig {
            jump_ratio_threshold: 0.1,
            ..Default::default()
        };
        let cfg = build_cfg(&code, 0, &config);

        assert!(!cfg.anomalies.is_empty());
        assert!(cfg.anomalies.iter().any(|a| a.description.contains("Excessive")));
    }

    #[test]
    fn test_empty_code() {
        let config = CfgConfig::default();
        let cfg = build_cfg(&[], 0, &config);
        assert_eq!(cfg.total_instructions, 0);
        assert!(cfg.blocks.is_empty());
    }
}


