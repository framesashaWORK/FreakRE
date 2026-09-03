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
    /// Edge types to each successor. INVARIANT: always exactly parallel to
    /// `successors` — `edge_types.len() == successors.len()`, entry `j`
    /// describes the edge to `successors[j]`. Blocks ending in a RET have no
    /// outgoing edges at all (returns leave the function), so they contribute
    /// neither a successor nor an edge-type entry.
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
                    && b.edge_types.contains(&EdgeType::UnconditionalJump)
            })
            .collect()
    }
}

// ─── Instruction classification via freakre-x86 ─────────────────────

/// Map a `freakre_x86::Mnemonic` to our control-flow `InstructionKind`.
///
/// Delegates to the shared [`freakre_x86::Mnemonic`] helpers — the single
/// source of truth (also used by `capstone-ffi`) — plus the CFG-local rule
/// that HLT/UD2 terminate a basic block like a return.
fn mnemonic_to_kind(m: &freakre_x86::Mnemonic) -> InstructionKind {
    use freakre_x86::Mnemonic as M;
    if m.is_unconditional_jump() {
        InstructionKind::UnconditionalJump
    } else if m.is_conditional_branch() {
        InstructionKind::ConditionalBranch
    } else if m.is_call() {
        InstructionKind::Call
    } else if m.is_ret() {
        InstructionKind::Return
    } else if matches!(m, M::Nop) {
        InstructionKind::Nop
    } else if matches!(m, M::Hlt | M::Ud2) {
        // HLT / UD2 terminate the basic block (no fall-through).
        InstructionKind::Return
    } else {
        InstructionKind::Normal
    }
}

/// Classify an x86/x64 instruction at the given position for CFG purposes.
/// Returns (length, kind). Powered by the `freakre-x86` disassembler; falls
/// back to a single-byte `Unknown` step on decode errors.
fn lde_classify_x86(code: &[u8], is_64bit: bool) -> (usize, InstructionKind) {
    match freakre_x86::decode(code, is_64bit) {
        Ok(insn) => (insn.length, mnemonic_to_kind(&insn.mnemonic)),
        Err(_) => (1, InstructionKind::Unknown),
    }
}

// ─── CFG Builder ──────────────────────────────────────────────────────

/// Configuration for CFG construction.
#[derive(Debug, Clone)]
pub struct CfgConfig {
    /// Whether the code is 64-bit (x86-64).
    pub is_64bit: bool,
    /// Base virtual address of the code region (for branch target resolution).
    pub base_va: u64,
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
    /// Enable recursive descent (follow jumps/calls to discover new blocks).
    pub recursive_descent: bool,
    /// Seed recursive descent from detected function prologues in addition to
    /// the entry point. Recovers functions that are only reached via indirect
    /// calls, tail calls, or data-driven dispatch — a hybrid linear-sweep +
    /// recursive-descent strategy — without the mis-decoding risk of a pure
    /// linear sweep (each seed still only decodes genuine control flow).
    pub seed_from_prologues: bool,
}

impl Default for CfgConfig {
    fn default() -> Self {
        Self {
            is_64bit: false,
            base_va: 0,
            max_instructions: 100_000,
            detect_unreachable: true,
            detect_trampolines: true,
            detect_excessive_jumps: true,
            jump_ratio_threshold: 0.3,
            recursive_descent: true,
            seed_from_prologues: true,
        }
    }
}

/// Build a CFG from raw code bytes.
pub fn build_cfg(code: &[u8], base_offset: usize, config: &CfgConfig) -> ControlFlowGraph {
    // Phase 1: Disassemble. Recursive descent only follows reachable code
    // (entry point + branch/call targets); linear sweep is kept only for the
    // (rare) opt-out path.
    let instructions = if config.recursive_descent {
        recursive_descent_sweep(code, config)
    } else {
        linear_sweep(code, config)
    };

    // Phase 2: Identify basic block leaders with branch target resolution
    let leaders = find_leaders(&instructions, code, config.base_va, config.is_64bit);

    // Phase 3: Build basic blocks
    let mut blocks = build_blocks(&instructions, &leaders);

    // Phase 4: Connect edges with target resolution
    connect_edges(&mut blocks, &instructions, code, config);

    // Phase 5: Detect anomalies
    let anomalies = detect_anomalies(&blocks, &instructions, code, config);

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

/// Recursive-descent disassembly.
///
/// Unlike [`linear_sweep`], this only decodes bytes reachable from the entry
/// point by following branch/call targets and fall-through. This avoids
/// mis-decoding padding and embedded data as code, so "unreachable" blocks
/// become a genuine signal (orphaned / dead code) rather than a linear-sweep
/// artifact.
fn recursive_descent_sweep(code: &[u8], config: &CfgConfig) -> Vec<Instruction> {
    let mut instructions: Vec<Instruction> = Vec::new();
    let mut decoded: HashSet<usize> = HashSet::new();
    let mut pending: Vec<usize> = vec![0];

    // Hybrid: seed from detected function prologues so functions reached only
    // via indirect calls / tail calls / data-driven dispatch are still
    // disassembled. Each seed still only decodes genuine control flow.
    if config.seed_from_prologues {
        for seed in find_function_starts(code, config.is_64bit) {
            pending.push(seed);
        }
    }

    while let Some(start) = pending.pop() {
        if start >= code.len() || decoded.contains(&start) {
            continue;
        }
        let mut offset = start;
        loop {
            if offset >= code.len() || decoded.contains(&offset) {
                break;
            }
            if instructions.len() >= config.max_instructions {
                break;
            }
            let remaining = &code[offset..];
            let (len, kind) = lde_classify_x86(remaining, config.is_64bit);
            let actual_len = len.min(remaining.len());
            if actual_len == 0 {
                break;
            }
            decoded.insert(offset);

            let inst = Instruction {
                offset,
                length: actual_len,
                kind,
            };
            let target = match kind {
                InstructionKind::ConditionalBranch
                | InstructionKind::UnconditionalJump
                | InstructionKind::Call => {
                    resolve_branch_target(&inst, code, config.base_va, config.is_64bit)
                }
                _ => None,
            };
            let is_terminal = matches!(
                kind,
                InstructionKind::Return | InstructionKind::UnconditionalJump
            );
            instructions.push(inst);

            if let Some(t) = target {
                let rel = (t as i64 - config.base_va as i64) as usize;
                if rel < code.len() && !decoded.contains(&rel) {
                    pending.push(rel);
                }
            }

            if is_terminal {
                break;
            }
            offset += actual_len;
        }
    }

    // Preserve offset order so downstream block construction works correctly.
    instructions.sort_by_key(|i| i.offset);
    instructions
}

/// Scan the code for common function prologue byte patterns and return the
/// candidate function-start offsets. O(n) — only a 3-byte window match, no
/// expensive epilogue scan. Used to seed recursive descent with additional
/// entry points beyond the single module entry.
fn find_function_starts(code: &[u8], _is_64bit: bool) -> Vec<usize> {
    // (first 3 bytes of) known prologues:
    //   55 89 E5        push ebp; mov ebp, esp        (x86)
    //   55 8B EC        push ebp; mov ebp, esp        (x86)
    //   48 83 EC xx     sub rsp, imm8                 (x64)
    //   48 81 EC xx..   sub rsp, imm32                (x64)
    const PROLOGUES: &[(u8, u8, u8)] = &[
        (0x55, 0x89, 0xE5),
        (0x55, 0x8B, 0xEC),
        (0x48, 0x83, 0xEC),
        (0x48, 0x81, 0xEC),
    ];
    let mut seeds = Vec::new();
    if code.len() < 3 {
        return seeds;
    }
    for i in 0..code.len() - 2 {
        let (a, b, c) = (code[i], code[i + 1], code[i + 2]);
        for (p0, p1, p2) in PROLOGUES {
            if a == *p0 && b == *p1 && c == *p2 {
                seeds.push(i);
                break;
            }
        }
    }
    seeds
}

/// Find basic block leader offsets with branch target resolution.
/// Leaders are: first instruction, targets of branches/jumps, instruction after branches.
fn find_leaders(instructions: &[Instruction], code: &[u8], base_va: u64, is_64bit: bool) -> HashSet<usize> {
    let mut leaders = HashSet::new();

    if !instructions.is_empty() {
        leaders.insert(0); // First instruction is always a leader
    }

    for (i, inst) in instructions.iter().enumerate() {
        match inst.kind {
            InstructionKind::ConditionalBranch | InstructionKind::UnconditionalJump => {
                // Instruction after a branch is a leader (fallthrough target)
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].offset);
                }

                // Resolve branch target
                if let Some(target_offset) = resolve_branch_target(inst, code, base_va, is_64bit) {
                    // Convert VA back to offset within analyzed region
                    if target_offset >= base_va as usize {
                        leaders.insert(target_offset - base_va as usize);
                    }
                }
            }
            InstructionKind::Return
                // Instruction after return is a leader (for unreachable code detection)
                if i + 1 < instructions.len() => {
                    leaders.insert(instructions[i + 1].offset);
                }
            _ => {}
        }
    }

    leaders
}

/// Resolve branch target address for a jump/call instruction.
/// Returns the target offset within the analyzed region, or None if cannot resolve.
///
/// Handles direct relative jumps/calls (EB/E9/E8/70-7F/E0-E3, 0F 80-8F) and, for
/// indirect `FF /2` (CALL r/m) and `FF /4` (JMP r/m) with a memory operand,
/// follows a RIP-relative (x64) or absolute (x86) pointer that lands inside the
/// analyzed region. Register-operand indirect branches still cannot be resolved
/// without data-flow analysis.
///
/// Legacy prefixes (2E/36/3E/26/64/65 segment overrides, 66 operand-size,
/// 67 address-size, F0 lock, F2/F3 rep) and — in 64-bit mode — REX are skipped
/// before opcode dispatch so prefixed jumps resolve correctly too.
fn resolve_branch_target(inst: &Instruction, code: &[u8], base_va: u64, is_64bit: bool) -> Option<usize> {
    let bytes = inst.get_bytes(code);
    if bytes.len() < 2 {
        return None;
    }

    // Skip known prefixes; the real opcode follows them.
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67
            | 0xF0 | 0xF2 | 0xF3 => i += 1,
            0x40..=0x4F if is_64bit => i += 1,
            _ => break,
        }
    }
    let opcode = *bytes.get(i)?;
    let disp_at = i + 1; // displacement starts right after the opcode

    let inst_va = base_va + inst.offset as u64;
    let next_inst_va = inst_va + inst.length as u64;

    match opcode {
        // Short jumps: EB rel8, 70-7F rel8
        0xEB | 0x70..=0x7F => {
            let disp = *bytes.get(disp_at)? as i8 as i64;
            let target_va = (next_inst_va as i64 + disp) as u64;
            Some(target_va as usize)
        }
        // Near jumps: E9 rel32, 0F 80-8F rel32 (rel16 with a 66 prefix)
        0xE9 => {
            let d = bytes.get(disp_at..disp_at + 4)?;
            let disp = i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64;
            let target_va = (next_inst_va as i64 + disp) as u64;
            Some(target_va as usize)
        }
        0x0F => {
            let op2 = *bytes.get(i + 1)?;
            if !(0x80..=0x8F).contains(&op2) {
                return None;
            }
            let d = bytes.get(i + 2..i + 6)?;
            let disp = i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64;
            let target_va = (next_inst_va as i64 + disp) as u64;
            Some(target_va as usize)
        }
        // CALL rel32
        0xE8 => {
            let d = bytes.get(disp_at..disp_at + 4)?;
            let disp = i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64;
            let target_va = (next_inst_va as i64 + disp) as u64;
            Some(target_va as usize)
        }
        // LOOP/JCXZ/JECXZ: E0-E3 rel8
        0xE0..=0xE3 => {
            let disp = *bytes.get(disp_at)? as i8 as i64;
            let target_va = (next_inst_va as i64 + disp) as u64;
            Some(target_va as usize)
        }
        // Indirect CALL/JMP via memory operand: FF /2 (CALL r/m), FF /4 (JMP r/m).
        0xFF => {
            let modrm = *bytes.get(disp_at)?;
            let reg = (modrm >> 3) & 7;
            let mmod = modrm >> 6;
            let rm = modrm & 7;
            if (reg == 2 || reg == 4) && mmod == 0 && rm == 5 {
                // 64-bit: [rip + disp32]; 32-bit: [disp32] absolute pointer.
                if bytes.len() >= disp_at + 5 {
                    let d = &bytes[disp_at + 1..disp_at + 5];
                    let disp = i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64;
                    let mem_va = if is_64bit {
                        (next_inst_va as i64 + disp) as u64
                    } else {
                        disp as u64
                    };
                    // Graceful None when the pointer lies below the region base
                    // instead of an underflow panic (debug builds).
                    let off = usize::try_from(mem_va.checked_sub(base_va)?).ok()?;
                    let ptr_size = if is_64bit { 8 } else { 4 };
                    if off + ptr_size <= code.len() {
                        let target = if is_64bit {
                            u64::from_le_bytes(code[off..off + 8].try_into().unwrap())
                        } else {
                            u32::from_le_bytes(code[off..off + 4].try_into().unwrap()) as u64
                        };
                        if target >= base_va && target < base_va + code.len() as u64 {
                            return Some(target as usize);
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
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

/// Connect edges between basic blocks based on instruction types with target resolution.
fn connect_edges(
    blocks: &mut [BasicBlock],
    instructions: &[Instruction],
    code: &[u8],
    config: &CfgConfig,
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
                    // Try to resolve jump target
                    if let Some(target_offset) = resolve_branch_target(inst, code, config.base_va, config.is_64bit) {
                        let target_relative = if target_offset >= config.base_va as usize {
                            target_offset - config.base_va as usize
                        } else {
                            continue;
                        };

                        if let Some(&target_id) = offset_to_block.get(&target_relative) {
                            blocks[i].successors.push(target_id);
                            blocks[i].edge_types.push(EdgeType::UnconditionalJump);
                        }
                    }
                    // No fallthrough for unconditional jumps
                }
                InstructionKind::ConditionalBranch => {
                    // Resolve branch target
                    if let Some(target_offset) = resolve_branch_target(inst, code, config.base_va, config.is_64bit) {
                        let target_relative = if target_offset >= config.base_va as usize {
                            target_offset - config.base_va as usize
                        } else {
                            continue;
                        };

                        if let Some(&target_id) = offset_to_block.get(&target_relative) {
                            blocks[i].successors.push(target_id);
                            blocks[i].edge_types.push(EdgeType::ConditionalBranch);
                        }
                    }

                    // Fallthrough edge (branch not taken)
                    if i + 1 < block_count {
                        let next_id = blocks[i + 1].id;
                        blocks[i].successors.push(next_id);
                        blocks[i].edge_types.push(EdgeType::Fallthrough);
                    }
                }
                InstructionKind::Return => {
                    // No successors: a RET leaves the function, so no edge is
                    // created and — to keep edge_types strictly parallel to
                    // successors (see BasicBlock::edge_types) — no EdgeType is
                    // pushed either.
                }
                InstructionKind::Call => {
                    // Edge to the called function so its entry block is not
                    // mistaken for unreachable code during anomaly detection.
                    if let Some(target_offset) = resolve_branch_target(inst, code, config.base_va, config.is_64bit) {
                        if target_offset >= config.base_va as usize {
                            let target_relative = target_offset - config.base_va as usize;
                            if let Some(&target_id) = offset_to_block.get(&target_relative) {
                                blocks[i].successors.push(target_id);
                                blocks[i].edge_types.push(EdgeType::Call);
                            }
                        }
                    }
                    // Fallthrough after call (call returns): the callee entry is
                    // a Call edge, but returning execution continues sequentially,
                    // which is a fallthrough edge.
                    if i + 1 < block_count {
                        let next_id = blocks[i + 1].id;
                        blocks[i].successors.push(next_id);
                        blocks[i].edge_types.push(EdgeType::Fallthrough);
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
/// Shannon entropy (bits per byte) of a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / n;
            ent -= p * p.log2();
        }
    }
    ent
}

fn detect_anomalies(
    blocks: &[BasicBlock],
    instructions: &[Instruction],
    code: &[u8],
    config: &CfgConfig,
) -> Vec<CfgAnomaly> {
    let mut anomalies = Vec::new();

    if config.detect_unreachable {
        // Recursive-descent only decodes reachable code. Any byte region of the
        // executable section that is NOT covered by a decoded instruction is
        // dead/orphaned code. Legitimate binaries contain benign low-entropy gaps
        // (switch tables, alignment padding, data), so a gap is only treated as a
        // real obfuscation / packing signal when it is both large (>= 256 bytes)
        // and high-entropy (>= 7.0 bits/byte) — i.e. an encrypted/packed stub.
        let mut covered = vec![false; code.len()];
        for inst in instructions {
            for c in covered[inst.offset..(inst.offset + inst.length).min(code.len())].iter_mut() {
                *c = true;
            }
        }

        let mut gap_offsets: Vec<usize> = Vec::new();
        let mut hi_gap_bytes = 0usize;
        let mut i = 0;
        while i < covered.len() {
            if !covered[i] {
                let start = i;
                while i < covered.len() && !covered[i] {
                    i += 1;
                }
                let len = i - start;
                if len >= 256 {
                    let ent = shannon_entropy(&code[start..i]);
                    if ent >= 7.0 {
                        gap_offsets.push(start);
                        hi_gap_bytes += len;
                    }
                }
            } else {
                i += 1;
            }
        }

        if !gap_offsets.is_empty() {
            let mut offsets = gap_offsets;
            if offsets.len() > 25 {
                offsets.truncate(25);
            }
            anomalies.push(CfgAnomaly {
                description: format!(
                    "{} bytes of high-entropy unreachable/dead code (entropy >= 7.0) detected — possible packing, encryption or anti-analysis stub",
                    hi_gap_bytes
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
                    && b.edge_types.contains(&EdgeType::UnconditionalJump)
            })
            .collect();

        if trampolines.len() > 10 {
            // Single-JMP thunks are abundant in normal binaries (import
            // trampolines, jump tables). Treat a large cluster as a weak Low
            // signal only, and cap the reported offsets to avoid flooding output.
            let mut offsets: Vec<usize> = trampolines.iter().map(|b| b.start_offset).collect();
            if offsets.len() > 25 {
                offsets.truncate(25);
            }
            anomalies.push(CfgAnomaly {
                description: format!(
                    "{} trampoline block(s) (single JMP) — possible opaque predicate or obfuscation",
                    trampolines.len()
                ),
                severity: AnomalySeverity::Low,
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
                severity: AnomalySeverity::Medium,
                offsets: vec![],
            });
        }
    }

    anomalies
}

// ─── Advanced Analysis ───────────────────────────────────────────────

/// Dominator tree node.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// Immediate dominator for each block (block_id → idom_block_id).
    /// Entry block has idom = None.
    pub idom: Vec<Option<usize>>,
    /// Dominance frontier for each block.
    pub dominance_frontier: Vec<Vec<usize>>,
}

impl DominatorTree {
    /// Compute dominator tree using Cooper-Harvey-Kennedy algorithm.
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let n = cfg.blocks.len();
        if n == 0 {
            return Self {
                idom: Vec::new(),
                dominance_frontier: Vec::new(),
            };
        }

        // Initialize: entry block dominates itself, others undefined
        let mut idom: Vec<Option<usize>> = vec![None; n];
        idom[0] = Some(0); // Entry block

        // Compute reverse postorder
        let rpo = Self::reverse_postorder(cfg);
        let rpo_idx: HashMap<usize, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

        // Iterate until fixed point
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == 0 {
                    continue; // Skip entry
                }

                // Find first processed predecessor
                let mut new_idom = None;
                for &p in &cfg.blocks[b].predecessors {
                    if idom[p].is_some() {
                        new_idom = Some(p);
                        break;
                    }
                }

                if new_idom.is_none() {
                    continue; // No processed predecessors yet
                }

                // Intersect with other processed predecessors
                for &p in &cfg.blocks[b].predecessors {
                    if Some(p) == new_idom || idom[p].is_none() {
                        continue;
                    }
                    new_idom = Some(Self::intersect(&idom, &rpo_idx, idom[p].unwrap(), new_idom.unwrap()));
                }

                if idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        // Compute dominance frontiers
        let dominance_frontier = Self::compute_dominance_frontier(cfg, &idom, &rpo);

        Self {
            idom,
            dominance_frontier,
        }
    }

    /// Compute reverse postorder using iterative DFS.
    fn reverse_postorder(cfg: &ControlFlowGraph) -> Vec<usize> {
        let n = cfg.blocks.len();
        let mut visited = vec![false; n];
        let mut postorder = Vec::new();
        if n == 0 {
            return postorder;
        }

        visited[0] = true;
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];

        while let Some(&mut (node, ref mut idx)) = stack.last_mut() {
            if *idx < cfg.blocks[node].successors.len() {
                let succ = cfg.blocks[node].successors[*idx];
                *idx += 1;
                if succ < n && !visited[succ] {
                    visited[succ] = true;
                    stack.push((succ, 0));
                }
            } else {
                postorder.push(node);
                stack.pop();
            }
        }

        postorder.reverse();
        postorder
    }

    /// Intersect two nodes in dominator tree (Cooper-Harvey-Kennedy).
    fn intersect(
        idom: &[Option<usize>],
        rpo_idx: &HashMap<usize, usize>,
        mut finger1: usize,
        mut finger2: usize,
    ) -> usize {
        // Guard against malformed CFG (missing idom) and irreducible loops.
        let mut iterations = 0usize;
        const LIMIT: usize = 1_000;
        while finger1 != finger2 && iterations < LIMIT {
            iterations += 1;
            let r1 = rpo_idx.get(&finger1).copied().unwrap_or(usize::MAX);
            let r2 = rpo_idx.get(&finger2).copied().unwrap_or(usize::MAX);
            if r1 > r2 {
                match idom[finger1] {
                    Some(up) if up != finger1 => finger1 = up,
                    _ => break,
                }
            } else if r2 > r1 {
                match idom[finger2] {
                    Some(up) if up != finger2 => finger2 = up,
                    _ => break,
                }
            } else {
                // Equal rank but different nodes (irreducible) — step both.
                let up1 = idom[finger1].unwrap_or(finger1);
                let up2 = idom[finger2].unwrap_or(finger2);
                if up1 == finger1 && up2 == finger2 {
                    break;
                }
                finger1 = up1;
                finger2 = up2;
            }
        }
        finger1
    }

    /// Compute dominance frontiers.
    fn compute_dominance_frontier(
        cfg: &ControlFlowGraph,
        idom: &[Option<usize>],
        _rpo: &[usize],
    ) -> Vec<Vec<usize>> {
        let n = cfg.blocks.len();
        let mut df = vec![Vec::new(); n];

        for b in 0..n {
            if cfg.blocks[b].predecessors.len() >= 2 {
                for &p in &cfg.blocks[b].predecessors {
                    let Some(target) = idom[b] else { continue };
                    let mut runner = p;
                    loop {
                        if runner == target || runner >= n {
                            break;
                        }
                        if !df[runner].contains(&b) {
                            df[runner].push(b);
                        }
                        match idom[runner] {
                            Some(up) if up != runner => runner = up,
                            _ => break,
                        }
                    }
                }
            }
        }

        df
    }

    /// Check if block `a` dominates block `b`.
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        let mut current = b;
        while let Some(idom) = self.idom[current] {
            if idom == a {
                return true;
            }
            if idom == current {
                break; // Reached entry
            }
            current = idom;
        }
        false
    }
}

/// Loop detection result.
#[derive(Debug, Clone)]
pub struct Loop {
    /// Header block (entry point of the loop).
    pub header: usize,
    /// All blocks in the loop (including header).
    pub blocks: Vec<usize>,
    /// Back edges (edges that create the loop).
    pub back_edges: Vec<(usize, usize)>,
}

/// Detect natural loops in the CFG.
pub fn detect_loops(cfg: &ControlFlowGraph) -> Vec<Loop> {
    let dom_tree = DominatorTree::compute(cfg);
    let mut loops = Vec::new();

    // Find back edges: edges where target dominates source
    for (block_id, block) in cfg.blocks.iter().enumerate() {
        for &succ in &block.successors {
            if dom_tree.dominates(succ, block_id) {
                // This is a back edge: block_id → succ
                let loop_blocks = find_loop_blocks(cfg, &dom_tree, block_id, succ);
                loops.push(Loop {
                    header: succ,
                    blocks: loop_blocks,
                    back_edges: vec![(block_id, succ)],
                });
            }
        }
    }

    loops
}

/// Find all blocks in a natural loop given a back edge.
fn find_loop_blocks(
    cfg: &ControlFlowGraph,
    _dom_tree: &DominatorTree,
    tail: usize,
    header: usize,
) -> Vec<usize> {
    let mut loop_blocks = vec![header];
    if tail == header {
        return loop_blocks;
    }

    let mut stack = vec![tail];
    let mut visited = vec![false; cfg.blocks.len()];
    visited[header] = true;

    while let Some(node) = stack.pop() {
        if !visited[node] {
            visited[node] = true;
            loop_blocks.push(node);
            for &pred in &cfg.blocks[node].predecessors {
                if !visited[pred] {
                    stack.push(pred);
                }
            }
        }
    }

    loop_blocks.sort();
    loop_blocks.dedup();
    loop_blocks
}

/// Function boundary detection result.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionBoundary {
    /// Start offset of the function.
    pub start_offset: usize,
    /// End offset (exclusive).
    pub end_offset: usize,
    /// Number of basic blocks in the function.
    pub num_blocks: usize,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Reason for detection.
    pub reason: String,
}

/// Detect function boundaries using prologue/epilogue patterns.
pub fn detect_functions(code: &[u8], _base_offset: usize, _config: &CfgConfig) -> Vec<FunctionBoundary> {
    let mut functions = Vec::new();

    // Scan for common prologues
    for i in 0..code.len().saturating_sub(4) {
        let is_prologue = match code[i..].get(0..4) {
            // PUSH EBP; MOV EBP, ESP (55 89 E5 or 55 8B EC)
            Some([0x55, 0x89, 0xE5, _]) | Some([0x55, 0x8B, 0xEC, _]) => true,
            // SUB RSP, imm (48 83 EC xx or 48 81 EC xx xx xx xx)
            Some([0x48, 0x83, 0xEC, _]) | Some([0x48, 0x81, 0xEC, _]) => true,
            // PUSH RBX (40 53)
            Some([0x40, 0x53, _, _]) => true,
            _ => false,
        };

        if is_prologue {
            // Find corresponding epilogue (RET or LEAVE; RET)
            let mut end = i + 4;
            while end < code.len().saturating_sub(2) {
                if code[end] == 0xC3 || code[end] == 0xCB { // RET
                    end += 1;
                    break;
                }
                if code[end] == 0xC9 && (code[end + 1] == 0xC3 || code[end + 1] == 0xCB) { // LEAVE; RET
                    end += 2;
                    break;
                }
                end += 1;
                if end - i > 10000 {
                    break; // Safety limit
                }
            }

            if end > i && end < code.len() {
                functions.push(FunctionBoundary {
                    start_offset: i,
                    end_offset: end,
                    num_blocks: 0, // Will be filled by caller
                    confidence: 0.8,
                    reason: "Prologue/epilogue pattern detected".to_string(),
                });
            }
        }
    }

    functions
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

    #[test]
    fn test_recursive_descent_flags_orphaned_code() {
        // Entry jumps past a gap into a RET, leaving a large trailing region
        // unreachable. The orphaned region is high-entropy (simulating a packed /
        // encrypted stub), which is the real obfuscation signal.
        let mut code = vec![0xEB, 0x05]; // JMP +5  -> offset 7
        code.extend_from_slice(&[0x90; 5]); // offsets 2..7 (skipped)
        code.push(0xC3); // offset 7: RET
        // 300 high-entropy bytes (LCG) as orphaned code.
        let mut rng = 0x1234_5678u32;
        for _ in 0..300 {
            rng = rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            code.push((rng >> 24) as u8);
        }

        let config = CfgConfig {
            seed_from_prologues: false, // keep RD-only so the orphaned gap stays unreachable
            ..Default::default()
        };
        let cfg = build_cfg(&code, 0, &config);

        let unreachable = cfg
            .anomalies
            .iter()
            .find(|a| a.description.contains("unreachable"));
        assert!(
            unreachable.is_some(),
            "expected unreachable anomaly, got {:?}",
            cfg.anomalies
        );
        assert_eq!(unreachable.unwrap().severity, AnomalySeverity::Medium);
    }

    #[test]
    fn test_recursive_descent_no_false_unreachable() {
        // Fully reachable: a call to a second function, both terminated by RET.
        // No code is orphaned, so there must be no unreachable anomaly.
        let code = vec![
            0xE8, 0x07, 0x00, 0x00, 0x00, // CALL +7 -> offset 12
            0x90, 0x90, // NOP, NOP
            0xC3, // RET (end of function 1)
            0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET (end of function 2, call target)
        ];

        let config = CfgConfig::default();
        let cfg = build_cfg(&code, 0, &config);

        assert!(
            !cfg.anomalies.iter().any(|a| a.description.contains("unreachable")),
            "unexpected unreachable anomaly on fully-reachable code: {:?}",
            cfg.anomalies
        );
    }

    #[test]
    fn edge_types_stay_parallel_to_successors() {
        let samples: Vec<Vec<u8>> = vec![
            vec![0x90, 0x90, 0xC3],                                    // plain ret
            vec![0x74, 0x02, 0x90, 0x90, 0xC3],                        // conditional
            vec![0x74, 0x05, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90, 0xC3], // call graph
            vec![0xEB, 0x00, 0xEB, 0x00],                              // jmp loop
        ];
        for code in samples {
            let config = CfgConfig { seed_from_prologues: false, ..Default::default() };
            let cfg = build_cfg(&code, 0, &config);
            for b in &cfg.blocks {
                assert_eq!(
                    b.successors.len(),
                    b.edge_types.len(),
                    "successors/edge_types diverged in block starting at {}",
                    b.start_offset
                );
                // A Return terminates the block without any outgoing edge;
                // no dangling EdgeType::Return may exist.
                assert!(
                    !b.edge_types.contains(&EdgeType::Return),
                    "dangling Return edge type in block at {}",
                    b.start_offset
                );
            }
        }
    }

    #[test]
    fn return_block_has_no_successors_and_no_dangling_edge_type() {
        //   0: 74 05           JZ -> 7         (block 0)
        //   2: E8 05 00 00 00  CALL -> 12      (block 1: call is its last inst,
        //                                       block boundary comes from the
        //                                       after-branch leader at 2)
        //   7: C3              RET             (block 2: no successors/edge_types)
        //   8..11: padding
        //  12: C3              RET             (block 3, call target)
        let code = vec![
            0x74, 0x05,
            0xE8, 0x05, 0x00, 0x00, 0x00,
            0xC3,
            0x90, 0x90, 0x90, 0x90,
            0xC3,
        ];
        let config = CfgConfig { seed_from_prologues: false, ..Default::default() };
        let cfg = build_cfg(&code, 0, &config);

        assert_eq!(cfg.blocks.len(), 4);

        // Every RET-terminated block must have neither successors nor
        // edge-type entries (no dangling EdgeType::Return).
        for idx in [2usize, 3] {
            assert!(cfg.blocks[idx].successors.is_empty(), "block {} has successors", idx);
            assert!(cfg.blocks[idx].edge_types.is_empty(), "block {} has dangling edge types", idx);
        }

        // Call block: callee entry gets a Call edge, sequential continuation
        // gets a Fallthrough edge (previously mislabeled as a second Call).
        let call_block = &cfg.blocks[1];
        assert_eq!(call_block.edge_types, vec![EdgeType::Call, EdgeType::Fallthrough]);
        assert_eq!(call_block.successors, vec![3, 2]);
    }

    #[test]
    fn prefixed_direct_branches_resolve() {
        // CS-prefixed short JMP: 2E EB 05 at offset 0, base 0x1000
        // -> next = 0x1003, target = 0x1008
        let inst = Instruction { offset: 0, length: 3, kind: InstructionKind::UnconditionalJump };
        let bytes = [0x2E, 0xEB, 0x05];
        assert_eq!(resolve_branch_target(&inst, &bytes, 0x1000, false), Some(0x1008));

        // Operand-size-prefixed near JMP: 66 E9 rel32 -> next = base + 6
        let inst = Instruction { offset: 0, length: 6, kind: InstructionKind::UnconditionalJump };
        let bytes = [0x66, 0xE9, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(resolve_branch_target(&inst, &bytes, 0x1000, false), Some(0x1016));

        // Long conditional Jcc: 0F 84 FE FF FF FF -> next = base + 6, disp -2
        let inst = Instruction { offset: 0, length: 6, kind: InstructionKind::ConditionalBranch };
        let bytes = [0x0F, 0x84, 0xFE, 0xFF, 0xFF, 0xFF];
        assert_eq!(resolve_branch_target(&inst, &bytes, 0x1000, true), Some(0x1004));

        // Prefix-only buffer (truncated) must yield None, not panic/index OOB.
        let inst = Instruction { offset: 0, length: 1, kind: InstructionKind::Unknown };
        let bytes = [0x66];
        assert_eq!(resolve_branch_target(&inst, &bytes, 0x1000, false), None);
    }

    #[test]
    fn indirect_call_target_below_base_is_none_not_panic() {
        // FF 25 disp32 with RIP-relative displacement landing BELOW base_va.
        // Previously `(mem_va - base_va) as usize` underflowed (debug panic).
        let mut code = vec![0u8; 16];
        code[0] = 0xFF;
        code[1] = 0x25;
        code[2..6].copy_from_slice(&(-0x2000i32).to_le_bytes()); // mem = base + 6 - 0x2000 < base
        let inst = Instruction { offset: 0, length: 6, kind: InstructionKind::UnconditionalJump };
        assert_eq!(resolve_branch_target(&inst, &code, 0x1_0000, true), None);
    }

    #[test]
    fn indirect_call_through_memory_resolves() {
        // Region holds both the indirect JMP and the pointer table entry:
        //   code[0..6]   = FF 25 0A 00 00 00  jmp qword [rip + 10]
        //   rip after insn = base + 6 -> mem_va = base + 16
        //   code[16..24] = 0x1014 (target VA inside the region)
        let mut code = vec![0u8; 24];
        code[0..6].copy_from_slice(&[0xFF, 0x25, 0x0A, 0x00, 0x00, 0x00]);
        code[16..24].copy_from_slice(&0x1014u64.to_le_bytes());
        let inst = Instruction { offset: 0, length: 6, kind: InstructionKind::UnconditionalJump };
        assert_eq!(resolve_branch_target(&inst, &code, 0x1000, true), Some(0x1014));
    }
}


