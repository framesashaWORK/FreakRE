//! Recursive descent function discovery
//!
//! Starting from known entry points, follows calls and jumps to discover
//! additional functions. This is the most reliable method because it only
//! reports functions that are actually reachable.

use crate::{
    Architecture, BasicBlock, DiscoveredFunction, FinderConfig,
    FunctionSource, Result,
};
use std::collections::{HashMap, HashSet, VecDeque};

/// Recursive descent analyzer
pub struct RecursiveAnalyzer {
    arch: Architecture,
    config: FinderConfig,
    /// Known function addresses
    known_functions: HashSet<u64>,
    /// Visited addresses (to avoid infinite loops)
    visited: HashSet<u64>,
    /// Work queue for BFS
    work_queue: VecDeque<WorkItem>,
    /// Discovered functions
    functions: HashMap<u64, DiscoveredFunction>,
}

#[derive(Clone, Debug)]
struct WorkItem {
    address: u64,
    depth: usize,
    source: FunctionSource,
}

/// Outcome of a single length-decode attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeOutcome {
    /// Instruction decoded successfully; occupies this many bytes (> 0).
    Length(usize),
    /// Opcode/prefix combination unknown to this simplified LDE, or the
    /// instruction is truncated at the edge of the region. Callers MUST
    /// stop the current sweep path here ("stop with warning") — this is
    /// NOT a verified end-of-function marker and must never be confused
    /// with a legitimate terminator such as RET/JMP.
    Unknown,
}

impl RecursiveAnalyzer {
    pub fn new(arch: Architecture, config: FinderConfig) -> Self {
        Self {
            arch,
            config,
            known_functions: HashSet::new(),
            visited: HashSet::new(),
            work_queue: VecDeque::new(),
            functions: HashMap::new(),
        }
    }

    /// Add an entry point to start analysis from
    pub fn add_entry_point(&mut self, address: u64) {
        self.work_queue.push_back(WorkItem {
            address,
            depth: 0,
            source: FunctionSource::SymbolTable,
        });
    }

    /// Add multiple entry points
    pub fn add_entry_points(&mut self, addresses: impl IntoIterator<Item = u64>) {
        for addr in addresses {
            self.add_entry_point(addr);
        }
    }

    /// Run the analysis on the given code regions
    pub fn analyze(&mut self, code_regions: &[crate::CodeRegion]) -> Result<Vec<DiscoveredFunction>> {
        // Build address-to-region mapping for fast lookup
        let region_map = self.build_region_map(code_regions);

        while let Some(item) = self.work_queue.pop_front() {
            if item.depth > self.config.max_recursion_depth {
                continue;
            }

            if self.known_functions.contains(&item.address) {
                continue;
            }

            // Try to analyze this address as a function
            if let Some(func) = self.analyze_function(&item, &region_map)? {
                self.known_functions.insert(func.address);

                // Queue callees for analysis
                for block in &func.blocks {
                    for callee in self.find_callees(block, &region_map) {
                        if !self.known_functions.contains(&callee) && !self.visited.contains(&callee) {
                            self.visited.insert(callee);
                            self.work_queue.push_back(WorkItem {
                                address: callee,
                                depth: item.depth + 1,
                                source: FunctionSource::RecursiveDescent,
                            });
                        }
                    }
                }

                self.functions.insert(func.address, func);
            }
        }

        let mut result: Vec<DiscoveredFunction> = self.functions.values().cloned().collect();
        result.sort_by_key(|f| f.address);
        Ok(result)
    }

    fn build_region_map<'a>(&self, regions: &'a [crate::CodeRegion]) -> HashMap<u64, &'a crate::CodeRegion> {
        regions.iter().map(|r| (r.address, r)).collect()
    }

    /// Analyze a single function starting at the given address
    fn analyze_function(
        &mut self,
        item: &WorkItem,
        region_map: &HashMap<u64, &crate::CodeRegion>,
    ) -> Result<Option<DiscoveredFunction>> {
        // Find the region containing this address
        let region = match self.find_region_for_address(item.address, region_map) {
            Some(r) => r,
            None => return Ok(None),
        };

        let offset = (item.address - region.address) as usize;
        if offset >= region.data.len() {
            return Ok(None);
        }

        // Quick sanity check: does it look like code?
        if !self.looks_like_code(&region.data[offset..]) {
            return Ok(None);
        }

        // Build basic blocks via linear sweep with control flow tracking
        let blocks = self.build_basic_blocks(item.address, region, region_map)?;

        if blocks.is_empty() {
            return Ok(None);
        }

        // Calculate function size
        let min_addr = blocks.iter().map(|b| b.start).min().unwrap_or(item.address);
        let max_addr = blocks.iter().map(|b| b.end).max().unwrap_or(item.address);
        let size = (max_addr - min_addr + 1) as usize;

        if size < self.config.min_function_size || size > self.config.max_function_size {
            return Ok(None);
        }

        // Check if it's a thunk (single block with just a jump)
        let is_thunk = blocks.len() == 1 && self.is_thunk_block(&blocks[0], region);
        let thunk_target = if is_thunk {
            self.get_jump_target(&blocks[0], region)
        } else {
            None
        };

        Ok(Some(DiscoveredFunction {
            address: item.address,
            size,
            source: item.source.clone(),
            confidence: self.calculate_confidence(&blocks, region),
            name: None,
            is_thunk,
            thunk_target,
            blocks,
        }))
    }

    fn find_region_for_address<'a>(
        &self,
        address: u64,
        region_map: &'a HashMap<u64, &crate::CodeRegion>,
    ) -> Option<&'a crate::CodeRegion> {
        // Check each region
        region_map.values().find(|&region| address >= region.address && address < region.address + region.data.len() as u64).map(|v| v as _)
    }

    /// Quick check if bytes look like executable code
    fn looks_like_code(&self, data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }

        if !self.passes_zero_heuristics(data) {
            return false;
        }

        match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                // Common prologue bytes suggest code
                let first = data[0];
                let prologue_bytes = [0x55, 0x53, 0x56, 0x57, 0x48, 0x41, 0xF3, 0x89, 0x8B];
                prologue_bytes.contains(&first)
                    || data[1] == 0x89 // mov reg, reg
                    || data[1] == 0x8B
                    || data[1] == 0x48 // REX.W prefix
            }
            _ => true,
        }
    }

    /// Zero-density heuristics applied to all architectures:
    /// reject all-zero prefixes and byte streams dominated by zeros.
    fn passes_zero_heuristics(&self, data: &[u8]) -> bool {
        const ZERO_PREFIX_LEN: usize = 8;
        const ZERO_DENSITY_WINDOW: usize = 32;

        if data.len() >= ZERO_PREFIX_LEN && data[..ZERO_PREFIX_LEN].iter().all(|&b| b == 0) {
            return false;
        }

        let window_len = data.len().min(ZERO_DENSITY_WINDOW);
        let zeros = data[..window_len].iter().filter(|&&b| b == 0).count();
        zeros * 2 <= window_len
    }

    /// Build basic blocks via linear sweep
    fn build_basic_blocks(
        &self,
        start_addr: u64,
        region: &crate::CodeRegion,
        _region_map: &HashMap<u64, &crate::CodeRegion>,
    ) -> Result<Vec<BasicBlock>> {
        let mut blocks = Vec::new();
        let mut current_block_start = start_addr;
        let mut addr = start_addr;
        let mut block_id = 0u32;
        let mut block_count = 0;
        const MAX_BLOCKS: usize = 10000;

        while addr < region.address + region.data.len() as u64 && block_count < MAX_BLOCKS {
            let offset = (addr - region.address) as usize;
            if offset >= region.data.len() {
                break;
            }

            let remaining = &region.data[offset..];
            let instr_len = match self.instruction_length(remaining) {
                DecodeOutcome::Length(len) => len,
                DecodeOutcome::Unknown => {
                    // Undecodable or truncated byte: stop this sweep path.
                    // This is a decoder limitation ("stop with warning"), NOT a
                    // verified end-of-function terminator like RET/JMP; blocks
                    // decoded so far are still returned for the function.
                    break;
                }
            };

            let instr_end = addr + instr_len as u64;

            // Check if this instruction terminates the block
            if self.is_terminator(&region.data[offset..offset + instr_len]) {
                // End current block
                let block = BasicBlock {
                    id: block_id,
                    start: current_block_start,
                    end: instr_end - 1,
                    successors: vec![],
                    predecessors: vec![],
                };
                blocks.push(block);
                block_id += 1;
                block_count += 1;

                current_block_start = instr_end;

                // If unconditional jump/ret, we're done with this path
                if self.is_unconditional_terminator(&region.data[offset..offset + instr_len]) {
                    break;
                }
            }

            addr = instr_end;

            // Safety: limit function size
            if (addr - start_addr) > self.config.max_function_size as u64 {
                break;
            }
        }

        // Close final block if needed
        if current_block_start < addr && block_count < MAX_BLOCKS {
            blocks.push(BasicBlock {
                id: block_id,
                start: current_block_start,
                end: addr - 1,
                successors: vec![],
                predecessors: vec![],
            });
        }

        Ok(blocks)
    }

    /// Get instruction length (simplified LDE for x86/x64).
    ///
    /// Fixed-width architectures always report their instruction size.
    /// For x86/x64, undecodable input is reported as [`DecodeOutcome::Unknown`]
    /// rather than a zero-length instruction so callers can distinguish
    /// "decoder gave up" from a real end-of-code condition.
    fn instruction_length(&self, data: &[u8]) -> DecodeOutcome {
        if data.is_empty() {
            return DecodeOutcome::Unknown;
        }

        match self.arch {
            Architecture::X86 => self
                .decode_x86_len(data, false)
                .map_or(DecodeOutcome::Unknown, DecodeOutcome::Length),
            Architecture::X86_64 => self
                .decode_x86_len(data, true)
                .map_or(DecodeOutcome::Unknown, DecodeOutcome::Length),
            Architecture::Arm | Architecture::Arm32 | Architecture::Arm32Thumb
            | Architecture::Arm64 | Architecture::Arm64BE
            | Architecture::Mips | Architecture::MipsEl
            | Architecture::Mips32LE | Architecture::Mips32BE
            | Architecture::Mips64LE | Architecture::Mips64BE
            | Architecture::RiscV32 | Architecture::RiscV64
            | Architecture::Ppc32 | Architecture::Ppc64 | Architecture::Ppc64LE
            | Architecture::Sparc32 | Architecture::Sparc64 => DecodeOutcome::Length(4),
        }
    }

    /// Offset of the opcode byte, skipping legacy prefixes (segment overrides,
    /// operand/address-size, lock, rep) and — in 64-bit mode — REX prefixes.
    fn x86_opcode_offset(&self, instr: &[u8]) -> usize {
        let is_64bit = matches!(self.arch, Architecture::X86_64);
        let mut i = 0usize;
        while i < instr.len() {
            match instr[i] {
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67
                | 0xF0 | 0xF2 | 0xF3 => i += 1,
                0x40..=0x4F if is_64bit => i += 1,
                _ => break,
            }
        }
        i
    }

    /// Simplified x86/x64 length decoder. Returns `None` for unknown
    /// opcode/prefix combinations or truncated instructions instead of
    /// guessing — a wrong guess silently desynchronizes every following
    /// instruction of the sweep.
    ///
    /// Covers the common integer/SSE-adjacent encodings: legacy prefixes,
    /// REX, one-byte ALU/mov/group ops, FPU (D8-DF), and the frequent
    /// two-byte 0F operations (Jcc near, setcc, cmovcc, movzx/movsx, bt*,
    /// imul, bswap, SSE moves).
    fn decode_x86_len(&self, data: &[u8], is_64bit: bool) -> Option<usize> {
        let mut i = 0usize;
        let mut o66 = false;

        // Legacy prefixes + (x64 only) REX. Realistic code emits them in
        // canonical order; we accept either interleaving since only lengths matter.
        while i < data.len() {
            match data[i] {
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x67
                | 0xF0 | 0xF2 | 0xF3 => i += 1,
                0x66 => {
                    o66 = true;
                    i += 1;
                }
                0x40..=0x4F if is_64bit => i += 1,
                _ => break,
            }
        }

        let op = *data.get(i)?;
        let imm32 = if o66 { 2 } else { 4 };

        // Total length = opcode index + body bytes; None when truncated.
        let need = |body: usize| -> Option<usize> {
            if i + body <= data.len() {
                Some(i + body)
            } else {
                None
            }
        };
        // ModRM-based operand after the opcode (`op_len` = 1 or 2 opcode bytes):
        // total length includes opcode(s), ModRM, SIB and displacement.
        let mrm = |op_len: usize| -> Option<usize> {
            let e = self.modrm_extra(data, i + op_len)?;
            need(op_len + e)
        };

        match op {
            // ─── Two-byte escape (0F xx) ────────────────────────────────
            0x0F => {
                let op2 = *data.get(i + 1)?;
                match op2 {
                    // Jcc near: rel32 (rel16 with operand-size override)
                    0x80..=0x8F => need(2 + imm32),
                    // No-ModRM system/misc: syscall/sysret/clts/invd/wbinvd/
                    // ud*/femms, rdtsc family, sysenter/sysexit/getsec,
                    // push/pop fs/gs, cpuid, rsm, bswap
                    0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0A | 0x0B | 0x0C
                    | 0x0E | 0x0F
                    | 0x30..=0x37
                    | 0xA0 | 0xA1 | 0xA2 | 0xA8 | 0xA9 | 0xAA
                    | 0xC8..=0xCF => need(2),
                    // ModRM + trailing imm8: pshuf*/shift groups, shld/shrd imm8,
                    // bt group imm8, cmpps, pinsrw/pextrw/shufp*
                    0x70..=0x73 | 0xA4 | 0xAC | 0xBA | 0xC2 | 0xC4 | 0xC5 | 0xC6 => {
                        let e = self.modrm_extra(data, i + 2)?;
                        need(2 + e + 1)
                    }
                    // Refuse to guess: three-byte escapes (#UD-prone imm tails)
                    // and undefined slots
                    0x38 | 0x3A | 0xA6 | 0xA7 | 0xB9 => None,
                    // Everything else commonly takes a ModRM byte (movzx/movsx/
                    // setcc/cmovcc/bt*/xadd/imul/SSE moves/groups...)
                    _ => mrm(2),
                }
            }

            // ─── One-byte ModRM operations ──────────────────────────────
            // ALU r/m,r and r,r/m families, bound/arpl, test/xchg/mov,
            // shifts by CL, FPU stack ops, inc/dec & call/jmp groups
            0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B
            | 0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B
            | 0x62 | 0x63
            | 0x84..=0x87 | 0x88..=0x8F
            | 0xD0..=0xD3 | 0xD8..=0xDF
            | 0xFE | 0xFF => mrm(1),
            // Group 1: ALU r/m, imm8/imm32 (add/or/adc/sbb/and/sub/xor/cmp)
            // (0x82 aliases 0x80 but is invalid in long mode)
            0x80 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + 1)
            }
            0x81 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + imm32)
            }
            0x82 if !is_64bit => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + 1)
            }
            0x83 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + 1)
            }
            // imul r,r/m,imm
            0x69 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + imm32)
            }
            0x6B => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + 1)
            }
            // Shift group with imm8
            0xC0 | 0xC1 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + 1)
            }
            // mov r/m, imm
            0xC6 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + 1)
            }
            0xC7 => {
                let e = self.modrm_extra(data, i + 1)?;
                need(1 + e + imm32)
            }
            // Group 3 (test/not/neg/mul/imul/div/idiv); test forms carry imm
            0xF6 => {
                let e = self.modrm_extra(data, i + 1)?;
                let reg = (data[i + 1] >> 3) & 7;
                need(1 + e + if reg < 2 { 1 } else { 0 })
            }
            0xF7 => {
                let e = self.modrm_extra(data, i + 1)?;
                let reg = (data[i + 1] >> 3) & 7;
                need(1 + e + if reg < 2 { imm32 } else { 0 })
            }

            // ─── Immediate accumulator forms ────────────────────────────
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => need(2),
            0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => need(1 + imm32),

            // ─── Stack / control flow ───────────────────────────────────
            0x50..=0x5F => need(1),
            0x68 => need(1 + imm32),
            0x6A => need(2),
            0x70..=0x7F | 0xE0..=0xE3 => need(2),
            0xE8 | 0xE9 => need(1 + imm32),
            0xEB => need(2),
            0xEA if !is_64bit => need(1 + imm32 + 2),

            // ─── String / accumulator / register-immediate moves ────────
            0xA4..=0xA7 | 0xAA..=0xAF => need(1),
            0xA8 => need(2),
            0xA9 => need(1 + imm32),
            0xA0..=0xA3 => need(1 + imm32),
            0xB0..=0xB7 => need(2),
            0xB8..=0xBF => need(1 + imm32),

            // ─── Single-byte instructions ───────────────────────────────
            0xCC | 0xCE | 0xCF | 0xD7 | 0xF1 | 0xF4 | 0xF5 | 0xF8..=0xFD
            | 0x90 | 0x98 | 0x99 | 0x9B | 0x9C..=0x9F => need(1),
            0xC2 | 0xCA => need(3),
            0xC3 | 0xCB => need(1),
            0xCD => need(2),
            0xE4..=0xE7 => need(2),

            // ─── 32-bit-only encodings (invalid in long mode) ───────────
            0x40..=0x4F if !is_64bit => need(1),
            0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F
            | 0x27 | 0x2F | 0x37 | 0x3F | 0x60 | 0x61
            | 0xD4 | 0xD5 if !is_64bit => need(1),

            _ => None,
        }
    }

    /// Size of the operand starting at `pos` (the ModRM byte itself plus any
    /// SIB byte and displacement). Returns `None` when the encoding is
    /// truncated by the end of the buffer.
    fn modrm_extra(&self, data: &[u8], pos: usize) -> Option<usize> {
        let modrm = *data.get(pos)?;
        let mod_bits = modrm >> 6;
        let rm = modrm & 7;

        let mut extra = 1usize; // ModRM byte itself

        // SIB byte follows when rm == 100b with memory addressing
        if rm == 4 && mod_bits != 0b11 {
            let sib = *data.get(pos + 1)?;
            extra += 1;
            // SIB base 101b with mod 00b has an additional disp32 (no base)
            if sib & 7 == 5 && mod_bits == 0b00 {
                extra += 4;
            }
        }

        extra += match mod_bits {
            0b00 => {
                if rm == 5 {
                    4 // [disp32]
                } else {
                    0
                }
            }
            0b01 => 1, // [reg + disp8]
            0b10 => 4, // [reg + disp32]
            _ => 0,    // register direct
        };

        Some(extra)
    }

    /// Check if instruction terminates a basic block (any control transfer:
    /// ret, call, jmp, jcc, loop, hlt).
    fn is_terminator(&self, instr: &[u8]) -> bool {
        if instr.is_empty() {
            return false;
        }

        match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                let pos = self.x86_opcode_offset(instr);
                let Some((op, after)) = self.x86_split_opcode(instr, pos) else {
                    return false;
                };
                match op {
                    0xC2..=0xC3 | 0xCA..=0xCB => true, // ret / ret imm16
                    0xE8..=0xEB => true,               // call rel32, jmp rel32/rel8/far
                    0x70..=0x7F | 0xE0..=0xE3 => true, // jcc short, loop*, jecxz/jrcxz
                    0xF4 => true,                      // hlt
                    // FF /2 near call, FF /3 far call, FF /4 jmp r/m, FF /5 ljmp.
                    // Other FF subgroups (/0 inc, /1 dec, /6 push) are NOT control flow.
                    0xFF => matches!(after.first().map(|m| (m >> 3) & 7), Some(2..=5)),
                    // Jcc near rel32 (conditional)
                    0x0F => matches!(after.first(), Some(0x80..=0x8F)),
                    _ => false,
                }
            }
            _ => false, // TODO: ARM/MIPS terminators
        }
    }

    /// Check if instruction ends the current function path with NO fallthrough:
    /// ret family, unconditional jumps (including `jmp r/m` — previously missed,
    /// which caused fallthrough into padding), far jmp and hlt. Indirect calls
    /// (`FF /2`, `FF /3`) terminate their basic block but execution continues at
    /// the next instruction, so they are NOT unconditional terminators here.
    fn is_unconditional_terminator(&self, instr: &[u8]) -> bool {
        if instr.is_empty() {
            return false;
        }

        match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                let pos = self.x86_opcode_offset(instr);
                let Some((op, after)) = self.x86_split_opcode(instr, pos) else {
                    return false;
                };
                match op {
                    0xC2..=0xC3 | 0xCA..=0xCB => true, // ret / ret imm16
                    0xE9..=0xEB => true,               // jmp rel32 / rel8 / far
                    // jmp r/m (FF /4) and ljmp r/m (FF /5); calls (/2, /3) continue
                    0xFF => matches!(after.first().map(|m| (m >> 3) & 7), Some(4 | 5)),
                    0xF4 => true, // hlt
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Split the instruction at the opcode byte into (opcode, following bytes),
    /// or None when prefixes consumed the whole buffer (truncated encoding).
    fn x86_split_opcode<'a>(&self, instr: &'a [u8], pos: usize) -> Option<(u8, &'a [u8])> {
        let rest = instr.get(pos..)?;
        let (&op, after) = rest.split_first()?;
        Some((op, after))
    }

    fn is_thunk_block(&self, block: &BasicBlock, region: &crate::CodeRegion) -> bool {
        let offset = (block.start - region.address) as usize;
        let len = (block.end - block.start + 1) as usize;
        if offset + len > region.data.len() {
            return false;
        }

        let data = &region.data[offset..offset + len];

        // Thunk: just a JMP (direct or indirect)
        matches!(data[0], 0xE9 | 0xEB | 0xFF)
    }

    fn get_jump_target(&self, block: &BasicBlock, region: &crate::CodeRegion) -> Option<u64> {
        let offset = (block.start - region.address) as usize;
        if offset >= region.data.len() {
            return None;
        }

        let data = &region.data[offset..];
        if data.is_empty() {
            return None;
        }

        // Skip prefixes so prefixed jumps (66/F2/F3/segment/REX) resolve too.
        let pos = self.x86_opcode_offset(data);
        match *data.get(pos)? {
            // JMP rel32
            0xE9 => {
                let rel_bytes = data.get(pos + 1..pos + 5)?;
                let rel = i32::from_le_bytes([rel_bytes[0], rel_bytes[1], rel_bytes[2], rel_bytes[3]]);
                let target = (block.start as i64 + pos as i64 + 5 + rel as i64) as u64;
                Some(target)
            }
            // JMP rel8
            0xEB => {
                let rel = *data.get(pos + 1)? as i8;
                let target = (block.start as i64 + pos as i64 + 2 + rel as i64) as u64;
                Some(target)
            }
            _ => None,
        }
    }

    fn find_callees(&self, block: &BasicBlock, region_map: &HashMap<u64, &crate::CodeRegion>) -> Vec<u64> {
        let mut callees = Vec::new();

        // Find the region containing this block
        let region = region_map
            .values()
            .find(|r| block.start >= r.address && block.end < r.address + r.data.len() as u64);

        let region = match region {
            Some(r) => r,
            None => return callees,
        };

        // Scan block for CALL instructions
        let mut addr = block.start;
        while addr <= block.end {
            let offset = (addr - region.address) as usize;
            if offset >= region.data.len() {
                break;
            }

            let remaining = &region.data[offset..];
            let instr_len = match self.instruction_length(remaining) {
                DecodeOutcome::Length(len) => len,
                DecodeOutcome::Unknown => break, // stop with warning; do not guess
            };

            // Check for CALL rel32 (also under legacy/REX prefixes)
            let pos = self.x86_opcode_offset(remaining);
            if remaining.get(pos) == Some(&0xE8) && instr_len >= pos + 5 {
                let rel = i32::from_le_bytes([
                    remaining[pos + 1],
                    remaining[pos + 2],
                    remaining[pos + 3],
                    remaining[pos + 4],
                ]);
                let target = (addr as i64 + pos as i64 + 5 + rel as i64) as u64;
                callees.push(target);
            }

            addr += instr_len as u64;
        }

        callees
    }

    fn calculate_confidence(&self, blocks: &[BasicBlock], _region: &crate::CodeRegion) -> f32 {
        if blocks.is_empty() {
            return 0.0;
        }

        // Base confidence from block count
        let mut conf: f32 = 0.5;

        // Multiple blocks suggest structured code
        if blocks.len() >= 3 {
            conf += 0.1;
        }

        // Larger functions are more likely to be real
        let total_size: u64 = blocks.iter().map(|b| b.end - b.start + 1).sum();
        if total_size >= 32 {
            conf += 0.1;
        }
        if total_size >= 128 {
            conf += 0.1;
        }

        conf.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzer(arch: Architecture) -> RecursiveAnalyzer {
        RecursiveAnalyzer::new(arch, FinderConfig::default())
    }

    #[test]
    fn test_rejects_zero_prefix_all_archs() {
        for arch in [
            Architecture::X86,
            Architecture::X86_64,
            Architecture::Arm32,
            Architecture::Arm64,
            Architecture::MipsEl,
            Architecture::RiscV32,
            Architecture::Ppc64,
            Architecture::Sparc32,
        ] {
            let data = [0u8; 32];
            assert!(!analyzer(arch).looks_like_code(&data), "arch {}", arch.as_str());
        }
    }

    #[test]
    fn test_rejects_zero_density_over_50_percent() {
        for arch in [Architecture::Arm32, Architecture::RiscV64, Architecture::X86_64] {
            let mut data = vec![0u8; 17];
            data.extend_from_slice(&[0xE1, 0xA0, 0xF0, 0x00]);
            assert!(
                !analyzer(arch).looks_like_code(&data),
                "arch {}",
                arch.as_str()
            );
        }
    }

    #[test]
    fn test_accepts_plausible_non_x86_code() {
        let data = [
            0x04, 0xB0, 0x2D, 0xE5, 0x00, 0x40, 0xA0, 0xE1, 0x01, 0x00, 0xA0, 0xE3,
            0x08, 0xD0, 0x4B, 0xE2, 0x1E, 0xFF, 0x2F, 0xE1,
        ];
        assert!(analyzer(Architecture::Arm32).looks_like_code(&data));
        assert!(analyzer(Architecture::RiscV32).looks_like_code(&data));
    }

    #[test]
    fn test_x86_still_requires_prologue_hint() {
        let data = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];
        assert!(!analyzer(Architecture::X86_64).looks_like_code(&data));
    }

    // ─── LDE: two-byte 0F opcodes ────────────────────────────────────────

    #[test]
    fn lde_jcc_near_rel32() {
        // 0F 84 de ad be ef = JE rel32
        let a = analyzer(Architecture::X86_64);
        assert_eq!(
            a.instruction_length(&[0x0F, 0x84, 0xDE, 0xAD, 0xBE, 0xEF]),
            DecodeOutcome::Length(6)
        );
        assert_eq!(
            a.instruction_length(&[0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00]),
            DecodeOutcome::Length(6)
        );
    }

    #[test]
    fn lde_movzx_movsx_setcc_cmov() {
        let a = analyzer(Architecture::X86_64);
        // movzx eax, byte [rbp+8] = 0F B6 45 08 (mod01 disp8) -> 4 bytes
        assert_eq!(a.instruction_length(&[0x0F, 0xB6, 0x45, 0x08]), DecodeOutcome::Length(4));
        // movsx ecx, word [eax] = 0F BF 08 (mod00 reg-indirect) -> 3 bytes
        assert_eq!(a.instruction_length(&[0x0F, 0xBF, 0x08]), DecodeOutcome::Length(3));
        // setne al = 0F 95 C0 (register form) -> 3 bytes
        assert_eq!(a.instruction_length(&[0x0F, 0x95, 0xC0]), DecodeOutcome::Length(3));
        // cmovne ecx, eax = 0F 45 C8 -> 3 bytes
        assert_eq!(a.instruction_length(&[0x0F, 0x45, 0xC8]), DecodeOutcome::Length(3));
    }

    #[test]
    fn lde_two_byte_misc_and_truncation() {
        let a = analyzer(Architecture::X86_64);
        // bswap eax = 0F C8
        assert_eq!(a.instruction_length(&[0x0F, 0xC8]), DecodeOutcome::Length(2));
        // rdtsc = 0F 31 (no ModRM)
        assert_eq!(a.instruction_length(&[0x0F, 0x31]), DecodeOutcome::Length(2));
        // imul ecx, [eax] = 0F AF 08 -> 3 bytes
        assert_eq!(a.instruction_length(&[0x0F, 0xAF, 0x08]), DecodeOutcome::Length(3));
        // Truncated jcc: only 0F 84 present -> Unknown, never a fake length
        assert_eq!(a.instruction_length(&[0x0F, 0x84, 0x00, 0x00]), DecodeOutcome::Unknown);
    }

    // ─── LDE: prefixes ───────────────────────────────────────────────────

    #[test]
    fn lde_legacy_prefixes() {
        // mov eax, imm32 with operand-size override: 66 B8 xx xx -> 4 bytes total
        let a = analyzer(Architecture::X86);
        assert_eq!(a.instruction_length(&[0x66, 0xB8, 0x34, 0x12]), DecodeOutcome::Length(4));
        // rep nop (pause): F3 90 -> 2 bytes
        assert_eq!(a.instruction_length(&[0xF3, 0x90]), DecodeOutcome::Length(2));
        // CS-prefixed mov: 2E 89 D8 (mod11) -> 3 bytes
        assert_eq!(a.instruction_length(&[0x2E, 0x89, 0xD8]), DecodeOutcome::Length(3));

        // REX.W + mov r/m64, r64: 48 89 E5 -> 3 bytes
        let a64 = analyzer(Architecture::X86_64);
        assert_eq!(a64.instruction_length(&[0x48, 0x89, 0xE5]), DecodeOutcome::Length(3));
        // REX.W + sub rsp, imm8: 48 83 EC 20 -> 4 bytes
        assert_eq!(a64.instruction_length(&[0x48, 0x83, 0xEC, 0x20]), DecodeOutcome::Length(4));
    }

    #[test]
    fn lde_modrm_sib_displacement() {
        let a = analyzer(Architecture::X86_64);
        // mov rax, [rsp+8] = 48 8B 44 24 08 (SIB + disp8) -> 5 bytes
        assert_eq!(a.instruction_length(&[0x48, 0x8B, 0x44, 0x24, 0x08]), DecodeOutcome::Length(5));
        // mov rax, [rip+disp32] = 48 8B 05 de ad be ef -> 7 bytes
        assert_eq!(
            a.instruction_length(&[0x48, 0x8B, 0x05, 0xDE, 0xAD, 0xBE, 0xEF]),
            DecodeOutcome::Length(7)
        );
    }

    // ─── LDE: unknown vs terminator ──────────────────────────────────────

    #[test]
    fn lde_unknown_opcode_reports_unknown_not_zero() {
        let a = analyzer(Architecture::X86_64);
        // VEX (AVX) prefix — unsupported, must be Unknown (stop with warning),
        // never a silent 0-length "end of function".
        assert_eq!(a.instruction_length(&[0xC4, 0xE2, 0x7D, 0x00, 0x00]), DecodeOutcome::Unknown);
        // Three-byte escape 0F 38 — refused rather than guessed.
        assert_eq!(a.instruction_length(&[0x0F, 0x38, 0x00, 0xC0]), DecodeOutcome::Unknown);
        // Truncated call rel32
        assert_eq!(a.instruction_length(&[0xE8, 0x00, 0x00]), DecodeOutcome::Unknown);
    }

    #[test]
    fn sweep_stops_on_unknown_without_faking_function_end() {
        // Decodable prologue ... then an unsupported VEX instruction ... then ret.
        // The sweep must stop at the undecodable byte and simply end the path;
        // blocks decoded so far are kept instead of silently mis-sized.
        let code = vec![
            0x55,                         // push rbp
            0x48, 0x89, 0xE5,             // mov rbp, rsp
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x31, 0xC0,                   // xor eax, eax
            0xC4, 0xE2, 0x7D, 0x00, 0xC0, // unsupported VEX instruction
            0xC3,                         // ret (never reached by the sweep)
        ];
        let region = crate::CodeRegion { address: 0x401000, data: code, executable: true };
        let mut a = RecursiveAnalyzer::new(Architecture::X86_64, FinderConfig::default());
        a.add_entry_point(0x401000);

        let funcs = a.analyze(&[region]).unwrap();
        assert_eq!(funcs.len(), 1);
        // Only the decodable prefix of the function was swept.
        assert_eq!(funcs[0].blocks.len(), 1);
        assert_eq!(funcs[0].blocks[0].start, 0x401000);
        assert_eq!(funcs[0].blocks[0].end, 0x40100A); // ends after `xor eax, eax`
    }

    // ─── Terminators: FF indirect call/jmp ───────────────────────────────

    #[test]
    fn ff_indirect_jmp_is_unconditional_terminator() {
        let a = analyzer(Architecture::X86_64);
        // FF 25 xx xx xx xx = jmp [rip+disp32]
        let jmp = [0xFF, 0x25, 0xDE, 0xAD, 0xBE, 0xEF];
        assert!(a.is_terminator(&jmp));
        assert!(a.is_unconditional_terminator(&jmp));

        // FF 15 xx xx xx xx = call [rip+disp32]: block terminator, but
        // execution continues afterwards (NOT a function-end).
        let call = [0xFF, 0x15, 0xDE, 0xAD, 0xBE, 0xEF];
        assert!(a.is_terminator(&call));
        assert!(!a.is_unconditional_terminator(&call));

        // FF /0 (inc r/m) is not control flow at all.
        let inc = [0xFF, 0x00];
        assert!(!a.is_terminator(&inc));
    }

    #[test]
    fn indirect_jmp_ends_sweep_at_padding_boundary() {
        // thunk: jmp qword [rip+0] then int3 padding must NOT be swallowed
        // into the function as fallthrough (FF /4 was previously not treated
        // as an unconditional terminator).
        let mut code = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]; // jmp [rip]
        code.extend_from_slice(&[0xCC; 16]);
        let region = crate::CodeRegion { address: 0x401000, data: code, executable: true };

        let a = analyzer(Architecture::X86_64);
        let blocks = a.build_basic_blocks(0x401000, &region, &HashMap::new()).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start, 0x401000);
        // Function path ends right after the 6-byte jmp, never in the padding.
        assert_eq!(blocks[0].end, 0x401005);
    }
}
