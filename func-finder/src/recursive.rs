//! Recursive descent function discovery
//!
//! Starting from known entry points, follows calls and jumps to discover
//! additional functions. This is the most reliable method because it only
//! reports functions that are actually reachable.

use crate::{
    Architecture, BasicBlock, DiscoveredFunction, FinderConfig, FinderError,
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
        for region in region_map.values() {
            if address >= region.address && address < region.address + region.data.len() as u64 {
                return Some(region);
            }
        }
        None
    }

    /// Quick check if bytes look like executable code
    fn looks_like_code(&self, data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }

        match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                // Reject all-zeros, all-0xFF, all-same-byte
                let first = data[0];
                if data.iter().take(16).all(|&b| b == first) {
                    return false;
                }

                // Common prologue bytes suggest code
                let prologue_bytes = [0x55, 0x53, 0x56, 0x57, 0x48, 0x41, 0xF3, 0x89, 0x8B];
                prologue_bytes.contains(&first)
                    || data[1] == 0x89 // mov reg, reg
                    || data[1] == 0x8B
                    || data[1] == 0x48 // REX.W prefix
            }
            Architecture::Arm | Architecture::Arm32 | Architecture::Arm32Thumb
            | Architecture::Arm64 | Architecture::Arm64BE
            | Architecture::Mips | Architecture::MipsEl
            | Architecture::Mips32LE | Architecture::Mips32BE
            | Architecture::Mips64LE | Architecture::Mips64BE => {
                // ARM/MIPS: instructions are 4-byte aligned
                true // TODO: add specific checks
            }
            Architecture::RiscV32 | Architecture::RiscV64 => {
                // RISC-V: check for common instruction patterns
                true // TODO: add specific checks
            }
            Architecture::Ppc32 | Architecture::Ppc64 | Architecture::Ppc64LE => {
                // PowerPC: 4-byte aligned instructions
                true // TODO: add specific checks
            }
            Architecture::Sparc32 | Architecture::Sparc64 => {
                // SPARC: 4-byte aligned instructions
                true // TODO: add specific checks
            }
        }
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

        let start_offset = (start_addr - region.address) as usize;

        while addr < region.address + region.data.len() as u64 && block_count < MAX_BLOCKS {
            let offset = (addr - region.address) as usize;
            if offset >= region.data.len() {
                break;
            }

            let remaining = &region.data[offset..];
            let instr_len = self.instruction_length(remaining);

            if instr_len == 0 {
                // Invalid instruction, end of function
                break;
            }

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

    /// Get instruction length (simplified LDE for x86/x64)
    fn instruction_length(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        match self.arch {
            Architecture::X86 => self.x86_instruction_length(data),
            Architecture::X86_64 => self.x86_64_instruction_length(data),
            Architecture::Arm | Architecture::Arm32 | Architecture::Arm32Thumb
            | Architecture::Arm64 | Architecture::Arm64BE
            | Architecture::Mips | Architecture::MipsEl
            | Architecture::Mips32LE | Architecture::Mips32BE
            | Architecture::Mips64LE | Architecture::Mips64BE
            | Architecture::RiscV32 | Architecture::RiscV64
            | Architecture::Ppc32 | Architecture::Ppc64 | Architecture::Ppc64LE
            | Architecture::Sparc32 | Architecture::Sparc64 => 4,
        }
    }

    fn x86_instruction_length(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        // Simplified x86 instruction length decoder
        // This handles common cases; for full accuracy, use capstone-ffi
        let opcode = data[0];

        let raw_len = match opcode {
            // Single-byte instructions
            0x90 | 0xC3 | 0xCB | 0xCC | 0xF4 | 0xF5 | 0x98 | 0x99 | 0x9C | 0x9D | 0x9E | 0x9F => 1,
            // ret imm16
            0xC2 => 3,
            // push/pop reg
            0x50..=0x5F => 1,
            // short jumps
            0xEB | 0x70..=0x7F => 2,
            // mov reg, imm8
            0xB0..=0xB7 => 2,
            // mov reg, imm32
            0xB8..=0xBF => 5,
            // Two-byte with ModRM (simplified)
            0x89 | 0x8B | 0x01 | 0x03 | 0x09 | 0x0B | 0x11 | 0x13 | 0x19 | 0x1B | 0x21 | 0x23 | 0x29 | 0x2B | 0x31 | 0x33 | 0x39 | 0x3B => {
                self.decode_modrm_length(data, 1).saturating_add(1)
            }
            // sub/add/etc imm8
            0x83 => self.decode_modrm_length(data, 1).saturating_add(2),
            // sub/add/etc imm32
            0x81 => self.decode_modrm_length(data, 1).saturating_add(5),
            // call/jmp rel32
            0xE8 | 0xE9 => 5,
            // call/jmp indirect
            0xFF => self.decode_modrm_length(data, 1).saturating_add(1),
            // LEA with ModRM
            0x8D => self.decode_modrm_length(data, 1).saturating_add(1),
            _ => {
                // Unknown instruction, bail out
                0
            }
        };

        // Safety: never report instruction longer than available data
        // to prevent OOB reads in caller
        if raw_len > data.len() {
            0
        } else {
            raw_len
        }
    }

    fn x86_64_instruction_length(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        // Check for REX prefix
        let (rex, offset) = if data[0] >= 0x40 && data[0] <= 0x4F {
            (Some(data[0]), 1)
        } else {
            (None, 0)
        };

        if offset >= data.len() {
            return 0;
        }

        let opcode = data[offset];
        let base_len = self.x86_instruction_length(&data[offset..]);

        if base_len == 0 {
            return 0;
        }

        base_len + offset
    }

    fn decode_modrm_length(&self, data: &[u8], modrm_offset: usize) -> usize {
        if modrm_offset >= data.len() {
            return 0;
        }

        let modrm = data[modrm_offset];
        let mod_bits = (modrm >> 6) & 0x03;
        let rm = modrm & 0x07;

        let mut extra = 1usize; // ModRM byte itself

        // SIB byte
        if rm == 0x04 && mod_bits != 0x03 {
            extra += 1;
        }

        // Displacement
        match mod_bits {
            0x00 => {
                if rm == 0x05 {
                    extra += 4; // disp32
                }
            }
            0x01 => extra += 1, // disp8
            0x02 => extra += 4, // disp32
            0x03 => {}          // register direct
            _ => {}
        }

        // Safety: ensure we don't claim more bytes than available
        let available = data.len().saturating_sub(modrm_offset);
        extra.min(available)
    }

    /// Check if instruction terminates a basic block
    fn is_terminator(&self, instr: &[u8]) -> bool {
        if instr.is_empty() {
            return false;
        }

        match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                let opcode = instr[0];
                matches!(
                    opcode,
                    0xC3 | 0xCB | 0xC2 | 0xCA | // ret
                    0xE8 | 0xE9 | 0xEB | // call/jmp
                    0xFF | // indirect call/jmp
                    0x70..=0x7F | // conditional jumps (short)
                    0x0F // extended (conditional jumps near)
                )
            }
            _ => false, // TODO: ARM/MIPS terminators
        }
    }

    fn is_unconditional_terminator(&self, instr: &[u8]) -> bool {
        if instr.is_empty() {
            return false;
        }

        let opcode = instr[0];
        matches!(opcode, 0xC3 | 0xCB | 0xC2 | 0xCA | 0xE9 | 0xEB)
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

        match data[0] {
            // JMP rel32
            0xE9 => {
                if data.len() >= 5 {
                    let rel = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                    let target = (block.start as i64 + 5 + rel as i64) as u64;
                    Some(target)
                } else {
                    None
                }
            }
            // JMP rel8
            0xEB => {
                if data.len() >= 2 {
                    let rel = data[1] as i8;
                    let target = (block.start as i64 + 2 + rel as i64) as u64;
                    Some(target)
                } else {
                    None
                }
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
            let instr_len = self.instruction_length(remaining);
            if instr_len == 0 {
                break;
            }

            // Check for CALL rel32
            if remaining[0] == 0xE8 && instr_len == 5 {
                let rel = i32::from_le_bytes([
                    remaining[1],
                    remaining[2],
                    remaining[3],
                    remaining[4],
                ]);
                let target = (addr as i64 + 5 + rel as i64) as u64;
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
        let mut conf = 0.5;

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
