#![allow(dead_code, unused_assignments)]
//! # Function Finder
//!
//! Finds function boundaries in binary code.
//! Essential for reverse engineering tools — without function detection,
//! you can only analyze the entry point.
//!
//! ## Methods
//!
//! 1. **Prologue scanning**: Search for common function prologues
//! 2. **Recursive descent**: Follow calls/jumps from known entry points
//! 3. **Jump table resolution**: Handle indirect jumps through tables
//! 4. **Function merging**: Merge overlapping function candidates

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod analyzer;
pub mod patterns;
pub mod recursive;

#[derive(Error, Debug)]
pub enum FinderError {
    #[error("No code section provided")]
    NoCode,
    #[error("No code sections provided")]
    NoCodeSections,
    #[error("Invalid offset: {0}")]
    InvalidOffset(usize),
    #[error("Architecture not supported: {0}")]
    UnsupportedArch(String),
}

pub type Result<T> = std::result::Result<T, FinderError>;

/// Architecture-specific function finder
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    // x86 family
    X86,
    X86_64,
    // ARM family
    Arm,
    Arm32,
    Arm32Thumb,
    Arm64,
    Arm64BE,
    // MIPS family
    Mips,
    MipsEl,
    Mips32LE,
    Mips32BE,
    Mips64LE,
    Mips64BE,
    // RISC-V
    RiscV32,
    RiscV64,
    // PowerPC
    Ppc32,
    Ppc64,
    Ppc64LE,
    // SPARC
    Sparc32,
    Sparc64,
}

impl Architecture {
    pub fn as_str(&self) -> &str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86_64",
            Architecture::Arm => "arm",
            Architecture::Arm32 => "arm32",
            Architecture::Arm32Thumb => "arm32_thumb",
            Architecture::Arm64 => "arm64",
            Architecture::Arm64BE => "arm64be",
            Architecture::Mips => "mips",
            Architecture::MipsEl => "mipsel",
            Architecture::Mips32LE => "mips32le",
            Architecture::Mips32BE => "mips32be",
            Architecture::Mips64LE => "mips64le",
            Architecture::Mips64BE => "mips64be",
            Architecture::RiscV32 => "riscv32",
            Architecture::RiscV64 => "riscv64",
            Architecture::Ppc32 => "ppc32",
            Architecture::Ppc64 => "ppc64",
            Architecture::Ppc64LE => "ppc64le",
            Architecture::Sparc32 => "sparc32",
            Architecture::Sparc64 => "sparc64",
        }
    }
}

/// A detected function
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DetectedFunction {
    /// Start address (in file or virtual address space)
    pub start: u64,
    /// Estimated end address (exclusive)
    pub end: u64,
    /// Size in bytes
    pub size: usize,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
    /// How the function was detected
    pub detection_method: DetectionMethod,
    /// Detected function prologue offset (relative to start)
    pub prologue_size: usize,
    /// Whether this is likely a library function
    pub is_library: bool,
    /// Function type
    pub func_type: FunctionKind,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum DetectionMethod {
    /// Found via function prologue pattern
    Prologue,
    /// Found via recursive descent from a known function
    Recursive,
    /// Found via call target resolution
    CallTarget,
    /// User-defined
    Manual,
    /// Merged from overlapping candidates
    Merged,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FunctionKind {
    Normal,
    Thunk,
    Trampoline,
    Library,
    ExceptionHandler,
    JumpTable,
}

// ─── Types used by analyzer / recursive modules ──────────────────────

/// A region of executable code
#[derive(Clone, Debug)]
pub struct CodeRegion {
    pub address: u64,
    pub data: Vec<u8>,
    pub executable: bool,
}

/// Source of a discovered function
#[derive(Clone, Debug, PartialEq)]
pub enum FunctionSource {
    SymbolTable,
    Prologue,
    RecursiveDescent,
    SignatureMatch,
    Manual,
}

/// A basic block within a function
#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub id: u32,
    pub start: u64,
    pub end: u64,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

/// A discovered function with full metadata
#[derive(Clone, Debug)]
pub struct DiscoveredFunction {
    pub address: u64,
    pub size: usize,
    pub source: FunctionSource,
    pub confidence: f32,
    pub name: Option<String>,
    pub is_thunk: bool,
    pub thunk_target: Option<u64>,
    pub blocks: Vec<BasicBlock>,
}

/// Configuration for the function finder
#[derive(Clone, Debug)]
pub struct FinderConfig {
    pub scan_prologues: bool,
    pub recursive_descent: bool,
    pub signature_matching: bool,
    pub min_function_size: usize,
    pub max_function_size: usize,
    pub min_confidence: f32,
    pub max_recursion_depth: usize,
}

impl Default for FinderConfig {
    fn default() -> Self {
        Self {
            scan_prologues: true,
            recursive_descent: true,
            signature_matching: false,
            min_function_size: 4,
            max_function_size: 0x100000,
            // 0.5 rejects weak heuristic candidates (lone 0x55 "push rbp" at 0.3,
            // bare `sub esp/rsp` at 0.4) so they neither appear in results nor
            // seed recursive descent from bogus mid-stream addresses.
            min_confidence: 0.5,
            max_recursion_depth: 64,
        }
    }
}

/// Statistics from function finding
#[derive(Clone, Debug, Default)]
pub struct FinderStats {
    pub symbol_count: usize,
    pub prologue_count: usize,
    pub recursive_count: usize,
    pub signature_count: usize,
    pub thunk_count: usize,
    pub total_blocks: usize,
    pub bytes_analyzed: usize,
}

/// Result of function finding
#[derive(Clone, Debug)]
pub struct FinderResult {
    pub functions: Vec<DiscoveredFunction>,
    pub code_regions: Vec<CodeRegion>,
    pub stats: FinderStats,
}

impl FinderResult {
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

/// Byte pattern for function detection
#[derive(Clone, Debug)]
pub struct Pattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<u8>, // 0xFF = match, 0x00 = wildcard
    pub description: &'static str,
}

impl Pattern {
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        for ((b, pb), m) in data.iter().zip(self.bytes.iter()).zip(self.mask.iter()) {
            if (b & m) != (pb & m) {
                return false;
            }
        }
        true
    }
}

/// Main function finder
pub struct FunctionFinder {
    arch: Architecture,
    prologues: Vec<Pattern>,
    epilogues: Vec<Pattern>,
    code_base: u64,
    max_recursion_depth: usize,
}

impl FunctionFinder {
    pub fn new(arch: Architecture) -> Self {
        let (prologues, epilogues) = Self::patterns_for_arch(&arch);
        Self {
            arch,
            prologues,
            epilogues,
            code_base: 0,
            max_recursion_depth: FinderConfig::default().max_recursion_depth,
        }
    }

    pub fn with_code_base(mut self, base: u64) -> Self {
        self.code_base = base;
        self
    }

    pub fn with_max_recursion_depth(mut self, depth: usize) -> Self {
        self.max_recursion_depth = depth;
        self
    }

    fn patterns_for_arch(arch: &Architecture) -> (Vec<Pattern>, Vec<Pattern>) {
        match arch {
            Architecture::X86 | Architecture::X86_64 => Self::x86_patterns(),
            Architecture::Arm | Architecture::Arm32 | Architecture::Arm32Thumb => {
                Self::arm32_patterns()
            }
            Architecture::Arm64 | Architecture::Arm64BE => Self::arm64_patterns(),
            Architecture::Mips
            | Architecture::MipsEl
            | Architecture::Mips32LE
            | Architecture::Mips32BE
            | Architecture::Mips64LE
            | Architecture::Mips64BE => Self::mips_patterns(),
            Architecture::RiscV32 | Architecture::RiscV64 => Self::riscv_patterns(),
            Architecture::Ppc32 | Architecture::Ppc64 | Architecture::Ppc64LE => {
                Self::ppc_patterns()
            }
            Architecture::Sparc32 | Architecture::Sparc64 => Self::sparc_patterns(),
        }
    }

    fn x86_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // push ebp; mov ebp, esp (classic 32-bit)
            Pattern {
                bytes: vec![0x55, 0x89, 0xE5],
                mask: vec![0xFF, 0xFF, 0xFF],
                description: "push ebp; mov ebp, esp",
            },
            // push rbp; mov rbp, rsp (classic 64-bit)
            Pattern {
                bytes: vec![0x55, 0x48, 0x89, 0xE5],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "push rbp; mov rbp, rsp",
            },
            // sub rsp, XX (function with stack frame, no frame pointer)
            Pattern {
                bytes: vec![0x48, 0x83, 0xEC],
                mask: vec![0xFF, 0xFF, 0xFF],
                description: "sub rsp, imm8",
            },
            // sub rsp, XXXXXXXX (large stack frame)
            Pattern {
                bytes: vec![0x48, 0x81, 0xEC],
                mask: vec![0xFF, 0xFF, 0xFF],
                description: "sub rsp, imm32",
            },
            // NOTE: single-byte prologue "patterns" (push rdi 0x57, push rbx 0x53,
            // enter 0xC8, lone push ebp/rbp 0x55) were removed deliberately: they
            // match thousands of mid-instruction and data locations, flooding the
            // candidate list with false functions. Only multi-byte sequences that
            // actually identify a function entry are kept.
            // Hotpatch prologue: mov edi, edi (2-byte NOP)
            Pattern {
                bytes: vec![0x8B, 0xFF],
                mask: vec![0xFF, 0xFF],
                description: "mov edi, edi (hotpatch)",
            },
            // int3 padding (often precedes functions)
            Pattern {
                bytes: vec![0xCC, 0x55],
                mask: vec![0xFF, 0xFF],
                description: "int3 + push ebp",
            },
        ];

        let epilogues = vec![
            // ret
            Pattern {
                bytes: vec![0xC3],
                mask: vec![0xFF],
                description: "ret",
            },
            // ret N
            Pattern {
                bytes: vec![0xC2],
                mask: vec![0xFF],
                description: "ret imm16",
            },
            // leave; ret
            Pattern {
                bytes: vec![0xC9, 0xC3],
                mask: vec![0xFF, 0xFF],
                description: "leave; ret",
            },
            // pop ebp; ret
            Pattern {
                bytes: vec![0x5D, 0xC3],
                mask: vec![0xFF, 0xFF],
                description: "pop ebp; ret",
            },
            // pop rbp; ret
            Pattern {
                bytes: vec![0x5D, 0xC3],
                mask: vec![0xFF, 0xFF],
                description: "pop rbp; ret",
            },
        ];

        (prologues, epilogues)
    }

    fn arm32_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // push {r4-rN, lr} — little-endian encoded
            // Common encoding: 0xE92D (push with LR in list)
            Pattern {
                bytes: vec![0x2D, 0xE9], // push {..., lr}
                mask: vec![0xFF, 0xFF],
                description: "push {..., lr}",
            },
            // stmdb sp!, {..., lr}
            Pattern {
                bytes: vec![0xF0, 0x4D, 0x2D, 0xE9],
                mask: vec![0xF0, 0x00, 0xFF, 0xFF],
                description: "stmdb sp!, {..., lr}",
            },
        ];

        let epilogues = vec![
            // pop {..., pc}
            Pattern {
                bytes: vec![0xBD, 0xE8],
                mask: vec![0xFF, 0xFF],
                description: "pop {..., pc}",
            },
            // bx lr
            Pattern {
                bytes: vec![0x1E, 0xFF, 0x2F, 0xE1],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "bx lr",
            },
        ];

        (prologues, epilogues)
    }

    fn arm64_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // stp x29, x30, [sp, #-N]! (frame pointer + link register save)
            // Encoding: 0xA9.. (STP pre-index with x29, x30)
            Pattern {
                bytes: vec![0xFD, 0x7B],
                mask: vec![0xFF, 0xFF],
                description: "stp x29, x30, [sp, #-N]!",
            },
            // sub sp, sp, #N
            Pattern {
                bytes: vec![0xFF, 0x03],
                mask: vec![0xFF, 0xFF],
                description: "sub sp, sp, #N",
            },
        ];

        let epilogues = vec![
            // ret
            Pattern {
                bytes: vec![0xC0, 0x03, 0x5F, 0xD6],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "ret",
            },
            // ldp x29, x30, [sp], #N
            Pattern {
                bytes: vec![0xFD, 0x7B],
                mask: vec![0xFF, 0xFF],
                description: "ldp x29, x30, [sp], #N",
            },
        ];

        (prologues, epilogues)
    }

    fn mips_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // addiu sp, sp, -N (LE: 0x27BDxxxx)
            Pattern {
                bytes: vec![0xBD, 0x27],
                mask: vec![0xFF, 0xFF],
                description: "addiu sp,sp,-N",
            },
            // sw ra, N(sp) (LE: 0xAFBFxxxx)
            Pattern {
                bytes: vec![0xBF, 0xAF],
                mask: vec![0xFF, 0xFF],
                description: "sw ra,N(sp)",
            },
            // BE variant: addiu sp,sp,-N (BE: 0x27BDxxxx)
            Pattern {
                bytes: vec![0x27, 0xBD],
                mask: vec![0xFF, 0xFF],
                description: "addiu sp,sp,-N (BE)",
            },
        ];
        let epilogues = vec![
            // jr ra (LE: 0x03E00008)
            Pattern {
                bytes: vec![0x08, 0x00, 0xE0, 0x03],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "jr ra",
            },
            // jr ra (BE)
            Pattern {
                bytes: vec![0x03, 0xE0, 0x00, 0x08],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "jr ra (BE)",
            },
        ];
        (prologues, epilogues)
    }

    fn riscv_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // addi sp, sp, -N (compressed: c.addi16sp = 0x71xx)
            Pattern {
                bytes: vec![0x71],
                mask: vec![0xFF],
                description: "c.addi16sp",
            },
            // sd ra, N(sp) (64-bit store ra: 0xE406 or full: 0x23Bxxxxx)
            Pattern {
                bytes: vec![0x06, 0xE4],
                mask: vec![0xFF, 0xFF],
                description: "c.sdsp ra",
            },
            // Full addi sp,sp,-imm (0x00110113 pattern)
            Pattern {
                bytes: vec![0x93, 0x01],
                mask: vec![0xFF, 0xFF],
                description: "addi sp,sp,-N",
            },
        ];
        let epilogues = vec![
            // ret (compressed c.ret = 0x8082)
            Pattern {
                bytes: vec![0x82, 0x80],
                mask: vec![0xFF, 0xFF],
                description: "c.ret",
            },
            // jalr zero, ra, 0 (full ret = 0x00008067)
            Pattern {
                bytes: vec![0x67, 0x80, 0x00, 0x00],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "ret (jalr x0,ra)",
            },
        ];
        (prologues, epilogues)
    }

    fn ppc_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // stwu r1, -N(r1) (0x9421xxxx BE)
            Pattern {
                bytes: vec![0x94, 0x21],
                mask: vec![0xFF, 0xFF],
                description: "stwu r1,-N(r1)",
            },
            // mflr r0 (0x7C0802A6 BE)
            Pattern {
                bytes: vec![0x7C, 0x08, 0x02, 0xA6],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "mflr r0",
            },
            // stw r0, N(r1) save LR (0x90010004 BE)
            Pattern {
                bytes: vec![0x90, 0x01],
                mask: vec![0xFF, 0xFF],
                description: "stw r0,N(r1)",
            },
        ];
        let epilogues = vec![
            // blr (branch to link register = 0x4E800020 BE)
            Pattern {
                bytes: vec![0x4E, 0x80, 0x00, 0x20],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "blr",
            },
        ];
        (prologues, epilogues)
    }

    fn sparc_patterns() -> (Vec<Pattern>, Vec<Pattern>) {
        let prologues = vec![
            // save %sp, -N, %sp (0x9DE3Bxxx BE)
            Pattern {
                bytes: vec![0x9D, 0xE3],
                mask: vec![0xFF, 0xFF],
                description: "save %sp,-N,%sp",
            },
        ];
        let epilogues = vec![
            // ret + restore (0x81C7E008 BE)
            Pattern {
                bytes: vec![0x81, 0xC7, 0xE0, 0x08],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "ret; restore",
            },
            // retl (0x81C3E008 BE)
            Pattern {
                bytes: vec![0x81, 0xC3, 0xE0, 0x08],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
                description: "retl",
            },
        ];
        (prologues, epilogues)
    }

    /// Find all functions using all methods
    pub fn find_all(&self, code: &[u8], entry_points: &[u64]) -> Result<Vec<DetectedFunction>> {
        if code.is_empty() {
            return Err(FinderError::NoCode);
        }

        let mut functions = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Method 1: Prologue scanning
        let prologue_funcs = self.find_by_prologue(code)?;
        for f in prologue_funcs {
            if seen.insert(f.start) {
                functions.push(f);
            }
        }

        // Method 2: Recursive descent from entry points
        for &ep in entry_points {
            let recursive_funcs = self.find_recursive(code, ep)?;
            for f in recursive_funcs {
                if seen.insert(f.start) {
                    functions.push(f);
                }
            }
        }

        // Sort by address
        functions.sort_by_key(|f| f.start);

        // Merge overlapping functions
        let merged = self.merge_overlapping(functions);

        Ok(merged)
    }

    /// Find functions by scanning for prologue patterns
    pub fn find_by_prologue(&self, code: &[u8]) -> Result<Vec<DetectedFunction>> {
        let mut functions = Vec::new();

        for offset in 0..code.len() {
            for pattern in &self.prologues {
                if pattern.matches(&code[offset..]) {
                    // Found a prologue — try to find the end
                    let end = self
                        .find_function_end(code, offset)
                        .unwrap_or((offset + 64).min(code.len())); // fallback: assume 64 bytes

                    functions.push(DetectedFunction {
                        start: self.code_base + offset as u64,
                        end: self.code_base + end as u64,
                        size: end - offset,
                        confidence: 0.7,
                        detection_method: DetectionMethod::Prologue,
                        prologue_size: pattern.bytes.len(),
                        is_library: false,
                        func_type: FunctionKind::Normal,
                    });
                    break; // one match per offset
                }
            }
        }

        Ok(functions)
    }

    /// Recursive descent from a known entry point
    pub fn find_recursive(&self, code: &[u8], entry: u64) -> Result<Vec<DetectedFunction>> {
        let mut functions = Vec::new();
        let mut worklist = std::collections::VecDeque::new();
        let mut visited = std::collections::HashSet::new();

        // Convert entry to offset
        let entry_offset = if entry >= self.code_base {
            (entry - self.code_base) as usize
        } else {
            entry as usize
        };

        if entry_offset < code.len() {
            worklist.push_back((entry_offset, 0usize));
        }

        while let Some((offset, depth)) = worklist.pop_front() {
            if offset >= code.len() {
                continue;
            }
            if depth > self.max_recursion_depth {
                continue;
            }
            if visited.contains(&offset) {
                continue;
            }
            visited.insert(offset);

            // Analyze this function
            let end = self
                .find_function_end(code, offset)
                .unwrap_or((offset + 64).min(code.len()));

            functions.push(DetectedFunction {
                start: self.code_base + offset as u64,
                end: self.code_base + end as u64,
                size: end - offset,
                confidence: 0.85,
                detection_method: DetectionMethod::Recursive,
                prologue_size: 0,
                is_library: false,
                func_type: FunctionKind::Normal,
            });

            // Find call targets within this function
            let call_targets = self.find_call_targets(code, offset, end);
            for target in call_targets {
                let target_offset = if target >= self.code_base {
                    (target - self.code_base) as usize
                } else {
                    target as usize
                };

                if target_offset < code.len() && !visited.contains(&target_offset) {
                    worklist.push_back((target_offset, depth + 1));
                }
            }
        }

        Ok(functions)
    }

    /// Find the end of a function starting at the given offset
    fn find_function_end(&self, code: &[u8], start: usize) -> Option<usize> {
        // Scan forward looking for an epilogue
        let max_scan = 4096; // don't scan more than 4KB
        let end = (start + max_scan).min(code.len());

        for offset in start..end {
            for pattern in &self.epilogues {
                if pattern.matches(&code[offset..]) {
                    // Include the epilogue in the function
                    return Some(offset + pattern.bytes.len());
                }
            }

            // Stop if we hit another function prologue
            if offset > start {
                for pattern in &self.prologues {
                    if pattern.matches(&code[offset..]) {
                        return Some(offset);
                    }
                }
            }
        }

        None
    }

    /// Find call targets within a range
    fn find_call_targets(&self, code: &[u8], start: usize, end: usize) -> Vec<u64> {
        let mut targets = Vec::new();

        match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                for offset in start..end.saturating_sub(5) {
                    // E8 xx xx xx xx (call rel32) — bounds first, then byte
                    if offset + 5 <= code.len() && code[offset] == 0xE8 {
                        let rel = i32::from_le_bytes([
                            code[offset + 1],
                            code[offset + 2],
                            code[offset + 3],
                            code[offset + 4],
                        ]);
                        let target =
                            (self.code_base + offset as u64 + 5).wrapping_add(rel as i64 as u64);
                        targets.push(target);
                    }
                }
            }
            _ => {
                // TODO: implement for other architectures
            }
        }

        targets
    }

    /// Merge overlapping function candidates
    fn merge_overlapping(&self, mut functions: Vec<DetectedFunction>) -> Vec<DetectedFunction> {
        if functions.is_empty() {
            return functions;
        }

        functions.sort_by_key(|f| f.start);

        let mut merged = Vec::new();
        let mut current = functions[0].clone();

        for f in functions.iter().skip(1) {
            if f.start <= current.end {
                // Overlapping — merge
                current.end = current.end.max(f.end);
                current.size = (current.end - current.start) as usize;
                current.confidence = current.confidence.max(f.confidence);
                current.detection_method = DetectionMethod::Merged;
            } else {
                merged.push(current);
                current = f.clone();
            }
        }
        merged.push(current);

        merged
    }

    /// Detect if a function is a library function by signature
    pub fn is_library_function(&self, code: &[u8], offset: usize) -> bool {
        // Check for common library function patterns
        // This is a simplified version — a real implementation would use
        // FLIRT-like signature matching

        // Check for "thunk" pattern: jmp [target]
        if offset + 6 <= code.len() && code[offset] == 0xFF && (code[offset + 1] & 0x38) == 0x20 {
            return true; // jmp [reg/abs]
        }

        false
    }
}

/// Quick function detection for common architectures
pub fn find_functions(
    code: &[u8],
    arch: Architecture,
    entry_points: &[u64],
) -> Result<Vec<DetectedFunction>> {
    let finder = FunctionFinder::new(arch);
    finder.find_all(code, entry_points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_prologue_detection() {
        let finder = FunctionFinder::new(Architecture::X86);

        // push ebp; mov ebp, esp; sub esp, 0x10; ...; ret
        let code = vec![
            0x55, 0x89, 0xE5, // push ebp; mov ebp, esp
            0x83, 0xEC, 0x10, // sub esp, 0x10
            0x31, 0xC0, // xor eax, eax
            0xC9, 0xC3, // leave; ret
        ];

        let functions = finder.find_by_prologue(&code).unwrap();
        assert!(!functions.is_empty());
        assert_eq!(functions[0].start, 0);
    }

    #[test]
    fn test_x86_64_prologue_detection() {
        let finder = FunctionFinder::new(Architecture::X86_64);

        let code = vec![
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x31, 0xC0, // xor eax, eax
            0xC9, 0xC3, // leave; ret
        ];

        let functions = finder.find_by_prologue(&code).unwrap();
        assert!(!functions.is_empty());
    }

    #[test]
    fn test_recursive_descent() {
        let finder = FunctionFinder::new(Architecture::X86_64);

        // main: push rbp; call sub; ret
        // sub: push rbp; xor eax, eax; ret
        let code = vec![
            // main at offset 0
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
            0xE8, 0x04, 0x00, 0x00, 0x00, // call +4 (relative)
            0xC3, // ret
            0x00, // padding
            // sub at offset 11
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
            0x31, 0xC0, // xor eax, eax
            0xC9, 0xC3, // leave; ret
        ];

        let functions = finder.find_recursive(&code, 0).unwrap();
        assert!(!functions.is_empty());
    }

    #[test]
    fn test_merge_overlapping() {
        let finder = FunctionFinder::new(Architecture::X86_64);

        let functions = vec![
            DetectedFunction {
                start: 0,
                end: 100,
                size: 100,
                confidence: 0.7,
                detection_method: DetectionMethod::Prologue,
                prologue_size: 3,
                is_library: false,
                func_type: FunctionKind::Normal,
            },
            DetectedFunction {
                start: 50,
                end: 150,
                size: 100,
                confidence: 0.8,
                detection_method: DetectionMethod::Recursive,
                prologue_size: 0,
                is_library: false,
                func_type: FunctionKind::Normal,
            },
        ];

        let merged = finder.merge_overlapping(functions);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 150);
    }

    #[test]
    fn test_recursive_respects_max_depth() {
        // Chain of 5 functions, each calling the next: [E8 01 00 00 00][C3] * 5
        let mut code = Vec::new();
        for _ in 0..5 {
            code.extend_from_slice(&[0xE8, 0x01, 0x00, 0x00, 0x00]);
            code.push(0xC3);
        }

        let deep = FunctionFinder::new(Architecture::X86).with_max_recursion_depth(64);
        assert_eq!(deep.find_recursive(&code, 0).unwrap().len(), 5);

        let shallow = FunctionFinder::new(Architecture::X86)
            .with_code_base(0)
            .with_max_recursion_depth(2);
        let found = shallow.find_recursive(&code, 0).unwrap();
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn test_empty_code() {
        let finder = FunctionFinder::new(Architecture::X86_64);
        let result = finder.find_all(&[], &[0]);
        assert!(result.is_err());
    }
}
