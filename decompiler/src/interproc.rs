//! Interprocedural analysis for the decompiler.
//!
//! Provides cross-function analysis including:
//! - Function summary computation (read/written globals, calling convention)
//! - Calling convention detection from prologue/epilogue patterns
//! - Global variable resolution from absolute address references
//! - Inline function candidate detection

use freakre_ir::{IrFunction, IrInst, IrProgram, OpCode, Ty, Value};
use std::collections::{HashMap, HashSet};

// ─── Function Summary ───────────────────────────────────────────────

/// Compact summary of a function's behavior for interprocedural analysis.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Function name
    pub name: String,
    /// Entry address
    pub address: u64,
    /// Detected calling convention
    pub calling_convention: CallingConvention,
    /// Number of parameters detected
    pub param_count: usize,
    /// Return type (if inferred)
    pub return_type: Option<Ty>,
    /// Whether this function may throw / raise exceptions
    pub may_throw: bool,
    /// Whether this is an inline candidate (small + single caller)
    pub inline_candidate: bool,
    /// Total instruction count
    pub instruction_count: usize,
    /// Global variables read by this function
    pub reads_globals: Vec<u64>,
    /// Global variables written by this function
    pub writes_globals: Vec<u64>,
}

/// Detected calling convention
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    SystemV, // Linux x64
    Win64,   // Windows x64
    Unknown,
}

impl std::fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallingConvention::Cdecl => write!(f, "cdecl"),
            CallingConvention::Stdcall => write!(f, "stdcall"),
            CallingConvention::Fastcall => write!(f, "fastcall"),
            CallingConvention::Thiscall => write!(f, "thiscall"),
            CallingConvention::SystemV => write!(f, "sysv_amd64"),
            CallingConvention::Win64 => write!(f, "win64"),
            CallingConvention::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── Analysis Engine ────────────────────────────────────────────────

/// Run interprocedural analysis on an entire program.
pub fn analyze_program(program: &IrProgram) -> ProgramAnalysis {
    let mut analysis = ProgramAnalysis::new();

    // Phase 1: Compute per-function summaries
    for func in &program.functions {
        let summary = analyze_function(func);
        analysis.summaries.insert(func.name.clone(), summary);
    }

    // Phase 2: Resolve global variables
    analysis.globals = resolve_globals(program);

    // Phase 3: Detect inline candidates
    detect_inline_candidates(program, &mut analysis);

    // Phase 4: Propagate return types through call graph
    propagate_return_types(program, &mut analysis);

    analysis
}

/// Analyze a single function and produce its summary.
pub fn analyze_function(func: &IrFunction) -> FunctionSummary {
    let cc = detect_calling_convention(func);
    let param_count = estimate_param_count(func, cc);
    let return_type = infer_return_type(func);
    let may_throw = check_may_throw(func);
    let reads = find_global_reads(func);
    let writes = find_global_writes(func);

    FunctionSummary {
        name: func.name.clone(),
        address: func.entry_address,
        calling_convention: cc,
        param_count,
        return_type,
        may_throw,
        inline_candidate: false, // Set later in detect_inline_candidates
        instruction_count: func.total_instructions(),
        reads_globals: reads,
        writes_globals: writes,
    }
}

// ─── Calling Convention Detection ───────────────────────────────────

fn detect_calling_convention(func: &IrFunction) -> CallingConvention {
    // Check metadata first
    if let Some(ref cc) = func.metadata.calling_convention {
        return match cc.as_str() {
            "cdecl" => CallingConvention::Cdecl,
            "stdcall" => CallingConvention::Stdcall,
            "fastcall" => CallingConvention::Fastcall,
            "thiscall" => CallingConvention::Thiscall,
            "sysv_amd64" | "systemv" => CallingConvention::SystemV,
            "win64" | "ms_x64" => CallingConvention::Win64,
            _ => CallingConvention::Unknown,
        };
    }

    // Heuristic detection from register usage in first block
    let entry = match func.block(func.entry_block) {
        Some(b) => b,
        None => return CallingConvention::Unknown,
    };

    let mut uses_rcx = false;
    let mut uses_rdx = false;
    let mut uses_r8 = false;
    let mut uses_r9 = false;
    let mut uses_edi = false;
    let mut uses_esi = false;
    let mut stack_cleanup = false;

    for inst in &entry.insts {
        for src in inst.sources() {
            if let Value::Register { name, .. } = src {
                match name.as_str() {
                    "rcx" | "ecx" => uses_rcx = true,
                    "rdx" | "edx" => uses_rdx = true,
                    "r8" | "r8d" => uses_r8 = true,
                    "r9" | "r9d" => uses_r9 = true,
                    "edi" | "rdi" => uses_edi = true,
                    "esi" | "rsi" => uses_esi = true,
                    _ => {}
                }
            }
        }
    }

    // Check epilogue for stack cleanup (stdcall indicator)
    for block in &func.blocks {
        if block.is_return_block() {
            for inst in &block.insts {
                if let IrInst::Binary {
                    op: OpCode::Add,
                    lhs,
                    rhs,
                    ..
                } = inst
                {
                    if let (Value::Register { name, .. }, Value::Const(val)) = (lhs, rhs) {
                        if (name == "esp" || name == "rsp") && *val > 0 {
                            stack_cleanup = true;
                        }
                    }
                }
            }
        }
    }

    // Decision logic.
    // Note: rcx/rdx are argument registers in BOTH Win64 and SysV, so they
    // alone cannot distinguish the conventions. rdi/rsi usage is a strong
    // SystemV signal (they are not Win64 args); rcx+rdx+r8/r9 without any
    // SysV-only register is most consistent with Win64.
    if uses_edi || uses_esi {
        CallingConvention::SystemV
    } else if uses_rcx && uses_rdx && (uses_r8 || uses_r9) {
        CallingConvention::Win64
    } else if stack_cleanup {
        CallingConvention::Stdcall
    } else if uses_rcx && !uses_rdx {
        CallingConvention::Thiscall
    } else if uses_edi && uses_esi {
        // unreachable, kept for clarity of the decision chain
        CallingConvention::SystemV
    } else {
        CallingConvention::Cdecl
    }
}

fn estimate_param_count(func: &IrFunction, cc: CallingConvention) -> usize {
    // Use metadata if available
    if !func.metadata.param_types.is_empty() {
        return func.metadata.param_types.len();
    }

    // Count argument registers used in entry block
    let entry = match func.block(func.entry_block) {
        Some(b) => b,
        None => return 0,
    };

    let arg_regs: &[&str] = match cc {
        CallingConvention::Win64 => &["rcx", "rdx", "r8", "r9"],
        CallingConvention::SystemV => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        CallingConvention::Fastcall => &["ecx", "edx"],
        CallingConvention::Thiscall => &["ecx"],
        _ => &[],
    };

    let mut used = HashSet::new();
    for inst in &entry.insts {
        for src in inst.sources() {
            if let Value::Register { name, .. } = src {
                for (i, reg) in arg_regs.iter().enumerate() {
                    if name == *reg {
                        used.insert(i);
                    }
                }
            }
        }
    }

    used.len()
        .max(if func.metadata.stack_frame_size.unwrap_or(0) > 0 {
            1
        } else {
            0
        })
}

fn infer_return_type(func: &IrFunction) -> Option<Ty> {
    // Check metadata
    if let Some(ref ty) = func.metadata.return_type {
        return Some(ty.clone());
    }

    // Look at return instructions
    for block in &func.blocks {
        if let Some(IrInst::Return { value: Some(val) }) = block.terminator() {
            return Some(val.ty());
        }
    }

    None
}

fn check_may_throw(func: &IrFunction) -> bool {
    let throwing_funcs: HashSet<&str> = [
        "__CxxFrameHandler3",
        "_except_handler3",
        "_except_handler4",
        "__gcc_personality_v0",
        "__gxx_personality_v0",
        "_C_specific_handler",
        "__clang_call_terminate",
        "__cxa_throw",
        "_CxxThrowException",
    ]
    .iter()
    .copied()
    .collect();

    for block in &func.blocks {
        for inst in &block.insts {
            if let IrInst::Call {
                target: Value::Symbol(sym),
                ..
            } = inst
            {
                if throwing_funcs.contains(sym.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

// ─── Global Variable Resolution ─────────────────────────────────────

fn find_global_reads(func: &IrFunction) -> Vec<u64> {
    let mut globals = Vec::new();
    for block in &func.blocks {
        for inst in &block.insts {
            if let IrInst::Load {
                addr: Value::Const(addr_val),
                ..
            } = inst
            {
                // Heuristic: addresses in typical data segment range
                if *addr_val > 0x10000 && (*addr_val as u64) < 0x7FFF_FFFF_FFFF {
                    globals.push(*addr_val as u64);
                }
            }
        }
    }
    globals.sort_unstable();
    globals.dedup();
    globals
}

fn find_global_writes(func: &IrFunction) -> Vec<u64> {
    let mut globals = Vec::new();
    for block in &func.blocks {
        for inst in &block.insts {
            if let IrInst::Store {
                addr: Value::Const(addr_val),
                ..
            } = inst
            {
                if *addr_val > 0x10000 && (*addr_val as u64) < 0x7FFF_FFFF_FFFF {
                    globals.push(*addr_val as u64);
                }
            }
        }
    }
    globals.sort_unstable();
    globals.dedup();
    globals
}

fn resolve_globals(program: &IrProgram) -> HashMap<u64, GlobalInfo> {
    let mut globals: HashMap<u64, GlobalInfo> = HashMap::new();

    // Collect all global references across all functions
    for func in &program.functions {
        for addr in find_global_reads(func) {
            globals
                .entry(addr)
                .or_insert_with(|| GlobalInfo {
                    address: addr,
                    name: format!("g_data_{:X}", addr),
                    read_by: Vec::new(),
                    written_by: Vec::new(),
                    inferred_type: Ty::Unknown,
                })
                .read_by
                .push(func.name.clone());
        }
        for addr in find_global_writes(func) {
            globals
                .entry(addr)
                .or_insert_with(|| GlobalInfo {
                    address: addr,
                    name: format!("g_data_{:X}", addr),
                    read_by: Vec::new(),
                    written_by: Vec::new(),
                    inferred_type: Ty::Unknown,
                })
                .written_by
                .push(func.name.clone());
        }
    }

    // Cross-reference with known globals from program
    for (&addr, data) in &program.globals {
        if let Some(info) = globals.get_mut(&addr) {
            info.name = data.name.clone();
            if let Some(ref ty) = data.ty {
                info.inferred_type = ty.clone();
            }
        }
    }

    globals
}

// ─── Inline Detection ───────────────────────────────────────────────

fn detect_inline_candidates(program: &IrProgram, analysis: &mut ProgramAnalysis) {
    // Count callers for each function
    let mut caller_counts: HashMap<String, usize> = HashMap::new();
    for func in &program.functions {
        for block in &func.blocks {
            for inst in &block.insts {
                if let IrInst::Call {
                    target: Value::Symbol(target_name),
                    ..
                } = inst
                {
                    *caller_counts.entry(target_name.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    // Mark inline candidates: ≤ 5 instructions AND exactly 1 caller
    for (name, summary) in analysis.summaries.iter_mut() {
        let callers = caller_counts.get(name).copied().unwrap_or(0);
        if summary.instruction_count <= 5 && callers == 1 {
            summary.inline_candidate = true;
        }
    }
}

// ─── Return Type Propagation ────────────────────────────────────────

fn propagate_return_types(program: &IrProgram, analysis: &mut ProgramAnalysis) {
    // If a caller has no return type of its own but returns the result of a
    // call whose return type is known, adopt the callee's type. Iterate to a
    // fixed point so types flow through call chains.
    let mut changed = true;
    let mut iterations = 0;

    while changed && iterations < 50 {
        changed = false;
        iterations += 1;

        for func in &program.functions {
            let needs_type = analysis
                .summaries
                .get(&func.name)
                .and_then(|s| s.return_type.as_ref())
                .map(|t| *t == Ty::Unknown)
                .unwrap_or(true);
            if !needs_type {
                continue;
            }

            // Map: dst var id → callee name for calls with known return types.
            let mut known_call_dsts: HashMap<u32, (&str, Ty)> = HashMap::new();
            for block in &func.blocks {
                for inst in &block.insts {
                    if let IrInst::Call {
                        dst: Some(d),
                        target: Value::Symbol(name),
                        ..
                    } = inst
                    {
                        if let Some(id) = d.var_id() {
                            if let Some(callee) = analysis.summaries.get(name) {
                                if let Some(ref rt) = callee.return_type {
                                    if *rt != Ty::Unknown && *rt != Ty::Void {
                                        known_call_dsts.insert(id, (name.as_str(), rt.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if known_call_dsts.is_empty() {
                continue;
            }

            // Does any Return directly hand back such a call result?
            for block in &func.blocks {
                if let Some(IrInst::Return { value: Some(v) }) = block.terminator() {
                    if let Some(vid) = v.var_id() {
                        if let Some((_callee, ty)) = known_call_dsts.get(&vid) {
                            if let Some(summary) = analysis.summaries.get_mut(&func.name) {
                                summary.return_type = Some(ty.clone());
                                changed = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── Result Types ───────────────────────────────────────────────────

/// Complete interprocedural analysis results.
#[derive(Debug, Clone)]
pub struct ProgramAnalysis {
    /// Per-function summaries
    pub summaries: HashMap<String, FunctionSummary>,
    /// Resolved global variables
    pub globals: HashMap<u64, GlobalInfo>,
}

/// Information about a global variable.
#[derive(Debug, Clone)]
pub struct GlobalInfo {
    pub address: u64,
    pub name: String,
    pub read_by: Vec<String>,
    pub written_by: Vec<String>,
    pub inferred_type: Ty,
}

impl ProgramAnalysis {
    pub fn new() -> Self {
        ProgramAnalysis {
            summaries: HashMap::new(),
            globals: HashMap::new(),
        }
    }

    /// Get summary for a function by name.
    pub fn get_summary(&self, name: &str) -> Option<&FunctionSummary> {
        self.summaries.get(name)
    }

    /// Get global variable info by address.
    pub fn get_global(&self, addr: u64) -> Option<&GlobalInfo> {
        self.globals.get(&addr)
    }

    /// List all inline candidates.
    pub fn inline_candidates(&self) -> Vec<&FunctionSummary> {
        self.summaries
            .values()
            .filter(|s| s.inline_candidate)
            .collect()
    }
}

impl Default for ProgramAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::IrFunction;

    #[test]
    fn test_analyze_empty_function() {
        let func = IrFunction::new("empty", 0x1000);
        let summary = analyze_function(&func);
        assert_eq!(summary.name, "empty");
        assert_eq!(summary.instruction_count, 0);
        assert!(!summary.may_throw);
    }

    #[test]
    fn test_calling_convention_from_metadata() {
        let mut func = IrFunction::new("test", 0x1000);
        func.metadata.calling_convention = Some("fastcall".into());
        let summary = analyze_function(&func);
        assert_eq!(summary.calling_convention, CallingConvention::Fastcall);
    }
}
