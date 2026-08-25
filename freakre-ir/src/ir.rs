//! Core IR types: values, instructions, blocks, functions, and programs.

use crate::types::Ty;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Values ──────────────────────────────────────────────────────────

/// A value in the IR.
///
/// Every IR instruction produces or consumes values. Values are either
/// SSA variables, registers, constants, or symbolic expressions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Value {
    /// SSA variable (e.g., v42 of type i64).
    Var {
        id: u32,
        ty: Ty,
    },
    /// Architectural register (e.g., "rax", "eip").
    Register {
        name: String,
        ty: Ty,
    },
    /// Immediate constant.
    Const(i64),
    /// Wide constant (for values > 64 bits).
    WideConst(Vec<u8>),
    /// String constant reference (for xrefs).
    StringRef(String),
    /// Symbolic address (e.g., function name, global variable).
    Symbol(String),
}

impl Value {
    /// Create a new SSA variable.
    pub fn var(id: u32, ty: Ty) -> Self {
        Value::Var { id, ty }
    }

    /// Create a register value.
    pub fn reg(name: &str, ty: Ty) -> Self {
        Value::Register {
            name: name.to_string(),
            ty,
        }
    }

    /// Create an integer constant.
    pub fn int(val: i64) -> Self {
        Value::Const(val)
    }

    /// Get the type of this value.
    pub fn ty(&self) -> Ty {
        match self {
            Value::Var { ty, .. } => ty.clone(),
            Value::Register { ty, .. } => ty.clone(),
            Value::Const(_) => Ty::i64(),
            Value::WideConst(b) => Ty::UInt(b.len() as u32 * 8),
            Value::StringRef(_) => Ty::Ptr(Box::new(Ty::u8())),
            Value::Symbol(_) => Ty::Ptr(Box::new(Ty::u8())),
        }
    }

    /// Check if this value is a constant.
    pub fn is_const(&self) -> bool {
        matches!(self, Value::Const(_) | Value::WideConst(_))
    }

    /// Get constant value if this is a Const.
    pub fn as_const(&self) -> Option<i64> {
        match self {
            Value::Const(v) => Some(*v),
            _ => None,
        }
    }

    /// Get variable ID if this is a Var.
    pub fn var_id(&self) -> Option<u32> {
        match self {
            Value::Var { id, .. } => Some(*id),
            _ => None,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Var { id, ty } => write!(f, "v{}:{}", id, ty),
            Value::Register { name, ty } => write!(f, "{}:{}", name, ty),
            Value::Const(v) => write!(f, "0x{:X}", v),
            Value::WideConst(b) => write!(f, "0x{}", hex::encode(b)),
            Value::StringRef(s) => write!(f, "\"{}\"", s),
            Value::Symbol(s) => write!(f, "@{}", s),
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self, other) {
            (Value::Var { id: a, ty: ta }, Value::Var { id: b, ty: tb }) => {
                a.cmp(b).then(ta.cmp(tb))
            }
            (Value::Var { .. }, _) => Less,
            (_, Value::Var { .. }) => Greater,
            (Value::Register { name: a, ty: ta }, Value::Register { name: b, ty: tb }) => {
                a.cmp(b).then(ta.cmp(tb))
            }
            (Value::Register { .. }, _) => Less,
            (_, Value::Register { .. }) => Greater,
            (Value::Const(a), Value::Const(b)) => a.cmp(b),
            (Value::Const(_), _) => Less,
            (_, Value::Const(_)) => Greater,
            (Value::WideConst(a), Value::WideConst(b)) => a.cmp(b),
            (Value::WideConst(_), _) => Less,
            (_, Value::WideConst(_)) => Greater,
            (Value::StringRef(a), Value::StringRef(b)) => a.cmp(b),
            (Value::StringRef(_), _) => Less,
            (_, Value::StringRef(_)) => Greater,
            (Value::Symbol(a), Value::Symbol(b)) => a.cmp(b),
        }
    }
}

// ─── OpCodes ─────────────────────────────────────────────────────────

/// IR operation codes, inspired by Ghidra P-code.
///
/// The IR uses a fixed set of primitive operations. Complex machine
/// instructions are decomposed ("lifted") into sequences of these ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpCode {
    // ─── Arithmetic ──────────────────────────────
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,

    // ─── Bitwise ─────────────────────────────────
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,       // Logical shift right
    Sar,       // Arithmetic shift right
    Ror,       // Rotate right
    Rol,       // Rotate left

    // ─── Comparison ──────────────────────────────
    Eq,
    Ne,
    LtU,       // Unsigned less-than
    LeU,       // Unsigned less-or-equal
    GtU,       // Unsigned greater-than
    GeU,       // Unsigned greater-or-equal
    LtS,       // Signed less-than
    LeS,       // Signed less-or-equal
    GtS,       // Signed greater-than
    GeS,       // Signed greater-or-equal

    // ─── Type conversions ────────────────────────
    Zext,      // Zero-extend
    Sext,      // Sign-extend
    Trunc,     // Truncate
    FloatToFloat,
    IntToFloat,
    FloatToInt,

    // ─── Float arithmetic ────────────────────────
    FloatAdd,
    FloatSub,
    FloatMul,
    FloatDiv,
    FloatNeg,
    FloatAbs,
    FloatSqrt,

    // ─── Special ─────────────────────────────────
    Copy,      // Simple assignment
    Phi,       // SSA phi node (for block merging)
}

impl OpCode {
    /// Whether this is a binary operation (takes 2 operands).
    pub fn is_binary(&self) -> bool {
        matches!(self,
            Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Mod |
            Self::And | Self::Or | Self::Xor |
            Self::Shl | Self::Shr | Self::Sar | Self::Ror | Self::Rol |
            Self::Eq | Self::Ne |
            Self::LtU | Self::LeU | Self::GtU | Self::GeU |
            Self::LtS | Self::LeS | Self::GtS | Self::GeS |
            Self::FloatAdd | Self::FloatSub | Self::FloatMul | Self::FloatDiv
        )
    }

    /// Whether this is a unary operation.
    pub fn is_unary(&self) -> bool {
        matches!(self,
            Self::Neg | Self::Not |
            Self::Zext | Self::Sext | Self::Trunc |
            Self::FloatToFloat | Self::IntToFloat | Self::FloatToInt |
            Self::FloatNeg | Self::FloatAbs | Self::FloatSqrt |
            Self::Copy
        )
    }

    /// Whether this is a comparison operation.
    pub fn is_comparison(&self) -> bool {
        matches!(self,
            Self::Eq | Self::Ne |
            Self::LtU | Self::LeU | Self::GtU | Self::GeU |
            Self::LtS | Self::LeS | Self::GtS | Self::GeS
        )
    }

    /// Whether this is a commutative operation.
    pub fn is_commutative(&self) -> bool {
        matches!(self,
            Self::Add | Self::Mul |
            Self::And | Self::Or | Self::Xor |
            Self::Eq | Self::Ne
        )
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OpCode::Add => "ADD",
            OpCode::Sub => "SUB",
            OpCode::Mul => "MUL",
            OpCode::Div => "DIV",
            OpCode::Mod => "MOD",
            OpCode::Neg => "NEG",
            OpCode::And => "AND",
            OpCode::Or => "OR",
            OpCode::Xor => "XOR",
            OpCode::Not => "NOT",
            OpCode::Shl => "SHL",
            OpCode::Shr => "SHR",
            OpCode::Sar => "SAR",
            OpCode::Ror => "ROR",
            OpCode::Rol => "ROL",
            OpCode::Eq => "EQ",
            OpCode::Ne => "NE",
            OpCode::LtU => "LT_U",
            OpCode::LeU => "LE_U",
            OpCode::GtU => "GT_U",
            OpCode::GeU => "GE_U",
            OpCode::LtS => "LT_S",
            OpCode::LeS => "LE_S",
            OpCode::GtS => "GT_S",
            OpCode::GeS => "GE_S",
            OpCode::Zext => "ZEXT",
            OpCode::Sext => "SEXT",
            OpCode::Trunc => "TRUNC",
            OpCode::FloatToFloat => "FLOAT2FLOAT",
            OpCode::IntToFloat => "INT2FLOAT",
            OpCode::FloatToInt => "FLOAT2INT",
            OpCode::FloatAdd => "FADD",
            OpCode::FloatSub => "FSUB",
            OpCode::FloatMul => "FMUL",
            OpCode::FloatDiv => "FDIV",
            OpCode::FloatNeg => "FNEG",
            OpCode::FloatAbs => "FABS",
            OpCode::FloatSqrt => "FSQRT",
            OpCode::Copy => "COPY",
            OpCode::Phi => "PHI",
        };
        write!(f, "{}", s)
    }
}

// ─── Instructions ────────────────────────────────────────────────────

/// A single IR instruction.
///
/// Instructions operate on typed Values and produce typed results.
/// Every instruction has a source address for traceability back to
/// the original machine code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrInst {
    /// dst = lhs OP rhs
    Binary {
        dst: Value,
        op: OpCode,
        lhs: Value,
        rhs: Value,
    },
    /// dst = OP(src)
    Unary {
        dst: Value,
        op: OpCode,
        src: Value,
    },
    /// dst = LOAD(addr, size)
    Load {
        dst: Value,
        addr: Value,
        size: u32,
    },
    /// STORE(addr, value, size)
    Store {
        addr: Value,
        value: Value,
        size: u32,
    },
    /// Unconditional branch to a block.
    Branch {
        target: BlockId,
    },
    /// Conditional branch: if (cond) goto target_true else goto target_false.
    CBranch {
        cond: Value,
        target_true: BlockId,
        target_false: BlockId,
    },
    /// Function call: dst = CALL(target, args...)
    Call {
        dst: Option<Value>,
        target: Value,
        args: Vec<Value>,
    },
    /// Return from function with optional value.
    Return {
        value: Option<Value>,
    },
    /// Indirect branch (jmp reg/mem — target computed at runtime).
    IndirectBranch {
        target: Value,
    },
    /// SSA Phi node: dst = PHI((block1: val1), (block2: val2), ...)
    Phi {
        dst: Value,
        incoming: Vec<(BlockId, Value)>,
    },
    /// System call (syscall / sysenter / svc).
    Syscall {
        number: Option<Value>,
        args: Vec<Value>,
    },
    /// No-operation (placeholder / alignment).
    Nop,
}

impl IrInst {
    /// Get the destination value, if any.
    pub fn dst(&self) -> Option<&Value> {
        match self {
            IrInst::Binary { dst, .. } => Some(dst),
            IrInst::Unary { dst, .. } => Some(dst),
            IrInst::Load { dst, .. } => Some(dst),
            IrInst::Phi { dst, .. } => Some(dst),
            IrInst::Call { dst, .. } => dst.as_ref(),
            _ => None,
        }
    }

    /// Get all values read by this instruction.
    pub fn sources(&self) -> Vec<&Value> {
        match self {
            IrInst::Binary { lhs, rhs, .. } => vec![lhs, rhs],
            IrInst::Unary { src, .. } => vec![src],
            IrInst::Load { addr, .. } => vec![addr],
            IrInst::Store { addr, value, .. } => vec![addr, value],
            IrInst::CBranch { cond, .. } => vec![cond],
            IrInst::Call { target, args, .. } => {
                let mut v = vec![target];
                v.extend(args.iter());
                v
            }
            IrInst::Return { value: Some(v) } => vec![v],
            IrInst::Return { value: None } => vec![],
            IrInst::IndirectBranch { target } => vec![target],
            IrInst::Phi { incoming, .. } => incoming.iter().map(|(_, v)| v).collect(),
            IrInst::Syscall { number, args } => {
                let mut v: Vec<&Value> = args.iter().collect();
                if let Some(n) = number {
                    v.push(n);
                }
                v
            }
            IrInst::Branch { .. } | IrInst::Nop => vec![],
        }
    }

    /// Whether this instruction is a terminator (ends a block).
    pub fn is_terminator(&self) -> bool {
        matches!(self,
            IrInst::Branch { .. } |
            IrInst::CBranch { .. } |
            IrInst::Return { .. } |
            IrInst::IndirectBranch { .. }
        )
    }

    /// Source address where this instruction was lifted from.
    /// (Stored separately in IrBlock for efficiency.)
    pub fn is_call(&self) -> bool {
        matches!(self, IrInst::Call { .. })
    }

    /// Pretty-print this instruction.
    pub fn display(&self) -> String {
        match self {
            IrInst::Binary { dst, op, lhs, rhs } => {
                format!("{} = {} {}, {}", dst, op, lhs, rhs)
            }
            IrInst::Unary { dst, op, src } => {
                format!("{} = {} {}", dst, op, src)
            }
            IrInst::Load { dst, addr, size } => {
                format!("{} = LOAD({}, {})", dst, addr, size)
            }
            IrInst::Store { addr, value, size } => {
                format!("STORE({}, {}, {})", addr, value, size)
            }
            IrInst::Branch { target } => {
                format!("BRANCH {}", target)
            }
            IrInst::CBranch { cond, target_true, target_false } => {
                format!("CBRANCH {} ? {} : {}", cond, target_true, target_false)
            }
            IrInst::Call { dst, target, args } => {
                let args_str: Vec<String> = args.iter().map(|a| a.to_string()).collect();
                match dst {
                    Some(d) => format!("{} = CALL {}({})", d, target, args_str.join(", ")),
                    None => format!("CALL {}({})", target, args_str.join(", ")),
                }
            }
            IrInst::Return { value: Some(v) } => format!("RETURN {}", v),
            IrInst::Return { value: None } => "RETURN".to_string(),
            IrInst::IndirectBranch { target } => format!("IBRANCH {}", target),
            IrInst::Phi { dst, incoming } => {
                let inc: Vec<String> = incoming.iter()
                    .map(|(b, v)| format!("{}:{}", b, v))
                    .collect();
                format!("{} = PHI({})", dst, inc.join(", "))
            }
            IrInst::Syscall { number, args } => {
                let args_str: Vec<String> = args.iter().map(|a| a.to_string()).collect();
                match number {
                    Some(n) => format!("SYSCALL {}({})", n, args_str.join(", ")),
                    None => format!("SYSCALL({})", args_str.join(", ")),
                }
            }
            IrInst::Nop => "NOP".to_string(),
        }
    }
}

// ─── Block and Function ──────────────────────────────────────────────

/// Block identifier within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// A basic block in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrBlock {
    /// Block identifier.
    pub id: BlockId,
    /// Optional label (e.g., "entry", "loop_body").
    pub label: String,
    /// Instructions in order. The last instruction must be a terminator.
    pub insts: Vec<IrInst>,
    /// Source address range (start, end) in the original binary.
    pub source_range: Option<(u64, u64)>,
    /// Predecessor block IDs (filled during CFG construction).
    pub predecessors: Vec<BlockId>,
    /// Successor block IDs (filled during CFG construction).
    pub successors: Vec<BlockId>,
}

impl IrBlock {
    /// Get the terminator instruction (last instruction).
    pub fn terminator(&self) -> Option<&IrInst> {
        self.insts.last().filter(|i| i.is_terminator())
    }

    /// Whether this block ends with a return.
    pub fn is_return_block(&self) -> bool {
        matches!(self.terminator(), Some(IrInst::Return { .. }))
    }

    /// Number of instructions in this block.
    pub fn num_instructions(&self) -> usize {
        self.insts.len()
    }
}

/// A function in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    /// Function name (from symbol table or auto-generated).
    pub name: String,
    /// Entry point address in the original binary.
    pub entry_address: u64,
    /// All basic blocks, indexed by BlockId.
    pub blocks: Vec<IrBlock>,
    /// Entry block ID.
    pub entry_block: BlockId,
    /// Next variable ID counter (for SSA allocation).
    next_var_id: u32,
    /// Next block ID counter.
    next_block_id: u32,
    /// Function-level metadata.
    pub metadata: FunctionMetadata,
}

/// Metadata about a function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionMetadata {
    /// Calling convention (e.g., "cdecl", "stdcall", "fastcall").
    pub calling_convention: Option<String>,
    /// Whether this function is a thunk / trampoline.
    pub is_thunk: bool,
    /// Whether this function is a library import.
    pub is_import: bool,
    /// Parameter types (if resolved).
    pub param_types: Vec<Ty>,
    /// Return type (if resolved).
    pub return_type: Option<Ty>,
    /// Stack frame size (if known).
    pub stack_frame_size: Option<u32>,
    /// Detected compiler/runtime (e.g., "MSVC", "GCC", "Go").
    pub compiler: Option<String>,
}

impl IrFunction {
    /// Create a new function with an entry block.
    pub fn new(name: &str, entry_address: u64) -> Self {
        let entry = IrBlock {
            id: BlockId(0),
            label: "entry".to_string(),
            insts: Vec::new(),
            source_range: None,
            predecessors: Vec::new(),
            successors: Vec::new(),
        };

        IrFunction {
            name: name.to_string(),
            entry_address,
            blocks: vec![entry],
            entry_block: BlockId(0),
            next_var_id: 0,
            next_block_id: 1,
            metadata: FunctionMetadata::default(),
        }
    }

    /// Allocate a new SSA variable.
    pub fn alloc_var(&mut self, ty: Ty) -> Value {
        let id = self.next_var_id;
        self.next_var_id += 1;
        Value::Var { id, ty }
    }

    /// Add a new basic block.
    pub fn add_block(&mut self, label: &str) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        self.blocks.push(IrBlock {
            id,
            label: label.to_string(),
            insts: Vec::new(),
            source_range: None,
            predecessors: Vec::new(),
            successors: Vec::new(),
        });
        id
    }

    /// Push an instruction to a block.
    ///
    /// Defensive: an unknown `block` is a lifter bug (flagged in debug
    /// builds) but is silently skipped in release instead of panicking.
    pub fn push_inst(&mut self, block: BlockId, inst: IrInst) {
        debug_assert!(
            self.blocks.iter().any(|b| b.id == block),
            "push_inst on unknown BlockId({})",
            block.0
        );
        if let Some(b) = self.blocks.iter_mut().find(|b| b.id == block) {
            b.insts.push(inst);
        }
    }

    /// Total number of instructions across all blocks.
    pub fn total_instructions(&self) -> usize {
        self.blocks.iter().map(|b| b.insts.len()).sum()
    }

    /// Build predecessor/successor edges from terminators.
    ///
    /// Defensive: terminators referencing blocks that were never added are
    /// a lifter bug (debug_assert) but their edges are skipped gracefully
    /// in release builds instead of corrupting the CFG.
    pub fn build_cfg(&mut self) {
        // Clear existing edges
        for block in &mut self.blocks {
            block.predecessors.clear();
            block.successors.clear();
        }

        // Collect edges
        let edges: Vec<(BlockId, BlockId)> = self.blocks.iter()
            .flat_map(|b| {
                let mut succs = Vec::new();
                match b.terminator() {
                    Some(IrInst::Branch { target }) => succs.push(*target),
                    Some(IrInst::CBranch { target_true, target_false, .. }) => {
                        succs.push(*target_true);
                        succs.push(*target_false);
                    }
                    _ => {}
                }
                succs.retain(|s| {
                    let known = self.blocks.iter().any(|blk| blk.id == *s);
                    debug_assert!(
                        known,
                        "build_cfg: terminator references unknown BlockId({})",
                        s.0
                    );
                    known
                });
                succs.into_iter().map(move |s| (b.id, s))
            })
            .collect();

        // Apply edges
        for (src, dst) in &edges {
            if let Some(src_block) = self.blocks.iter_mut().find(|b| b.id == *src) {
                if !src_block.successors.contains(dst) {
                    src_block.successors.push(*dst);
                }
            }
            if let Some(dst_block) = self.blocks.iter_mut().find(|b| b.id == *dst) {
                if !dst_block.predecessors.contains(src) {
                    dst_block.predecessors.push(*src);
                }
            }
        }
    }

    /// Get a block by ID.
    pub fn block(&self, id: BlockId) -> Option<&IrBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Get a mutable block by ID.
    pub fn block_mut(&mut self, id: BlockId) -> Option<&mut IrBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    /// Print the IR in human-readable format.
    pub fn display(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("function {} @ 0x{:X}:\n", self.name, self.entry_address));

        for block in &self.blocks {
            out.push_str(&format!("  {} ({})\n", block.label, block.id));
            for inst in &block.insts {
                out.push_str(&format!("    {}\n", inst.display()));
            }
        }

        out
    }
}

// ─── Block graph repair ──────────────────────────────────────────────

/// Re-target branch terminators from empty label blocks onto the non-empty
/// `bb_N` continuation chunks that start at the same address.
///
/// Lifters pre-create empty `loc_`/`fall_`-style label blocks when a branch
/// is decoded, while the actual instructions land in `bb_N` continuation
/// chunks. Without repair the CFG edges all point at empty labels and every
/// code chunk becomes an unreachable island. Arch-specific guarded/after/
/// taken blocks are deliberately *not* resolution targets: they carry
/// true-path-only effects and are reached exclusively through their own
/// direct edges.
///
/// `parse_label` extracts the source address encoded in a block label
/// (`None` for labels carrying no address). Label addresses may be off by up
/// to one instruction (length computation drift), so the nearest following
/// code chunk within a 15-byte window is accepted.
pub(crate) fn repair_block_graph(
    func: &mut IrFunction,
    parse_label: fn(&str, u64) -> Option<u64>,
) {
    let base = func.entry_address;
    // (address, rank, block) — rank 0 = bb_ chunk, 1 = entry block.
    let mut code_starts: Vec<(u64, u8, BlockId)> = Vec::new();
    let mut label_addrs: Vec<(BlockId, u64)> = Vec::new();

    for b in &func.blocks {
        match parse_label(&b.label, base) {
            Some(addr) => {
                if b.insts.is_empty() {
                    label_addrs.push((b.id, addr));
                } else if b.label.starts_with("bb_") {
                    code_starts.push((addr, 0, b.id));
                }
            }
            None => {
                if b.id == func.entry_block && !b.insts.is_empty() {
                    code_starts.push((base, 1, b.id));
                }
            }
        }
    }
    code_starts.sort_unstable();

    let resolve = |id: BlockId| -> Option<BlockId> {
        let &(_, addr) = label_addrs.iter().find(|(bid, _)| *bid == id)?;
        let idx = code_starts.partition_point(|&(a, _, _)| a < addr);
        code_starts.get(idx).filter(|&&(a, _, _)| a - addr <= 15).map(|&(_, _, b)| b)
    };

    if std::env::var("REPAIR_DEBUG").is_ok() {
        for b in &func.blocks {
            eprintln!("[repair] {} {} insts={}", b.id.0, b.label, b.insts.len());
        }
        eprintln!("[repair] code_starts: {:?}", code_starts);
        eprintln!("[repair] labels: {:?}", label_addrs);
    }

    for b in func.blocks.iter_mut() {
        let Some(last) = b.insts.last_mut() else { continue };
        match last {
            IrInst::Branch { target } => {
                if let Some(new) = resolve(*target) {
                    *target = new;
                }
            }
            IrInst::CBranch { target_true, target_false, .. } => {
                if let Some(new) = resolve(*target_true) {
                    *target_true = new;
                }
                if let Some(new) = resolve(*target_false) {
                    *target_false = new;
                }
            }
            _ => {}
        }
    }
}

/// A complete program: collection of functions + global data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrProgram {
    /// All functions in the program.
    pub functions: Vec<IrFunction>,
    /// Global variables / data sections.
    pub globals: HashMap<u64, GlobalData>,
    /// Import table (address → symbol name).
    pub imports: HashMap<u64, String>,
    /// Export table (address → symbol name).
    pub exports: HashMap<u64, String>,
    /// Source binary metadata.
    pub metadata: ProgramMetadata,
}

/// Global data region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalData {
    pub address: u64,
    pub name: String,
    pub data: Vec<u8>,
    pub ty: Option<Ty>,
}

/// Program-level metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramMetadata {
    pub arch: String,
    pub endianness: String,
    pub bitness: u32,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
}

/// Section information from the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub flags: u32,
}

impl IrProgram {
    /// Create a new empty IR program.
    pub fn new() -> Self {
        IrProgram {
            functions: Vec::new(),
            globals: HashMap::new(),
            imports: HashMap::new(),
            exports: HashMap::new(),
            metadata: ProgramMetadata::default(),
        }
    }

    /// Total number of functions.
    pub fn num_functions(&self) -> usize {
        self.functions.len()
    }

    /// Total number of instructions across all functions.
    pub fn total_instructions(&self) -> usize {
        self.functions.iter().map(|f| f.total_instructions()).sum()
    }

    /// Find a function by address.
    pub fn function_at(&self, address: u64) -> Option<&IrFunction> {
        self.functions.iter().find(|f| f.entry_address == address)
    }

    /// Find a function by name.
    pub fn function_by_name(&self, name: &str) -> Option<&IrFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Add a function to the program.
    pub fn add_function(&mut self, func: IrFunction) {
        self.functions.push(func);
    }

    /// Serialise to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Default for IrProgram {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_function() {
        let mut func = IrFunction::new("test_func", 0x401000);
        let v0 = func.alloc_var(Ty::i64());
        let v1 = func.alloc_var(Ty::i64());
        let v2 = func.alloc_var(Ty::i64());

        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v2.clone(),
            op: OpCode::Add,
            lhs: v0.clone(),
            rhs: v1.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v2),
        });

        assert_eq!(func.total_instructions(), 2);
        assert!(func.block(func.entry_block).unwrap().is_return_block());
    }

    #[test]
    fn test_cfg_edges() {
        let mut func = IrFunction::new("cfg_test", 0x0);
        let cond = Value::var(0, Ty::Bool);
        let bb1 = func.add_block("then");
        let bb2 = func.add_block("else");

        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: cond.clone(),
            target_true: bb1,
            target_false: bb2,
        });
        func.push_inst(bb1, IrInst::Branch { target: bb2 });
        func.push_inst(bb2, IrInst::Return { value: None });

        func.build_cfg();

        let entry = func.block(func.entry_block).unwrap();
        assert_eq!(entry.successors.len(), 2);
        assert!(entry.successors.contains(&bb1));
        assert!(entry.successors.contains(&bb2));

        let then_block = func.block(bb1).unwrap();
        assert_eq!(then_block.successors, vec![bb2]);
        assert!(then_block.predecessors.contains(&func.entry_block));
    }

    #[test]
    fn test_value_display() {
        assert_eq!(format!("{}", Value::var(0, Ty::i64())), "v0:i64");
        assert_eq!(format!("{}", Value::reg("rax", Ty::i64())), "rax:i64");
        assert_eq!(format!("{}", Value::int(42)), "0x2A");
    }

    #[test]
    fn test_inst_display() {
        let inst = IrInst::Binary {
            dst: Value::var(0, Ty::i64()),
            op: OpCode::Add,
            lhs: Value::reg("rax", Ty::i64()),
            rhs: Value::int(8),
        };
        let display = inst.display();
        assert!(display.contains("ADD"));
        assert!(display.contains("rax"));
    }

    #[test]
    fn test_ir_program_serialization() {
        let mut prog = IrProgram::new();
        let func = IrFunction::new("main", 0x401000);
        prog.add_function(func);

        let json = prog.to_json().unwrap();
        let restored = IrProgram::from_json(&json).unwrap();
        assert_eq!(restored.num_functions(), 1);
        assert_eq!(restored.functions[0].name, "main");
    }

    #[test]
    fn test_opcode_properties() {
        assert!(OpCode::Add.is_binary());
        assert!(OpCode::Add.is_commutative());
        assert!(!OpCode::Sub.is_commutative());
        assert!(OpCode::Eq.is_comparison());
        assert!(OpCode::Not.is_unary());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "unknown BlockId")]
    fn test_push_inst_unknown_block_debug_assert() {
        let mut func = IrFunction::new("t", 0);
        func.push_inst(BlockId(42), IrInst::Nop);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_push_inst_unknown_block_skipped_gracefully() {
        let mut func = IrFunction::new("t", 0);
        func.push_inst(BlockId(42), IrInst::Nop);
        assert_eq!(func.total_instructions(), 0);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "unknown BlockId")]
    fn test_build_cfg_dangling_edge_debug_assert() {
        let mut func = IrFunction::new("t", 0);
        func.push_inst(func.entry_block, IrInst::Branch { target: BlockId(7) });
        func.build_cfg();
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_build_cfg_dangling_edge_skipped_gracefully() {
        let mut func = IrFunction::new("t", 0);
        func.push_inst(func.entry_block, IrInst::Branch { target: BlockId(7) });
        func.build_cfg();
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.successors.is_empty());
        assert!(entry.predecessors.is_empty());
    }
}
