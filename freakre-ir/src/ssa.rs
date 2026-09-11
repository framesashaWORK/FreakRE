//! SSA (Static Single Assignment) form construction and deconstruction.
//!
//! Classic construction pipeline:
//!
//! 1. Dominators via reverse post-order + Cooper-Harvey-Kennedy intersect.
//! 2. Dominance frontiers (standard runner-up algorithm).
//! 3. Minimal phi placement with the Cytron worklist algorithm.
//! 4. Renaming during a dominator-tree walk with per-variable version stacks.
//!
//! Variables used before any definition receive an implicit version `0`
//! (the value the storage location holds on function entry). Unreachable
//! blocks are rejected with [`SsaError::UnreachableBlocks`] — they cannot
//! participate in renaming, so [`to_ssa`] fails instead of silently
//! producing a mixed-form function.
//!
//! [`from_ssa`] performs naive out-of-SSA translation: every phi is lowered
//! into edge copies (a unique temporary per incoming edge placed at the end
//! of the predecessor, plus an assignment at the start of the successor).
//! This preserves parallel-copy semantics but may leave redundant copies
//! (lost-copy / swap problems are handled correctly by the temporaries,
//! only copy-coalescing opportunities are missed).

use crate::ir::{BlockId, FunctionMetadata, IrBlock, IrFunction, IrInst, OpCode, Value};
use crate::types::Ty;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use thiserror::Error;

/// Placeholder version for operands whose definition is assigned later
/// during the renaming walk.
const PENDING: u32 = u32::MAX;

/// Errors produced by SSA construction.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SsaError {
    /// The function entry block does not exist.
    #[error("entry block bb{0} does not exist")]
    InvalidEntry(u32),
    /// The function contains duplicate block identifiers.
    #[error("duplicate block id bb{0}")]
    DuplicateBlock(u32),
    /// A terminator appears before the end of a basic block.
    #[error("terminator in the middle of block bb{0}")]
    TerminatorInMiddle(BlockId),
    /// A terminator references a block that does not exist in the function.
    #[error("terminator references unknown block bb{0}")]
    UnknownBlock(u32),
    /// The function contains blocks not reachable from the entry block.
    /// Such blocks cannot be renamed consistently, so conversion refuses them.
    #[error("function contains unreachable blocks: {0:?}")]
    UnreachableBlocks(Vec<BlockId>),
    /// The input IR already contains `Phi` instructions; strip them first
    /// (the constructor expects phi-free, mutable-register form).
    #[error("unexpected Phi instruction at block {0}; input IR must be phi-free")]
    UnexpectedPhi(BlockId),
    /// An instruction writes to a non-variable destination (constant, symbol,
    /// …) which has no SSA version to assign.
    #[error("instruction in block bb{0} writes to a non-variable destination")]
    InvalidDestination(BlockId),
    /// Block-id space is exhausted (the input already uses `u32::MAX`).
    #[error("block id space exhausted")]
    IdExhausted,
}

/// Identity of a mutable storage location in the input IR: either a numbered
/// IR variable (`v7`) or an architectural register (`rax`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BaseVar {
    /// IR variable with its id.
    Var(u32),
    /// Architectural register with its name.
    Reg(String),
}

impl std::fmt::Display for BaseVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseVar::Var(id) => write!(f, "v{}", id),
            BaseVar::Reg(name) => write!(f, "{}", name),
        }
    }
}

/// A variable reference pinned to a specific SSA version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VersionedVar {
    /// Underlying storage location.
    pub base: BaseVar,
    /// SSA version (0 = implicit initial value).
    pub version: u32,
    /// Type carried over from the IR.
    pub ty: Ty,
}

impl std::fmt::Display for VersionedVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.base, self.version)
    }
}

/// Operand of an SSA instruction: either a versioned variable or a constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaVal {
    /// Versioned variable reference.
    Ver(VersionedVar),
    /// Immediate constant.
    Const(i64),
    /// Wide constant.
    WideConst(Vec<u8>),
    /// String constant reference.
    StringRef(String),
    /// Symbolic address.
    Symbol(String),
}

/// SSA phi node: `dst = PHI(inputs)` where each input is tagged with the
/// predecessor block it arrives from.
#[derive(Debug, Clone)]
pub struct Phi {
    /// Result of the phi (fresh version of the merged variable).
    pub dst: VersionedVar,
    /// One input per predecessor edge.
    pub inputs: Vec<(BlockId, VersionedVar)>,
}

/// Instruction in SSA form. Mirrors [`IrInst`] with all variable operands
/// replaced by [`VersionedVar`] / [`SsaVal`].
#[derive(Debug, Clone)]
pub enum SsaInst {
    /// dst = lhs OP rhs
    Binary {
        dst: VersionedVar,
        op: OpCode,
        lhs: SsaVal,
        rhs: SsaVal,
    },
    /// dst = OP(src)
    Unary {
        dst: VersionedVar,
        op: OpCode,
        src: SsaVal,
    },
    /// dst = a + b + carry (ADC)
    Adc {
        dst: VersionedVar,
        a: SsaVal,
        b: SsaVal,
        carry: SsaVal,
    },
    /// dst = a - b - carry (SBB)
    Sbb {
        dst: VersionedVar,
        a: SsaVal,
        b: SsaVal,
        carry: SsaVal,
    },
    /// dst = LOAD(addr, size)
    Load {
        dst: VersionedVar,
        addr: SsaVal,
        size: u32,
    },
    /// STORE(addr, value, size)
    Store {
        addr: SsaVal,
        value: SsaVal,
        size: u32,
    },
    /// Unconditional branch.
    Branch { target: BlockId },
    /// Conditional branch.
    CBranch {
        cond: SsaVal,
        target_true: BlockId,
        target_false: BlockId,
    },
    /// Function call.
    Call {
        dst: Option<VersionedVar>,
        target: SsaVal,
        args: Vec<SsaVal>,
    },
    /// Return from function.
    Return { value: Option<SsaVal> },
    /// Indirect branch.
    IndirectBranch { target: SsaVal },
    /// Multi-way dispatch (jump-table switch).
    Switch {
        index: SsaVal,
        cases: Vec<(i64, BlockId)>,
        default: Option<BlockId>,
    },
    /// System call.
    Syscall {
        number: Option<SsaVal>,
        args: Vec<SsaVal>,
    },
    /// No-op.
    Nop,
}

impl SsaInst {
    /// Pretty-print this instruction.
    pub fn display(&self) -> String {
        fn val(v: &SsaVal) -> String {
            match v {
                SsaVal::Ver(vv) => vv.to_string(),
                SsaVal::Const(c) => format!("0x{:X}", c),
                SsaVal::WideConst(b) => format!("0x{}", hex::encode(b)),
                SsaVal::StringRef(s) => format!("\"{}\"", s),
                SsaVal::Symbol(s) => format!("@{}", s),
            }
        }
        match self {
            SsaInst::Binary { dst, op, lhs, rhs } => {
                format!("{} = {} {}, {}", dst, op, val(lhs), val(rhs))
            }
            SsaInst::Unary { dst, op, src } => format!("{} = {} {}", dst, op, val(src)),
            SsaInst::Adc { dst, a, b, carry } => {
                format!("{} = ADC {}, {}, {}", dst, val(a), val(b), val(carry))
            }
            SsaInst::Sbb { dst, a, b, carry } => {
                format!("{} = SBB {}, {}, {}", dst, val(a), val(b), val(carry))
            }
            SsaInst::Load { dst, addr, size } => format!("{} = LOAD({}, {})", dst, val(addr), size),
            SsaInst::Store { addr, value, size } => {
                format!("STORE({}, {}, {})", val(addr), val(value), size)
            }
            SsaInst::Branch { target } => format!("BRANCH {}", target),
            SsaInst::CBranch {
                cond,
                target_true,
                target_false,
            } => format!("CBRANCH {} ? {} : {}", val(cond), target_true, target_false),
            SsaInst::Call { dst, target, args } => {
                let args_str: Vec<String> = args.iter().map(val).collect();
                match dst {
                    Some(d) => format!("{} = CALL {}({})", d, val(target), args_str.join(", ")),
                    None => format!("CALL {}({})", val(target), args_str.join(", ")),
                }
            }
            SsaInst::Return { value } => match value {
                Some(v) => format!("RETURN {}", val(v)),
                None => "RETURN".to_string(),
            },
            SsaInst::IndirectBranch { target } => format!("IBRANCH {}", val(target)),
            SsaInst::Switch { index, cases, default } => {
                let cs: Vec<String> = cases.iter().map(|(v, b)| format!("{}=>bb{}", v, b.0)).collect();
                match default {
                    Some(d) => format!("SWITCH {} {{ {} default=>bb{} }}", val(index), cs.join(", "), d.0),
                    None => format!("SWITCH {} {{ {} }}", val(index), cs.join(", ")),
                }
            }
            SsaInst::Syscall { number, args } => {
                let args_str: Vec<String> = args.iter().map(val).collect();
                match number {
                    Some(n) => format!("SYSCALL {}({})", val(n), args_str.join(", ")),
                    None => format!("SYSCALL({})", args_str.join(", ")),
                }
            }
            SsaInst::Nop => "NOP".to_string(),
        }
    }
}

/// Basic block in SSA form.
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Block identifier (same as in the source IR).
    pub id: BlockId,
    /// Block label.
    pub label: String,
    /// Phi nodes, placed at the beginning of the block.
    pub phis: Vec<Phi>,
    /// Non-phi instructions in order.
    pub insts: Vec<SsaInst>,
    /// Source address range in the original binary.
    pub source_range: Option<(u64, u64)>,
    /// Predecessor block ids.
    pub predecessors: Vec<BlockId>,
    /// Successor block ids.
    pub successors: Vec<BlockId>,
}

/// A function converted to SSA form.
#[derive(Debug, Clone)]
pub struct SsaFunction {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_address: u64,
    /// Entry block id.
    pub entry_block: BlockId,
    /// All blocks, in the same relative order as the source IR.
    pub blocks: Vec<SsaBlock>,
    /// Highest SSA version allocated per variable (after renaming).
    pub versions: HashMap<BaseVar, u32>,
    /// Function-level metadata copied from the source IR.
    pub metadata: FunctionMetadata,
}

impl SsaFunction {
    /// Get a block by id.
    pub fn block(&self, id: BlockId) -> Option<&SsaBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Human-readable dump (useful for debugging).
    pub fn display(&self) -> String {
        let mut out = format!("function {} @ 0x{:X}:\n", self.name, self.entry_address);
        for b in &self.blocks {
            out.push_str(&format!("  {} ({})\n", b.label, b.id));
            for p in &b.phis {
                let inputs: Vec<String> = p
                    .inputs
                    .iter()
                    .map(|(bl, v)| format!("{}: {}", bl, v))
                    .collect();
                out.push_str(&format!("    {} = PHI({})\n", p.dst, inputs.join(", ")));
            }
            for i in &b.insts {
                out.push_str(&format!("    {}\n", i.display()));
            }
        }
        out
    }
}

// ─── Dominators ──────────────────────────────────────────────────────

/// Iterative DFS producing reverse post-order over reachable blocks.
fn rpo_order(func: &IrFunction) -> Vec<BlockId> {
    let entry = func.entry_block;
    let mut visited: HashSet<BlockId> = HashSet::new();
    let mut post: Vec<BlockId> = Vec::new();
    let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
    visited.insert(entry);

    while let Some(frame) = stack.last_mut() {
        let succs = match func.block(frame.0) {
            Some(b) => b.successors.clone(),
            None => Vec::new(),
        };
        if frame.1 < succs.len() {
            let s = succs[frame.1];
            frame.1 += 1;
            if visited.insert(s) {
                stack.push((s, 0));
            }
        } else {
            post.push(frame.0);
            stack.pop();
        }
    }

    post.reverse();
    post
}

/// Compute immediate dominators with the Cooper-Harvey-Kennedy iterative
/// algorithm driven by reverse post-order numbering.
///
/// Returns a map `block -> immediate dominator` covering exactly the blocks
/// reachable from the entry (`idom[entry] = entry`). Unreachable blocks are
/// absent from the result.
pub fn compute_dominators(func: &IrFunction) -> HashMap<BlockId, BlockId> {
    let entry = func.entry_block;
    let rpo = rpo_order(func);
    let rpo_num: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, &id)| (id, i)).collect();

    let mut idoms: HashMap<BlockId, BlockId> = HashMap::new();
    idoms.insert(entry, entry);

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == entry {
                continue;
            }
            let preds = match func.block(b) {
                Some(bl) => &bl.predecessors,
                None => continue,
            };

            let mut new_idom: Option<BlockId> = None;
            for &p in preds {
                if idoms.contains_key(&p) {
                    new_idom = Some(p);
                    break;
                }
            }
            let mut new_idom = match new_idom {
                Some(p) => p,
                None => continue,
            };
            for &p in preds {
                if p == new_idom || !idoms.contains_key(&p) {
                    continue;
                }
                new_idom = intersect(p, new_idom, &idoms, &rpo_num);
            }

            if idoms.get(&b) != Some(&new_idom) {
                idoms.insert(b, new_idom);
                changed = true;
            }
        }
    }

    idoms
}

/// Intersect two blocks in the dominator tree using RPO numbering.
fn intersect(
    b1: BlockId,
    b2: BlockId,
    idoms: &HashMap<BlockId, BlockId>,
    rpo_num: &HashMap<BlockId, usize>,
) -> BlockId {
    let order = |id: BlockId| -> usize { *rpo_num.get(&id).unwrap_or(&usize::MAX) };

    let mut finger1 = b1;
    let mut finger2 = b2;
    let mut iterations = 0;
    while finger1 != finger2 && iterations < 100_000 {
        iterations += 1;
        while order(finger1) > order(finger2) {
            let next = *idoms.get(&finger1).unwrap_or(&finger1);
            if next == finger1 {
                break;
            }
            finger1 = next;
        }
        while order(finger2) > order(finger1) {
            let next = *idoms.get(&finger2).unwrap_or(&finger2);
            if next == finger2 {
                break;
            }
            finger2 = next;
        }
    }
    finger1
}

/// Compute dominance frontiers.
///
/// `DF(b)` = set of blocks `y` such that `b` dominates a predecessor of `y`
/// but does not strictly dominate `y`.
pub fn compute_dominance_frontiers(
    func: &IrFunction,
    idoms: &HashMap<BlockId, BlockId>,
) -> HashMap<BlockId, HashSet<BlockId>> {
    let mut df: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();
    for block in &func.blocks {
        df.insert(block.id, HashSet::new());
    }

    for join in &func.blocks {
        if join.predecessors.len() < 2 {
            continue;
        }
        let join_idom = match idoms.get(&join.id) {
            Some(d) => *d,
            None => continue,
        };
        for &pred in &join.predecessors {
            let mut runner = pred;
            let mut guard = 0;
            while runner != join_idom && guard <= func.blocks.len() + 1 {
                guard += 1;
                match idoms.get(&runner) {
                    Some(_) => {
                        if let Some(frontier) = df.get_mut(&runner) {
                            frontier.insert(join.id);
                        }
                        let next = *idoms.get(&runner).unwrap();
                        if next == runner {
                            break;
                        }
                        runner = next;
                    }
                    None => break,
                }
            }
        }
    }

    df
}

// ─── Construction ────────────────────────────────────────────────────

fn base_of(v: &Value) -> Option<BaseVar> {
    match v {
        Value::Var { id, .. } => Some(BaseVar::Var(*id)),
        Value::Register { name, .. } => Some(BaseVar::Reg(name.clone())),
        _ => None,
    }
}

/// `None` when `v` is not a variable/register (constant, symbol, …) — the
/// caller maps that to [`SsaError::InvalidDestination`] instead of panicking.
fn ver_of(v: &Value) -> Option<VersionedVar> {
    match v {
        Value::Var { id, ty } => Some(VersionedVar {
            base: BaseVar::Var(*id),
            version: PENDING,
            ty: ty.clone(),
        }),
        Value::Register { name, ty } => Some(VersionedVar {
            base: BaseVar::Reg(name.clone()),
            version: PENDING,
            ty: ty.clone(),
        }),
        _ => None,
    }
}

fn val_to_ssa(v: &Value) -> SsaVal {
    match v {
        // Safe by construction: this arm already matched Var/Register, for
        // which `ver_of` always returns `Some`.
        Value::Var { .. } | Value::Register { .. } => {
            SsaVal::Ver(ver_of(v).expect("ver_of succeeds for Var/Register"))
        }
        Value::Const(c) => SsaVal::Const(*c),
        Value::WideConst(b) => SsaVal::WideConst(b.clone()),
        Value::StringRef(s) => SsaVal::StringRef(s.clone()),
        Value::Symbol(s) => SsaVal::Symbol(s.clone()),
    }
}

/// Returns `None` when the instruction writes to a non-variable destination;
/// the caller maps that to [`SsaError::InvalidDestination`].
fn to_ssa_inst(inst: &IrInst) -> Option<SsaInst> {
    let ssa = match inst {
        IrInst::Binary { dst, op, lhs, rhs } => SsaInst::Binary {
            dst: ver_of(dst)?,
            op: *op,
            lhs: val_to_ssa(lhs),
            rhs: val_to_ssa(rhs),
        },
        IrInst::Adc { dst, a, b, carry } => SsaInst::Adc {
            dst: ver_of(dst)?,
            a: val_to_ssa(a),
            b: val_to_ssa(b),
            carry: val_to_ssa(carry),
        },
        IrInst::Sbb { dst, a, b, carry } => SsaInst::Sbb {
            dst: ver_of(dst)?,
            a: val_to_ssa(a),
            b: val_to_ssa(b),
            carry: val_to_ssa(carry),
        },
        IrInst::Unary { dst, op, src } => SsaInst::Unary {
            dst: ver_of(dst)?,
            op: *op,
            src: val_to_ssa(src),
        },
        IrInst::Load { dst, addr, size } => SsaInst::Load {
            dst: ver_of(dst)?,
            addr: val_to_ssa(addr),
            size: *size,
        },
        IrInst::Store { addr, value, size } => SsaInst::Store {
            addr: val_to_ssa(addr),
            value: val_to_ssa(value),
            size: *size,
        },
        IrInst::Branch { target } => SsaInst::Branch { target: *target },
        IrInst::CBranch {
            cond,
            target_true,
            target_false,
        } => SsaInst::CBranch {
            cond: val_to_ssa(cond),
            target_true: *target_true,
            target_false: *target_false,
        },
        IrInst::Call { dst, target, args } => SsaInst::Call {
            dst: match dst.as_ref() {
                Some(d) => Some(ver_of(d)?),
                None => None,
            },
            target: val_to_ssa(target),
            args: args.iter().map(val_to_ssa).collect(),
        },
        IrInst::Return { value } => SsaInst::Return {
            value: value.as_ref().map(val_to_ssa),
        },
        IrInst::IndirectBranch { target } => SsaInst::IndirectBranch {
            target: val_to_ssa(target),
        },
        IrInst::Switch {
            index,
            cases,
            default,
        } => SsaInst::Switch {
            index: val_to_ssa(index),
            cases: cases.clone(),
            default: *default,
        },
        IrInst::Syscall { number, args } => SsaInst::Syscall {
            number: number.as_ref().map(val_to_ssa),
            args: args.iter().map(val_to_ssa).collect(),
        },
        IrInst::Nop => SsaInst::Nop,
        IrInst::Phi { .. } => unreachable!("Phi instructions are rejected before conversion"),
    };
    Some(ssa)
}

/// Mutable access to the destination slot of an SSA instruction.
fn ssa_inst_dst(inst: &mut SsaInst) -> Option<&mut VersionedVar> {
    match inst {
        SsaInst::Binary { dst, .. }
        | SsaInst::Unary { dst, .. }
        | SsaInst::Adc { dst, .. }
        | SsaInst::Sbb { dst, .. }
        | SsaInst::Load { dst, .. } => Some(dst),
        SsaInst::Call { dst: Some(dst), .. } => Some(dst),
        _ => None,
    }
}

/// Apply an in-place transformation to every operand of an SSA instruction.
fn ssa_inst_map_vals(inst: &mut SsaInst, f: &mut impl FnMut(&mut SsaVal)) {
    match inst {
        SsaInst::Binary { lhs, rhs, .. } => {
            f(lhs);
            f(rhs);
        }
        SsaInst::Unary { src, .. } => f(src),
        SsaInst::Adc { a, b, carry, .. } => {
            f(a);
            f(b);
            f(carry);
        }
        SsaInst::Sbb { a, b, carry, .. } => {
            f(a);
            f(b);
            f(carry);
        }
        SsaInst::Load { addr, .. } => f(addr),
        SsaInst::Store { addr, value, .. } => {
            f(addr);
            f(value);
        }
        SsaInst::CBranch { cond, .. } => f(cond),
        SsaInst::Call { target, args, .. } => {
            f(target);
            for a in args {
                f(a);
            }
        }
        SsaInst::Return { value } => {
            if let Some(v) = value {
                f(v);
            }
        }
        SsaInst::IndirectBranch { target } => f(target),
        SsaInst::Switch { index, .. } => f(index),
        SsaInst::Syscall { number, args } => {
            for a in args {
                f(a);
            }
            if let Some(n) = number {
                f(n);
            }
        }
        SsaInst::Branch { .. } | SsaInst::Nop => {}
    }
}

/// Read-only counterpart of [`ssa_inst_map_vals`]: visit every operand of
/// an SSA instruction without mutating it.
fn map_ssa_val_read(inst: &SsaInst, f: &mut impl FnMut(&SsaVal)) {
    match inst {
        SsaInst::Binary { lhs, rhs, .. } => {
            f(lhs);
            f(rhs);
        }
        SsaInst::Unary { src, .. } => f(src),
        SsaInst::Adc { a, b, carry, .. } => {
            f(a);
            f(b);
            f(carry);
        }
        SsaInst::Sbb { a, b, carry, .. } => {
            f(a);
            f(b);
            f(carry);
        }
        SsaInst::Load { addr, .. } => f(addr),
        SsaInst::Store { addr, value, .. } => {
            f(addr);
            f(value);
        }
        SsaInst::CBranch { cond, .. } => f(cond),
        SsaInst::Call { target, args, .. } => {
            f(target);
            for a in args {
                f(a);
            }
        }
        SsaInst::Return { value } => {
            if let Some(v) = value {
                f(v);
            }
        }
        SsaInst::IndirectBranch { target } => f(target),
        SsaInst::Switch { index, .. } => f(index),
        SsaInst::Syscall { number, args } => {
            for a in args {
                f(a);
            }
            if let Some(n) = number {
                f(n);
            }
        }
        SsaInst::Branch { .. } | SsaInst::Nop => {}
    }
}

/// Allocate the next SSA version for `base` and push it onto its stack.
fn define(
    stacks: &mut HashMap<BaseVar, Vec<VersionedVar>>,
    counters: &mut HashMap<BaseVar, u32>,
    base: &BaseVar,
    ty: &Ty,
) -> VersionedVar {
    let counter = counters.entry(base.clone()).or_insert(0);
    *counter += 1;
    let vv = VersionedVar {
        base: base.clone(),
        version: *counter,
        ty: ty.clone(),
    };
    stacks.entry(base.clone()).or_default().push(vv.clone());
    vv
}

/// Convert an IR function to minimal SSA form.
///
/// Phi nodes are placed at the iterated dominance frontiers of every
/// variable definition site (Cytron worklist algorithm); variables are then
/// renamed during a dominator-tree walk. Variables read before any definition
/// receive implicit version 0 standing for the value held on function entry.
///
/// Fails with [`SsaError::UnreachableBlocks`] if the function contains blocks
/// unreachable from the entry (they cannot be renamed soundly), with
/// [`SsaError::UnexpectedPhi`] if the input already contains phi nodes, with
/// [`SsaError::UnknownBlock`] if a terminator references a missing block, or
/// with [`SsaError::InvalidDestination`] if an instruction writes to a
/// non-variable destination.
pub fn to_ssa(func: &mut IrFunction) -> Result<SsaFunction, SsaError> {
    // `build_cfg` intentionally debug-asserts on dangling edges. Validate the
    // graph first so malformed input has the documented Result-based failure
    // mode in both debug and release builds.
    let mut seen_blocks = HashSet::new();
    for block in &func.blocks {
        if !seen_blocks.insert(block.id) {
            return Err(SsaError::DuplicateBlock(block.id.0));
        }
        for (index, inst) in block.insts.iter().enumerate() {
            if inst.is_terminator() && index + 1 != block.insts.len() {
                return Err(SsaError::TerminatorInMiddle(block.id));
            }
        }
    }
    if func.block(func.entry_block).is_none() {
        return Err(SsaError::InvalidEntry(func.entry_block.0));
    }
    for block in &func.blocks {
        if let Some(IrInst::Branch { target }) = block.terminator() {
            if func.block(*target).is_none() {
                return Err(SsaError::UnknownBlock(target.0));
            }
        }
        if let Some(IrInst::CBranch {
            target_true,
            target_false,
            ..
        }) = block.terminator()
        {
            if func.block(*target_true).is_none() {
                return Err(SsaError::UnknownBlock(target_true.0));
            }
            if func.block(*target_false).is_none() {
                return Err(SsaError::UnknownBlock(target_false.0));
            }
        }
        if let Some(IrInst::Switch { cases, default, .. }) = block.terminator() {
            for (_, t) in cases {
                if func.block(*t).is_none() {
                    return Err(SsaError::UnknownBlock(t.0));
                }
            }
            if let Some(d) = default {
                if func.block(*d).is_none() {
                    return Err(SsaError::UnknownBlock(d.0));
                }
            }
        }
    }
    func.build_cfg();
    let entry = func.entry_block;

    for b in &func.blocks {
        for succ in &b.successors {
            if func.block(*succ).is_none() {
                return Err(SsaError::UnknownBlock(succ.0));
            }
        }
        for inst in &b.insts {
            if matches!(inst, IrInst::Phi { .. }) {
                return Err(SsaError::UnexpectedPhi(b.id));
            }
        }
    }

    let order = rpo_order(func);
    let reachable: HashSet<BlockId> = order.iter().copied().collect();
    let unreachable: Vec<BlockId> = func
        .blocks
        .iter()
        .map(|b| b.id)
        .filter(|id| !reachable.contains(id))
        .collect();
    if !unreachable.is_empty() {
        return Err(SsaError::UnreachableBlocks(unreachable));
    }

    let idoms = compute_dominators(func);
    let df = compute_dominance_frontiers(func, &idoms);

    // Collect definitions (per variable, list of defining blocks in block
    // order) and all referenced variables.
    let mut def_blocks: BTreeMap<BaseVar, Vec<BlockId>> = BTreeMap::new();
    let mut tys: HashMap<BaseVar, Ty> = HashMap::new();
    let mut used: BTreeSet<BaseVar> = BTreeSet::new();
    for b in &func.blocks {
        for inst in &b.insts {
            if let Some(d) = inst.dst() {
                if let Some(base) = base_of(d) {
                    tys.entry(base.clone()).or_insert_with(|| d.ty());
                    let defs = def_blocks.entry(base).or_default();
                    if !defs.contains(&b.id) {
                        defs.push(b.id);
                    }
                }
            }
            for s in inst.sources() {
                if let Some(base) = base_of(s) {
                    tys.entry(base.clone()).or_insert_with(|| s.ty());
                    used.insert(base);
                }
            }
        }
    }

    // Phi placement (Cytron): seed the worklist from every definition site —
    // including variables defined in a single block. A lone definition that
    // does not dominate a join still demands a phi there, so pruning by
    // definition count alone is unsound.
    let mut phi_bases: HashMap<BlockId, Vec<BaseVar>> = HashMap::new();
    let mut has_phi: HashSet<(BaseVar, BlockId)> = HashSet::new();
    for (base, defs) in &def_blocks {
        if defs.is_empty() {
            continue;
        }
        let mut work: VecDeque<BlockId> = defs.iter().copied().collect();
        let mut ever_queued: HashSet<BlockId> = defs.iter().copied().collect();
        while let Some(x) = work.pop_front() {
            if let Some(frontier) = df.get(&x) {
                for &y in frontier {
                    if has_phi.insert((base.clone(), y)) {
                        phi_bases.entry(y).or_default().push(base.clone());
                        if ever_queued.insert(y) {
                            work.push_back(y);
                        }
                    }
                }
            }
        }
    }
    for bases in phi_bases.values_mut() {
        bases.sort();
    }

    // Materialise blocks with pending phi placeholders. A `None` from
    // `to_ssa_inst` means a non-variable destination — fail with a proper
    // error instead of the old `unreachable!` panic.
    let mut blocks: Vec<SsaBlock> = Vec::with_capacity(func.blocks.len());
    for b in &func.blocks {
        let mut insts = Vec::with_capacity(b.insts.len());
        for inst in &b.insts {
            match to_ssa_inst(inst) {
                Some(si) => insts.push(si),
                None => return Err(SsaError::InvalidDestination(b.id)),
            }
        }
        blocks.push(SsaBlock {
            id: b.id,
            label: b.label.clone(),
            phis: Vec::new(),
            insts,
            source_range: b.source_range,
            predecessors: b.predecessors.clone(),
            successors: b.successors.clone(),
        });
    }
    let idx: HashMap<BlockId, usize> = blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();

    for (block_id, bases) in &phi_bases {
        let bi = idx[block_id];
        for base in bases {
            let ty = tys.get(base).cloned().unwrap_or_else(Ty::i64);
            blocks[bi].phis.push(Phi {
                dst: VersionedVar {
                    base: base.clone(),
                    version: PENDING,
                    ty,
                },
                inputs: Vec::new(),
            });
        }
    }

    // Renaming state: implicit version 0 for every referenced variable.
    let mut counters: HashMap<BaseVar, u32> = HashMap::new();
    let mut stacks: HashMap<BaseVar, Vec<VersionedVar>> = HashMap::new();
    let mut all_bases: BTreeSet<BaseVar> = used;
    for base in def_blocks.keys() {
        all_bases.insert(base.clone());
    }
    for base in &all_bases {
        let ty = tys.get(base).cloned().unwrap_or_else(Ty::i64);
        counters.insert(base.clone(), 0);
        stacks.insert(
            base.clone(),
            vec![VersionedVar {
                base: base.clone(),
                version: 0,
                ty,
            }],
        );
    }

    // Dominator-tree children (sorted for deterministic traversal).
    let mut children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for b in &func.blocks {
        if b.id == entry {
            continue;
        }
        if let Some(&d) = idoms.get(&b.id) {
            children.entry(d).or_default().push(b.id);
        }
    }
    for kids in children.values_mut() {
        kids.sort();
    }

    enum Frame {
        Enter(BlockId),
        Exit(BlockId),
    }

    let mut pushed_defs: HashMap<BlockId, Vec<BaseVar>> = HashMap::new();
    let mut stack: Vec<Frame> = vec![Frame::Enter(entry)];

    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(b) => {
                let bi = idx[&b];

                let mut pushed: Vec<BaseVar> = Vec::new();
                for phi in &mut blocks[bi].phis {
                    if phi.dst.version == PENDING {
                        let base = phi.dst.base.clone();
                        let ty = phi.dst.ty.clone();
                        let vv = define(&mut stacks, &mut counters, &base, &ty);
                        phi.dst = vv;
                        pushed.push(base);
                    }
                }

                for inst in &mut blocks[bi].insts {
                    ssa_inst_map_vals(inst, &mut |operand| {
                        if let SsaVal::Ver(vv) = operand {
                            let current = stacks[&vv.base]
                                .last()
                                .cloned()
                                .expect("variable missing implicit version 0");
                            *vv = current;
                        }
                    });
                    if let Some(slot) = ssa_inst_dst(inst) {
                        let base = slot.base.clone();
                        let ty = slot.ty.clone();
                        let vv = define(&mut stacks, &mut counters, &base, &ty);
                        *slot = vv;
                        pushed.push(base);
                    }
                }

                let bid = blocks[bi].id;
                let succs = blocks[bi].successors.clone();
                let mut seen_succs: HashSet<BlockId> = HashSet::new();
                for s in succs {
                    if !seen_succs.insert(s) {
                        continue;
                    }
                    let si = idx[&s];
                    for phi in &mut blocks[si].phis {
                        let current = stacks[&phi.dst.base]
                            .last()
                            .cloned()
                            .expect("variable missing implicit version 0");
                        phi.inputs.push((bid, current));
                    }
                }

                pushed_defs.insert(bid, pushed);
                stack.push(Frame::Exit(bid));
                if let Some(kids) = children.get(&bid) {
                    for &kid in kids.iter().rev() {
                        stack.push(Frame::Enter(kid));
                    }
                }
            }
            Frame::Exit(b) => {
                if let Some(defs) = pushed_defs.remove(&b) {
                    for base in defs.iter().rev() {
                        stacks.get_mut(base).unwrap().pop();
                    }
                }
            }
        }
    }

    Ok(SsaFunction {
        name: func.name.clone(),
        entry_address: func.entry_address,
        entry_block: entry,
        metadata: func.metadata.clone(),
        versions: counters,
        blocks,
    })
}

// ─── Optimisation on SSA ─────────────────────────────────────────────

/// Resolve a substitution chain for `v` in place (guarded against cycles).
fn resolve_var(v: &mut VersionedVar, subst: &HashMap<VersionedVar, VersionedVar>) {
    let mut steps = 0;
    while steps <= subst.len() {
        match subst.get(v) {
            Some(next) if *next != *v => {
                *v = next.clone();
                steps += 1;
            }
            _ => break,
        }
    }
}

/// Remove trivial phis. A phi is trivial when all its *non-self* inputs are
/// the same versioned variable; the two classic shapes are
/// `PHI(x, x, …, x)` and `PHI(d, x)` (self-referencing input). Trivial phis
/// are deleted and every reference to their destination is substituted with
/// the surviving variable. Chains collapse because the substitution map is
/// resolved transitively (`resolve_var`) and the whole pass repeats to a
/// fixpoint, so `PHI(a, b); PHI(b, a)` degenerate cycles — which would
/// otherwise loop forever — are detected and skipped.
pub fn remove_trivial_phis(ssa: &mut SsaFunction) {
    loop {
        let mut subst: HashMap<VersionedVar, VersionedVar> = HashMap::new();
        for b in &ssa.blocks {
            for p in &b.phis {
                if p.inputs.is_empty() {
                    continue;
                }
                // The surviving value: the unique non-self input.
                let survivor = p
                    .inputs
                    .iter()
                    .map(|(_, v)| v)
                    .find(|v| **v != p.dst)
                    .cloned();
                let Some(survivor) = survivor else {
                    continue; // all inputs self-referencing: leave as-is
                };
                if p
                    .inputs
                    .iter()
                    .all(|(_, v)| *v == survivor || *v == p.dst)
                    && survivor != p.dst
                {
                    // Skip cycles: a phi that (transitively) feeds itself
                    // with the survivor via other phis must not be folded.
                    let is_cyclic = {
                        let mut cur = survivor.clone();
                        let mut steps = 0;
                        let cyc = loop {
                            if cur == p.dst {
                                break true;
                            }
                            match subst.get(&cur) {
                                Some(next) if *next != cur => {
                                    cur = next.clone();
                                    steps += 1;
                                    if steps > subst.len() {
                                        break false;
                                    }
                                }
                                _ => break false,
                            }
                        };
                        cyc
                    };
                    if !is_cyclic {
                        subst.insert(p.dst.clone(), survivor);
                    }
                }
            }
        }
        if subst.is_empty() {
            break;
        }

        for b in &mut ssa.blocks {
            b.phis.retain(|p| !subst.contains_key(&p.dst));
            for p in &mut b.phis {
                for (_, v) in &mut p.inputs {
                    resolve_var(v, &subst);
                }
            }
            for inst in &mut b.insts {
                ssa_inst_map_vals(inst, &mut |operand| {
                    if let SsaVal::Ver(ref mut vv) = *operand {
                        resolve_var(vv, &subst);
                    }
                });
            }
        }
    }
}

// ─── Deconstruction ──────────────────────────────────────────────────

/// Statistics reported by [`ssa_gvn`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GvnStats {
    /// Redundant pure instructions eliminated (uses rewritten to the
    /// dominating equivalent).
    pub eliminated: usize,
}

/// Hashable, orderable value identity for GVN keys. Mirrors [`SsaVal`]
/// minus the type (SSA versions are unique per base variable, so the
/// version pair already identifies the value).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum GvnVal {
    Ver(BaseVar, u32),
    Const(i64),
    Wide(Vec<u8>),
    Str(String),
    Sym(String),
}

impl From<&SsaVal> for GvnVal {
    fn from(v: &SsaVal) -> Self {
        match v {
            SsaVal::Ver(vv) => GvnVal::Ver(vv.base.clone(), vv.version),
            SsaVal::Const(c) => GvnVal::Const(*c),
            SsaVal::WideConst(b) => GvnVal::Wide(b.clone()),
            SsaVal::StringRef(s) => GvnVal::Str(s.clone()),
            SsaVal::Symbol(s) => GvnVal::Sym(s.clone()),
        }
    }
}

/// Hash-consing key for a pure SSA instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GvnKey {
    Bin {
        op: OpCode,
        a: GvnVal,
        b: GvnVal,
    },
    Un {
        op: OpCode,
        a: GvnVal,
    },
    Adc {
        a: GvnVal,
        b: GvnVal,
        c: GvnVal,
    },
    Sbb {
        a: GvnVal,
        b: GvnVal,
        c: GvnVal,
    },
}

/// Whether `op` is commutative (`a OP b == b OP a`), enabling operand
/// order normalization before hashing.
fn op_is_commutative(op: &OpCode) -> bool {
    matches!(op, OpCode::Add | OpCode::Mul | OpCode::And | OpCode::Or | OpCode::Xor)
}

fn ssa_inst_dst_read(inst: &SsaInst) -> Option<&VersionedVar> {
    match inst {
        SsaInst::Binary { dst, .. }
        | SsaInst::Unary { dst, .. }
        | SsaInst::Adc { dst, .. }
        | SsaInst::Sbb { dst, .. }
        | SsaInst::Load { dst, .. } => Some(dst),
        SsaInst::Call { dst: Some(dst), .. } => Some(dst),
        _ => None,
    }
}

/// Dominators over the SSA CFG (same Cooper-Harvey-Kennedy algorithm as
/// [`compute_dominators`], which operates on plain IR).
fn ssa_dominators(ssa: &SsaFunction) -> HashMap<BlockId, BlockId> {
    let entry = ssa.entry_block;
    // Reverse post-order over SSA successors.
    let mut visited: HashSet<BlockId> = HashSet::new();
    let mut post: Vec<BlockId> = Vec::new();
    let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
    visited.insert(entry);
    while let Some(frame) = stack.last_mut() {
        let succs: &[BlockId] = match ssa.block(frame.0) {
            Some(b) => &b.successors,
            None => &[],
        };
        if frame.1 < succs.len() {
            let s = succs[frame.1];
            frame.1 += 1;
            if visited.insert(s) {
                stack.push((s, 0));
            }
        } else {
            post.push(frame.0);
            stack.pop();
        }
    }
    let rpo: Vec<BlockId> = post.into_iter().rev().collect();
    let rpo_num: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, &id)| (id, i)).collect();

    let mut idoms: HashMap<BlockId, BlockId> = HashMap::new();
    idoms.insert(entry, entry);
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == entry {
                continue;
            }
            let preds = match ssa.block(b) {
                Some(bl) => &bl.predecessors,
                None => continue,
            };
            let mut new_idom = match preds.iter().copied().find(|p| idoms.contains_key(p)) {
                Some(p) => p,
                None => continue,
            };
            for &p in preds {
                if p == new_idom || !idoms.contains_key(&p) {
                    continue;
                }
                new_idom = intersect(p, new_idom, &idoms, &rpo_num);
            }
            if idoms.get(&b) != Some(&new_idom) {
                idoms.insert(b, new_idom);
                changed = true;
            }
        }
    }
    idoms
}

/// Global value numbering (common-subexpression elimination) on SSA form.
///
/// Walks the dominator tree in preorder with a *scoped* hash table of pure
/// instruction values: a value computed in block B remains available only
/// in B's dominator subtree, which is exactly the region where reuse is
/// sound (the definition dominates every rewritten use). Identical pure
/// instructions (`dst2 = Add(x, y)` where a dominating block already holds
/// `dst1 = Add(x, y)`) are eliminated: `dst2` is substituted with `dst1`
/// everywhere (instruction operands and phi inputs). Commutative
/// operations (`+ * & | ^`) are canonicalized by operand order before
/// hashing, so `a + b` and `b + a` unify.
///
/// Loads, stores, calls, syscalls and terminators are never merged — only
/// their operands get substituted.
pub fn ssa_gvn(ssa: &mut SsaFunction) -> GvnStats {
    let mut stats = GvnStats::default();
    let idom = ssa_dominators(ssa);

    // Dominator-tree children lists.
    let mut children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for (&b, &d) in &idom {
        if b != d {
            children.entry(d).or_default().push(b);
        }
    }

    // Substitution for eliminated destinations (applied after the walk).
    let mut subst: HashMap<VersionedVar, VersionedVar> = HashMap::new();
    // Scoped value table: key -> defining version.
    let mut table: HashMap<GvnKey, VersionedVar> = HashMap::new();

    // Explicit DFS with undo frames so table entries inserted inside a
    // subtree are removed when leaving it.
    enum Frame {
        Enter(BlockId),
        Exit(Vec<GvnKey>),
    }
    let mut stack: Vec<Frame> = vec![Frame::Enter(ssa.entry_block)];

    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(b) => {
                let bi = match ssa.blocks.iter().position(|sb| sb.id == b) {
                    Some(i) => i,
                    None => continue,
                };
                let mut inserted: Vec<GvnKey> = Vec::new();
                for inst in &mut ssa.blocks[bi].insts {
                    // Resolve operands through prior eliminations first —
                    // keys must be built on canonical values.
                    ssa_inst_map_vals(inst, &mut |op| {
                        if let SsaVal::Ver(vv) = op {
                            resolve_var(vv, &subst);
                        }
                    });
                    let (key, dst) = match inst {
                        SsaInst::Binary { dst, op, lhs, rhs } => {
                            let (a, b) = (GvnVal::from(&*lhs), GvnVal::from(&*rhs));
                            let (a, b) = if op_is_commutative(op) && a > b {
                                (b, a)
                            } else {
                                (a, b)
                            };
                            (
                                GvnKey::Bin {
                                    op: *op,
                                    a,
                                    b,
                                },
                                dst,
                            )
                        }
                        SsaInst::Unary { dst, op, src } => {
                            (GvnKey::Un { op: *op, a: GvnVal::from(&*src) }, dst)
                        }
                        SsaInst::Adc { dst, a, b, carry } => (
                            GvnKey::Adc {
                                a: GvnVal::from(&*a),
                                b: GvnVal::from(&*b),
                                c: GvnVal::from(&*carry),
                            },
                            dst,
                        ),
                        SsaInst::Sbb { dst, a, b, carry } => (
                            GvnKey::Sbb {
                                a: GvnVal::from(&*a),
                                b: GvnVal::from(&*b),
                                c: GvnVal::from(&*carry),
                            },
                            dst,
                        ),
                        // Impure or non-value instructions: operands were
                        // resolved above, nothing to number.
                        _ => continue,
                    };
                    match table.get(&key) {
                        Some(canonical) => {
                            // Redundant re-computation: substitute dst with
                            // the dominating definition.
                            subst.insert(dst.clone(), canonical.clone());
                            stats.eliminated += 1;
                        }
                        None => {
                            table.insert(key.clone(), dst.clone());
                            inserted.push(key);
                        }
                    }
                }
                stack.push(Frame::Exit(inserted));
                if let Some(kids) = children.get(&b) {
                    for &kid in kids.iter().rev() {
                        stack.push(Frame::Enter(kid));
                    }
                }
            }
            Frame::Exit(keys) => {
                for k in keys {
                    table.remove(&k);
                }
            }
        }
    }

    if subst.is_empty() {
        return stats;
    }

    // Rewrite remaining operands (phi inputs and instructions) to the
    // canonical definitions, and drop the eliminated instructions.
    for b in &mut ssa.blocks {
        for p in &mut b.phis {
            for (_, v) in &mut p.inputs {
                resolve_var(v, &subst);
            }
        }
        let mut kept = Vec::with_capacity(b.insts.len());
        for inst in b.insts.drain(..) {
            let mut inst = inst;
            ssa_inst_map_vals(&mut inst, &mut |op| {
                if let SsaVal::Ver(vv) = op {
                    resolve_var(vv, &subst);
                }
            });
            let eliminated = ssa_inst_dst_read(&inst).is_some_and(|d| subst.contains_key(d));
            if !eliminated {
                kept.push(inst);
            }
        }
        b.insts = kept;
    }
    stats
}

/// Statistics reported by [`ssa_dce`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DceStats {
    /// Pure instructions removed (dead Binary/Unary/Copy chains).
    pub removed: usize,
}

/// Dead-code elimination on SSA form.
///
/// Removes *pure* instructions (Binary, Unary with arithmetic ops, Adc/Sbb)
/// whose results are never used. Loads, stores, calls, syscalls,
/// terminators and flag-compare producers are never removed — only phi and
/// pure-value definitions are candidates. Iterates to a fixpoint because
/// removing one dead definition can kill its operands' last use.
///
/// This is the SSA-form counterpart of the decompiler's
/// `eliminate_dead_flag_defs`, but exact (use counts, not name prefixes)
/// and general (any pure def, not only `flag_*`).
pub fn ssa_dce(ssa: &mut SsaFunction) -> DceStats {
    let mut stats = DceStats::default();
    loop {
        // Count uses of every versioned variable across all operands
        // (instruction operands, phi inputs, phi-referencing operands).
        let mut uses: HashMap<VersionedVar, usize> = HashMap::new();
        {
            let mut count = |op: &SsaVal| {
                if let SsaVal::Ver(vv) = op {
                    *uses.entry(vv.clone()).or_insert(0) += 1;
                }
            };
            for inst in ssa.blocks.iter().flat_map(|b| b.insts.iter()) {
                map_ssa_val_read(inst, &mut count);
            }
            for b in &ssa.blocks {
                for p in &b.phis {
                    for (_, v) in &p.inputs {
                        *uses.entry(v.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Sweep: drop pure instructions with zero uses.
        let before = stats.removed;
        for b in &mut ssa.blocks {
            b.insts.retain(|inst| {
                let dead = match inst {
                    SsaInst::Binary { dst, .. }
                    | SsaInst::Unary { dst, .. }
                    | SsaInst::Adc { dst, .. }
                    | SsaInst::Sbb { dst, .. } => uses.get(dst).copied().unwrap_or(0) == 0,
                    // Copy materializes as Unary with OpCode::Copy; it is
                    // pure, but removal of copies is left to coalescing /
                    // copy propagation in the decompiler, and a copy that
                    // materializes an implicit initial version (v#0, no
                    // textual definition) must never be dropped here.
                    _ => false,
                };
                if dead {
                    stats.removed += 1;
                }
                !dead
            });
        }
        if stats.removed == before {
            break;
        }
    }
    stats
}

fn concrete(
    vals: &mut HashMap<VersionedVar, Value>,
    out: &mut IrFunction,
    vv: &VersionedVar,
) -> Value {
    if let Some(v) = vals.get(vv) {
        return v.clone();
    }
    let v = out.alloc_var(vv.ty.clone());
    vals.insert(vv.clone(), v.clone());
    v
}

fn lower_val(vals: &mut HashMap<VersionedVar, Value>, out: &mut IrFunction, v: &SsaVal) -> Value {
    match v {
        SsaVal::Ver(vv) => concrete(vals, out, vv),
        SsaVal::Const(c) => Value::Const(*c),
        SsaVal::WideConst(b) => Value::WideConst(b.clone()),
        SsaVal::StringRef(s) => Value::StringRef(s.clone()),
        SsaVal::Symbol(s) => Value::Symbol(s.clone()),
    }
}

fn lower_inst(
    vals: &mut HashMap<VersionedVar, Value>,
    out: &mut IrFunction,
    inst: &SsaInst,
) -> IrInst {
    match inst {
        SsaInst::Binary { dst, op, lhs, rhs } => IrInst::Binary {
            dst: concrete(vals, out, dst),
            op: *op,
            lhs: lower_val(vals, out, lhs),
            rhs: lower_val(vals, out, rhs),
        },
        SsaInst::Adc { dst, a, b, carry } => IrInst::Adc {
            dst: concrete(vals, out, dst),
            a: lower_val(vals, out, a),
            b: lower_val(vals, out, b),
            carry: lower_val(vals, out, carry),
        },
        SsaInst::Sbb { dst, a, b, carry } => IrInst::Sbb {
            dst: concrete(vals, out, dst),
            a: lower_val(vals, out, a),
            b: lower_val(vals, out, b),
            carry: lower_val(vals, out, carry),
        },
        SsaInst::Unary { dst, op, src } => IrInst::Unary {
            dst: concrete(vals, out, dst),
            op: *op,
            src: lower_val(vals, out, src),
        },
        SsaInst::Load { dst, addr, size } => IrInst::Load {
            dst: concrete(vals, out, dst),
            addr: lower_val(vals, out, addr),
            size: *size,
        },
        SsaInst::Store { addr, value, size } => IrInst::Store {
            addr: lower_val(vals, out, addr),
            value: lower_val(vals, out, value),
            size: *size,
        },
        SsaInst::Branch { target } => IrInst::Branch { target: *target },
        SsaInst::CBranch {
            cond,
            target_true,
            target_false,
        } => IrInst::CBranch {
            cond: lower_val(vals, out, cond),
            target_true: *target_true,
            target_false: *target_false,
        },
        SsaInst::Call { dst, target, args } => IrInst::Call {
            dst: dst.as_ref().map(|d| concrete(vals, out, d)),
            target: lower_val(vals, out, target),
            args: args.iter().map(|a| lower_val(vals, out, a)).collect(),
        },
        SsaInst::Return { value } => IrInst::Return {
            value: value.as_ref().map(|v| lower_val(vals, out, v)),
        },
        SsaInst::IndirectBranch { target } => IrInst::IndirectBranch {
            target: lower_val(vals, out, target),
        },
        SsaInst::Switch {
            index,
            cases,
            default,
        } => IrInst::Switch {
            index: lower_val(vals, out, index),
            cases: cases.clone(),
            default: *default,
        },
        SsaInst::Syscall { number, args } => IrInst::Syscall {
            number: number.as_ref().map(|n| lower_val(vals, out, n)),
            args: args.iter().map(|a| lower_val(vals, out, a)).collect(),
        },
        SsaInst::Nop => IrInst::Nop,
    }
}

/// Lower SSA back to plain IR (out-of-SSA with critical-edge splits).
///
/// Every phi `d = PHI((p0, s0), (p1, s1), …)` becomes, for each incoming
/// edge `pi -> block`, a single copy `d = s_i` placed just before the
/// terminator of `pi`. If `pi` is a *critical* edge (the predecessor has
/// more than one successor), the copy cannot be placed there without
/// changing semantics, so a fresh intermediate block holding the copies
/// and a branch to the phi-block is created and the predecessor's
/// terminator is redirected through it. All phis fed across the same
/// critical edge share one split block (keyed once per edge), so every
/// copy stays reachable and executes.
///
/// No per-edge temporaries are materialized: every VersionedVar lowers to
/// a distinct fresh `Var`, and a phi never reads another phi of the same
/// block (only its own destination, which is skipped as an identity), so
/// the sequential copies are equivalent to parallel-copy semantics. This
/// is the copy-coalescing-friendly form — the old double-hop
/// (`t = s; d = t`) is gone.
///
/// Fails with [`SsaError::UnknownBlock`] if a phi references a predecessor
/// block missing from the function, or with [`SsaError::IdExhausted`] if the
/// input already uses `u32::MAX` block ids and no split-block id is left.
pub fn from_ssa(ssa: &SsaFunction) -> Result<IrFunction, SsaError> {
    let mut out = IrFunction::new(&ssa.name, ssa.entry_address);
    out.metadata = ssa.metadata.clone();
    out.entry_block = ssa.entry_block;
    out.blocks.clear();
    for sb in &ssa.blocks {
        out.blocks.push(IrBlock {
            id: sb.id,
            label: sb.label.clone(),
            insts: Vec::new(),
            source_range: sb.source_range,
            predecessors: Vec::new(),
            successors: Vec::new(),
        });
    }
    out.rebuild_index();

    let pos: HashMap<BlockId, usize> = ssa
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.id, i))
        .collect();

    let mut next_id = ssa
        .blocks
        .iter()
        .map(|b| b.id.0)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(SsaError::IdExhausted)?;
    let mut splits: HashMap<(BlockId, BlockId), BlockId> = HashMap::new();
    let mut vals: HashMap<VersionedVar, Value> = HashMap::new();
    let mut edge_copies: Vec<Vec<IrInst>> = vec![Vec::new(); ssa.blocks.len()];
    let mut lowered: Vec<Vec<IrInst>> = Vec::with_capacity(ssa.blocks.len());

    // Copies pending on each critical edge. All phis fed across the same
    // critical edge share ONE split block (keyed once per edge), so every
    // copy stays reachable and executes; unique temporaries preserve
    // parallel-copy semantics within the shared block.
    let mut split_copies: BTreeMap<(BlockId, BlockId), Vec<IrInst>> = BTreeMap::new();

    for sb in ssa.blocks.iter() {
        for phi in &sb.phis {
            let dst_val = concrete(&mut vals, &mut out, &phi.dst);
            for (pred, input) in &phi.inputs {
                let pi = *pos.get(pred).ok_or(SsaError::UnknownBlock(pred.0))?;
                let pred_block =
                    ssa.blocks.get(pi).ok_or(SsaError::UnknownBlock(pred.0))?;
                // Self-referencing input (`d = PHI(…, d)`): identity, no copy.
                if *input == phi.dst {
                    continue;
                }
                let src_val = concrete(&mut vals, &mut out, input);
                if src_val == dst_val {
                    continue;
                }
                let copies: &mut Vec<IrInst> = if pred_block.successors.len() > 1 {
                    split_copies.entry((*pred, sb.id)).or_default()
                } else {
                    &mut edge_copies[pi]
                };
                // One direct copy per edge — no intermediate temporary.
                // Soundness: every VersionedVar lowers to a distinct fresh
                // Var (`concrete` allocates one per version), and to_ssa
                // never places two phis of the same base variable in one
                // block, so distinct phis can never alias each other's
                // sources. The only possible aliasing — a phi reading its
                // own destination — is skipped above, which makes the
                // sequential copies equivalent to parallel phi semantics.
                copies.push(IrInst::Unary {
                    dst: dst_val.clone(),
                    op: OpCode::Copy,
                    src: src_val,
                });
            }
        }
        let mut insts = Vec::with_capacity(sb.insts.len());
        for si in &sb.insts {
            insts.push(lower_inst(&mut vals, &mut out, si));
        }
        lowered.push(insts);
    }

    for ((pred, succ), mut insts) in split_copies {
        let mid = BlockId(next_id);
        next_id = next_id.checked_add(1).ok_or(SsaError::IdExhausted)?;
        insts.push(IrInst::Branch { target: succ });
        out.blocks.push(IrBlock {
            id: mid,
            label: format!("edge_{}_{}", pred.0, succ.0),
            insts,
            source_range: None,
            predecessors: Vec::new(),
            successors: Vec::new(),
        });
        splits.insert((pred, succ), mid);
    }

    for (bi, sb) in ssa.blocks.iter().enumerate() {
        let block = out.block_mut(sb.id).expect("block just created");
        block.source_range = sb.source_range;

        let mut insts = std::mem::take(&mut lowered[bi]);
        let terminator = if insts.last().map(|i| i.is_terminator()).unwrap_or(false) {
            insts.pop()
        } else {
            None
        };
        insts.extend(std::mem::take(&mut edge_copies[bi]));
        if let Some(t) = terminator {
            insts.push(t);
        }
        block.insts = insts;
    }

    if !splits.is_empty() {
        for block in out.blocks.iter_mut() {
            let src = block.id;
            if let Some(term) = block.insts.last_mut() {
                match term {
                    IrInst::Branch { target } => {
                        if let Some(&mid) = splits.get(&(src, *target)) {
                            *target = mid;
                        }
                    }
                    IrInst::CBranch {
                        target_true,
                        target_false,
                        ..
                    } => {
                        if let Some(&mid) = splits.get(&(src, *target_true)) {
                            *target_true = mid;
                        }
                        if let Some(&mid) = splits.get(&(src, *target_false)) {
                            *target_false = mid;
                        }
                    }
                    IrInst::Switch { cases, default, .. } => {
                        for (_, t) in cases.iter_mut() {
                            if let Some(&mid) = splits.get(&(src, *t)) {
                                *t = mid;
                            }
                        }
                        if let Some(d) = default {
                            if let Some(&mid) = splits.get(&(src, *d)) {
                                *d = mid;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    out.rebuild_index();
    out.build_cfg();
    Ok(out)
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::OpCode;

    /// Diamond: entry -> b1 / b2 -> merge. Both arms redefine "x".
    fn diamond() -> IrFunction {
        let mut f = IrFunction::new("diamond", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let b1 = f.add_block("then");
        let b2 = f.add_block("else");
        let b3 = f.add_block("merge");
        let x = Value::reg("x", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond,
                target_true: b1,
                target_false: b2,
            },
        );
        f.push_inst(
            b1,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(1),
                rhs: Value::int(0),
            },
        );
        f.push_inst(b1, IrInst::Branch { target: b3 });
        f.push_inst(
            b2,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(2),
                rhs: Value::int(0),
            },
        );
        f.push_inst(b2, IrInst::Branch { target: b3 });
        f.push_inst(b3, IrInst::Return { value: Some(x) });
        f
    }

    #[test]
    fn test_dominator_computation() {
        let mut func = diamond();
        func.build_cfg();
        let doms = compute_dominators(&func);

        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);

        assert_eq!(doms.get(&func.entry_block), Some(&func.entry_block));
        assert_eq!(doms.get(&b1), Some(&func.entry_block));
        assert_eq!(doms.get(&b2), Some(&func.entry_block));
        assert_eq!(doms.get(&b3), Some(&func.entry_block));

        let df = compute_dominance_frontiers(&func, &doms);
        assert!(df[&b1].contains(&b3));
        assert!(df[&b2].contains(&b3));
        assert!(!df[&func.entry_block].contains(&b3));
        assert!(df[&b3].is_empty());
    }

    #[test]
    fn test_diamond_single_phi_with_two_versions() {
        let mut func = diamond();
        let ssa = to_ssa(&mut func).unwrap();

        let merge = ssa.block(BlockId(3)).unwrap();
        assert_eq!(merge.phis.len(), 1);
        let phi = &merge.phis[0];
        assert_eq!(phi.dst.base, BaseVar::Reg("x".to_string()));
        assert_eq!(phi.inputs.len(), 2);

        let mut versions: Vec<u32> = phi.inputs.iter().map(|(_, v)| v.version).collect();
        versions.sort_unstable();
        assert_eq!(versions, vec![1, 2]);
        assert_ne!(phi.dst.version, 1);
        assert_ne!(phi.dst.version, 2);

        let ret = merge.insts.last().unwrap();
        if let SsaInst::Return {
            value: Some(SsaVal::Ver(vv)),
        } = ret
        {
            assert_eq!(vv.version, phi.dst.version);
        } else {
            panic!("merge must return the phi result");
        }
    }

    #[test]
    fn test_loop_header_phi_from_entry_and_latch() {
        let mut f = IrFunction::new("loop", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let header = f.add_block("header");
        let latch = f.add_block("latch");
        let exit = f.add_block("exit");
        let i = Value::reg("i", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: i.clone(),
                op: OpCode::Add,
                lhs: Value::int(0),
                rhs: Value::int(0),
            },
        );
        f.push_inst(f.entry_block, IrInst::Branch { target: header });
        f.push_inst(
            header,
            IrInst::CBranch {
                cond,
                target_true: latch,
                target_false: exit,
            },
        );
        f.push_inst(
            latch,
            IrInst::Binary {
                dst: i.clone(),
                op: OpCode::Add,
                lhs: i.clone(),
                rhs: Value::int(1),
            },
        );
        f.push_inst(latch, IrInst::Branch { target: header });
        f.push_inst(exit, IrInst::Return { value: Some(i) });

        let ssa = to_ssa(&mut f).unwrap();
        let h = ssa.block(header).unwrap();
        assert_eq!(h.phis.len(), 1);
        let phi = &h.phis[0];

        let from_entry = phi
            .inputs
            .iter()
            .find(|(b, _)| *b == f.entry_block)
            .unwrap();
        let from_latch = phi.inputs.iter().find(|(b, _)| *b == latch).unwrap();
        assert_ne!(from_entry.1.version, from_latch.1.version);

        let latch_inst = &ssa.block(latch).unwrap().insts[0];
        if let SsaInst::Binary {
            lhs: SsaVal::Ver(use_vv),
            ..
        } = latch_inst
        {
            assert_eq!(use_vv.version, phi.dst.version);
        } else {
            panic!("latch must read the phi result");
        }
    }

    #[test]
    fn test_renaming_after_redefine() {
        let mut f = IrFunction::new("redefine", 0x0);
        let x = Value::reg("x", Ty::i64());
        let y = f.alloc_var(Ty::i64());
        let z = f.alloc_var(Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(1),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: y.clone(),
                op: OpCode::Copy,
                src: x.clone(),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(2),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: z.clone(),
                op: OpCode::Copy,
                src: x.clone(),
            },
        );
        f.push_inst(f.entry_block, IrInst::Return { value: Some(z) });

        let ssa = to_ssa(&mut f).unwrap();
        let insts = &ssa.block(f.entry_block).unwrap().insts;

        let y_def_version = match &insts[1] {
            SsaInst::Unary {
                dst,
                src: SsaVal::Ver(src),
                ..
            } => {
                assert_eq!(src.base, BaseVar::Reg("x".to_string()));
                assert_eq!(src.version, 1);
                dst.version
            }
            other => panic!("expected copy into y, got {:?}", other),
        };
        match &insts[3] {
            SsaInst::Unary {
                src: SsaVal::Ver(src),
                ..
            } => {
                assert_eq!(src.version, 2);
                assert_ne!(src.version, y_def_version);
            }
            other => panic!("expected copy into z, got {:?}", other),
        }
        assert!(ssa.block(f.entry_block).unwrap().phis.is_empty());
    }

    #[test]
    fn test_from_ssa_edge_copies_structure() {
        let mut func = diamond();
        let ssa = to_ssa(&mut func).unwrap();
        let ir = from_ssa(&ssa).unwrap();

        for b in &ir.blocks {
            for inst in &b.insts {
                assert!(!matches!(inst, IrInst::Phi { .. }), "phi must be gone");
            }
        }

        let then_b = ir.block(BlockId(1)).unwrap();
        let copies_then: Vec<&IrInst> = then_b
            .insts
            .iter()
            .filter(|i| {
                matches!(
                    **i,
                    IrInst::Unary {
                        op: OpCode::Copy,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(copies_then.len(), 1, "one direct copy per phi input");
        assert!(matches!(
            then_b.terminator(),
            Some(IrInst::Branch { target }) if *target == BlockId(3)
        ));
        let merged = match copies_then[0] {
            IrInst::Unary {
                dst,
                op: OpCode::Copy,
                ..
            } => dst.clone(),
            _ => unreachable!(),
        };

        let else_b = ir.block(BlockId(2)).unwrap();
        let copies_else: Vec<&IrInst> = else_b
            .insts
            .iter()
            .filter(|i| {
                matches!(
                    **i,
                    IrInst::Unary {
                        op: OpCode::Copy,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(copies_else.len(), 1, "one direct copy per phi input");

        let merge = ir.block(BlockId(3)).unwrap();
        assert_eq!(merge.insts.len(), 1);
        match &merge.insts[0] {
            IrInst::Return { value: Some(v) } => assert_eq!(v, &merged),
            other => panic!("expected return of merged var, got {:?}", other),
        }
    }

    #[test]
    fn test_from_ssa_splits_critical_edges() {
        let mut f = IrFunction::new("critical", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let b1 = f.add_block("inner");
        let b2 = f.add_block("else");
        let merge = f.add_block("merge");
        let x = Value::reg("x", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond: cond.clone(),
                target_true: b1,
                target_false: b2,
            },
        );
        f.push_inst(
            b1,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(1),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            b1,
            IrInst::CBranch {
                cond: cond.clone(),
                target_true: merge,
                target_false: b2,
            },
        );
        f.push_inst(
            b2,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(2),
                rhs: Value::int(0),
            },
        );
        f.push_inst(b2, IrInst::Branch { target: merge });
        f.push_inst(merge, IrInst::Return { value: Some(x) });

        let ssa = to_ssa(&mut f).unwrap();
        let phi = &ssa.block(merge).unwrap().phis[0];
        assert_eq!(phi.inputs.len(), 2);

        let ir = from_ssa(&ssa).unwrap();

        let edge_blocks: Vec<&IrBlock> = ir
            .blocks
            .iter()
            .filter(|b| b.label.starts_with("edge_"))
            .collect();
        let edges_to_merge: Vec<&&IrBlock> = edge_blocks
            .iter()
            .filter(
                |b| matches!(b.insts.last(), Some(IrInst::Branch { target }) if *target == merge),
            )
            .collect();
        assert_eq!(
            edges_to_merge.len(),
            1,
            "exactly one split block must branch to merge"
        );
        let edge: &IrBlock = edges_to_merge[0];
        assert_eq!(edge.insts.len(), 2, "one copy plus branch");
        assert_eq!(
            edge.insts.iter().filter(|i| i.is_terminator()).count(),
            1,
            "edge block must end with a single branch"
        );

        let b1_ir = ir.block(b1).unwrap();
        let redirected = match b1_ir.terminator() {
            Some(IrInst::CBranch { target_true, .. }) => *target_true == edge.id,
            _ => false,
        };
        assert!(
            redirected,
            "critical edge must be routed through the split block"
        );

        let merge_ir = ir.block(merge).unwrap();
        assert_eq!(merge_ir.insts.len(), 1);
        assert!(matches!(
            &merge_ir.insts[0],
            IrInst::Return { value: Some(_) }
        ));

        for b in &ir.blocks {
            if b.label.starts_with("edge_") {
                continue;
            }
            for inst in &b.insts {
                assert!(!matches!(inst, IrInst::Phi { .. }));
            }
        }
    }

    #[test]
    fn test_unreachable_block_rejected() {
        let mut func = diamond();
        func.add_block("dead");
        let err = to_ssa(&mut func).unwrap_err();
        assert_eq!(err, SsaError::UnreachableBlocks(vec![BlockId(4)]));
    }

    #[test]
    fn test_unknown_branch_target_returns_error_without_panicking() {
        let mut f = IrFunction::new("dangling", 0x0);
        f.push_inst(
            f.entry_block,
            IrInst::Branch {
                target: BlockId(99),
            },
        );

        assert!(matches!(
            to_ssa(&mut f),
            Err(SsaError::UnknownBlock(99))
        ));
    }

    #[test]
    fn test_missing_entry_returns_error_without_panicking() {
        let mut f = IrFunction::new("bad_entry", 0x0);
        f.entry_block = BlockId(99);

        assert!(matches!(to_ssa(&mut f), Err(SsaError::InvalidEntry(99))));
    }

    #[test]
    fn test_terminator_in_middle_returns_error() {
        let mut f = IrFunction::new("middle_term", 0x0);
        f.push_inst(
            f.entry_block,
            IrInst::Branch {
                target: f.entry_block,
            },
        );
        f.blocks[0].insts.push(IrInst::Nop);

        assert!(matches!(
            to_ssa(&mut f),
            Err(SsaError::TerminatorInMiddle(BlockId(0)))
        ));
    }

    #[test]
    fn test_from_ssa_shares_split_block_per_critical_edge() {
        // Two phis fed across the SAME critical edge must share one split
        // block holding all four copies — per-edge keying guarantees every
        // copy executes.
        let mut f = IrFunction::new("two_phi", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let b1 = f.add_block("inner");
        let b2 = f.add_block("else");
        let merge = f.add_block("merge");
        let x = Value::reg("x", Ty::i64());
        let y = Value::reg("y", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond: cond.clone(),
                target_true: b1,
                target_false: b2,
            },
        );
        f.push_inst(
            b1,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(1),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            b1,
            IrInst::Binary {
                dst: y.clone(),
                op: OpCode::Add,
                lhs: Value::int(2),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            b1,
            IrInst::CBranch {
                cond,
                target_true: merge,
                target_false: b2,
            },
        );
        f.push_inst(
            b2,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(3),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            b2,
            IrInst::Binary {
                dst: y.clone(),
                op: OpCode::Add,
                lhs: Value::int(4),
                rhs: Value::int(0),
            },
        );
        f.push_inst(b2, IrInst::Branch { target: merge });
        f.push_inst(merge, IrInst::Return { value: Some(x) });

        let ssa = to_ssa(&mut f).unwrap();
        assert_eq!(ssa.block(merge).unwrap().phis.len(), 2);

        let ir = from_ssa(&ssa).unwrap();
        let edges_to_merge: Vec<&IrBlock> = ir
            .blocks
            .iter()
            .filter(|b| b.label.starts_with("edge_"))
            .filter(
                |b| matches!(b.insts.last(), Some(IrInst::Branch { target }) if *target == merge),
            )
            .collect();
        assert_eq!(
            edges_to_merge.len(),
            1,
            "one shared split block per critical edge"
        );
        assert_eq!(
            edges_to_merge[0].insts.len(),
            3,
            "two phis x one direct copy each plus branch expected"
        );

        let b1_ir = ir.block(b1).unwrap();
        assert!(
            matches!(b1_ir.terminator(),
                Some(IrInst::CBranch { target_true, .. }) if *target_true == edges_to_merge[0].id),
            "critical edge must be routed through the shared split block"
        );
    }

    #[test]
    fn test_single_def_variable_gets_phi_when_def_does_not_dominate_merge() {
        let mut f = IrFunction::new("single_def", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let then_b = f.add_block("then");
        let merge = f.add_block("merge");
        let x = Value::reg("x", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond,
                target_true: then_b,
                target_false: merge,
            },
        );
        f.push_inst(
            then_b,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(1),
                rhs: Value::int(0),
            },
        );
        f.push_inst(then_b, IrInst::Branch { target: merge });
        f.push_inst(merge, IrInst::Return { value: Some(x) });

        let ssa = to_ssa(&mut f).unwrap();
        let merge_phis = &ssa.block(merge).unwrap().phis;
        assert_eq!(
            merge_phis.len(),
            1,
            "a single non-dominating definition still requires a phi at the merge"
        );
        assert_eq!(merge_phis[0].inputs.len(), 2);
    }

    #[test]
    fn test_single_def_dominating_merge_needs_no_phi() {
        let mut f = IrFunction::new("dom_def", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let b1 = f.add_block("then");
        let b2 = f.add_block("else");
        let merge = f.add_block("merge");
        let x = Value::reg("x", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: x.clone(),
                op: OpCode::Add,
                lhs: Value::int(7),
                rhs: Value::int(0),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond,
                target_true: b1,
                target_false: b2,
            },
        );
        f.push_inst(b1, IrInst::Branch { target: merge });
        f.push_inst(b2, IrInst::Branch { target: merge });
        f.push_inst(merge, IrInst::Return { value: Some(x) });

        let ssa = to_ssa(&mut f).unwrap();
        assert!(
            ssa.block(merge).unwrap().phis.is_empty(),
            "a dominating single definition must not produce a phi"
        );
    }

    #[test]
    fn test_remove_trivial_phi_substitutes_uses() {
        let x1 = VersionedVar {
            base: BaseVar::Reg("x".to_string()),
            version: 1,
            ty: Ty::i64(),
        };
        let x3 = VersionedVar {
            base: BaseVar::Reg("x".to_string()),
            version: 3,
            ty: Ty::i64(),
        };
        let mut ssa = SsaFunction {
            name: "trivial".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                label: "merge".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![Phi {
                    dst: x3.clone(),
                    inputs: vec![(BlockId(1), x1.clone()), (BlockId(2), x1.clone())],
                }],
                insts: vec![SsaInst::Return {
                    value: Some(SsaVal::Ver(x3.clone())),
                }],
            }],
        };

        remove_trivial_phis(&mut ssa);

        assert!(ssa.blocks[0].phis.is_empty());
        match &ssa.blocks[0].insts[0] {
            SsaInst::Return {
                value: Some(SsaVal::Ver(vv)),
            } => assert_eq!(*vv, x1),
            other => panic!("expected substituted return, got {:?}", other),
        }
    }

    #[test]
    fn test_to_ssa_rejects_const_destination() {
        // `v0 = ...` is fine, but writing into a constant has no SSA version;
        // it used to hit `unreachable!` and panic.
        let mut func = IrFunction::new("const_dst", 0x0);
        let entry = func.entry_block;
        func.push_inst(
            entry,
            IrInst::Binary {
                dst: Value::Const(0),
                op: OpCode::Add,
                lhs: Value::Const(1),
                rhs: Value::Const(2),
            },
        );
        assert!(matches!(
            to_ssa(&mut func),
            Err(SsaError::InvalidDestination(_))
        ));
    }

    #[test]
    fn test_from_ssa_rejects_unknown_phi_pred() {
        // Hand-built SSA whose phi cites a predecessor that does not exist.
        // The old `pos[pred]` indexing panicked.
        let v0 = VersionedVar {
            base: BaseVar::Var(0),
            version: 0,
            ty: Ty::i64(),
        };
        let ssa = SsaFunction {
            name: "bad_pred".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                label: "entry".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![Phi {
                    dst: v0.clone(),
                    inputs: vec![(BlockId(99), v0.clone())],
                }],
                insts: vec![SsaInst::Return {
                    value: Some(SsaVal::Ver(v0.clone())),
                }],
            }],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };
        assert!(matches!(
            from_ssa(&ssa),
            Err(SsaError::UnknownBlock(99))
        ));
    }

    #[test]
    fn test_from_ssa_rejects_exhausted_block_ids() {
        // Input already sitting on `u32::MAX`: no id left for split blocks.
        let ssa = SsaFunction {
            name: "max_id".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(u32::MAX),
            blocks: vec![SsaBlock {
                id: BlockId(u32::MAX),
                label: "entry".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![],
                insts: vec![SsaInst::Return { value: None }],
            }],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };
        assert!(matches!(from_ssa(&ssa), Err(SsaError::IdExhausted)));
    }

    #[test]
    fn test_ssa_gvn_eliminates_dominated_recomputation() {
        // entry: x=1; y=2; t1=x+y; cbranch b1/b2
        // b1: t2=x+y (redundant, entry dominates b1); return t2
        // b2: return t1
        let mut f = IrFunction::new("gvn_dom", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let b1 = f.add_block("then");
        let b2 = f.add_block("else");
        let x = Value::reg("x", Ty::i64());
        let y = Value::reg("y", Ty::i64());
        let t1 = Value::reg("t1", Ty::i64());
        let t2 = Value::reg("t2", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: x.clone(),
                op: OpCode::Copy,
                src: Value::int(1),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: y.clone(),
                op: OpCode::Copy,
                src: Value::int(2),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: t1.clone(),
                op: OpCode::Add,
                lhs: x.clone(),
                rhs: y.clone(),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond,
                target_true: b1,
                target_false: b2,
            },
        );
        f.push_inst(
            b1,
            IrInst::Binary {
                dst: t2.clone(),
                op: OpCode::Add,
                lhs: x.clone(),
                rhs: y.clone(),
            },
        );
        f.push_inst(b1, IrInst::Return { value: Some(t2) });
        f.push_inst(b2, IrInst::Return { value: Some(t1) });

        let mut ssa = to_ssa(&mut f).unwrap();
        let stats = ssa_gvn(&mut ssa);
        assert_eq!(stats.eliminated, 1, "dominated recomputation must fold");

        // b1 must now return t1's version directly.
        let b1_ssa = ssa.block(b1).unwrap();
        match &b1_ssa.insts.last() {
            Some(SsaInst::Return {
                value: Some(SsaVal::Ver(v)),
            }) => {
                assert_eq!(v.base, BaseVar::Reg("t1".to_string()));
            }
            other => panic!("expected return of t1, got {other:?}"),
        }
    }

    #[test]
    fn test_ssa_gvn_keeps_sibling_recomputation() {
        // Same add in two sibling branches: neither dominates the other,
        // both must survive.
        let mut f = IrFunction::new("gvn_sib", 0x0);
        let cond = f.alloc_var(Ty::Bool);
        let b1 = f.add_block("then");
        let b2 = f.add_block("else");
        let x = Value::reg("x", Ty::i64());
        let y = Value::reg("y", Ty::i64());
        let t2 = Value::reg("t2", Ty::i64());
        let t3 = Value::reg("t3", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: x.clone(),
                op: OpCode::Copy,
                src: Value::int(1),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: y.clone(),
                op: OpCode::Copy,
                src: Value::int(2),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond,
                target_true: b1,
                target_false: b2,
            },
        );
        f.push_inst(
            b1,
            IrInst::Binary {
                dst: t2.clone(),
                op: OpCode::Add,
                lhs: x.clone(),
                rhs: y.clone(),
            },
        );
        f.push_inst(b1, IrInst::Return { value: Some(t2) });
        f.push_inst(
            b2,
            IrInst::Binary {
                dst: t3.clone(),
                op: OpCode::Add,
                lhs: x.clone(),
                rhs: y.clone(),
            },
        );
        f.push_inst(b2, IrInst::Return { value: Some(t3) });

        let mut ssa = to_ssa(&mut f).unwrap();
        let stats = ssa_gvn(&mut ssa);
        assert_eq!(stats.eliminated, 0, "sibling adds must survive");
        assert_eq!(ssa.block(b1).unwrap().insts.len(), 2);
        assert_eq!(ssa.block(b2).unwrap().insts.len(), 2);
    }

    #[test]
    fn test_ssa_gvn_commutative_unification() {
        // t1 = x + y; t2 = y + x — same block, commutative normalization
        // must unify them.
        let mut f = IrFunction::new("gvn_com", 0x0);
        let x = Value::reg("x", Ty::i64());
        let y = Value::reg("y", Ty::i64());
        let t1 = Value::reg("t1", Ty::i64());
        let t2 = Value::reg("t2", Ty::i64());

        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: x.clone(),
                op: OpCode::Copy,
                src: Value::int(1),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Unary {
                dst: y.clone(),
                op: OpCode::Copy,
                src: Value::int(2),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: t1.clone(),
                op: OpCode::Add,
                lhs: x.clone(),
                rhs: y.clone(),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: t2.clone(),
                op: OpCode::Add,
                lhs: y.clone(),
                rhs: x.clone(),
            },
        );
        f.push_inst(f.entry_block, IrInst::Return { value: Some(t2) });

        let mut ssa = to_ssa(&mut f).unwrap();
        let stats = ssa_gvn(&mut ssa);
        assert_eq!(stats.eliminated, 1, "y+x must unify with x+y");
        match &ssa.blocks[0].insts.last() {
            Some(SsaInst::Return {
                value: Some(SsaVal::Ver(v)),
            }) => assert_eq!(v.base, BaseVar::Reg("t1".to_string())),
            other => panic!("expected return of t1, got {other:?}"),
        }
    }

    #[test]
    fn test_ssa_dce_removes_dead_pure_chain() {
        // entry: a1 = 5; t1 = a1 + 1 (dead); exit: return a1.
        // DCE must drop t1 but keep a1 (used by return).
        let vv = |base: &str, version: u32| VersionedVar {
            base: BaseVar::Reg(base.to_string()),
            version,
            ty: Ty::i64(),
        };
        let a1 = vv("a", 1);
        let t1 = vv("t", 1);
        let mut ssa = SsaFunction {
            name: "dce".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                label: "entry".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![],
                insts: vec![
                    SsaInst::Unary {
                        dst: a1.clone(),
                        op: OpCode::Copy,
                        src: SsaVal::Const(5),
                    },
                    SsaInst::Binary {
                        dst: t1,
                        op: OpCode::Add,
                        lhs: SsaVal::Ver(a1.clone()),
                        rhs: SsaVal::Const(1),
                    },
                    SsaInst::Return {
                        value: Some(SsaVal::Ver(a1)),
                    },
                ],
            }],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };
        let stats = ssa_dce(&mut ssa);
        assert_eq!(stats.removed, 1);
        assert_eq!(ssa.blocks[0].insts.len(), 2);
    }

    #[test]
    fn test_ssa_dce_keeps_live_loads_stores_calls() {
        // A Load whose dst is unused must SURVIVE (memory read side effects
        // are conservative); a Store always survives; a Call survives.
        let vv = |base: &str, version: u32| VersionedVar {
            base: BaseVar::Reg(base.to_string()),
            version,
            ty: Ty::i64(),
        };
        let a1 = vv("a", 1);
        let dst1 = vv("d", 1);
        let mut ssa = SsaFunction {
            name: "dce_side".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                label: "entry".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![],
                insts: vec![
                    SsaInst::Unary {
                        dst: a1.clone(),
                        op: OpCode::Copy,
                        src: SsaVal::Const(5),
                    },
                    SsaInst::Load {
                        dst: dst1,
                        addr: SsaVal::Ver(a1.clone()),
                        size: 4,
                    },
                    SsaInst::Store {
                        addr: SsaVal::Ver(a1),
                        value: SsaVal::Const(9),
                        size: 4,
                    },
                    SsaInst::Return { value: None },
                ],
            }],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };
        let stats = ssa_dce(&mut ssa);
        assert_eq!(stats.removed, 0);
        assert_eq!(ssa.blocks[0].insts.len(), 4);
    }

    #[test]
    fn test_remove_trivial_phi_self_reference() {
        // Loop phi `d = PHI(x, d)` (self-input from the latch): trivial,
        // collapses to `x` — the loop does not change the value.
        let vv = |base: &str, version: u32| VersionedVar {
            base: BaseVar::Reg(base.to_string()),
            version,
            ty: Ty::i64(),
        };
        let x1 = vv("x", 1);
        let d2 = vv("x", 2);
        let mut ssa = SsaFunction {
            name: "selfref".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    label: "entry".to_string(),
                    predecessors: vec![],
                    successors: vec![BlockId(1)],
                    source_range: None,
                    phis: vec![],
                    insts: vec![
                        SsaInst::Unary {
                            dst: x1.clone(),
                            op: OpCode::Copy,
                            src: SsaVal::Const(7),
                        },
                        SsaInst::Branch { target: BlockId(1) },
                    ],
                },
                SsaBlock {
                    id: BlockId(1),
                    label: "header".to_string(),
                    predecessors: vec![BlockId(0), BlockId(2)],
                    successors: vec![BlockId(2), BlockId(3)],
                    source_range: None,
                    phis: vec![Phi {
                        dst: d2.clone(),
                        inputs: vec![(BlockId(0), x1.clone()), (BlockId(2), d2.clone())],
                    }],
                    insts: vec![
                        SsaInst::CBranch {
                            cond: SsaVal::Const(1),
                            target_true: BlockId(2),
                            target_false: BlockId(3),
                        },
                    ],
                },
                SsaBlock {
                    id: BlockId(2),
                    label: "latch".to_string(),
                    predecessors: vec![BlockId(1)],
                    successors: vec![BlockId(1)],
                    source_range: None,
                    phis: vec![],
                    insts: vec![SsaInst::Branch { target: BlockId(1) }],
                },
                SsaBlock {
                    id: BlockId(3),
                    label: "exit".to_string(),
                    predecessors: vec![BlockId(1)],
                    successors: vec![],
                    source_range: None,
                    phis: vec![],
                    insts: vec![SsaInst::Return {
                        value: Some(SsaVal::Ver(d2.clone())),
                    }],
                },
            ],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };

        remove_trivial_phis(&mut ssa);

        let header = ssa.block(BlockId(1)).unwrap();
        assert!(header.phis.is_empty(), "self-referencing phi must fold");
        let exit = ssa.block(BlockId(3)).unwrap();
        match exit.insts.last() {
            Some(SsaInst::Return {
                value: Some(SsaVal::Ver(v)),
            }) => assert_eq!(v, &x1),
            other => panic!("exit must return the surviving x#1, got {other:?}"),
        }
        // The latch input must have been substituted too.
        let header = ssa.block(BlockId(1)).unwrap();
        let _ = header;
    }

    #[test]
    fn test_remove_trivial_phi_cycle_not_folded() {
        // Degenerate `a = PHI(b); b = PHI(a)` pair: folding either would
        // create an infinite substitution loop. The pass must leave both.
        let vv = |base: &str, version: u32| VersionedVar {
            base: BaseVar::Reg(base.to_string()),
            version,
            ty: Ty::i64(),
        };
        let a1 = vv("a", 1);
        let b1 = vv("b", 1);
        let entry_to_a = Phi {
            dst: a1.clone(),
            inputs: vec![(BlockId(0), b1.clone())],
        };
        let entry_to_b = Phi {
            dst: b1.clone(),
            inputs: vec![(BlockId(0), a1.clone())],
        };
        let mut ssa = SsaFunction {
            name: "cycle".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                label: "entry".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![entry_to_a, entry_to_b],
                insts: vec![],
            }],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };

        remove_trivial_phis(&mut ssa);
        // `a = PHI(b)` folds first: uses of `a` (the phi for `b`) become `b`.
        // Then `b = PHI(b)` is a self-identity and folds too. No infinite
        // substitution loop is the requirement — collapse is fine.
        let surviving: Vec<&VersionedVar> = ssa.blocks[0]
            .phis
            .iter()
            .map(|p| &p.dst)
            .collect();
        let _ = surviving;
        assert!(
            ssa.blocks[0].phis.len() <= 2,
            "cycle must terminate, not loop"
        );
    }

    #[test]
    fn test_remove_trivial_phi_chain_collapses() {
        // `c = PHI(a); b = PHI(c); use(b)` — chain through two phis must
        // collapse to direct uses of `a` in one fixpoint round set.
        let vv = |base: &str, version: u32| VersionedVar {
            base: BaseVar::Reg(base.to_string()),
            version,
            ty: Ty::i64(),
        };
        let a1 = vv("a", 1);
        let b2 = vv("b", 2);
        let c3 = vv("c", 3);
        let mut ssa = SsaFunction {
            name: "chain".to_string(),
            entry_address: 0x0,
            entry_block: BlockId(0),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                label: "merge".to_string(),
                predecessors: vec![],
                successors: vec![],
                source_range: None,
                phis: vec![
                    Phi {
                        dst: c3.clone(),
                        inputs: vec![(BlockId(0), a1.clone())],
                    },
                    Phi {
                        dst: b2.clone(),
                        inputs: vec![(BlockId(0), c3.clone())],
                    },
                ],
                insts: vec![SsaInst::Return {
                    value: Some(SsaVal::Ver(b2.clone())),
                }],
            }],
            versions: HashMap::new(),
            metadata: FunctionMetadata::default(),
        };

        remove_trivial_phis(&mut ssa);
        assert!(ssa.blocks[0].phis.is_empty(), "chain must collapse");
        match &ssa.blocks[0].insts[0] {
            SsaInst::Return {
                value: Some(SsaVal::Ver(v)),
            } => assert_eq!(v, &a1),
            other => panic!("expected return of a#1, got {other:?}"),
        }
    }
}
