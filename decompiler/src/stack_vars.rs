//! Stack-variable recovery: fold `rsp`-relative memory accesses into named locals.
//!
//! Raw lifted IR materialises every stack access as an explicit address
//! computation followed by a memory operation, which renders in C as
//! `*(rsp + 0x38) = rcx;`. This IR-level pass rewrites
//!
//! ```text
//! t = rsp + K  (or rsp - K)      -- Binary { Add / Sub }
//! STORE(t, v, n)   /   LOAD(dst, t, n)
//! ```
//!
//! into plain copies through one synthetic variable per distinct stack slot,
//! so the C output shows `local_38 = rcx;` / `rcx = local_38;`. The x86
//! lifter always emits the address expression immediately before its use
//! (`freakre_ir::x86_lifter::X86Lifter::build_address`), so matching a
//! single `rsp ± const` step covers compiler-generated frames.
//!
//! The pass handles rbp-based frames the same way: a canonical frame-setup
//! (`tmp = rsp ± k; rbp = tmp`, the lifter's shape for `lea rbp, [rsp+k]`,
//! plus the direct `rbp = rsp ± k` / `rbp = rsp` forms) pins rbp to
//! `entry_rsp + base`. Every subsequent `rbp ± N` access then maps to the
//! entry-relative offset `base ± N` and reuses the slot table above; the
//! setup statement itself is deleted. Address computations anchored at rbp
//! behave exactly like rsp ones: temps fully consumed by matched accesses
//! are deleted, while escaping ones (`lea rcx, [rbp-0x28]` passed to a
//! call) stay in raw form. Pop-sequence restores materialise as
//! `Load([rsp]); rbp = tmp`; once rbp is a recognised frame pointer those
//! pairs are dead writes and are removed.
//!
//! The pass is conservative and leaves the function untouched whenever
//! `rsp` escapes its well-understood role:
//!
//! - `rsp` is written by anything except the canonical
//!   `tmp = rsp ± k; rsp = tmp` shape the lifters emit for
//!   `sub/add rsp`, push/pop and epilogues, or
//! - two control-flow paths disagree about a block's entry delta, or
//! - recovered slots would overlap ambiguously (mixed access sizes at one
//!   offset or overlapping byte ranges), or
//! - the function's variable-id counter is out of sync with existing ids,
//!   or
//! - `rbp` is written anywhere except the recognised setup / restore
//!   pattern (multiple setups included), or — once a frame pointer was
//!   recognised — read as a plain value outside address computations.
//!
//! When no rbp write exists at all the pass behaves exactly like the
//! rsp-only recovery of previous revisions.
//!
//! Recovered slots become ordinary SSA variables via
//! [`IrFunction::alloc_var`], so `ir_to_ast`'s local collection declares
//! them automatically; [`apply_recovered_names`] then renames `v{id}` to
//! the conventional `local_<hex offset>` spelling at AST level (and
//! declares slots that are only ever loaded, which have no destination
//! instruction for `ir_to_ast` to record).
//!
//! Note: once a stack slot is a plain variable, later AST passes can see
//! when it is written but never read (typical MSVC home-space spills) and
//! eliminate those dead stores. That removal is sound within the function
//! because the safety rules above guarantee the slot address never
//! escapes.

use crate::ast::{Expr, Stmt};
use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Base register treated as the stack pointer.
const STACK_REG: &str = "rsp";

/// Register recognised as an optional frame pointer.
const FRAME_REG: &str = "rbp";

/// A recovered stack-slot variable.
#[derive(Debug, Clone)]
pub struct RecoveredStackVar {
    /// Conventional spelling, e.g. `"local_38"`.
    pub name: String,
    /// Access-width type of the slot.
    pub ty: Ty,
}

/// Recovered stack slots keyed by synthetic IR variable id.
///
/// `ir_to_ast` collects local declarations from variable *destinations*
/// only, so slots that are merely loaded (never stored within the
/// function) would stay undeclared; [`apply_recovered_names`] closes that
/// gap using this map.
pub type StackVarNames = HashMap<u32, RecoveredStackVar>;

/// Recover stack variables in-place and return the id → slot mapping for
/// the freshly allocated variables. An empty map means "skipped".
pub fn recover_stack_vars(func: &mut IrFunction) -> StackVarNames {
    let plan = match plan_recovery(func) {
        Some(plan) => plan,
        None => return StackVarNames::new(),
    };

    // Guard against hand-built functions whose var ids bypass `alloc_var`:
    // if any existing id sits at-or-above the allocation frontier, renaming
    // `v{id}` strings could clobber an unrelated variable.
    let max_existing = max_var_id(func);
    let first_new = func.alloc_var(Ty::u64()).var_id().unwrap_or(u32::MAX);
    if max_existing >= first_new {
        return StackVarNames::new();
    }

    // One typed variable per distinct slot offset (deterministic order).
    let mut names: StackVarNames = StackVarNames::new();
    let mut slot_values: HashMap<i64, Value> = HashMap::new();
    for (&offset, &size) in &plan.slots {
        let ty = int_ty_for(size);
        let value = func.alloc_var(ty.clone());
        if let Value::Var { id, .. } = &value {
            names.insert(
                *id,
                RecoveredStackVar {
                    name: slot_name(offset, &ty),
                    ty,
                },
            );
        }
        slot_values.insert(offset, value);
    }

    for (bi, block) in func.blocks.iter_mut().enumerate() {
        let old = std::mem::take(&mut block.insts);
        let mut out = Vec::with_capacity(old.len());
        for (ii, inst) in old.into_iter().enumerate() {
            if plan.removals.contains(&(bi, ii)) {
                continue;
            }
            match plan.accesses.get(&(bi, ii)) {
                Some(access) => {
                    let slot = slot_values[&access.offset].clone();
                    out.push(match (access.kind, &inst) {
                        (AccessKind::Load, IrInst::Load { dst, .. }) => IrInst::Unary {
                            dst: dst.clone(),
                            op: OpCode::Copy,
                            src: slot,
                        },
                        (AccessKind::Store, IrInst::Store { value, .. }) => IrInst::Unary {
                            dst: slot,
                            op: OpCode::Copy,
                            src: value.clone(),
                        },
                        _ => inst,
                    });
                }
                None => out.push(inst),
            }
        }
        block.insts = out;
    }

    names
}

/// Rename AST variables produced by [`recover_stack_vars`] from `v{id}` to
/// their `local_xx` spelling — in declarations and throughout the body —
/// and declare any slot that `ir_to_ast` could not have picked up (slots
/// that are only ever loaded have no destination instruction to record).
pub fn apply_recovered_names(func: &mut crate::ast::AstFunction, names: &StackVarNames) {
    if names.is_empty() {
        return;
    }
    for local in &mut func.locals {
        if let Some(var) = local_name(&local.name, names) {
            local.name = var.name.clone();
        }
    }
    for var in names.values() {
        if !func.locals.iter().any(|l| l.name == var.name) {
            func.locals.push(crate::ast::LocalVar {
                name: var.name.clone(),
                ty: var.ty.clone(),
                is_used: true,
            });
        }
    }
    rename_stmts(&mut func.body, names);
}

// ─── Analysis ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessKind {
    Load,
    Store,
}

#[derive(Debug, Clone, Copy)]
struct Access {
    /// Slot offset relative to function-entry rsp.
    offset: i64,
    size: u32,
    kind: AccessKind,
    /// Address temp consumed by this access, when routed through one.
    via_def: Option<u32>,
}

struct RecoveryPlan {
    /// (block index, instruction index) → rewritten access.
    accesses: HashMap<(usize, usize), Access>,
    /// Fully-consumed address-computation instructions to delete.
    removals: HashSet<(usize, usize)>,
    /// Slot offset → uniform access size in bytes.
    slots: BTreeMap<i64, u32>,
}

/// Analyse `func`; returns `None` when recovery is unsafe or pointless.
///
/// Offsets are normalised to function-entry `rsp`: a canonical stack-pointer
/// update (`tmp = rsp ± k; rsp = tmp`, exactly how the lifters emit
/// `sub/add rsp`, push/pop and epilogues) shifts a running delta, and each
/// access is folded at `literal_offset + delta`. Deltas propagate over the
/// CFG; if two paths disagree about a block's entry delta, recovery is
/// refused entirely.
fn plan_recovery(func: &IrFunction) -> Option<RecoveryPlan> {
    let mut def_counts: HashMap<u32, usize> = HashMap::new();
    let mut refs: HashMap<u32, usize> = HashMap::new();

    for block in &func.blocks {
        for inst in &block.insts {
            if let Some(Value::Var { id, .. }) = inst.dst() {
                *def_counts.entry(*id).or_insert(0) += 1;
            }
            for src in inst.sources() {
                if let Value::Var { id, .. } = src {
                    *refs.entry(*id).or_insert(0) += 1;
                }
            }
        }
    }

    // Definition site of every single-definition variable (for chains).
    let mut inst_defs: HashMap<u32, &IrInst> = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            if let Some(Value::Var { id, .. }) = inst.dst() {
                if def_counts.get(id) == Some(&1) {
                    inst_defs.insert(*id, inst);
                }
            }
            // rsp may only appear where this pass understands it: as the
            // base of address computations, inside canonical updates, or
            // as the address of a Load/Store. Any other read (frame
            // aliases like `rbp = rsp`, comparisons, passing rsp to a
            // call) aborts recovery.
            if uses_rsp_unsafely(inst) {
                return None;
            }
        }
    }

    let deltas = entry_deltas(func, &inst_defs, &refs)?;

    // Second sweep: collect accesses with entry-relative offsets.
    let mut addr_defs: HashMap<u32, i64> = HashMap::new();
    let mut def_deltas: HashMap<u32, i64> = HashMap::new();
    let mut accesses: Vec<Access> = Vec::new();
    let mut positions: Vec<(usize, usize)> = Vec::new();
    let mut slots: BTreeMap<i64, u32> = BTreeMap::new();

    for (bi, block) in func.blocks.iter().enumerate() {
        // Blocks unreachable from the entry keep raw memory form.
        let mut delta = match deltas[bi] {
            Some(d) => d,
            None => continue,
        };
        for (ii, inst) in block.insts.iter().enumerate() {
            match step_of(inst, &inst_defs, &refs) {
                Step::Unsafe => return None,
                Step::Update(k) => {
                    delta += k;
                    continue;
                }
                Step::Other => {}
            }
            if let Some((id, off)) = classify_addr_def(inst) {
                addr_defs.insert(id, off);
                def_deltas.insert(id, delta);
                continue;
            }
            let (addr, size, kind) = match inst {
                IrInst::Load { addr, size, .. } => (addr, *size, AccessKind::Load),
                IrInst::Store { addr, size, .. } => (addr, *size, AccessKind::Store),
                _ => continue,
            };
            let (offset, via_def) = match addr {
                v if is_stack_reg(v) => (delta, None),
                Value::Var { id, .. } => match (addr_defs.get(id), def_deltas.get(id)) {
                    (Some(&lit), Some(&def_delta)) if def_delta == delta => {
                        (lit + delta, Some(*id))
                    }
                    (Some(_), Some(_)) => return None,
                    _ => continue,
                },
                _ => continue,
            };
            match slots.get(&offset) {
                Some(s) if *s != size => return None,
                Some(_) => {}
                None => {
                    slots.insert(offset, size);
                }
            }
            accesses.push(Access {
                offset,
                size,
                kind,
                via_def,
            });
            positions.push((bi, ii));
        }
    }
    if accesses.is_empty() {
        return None;
    }

    // Overlapping byte ranges would alias one physical slot while being
    // modelled as two independent variables — refuse instead.
    let ranges: Vec<(i64, i64)> = slots.iter().map(|(o, s)| (*o, *o + *s as i64)).collect();
    for w in ranges.windows(2) {
        if w[1].0 < w[0].1 {
            return None;
        }
    }

    // Delete an address temp only when every reference to it is a matched
    // access address; otherwise keep it alive for its remaining users.
    let mut match_counts: HashMap<u32, usize> = HashMap::new();
    let mut access_map: HashMap<(usize, usize), Access> = HashMap::new();
    for (access, pos) in accesses.iter().zip(&positions) {
        if let Some(id) = access.via_def {
            *match_counts.entry(id).or_insert(0) += 1;
        }
        access_map.insert(*pos, *access);
    }

    let mut removals: HashSet<(usize, usize)> = HashSet::new();
    for (bi, block) in func.blocks.iter().enumerate() {
        for (ii, inst) in block.insts.iter().enumerate() {
            if let Some((id, _)) = classify_addr_def(inst) {
                if match_counts.contains_key(&id) && refs.get(&id) == match_counts.get(&id) {
                    removals.insert((bi, ii));
                }
            }
        }
    }

    Some(RecoveryPlan {
        accesses: access_map,
        removals,
        slots,
    })
}

/// True when this instruction reads or writes `rsp` in a role the pass
/// does not model (anything beyond address bases and canonical updates).
fn uses_rsp_unsafely(inst: &IrInst) -> bool {
    match inst {
        IrInst::Load { .. } => false,
        IrInst::Store { value, .. } => is_stack_reg(value),
        IrInst::Binary {
            op: OpCode::Add | OpCode::Sub,
            ..
        } if is_stack_reg(inst.dst().unwrap_or(&Value::Const(0)))
            || classify_addr_def(inst).is_some()
            || is_direct_setup_shape(inst) =>
        {
            false
        }
        other => other.sources().iter().any(|v| is_stack_reg(v)),
    }
}

/// Structural check for the direct frame setup `rbp = rsp ± k`: writing
/// rbp from rsp+const is a potential setup the rbp analysis decides about;
/// it must not trip the rsp safety net first.
fn is_direct_setup_shape(inst: &IrInst) -> bool {
    match inst {
        IrInst::Binary {
            dst,
            op: bin_op @ (OpCode::Add | OpCode::Sub),
            lhs,
            rhs,
        } if is_frame_reg(dst) => match (lhs, rhs) {
            (l, Value::Const(_)) if is_stack_reg(l) => true,
            (Value::Const(_), r) if is_stack_reg(r) => *bin_op == OpCode::Add,
            _ => false,
        },
        _ => false,
    }
}

/// What the analyser does with one instruction while walking a block.
enum Step {
    /// Nothing special.
    Other,
    /// Canonical stack-pointer update shifting rsp by the given amount.
    Update(i64),
    /// Writes rsp in a way this pass cannot model — bail out.
    Unsafe,
}

/// Classify instructions that define `rsp`. The lifters always materialise
/// updates as `tmp = rsp ± k` followed by `rsp = tmp`; anything else that
/// writes rsp is rejected.
fn step_of(inst: &IrInst, defs: &HashMap<u32, &IrInst>, refs: &HashMap<u32, usize>) -> Step {
    match inst.dst() {
        Some(v) if is_stack_reg(v) => {}
        _ => return Step::Other,
    }
    match inst {
        IrInst::Unary {
            op: OpCode::Copy,
            src,
            ..
        } => match chain_offset(src, defs, refs) {
            Some(k) => Step::Update(k),
            None => Step::Unsafe,
        },
        IrInst::Binary {
            op: bin_op @ (OpCode::Add | OpCode::Sub),
            lhs,
            rhs,
            ..
        } => {
            let off = match (lhs, rhs) {
                (l, Value::Const(c)) => chain_offset(l, defs, refs).map(|base| {
                    if *bin_op == OpCode::Sub {
                        base - c
                    } else {
                        base + c
                    }
                }),
                (Value::Const(c), r) if *bin_op == OpCode::Add => {
                    chain_offset(r, defs, refs).map(|base| base + c)
                }
                _ => None,
            };
            match off {
                Some(k) => Step::Update(k),
                None => Step::Unsafe,
            }
        }
        _ => Step::Unsafe,
    }
}

/// Maximum length of a `rsp ± const` definition chain we follow.
const CHAIN_DEPTH: u32 = 4;

/// Resolve `value` to a constant offset from `rsp` through pure add/sub
/// chains. Every intermediate temp must be single-use so the derived
/// pointer value cannot escape into unrelated computations.
fn chain_offset(
    value: &Value,
    defs: &HashMap<u32, &IrInst>,
    refs: &HashMap<u32, usize>,
) -> Option<i64> {
    chain_offset_at(value, defs, refs, CHAIN_DEPTH)
}

fn chain_offset_at(
    value: &Value,
    defs: &HashMap<u32, &IrInst>,
    refs: &HashMap<u32, usize>,
    depth: u32,
) -> Option<i64> {
    match value {
        v if is_stack_reg(v) => Some(0),
        Value::Var { id, .. } if depth > 0 && refs.get(id) == Some(&1) => {
            let def = defs.get(id)?;
            match def {
                IrInst::Binary {
                    op: bin_op @ (OpCode::Add | OpCode::Sub),
                    lhs,
                    rhs,
                    ..
                } => {
                    let (base, off) = match (lhs, rhs) {
                        (l, Value::Const(c)) => (l, *c),
                        (Value::Const(c), r) if *bin_op == OpCode::Add => (r, *c),
                        _ => return None,
                    };
                    let lower = chain_offset_at(base, defs, refs, depth - 1)?;
                    Some(if *bin_op == OpCode::Sub {
                        lower - off
                    } else {
                        lower + off
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Entry-relative rsp delta for every reachable block. Returns `None` when
/// an unsafe rsp write exists anywhere reachable, or when two paths
/// disagree about a block's entry delta.
fn entry_deltas(
    func: &IrFunction,
    defs: &HashMap<u32, &IrInst>,
    refs: &HashMap<u32, usize>,
) -> Option<Vec<Option<i64>>> {
    let mut deltas: Vec<Option<i64>> = vec![None; func.blocks.len()];
    let entry = func.entry_block.0 as usize;
    if entry >= func.blocks.len() {
        return None;
    }
    deltas[entry] = Some(0);
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(entry);
    while let Some(bi) = queue.pop_front() {
        let mut delta = deltas[bi]?;
        for inst in &func.blocks[bi].insts {
            match step_of(inst, defs, refs) {
                Step::Unsafe => return None,
                Step::Update(k) => delta += k,
                Step::Other => {}
            }
        }
        for succ in block_successors(&func.blocks[bi]) {
            if succ >= deltas.len() {
                return None;
            }
            match deltas[succ] {
                None => {
                    deltas[succ] = Some(delta);
                    queue.push_back(succ);
                }
                Some(prev) if prev != delta => return None,
                _ => {}
            }
        }
    }
    Some(deltas)
}

fn block_successors(block: &freakre_ir::IrBlock) -> Vec<usize> {
    match block.insts.last() {
        Some(IrInst::Branch { target }) => vec![target.0 as usize],
        Some(IrInst::CBranch {
            target_true,
            target_false,
            ..
        }) => vec![target_true.0 as usize, target_false.0 as usize],
        _ => vec![],
    }
}

/// Recognise `t = rsp + const` / `t = rsp - const` (Add accepts either
/// operand order); returns the destination id and the signed offset.
fn classify_addr_def(inst: &IrInst) -> Option<(u32, i64)> {
    match inst {
        IrInst::Binary {
            dst: Value::Var { id, .. },
            op,
            lhs,
            rhs,
        } => {
            let offset = match (op, lhs, rhs) {
                (_, l, Value::Const(c)) if is_stack_reg(l) => *c,
                (OpCode::Add, Value::Const(c), r) if is_stack_reg(r) => *c,
                _ => return None,
            };
            Some((*id, offset))
        }
        _ => None,
    }
}

fn is_stack_reg(value: &Value) -> bool {
    matches!(value, Value::Register { name, .. } if name == STACK_REG)
}

fn is_frame_reg(value: &Value) -> bool {
    matches!(value, Value::Register { name, .. } if name == FRAME_REG)
}

/// A recognised frame-pointer setup: rbp pinned to `entry_rsp + rel_base`.
#[derive(Debug, Clone, Copy)]
struct FrameSetup {
    /// Offset from the rsp value current at the setup instruction.
    rel_base: i64,
    /// Temp consumed by the setup copy, when materialised through one.
    via_temp: Option<u32>,
    /// Position of the setup's final instruction (copy / binary).
    at: (usize, usize),
    /// Position of the temp definition to delete alongside, when present.
    temp_at: Option<(usize, usize)>,
}

/// A recognised pop-style restore pair: `Load([rsp..]); rbp = tmp`.
#[derive(Debug, Clone, Copy)]
struct FrameRestore {
    copy_at: (usize, usize),
    load_at: (usize, usize),
}

/// Recognise a canonical frame-setup write to rbp:
///
/// ```text
/// tmp = rsp ± k ; rbp = COPY tmp     (lifter shape for lea rbp,[rsp±k])
/// rbp = COPY rsp                     (mov rbp, rsp)
/// rbp = rsp ± k                      (direct binary form)
/// ```
///
/// The temp variant requires the temp to be defined directly by a
/// `rsp ± const` address computation and to have exactly one reference,
/// so both halves can be deleted. Returns `(via_temp, rel_base)`.
fn classify_setup_write(
    inst: &IrInst,
    defs: &HashMap<u32, &IrInst>,
    refs: &HashMap<u32, usize>,
) -> Option<(Option<u32>, i64)> {
    match inst {
        IrInst::Unary {
            op: OpCode::Copy,
            dst,
            src,
        } if is_frame_reg(dst) => {
            let base = chain_offset(src, defs, refs)?;
            let via = match src {
                v if is_stack_reg(v) => None,
                Value::Var { id, .. } => {
                    // Only a direct, single-use `rsp ± k` def is deletable.
                    refs.get(id).filter(|&&n| n == 1)?;
                    match defs.get(id)? {
                        other if classify_addr_def(other).is_some() => Some(*id),
                        _ => return None,
                    }
                }
                _ => return None,
            };
            Some((via, base))
        }
        IrInst::Binary {
            dst,
            op: bin_op @ (OpCode::Add | OpCode::Sub),
            lhs,
            rhs,
        } if is_frame_reg(dst) => {
            let base = match (lhs, rhs) {
                (l, Value::Const(c)) if is_stack_reg(l) => {
                    if *bin_op == OpCode::Sub {
                        -*c
                    } else {
                        *c
                    }
                }
                (Value::Const(c), r) if *bin_op == OpCode::Add && is_stack_reg(r) => *c,
                _ => return None,
            };
            Some((None, base))
        }
        _ => None,
    }
}

/// Recognise a pop-style restore write: `rbp = COPY tmp` where tmp is
/// defined exactly once by a Load whose address sits at a tracked rsp
/// position. Returns the Load's destination id.
fn classify_restore_write(
    inst: &IrInst,
    defs: &HashMap<u32, &IrInst>,
    refs: &HashMap<u32, usize>,
) -> Option<u32> {
    match inst {
        IrInst::Unary {
            op: OpCode::Copy,
            dst,
            src,
        } if is_frame_reg(dst) => {
            let id = match src {
                Value::Var { id, .. } => *id,
                _ => return None,
            };
            if refs.get(&id) != Some(&1) {
                return None;
            }
            match defs.get(&id)? {
                IrInst::Load { addr, .. } if chain_offset(addr, defs, refs).is_some() => Some(id),
                _ => None,
            }
        }
        _ => None,
    }
}

/// True when this instruction reads rbp in a role the pass does not model
/// once it is a recognised frame pointer (plain-value uses: copies into
/// GPRs, call arguments, returns, flag-producing arithmetic, ...).
/// Address computations (`rbp ± const`) and memory operations through or
/// spilling rbp remain allowed.
fn reads_frame_reg_unsafely(inst: &IrInst) -> bool {
    if !inst.sources().iter().any(|v| is_frame_reg(v)) {
        return false;
    }
    !matches!(
        inst,
        IrInst::Binary {
            op: OpCode::Add | OpCode::Sub,
            ..
        } | IrInst::Load { .. }
            | IrInst::Store { .. }
    )
}

/// Recognise `t = rbp + const` / `t = rbp - const`; the rbp counterpart of
/// [`classify_addr_def`]. Returns the destination id and signed offset.
fn classify_frame_addr_def(inst: &IrInst) -> Option<(u32, i64)> {
    match inst {
        IrInst::Binary {
            dst: Value::Var { id, .. },
            op,
            lhs,
            rhs,
        } => {
            let offset = match (op, lhs, rhs) {
                (_, l, Value::Const(c)) if is_frame_reg(l) => *c,
                (OpCode::Add, Value::Const(c), r) if is_frame_reg(r) => *c,
                _ => return None,
            };
            Some((*id, offset))
        }
        _ => None,
    }
}

fn int_ty_for(size: u32) -> Ty {
    match size {
        1 => Ty::u8(),
        2 => Ty::u16(),
        4 => Ty::u32(),
        8 => Ty::u64(),
        n => Ty::UInt(n.saturating_mul(8)),
    }
}

/// Generate meaningful name for stack variable based on offset and type.
///
/// Naming convention:
/// - Negative offsets (arguments): arg_<offset>, ptr_<offset>, etc.
/// - Positive offsets (locals): local_<offset>, var_<offset>, etc.
/// - Type prefixes: byte_, word_, dword_, qword_, float_, double_, ptr_
///
/// Examples:
/// - arg_10 (function argument at offset -0x10)
/// - ptr_20 (pointer at offset 0x20)
/// - dword_30 (32-bit value at offset 0x30)
/// - local_m10 (local variable at offset -0x10)
fn slot_name(offset: i64, ty: &Ty) -> String {
    let prefix = type_prefix(ty);
    let is_arg = offset < 0;

    if is_arg {
        // Function arguments (negative offsets from base pointer)
        if prefix == "ptr" {
            format!("arg_ptr_{:x}", offset.unsigned_abs())
        } else {
            format!("arg_{:x}", offset.unsigned_abs())
        }
    } else {
        // Local variables (positive offsets from stack pointer)
        if offset == 0 {
            format!("{}_0", prefix)
        } else {
            format!("{}_{:x}", prefix, offset)
        }
    }
}

/// Get type prefix for variable naming based on type.
fn type_prefix(ty: &Ty) -> String {
    match ty {
        Ty::Ptr(_) => "ptr".to_string(),
        Ty::Int(8) | Ty::UInt(8) => "byte".to_string(),
        Ty::Int(16) | Ty::UInt(16) => "word".to_string(),
        Ty::Int(32) | Ty::UInt(32) => "dword".to_string(),
        Ty::Int(64) | Ty::UInt(64) => "qword".to_string(),
        Ty::Int(n) => format!("i{}", n),
        Ty::UInt(n) => format!("u{}", n),
        Ty::Float(32) => "float".to_string(),
        Ty::Float(64) => "double".to_string(),
        Ty::Float(n) => format!("f{}", n),
        Ty::Void => "void".to_string(),
        Ty::Bool => "bool".to_string(),
        Ty::Struct(_) => "struct".to_string(),
        Ty::Array(_, _) => "array".to_string(),
        Ty::Unknown => "var".to_string(),
    }
}

fn max_var_id(func: &IrFunction) -> u32 {
    let mut max = 0;
    for block in &func.blocks {
        for inst in &block.insts {
            if let Some(Value::Var { id, .. }) = inst.dst() {
                max = max.max(*id);
            }
            for src in inst.sources() {
                if let Value::Var { id, .. } = src {
                    max = max.max(*id);
                }
            }
        }
    }
    max
}

// ─── AST-level renaming ──────────────────────────────────────────────

fn local_name<'a>(name: &str, names: &'a StackVarNames) -> Option<&'a RecoveredStackVar> {
    let id = name.strip_prefix('v')?.parse::<u32>().ok()?;
    names.get(&id)
}

fn rename_stmts(stmts: &mut [Stmt], names: &StackVarNames) {
    for stmt in stmts {
        rename_stmt(stmt, names);
    }
}

fn rename_stmt(stmt: &mut Stmt, names: &StackVarNames) {
    match stmt {
        Stmt::Assign { target, value } => {
            rename_expr(target, names);
            rename_expr(value, names);
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            rename_expr(cond, names);
            rename_stmts(then_body, names);
            if let Some(body) = else_body {
                rename_stmts(body, names);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            rename_expr(cond, names);
            rename_stmts(body, names);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                rename_stmt(init, names);
            }
            if let Some(cond) = cond {
                rename_expr(cond, names);
            }
            if let Some(update) = update {
                rename_stmt(update, names);
            }
            rename_stmts(body, names);
        }
        Stmt::Switch {
            expr,
            cases,
            default,
        } => {
            rename_expr(expr, names);
            for case in cases {
                rename_expr(&mut case.value, names);
                rename_stmts(&mut case.body, names);
            }
            if let Some(default) = default {
                rename_stmts(default, names);
            }
        }
        Stmt::Return { value: Some(expr) } => rename_expr(expr, names),
        Stmt::Call { args, .. } => {
            for arg in args {
                rename_expr(arg, names);
            }
        }
        Stmt::Expr(expr) => rename_expr(expr, names),
        Stmt::Block(body) => rename_stmts(body, names),
        Stmt::Decl {
            init: Some(expr), ..
        } => rename_expr(expr, names),
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
            rename_stmts(try_body, names);
            rename_stmts(catch_body, names);
        }
        _ => {}
    }
}

fn rename_expr(expr: &mut Expr, names: &StackVarNames) {
    match expr {
        Expr::Var(name) => {
            if let Some(var) = local_name(name, names) {
                *name = var.name.clone();
            }
        }
        Expr::Binary { lhs, rhs, .. } => {
            rename_expr(lhs, names);
            rename_expr(rhs, names);
        }
        Expr::Unary { operand, .. }
        | Expr::Deref(operand)
        | Expr::AddrOf(operand)
        | Expr::Sizeof(operand) => rename_expr(operand, names),
        Expr::Call { args, .. } => {
            for arg in args {
                rename_expr(arg, names);
            }
        }
        Expr::Index { base, index } => {
            rename_expr(base, names);
            rename_expr(index, names);
        }
        Expr::Member { base, .. } => rename_expr(base, names),
        Expr::Cast { expr, .. } => rename_expr(expr, names),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            rename_expr(cond, names);
            rename_expr(then_expr, names);
            rename_expr(else_expr, names);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{x86_lifter::X86Lifter, Lifter};

    fn stack_access_func() -> IrFunction {
        let mut func = IrFunction::new("stacky", 0x1000);
        let rsp = Value::reg("rsp", Ty::i64());
        let rcx = Value::reg("rcx", Ty::i64());

        let t1 = func.alloc_var(Ty::i64());
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: t1.clone(),
                op: OpCode::Add,
                lhs: rsp.clone(),
                rhs: Value::Const(0x30),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Store {
                addr: t1,
                value: rcx.clone(),
                size: 8,
            },
        );

        let t2 = func.alloc_var(Ty::i64());
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: t2.clone(),
                op: OpCode::Add,
                lhs: rsp,
                rhs: Value::Const(0x70),
            },
        );
        let out = func.alloc_var(Ty::i64());
        func.push_inst(
            func.entry_block,
            IrInst::Load {
                dst: out.clone(),
                addr: t2,
                size: 8,
            },
        );
        func.push_inst(func.entry_block, IrInst::Return { value: Some(out) });
        func
    }

    fn counts(func: &IrFunction) -> (usize, usize, usize) {
        let mut loads = 0;
        let mut stores = 0;
        let mut addr_bins = 0;
        for b in &func.blocks {
            for inst in &b.insts {
                if matches!(inst, IrInst::Load { .. }) {
                    loads += 1;
                }
                if matches!(inst, IrInst::Store { .. }) {
                    stores += 1;
                }
                if classify_addr_def(inst).is_some() {
                    addr_bins += 1;
                }
            }
        }
        (loads, stores, addr_bins)
    }

    #[test]
    fn test_recovers_store_and_load() {
        let mut func = stack_access_func();
        let names = recover_stack_vars(&mut func);

        let mut recovered: Vec<&str> = names.values().map(|v| v.name.as_str()).collect();
        recovered.sort();
        // With improved naming: qword_ prefix for 8-byte variables
        assert_eq!(recovered, ["qword_30", "qword_70"]);
        assert_eq!(
            counts(&func),
            (0, 0, 0),
            "loads/stores/address temps must be gone"
        );

        let copies: Vec<_> = func.blocks[0]
            .insts
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    IrInst::Unary {
                        op: OpCode::Copy,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(copies.len(), 2, "both accesses become copies");

        // Check the declaration/naming wiring directly on the AST. The
        // load-only slot qword_70 has no destination instruction, so it
        // must arrive via apply_recovered_names' declaration fix-up.
        let mut ast = crate::ir_to_ast::ir_to_ast(&func);
        crate::stack_vars::apply_recovered_names(&mut ast, &names);
        let c = crate::ast_to_c::ast_to_c(&ast);
        assert!(c.contains("uint64_t qword_30;"), "{}", c);
        assert!(c.contains("uint64_t qword_70;"), "{}", c);
        assert!(c.contains("qword_30 = rcx"), "{}", c);
        assert!(c.contains("= qword_70"), "{}", c);
    }

    #[test]
    fn test_skips_function_that_writes_rsp() {
        let mut func = stack_access_func();
        func.push_inst(
            func.entry_block,
            IrInst::Unary {
                dst: Value::reg("rsp", Ty::i64()),
                op: OpCode::Copy,
                src: Value::Const(8),
            },
        );
        let before = func.display();
        let names = recover_stack_vars(&mut func);

        assert!(names.is_empty(), "must bail on rsp writes");
        assert_eq!(before, func.display(), "function must be untouched");
    }

    #[test]
    fn test_skips_when_rsp_used_as_value() {
        let mut func = stack_access_func();
        let t = func.alloc_var(Ty::i64());
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: t,
                op: OpCode::And,
                lhs: Value::reg("rsp", Ty::i64()),
                rhs: Value::reg("rbp", Ty::i64()),
            },
        );
        let before = func.display();
        let names = recover_stack_vars(&mut func);

        assert!(names.is_empty(), "must bail on non-address rsp uses");
        assert_eq!(before, func.display());
    }

    #[test]
    fn test_skips_on_overlapping_slots() {
        let mut func = IrFunction::new("overlap", 0x1000);
        let rsp = Value::reg("rsp", Ty::i64());
        // [0x30..0x38) via qword store vs [0x34..0x38) via dword store.
        for (off, size) in [(0x30i64, 8u32), (0x34, 4)] {
            let t = func.alloc_var(Ty::i64());
            func.push_inst(
                func.entry_block,
                IrInst::Binary {
                    dst: t.clone(),
                    op: OpCode::Add,
                    lhs: rsp.clone(),
                    rhs: Value::Const(off),
                },
            );
            func.push_inst(
                func.entry_block,
                IrInst::Store {
                    addr: t,
                    value: Value::int(1),
                    size,
                },
            );
        }
        assert!(recover_stack_vars(&mut func).is_empty());
    }

    /// `sub rsp, 0x38` prologue: `[rsp+0x68]` is entry-relative `qword_30`,
    /// matching typical MSVC spill code after a frame allocation.
    #[test]
    fn test_offsets_shift_with_rsp_updates() {
        let mut func = IrFunction::new("msvcish", 0x1000);
        let rsp = Value::reg("rsp", Ty::i64());
        let entry = func.entry_block;

        let tmp = func.alloc_var(Ty::i64());
        func.push_inst(
            entry,
            IrInst::Binary {
                dst: tmp.clone(),
                op: OpCode::Sub,
                lhs: rsp.clone(),
                rhs: Value::Const(0x38),
            },
        );
        func.push_inst(
            entry,
            IrInst::Unary {
                dst: rsp.clone(),
                op: OpCode::Copy,
                src: tmp,
            },
        );

        let t = func.alloc_var(Ty::i64());
        func.push_inst(
            entry,
            IrInst::Binary {
                dst: t.clone(),
                op: OpCode::Add,
                lhs: rsp.clone(),
                rhs: Value::Const(0x68),
            },
        );
        func.push_inst(
            entry,
            IrInst::Store {
                addr: t,
                value: Value::reg("rcx", Ty::i64()),
                size: 8,
            },
        );
        func.push_inst(entry, IrInst::Return { value: None });

        let names = recover_stack_vars(&mut func);
        let recovered: Vec<_> = names.values().map(|v| v.name.as_str()).collect();
        assert_eq!(recovered, ["qword_30"]);
        assert_eq!(counts(&func).0 + counts(&func).1, 0);

        let mut ast = crate::ir_to_ast::ir_to_ast(&func);
        crate::stack_vars::apply_recovered_names(&mut ast, &names);
        let c = crate::ast_to_c::ast_to_c(&ast);
        assert!(c.contains("qword_30 = rcx"), "{}", c);
    }

    /// Two paths reaching one block with different rsp deltas must abort.
    #[test]
    fn test_bails_when_paths_disagree_on_delta() {
        let mut func = IrFunction::new("mismatch", 0x1000);
        let rsp = Value::reg("rsp", Ty::i64());
        let cond = func.alloc_var(Ty::Bool);
        let then_b = func.add_block("then");
        let merge = func.add_block("merge");

        func.push_inst(
            func.entry_block,
            IrInst::CBranch {
                cond,
                target_true: then_b,
                target_false: merge,
            },
        );
        // then: add rsp, 8
        let tmp = func.alloc_var(Ty::i64());
        func.push_inst(
            then_b,
            IrInst::Binary {
                dst: tmp.clone(),
                op: OpCode::Add,
                lhs: rsp.clone(),
                rhs: Value::Const(8),
            },
        );
        func.push_inst(
            then_b,
            IrInst::Unary {
                dst: rsp.clone(),
                op: OpCode::Copy,
                src: tmp,
            },
        );
        func.push_inst(then_b, IrInst::Branch { target: merge });
        // merge: store [rsp+0x10]
        let t = func.alloc_var(Ty::i64());
        func.push_inst(
            merge,
            IrInst::Binary {
                dst: t.clone(),
                op: OpCode::Add,
                lhs: rsp.clone(),
                rhs: Value::Const(0x10),
            },
        );
        func.push_inst(
            merge,
            IrInst::Store {
                addr: t,
                value: Value::int(1),
                size: 8,
            },
        );
        func.push_inst(merge, IrInst::Return { value: None });

        let before = func.display();
        assert!(recover_stack_vars(&mut func).is_empty());
        assert_eq!(before, func.display());
    }

    #[test]
    fn test_negative_offset_naming() {
        use freakre_ir::Ty;
        // Positive offsets (locals)
        assert_eq!(slot_name(0, &Ty::u64()), "qword_0");
        assert_eq!(slot_name(0x40, &Ty::u64()), "qword_40");
        assert_eq!(slot_name(0x20, &Ty::u32()), "dword_20");
        assert_eq!(slot_name(0x10, &Ty::u16()), "word_10");
        assert_eq!(slot_name(0x08, &Ty::u8()), "byte_8");

        // Negative offsets (arguments)
        assert_eq!(slot_name(-8, &Ty::u64()), "arg_8");
        assert_eq!(slot_name(-0x10, &Ty::u64()), "arg_10");
        assert_eq!(slot_name(-0x20, &Ty::Ptr(Box::new(Ty::u8()))), "arg_ptr_20");

        // Pointer types
        assert_eq!(slot_name(0x30, &Ty::Ptr(Box::new(Ty::u8()))), "ptr_30");
    }

    #[test]
    #[ignore]
    fn dbg_dump_real_ir() {
        let path = r"C:\Users\DD7D~1\AppData\Local\Temp\opencode\sample_frozen.exe";
        let off_hex = std::env::var("DBG_OFF").unwrap_or_else(|_| "2E00".into());
        let offset = usize::from_str_radix(&off_hex, 16).unwrap();
        let data = std::fs::read(path).expect("read");
        let pe = pe_parser::PeFile::parse(&data).expect("pe");
        let text = pe
            .sections
            .iter()
            .find(|s| s.name_string() == ".text")
            .expect(".text");
        let raw = text.raw_data(&data);
        let mut off = offset.saturating_sub(text.raw_data_offset as usize);
        let prologues: [&[u8]; 4] = [
            &[0x48, 0x89, 0x5C, 0x24],
            &[0x48, 0x89, 0x4C, 0x24],
            &[0x40, 0x53],
            &[0x48, 0x83, 0xEC],
        ];
        let orig = off;
        'found: while off < raw.len() {
            for p in prologues {
                if raw[off..].starts_with(p) {
                    break 'found;
                }
            }
            off += 1;
            if off > orig + 0x40000 {
                break 'found;
            }
        }
        let code = &raw[off..];
        let lifter = X86Lifter::new(true);
        let func = lifter
            .lift_function(code, 0x140001000u64, "dbg")
            .expect("lift");
        eprintln!("=== RAW IR @ {:#x} ===\n{}", offset, func.display());
    }

    /// Debug/integration check against the real x86 lifter: dumps the lifted
    /// IR shape (run with `-- --nocapture`) and verifies recovery on it,
    /// including the end-to-end pipeline on a fresh lift.
    #[test]
    fn test_lifted_x86_stack_accesses() {
        // mov [rsp+0x38], rbx ; mov rbx, [rsp+0x38] ; mov rax, [rsp+0x70] ; ret
        let code = [
            0x48, 0x89, 0x5C, 0x24, 0x38, 0x48, 0x8B, 0x5C, 0x24, 0x38, 0x48, 0x8B, 0x44, 0x24,
            0x70, 0xC3,
        ];
        let lifter = X86Lifter::new(true);

        // First lift: dump the raw IR shape and recover in place.
        let mut func = lifter
            .lift_function(&code, 0x140001000, "shape")
            .expect("lift");
        eprintln!("=== lifted IR ===\n{}", func.display());
        let names = recover_stack_vars(&mut func);
        eprintln!("=== recovered: {:?} ===", names);

        let recovered: Vec<&str> = names.values().map(|v| v.name.as_str()).collect();
        assert!(recovered.contains(&"qword_38"), "{:?}", recovered);
        assert!(recovered.contains(&"qword_70"), "{:?}", recovered);
        // The lifter's `ret` reads its return address from bare [rsp].
        assert!(recovered.contains(&"qword_0"), "{:?}", recovered);
        assert_eq!((counts(&func).0, counts(&func).1), (0, 0));

        // Second lift through the full pipeline. The [rsp+0x38] spill and
        // its immediate reload are legitimately folded into one variable
        // (or dropped as redundant) by later passes; what matters is that
        // no raw stack derefs remain and recovered names appear.
        let fresh = lifter
            .lift_function(&code, 0x140001000, "shape")
            .expect("lift");
        let c = crate::decompile_function(&fresh).unwrap();
        eprintln!("=== decompiled ===\n{}", c);
        assert!(!c.contains("*(rsp"), "{}", c);
        assert!(c.contains("qword_70"), "{}", c);
    }
}
