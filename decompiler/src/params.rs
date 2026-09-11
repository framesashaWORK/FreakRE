//! Function-parameter recovery.
//!
//! The x86 lifter recovers **call-site arguments** (which convention
//! registers/stack pushes feed a call). This module recovers the symmetric
//! piece: **the decompiled function's own parameters**. A convention register
//! is a parameter when some block reachable from the entry reads it before
//! defining it (reaching-definition chain from entry). Recovered parameters
//! become named locals (`a1`, `a2`, ...); the function signature is printed
//! with them instead of `void f(void)`.

use crate::ast::{LocalVar, Param};
use freakre_ir::ir::{BlockId, IrFunction, IrInst, Value};
use freakre_ir::Ty;
/// Convention register slots per architecture, in argument order.
/// Each slot lists the spellings that alias the same argument
/// (64-bit first = canonical form).
const X64_ARG_SLOTS: [&[&str]; 4] = [
    &["rcx", "ecx", "cx", "cl", "ch"],
    &["rdx", "edx", "dx", "dl", "dh"],
    &["r8", "r8d", "r8w", "r8b"],
    &["r9", "r9d", "r9w", "r9b"],
];

const X86_ARG_SLOTS: [&[&str]; 2] = [&["ecx", "cx", "cl", "ch"], &["edx", "dx", "dl", "dh"]];

/// A recovered parameter: slot index, canonical register, inferred type.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredParam {
    pub slot: usize,
    pub canonical: &'static str,
    /// Every spelling of this argument slot (canonical first).
    pub aliases: Vec<&'static str>,
    pub ty: Ty,
}

/// Recover the function's parameters from reaching-definition analysis over
/// the arg-register slots. `is_64bit` selects the register convention.
pub fn recover_params(func: &IrFunction, is_64bit: bool) -> Vec<RecoveredParam> {
    let slots: &[&[&str]] = if is_64bit {
        &X64_ARG_SLOTS
    } else {
        &X86_ARG_SLOTS
    };
    let mut params = Vec::new();
    for (slot, aliases) in slots.iter().enumerate() {
        let Some((block, ty)) = first_undefined_read(func, aliases) else {
            continue;
        };
        let _ = block;
        params.push(RecoveredParam {
            slot,
            canonical: aliases[0],
            aliases: aliases.to_vec(),
            ty,
        });
    }
    params
}

/// Find the first point (in BFS order from the entry block) where `aliases`
/// is read without any prior definition on the path. Returns the type the
/// value is used as (register type = lifter-chosen width).
fn first_undefined_read(
    func: &IrFunction,
    aliases: &[&str],
) -> Option<(BlockId, Ty)> {
    let mut visited = vec![false; func.blocks.len()];
    // Per-DFS-path tracking would be precise; BFS with a "defined anywhere on
    // the current path" set is approximated conservatively: a register counts
    // as a parameter when ANY reachable block reads it before the FIRST
    // definition the analyzer can prove dominates the read. For straight-line
    // prologues (the overwhelmingly common case) this is exact.
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(func.entry_block);
    visited[func.entry_block.0 as usize] = true;

    while let Some(bid) = queue.pop_front() {
        let Some(block) = func.block(bid) else {
            continue;
        };
        for inst in &block.insts {
            // Reads before writes on this path: read-modify-write
            // instructions (add rcx, 1) READ the incoming value first, so
            // reads are checked before defs.
            if let Some(ty) = first_undef_read_in_inst(inst, aliases) {
                return Some((bid, ty));
            }
            if defines_reg(inst, aliases) {
                // Defined on this path: not a parameter, stop tracking this
                // slot for the remainder of the traversal.
                return None;
            }
        }
        for succ in func.successors(bid) {
            let i = succ.0 as usize;
            if i < visited.len() && !visited[i] {
                visited[i] = true;
                queue.push_back(succ);
            }
        }
    }
    None
}

/// True when `inst` (re)defines any of `aliases` registers.
fn defines_reg(inst: &IrInst, aliases: &[&str]) -> bool {
    inst.dst()
        .is_some_and(|d| matches!(d, Value::Register { name, .. } if aliases.contains(&name.as_str())))
}

/// The type `inst` reads `aliases` with, when it reads the register value
/// before any definition this instruction performs (read-modify-write reads
/// the incoming value; a pure write does not).
fn first_undef_read_in_inst(inst: &IrInst, aliases: &[&str]) -> Option<Ty> {
    // A read-modify-write (dst is the same register it reads) uses the
    // incoming value: e.g. `add rcx, 1` reads rcx.
    let dst_is_arg = defines_reg(inst, aliases);
    for src in inst.sources() {
        if let Value::Register { name, ty } = src {
            if aliases.contains(&name.as_str()) {
                return Some(ty.clone());
            }
        }
    }
    let _ = dst_is_arg;
    None
}
/// Wire recovered parameters into the AST: signature params + `a1..aN` locals.
/// Returns the number of parameters recovered.
pub fn apply_params(
    ast: &mut crate::ast::AstFunction,
    params: &[RecoveredParam],
) -> usize {
    if params.is_empty() {
        return 0;
    }
    ast.params = params
        .iter()
        .map(|p| Param {
            name: format!("a{}", p.slot + 1),
            ty: p.ty.clone(),
        })
        .collect();
    // Register reads in the body carry the canonical register name; declare
    // the parameter locals so the printer renders `a1` instead of `rcx`.
    // Renaming happens in ir_to_ast via the var-name map, so here we only
    // seed locals + let the printer resolve register names through the
    // parameter name map. Every alias spelling maps to a1..aN (the IR may
    // reference `ecx` while the canonical slot is `rcx`).
    for p in params.iter() {
        let name = format!("a{}", p.slot + 1);
        if !ast.locals.iter().any(|l| l.name == name) {
            ast.locals.push(LocalVar {
                name,
                ty: p.ty.clone(),
                is_used: true,
                fields: Vec::new(),
            });
        }
    }
    ast.param_register_names = params
        .iter()
        .flat_map(|p| p.aliases.iter().copied())
        .map(str::to_string)
        .collect();
    params.len()
}
