//! Expression simplification pass for decompiled AST.
//!
//! Applies algebraic identities, constant folding, dead assignment elimination,
//! copy propagation, and condition merging to produce cleaner pseudocode.

use crate::ast::*;
use std::collections::{HashMap, HashSet};

/// Run all simplification passes on an AST function (in-place).
pub fn simplify_function(func: &mut AstFunction) {
    // Pass 0: strip prologue/epilogue noise (rsp adjustments, frame-setup
    // copies) and dead `flag_*` assignments before they can feed copy
    // propagation.
    strip_stack_noise(&mut func.body);
    strip_dead_flag_assignments(&mut func.body);

    // Pass 1: Constant folding + algebraic identities (bottom-up on expressions)
    simplify_stmts(&mut func.body);

    // Pass 2: Dead assignment elimination
    eliminate_dead_assignments(&mut func.body);

    // Pass 3: Copy propagation (single-use variables)
    propagate_copies(&mut func.body);

    // Pass 4: Condition merging (nested if without else)
    merge_conditions(&mut func.body);

    // Pass 5: Second round of constant folding after propagation
    simplify_stmts(&mut func.body);

    // Pass 6: Final cleanup — copy propagation may turn `rsp = v12` copies
    // into plain `rsp = rsp - 8` adjustments, and pattern transforms may
    // surface further dead flag assignments.
    strip_stack_noise(&mut func.body);
    strip_dead_flag_assignments(&mut func.body);
}

// в”Ђв”Ђв”Ђ Prologue / Epilogue Noise Removal в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn is_stack_reg(name: &str) -> bool {
    name == "rsp" || name == "esp"
}

/// Stack-pointer adjustments (`rsp = rsp ± N`) and frame-setup copies
/// (`rbp = rsp`, `rsp = rbp`) carry no meaning in pseudocode. Stores THROUGH
/// rsp/rbp pointers are untouched, as are dynamic adjustments
/// (`rsp = rsp + rcx`).
fn is_stack_noise(target: &Expr, value: &Expr) -> bool {
    match target {
        Expr::Var(name) if is_stack_reg(name) => match value {
            Expr::Var(n) if n == "rbp" => true,
            Expr::Binary { op: bin_op @ (BinOp::Add | BinOp::Sub), lhs, rhs } => {
                let sp_base = |e: &Expr| matches!(e, Expr::Var(n) if is_stack_reg(n));
                (sp_base(lhs) && matches!(rhs.as_ref(), Expr::IntLit(_)))
                    || (*bin_op == BinOp::Add
                        && sp_base(rhs)
                        && matches!(lhs.as_ref(), Expr::IntLit(_)))
            }
            _ => false,
        },
        Expr::Var(name) if name == "rbp" => {
            matches!(value, Expr::Var(n) if is_stack_reg(n))
        }
        _ => false,
    }
}

fn strip_stack_noise(stmts: &mut Vec<Stmt>) {
    stmts.retain(|stmt| !matches!(
        stmt,
        Stmt::Assign { target, value } if is_stack_noise(target, value)
    ));

    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If { then_body, else_body, .. } => {
                strip_stack_noise(then_body);
                if let Some(eb) = else_body { strip_stack_noise(eb); }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                strip_stack_noise(body);
            }
            Stmt::For { init, update, body, .. } => {
                if let Some(i) = init { strip_single(i.as_mut()); }
                if let Some(u) = update { strip_single(u.as_mut()); }
                strip_stack_noise(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() { strip_stack_noise(&mut c.body); }
                if let Some(d) = default { strip_stack_noise(d); }
            }
            Stmt::Block(inner) => { strip_stack_noise(inner); }
            Stmt::TryCatch { try_body, catch_body, .. } => {
                strip_stack_noise(try_body);
                strip_stack_noise(catch_body);
            }
            _ => {}
        }
    }
}

/// Strip noise from a single statement (a `for` init/update slot) that is not
/// itself a list: routed through a temporary list so removal still works.
fn strip_single(stmt: &mut Stmt) {
    let mut tmp = vec![std::mem::replace(stmt, Stmt::Empty)];
    strip_stack_noise(&mut tmp);
    *stmt = tmp.into_iter().next().unwrap_or(Stmt::Empty);
}

/// Belt-and-suspenders: drop assignments to `flag_*` variables that survived
/// IR-level cleanup and are no longer read anywhere.
fn strip_dead_flag_assignments(stmts: &mut Vec<Stmt>) {
    let mut used_vars = HashSet::new();
    collect_used_vars_stmts(stmts, &mut used_vars);
    strip_dead_flag_assignments_inner(stmts, &used_vars);
}

fn strip_dead_flag_assignments_inner(stmts: &mut Vec<Stmt>, used_vars: &HashSet<String>) {
    stmts.retain(|stmt| !matches!(
        stmt,
        Stmt::Assign { target: Expr::Var(name), .. }
            if name.starts_with("flag_") && !used_vars.contains(name)
    ));

    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If { then_body, else_body, .. } => {
                strip_dead_flag_assignments_inner(then_body, used_vars);
                if let Some(eb) = else_body { strip_dead_flag_assignments_inner(eb, used_vars); }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                strip_dead_flag_assignments_inner(body, used_vars);
            }
            Stmt::For { body, .. } => { strip_dead_flag_assignments_inner(body, used_vars); }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() { strip_dead_flag_assignments_inner(&mut c.body, used_vars); }
                if let Some(d) = default { strip_dead_flag_assignments_inner(d, used_vars); }
            }
            Stmt::Block(inner) => { strip_dead_flag_assignments_inner(inner, used_vars); }
            Stmt::TryCatch { try_body, catch_body, .. } => {
                strip_dead_flag_assignments_inner(try_body, used_vars);
                strip_dead_flag_assignments_inner(catch_body, used_vars);
            }
            _ => {}
        }
    }
}

// в”Ђв”Ђв”Ђ Expression Simplification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn simplify_expr(expr: &Expr) -> Expr {
    match expr {
        // в”Ђв”Ђ Binary operations в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Binary { op, lhs, rhs } => {
            let l = simplify_expr(lhs);
            let r = simplify_expr(rhs);

            // Constant folding
            if let (Expr::IntLit(a), Expr::IntLit(b)) = (&l, &r) {
                if let Some(val) = eval_const_binop(*op, *a, *b) {
                    return Expr::IntLit(val);
                }
            }

            // Bool constant folding
            if let (Expr::BoolLit(a), Expr::BoolLit(b)) = (&l, &r) {
                return match op {
                    BinOp::LogAnd => Expr::BoolLit(*a && *b),
                    BinOp::LogOr => Expr::BoolLit(*a || *b),
                    BinOp::Eq => Expr::BoolLit(a == b),
                    BinOp::Ne => Expr::BoolLit(a != b),
                    _ => Expr::Binary { op: *op, lhs: Box::new(l), rhs: Box::new(r) },
                };
            }

            // Identity: x + 0, x - 0, x | 0, x ^ 0, x << 0, x >> 0
            if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr)
                && is_zero(&r)
            {
                return l;
            }
            // Identity: 0 + x
            if matches!(op, BinOp::Add | BinOp::Or | BinOp::Xor) && is_zero(&l) {
                return r;
            }

            // Identity: x * 1, x / 1
            if matches!(op, BinOp::Mul | BinOp::Div) && is_one(&r) {
                return l;
            }
            // Identity: 1 * x
            if matches!(op, BinOp::Mul) && is_one(&l) {
                return r;
            }

            // Annihilator: x * 0 в†’ 0, x & 0 в†’ 0
            if matches!(op, BinOp::Mul | BinOp::And) && is_zero(&r) && is_pure(&l) {
                return Expr::IntLit(0);
            }
            if matches!(op, BinOp::Mul) && is_zero(&l) && is_pure(&r) {
                return Expr::IntLit(0);
            }

            // Self-cancel: x ^ x в†’ 0, x - x в†’ 0
            if matches!(op, BinOp::Xor | BinOp::Sub) && l == r && is_pure(&l) {
                return Expr::IntLit(0);
            }

            // Self: x & x в†’ x, x | x в†’ x
            if matches!(op, BinOp::And | BinOp::Or) && l == r && is_pure(&l) {
                return l;
            }

            // Comparison self: x == x в†’ true, x != x в†’ false
            if *op == BinOp::Eq && l == r && is_pure(&l) {
                return Expr::BoolLit(true);
            }
            if *op == BinOp::Ne && l == r && is_pure(&l) {
                return Expr::BoolLit(false);
            }

            // Bitwise mask simplification: (x & 0xFF) в†’ cast to u8 conceptually
            // We keep it as-is but note for type inference

            // Shift+mask: (x >> n) & ((1 << m) - 1) вЂ” bitfield extract
            // Left as-is for now (requires type info)

            Expr::Binary { op: *op, lhs: Box::new(l), rhs: Box::new(r) }
        }

        // в”Ђв”Ђ Unary operations в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Unary { op, operand } => {
            let inner = simplify_expr(operand);

            // Constant folding
            if let Expr::IntLit(v) = &inner {
                match op {
                    UnOp::Neg => return Expr::IntLit(v.wrapping_neg()),
                    UnOp::Not => return Expr::IntLit(!v),
                    UnOp::LogNot => return Expr::BoolLit(*v == 0),
                    _ => {}
                }
            }
            if let Expr::BoolLit(b) = &inner {
                if *op == UnOp::LogNot {
                    return Expr::BoolLit(!b);
                }
            }

            // Double negation: ~~x в†’ x
            if *op == UnOp::Not {
                if let Expr::Unary { op: UnOp::Not, operand: inner2 } = &inner {
                    return (**inner2).clone();
                }
            }
            // Double logical not: !!x в†’ x (semantically for bools)
            if *op == UnOp::LogNot {
                if let Expr::Unary { op: UnOp::LogNot, operand: inner2 } = &inner {
                    return (**inner2).clone();
                }
            }

            // !(a == b) -> a != b and friends: decompilers emit !(cmp) from
            // inverted branches; negating the comparison reads much better.
            if *op == UnOp::LogNot {
                if let Expr::Binary { op: bop, lhs, rhs } = &inner {
                    let negated = match bop {
                        BinOp::Eq => Some(BinOp::Ne),
                        BinOp::Ne => Some(BinOp::Eq),
                        BinOp::LtU => Some(BinOp::GeU),
                        BinOp::LeU => Some(BinOp::GtU),
                        BinOp::GtU => Some(BinOp::LeU),
                        BinOp::GeU => Some(BinOp::LtU),
                        BinOp::Lt => Some(BinOp::Ge),
                        BinOp::Le => Some(BinOp::Gt),
                        BinOp::Gt => Some(BinOp::Le),
                        BinOp::Ge => Some(BinOp::Lt),
                        _ => None,
                    };
                    if let Some(neg) = negated {
                        return Expr::Binary { op: neg, lhs: lhs.clone(), rhs: rhs.clone() };
                    }
                }
            }

            Expr::Unary { op: *op, operand: Box::new(inner) }
        }

        // в”Ђв”Ђ Cast simplification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Cast { ty, expr } => {
            let inner = simplify_expr(expr);
            // Redundant cast: (T)(T)x в†’ (T)x вЂ” would need type equality check
            // For now just recurse
            Expr::Cast { ty: ty.clone(), expr: Box::new(inner) }
        }

        // в”Ђв”Ђ Ternary simplification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Ternary { cond, then_expr, else_expr } => {
            let c = simplify_expr(cond);
            let t = simplify_expr(then_expr);
            let e = simplify_expr(else_expr);

            // Constant condition
            if let Expr::BoolLit(b) = &c {
                return if *b { t } else { e };
            }

            Expr::Ternary {
                cond: Box::new(c),
                then_expr: Box::new(t),
                else_expr: Box::new(e),
            }
        }

        // в”Ђв”Ђ Recursive descent for compound expressions в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Call { func, args } => {
            let new_args: Vec<Expr> = args.iter().map(simplify_expr).collect();
            Expr::Call { func: func.clone(), args: new_args }
        }
        Expr::Index { base, index } => Expr::Index {
            base: Box::new(simplify_expr(base)),
            index: Box::new(simplify_expr(index)),
        },
        Expr::Member { base, field } => Expr::Member {
            base: Box::new(simplify_expr(base)),
            field: field.clone(),
        },
        Expr::Deref(inner) => Expr::Deref(Box::new(simplify_expr(inner))),
        Expr::AddrOf(inner) => Expr::AddrOf(Box::new(simplify_expr(inner))),
        Expr::Sizeof(inner) => Expr::Sizeof(Box::new(simplify_expr(inner))),

        // Leaves вЂ” no simplification
        other => other.clone(),
    }
}

fn eval_const_binop(op: BinOp, a: i64, b: i64) -> Option<i64> {
    match op {
        BinOp::Add => Some(a.wrapping_add(b)),
        BinOp::Sub => Some(a.wrapping_sub(b)),
        BinOp::Mul => Some(a.wrapping_mul(b)),
        BinOp::Div if b != 0 => Some(a.wrapping_div(b)),
        BinOp::Mod if b != 0 => Some(a.wrapping_rem(b)),
        BinOp::And => Some(a & b),
        BinOp::Or => Some(a | b),
        BinOp::Xor => Some(a ^ b),
        BinOp::Shl if (0..64).contains(&b) => Some(a.wrapping_shl(b as u32)),
        BinOp::Shr if (0..64).contains(&b) => Some((a as u64).wrapping_shr(b as u32) as i64),
        BinOp::Eq => Some(if a == b { 1 } else { 0 }),
        BinOp::Ne => Some(if a != b { 1 } else { 0 }),
        BinOp::Lt => Some(if a < b { 1 } else { 0 }),
        BinOp::Le => Some(if a <= b { 1 } else { 0 }),
        BinOp::Gt => Some(if a > b { 1 } else { 0 }),
        BinOp::Ge => Some(if a >= b { 1 } else { 0 }),
        _ => None,
    }
}

fn is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::IntLit(0))
}

fn is_one(expr: &Expr) -> bool {
    matches!(expr, Expr::IntLit(1))
}

/// An expression is pure if evaluating it has no side effects
/// (no calls, no memory reads).
fn is_pure(expr: &Expr) -> bool {
    match expr {
        Expr::Call { .. } | Expr::Deref(_) => false,
        Expr::Binary { lhs, rhs, .. } => is_pure(lhs) && is_pure(rhs),
        Expr::Unary { operand, .. } => is_pure(operand),
        Expr::Cast { expr, .. } | Expr::AddrOf(expr) | Expr::Sizeof(expr) => is_pure(expr),
        Expr::Index { base, index } => is_pure(base) && is_pure(index),
        Expr::Member { base, .. } => is_pure(base),
        Expr::Ternary { cond, then_expr, else_expr } => {
            is_pure(cond) && is_pure(then_expr) && is_pure(else_expr)
        }
        _ => true,
    }
}

// в”Ђв”Ђв”Ђ Statement-level simplification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn simplify_stmts(stmts: &mut [Stmt]) {
    for stmt in stmts.iter_mut() {
        simplify_stmt(stmt);
    }
}

fn simplify_stmt(stmt: &mut Stmt) {
    match stmt {
        Stmt::Assign { target, value } => {
            *target = simplify_expr(target);
            *value = simplify_expr(value);
        }
        Stmt::If { cond, then_body, else_body } => {
            *cond = simplify_expr(cond);
            simplify_stmts(then_body);
            if let Some(eb) = else_body {
                simplify_stmts(eb);
            }
        }
        Stmt::While { cond, body } => {
            *cond = simplify_expr(cond);
            simplify_stmts(body);
        }
        Stmt::For { init, cond, update, body } => {
            if let Some(i) = init { simplify_stmt(i); }
            if let Some(c) = cond { *c = simplify_expr(c); }
            if let Some(u) = update { simplify_stmt(u); }
            simplify_stmts(body);
        }
        Stmt::DoWhile { body, cond } => {
            simplify_stmts(body);
            *cond = simplify_expr(cond);
        }
        Stmt::Switch { expr, cases, default } => {
            *expr = simplify_expr(expr);
            for case in cases.iter_mut() {
                case.value = simplify_expr(&case.value);
                simplify_stmts(&mut case.body);
            }
            if let Some(d) = default { simplify_stmts(d); }
        }
        Stmt::Return { value: Some(v) } => { *v = simplify_expr(v); }
        Stmt::Call { args, .. } => {
            for a in args.iter_mut() { *a = simplify_expr(a); }
        }
        Stmt::Expr(e) => { *e = simplify_expr(e); }
        Stmt::Block(inner) => { simplify_stmts(inner); }
        Stmt::Decl { init: Some(e), .. } => { *e = simplify_expr(e); }
        Stmt::TryCatch { try_body, catch_body, .. } => {
            simplify_stmts(try_body);
            simplify_stmts(catch_body);
        }
        _ => {}
    }
}

// в”Ђв”Ђв”Ђ Dead Assignment Elimination в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Remove assignments whose targets are never read afterwards.
fn eliminate_dead_assignments(stmts: &mut Vec<Stmt>) {
    // Collect all variable reads
    let mut used_vars = HashSet::new();
    collect_used_vars_stmts(stmts, &mut used_vars);

    // Also mark function params and return values as "used"
    // (they're external interfaces)

    // Remove dead assignments (iterate until stable)
    let mut changed = true;
    while changed {
        changed = false;
        let before = stmts.len();
        remove_dead_stmts(stmts, &used_vars);
        if stmts.len() != before {
            changed = true;
            // Recompute used vars after removal
            used_vars.clear();
            collect_used_vars_stmts(stmts, &mut used_vars);
        }
    }
}

/// True when evaluating `expr` may have side effects. Statements whose
/// right-hand side contains a call must survive dead-store elimination even
/// when their target is never read: `v3 = f();` still performs the call.
fn expr_may_side_effect(expr: &Expr) -> bool {
    match expr {
        Expr::Call { .. } => true,
        Expr::Binary { lhs, rhs, .. } => {
            expr_may_side_effect(lhs) || expr_may_side_effect(rhs)
        }
        Expr::Unary { operand, .. }
        | Expr::Deref(operand)
        | Expr::AddrOf(operand)
        | Expr::Sizeof(operand) => expr_may_side_effect(operand),
        Expr::Index { base, index } => {
            expr_may_side_effect(base) || expr_may_side_effect(index)
        }
        Expr::Member { base, .. } => expr_may_side_effect(base),
        Expr::Cast { expr, .. } => expr_may_side_effect(expr),
        Expr::Ternary { cond, then_expr, else_expr } => {
            expr_may_side_effect(cond)
                || expr_may_side_effect(then_expr)
                || expr_may_side_effect(else_expr)
        }
        _ => false,
    }
}

/// True when `expr` reads the variable `name`.
fn expr_references_var(expr: &Expr, name: &str) -> bool {
    let mut reads = HashSet::new();
    collect_used_vars_expr(expr, &mut reads);
    reads.contains(name)
}

fn remove_dead_stmts(stmts: &mut Vec<Stmt>, used_vars: &HashSet<String>) {
    stmts.retain(|stmt| {
        match stmt {
            Stmt::Assign { target: Expr::Var(name), value } => {
                // Keep if target variable is used somewhere, or if evaluating
                // the RHS has side effects (calls must not be deleted).
                used_vars.contains(name) || expr_may_side_effect(value)
            }
            Stmt::Decl { name, init, .. } => {
                used_vars.contains(name)
                    || init.as_ref().is_some_and(|e| expr_may_side_effect(e))
            }
            _ => true,
        }
    });

    // Recurse into nested blocks
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If { then_body, else_body, .. } => {
                remove_dead_stmts(then_body, used_vars);
                if let Some(eb) = else_body { remove_dead_stmts(eb, used_vars); }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                remove_dead_stmts(body, used_vars);
            }
            Stmt::For { body, .. } => { remove_dead_stmts(body, used_vars); }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() { remove_dead_stmts(&mut c.body, used_vars); }
                if let Some(d) = default { remove_dead_stmts(d, used_vars); }
            }
            Stmt::Block(inner) => { remove_dead_stmts(inner, used_vars); }
            Stmt::TryCatch { try_body, catch_body, .. } => {
                remove_dead_stmts(try_body, used_vars);
                remove_dead_stmts(catch_body, used_vars);
            }
            _ => {}
        }
    }
}

fn collect_used_vars_stmts(stmts: &[Stmt], out: &mut HashSet<String>) {
    for stmt in stmts {
        collect_used_vars_stmt(stmt, out);
    }
}

fn collect_used_vars_stmt(stmt: &Stmt, out: &mut HashSet<String>) {
    match stmt {
        Stmt::Assign { target, value } => {
            if !matches!(target, Expr::Var(_)) {
                collect_used_vars_expr(target, out);
            }
            collect_used_vars_expr(value, out);
        }
        Stmt::If { cond, then_body, else_body } => {
            collect_used_vars_expr(cond, out);
            collect_used_vars_stmts(then_body, out);
            if let Some(eb) = else_body { collect_used_vars_stmts(eb, out); }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            collect_used_vars_expr(cond, out);
            collect_used_vars_stmts(body, out);
        }
        Stmt::For { init, cond, update, body } => {
            if let Some(i) = init { collect_used_vars_stmt(i, out); }
            if let Some(c) = cond { collect_used_vars_expr(c, out); }
            if let Some(u) = update { collect_used_vars_stmt(u, out); }
            collect_used_vars_stmts(body, out);
        }
        Stmt::Switch { expr, cases, default } => {
            collect_used_vars_expr(expr, out);
            for c in cases { collect_used_vars_stmts(&c.body, out); }
            if let Some(d) = default { collect_used_vars_stmts(d, out); }
        }
        Stmt::Return { value: Some(v) } => { collect_used_vars_expr(v, out); }
        Stmt::Call { args, .. } => { for a in args { collect_used_vars_expr(a, out); } }
        Stmt::Expr(e) => { collect_used_vars_expr(e, out); }
        Stmt::Block(inner) => { collect_used_vars_stmts(inner, out); }
        Stmt::Decl { init: Some(e), .. } => { collect_used_vars_expr(e, out); }
        Stmt::TryCatch { try_body, catch_body, .. } => {
            collect_used_vars_stmts(try_body, out);
            collect_used_vars_stmts(catch_body, out);
        }
        _ => {}
    }
}

fn collect_used_vars_expr(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Var(name) => { out.insert(name.clone()); }
        Expr::Binary { lhs, rhs, .. } => {
            collect_used_vars_expr(lhs, out);
            collect_used_vars_expr(rhs, out);
        }
        Expr::Unary { operand, .. } => { collect_used_vars_expr(operand, out); }
        Expr::Call { args, .. } => { for a in args { collect_used_vars_expr(a, out); } }
        Expr::Index { base, index } => {
            collect_used_vars_expr(base, out);
            collect_used_vars_expr(index, out);
        }
        Expr::Member { base, .. } => { collect_used_vars_expr(base, out); }
        Expr::Deref(e) | Expr::AddrOf(e) | Expr::Sizeof(e) => { collect_used_vars_expr(e, out); }
        Expr::Cast { expr: e, .. } => { collect_used_vars_expr(e, out); }
        Expr::Ternary { cond, then_expr, else_expr } => {
            collect_used_vars_expr(cond, out);
            collect_used_vars_expr(then_expr, out);
            collect_used_vars_expr(else_expr, out);
        }
        _ => {}
    }
}

// в”Ђв”Ђв”Ђ Copy Propagation в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Inline single-use variables: `x = expr; ... use(x)` в†’ `... use(expr)`.
///
/// A variable is propagated only when ALL of these hold:
/// - exactly ONE definition in the whole function (multi-def variables would
///   otherwise get the wrong value on some paths),
/// - exactly ONE use,
/// - both the definition and the use live in the same statement list, with
///   the definition strictly earlier (never across loop/branch boundaries).
///
/// Literal constants are additionally propagated into nested blocks;
/// variable-to-variable copies never cross block boundaries because the
/// source variable could be re-assigned inside them.
fn propagate_copies(stmts: &mut Vec<Stmt>) {
    let mut def_counts: HashMap<String, usize> = HashMap::new();
    count_var_defs_stmts(stmts, &mut def_counts);
    let mut use_counts: HashMap<String, usize> = HashMap::new();
    count_var_uses_stmts(stmts, &mut use_counts);

    substitute_within_list(stmts, &def_counts, &use_counts, &HashMap::new());

    // Remove now-unused definitions
    let mut used_after = HashSet::new();
    collect_used_vars_stmts(stmts, &mut used_after);
    remove_dead_stmts(stmts, &used_after);
}

fn substitute_within_list(
    stmts: &mut [Stmt],
    def_counts: &HashMap<String, usize>,
    use_counts: &HashMap<String, usize>,
    inherited_literals: &HashMap<String, Expr>,
) {
    // `pending` holds candidates visible to *direct* sub-expressions of
    // following statements at this nesting level.
    let mut pending: HashMap<String, Expr> = inherited_literals.clone();

    for stmt in stmts.iter_mut() {
        // 1. Apply all pending replacements to this statement's own
        //    sub-expressions (not to its child lists).
        apply_pending_to_own_exprs(stmt, &pending);

        // 2. Register new candidate definitions found at this level.
        if let Stmt::Assign { target: Expr::Var(name), value } = stmt {
            if is_inline_candidate(value)
                && !pending.contains_key(name)
                && def_counts.get(name).copied().unwrap_or(0) == 1
                && use_counts.get(name).copied().unwrap_or(0) == 1
            {
                pending.insert(name.clone(), value.clone());
            }
        }

        // 3. Invalidate candidates whose source variable is redefined by this
        //    statement: `v1 = rax; rax = rcx; return v1` must NOT become
        //    `return rcx`. Self-referential candidates registered just above
        //    (`v1 = v1 + 1`) are culled here too — later uses observe the NEW
        //    value, not the expression.
        let redefined = match stmt {
            Stmt::Assign { target: Expr::Var(name), .. } | Stmt::Decl { name, .. } => Some(name),
            _ => None,
        };
        if let Some(def_name) = redefined {
            pending.retain(|_, expr| !expr_references_var(expr, def_name));
        }
    }

    // 3. Recurse into nested lists, carrying only literal constants down.
    let literals: HashMap<String, Expr> = pending
        .into_iter()
        .filter(|(_, v)| matches!(v, Expr::IntLit(_) | Expr::BoolLit(_) | Expr::FloatLit(_) | Expr::StringLit(_)))
        .collect();

    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If { then_body, else_body, .. } => {
                substitute_within_list(then_body, def_counts, use_counts, &literals);
                if let Some(eb) = else_body { substitute_within_list(eb, def_counts, use_counts, &literals); }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                substitute_within_list(body, def_counts, use_counts, &literals);
            }
            Stmt::For { init, update, body, .. } => {
                if let Some(i) = init { substitute_within_list(std::slice::from_mut(i.as_mut()), def_counts, use_counts, &literals); }
                if let Some(u) = update { substitute_within_list(std::slice::from_mut(u.as_mut()), def_counts, use_counts, &literals); }
                substitute_within_list(body, def_counts, use_counts, &literals);
            }
            Stmt::Block(inner) => substitute_within_list(inner, def_counts, use_counts, &literals),
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() { substitute_within_list(&mut c.body, def_counts, use_counts, &literals); }
                if let Some(d) = default { substitute_within_list(d, def_counts, use_counts, &literals); }
            }
            Stmt::TryCatch { try_body, catch_body, .. } => {
                substitute_within_list(try_body, def_counts, use_counts, &literals);
                substitute_within_list(catch_body, def_counts, use_counts, &literals);
            }
            _ => {}
        }
    }
}

/// Substitute pending variables into the statement's own expressions,
/// without descending into nested statement lists.
fn apply_pending_to_own_exprs(stmt: &mut Stmt, pending: &HashMap<String, Expr>) {
    match stmt {
        Stmt::Assign { target, value } => {
            substitute_vars_expr(target, pending);
            substitute_vars_expr(value, pending);
        }
        Stmt::Return { value: Some(v) } => substitute_vars_expr(v, pending),
        Stmt::Call { args, .. } => {
            for a in args.iter_mut() { substitute_vars_expr(a, pending); }
        }
        Stmt::Expr(e) => substitute_vars_expr(e, pending),
        Stmt::Decl { init: Some(e), .. } => substitute_vars_expr(e, pending),
        Stmt::If { cond, .. } => substitute_vars_expr(cond, pending),
        Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => substitute_vars_expr(cond, pending),
        Stmt::For { cond, .. } => {
            if let Some(c) = cond { substitute_vars_expr(c, pending); }
        }
        Stmt::Switch { expr, cases, .. } => {
            substitute_vars_expr(expr, pending);
            for c in cases.iter_mut() { substitute_vars_expr(&mut c.value, pending); }
        }
        _ => {}
    }
}

fn count_var_defs_stmts(stmts: &[Stmt], counts: &mut HashMap<String, usize>) {
    for stmt in stmts {
        count_var_defs_stmt(stmt, counts);
    }
}

fn count_var_defs_stmt(stmt: &Stmt, counts: &mut HashMap<String, usize>) {
    fn bump_target(target: &Expr, counts: &mut HashMap<String, usize>) {
        if let Expr::Var(name) = target {
            *counts.entry(name.clone()).or_insert(0) += 1;
        }
    }
    match stmt {
        Stmt::Assign { target, .. } => bump_target(target, counts),
        Stmt::If { then_body, else_body, .. } => {
            count_var_defs_stmts(then_body, counts);
            if let Some(eb) = else_body { count_var_defs_stmts(eb, counts); }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            count_var_defs_stmts(body, counts);
        }
        Stmt::For { init, update, body, .. } => {
            if let Some(i) = init { count_var_defs_stmt(i, counts); }
            if let Some(u) = update { count_var_defs_stmt(u, counts); }
            count_var_defs_stmts(body, counts);
        }
        Stmt::Block(inner) => count_var_defs_stmts(inner, counts),
        Stmt::Switch { cases, default, .. } => {
            for c in cases { count_var_defs_stmts(&c.body, counts); }
            if let Some(d) = default { count_var_defs_stmts(d, counts); }
        }
        Stmt::TryCatch { try_body, catch_body, .. } => {
            count_var_defs_stmts(try_body, counts);
            count_var_defs_stmts(catch_body, counts);
        }
        _ => {}
    }
}

fn count_var_uses_stmts(stmts: &[Stmt], counts: &mut HashMap<String, usize>) {
    for stmt in stmts {
        count_var_uses_stmt(stmt, counts);
    }
}

fn count_var_uses_stmt(stmt: &Stmt, counts: &mut HashMap<String, usize>) {
    match stmt {
        Stmt::Assign { target, value } => {
            if !matches!(target, Expr::Var(_)) {
                count_var_uses_expr(target, counts);
            }
            count_var_uses_expr(value, counts);
        }
        Stmt::If { cond, then_body, else_body } => {
            count_var_uses_expr(cond, counts);
            count_var_uses_stmts(then_body, counts);
            if let Some(eb) = else_body { count_var_uses_stmts(eb, counts); }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            count_var_uses_expr(cond, counts);
            count_var_uses_stmts(body, counts);
        }
        Stmt::For { init, cond, update, body } => {
            if let Some(i) = init { count_var_uses_stmt(i, counts); }
            if let Some(c) = cond { count_var_uses_expr(c, counts); }
            if let Some(u) = update { count_var_uses_stmt(u, counts); }
            count_var_uses_stmts(body, counts);
        }
        Stmt::Switch { expr, cases, default } => {
            count_var_uses_expr(expr, counts);
            for c in cases { count_var_uses_stmts(&c.body, counts); }
            if let Some(d) = default { count_var_uses_stmts(d, counts); }
        }
        Stmt::Return { value: Some(v) } => { count_var_uses_expr(v, counts); }
        Stmt::Call { args, .. } => { for a in args { count_var_uses_expr(a, counts); } }
        Stmt::Expr(e) => { count_var_uses_expr(e, counts); }
        Stmt::Block(inner) => { count_var_uses_stmts(inner, counts); }
        Stmt::Decl { init: Some(e), .. } => { count_var_uses_expr(e, counts); }
        Stmt::TryCatch { try_body, catch_body, .. } => {
            count_var_uses_stmts(try_body, counts);
            count_var_uses_stmts(catch_body, counts);
        }
        _ => {}
    }
}

fn count_var_uses_expr(expr: &Expr, counts: &mut HashMap<String, usize>) {
    match expr {
        Expr::Var(name) => { *counts.entry(name.clone()).or_insert(0) += 1; }
        Expr::Binary { lhs, rhs, .. } => {
            count_var_uses_expr(lhs, counts);
            count_var_uses_expr(rhs, counts);
        }
        Expr::Unary { operand, .. } => { count_var_uses_expr(operand, counts); }
        Expr::Call { args, .. } => { for a in args { count_var_uses_expr(a, counts); } }
        Expr::Index { base, index } => {
            count_var_uses_expr(base, counts);
            count_var_uses_expr(index, counts);
        }
        Expr::Member { base, .. } => { count_var_uses_expr(base, counts); }
        Expr::Deref(e) | Expr::AddrOf(e) | Expr::Sizeof(e) => { count_var_uses_expr(e, counts); }
        Expr::Cast { expr: e, .. } => { count_var_uses_expr(e, counts); }
        Expr::Ternary { cond, then_expr, else_expr } => {
            count_var_uses_expr(cond, counts);
            count_var_uses_expr(then_expr, counts);
            count_var_uses_expr(else_expr, counts);
        }
        _ => {}
    }
}

/// Check if an expression is simple enough to inline.
fn is_simple_expr(expr: &Expr) -> bool {
    matches!(expr,
        Expr::IntLit(_) | Expr::BoolLit(_) | Expr::StringLit(_) |
        Expr::Var(_) | Expr::FloatLit(_)
    )
}

fn is_pure_leaf_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Var(_)
        | Expr::IntLit(_)
        | Expr::FloatLit(_)
        | Expr::StringLit(_)
        | Expr::BoolLit(_) => true,
        Expr::Binary { lhs, rhs, .. } => is_pure_leaf_expr(lhs) && is_pure_leaf_expr(rhs),
        Expr::Unary { operand, .. } => is_pure_leaf_expr(operand),
        Expr::Cast { expr: e, .. } => is_pure_leaf_expr(e),
        Expr::AddrOf(e) | Expr::Sizeof(e) => is_pure_leaf_expr(e),
        Expr::Call { .. }
        | Expr::Deref(_)
        | Expr::Index { .. }
        | Expr::Member { .. }
        | Expr::Ternary { .. } => false,
    }
}

fn is_inline_candidate(value: &Expr) -> bool {
    is_simple_expr(value) || (matches!(value, Expr::Binary { .. }) && is_pure_leaf_expr(value))
}

fn substitute_vars_expr(expr: &mut Expr, defs: &HashMap<String, Expr>) {
    match expr {
        Expr::Var(name) => {
            if let Some(replacement) = defs.get(name) {
                *expr = replacement.clone();
            }
        }
        Expr::Binary { lhs, rhs, .. } => {
            substitute_vars_expr(lhs, defs);
            substitute_vars_expr(rhs, defs);
        }
        Expr::Unary { operand, .. } => { substitute_vars_expr(operand, defs); }
        Expr::Call { args, .. } => { for a in args.iter_mut() { substitute_vars_expr(a, defs); } }
        Expr::Index { base, index } => {
            substitute_vars_expr(base, defs);
            substitute_vars_expr(index, defs);
        }
        Expr::Member { base, .. } => { substitute_vars_expr(base, defs); }
        Expr::Deref(e) | Expr::AddrOf(e) | Expr::Sizeof(e) => { substitute_vars_expr(e, defs); }
        Expr::Cast { expr: e, .. } => { substitute_vars_expr(e, defs); }
        Expr::Ternary { cond, then_expr, else_expr } => {
            substitute_vars_expr(cond, defs);
            substitute_vars_expr(then_expr, defs);
            substitute_vars_expr(else_expr, defs);
        }
        _ => {}
    }
}

// в”Ђв”Ђв”Ђ Condition Merging в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Merge nested if-without-else: `if (a) { if (b) { ... } }` в†’ `if (a && b) { ... }`
fn merge_conditions(stmts: &mut [Stmt]) {
    for stmt in stmts.iter_mut() {
        merge_conditions_stmt(stmt);
    }
}

fn merge_conditions_stmt(stmt: &mut Stmt) {
    match stmt {
        Stmt::If { cond, then_body, else_body } => {
            // Recurse first
            merge_conditions_stmts(then_body);
            if let Some(eb) = else_body { merge_conditions_stmts(eb); }

            // Merge: if outer has no else, and then_body is a single if with no else
            if else_body.is_none() && then_body.len() == 1 {
                if let Stmt::If {
                    cond: inner_cond,
                    then_body: inner_then,
                    else_body: None,
                } = &then_body[0]
                {
                    let merged_cond = Expr::Binary {
                        op: BinOp::LogAnd,
                        lhs: Box::new(cond.clone()),
                        rhs: Box::new(inner_cond.clone()),
                    };
                    *cond = merged_cond;
                    *then_body = inner_then.clone();
                }
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            merge_conditions_stmts(body);
        }
        Stmt::For { body, .. } => { merge_conditions_stmts(body); }
        Stmt::Block(inner) => { merge_conditions_stmts(inner); }
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() { merge_conditions_stmts(&mut c.body); }
            if let Some(d) = default { merge_conditions_stmts(d); }
        }
        Stmt::TryCatch { try_body, catch_body, .. } => {
            merge_conditions_stmts(try_body);
            merge_conditions_stmts(catch_body);
        }
        _ => {}
    }
}

fn merge_conditions_stmts(stmts: &mut [Stmt]) {
    merge_conditions(stmts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_fold_add() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::IntLit(3)),
            rhs: Box::new(Expr::IntLit(5)),
        };
        assert_eq!(simplify_expr(&expr), Expr::IntLit(8));
    }

    #[test]
    fn test_identity_add_zero() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var("x".into())),
            rhs: Box::new(Expr::IntLit(0)),
        };
        assert_eq!(simplify_expr(&expr), Expr::Var("x".into()));
    }

    #[test]
    fn test_annihilator_mul_zero() {
        let expr = Expr::Binary {
            op: BinOp::Mul,
            lhs: Box::new(Expr::Var("x".into())),
            rhs: Box::new(Expr::IntLit(0)),
        };
        assert_eq!(simplify_expr(&expr), Expr::IntLit(0));
    }

    #[test]
    fn test_self_cancel_xor() {
        let expr = Expr::Binary {
            op: BinOp::Xor,
            lhs: Box::new(Expr::Var("x".into())),
            rhs: Box::new(Expr::Var("x".into())),
        };
        assert_eq!(simplify_expr(&expr), Expr::IntLit(0));
    }

    #[test]
    fn test_double_negation() {
        let expr = Expr::Unary {
            op: UnOp::Not,
            operand: Box::new(Expr::Unary {
                op: UnOp::Not,
                operand: Box::new(Expr::Var("x".into())),
            }),
        };
        assert_eq!(simplify_expr(&expr), Expr::Var("x".into()));
    }

    #[test]
    fn test_lognot_comparison_folds() {
        let expr = Expr::Unary {
            op: UnOp::LogNot,
            operand: Box::new(Expr::Binary {
                op: BinOp::Ne,
                lhs: Box::new(Expr::Var("x".into())),
                rhs: Box::new(Expr::IntLit(1)),
            }),
        };
        assert_eq!(
            simplify_expr(&expr),
            Expr::Binary {
                op: BinOp::Eq,
                lhs: Box::new(Expr::Var("x".into())),
                rhs: Box::new(Expr::IntLit(1)),
            }
        );
    }

    #[test]
    fn test_lognot_unsigned_folds() {
        let expr = Expr::Unary {
            op: UnOp::LogNot,
            operand: Box::new(Expr::Binary {
                op: BinOp::LtU,
                lhs: Box::new(Expr::Var("a".into())),
                rhs: Box::new(Expr::Var("b".into())),
            }),
        };
        assert_eq!(
            simplify_expr(&expr),
            Expr::Binary {
                op: BinOp::GeU,
                lhs: Box::new(Expr::Var("a".into())),
                rhs: Box::new(Expr::Var("b".into())),
            }
        );
    }

    fn rsp_minus_8() -> Expr {
        Expr::Binary {
            op: BinOp::Sub,
            lhs: Box::new(Expr::Var("rsp".into())),
            rhs: Box::new(Expr::IntLit(8)),
        }
    }

    #[test]
    fn binary_value_inlined_into_deref_target() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Assign {
            target: Expr::Var("v0".into()),
            value: rsp_minus_8(),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Deref(Box::new(Expr::Var("v0".into()))),
            value: Expr::Var("rbp".into()),
        });
        func.body.push(Stmt::Return { value: None });

        simplify_function(&mut func);

        assert_eq!(func.body.len(), 2, "dead v0 definition must be removed: {:?}", func.body);
        match &func.body[0] {
            Stmt::Assign { target, value } => {
                assert_eq!(value, &Expr::Var("rbp".into()));
                match target {
                    Expr::Deref(inner) => assert_eq!(
                        inner.as_ref(),
                        &rsp_minus_8(),
                        "Binary value was not inlined into Deref target"
                    ),
                    other => panic!("expected Deref target, got {:?}", other),
                }
            }
            other => panic!("expected Assign, got {:?}", other),
        }
    }

    #[test]
    fn binary_value_not_inlined_when_two_uses() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Assign {
            target: Expr::Var("v0".into()),
            value: rsp_minus_8(),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Deref(Box::new(Expr::Var("v0".into()))),
            value: Expr::Var("rbp".into()),
        });
        func.body.push(Stmt::Return { value: Some(Expr::Var("v0".into())) });

        simplify_function(&mut func);

        match &func.body[1] {
            Stmt::Assign { target, .. } => {
                assert_eq!(
                    target,
                    &Expr::Deref(Box::new(Expr::Var("v0".into()))),
                    "v0 has two uses — inlining is forbidden"
                );
            }
            other => panic!("expected Assign at index 1, got {:?}", other),
        }
        match &func.body[0] {
            Stmt::Assign { target: Expr::Var(name), value } => {
                assert_eq!(name, "v0");
                assert_eq!(value, &rsp_minus_8(), "definition of v0 must survive");
            }
            other => panic!("expected v0 definition kept, got {:?}", other),
        }
    }

    fn sp_add(n: i64) -> Stmt {
        Stmt::Assign {
            target: Expr::Var("rsp".into()),
            value: Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Var("rsp".into())),
                rhs: Box::new(Expr::IntLit(n)),
            },
        }
    }

    /// Epilogue noise (`rsp = rsp + 8` repeated) and frame-setup copies
    /// (`rbp = rsp`, `rsp = rbp`) must all disappear.
    #[test]
    fn stack_adjustments_and_frame_copies_removed() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Assign {
            target: Expr::Var("rax".into()),
            value: Expr::Call { func: "sub_140001675".into(), args: vec![] },
        });
        for _ in 0..3 {
            func.body.push(sp_add(8));
        }
        func.body.push(Stmt::Assign {
            target: Expr::Var("rbp".into()),
            value: Expr::Var("rsp".into()),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Var("rsp".into()),
            value: Expr::Var("rbp".into()),
        });
        func.body.push(Stmt::Return { value: Some(Expr::Var("rax".into())) });

        simplify_function(&mut func);

        assert!(
            !func.body.iter().any(|s| matches!(
                s,
                Stmt::Assign { target: Expr::Var(n), .. } if n == "rsp" || n == "rbp"
            )),
            "no rsp/rbp assignments may remain: {:?}",
            func.body
        );
        assert_eq!(func.body.len(), 2, "only the call and return survive");
    }

    /// Stores THROUGH rsp pointers and dynamic adjustments are semantic and
    /// must never be stripped.
    #[test]
    fn stores_through_rsp_and_dynamic_adjust_kept() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Assign {
            target: Expr::Deref(Box::new(Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Var("rsp".into())),
                rhs: Box::new(Expr::IntLit(0x40)),
            })),
            value: Expr::Var("rcx".into()),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Var("rsp".into()),
            value: Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Var("rsp".into())),
                rhs: Box::new(Expr::Var("rcx".into())),
            },
        });
        func.body.push(sp_add(8));
        func.body.push(Stmt::Return { value: None });

        simplify_function(&mut func);

        assert_eq!(func.body.len(), 3, "only `rsp = rsp + 8` is removed");
        assert!(
            matches!(&func.body[0], Stmt::Assign { target: Expr::Deref(_), .. }),
            "the store through rsp must stay: {:?}",
            func.body[0]
        );
        assert!(
            matches!(
                &func.body[1],
                Stmt::Assign { target: Expr::Var(n), value: Expr::Binary { rhs, .. } }
                    if n == "rsp" && **rhs == Expr::Var("rcx".into())
            ),
            "the dynamic adjustment must stay: {:?}",
            func.body[1]
        );
    }

    /// Dead `flag_*` assignments that survived IR cleanup are dropped at AST
    /// level; assignments still read somewhere remain (they cannot be removed
    /// without changing semantics). A second definition keeps the variable
    /// alive AND blocks copy propagation, so the read assignment survives.
    #[test]
    fn dead_flag_assignments_dropped_live_ones_kept() {
        let mut dead = AstFunction::new("dead");
        dead.body.push(Stmt::Assign {
            target: Expr::Var("flag_zf".into()),
            value: Expr::Binary {
                op: BinOp::Eq,
                lhs: Box::new(Expr::Var("rax".into())),
                rhs: Box::new(Expr::Var("rcx".into())),
            },
        });
        dead.body.push(Stmt::Return { value: None });
        simplify_function(&mut dead);
        assert!(
            !format!("{:?}", dead.body).contains("flag_zf"),
            "unread flag assignment must be dropped: {:?}",
            dead.body
        );

        let mut live = AstFunction::new("live");
        for (lhs_name, rhs_lit) in [("rax", 0), ("rdx", 1)] {
            live.body.push(Stmt::Assign {
                target: Expr::Var("flag_zf".into()),
                value: Expr::Binary {
                    op: BinOp::Eq,
                    lhs: Box::new(Expr::Var(lhs_name.into())),
                    rhs: Box::new(Expr::IntLit(rhs_lit)),
                },
            });
        }
        live.body.push(Stmt::If {
            cond: Expr::Binary {
                op: BinOp::Ne,
                lhs: Box::new(Expr::Var("flag_zf".into())),
                rhs: Box::new(Expr::IntLit(1)),
            },
            then_body: vec![],
            else_body: None,
        });
        simplify_function(&mut live);
        assert!(
            format!("{:?}", live.body).contains("flag_zf"),
            "a read flag assignment must be kept by the AST pass: {:?}",
            live.body
        );
    }

    /// Stack-noise removal also reaches statements nested inside loops and
    /// branches.
    #[test]
    fn stack_noise_removed_from_nested_bodies() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::While {
            cond: Expr::BoolLit(true),
            body: vec![
                sp_add(8),
                Stmt::Assign {
                    target: Expr::Var("rax".into()),
                    value: Expr::IntLit(1),
                },
            ],
        });
        // Keep the nested assignment observable so generic DCE cannot eat it —
        // only the noise pass may remove things here.
        func.body.push(Stmt::Return { value: Some(Expr::Var("rax".into())) });
        simplify_function(&mut func);
        match &func.body[0] {
            Stmt::While { body, .. } => {
                assert_eq!(body.len(), 1, "nested rsp adjustment must be gone");
            }
            other => panic!("expected While, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod lognot_pipeline_probe {
    use super::*;
    use crate::ast::*;

    #[test]
    fn probe_inline_then_fold() {
        // v31 = rcx != 1; if (!v31) { X }
        let mut f = AstFunction::new("p");
        f.body.push(Stmt::Assign {
            target: Expr::Var("v31".into()),
            value: Expr::Binary {
                op: BinOp::Ne,
                lhs: Box::new(Expr::Var("rcx".into())),
                rhs: Box::new(Expr::IntLit(1)),
            },
        });
        f.body.push(Stmt::If {
            cond: Expr::Unary {
                op: UnOp::LogNot,
                operand: Box::new(Expr::Var("v31".into())),
            },
            then_body: vec![Stmt::Empty],
            else_body: None,
        });
        simplify_function(&mut f);
        println!("{:#?}", f.body);
        // After inlining, the now-dead `v31` assignment is removed, so the If
        // may not stay at index 1 — locate it anywhere in the body.
        let folded = f.body.iter().any(|stmt| {
            matches!(
                stmt,
                Stmt::If { cond: Expr::Binary { op: BinOp::Eq, .. }, .. }
            )
        });
        assert!(folded, "cond should be Binary Eq after pipeline");
    }
}
