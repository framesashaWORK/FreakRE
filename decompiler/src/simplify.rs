//! Expression simplification pass for decompiled AST.
//!
//! Applies algebraic identities, constant folding, dead assignment elimination,
//! copy propagation, and condition merging to produce cleaner pseudocode.

use crate::ast::*;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Run all simplification passes on an AST function (in-place).
pub fn simplify_function(func: &mut AstFunction) {
    let _ = simplify_function_with_stats(func);
}

/// Tallies for the output-quality transforms applied by
/// [`simplify_function_with_stats`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SimplifyStats {
    pub conditions_merged_and: usize,
    pub conditions_merged_or: usize,
    pub ternaries_collapsed: usize,
    pub gotos_removed: usize,
    pub labels_inlined: usize,
    pub unused_labels_removed: usize,
    pub unreachable_dropped: usize,
    pub continue_trimmed: usize,
    pub void_returns_trimmed: usize,
    pub dead_locals_removed: usize,
    pub self_assigns_removed: usize,
}

impl SimplifyStats {
    pub fn tally(&self) -> String {
        format!(
             "conditions_merged_and={} conditions_merged_or={} ternaries_collapsed={} \
             gotos_removed={} labels_inlined={} unused_labels_removed={} unreachable_dropped={} \
             continue_trimmed={} void_returns_trimmed={} dead_locals_removed={} \
             self_assigns_removed={}",
            self.conditions_merged_and,
            self.conditions_merged_or,
            self.ternaries_collapsed,
            self.gotos_removed,
            self.labels_inlined,
            self.unused_labels_removed,
            self.unreachable_dropped,
            self.continue_trimmed,
            self.void_returns_trimmed,
            self.dead_locals_removed,
            self.self_assigns_removed
        )
    }
}

/// Like [`simplify_function`], but reports how often each output-quality
/// transform fired.
pub fn simplify_function_with_stats(func: &mut AstFunction) -> SimplifyStats {
    let mut stats = SimplifyStats::default();

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

    // Pass 3.5: Fuse `a = *base; b = a OP x; *base = b` into `*base OP= x`,
    // keeping any intervening `flag_*` assignments (substituting the fused
    // operands into them). This collapses the dominant load/add/store noise
    // emitted by the x86 lifter for mem-op arithmetic.
    fuse_memory_updates(&mut func.body);

    // Pass 4: Condition merging (nested ifs sharing a merge point)
    merge_conditions(&mut func.body, &mut stats);

    // Pass 4b: Ternary collapse (`if (c) {v=a} else {v=b}` → `v = c ? a : b`)
    collapse_ternaries(&mut func.body, &mut stats);

    // Pass 5: Second round of constant folding after restructuring
    simplify_stmts(&mut func.body);

    // Pass 5b: Goto/label cleanup (drop unreachable tails, remove redundant
    // gotos, inline single-predecessor labels)
    cleanup_gotos(&mut func.body, &mut stats);

    // Pass 5c: Trailing-control cleanup — drop a redundant trailing
    // `continue` at the end of loop bodies (the loop back-edge does it) and a
    // trailing `return;` at the end of a void function.
    trim_trailing_continue(&mut func.body, &mut stats, false);
    if matches!(func.return_type, freakre_ir::Ty::Void) {
        trim_trailing_void_return(&mut func.body, &mut stats);
    }

    // Pass 5d: dead-local cleanup — drop self-assignments (`x = x`) and
    // local declarations never read anywhere in the body.
    remove_dead_locals(func, &mut stats);

    // Pass 6: Final cleanup — copy propagation may turn `rsp = v12` copies
    // into plain `rsp = rsp - 8` adjustments, and pattern transforms may
    // surface further dead flag assignments.
    strip_stack_noise(&mut func.body);
    strip_dead_flag_assignments(&mut func.body);

    stats
}

// в”Ђв”Ђв”Ђ Prologue / Epilogue Noise Removal в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Pass 5d: drop self-assignments (`x = x`) and local declarations whose
/// name is never read anywhere in the body. Parameters are exempt (they are
/// part of the signature, not `locals`).
fn remove_dead_locals(func: &mut AstFunction, stats: &mut SimplifyStats) {
    let param_names: HashSet<String> =
        func.params.iter().map(|p| p.name.clone()).collect();

    // (a) self-assignments
    let mut self_assigns = 0usize;
    remove_self_assigns(&mut func.body, &mut self_assigns);
    stats.self_assigns_removed += self_assigns;

    // (b) collect every name referenced anywhere, retain only locals in use
    let mut used: HashSet<String> = HashSet::new();
    for s in &func.body {
        s.for_each_expr(&mut |e: &crate::ast::Expr| {
            if let crate::ast::Expr::Var(name) = e {
                used.insert(name.clone());
            }
        });
    }
    let before = func.locals.len();
    func.locals
        .retain(|l| param_names.contains(&l.name) || used.contains(&l.name));
    stats.dead_locals_removed += before - func.locals.len();
}

/// Recursively remove `x = x` statements (both sides the same plain Var).
fn remove_self_assigns(stmts: &mut Vec<Stmt>, count: &mut usize) {
    let before = stmts.len();
    stmts.retain(|s| {
        !matches!(
            s,
            Stmt::Assign {
                target: crate::ast::Expr::Var(t),
                value: crate::ast::Expr::Var(v),
            } if t == v
        )
    });
    *count += before - stmts.len();
    for s in stmts.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                remove_self_assigns(then_body, count);
                if let Some(eb) = else_body {
                    remove_self_assigns(eb, count);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                remove_self_assigns(body, count)
            }
            Stmt::For { body, .. } => remove_self_assigns(body, count),
            Stmt::Switch { cases, default, .. } => {
                for c in cases {
                    remove_self_assigns(&mut c.body, count);
                }
                if let Some(d) = default {
                    remove_self_assigns(d, count);
                }
            }
            Stmt::Block(b) => remove_self_assigns(b, count),
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
                remove_self_assigns(try_body, count);
                remove_self_assigns(catch_body, count);
            }
            _ => {}
        }
    }
}

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
            Expr::Binary {
                op: bin_op @ (BinOp::Add | BinOp::Sub),
                lhs,
                rhs,
            } => {
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
    stmts.retain(|stmt| {
        !matches!(
            stmt,
            Stmt::Assign { target, value } if is_stack_noise(target, value)
        )
    });

    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                strip_stack_noise(then_body);
                if let Some(eb) = else_body {
                    strip_stack_noise(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                strip_stack_noise(body);
            }
            Stmt::For {
                init, update, body, ..
            } => {
                if let Some(i) = init {
                    strip_single(i.as_mut());
                }
                if let Some(u) = update {
                    strip_single(u.as_mut());
                }
                strip_stack_noise(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    strip_stack_noise(&mut c.body);
                }
                if let Some(d) = default {
                    strip_stack_noise(d);
                }
            }
            Stmt::Block(inner) => {
                strip_stack_noise(inner);
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
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
    stmts.retain(|stmt| {
        !matches!(
            stmt,
            Stmt::Assign { target: Expr::Var(name), .. }
                if name.starts_with("flag_") && !used_vars.contains(name)
        )
    });

    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                strip_dead_flag_assignments_inner(then_body, used_vars);
                if let Some(eb) = else_body {
                    strip_dead_flag_assignments_inner(eb, used_vars);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                strip_dead_flag_assignments_inner(body, used_vars);
            }
            Stmt::For { body, .. } => {
                strip_dead_flag_assignments_inner(body, used_vars);
            }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    strip_dead_flag_assignments_inner(&mut c.body, used_vars);
                }
                if let Some(d) = default {
                    strip_dead_flag_assignments_inner(d, used_vars);
                }
            }
            Stmt::Block(inner) => {
                strip_dead_flag_assignments_inner(inner, used_vars);
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
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
                    _ => Expr::Binary {
                        op: *op,
                        lhs: Box::new(l),
                        rhs: Box::new(r),
                    },
                };
            }

            // Identity: x + 0, x - 0, x | 0, x ^ 0, x << 0, x >> 0
            if matches!(
                op,
                BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr
            ) && is_zero(&r)
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

            Expr::Binary {
                op: *op,
                lhs: Box::new(l),
                rhs: Box::new(r),
            }
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
                if let Expr::Unary {
                    op: UnOp::Not,
                    operand: inner2,
                } = &inner
                {
                    return (**inner2).clone();
                }
            }
            // Double logical not: !!x в†’ x (semantically for bools)
            if *op == UnOp::LogNot {
                if let Expr::Unary {
                    op: UnOp::LogNot,
                    operand: inner2,
                } = &inner
                {
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
                        return Expr::Binary {
                            op: neg,
                            lhs: lhs.clone(),
                            rhs: rhs.clone(),
                        };
                    }
                }
            }

            Expr::Unary {
                op: *op,
                operand: Box::new(inner),
            }
        }

        // в”Ђв”Ђ Cast simplification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Cast { ty, expr } => {
            let inner = simplify_expr(expr);
            // Redundant cast: (T)(T)x в†’ (T)x вЂ” would need type equality check
            // For now just recurse
            Expr::Cast {
                ty: ty.clone(),
                expr: Box::new(inner),
            }
        }

        // в”Ђв”Ђ Ternary simplification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
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
            Expr::Call {
                func: func.clone(),
                args: new_args,
            }
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
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => is_pure(cond) && is_pure(then_expr) && is_pure(else_expr),
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
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
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
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(i) = init {
                simplify_stmt(i);
            }
            if let Some(c) = cond {
                *c = simplify_expr(c);
            }
            if let Some(u) = update {
                simplify_stmt(u);
            }
            simplify_stmts(body);
        }
        Stmt::DoWhile { body, cond } => {
            simplify_stmts(body);
            *cond = simplify_expr(cond);
        }
        Stmt::Switch {
            expr,
            cases,
            default,
        } => {
            *expr = simplify_expr(expr);
            for case in cases.iter_mut() {
                case.value = simplify_expr(&case.value);
                simplify_stmts(&mut case.body);
            }
            if let Some(d) = default {
                simplify_stmts(d);
            }
        }
        Stmt::Return { value: Some(v) } => {
            *v = simplify_expr(v);
        }
        Stmt::Call { args, .. } => {
            for a in args.iter_mut() {
                *a = simplify_expr(a);
            }
        }
        Stmt::Expr(e) => {
            *e = simplify_expr(e);
        }
        Stmt::Block(inner) => {
            simplify_stmts(inner);
        }
        Stmt::Decl { init: Some(e), .. } => {
            *e = simplify_expr(e);
        }
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
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
        Expr::Binary { lhs, rhs, .. } => expr_may_side_effect(lhs) || expr_may_side_effect(rhs),
        Expr::Unary { operand, .. }
        | Expr::Deref(operand)
        | Expr::AddrOf(operand)
        | Expr::Sizeof(operand) => expr_may_side_effect(operand),
        Expr::Index { base, index } => expr_may_side_effect(base) || expr_may_side_effect(index),
        Expr::Member { base, .. } => expr_may_side_effect(base),
        Expr::Cast { expr, .. } => expr_may_side_effect(expr),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
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
            Stmt::Assign {
                target: Expr::Var(name),
                value,
            } => {
                // Keep if target variable is used somewhere, or if evaluating
                // the RHS has side effects (calls must not be deleted).
                used_vars.contains(name) || expr_may_side_effect(value)
            }
            Stmt::Decl { name, init, .. } => {
                used_vars.contains(name) || init.as_ref().is_some_and(expr_may_side_effect)
            }
            _ => true,
        }
    });

    // Recurse into nested blocks
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                remove_dead_stmts(then_body, used_vars);
                if let Some(eb) = else_body {
                    remove_dead_stmts(eb, used_vars);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                remove_dead_stmts(body, used_vars);
            }
            Stmt::For { body, .. } => {
                remove_dead_stmts(body, used_vars);
            }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    remove_dead_stmts(&mut c.body, used_vars);
                }
                if let Some(d) = default {
                    remove_dead_stmts(d, used_vars);
                }
            }
            Stmt::Block(inner) => {
                remove_dead_stmts(inner, used_vars);
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
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
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            collect_used_vars_expr(cond, out);
            collect_used_vars_stmts(then_body, out);
            if let Some(eb) = else_body {
                collect_used_vars_stmts(eb, out);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            collect_used_vars_expr(cond, out);
            collect_used_vars_stmts(body, out);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(i) = init {
                collect_used_vars_stmt(i, out);
            }
            if let Some(c) = cond {
                collect_used_vars_expr(c, out);
            }
            if let Some(u) = update {
                collect_used_vars_stmt(u, out);
            }
            collect_used_vars_stmts(body, out);
        }
        Stmt::Switch {
            expr,
            cases,
            default,
        } => {
            collect_used_vars_expr(expr, out);
            for c in cases {
                collect_used_vars_stmts(&c.body, out);
            }
            if let Some(d) = default {
                collect_used_vars_stmts(d, out);
            }
        }
        Stmt::Return { value: Some(v) } => {
            collect_used_vars_expr(v, out);
        }
        Stmt::Call { args, .. } => {
            for a in args {
                collect_used_vars_expr(a, out);
            }
        }
        Stmt::Expr(e) => {
            collect_used_vars_expr(e, out);
        }
        Stmt::Block(inner) => {
            collect_used_vars_stmts(inner, out);
        }
        Stmt::Decl { init: Some(e), .. } => {
            collect_used_vars_expr(e, out);
        }
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
            collect_used_vars_stmts(try_body, out);
            collect_used_vars_stmts(catch_body, out);
        }
        _ => {}
    }
}

fn collect_used_vars_expr(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Var(name) => {
            out.insert(name.clone());
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_used_vars_expr(lhs, out);
            collect_used_vars_expr(rhs, out);
        }
        Expr::Unary { operand, .. } => {
            collect_used_vars_expr(operand, out);
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_used_vars_expr(a, out);
            }
        }
        Expr::Index { base, index } => {
            collect_used_vars_expr(base, out);
            collect_used_vars_expr(index, out);
        }
        Expr::Member { base, .. } => {
            collect_used_vars_expr(base, out);
        }
        Expr::Deref(e) | Expr::AddrOf(e) | Expr::Sizeof(e) => {
            collect_used_vars_expr(e, out);
        }
        Expr::Cast { expr: e, .. } => {
            collect_used_vars_expr(e, out);
        }
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
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
        if let Stmt::Assign {
            target: Expr::Var(name),
            value,
        } = stmt
        {
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
            Stmt::Assign {
                target: Expr::Var(name),
                ..
            }
            | Stmt::Decl { name, .. } => Some(name),
            _ => None,
        };
        if let Some(def_name) = redefined {
            pending.retain(|_, expr| !expr_references_var(expr, def_name));
        }
    }

    // 3. Recurse into nested lists, carrying only literal constants down.
    let literals: HashMap<String, Expr> = pending
        .into_iter()
        .filter(|(_, v)| {
            matches!(
                v,
                Expr::IntLit(_) | Expr::BoolLit(_) | Expr::FloatLit(_) | Expr::StringLit(_)
            )
        })
        .collect();

    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                substitute_within_list(then_body, def_counts, use_counts, &literals);
                if let Some(eb) = else_body {
                    substitute_within_list(eb, def_counts, use_counts, &literals);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                substitute_within_list(body, def_counts, use_counts, &literals);
            }
            Stmt::For {
                init, update, body, ..
            } => {
                if let Some(i) = init {
                    substitute_within_list(
                        std::slice::from_mut(i.as_mut()),
                        def_counts,
                        use_counts,
                        &literals,
                    );
                }
                if let Some(u) = update {
                    substitute_within_list(
                        std::slice::from_mut(u.as_mut()),
                        def_counts,
                        use_counts,
                        &literals,
                    );
                }
                substitute_within_list(body, def_counts, use_counts, &literals);
            }
            Stmt::Block(inner) => substitute_within_list(inner, def_counts, use_counts, &literals),
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    substitute_within_list(&mut c.body, def_counts, use_counts, &literals);
                }
                if let Some(d) = default {
                    substitute_within_list(d, def_counts, use_counts, &literals);
                }
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
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
            for a in args.iter_mut() {
                substitute_vars_expr(a, pending);
            }
        }
        Stmt::Expr(e) => substitute_vars_expr(e, pending),
        Stmt::Decl { init: Some(e), .. } => substitute_vars_expr(e, pending),
        Stmt::If { cond, .. } => substitute_vars_expr(cond, pending),
        Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            substitute_vars_expr(cond, pending)
        }
        Stmt::For { cond: Some(c), .. } => {
            substitute_vars_expr(c, pending);
        }
        Stmt::For { cond: None, .. } => {}
        Stmt::Switch { expr, cases, .. } => {
            substitute_vars_expr(expr, pending);
            for c in cases.iter_mut() {
                substitute_vars_expr(&mut c.value, pending);
            }
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
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            count_var_defs_stmts(then_body, counts);
            if let Some(eb) = else_body {
                count_var_defs_stmts(eb, counts);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            count_var_defs_stmts(body, counts);
        }
        Stmt::For {
            init, update, body, ..
        } => {
            if let Some(i) = init {
                count_var_defs_stmt(i, counts);
            }
            if let Some(u) = update {
                count_var_defs_stmt(u, counts);
            }
            count_var_defs_stmts(body, counts);
        }
        Stmt::Block(inner) => count_var_defs_stmts(inner, counts),
        Stmt::Switch { cases, default, .. } => {
            for c in cases {
                count_var_defs_stmts(&c.body, counts);
            }
            if let Some(d) = default {
                count_var_defs_stmts(d, counts);
            }
        }
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
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
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            count_var_uses_expr(cond, counts);
            count_var_uses_stmts(then_body, counts);
            if let Some(eb) = else_body {
                count_var_uses_stmts(eb, counts);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            count_var_uses_expr(cond, counts);
            count_var_uses_stmts(body, counts);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(i) = init {
                count_var_uses_stmt(i, counts);
            }
            if let Some(c) = cond {
                count_var_uses_expr(c, counts);
            }
            if let Some(u) = update {
                count_var_uses_stmt(u, counts);
            }
            count_var_uses_stmts(body, counts);
        }
        Stmt::Switch {
            expr,
            cases,
            default,
        } => {
            count_var_uses_expr(expr, counts);
            for c in cases {
                count_var_uses_stmts(&c.body, counts);
            }
            if let Some(d) = default {
                count_var_uses_stmts(d, counts);
            }
        }
        Stmt::Return { value: Some(v) } => {
            count_var_uses_expr(v, counts);
        }
        Stmt::Call { args, .. } => {
            for a in args {
                count_var_uses_expr(a, counts);
            }
        }
        Stmt::Expr(e) => {
            count_var_uses_expr(e, counts);
        }
        Stmt::Block(inner) => {
            count_var_uses_stmts(inner, counts);
        }
        Stmt::Decl { init: Some(e), .. } => {
            count_var_uses_expr(e, counts);
        }
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
            count_var_uses_stmts(try_body, counts);
            count_var_uses_stmts(catch_body, counts);
        }
        _ => {}
    }
}

fn count_var_uses_expr(expr: &Expr, counts: &mut HashMap<String, usize>) {
    match expr {
        Expr::Var(name) => {
            *counts.entry(name.clone()).or_insert(0) += 1;
        }
        Expr::Binary { lhs, rhs, .. } => {
            count_var_uses_expr(lhs, counts);
            count_var_uses_expr(rhs, counts);
        }
        Expr::Unary { operand, .. } => {
            count_var_uses_expr(operand, counts);
        }
        Expr::Call { args, .. } => {
            for a in args {
                count_var_uses_expr(a, counts);
            }
        }
        Expr::Index { base, index } => {
            count_var_uses_expr(base, counts);
            count_var_uses_expr(index, counts);
        }
        Expr::Member { base, .. } => {
            count_var_uses_expr(base, counts);
        }
        Expr::Deref(e) | Expr::AddrOf(e) | Expr::Sizeof(e) => {
            count_var_uses_expr(e, counts);
        }
        Expr::Cast { expr: e, .. } => {
            count_var_uses_expr(e, counts);
        }
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            count_var_uses_expr(cond, counts);
            count_var_uses_expr(then_expr, counts);
            count_var_uses_expr(else_expr, counts);
        }
        _ => {}
    }
}

/// Check if an expression is simple enough to inline.
fn is_simple_expr(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::IntLit(_) | Expr::BoolLit(_) | Expr::StringLit(_) | Expr::Var(_) | Expr::FloatLit(_)
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
        | Expr::Field { .. }
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
        Expr::Unary { operand, .. } => {
            substitute_vars_expr(operand, defs);
        }
        Expr::Call { args, .. } => {
            for a in args.iter_mut() {
                substitute_vars_expr(a, defs);
            }
        }
        Expr::Index { base, index } => {
            substitute_vars_expr(base, defs);
            substitute_vars_expr(index, defs);
        }
        Expr::Member { base, .. } | Expr::Field { base, .. } => {
            substitute_vars_expr(base, defs);
        }
        Expr::Deref(e) | Expr::AddrOf(e) | Expr::Sizeof(e) => {
            substitute_vars_expr(e, defs);
        }
        Expr::Cast { expr: e, .. } => {
            substitute_vars_expr(e, defs);
        }
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            substitute_vars_expr(cond, defs);
            substitute_vars_expr(then_expr, defs);
            substitute_vars_expr(else_expr, defs);
        }
        _ => {}
    }
}

// в”Ђв”Ђв”Ђ Condition Merging в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Merge nested if-without-else: `if (a) { if (b) { ... } }` в†’ `if (a && b) { ... }`
/// Merge nested if-without-else into a single conjunction.
/// Counts each AND-merged condition in `stats.conditions_merged_and`.
#[allow(clippy::ptr_arg)]
fn merge_conditions(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats) {
    for stmt in stmts.iter_mut() {
        merge_conditions_stmt(stmt, stats);
    }
}

fn merge_conditions_stmt(stmt: &mut Stmt, stats: &mut SimplifyStats) {
    match stmt {
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            // Recurse first
            merge_conditions_stmts(then_body, stats);
            if let Some(eb) = else_body {
                merge_conditions_stmts(eb, stats);
            }

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
                    stats.conditions_merged_and += 1;
                }
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            merge_conditions_stmts(body, stats);
        }
        Stmt::For { body, .. } => {
            merge_conditions_stmts(body, stats);
        }
        Stmt::Block(inner) => {
            merge_conditions_stmts(inner, stats);
        }
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() {
                merge_conditions_stmts(&mut c.body, stats);
            }
            if let Some(d) = default {
                merge_conditions_stmts(d, stats);
            }
        }
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
            merge_conditions_stmts(try_body, stats);
            merge_conditions_stmts(catch_body, stats);
        }
        _ => {}
    }
}

fn merge_conditions_stmts(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats) {
    merge_conditions(stmts, stats);
}

/// Collapse `if (c) { v = a } else { v = b }` into `v = c ? a : b`
/// when both branches assign the same target. Counts each collapse in
/// `stats.ternaries_collapsed`.
#[allow(clippy::ptr_arg)]
fn collapse_ternaries(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_ternaries(then_body, stats);
                if let Some(eb) = else_body {
                    collapse_ternaries(eb, stats);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collapse_ternaries(body, stats);
            }
            Stmt::For { body, .. } => {
                collapse_ternaries(body, stats);
            }
            Stmt::Block(inner) => {
                collapse_ternaries(inner, stats);
            }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    collapse_ternaries(&mut c.body, stats);
                }
                if let Some(d) = default {
                    collapse_ternaries(d, stats);
                }
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
                collapse_ternaries(try_body, stats);
                collapse_ternaries(catch_body, stats);
            }
            _ => {}
        }
    }

    let mut i = 0;
    while i < stmts.len() {
        let transformed = if let Stmt::If {
            cond,
            then_body,
            else_body,
        } = &stmts[i]
        {
            if then_body.len() == 1 && else_body.as_ref().is_some_and(|e| e.len() == 1) {
                if let (
                    Stmt::Assign {
                        target: t1,
                        value: v1,
                    },
                    Stmt::Assign {
                        target: t2,
                        value: v2,
                    },
                ) = (&then_body[0], &else_body.as_ref().unwrap()[0])
                {
                    if t1 == t2 {
                        Some((cond.clone(), t1.clone(), v1.clone(), v2.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some((cond, target, v1, v2)) = transformed {
            stmts[i] = Stmt::Assign {
                target,
                value: Expr::Ternary {
                    cond: Box::new(cond),
                    then_expr: Box::new(v1),
                    else_expr: Box::new(v2),
                },
            };
            stats.ternaries_collapsed += 1;
        }
        i += 1;
    }
}

/// Collect every `goto` target label reachable anywhere in `stmts` (including
/// those nested inside `if`/`while`/`for`/`switch`/`try` bodies). A label must
/// be kept iff *any* `goto` in the whole subtree references it — using only the
/// current list level would drop a label targeted by a `goto` sitting inside a
/// nested `if` (the classic irreducible-CFG fallback shape).
fn collect_goto_targets(stmts: &[Stmt], out: &mut HashSet<String>) {
    for s in stmts {
        match s {
            Stmt::Goto { label } => {
                out.insert(label.clone());
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_goto_targets(then_body, out);
                if let Some(eb) = else_body {
                    collect_goto_targets(eb, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collect_goto_targets(body, out)
            }
            Stmt::Block(inner) => collect_goto_targets(inner, out),
            Stmt::Switch { cases, default, .. } => {
                for c in cases {
                    collect_goto_targets(&c.body, out);
                }
                if let Some(d) = default {
                    collect_goto_targets(d, out);
                }
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
                collect_goto_targets(try_body, out);
                collect_goto_targets(catch_body, out);
            }
            _ => {}
        }
    }
}

/// Drop unreachable tails, remove redundant gotos, and inline single-predecessor
/// labels. Tallies the corresponding `SimplifyStats` counters.
///
/// `targets` is the *globally* collected set of labels referenced by any `goto`
/// in the entire function. It is computed once by the entry point and threaded
/// down so that a label whose only jumper lives inside a different (nested or
/// outer) block is still preserved instead of being mis-reported as dead.
fn cleanup_gotos(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats) {
    let mut targets: HashSet<String> = HashSet::new();
    collect_goto_targets(stmts, &mut targets);
    cleanup_gotos_with(stmts, stats, &targets);
}

fn cleanup_gotos_with(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats, targets: &HashSet<String>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                cleanup_gotos_with(then_body, stats, targets);
                if let Some(eb) = else_body {
                    cleanup_gotos_with(eb, stats, targets);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                cleanup_gotos_with(body, stats, targets)
            }
            Stmt::For { body, .. } => cleanup_gotos_with(body, stats, targets),
            Stmt::Block(inner) => cleanup_gotos_with(inner, stats, targets),
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    cleanup_gotos_with(&mut c.body, stats, targets);
                }
                if let Some(d) = default {
                    cleanup_gotos_with(d, stats, targets);
                }
            }
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
                cleanup_gotos_with(try_body, stats, targets);
                cleanup_gotos_with(catch_body, stats, targets);
            }
            _ => {}
        }
    }

    // Drop unreachable tail after a terminating statement.
    let mut drop_from: Option<usize> = None;
    for (idx, s) in stmts.iter().enumerate() {
        if matches!(
            s,
            Stmt::Goto { .. } | Stmt::Return { .. } | Stmt::Break | Stmt::Continue
        ) {
            drop_from = Some(idx + 1);
            break;
        }
    }
    if let Some(start) = drop_from {
        if start < stmts.len() {
            stats.unreachable_dropped += stmts.len() - start;
            stmts.truncate(start);
        }
    }

    // Remove a `goto X` immediately followed by `label X` (redundant jump),
    // and inline the label if nothing else references it.
    let mut j = 0;
    while j + 1 < stmts.len() {
        let redundant = matches!(&stmts[j], Stmt::Goto { label }
            if matches!(&stmts[j + 1], Stmt::Label { name } if name == label));
        if redundant {
            stmts.remove(j);
            stats.gotos_removed += 1;
            if let Stmt::Label { name } = &stmts[j] {
                let name = name.clone();
                // Use the *global* target set: a label kept alive by a `goto`
                // anywhere in the function must not be inlined away here.
                let still_referenced = targets.contains(&name);
                if !still_referenced {
                    stmts.remove(j);
                    stats.labels_inlined += 1;
                }
            }
            continue;
        }
        j += 1;
    }

    // Remove labels that are never targeted by a `goto` *anywhere in the
    // function*. `targets` is the globally collected set, so a label whose only
    // jumper lives inside a nested `if`/`while`/`else` (the classic
    // irreducible-CFG fallback shape) is still preserved instead of being
    // mis-flagged as dead and leaving a dangling `goto`.
    let before = stmts.len();
    stmts.retain(|s| !matches!(s, Stmt::Label { name } if !targets.contains(name)));
    stats.unused_labels_removed += before - stmts.len();
}

// ─── Trailing control-flow cleanup ──────────────────────────────────────
//
// A `continue` as the very last statement of a loop body is redundant (the
// back edge jumps to the header anyway), and a trailing `return;` in a void
// function is pure noise. Both are trimmed recursively.

fn trim_trailing_continue(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats, in_loop: bool) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                trim_trailing_continue(body, stats, true)
            }
            Stmt::For { body, .. } => trim_trailing_continue(body, stats, true),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                // A `continue` inside an `if` at the end of the loop body is
                // NOT redundant (the other arm falls through differently).
                trim_trailing_continue(then_body, stats, in_loop);
                if let Some(eb) = else_body {
                    trim_trailing_continue(eb, stats, in_loop);
                }
            }
            Stmt::Block(inner) => trim_trailing_continue(inner, stats, in_loop),
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    trim_trailing_continue(&mut c.body, stats, in_loop);
                }
                if let Some(d) = default {
                    trim_trailing_continue(d, stats, in_loop);
                }
            }
            _ => {}
        }
    }
    if in_loop {
        while matches!(stmts.last(), Some(Stmt::Continue)) {
            stmts.pop();
            stats.continue_trimmed += 1;
        }
    }
}

/// Trim a trailing bare `return;` from the function body only. Nested lists
/// are left alone: a `return;` at the end of an `if` arm is an early exit,
/// not noise.
fn trim_trailing_void_return(stmts: &mut Vec<Stmt>, stats: &mut SimplifyStats) {
    if matches!(stmts.last(), Some(Stmt::Return { value: None })) {
        stmts.pop();
        stats.void_returns_trimmed += 1;
    }
}

// ─── Memory Update Fusion ───────────────────────────────────────────────
//
// Collapses the common lifter pattern for arithmetic on a memory operand:
//
//     a = *base;          // load
//     b = a OP x;         // arithmetic on the loaded value
//     flag_zf = ...;      // (optional, intervening flag assignment)
//     *base = b;          // store back
//
// into a single `(*base) OP= x` update. The intervening `flag_*` assignment
// (if any) is preserved with `a`/`b` substituted by their fused expressions,
// so carry/overflow flag consumers keep reading the correct value. This is
// the single biggest noise reducer for x86 mem-op (add/sub/and/or/xor [mem]).

fn deref_inner(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Deref(inner) => match inner.as_ref() {
            Expr::Cast { expr, .. } => Some((**expr).clone()),
            other => Some(other.clone()),
        },
        _ => None,
    }
}

fn is_fusable_op(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Sub | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

/// If `stmt` is `name = *base` (a plain load), return `(name, base)`.
fn load_of(stmt: &Stmt) -> Option<(String, Expr)> {
    if let Stmt::Assign {
        target: Expr::Var(name),
        value,
    } = stmt
    {
        if let Some(base) = deref_inner(value) {
            return Some((name.clone(), base));
        }
    }
    None
}

/// Substitute `Var` references from `map` throughout an expression.
fn subst_expr(expr: &Expr, map: &HashMap<String, Expr>) -> Expr {
    match expr {
        Expr::Var(n) => map.get(n).cloned().unwrap_or_else(|| expr.clone()),
        Expr::Binary { op, lhs, rhs } => Expr::Binary {
            op: *op,
            lhs: Box::new(subst_expr(lhs, map)),
            rhs: Box::new(subst_expr(rhs, map)),
        },
        Expr::Unary { op, operand } => Expr::Unary {
            op: *op,
            operand: Box::new(subst_expr(operand, map)),
        },
        Expr::Deref(x) => Expr::Deref(Box::new(subst_expr(x, map))),
        Expr::AddrOf(x) => Expr::AddrOf(Box::new(subst_expr(x, map))),
        Expr::Cast { ty, expr } => Expr::Cast {
            ty: ty.clone(),
            expr: Box::new(subst_expr(expr, map)),
        },
        Expr::Index { base, index } => Expr::Index {
            base: Box::new(subst_expr(base, map)),
            index: Box::new(subst_expr(index, map)),
        },
        Expr::Member { base, field } => Expr::Member {
            base: Box::new(subst_expr(base, map)),
            field: field.clone(),
        },
        Expr::Call { func, args } => Expr::Call {
            func: func.clone(),
            args: args.iter().map(|a| subst_expr(a, map)).collect(),
        },
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => Expr::Ternary {
            cond: Box::new(subst_expr(cond, map)),
            then_expr: Box::new(subst_expr(then_expr, map)),
            else_expr: Box::new(subst_expr(else_expr, map)),
        },
        other => other.clone(),
    }
}

fn subst_stmt(stmt: &Stmt, map: &HashMap<String, Expr>) -> Stmt {
    match stmt {
        Stmt::Assign { target, value } => Stmt::Assign {
            target: subst_expr(target, map),
            value: subst_expr(value, map),
        },
        _ => stmt.clone(),
    }
}

/// Fuse memory load/op/store triples in `stmts` and all nested bodies.
pub fn fuse_memory_updates(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fuse_memory_updates(then_body);
                if let Some(eb) = else_body {
                    fuse_memory_updates(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => fuse_memory_updates(body),
            Stmt::For { body, .. } => {
                fuse_memory_updates(body);
            }
            Stmt::Switch { cases, default, .. } => {
                for c in cases.iter_mut() {
                    fuse_memory_updates(&mut c.body);
                }
                if let Some(d) = default {
                    fuse_memory_updates(d);
                }
            }
            Stmt::Block(inner) => fuse_memory_updates(inner),
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
                fuse_memory_updates(try_body);
                fuse_memory_updates(catch_body);
            }
            _ => {}
        }
    }

    fuse_memory_updates_level(stmts);
}

fn fuse_memory_updates_level(stmts: &mut Vec<Stmt>) {
    let mut def_counts: HashMap<String, usize> = HashMap::new();
    count_var_defs_stmts(stmts, &mut def_counts);
    let mut use_counts: HashMap<String, usize> = HashMap::new();
    count_var_uses_stmts(stmts, &mut use_counts);

    let n = stmts.len();
    let mut out: Vec<Stmt> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        let mut fused = false;
        if let Some((a, base)) = load_of(&stmts[i]) {
            if def_counts.get(&a).copied().unwrap_or(0) == 1 {
                // Locate the arithmetic op: b = a OP operand.
                let mut j_op = None;
                #[allow(clippy::needless_range_loop)]
                for j in (i + 1)..n {
                    if let Stmt::Assign {
                        target: Expr::Var(b),
                        value,
                    } = &stmts[j]
                    {
                        if *b != a {
                            if let Expr::Binary { op, lhs, rhs } = value {
                                if is_fusable_op(*op)
                                    && **lhs == Expr::Var(a.clone())
                                    && def_counts.get(b).copied().unwrap_or(0) == 1
                                {
                                    j_op = Some((j, b.clone(), *op, (**rhs).clone()));
                                    break;
                                }
                            }
                        }
                    }
                }
                if let Some((j, b, op, operand)) = j_op {
                    // Locate the store back to the same base: *base = b.
                    let mut k_store = None;
                    #[allow(clippy::needless_range_loop)]
                    for k in (j + 1)..n {
                        if let Stmt::Assign {
                            target,
                            value: Expr::Var(v),
                        } = &stmts[k]
                        {
                            if *v == b && deref_inner(target) == Some(base.clone()) {
                                k_store = Some(k);
                                break;
                            }
                        }
                    }
                    if let Some(k) = k_store {
                        // Everything strictly between the op and the store must
                        // be an intervening flag assignment, a comment, or empty.
                        let mut ok = true;
                        let mut mids: Vec<usize> = Vec::new();
                        #[allow(clippy::needless_range_loop)]
                        for m in (j + 1)..k {
                            match &stmts[m] {
                                Stmt::Comment(_) | Stmt::Empty => {}
                                Stmt::Assign {
                                    target: Expr::Var(fn_),
                                    ..
                                } if fn_.starts_with("flag_") => mids.push(m),
                                _ => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            // Safety: `a` and `b` must not be referenced
                            // anywhere outside the matched region.
                            let mut a_region = 1usize; // op lhs reads `a`
                            let mut b_region = 1usize; // store value reads `b`
                            for &m in &mids {
                                let mut tmp = HashSet::new();
                                collect_used_vars_stmt(&stmts[m], &mut tmp);
                                if tmp.contains(&a) {
                                    a_region += 1;
                                }
                                if tmp.contains(&b) {
                                    b_region += 1;
                                }
                            }
                            let a_total = use_counts.get(&a).copied().unwrap_or(0);
                            let b_total = use_counts.get(&b).copied().unwrap_or(0);
                            if a_total == a_region && b_total == b_region {
                                let mut map: HashMap<String, Expr> = HashMap::new();
                                let load_expr = Expr::Deref(Box::new(base.clone()));
                                map.insert(a.clone(), load_expr.clone());
                                map.insert(
                                    b.clone(),
                                    Expr::Binary {
                                        op,
                                        lhs: Box::new(load_expr.clone()),
                                        rhs: Box::new(operand.clone()),
                                    },
                                );
                                for &m in &mids {
                                    out.push(subst_stmt(&stmts[m], &map));
                                }
                                out.push(Stmt::Assign {
                                    target: load_expr.clone(),
                                    value: Expr::Binary {
                                        op,
                                        lhs: Box::new(load_expr),
                                        rhs: Box::new(operand),
                                    },
                                });
                                i = k + 1;
                                fused = true;
                            }
                        }
                    }
                }
            }
        }
        if !fused {
            out.push(stmts[i].clone());
            i += 1;
        }
    }
    *stmts = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::Ty;

    #[test]
    fn test_ensure_declared_temps() {
        // `v42` is referenced but never declared: the pass must add a
        // declaration; already-declared `v7` stays untouched.
        let mut func = AstFunction {
            name: "t".into(),
            entry_address: 0,
            params: vec![],
            body: vec![Stmt::Assign {
                target: Expr::Var("v7".into()),
                value: Expr::Var("v42".into()),
            }],
            locals: vec![LocalVar {
                name: "v7".into(),
                ty: Ty::Int(32),
                is_used: true,
                fields: Vec::new(),
            }],
            return_type: Ty::Void,
            param_register_names: vec![],
        };
        let added = ensure_declared_temps(&mut func);
        assert_eq!(added, 1);
        assert!(func.locals.iter().any(|l| l.name == "v42"));
        // Second run is a no-op.
        assert_eq!(ensure_declared_temps(&mut func), 0);
    }

    #[test]
    fn test_dead_locals_removed() {
        // local `dead` is declared but never referenced → dropped;
        // `used` is read → kept; params are never in locals anyway.
        let mut func = AstFunction {
            name: "t".into(),
            entry_address: 0,
            params: vec![],
            locals: vec![
                LocalVar { name: "used".into(), ty: Ty::Int(32), is_used: true, fields: Vec::new() },
                LocalVar { name: "dead".into(), ty: Ty::Int(32), is_used: true, fields: Vec::new() },
            ],
            body: vec![
                Stmt::Assign { target: Expr::Var("used".into()), value: Expr::IntLit(1) },
                Stmt::Assign { target: Expr::Var("eax".into()), value: Expr::Var("used".into()) },
            ],
            return_type: Ty::Void,
            param_register_names: Vec::new(),
        };
        let mut stats = SimplifyStats::default();
        remove_dead_locals(&mut func, &mut stats);
        assert_eq!(stats.dead_locals_removed, 1);
        assert_eq!(func.locals.len(), 1);
        assert_eq!(func.locals[0].name, "used");
    }

    #[test]
    fn test_self_assign_removed() {
        let mut func = AstFunction {
            name: "t".into(),
            entry_address: 0,
            params: vec![],
            locals: vec![],
            body: vec![
                Stmt::Assign { target: Expr::Var("v".into()), value: Expr::Var("v".into()) },
                Stmt::Assign { target: Expr::Var("v".into()), value: Expr::IntLit(2) },
            ],
            return_type: Ty::Void,
            param_register_names: Vec::new(),
        };
        let mut stats = SimplifyStats::default();
        remove_dead_locals(&mut func, &mut stats);
        assert_eq!(stats.self_assigns_removed, 1);
        assert_eq!(func.body.len(), 1);
    }

    #[test]
    fn test_self_assign_removed_nested() {
        let mut func = AstFunction {
            name: "t".into(),
            entry_address: 0,
            params: vec![],
            locals: vec![],
            body: vec![Stmt::If {
                cond: Expr::BoolLit(true),
                then_body: vec![Stmt::Assign {
                    target: Expr::Var("x".into()),
                    value: Expr::Var("x".into()),
                }],
                else_body: None,
            }],
            return_type: Ty::Void,
            param_register_names: Vec::new(),
        };
        let mut stats = SimplifyStats::default();
        remove_dead_locals(&mut func, &mut stats);
        assert_eq!(stats.self_assigns_removed, 1);
        match &func.body[0] {
            Stmt::If { then_body, .. } => assert!(then_body.is_empty()),
            other => panic!("unexpected stmt: {other:?}"),
        }
    }

    #[test]
    fn test_trim_trailing_continue_and_void_return() {
        // while body ending in `continue` → trimmed; void fn trailing `return;` → trimmed
        let mut func = AstFunction {
            name: "t".into(),
            entry_address: 0,
            params: vec![],
            locals: vec![],
            body: vec![Stmt::While {
                cond: Expr::Binary {
                    op: BinOp::Lt,
                    lhs: Box::new(Expr::Var("i".into())),
                    rhs: Box::new(Expr::IntLit(10)),
                },
                body: vec![
                    Stmt::Expr(Expr::Call {
                        func: "f".into(),
                        args: vec![],
                    }),
                    Stmt::Continue,
                ],
            }],
            return_type: freakre_ir::Ty::Void,
            param_register_names: vec![],
        };
        let stats = simplify_function_with_stats(&mut func);
        assert_eq!(stats.continue_trimmed, 1, "{}", stats.tally());
        assert_eq!(stats.void_returns_trimmed, 0);
        assert_eq!(func.body.len(), 1);

        // Top-level trailing `return;` in a void function
        let mut func2 = AstFunction {
            name: "t2".into(),
            entry_address: 0,
            params: vec![],
            locals: vec![],
            body: vec![
                Stmt::Expr(Expr::Call {
                    func: "g".into(),
                    args: vec![],
                }),
                Stmt::Return { value: None },
            ],
            return_type: freakre_ir::Ty::Void,
            param_register_names: vec![],
        };
        let stats2 = simplify_function_with_stats(&mut func2);
        assert_eq!(stats2.void_returns_trimmed, 1, "{}", stats2.tally());
        assert_eq!(func2.body.len(), 1);

        // Non-void return of value must be kept
        let mut func3 = AstFunction {
            name: "t3".into(),
            entry_address: 0,
            params: vec![],
            locals: vec![],
            body: vec![
                Stmt::Expr(Expr::Call {
                    func: "g".into(),
                    args: vec![],
                }),
                Stmt::Return {
                    value: Some(Expr::IntLit(1)),
                },
            ],
            return_type: freakre_ir::Ty::i64(),
            param_register_names: vec![],
        };
        let _ = simplify_function_with_stats(&mut func3);
        assert_eq!(func3.body.len(), 2);
    }

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

        // The v0 def is consumed by the Deref store (copy-propagated into
        // it), and the trailing bare `return;` is trimmed by pass 5c
        // (void function) — only the store itself remains.
        assert_eq!(
            func.body.len(),
            1,
            "dead v0 definition must be removed: {:?}",
            func.body
        );
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
        func.body.push(Stmt::Return {
            value: Some(Expr::Var("v0".into())),
        });

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
            Stmt::Assign {
                target: Expr::Var(name),
                value,
            } => {
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
            value: Expr::Call {
                func: "sub_140001675".into(),
                args: vec![],
            },
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
        func.body.push(Stmt::Return {
            value: Some(Expr::Var("rax".into())),
        });

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

        // `rsp = rsp + 8` removed by stack-noise cleanup, trailing bare
        // `return;` trimmed by pass 5c (void function) → two statements.
        assert_eq!(func.body.len(), 2, "only `rsp = rsp + 8` is removed");
        assert!(
            matches!(
                &func.body[0],
                Stmt::Assign {
                    target: Expr::Deref(_),
                    ..
                }
            ),
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
        func.body.push(Stmt::Return {
            value: Some(Expr::Var("rax".into())),
        });
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
                Stmt::If {
                    cond: Expr::Binary { op: BinOp::Eq, .. },
                    ..
                }
            )
        });
        assert!(folded, "cond should be Binary Eq after pipeline");
    }

    #[test]
    fn test_fuse_load_op_store_with_flag() {
        let mut body = vec![
            Stmt::Assign {
                target: Expr::Var("a".to_string()),
                value: Expr::Deref(Box::new(Expr::Var("rbx".to_string()))),
            },
            Stmt::Assign {
                target: Expr::Var("b".to_string()),
                value: Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Var("a".to_string())),
                    rhs: Box::new(Expr::Var("al".to_string())),
                },
            },
            Stmt::Assign {
                target: Expr::Var("flag_cf".to_string()),
                value: Expr::Binary {
                    op: BinOp::LtU,
                    lhs: Box::new(Expr::Var("b".to_string())),
                    rhs: Box::new(Expr::Var("a".to_string())),
                },
            },
            Stmt::Assign {
                target: Expr::Deref(Box::new(Expr::Var("rbx".to_string()))),
                value: Expr::Var("b".to_string()),
            },
        ];
        fuse_memory_updates(&mut body);

        // load + op + flag + store → flag (substituted) + fused store
        assert_eq!(body.len(), 2);
        match &body[1] {
            Stmt::Assign { target, value } => {
                assert_eq!(target, &Expr::Deref(Box::new(Expr::Var("rbx".to_string()))));
                assert_eq!(
                    value,
                    &Expr::Binary {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Deref(Box::new(Expr::Var("rbx".to_string())))),
                        rhs: Box::new(Expr::Var("al".to_string())),
                    }
                );
            }
            _ => panic!("expected fused store, got {:?}", body[1]),
        }
    }

    #[test]
    fn test_fuse_does_not_fire_on_external_use() {
        // `b` is used after the store too, so fusion must NOT happen.
        let mut body = vec![
            Stmt::Assign {
                target: Expr::Var("a".to_string()),
                value: Expr::Deref(Box::new(Expr::Var("rbx".to_string()))),
            },
            Stmt::Assign {
                target: Expr::Var("b".to_string()),
                value: Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Var("a".to_string())),
                    rhs: Box::new(Expr::Var("al".to_string())),
                },
            },
            Stmt::Assign {
                target: Expr::Deref(Box::new(Expr::Var("rbx".to_string()))),
                value: Expr::Var("b".to_string()),
            },
            Stmt::Assign {
                target: Expr::Var("c".to_string()),
                value: Expr::Var("b".to_string()),
            },
        ];
        fuse_memory_updates(&mut body);
        assert_eq!(body.len(), 4, "fusion must not drop externally-used temps");
    }
}

/// Safety net for malformed input: any `vN` temporary referenced in the
/// AST but never declared (its defining instruction was dropped along a
/// dangling block) gets a scalar declaration, so the emitted C always
/// compiles. Returns how many declarations were added.
pub fn ensure_declared_temps(func: &mut AstFunction) -> usize {
    fn is_vtemp(name: &str) -> bool {
        let bytes = name.as_bytes();
        bytes.len() > 1
            && bytes[0] == b'v'
            && bytes[1..].iter().all(|b| b.is_ascii_digit())
    }

    let mut declared: BTreeSet<String> = func
        .locals
        .iter()
        .filter(|l| is_vtemp(&l.name))
        .map(|l| l.name.clone())
        .collect();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for stmt in &func.body {
        stmt.for_each_expr(&mut |e| {
            if let Expr::Var(name) = e {
                if is_vtemp(name) {
                    used.insert(name.clone());
                }
            }
        });
    }
    let missing: Vec<String> = used.difference(&declared).cloned().collect();
    for name in &missing {
        func.locals.push(LocalVar {
            name: name.clone(),
            ty: freakre_ir::Ty::Int(64),
            is_used: true,
            fields: Vec::new(),
        });
        declared.insert(name.clone());
    }
    missing.len()
}
