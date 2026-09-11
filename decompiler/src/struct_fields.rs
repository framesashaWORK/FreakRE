//! Struct-field recovery: fold `*(T*)(base + off)` into `base->field_0xNN`.
//!
//! A pointer-typed variable that is dereferenced at constant offsets has a
//! struct layout: each (offset, width) pair becomes a field. The pass is
//! conservative:
//! - only `Var` bases (locals/params), never expressions;
//! - negative offsets are left untouched;
//! - reads *through* the base (`*base`, offset 0) also become fields only
//!   when the base is dereferenced with a cast (typed access);
//! - layouts are declared on the matching `LocalVar` for C struct printing.

use crate::ast::{AstFunction, BinOp, Expr, Stmt};
use freakre_ir::Ty;
use std::collections::BTreeMap;

/// Recovered field list per base variable name: (offset, width) → use count.
type Layouts = BTreeMap<String, BTreeMap<(u64, u8), usize>>;

/// Run struct-field recovery over a decompiled function.
/// Returns the number of distinct fields recovered.
/// Recover struct fields with a visibility threshold: a (base, offset) pair
/// becomes a field only when accessed at the same width at least `min_uses`
/// times. `min_uses = 1` recovers every cast shape (unit tests), `2` is the
/// production default (keeps one-off pointer casts untouched).
pub fn recover_struct_fields(func: &mut AstFunction, min_uses: usize) -> usize {
    let mut layouts = Layouts::new();
    scan_stmts(&func.body, &mut layouts);
    if layouts.is_empty() {
        return 0;
    }
    // Apply the threshold: keep only offsets seen >= min_uses times.
    layouts.retain(|_, offs| {
        offs.retain(|_, count| *count >= min_uses);
        !offs.is_empty()
    });
    if layouts.is_empty() {
        return 0;
    }

    rewrite_stmts(&mut func.body, &layouts);

    let mut count = 0usize;
    for local in func.locals.iter_mut() {
        if let Some(offs) = layouts.get(&local.name) {
            if !offs.is_empty() {
                local.fields = offs
                    .iter()
                    .map(|((off, w), _)| (*off, field_name(*off), *w))
                    .collect();
                count += offs.len();
            }
        }
    }
    count
}

/// `field_0x10` style field name (matches IDA conventions).
fn field_name(off: u64) -> String {
    format!("field_{:#x}", off)
}

/// Pointee type for an access width (bytes).
fn width_ty(w: u8) -> Ty {
    match w {
        1 => Ty::UInt(8),
        2 => Ty::UInt(16),
        8 => Ty::UInt(64),
        // 4 and anything else: signed int like the rest of the decompiler.
        _ => Ty::Int(32),
    }
}

/// First pass: collect (base, offset, width) triples from Deref-of-Cast shapes.
fn scan_stmts(stmts: &[Stmt], out: &mut Layouts) {
    for s in stmts {
        scan_stmt(s, out);
    }
}

fn scan_stmt(stmt: &Stmt, out: &mut Layouts) {
    match stmt {
        Stmt::Assign { target, value } => {
            scan_expr(target, out);
            scan_expr(value, out);
        }
        Stmt::Expr(e) => scan_expr(e, out),
        Stmt::If { cond, then_body, else_body, .. } => {
            scan_expr(cond, out);
            scan_stmts(then_body, out);
            if let Some(eb) = else_body {
                scan_stmts(eb, out);
            }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
            scan_expr(cond, out);
            scan_stmts(body, out);
        }
        Stmt::For { init, cond, update, body, .. } => {
            if let Some(i) = init {
                scan_stmt(i, out);
            }
            if let Some(c) = cond {
                scan_expr(c, out);
            }
            if let Some(u) = update {
                scan_stmt(u, out);
            }
            scan_stmts(body, out);
        }
        Stmt::Return { value: Some(e), .. } => scan_expr(e, out),
        Stmt::Switch { expr, cases, default } => {
            scan_expr(expr, out);
            for case in cases {
                scan_stmts(&case.body, out);
            }
            if let Some(d) = default {
                scan_stmts(d, out);
            }
        }
        _ => {}
    }
}

fn scan_expr(e: &Expr, out: &mut Layouts) {
    match e {
        Expr::Binary { lhs, rhs, .. } => {
            scan_expr(lhs, out);
            scan_expr(rhs, out);
        }
        Expr::Unary { operand, .. }
        | Expr::Deref(operand)
        | Expr::AddrOf(operand)
        | Expr::Sizeof(operand) => scan_expr(operand, out),
        Expr::Field { base, .. } => scan_expr(base, out),
        Expr::Call { args, .. } => {
            for a in args {
                scan_expr(a, out);
            }
        }
        Expr::Index { base, index } => {
            scan_expr(base, out);
            scan_expr(index, out);
        }
        Expr::Member { base, .. } => scan_expr(base, out),
        Expr::Cast { expr, .. } => scan_expr(expr, out),
        Expr::Ternary { cond, then_expr, else_expr } => {
            scan_expr(cond, out);
            scan_expr(then_expr, out);
            scan_expr(else_expr, out);
        }
        _ => {}
    }
    if let Some((base, off, w)) = field_shape(e) {
        *out.entry(base).or_default().entry((off, w)).or_insert(0) += 1;
    }
}

/// Recognize `*(T*)(base + off)` where base is a Var.
/// Returns (base name, offset, access width in bytes) when the shape matches.
fn field_shape(e: &Expr) -> Option<(String, u64, u8)> {
    let Expr::Deref(inner) = e else { return None };
    let Expr::Cast { ty, expr: addr } = inner.as_ref() else {
        return None;
    };
    let Ty::Ptr(pointee) = ty else { return None };
    let width = match pointee.as_ref() {
        Ty::UInt(n) | Ty::Int(n) if [8u32, 16, 32, 64].contains(n) => (n / 8) as u8,
        _ => return None,
    };
    let (base, off) = match addr.as_ref() {
        Expr::Binary { op: BinOp::Add | BinOp::Sub, lhs, rhs } => {
            // base ± constant; negative results are rejected to stay safe.
            let (var, lit) = match (lhs.as_ref(), rhs.as_ref()) {
                (v, Expr::IntLit(o)) => (v, *o),
                (Expr::IntLit(o), v) => (v, *o),
                _ => return None,
            };
            if lit < 0 {
                return None;
            }
            let Expr::Var { 0: name } = var else { return None };
            // Stack slots (rsp/rbp-relative) belong to stack-var recovery,
            // not struct fields — otherwise every prologue spill prints as
            // `rsp->field_0xNN`.
            if matches!(name.as_str(), "rsp" | "esp" | "rbp" | "ebp") {
                return None;
            }
            (name.clone(), lit as u64)
        }
        Expr::Var { 0: name } => (name.clone(), 0),
        _ => return None,
    };
    Some((base, off, width))
}

/// Second pass: rewrite matching derefs into Field nodes.
fn rewrite_stmts(stmts: &mut [Stmt], stable: &Layouts) {
    for s in stmts {
        rewrite_stmt(s, stable);
    }
}

fn rewrite_stmt(stmt: &mut Stmt, stable: &Layouts) {
    match stmt {
        Stmt::Assign { target, value } => {
            rewrite_expr(target, stable);
            rewrite_expr(value, stable);
        }
        Stmt::Expr(e) => rewrite_expr(e, stable),
        Stmt::If { cond, then_body, else_body, .. } => {
            rewrite_expr(cond, stable);
            rewrite_stmts(then_body, stable);
            if let Some(eb) = else_body {
                rewrite_stmts(eb, stable);
            }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
            rewrite_expr(cond, stable);
            rewrite_stmts(body, stable);
        }
        Stmt::For { init, cond, update, body, .. } => {
            if let Some(i) = init {
                rewrite_stmt(i, stable);
            }
            if let Some(c) = cond {
                rewrite_expr(c, stable);
            }
            if let Some(u) = update {
                rewrite_stmt(u, stable);
            }
            rewrite_stmts(body, stable);
        }
        Stmt::Return { value: Some(e), .. } => rewrite_expr(e, stable),
        Stmt::Switch { expr, cases, default } => {
            rewrite_expr(expr, stable);
            for case in cases.iter_mut() {
                rewrite_stmts(&mut case.body, stable);
            }
            if let Some(d) = default {
                rewrite_stmts(d, stable);
            }
        }
        _ => {}
    }
}

fn rewrite_expr(e: &mut Expr, stable: &Layouts) {
    e.rewrite_subexprs(&mut |sub: &mut Expr| {
        if let Some((base, off, w)) = field_shape(sub) {
            if let Some(offs) = stable.get(&base) {
                if offs.contains_key(&(off, w)) {
                    *sub = Expr::Field {
                        base: Box::new(Expr::Var(base)),
                        field: field_name(off),
                        ty: width_ty(w),
                    };
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::LocalVar;

    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }

    /// `*(int32_t*)(a1 + 0x10)` shape.
    fn deref_field(base: &str, off: i64) -> Expr {
        Expr::Deref(Box::new(Expr::Cast {
            ty: Ty::Ptr(Box::new(Ty::Int(32))),
            expr: Box::new(Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(var(base)),
                rhs: Box::new(Expr::IntLit(off)),
            }),
        }))
    }

    #[test]
    fn repeated_accesses_become_fields() {
        let mut f = AstFunction::new("t");
        f.locals.push(LocalVar {
            name: "a1".into(),
            ty: Ty::UInt(64),
            is_used: true,
            fields: Vec::new(),
        });
        // Two reads of the same field (threshold = 2).
        f.body.push(Stmt::Assign {
            target: var("x"),
            value: deref_field("a1", 0x10),
        });
        f.body.push(Stmt::Assign {
            target: var("y"),
            value: deref_field("a1", 0x10),
        });
        let n = recover_struct_fields(&mut f, 2);
        assert_eq!(n, 1, "one distinct field recovered");
        assert_eq!(f.locals[0].fields, vec![(0x10, "field_0x10".into(), 4)]);
        // Both accesses rewritten.
        let rendered = format!("{:?}", f.body[0]);
        assert!(rendered.contains("Field"), "body not rewritten: {}", rendered);
    }

    #[test]
    fn single_use_not_rewritten() {
        let mut f = AstFunction::new("t");
        f.locals.push(LocalVar {
            name: "a1".into(),
            ty: Ty::UInt(64),
            is_used: true,
            fields: Vec::new(),
        });
        f.body.push(Stmt::Assign {
            target: var("x"),
            value: deref_field("a1", 0x20),
        });
        let n = recover_struct_fields(&mut f, 2);
        assert_eq!(n, 0, "single access must stay a raw deref");
    }

    #[test]
    fn differing_widths_are_separate_fields() {
        let mut f = AstFunction::new("t");
        f.locals.push(LocalVar {
            name: "p".into(),
            ty: Ty::UInt(64),
            is_used: true,
            fields: Vec::new(),
        });
        // Same offset, different widths: 2 distinct shapes.
        f.body.push(Stmt::Assign {
            target: var("a"),
            value: deref_field("p", 0x8),
        });
        f.body.push(Stmt::Assign {
            target: var("b"),
            value: deref_field("p", 0x8),
        });
        f.body.push(Stmt::Assign {
            target: var("c"),
            value: Expr::Deref(Box::new(Expr::Cast {
                ty: Ty::Ptr(Box::new(Ty::UInt(8))),
                expr: Box::new(Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(var("p")),
                    rhs: Box::new(Expr::IntLit(0x8)),
                }),
            })),
        });
        f.body.push(Stmt::Assign {
            target: var("d"),
            value: Expr::Deref(Box::new(Expr::Cast {
                ty: Ty::Ptr(Box::new(Ty::UInt(8))),
                expr: Box::new(Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(var("p")),
                    rhs: Box::new(Expr::IntLit(0x8)),
                }),
            })),
        });
        let n = recover_struct_fields(&mut f, 2);
        assert_eq!(n, 2, "int32@0x8 and uint8@0x8 are distinct fields");
        let offs: Vec<u64> = f.locals[0].fields.iter().map(|(o, _, _)| *o).collect();
        assert_eq!(offs, vec![0x8, 0x8]);
    }
}
