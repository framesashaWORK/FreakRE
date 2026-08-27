//! Compiler pattern recognition for decompiled code.
//!
//! Detects and transforms compiler-generated idioms into high-level constructs:
//! - Virtual call resolution (vtable dispatch)
//! - Memory operation idioms (memcpy, memset, strlen)
//! - Security cookie / stack canary removal
//! - Switch table patterns (jump tables, binary search, computed gotos)
//! - Compiler prologue/epilogue normalization

use crate::ast::*;

/// Run all pattern recognition passes on an AST function (in-place).
pub fn recognize_patterns(func: &mut AstFunction) {
    // Pass 1: Remove security cookies
    remove_security_cookies(&mut func.body);

    // Pass 2: Detect virtual calls
    detect_virtual_calls(&mut func.body);

    // Pass 3: Detect memory idioms
    detect_memory_idioms(&mut func.body);

    // Pass 4: Normalize compiler artifacts
    normalize_prologue_epilogue(&mut func.body);

    // Pass 5: No-op assignments + empty-then if inversion
    cleanup_noops_and_empty_branches(&mut func.body);
}

fn expr_is_var_eq(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::Var(x), Expr::Var(y)) => x == y,
        _ => false,
    }
}

fn cleanup_noops_and_empty_branches(stmts: &mut Vec<Stmt>) {
    stmts.retain(|s| match s {
        Stmt::Assign { target, value } => !expr_is_var_eq(target, value),
        Stmt::Expr(Expr::IntLit(_)) | Stmt::Expr(Expr::BoolLit(_)) => false,
        _ => true,
    });

    for s in stmts.iter_mut() {
        match s {
            Stmt::If { cond, then_body, else_body } => {
                cleanup_noops_and_empty_branches(then_body);
                if let Some(eb) = else_body {
                    cleanup_noops_and_empty_branches(eb);
                }
                let then_empty = then_body.is_empty();
                let else_nonempty = else_body.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
                if then_empty && else_nonempty {
                    *cond = Expr::Unary {
                        op: UnOp::LogNot,
                        operand: Box::new(std::mem::replace(
                            cond,
                            Expr::BoolLit(true),
                        )),
                    };
                    let taken = std::mem::take(then_body);
                    if let Some(eb) = else_body.take() {
                        *then_body = eb;
                        *else_body = Some(taken);
                    } else {
                        *then_body = taken;
                    }
                }
                if let Some(eb) = else_body {
                    if eb.is_empty() {
                        *else_body = None;
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                cleanup_noops_and_empty_branches(body);
            }
            Stmt::Block(b) => cleanup_noops_and_empty_branches(b),
            _ => {}
        }
    }
}

// ─── Security Cookie Removal ────────────────────────────────────────

/// Remove stack canary check sequences, replacing with comments.
#[allow(clippy::ptr_arg)]
fn remove_security_cookies(stmts: &mut Vec<Stmt>) {
    let mut i = 0;
    while i < stmts.len() {
        // Pattern: XOR(var, frame_ptr) followed later by XOR(var, frame_ptr) + CMP
        // Simplified: look for assignments involving __security_cookie
        if is_security_cookie_stmt(&stmts[i]) {
            stmts[i] = Stmt::Comment("stack canary".into());
        }
        // Recurse into nested structures
        recurse_into_stmt_mut(&mut stmts[i], remove_security_cookies);
        i += 1;
    }
}

fn is_security_cookie_stmt(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign { value, .. } => expr_contains_symbol(value, "__security_cookie"),
        Stmt::Expr(e) => expr_contains_symbol(e, "__security_cookie"),
        Stmt::Call { func, .. } => func.contains("security_cookie") || func.contains("__stack_chk"),
        _ => false,
    }
}

fn expr_contains_symbol(expr: &Expr, symbol: &str) -> bool {
    match expr {
        Expr::Var(name) => name.contains(symbol),
        Expr::Binary { lhs, rhs, .. } => {
            expr_contains_symbol(lhs, symbol) || expr_contains_symbol(rhs, symbol)
        }
        Expr::Unary { operand, .. } => expr_contains_symbol(operand, symbol),
        Expr::Call { func, args } => {
            func.contains(symbol) || args.iter().any(|a| expr_contains_symbol(a, symbol))
        }
        Expr::Deref(e) | Expr::AddrOf(e) => expr_contains_symbol(e, symbol),
        _ => false,
    }
}

// ─── Virtual Call Detection ─────────────────────────────────────────

/// Transform vtable dispatch patterns into method calls.
///
/// Pattern: `vt = *obj; fn = *(vt + off); fn(args...)`
/// Becomes: `obj->vfunc_off(args...)`
#[allow(clippy::ptr_arg)]
fn detect_virtual_calls(stmts: &mut Vec<Stmt>) {
    let mut i = 0;
    while i < stmts.len() {
        // Three-statement pattern: vtable load → method-pointer load → call
        // through that pointer.
        //
        //   [i]     vt  = *obj
        //   [i+1]   fp  = *(vt + off)          (or fp = *vt)
        //   [i+2]   ... = fp(args) / fp(args);
        if i + 2 < stmts.len() {
            let vt_name = match &stmts[i] {
                Stmt::Assign { target: Expr::Var(v), value: Expr::Deref(_) } => Some(v.clone()),
                _ => None,
            };
            if let Some(vt_name) = vt_name {
                // Method pointer loaded from the vtable variable?
                let fp_load: Option<(String, u64)> = match &stmts[i + 1] {
                    Stmt::Assign { target: Expr::Var(fp), value } => {
                        extract_pointer_load(value, &vt_name)
                            .map(|off| (fp.clone(), off))
                    }
                    _ => None,
                };
                if let Some((fp_name, offset)) = fp_load {
                    // Call through fp?
                    let call_matches = match &stmts[i + 2] {
                        Stmt::Call { func, .. } => func == &fp_name,
                        Stmt::Expr(Expr::Call { func, .. }) => func == &fp_name,
                        Stmt::Assign { value: Expr::Call { func, .. }, .. } => func == &fp_name,
                        _ => false,
                    };
                    if call_matches {
                        let obj_expr = match &stmts[i] {
                            Stmt::Assign { value: Expr::Deref(base), .. } => (**base).clone(),
                            _ => Expr::Var(vt_name.clone()),
                        };
                        let args = match &stmts[i + 2] {
                            Stmt::Call { args, .. }
                            | Stmt::Expr(Expr::Call { args, .. })
                            | Stmt::Assign { value: Expr::Call { args, .. }, .. } => args.clone(),
                            _ => Vec::new(),
                        };
                        stmts[i] = Stmt::Comment(format!(
                            "vtable dispatch @ offset 0x{:X}",
                            offset
                        ));
                        stmts[i + 1] = Stmt::Empty;
                        stmts[i + 2] = Stmt::Expr(Expr::Call {
                            func: format!("{}.vfunc_0x{:X}", expr_to_simple_string(&obj_expr), offset),
                            args,
                        });
                    }
                }
            }
        }

        // Two-statement pattern for already-resolved names (kept for compat).
        if i + 1 < stmts.len() {
            if let Stmt::Assign { target: Expr::Var(vtable_var), value: Expr::Deref(base) } = &stmts[i] {
                if let Stmt::Assign { value: Expr::Call { func, args }, .. }
                | Stmt::Call { func, args } = &stmts[i + 1]
                {
                    if !matches!(func.as_str(), "goto" | "syscall") && func.starts_with("vfunc_") {
                        if let Some(offset) = extract_vtable_offset(func, vtable_var) {
                            let obj_expr = (**base).clone();
                            stmts[i + 1] = Stmt::Expr(Expr::Call {
                                func: format!("{}.{}", expr_to_simple_string(&obj_expr), func),
                                args: args.clone(),
                            });
                            stmts[i] = Stmt::Comment(format!("vtable dispatch @ offset 0x{:X}", offset));
                        }
                    }
                }
            }
        }

        recurse_into_stmt_mut(&mut stmts[i], detect_virtual_calls);
        i += 1;
    }
}

/// If `value` is a load through `vt` (`*vt` or `*vt + off` wrapped in casts),
/// return the vtable slot offset.
fn extract_pointer_load(value: &Expr, vt_name: &str) -> Option<u64> {
    match value {
        Expr::Deref(inner) => match inner.as_ref() {
            Expr::Var(name) if name == vt_name => Some(0),
            Expr::Binary { op: BinOp::Add, lhs, rhs } => {
                let (var_part, lit_part) = if matches!(lhs.as_ref(), Expr::Var(n) if n == vt_name) {
                    (lhs.as_ref(), rhs.as_ref())
                } else if matches!(rhs.as_ref(), Expr::Var(n) if n == vt_name) {
                    (rhs.as_ref(), lhs.as_ref())
                } else {
                    return None;
                };
                if let Expr::IntLit(off) = lit_part {
                    if matches!(var_part, Expr::Var(n) if n == vt_name) {
                        return Some(*off as u64);
                    }
                }
                None
            }
            _ => None,
        },
        _ => None,
    }
}

fn extract_vtable_offset(func_name: &str, _vtable_var: &str) -> Option<u64> {
    // If func_name looks like a resolved vtable offset
    if func_name.starts_with("vfunc_") {
        let hex = func_name.strip_prefix("vfunc_0x").or_else(|| func_name.strip_prefix("vfunc_"))?;
        u64::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

fn expr_to_simple_string(expr: &Expr) -> String {
    match expr {
        Expr::Var(name) => name.clone(),
        Expr::Deref(inner) => format!("*{}", expr_to_simple_string(inner)),
        Expr::Member { base, field } => format!("{}.{}", expr_to_simple_string(base), field),
        _ => "_obj".into(),
    }
}

// ─── Memory Idiom Detection ─────────────────────────────────────────

/// Detect unrolled memcpy/memset/strlen patterns and replace with function calls.
fn detect_memory_idioms(stmts: &mut Vec<Stmt>) {
    // Detect repeated store patterns → memset
    detect_memset_pattern(stmts);
    // Detect repeated load-store pairs → memcpy
    detect_memcpy_pattern(stmts);
    // Recurse
    for stmt in stmts.iter_mut() {
        recurse_into_stmt_mut(stmt, detect_memory_idioms);
    }
}

fn detect_memset_pattern(stmts: &mut Vec<Stmt>) {
    // Look for ≥3 consecutive stores of 0 to sequential addresses (base + 4*i)
    let mut i = 0;
    while i + 3 <= stmts.len() {
        let run = match &stmts[i] {
            Stmt::Assign { target: Expr::Deref(addr1), value: val1 } if is_zero_expr(val1) => {
                store_addr_info(addr1)
            }
            _ => None,
        };

        if let Some((base, off0)) = run {
            let mut count = 0usize;
            while i + count < stmts.len() {
                let ok = match &stmts[i + count] {
                    Stmt::Assign { target: Expr::Deref(a), value: v } => {
                        is_zero_expr(v)
                            && matches!(
                                store_addr_info(a),
                                Some((b, off)) if b == base && off == off0 + count as i64 * 4
                            )
                    }
                    _ => false,
                };
                if ok {
                    count += 1;
                } else {
                    break;
                }
            }

            if count >= 3 {
                if let Stmt::Assign { target: Expr::Deref(ptr_expr), .. } = &stmts[i] {
                    let ptr_expr = (**ptr_expr).clone();
                    stmts[i] = Stmt::Call {
                        func: "memset".into(),
                        args: vec![
                            ptr_expr,
                            Expr::IntLit(0),
                            Expr::IntLit(count as i64 * 4),
                        ],
                    };
                    stmts.drain((i + 1)..(i + count));
                }
            }
        }
        i += 1;
    }
}

/// Extract (base variable name, constant offset) from a store address expression.
fn store_addr_info(addr: &Expr) -> Option<(String, i64)> {
    match addr {
        Expr::Var(name) => Some((name.clone(), 0)),
        Expr::Binary { op: BinOp::Add, lhs, rhs } => {
            if let (Expr::Var(name), Expr::IntLit(off)) = (&**lhs, &**rhs) {
                return Some((name.clone(), *off));
            }
            if let (Expr::IntLit(off), Expr::Var(name)) = (&**lhs, &**rhs) {
                return Some((name.clone(), *off));
            }
            None
        }
        _ => None,
    }
}

fn detect_memcpy_pattern(stmts: &mut Vec<Stmt>) {
    // Detect unrolled memcpy: tmp = *src; *dst = tmp; tmp2 = *(src+4); *(dst+4) = tmp2; ...
    // At least 2 pairs with base+0, base+4, base+8 etc.
    let mut i = 0;
    while i + 1 < stmts.len() {
        // Look for Load then Store pair
        let (src_base, src_off, tmp_name) = match &stmts[i] {
            Stmt::Assign { target: Expr::Var(tmp), value: Expr::Deref(addr) } => {
                if let Some((base, off)) = store_addr_info(addr) {
                    (base, off, tmp.clone())
                } else { i+=1; continue; }
            }
            _ => { i+=1; continue; }
        };
        let (dst_base, dst_off) = match &stmts[i+1] {
            Stmt::Assign { target: Expr::Deref(addr), value: Expr::Var(v) } if v == &tmp_name => {
                if let Some((base, off)) = store_addr_info(addr) {
                    (base, off)
                } else { i+=1; continue; }
            }
            _ => { i+=1; continue; }
        };
        // Found first pair, check for sequential pairs
        let mut count = 1;
        let mut last_src_off = src_off;
        let mut last_dst_off = dst_off;
        while i + count*2 + 1 < stmts.len() {
            let src_idx = i + count*2;
            let dst_idx = i + count*2 + 1;
            let src_ok = match &stmts[src_idx] {
                Stmt::Assign { target: Expr::Var(tmp), value: Expr::Deref(addr) } => {
                    if let Some((base, off)) = store_addr_info(addr) {
                        base == src_base && off == last_src_off + 4 && tmp != &tmp_name
                    } else { false }
                }
                _ => false,
            };
            let dst_ok = match &stmts[dst_idx] {
                Stmt::Assign { target: Expr::Deref(addr), value: Expr::Var(v) } => {
                    // Need to check that v is the tmp from previous src
                    if let Stmt::Assign { target: Expr::Var(tmp2), .. } = &stmts[src_idx] {
                        if v != tmp2 { false } else {
                            if let Some((base, off)) = store_addr_info(addr) {
                                base == dst_base && off == last_dst_off + 4
                            } else { false }
                        }
                    } else { false }
                }
                _ => false,
            };
            if src_ok && dst_ok {
                count += 1;
                last_src_off += 4;
                last_dst_off += 4;
            } else {
                break;
            }
        }
        if count >= 2 {
            // Replace with memcpy call
            let src_expr = Expr::Var(src_base.clone());
            let dst_expr = Expr::Var(dst_base.clone());
            stmts[i] = Stmt::Call { func: "memcpy".into(), args: vec![dst_expr, src_expr, Expr::IntLit(count as i64 * 4)] };
            stmts.drain((i+1)..(i+count*2));
        }
        i += 1;
    }
}

fn is_zero_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::IntLit(0))
}

// ─── Prologue/Epilogue Normalization ────────────────────────────────

/// Annotate compiler-generated prologue/epilogue code.
fn normalize_prologue_epilogue(stmts: &mut Vec<Stmt>) {
    // Remove leading NOPs and frame setup comments
    while let Some(Stmt::Empty) = stmts.first() {
        stmts.remove(0);
    }

    // Annotate alloca-like patterns (keep the assignment — removing it would
    // change the value of rsp/esp for later statements).
    let mut i = 0;
    while i < stmts.len() {
        let is_frame_alloc = matches!(
            &stmts[i],
            Stmt::Assign { target: Expr::Var(name), value: Expr::Binary { op: BinOp::Sub, .. } }
                if name == "esp" || name == "rsp"
        );
        if is_frame_alloc {
            let original = std::mem::replace(&mut stmts[i], Stmt::Empty);
            stmts[i] = Stmt::Block(vec![
                original,
                Stmt::Comment("frame allocation".into()),
            ]);
        } else {
            recurse_into_stmt_mut(&mut stmts[i], normalize_prologue_epilogue);
        }
        i += 1;
    }
}

// ─── Utility: Recursive Statement Mutation ──────────────────────────

fn recurse_into_stmt_mut<F>(stmt: &mut Stmt, f: F)
where
    F: Fn(&mut Vec<Stmt>) + Copy,
{
    match stmt {
        Stmt::If { then_body, else_body, .. } => {
            f(then_body);
            if let Some(eb) = else_body { f(eb); }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => { f(body); }
        Stmt::For { body, .. } => { f(body); }
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() { f(&mut c.body); }
            if let Some(d) = default { f(d); }
        }
        Stmt::Block(inner) => { f(inner); }
        Stmt::TryCatch { try_body, catch_body, .. } => {
            f(try_body);
            f(catch_body);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_cookie_detection() {
        let stmt = Stmt::Assign {
            target: Expr::Var("v0".into()),
            value: Expr::Var("__security_cookie".into()),
        };
        assert!(is_security_cookie_stmt(&stmt));
    }

    #[test]
    fn test_zero_expr() {
        assert!(is_zero_expr(&Expr::IntLit(0)));
        assert!(!is_zero_expr(&Expr::IntLit(1)));
    }

    #[test]
    fn test_expr_contains_symbol() {
        let expr = Expr::Binary {
            op: BinOp::Xor,
            lhs: Box::new(Expr::Var("v0".into())),
            rhs: Box::new(Expr::Var("__security_cookie".into())),
        };
        assert!(expr_contains_symbol(&expr, "__security_cookie"));
    }
}
