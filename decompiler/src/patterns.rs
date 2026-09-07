//! Compiler pattern recognition for decompiled code.
//!
//! Detects and transforms compiler-generated idioms into high-level constructs:
//! - Virtual call resolution (vtable dispatch)
//! - Memory operation idioms (memcpy, memset, strlen)
//! - Security cookie / stack canary removal
//! - Switch table patterns (jump tables, binary search, computed gotos)
//! - Compiler prologue/epilogue normalization

use crate::ast::*;
use freakre_ir::Ty;

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
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                cleanup_noops_and_empty_branches(then_body);
                if let Some(eb) = else_body {
                    cleanup_noops_and_empty_branches(eb);
                }
                let then_empty = then_body.is_empty();
                let else_nonempty = else_body.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
                if then_empty && else_nonempty {
                    *cond = Expr::Unary {
                        op: UnOp::LogNot,
                        operand: Box::new(std::mem::replace(cond, Expr::BoolLit(true))),
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
///
/// Conservative mode: only statements whose *entire* value is a recognized
/// canary idiom are removed. Anything that merely *mentions* the cookie
/// symbol is annotated with a comment instead of being deleted, so a real
/// data flow through the cookie value is never silently dropped.
#[allow(clippy::ptr_arg)]
fn remove_security_cookies(stmts: &mut Vec<Stmt>) {
    let mut i = 0;
    while i < stmts.len() {
        match classify_cookie_stmt(&stmts[i]) {
            CookieKind::PureIdiom => {
                // Whole statement is canary bookkeeping (e.g. `v = cookie ^ fp`
                // feeding only the check, or the check call itself).
                stmts[i] = Stmt::Comment("stack canary".into());
            }
            CookieKind::MentionsCookie => {
                // Unknown shape that references the cookie — keep the
                // statement, annotate it so the reader sees why it stays.
                if annotate_with_cookie_note(&mut stmts[i]) {
                    let note = Stmt::Comment(
                        "note: statement references __security_cookie; kept verbatim (possible data use)".into(),
                    );
                    stmts.insert(i, note);
                    i += 1; // skip past the inserted note
                }
            }
            CookieKind::None => {}
        }
        // Recurse into nested structures
        recurse_into_stmt_mut(&mut stmts[i], remove_security_cookies);
        i += 1;
    }
}

/// Conservative classification of a statement that references the cookie.
enum CookieKind {
    /// No cookie reference at all.
    None,
    /// Statement only touches the cookie for the canary idiom and is safe to
    /// drop: a bare copy (`v = __security_cookie`), the standard XOR-with-
    /// frame idiom, or the check call.
    PureIdiom,
    /// References the cookie in any other way — must not be removed.
    MentionsCookie,
}

fn classify_cookie_stmt(stmt: &Stmt) -> CookieKind {
    match stmt {
        Stmt::Assign { target, value } => {
            if !expr_contains_symbol(value, "__security_cookie")
                && !expr_contains_symbol(target, "__security_cookie")
            {
                return CookieKind::None;
            }
            match value {
                // `v = cookie` / `v = cookie ^ fp` — the canonical prologue
                // and epilogue forms when the target is a plain variable.
                Expr::Var(name) if name.contains("__security_cookie") => CookieKind::PureIdiom,
                Expr::Binary { op: BinOp::Xor, lhs, rhs } => {
                    let lhs_cookie = expr_contains_symbol(lhs, "__security_cookie");
                    let rhs_cookie = expr_contains_symbol(rhs, "__security_cookie");
                    // XOR with the frame/register side is the standard form;
                    // anything else might be real arithmetic on the value.
                    if (lhs_cookie ^ rhs_cookie)
                        && matches!(rhs.as_ref(), Expr::Var(_))
                        && matches!(lhs.as_ref(), Expr::Var(_))
                    {
                        CookieKind::PureIdiom
                    } else {
                        CookieKind::MentionsCookie
                    }
                }
                _ => CookieKind::MentionsCookie,
            }
        }
        Stmt::Expr(e) => {
            if !expr_contains_symbol(e, "__security_cookie") {
                return CookieKind::None;
            }
            match e {
                // Bare cookie read as a statement — canary bookkeeping.
                Expr::Var(name) if name.contains("__security_cookie") => CookieKind::PureIdiom,
                _ => CookieKind::MentionsCookie,
            }
        }
        Stmt::Call { func, .. } => {
            // `__security_check_cookie` (MSVC) and `__stack_chk_fail`
            // (GCC/Clang) are the runtime check calls; also catch
            // `__security_init_cookie` (pure runtime setup).
            if func.contains("cookie") || func.contains("__stack_chk") {
                CookieKind::PureIdiom
            } else {
                CookieKind::None
            }
        }
        _ => {
            if expr_contains_stmt_symbol(stmt, "__security_cookie") {
                CookieKind::MentionsCookie
            } else {
                CookieKind::None
            }
        }
    }
}

/// Symbol containment for statements not covered by the Assign/Expr/Call arms.
fn expr_contains_stmt_symbol(stmt: &Stmt, symbol: &str) -> bool {
    match stmt {
        Stmt::Return { value: Some(e) } => expr_contains_symbol(e, symbol),
        Stmt::If { cond, .. } => expr_contains_symbol(cond, symbol),
        _ => false,
    }
}

/// Prepend a `// note:` comment keeping the original statement in place.
///
/// For top-level statements the note is recorded and emitted by the caller
/// right before the statement; inside block-like statements it is inserted
/// at the head of the body.
fn annotate_with_cookie_note(stmt: &mut Stmt) -> bool {
    let note = Stmt::Comment(
        "note: statement references __security_cookie; kept verbatim (possible data use)".into(),
    );
    match stmt {
        // Inside a block-like statement, the note goes at the head of the body.
        Stmt::If { then_body, .. } | Stmt::Block(then_body) => {
            then_body.insert(0, note);
            false
        }
        // The caller must splice the note before this statement.
        _ => {
            let _ = note;
            true
        }
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
                Stmt::Assign {
                    target: Expr::Var(v),
                    value: Expr::Deref(_),
                } => Some(v.clone()),
                _ => None,
            };
            if let Some(vt_name) = vt_name {
                // Method pointer loaded from the vtable variable?
                let fp_load: Option<(String, u64)> = match &stmts[i + 1] {
                    Stmt::Assign {
                        target: Expr::Var(fp),
                        value,
                    } => extract_pointer_load(value, &vt_name).map(|off| (fp.clone(), off)),
                    _ => None,
                };
                if let Some((fp_name, offset)) = fp_load {
                    // Call through fp?
                    let call_matches = match &stmts[i + 2] {
                        Stmt::Call { func, .. } => func == &fp_name,
                        Stmt::Expr(Expr::Call { func, .. }) => func == &fp_name,
                        Stmt::Assign {
                            value: Expr::Call { func, .. },
                            ..
                        } => func == &fp_name,
                        _ => false,
                    };
                    if call_matches {
                        let obj_expr = match &stmts[i] {
                            Stmt::Assign {
                                value: Expr::Deref(base),
                                ..
                            } => (**base).clone(),
                            _ => Expr::Var(vt_name.clone()),
                        };
                        let args = match &stmts[i + 2] {
                            Stmt::Call { args, .. }
                            | Stmt::Expr(Expr::Call { args, .. })
                            | Stmt::Assign {
                                value: Expr::Call { args, .. },
                                ..
                            } => args.clone(),
                            _ => Vec::new(),
                        };
                        stmts[i] =
                            Stmt::Comment(format!("vtable dispatch @ offset 0x{:X}", offset));
                        stmts[i + 1] = Stmt::Empty;
                        stmts[i + 2] = Stmt::Expr(Expr::Call {
                            func: format!(
                                "{}.vfunc_0x{:X}",
                                expr_to_simple_string(&obj_expr),
                                offset
                            ),
                            args,
                        });
                    }
                }
            }
        }

        // Two-statement pattern for already-resolved names (kept for compat).
        if i + 1 < stmts.len() {
            if let Stmt::Assign {
                target: Expr::Var(vtable_var),
                value: Expr::Deref(base),
            } = &stmts[i]
            {
                if let Stmt::Assign {
                    value: Expr::Call { func, args },
                    ..
                }
                | Stmt::Call { func, args } = &stmts[i + 1]
                {
                    if !matches!(func.as_str(), "goto" | "syscall") && func.starts_with("vfunc_") {
                        if let Some(offset) = extract_vtable_offset(func, vtable_var) {
                            let obj_expr = (**base).clone();
                            stmts[i + 1] = Stmt::Expr(Expr::Call {
                                func: format!("{}.{}", expr_to_simple_string(&obj_expr), func),
                                args: args.clone(),
                            });
                            stmts[i] =
                                Stmt::Comment(format!("vtable dispatch @ offset 0x{:X}", offset));
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
            Expr::Binary {
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
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
        let hex = func_name
            .strip_prefix("vfunc_0x")
            .or_else(|| func_name.strip_prefix("vfunc_"))?;
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
    // Look for ≥3 consecutive stores of 0 to sequential addresses
    // (base + width*i), all with the same access width.
    let mut i = 0;
    while i + 3 <= stmts.len() {
        let run = match &stmts[i] {
            Stmt::Assign {
                target: target1,
                value: val1,
            } if is_zero_expr(val1) => {
                access_addr(target1).and_then(|(addr, width)| {
                    store_addr_info(addr).map(|(b, off)| (b, off, width))
                })
            }
            _ => None,
        };

        if let Some((base, off0, width)) = run {
            let mut count = 0usize;
            while i + count < stmts.len() {
                let ok = match &stmts[i + count] {
                    Stmt::Assign { target, value } => {
                        is_zero_expr(value)
                            && matches!(
                                access_addr(target),
                                Some((addr, w)) if w == width && matches!(
                                    store_addr_info(addr),
                                    Some((b, off)) if b == base && off == off0 + count as i64 * width as i64
                                )
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
                if let Stmt::Assign { target, .. } = &stmts[i] {
                    if let Some((addr, _)) = access_addr(target) {
                        let ptr_expr = addr.clone();
                        stmts[i] = Stmt::Call {
                            func: "memset".into(),
                            args: vec![
                                ptr_expr,
                                Expr::IntLit(0),
                                Expr::IntLit(count as i64 * width as i64),
                            ],
                        };
                        stmts.drain((i + 1)..(i + count));
                    }
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
        Expr::Binary {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
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

/// Byte width of a memory access expression.
///
/// A deref wrapped in a pointee cast carries its width (`*(uint8_t *)p` is 1
/// byte); a bare `Deref` is the historical 4-byte slot. Widths that do not
/// map to the integer widths the recognizer understands refuse the access.
fn access_addr(expr: &Expr) -> Option<(&Expr, u64)> {
    let Expr::Deref(inner) = expr else {
        return None;
    };
    let width = match inner.as_ref() {
        Expr::Cast { ty, .. } => match ty {
            // Pointee casts are pointer-typed (`*(uint8_t *)p`).
            Ty::Ptr(pointee) => match pointee.as_ref() {
                Ty::UInt(n) | Ty::Int(n) if *n > 0 && *n % 8 == 0 => Some(u64::from(*n / 8)),
                _ => None,
            },
            Ty::UInt(n) | Ty::Int(n) if *n > 0 && *n % 8 == 0 => Some(u64::from(*n / 8)),
            _ => None,
        },
        _ => Some(4),
    }?;
    let addr = match inner.as_ref() {
        Expr::Cast { expr, .. } => expr.as_ref(),
        other => other,
    };
    Some((addr, width))
}

fn detect_memcpy_pattern(stmts: &mut Vec<Stmt>) {
    // Detect unrolled memcpy: tmp = *src; *dst = tmp; tmp2 = *(src+w); *(dst+w) = tmp2; ...
    // At least 2 pairs with base+0, base+w, base+2w etc. All accesses must
    // share the same width `w`; the emitted length is count*w, so a wrong
    // width would produce a wrong memcpy size — refused instead.
    let mut i = 0;
    while i + 1 < stmts.len() {
        // Look for Load then Store pair
        let (src_base, src_off, src_width, tmp_name) = match &stmts[i] {
            Stmt::Assign {
                target: Expr::Var(tmp),
                value,
            } => match access_addr(value) {
                Some((addr, width)) => match store_addr_info(addr) {
                    Some((base, off)) => (base, off, width, tmp.clone()),
                    None => {
                        i += 1;
                        continue;
                    }
                },
                None => {
                    i += 1;
                    continue;
                }
            },
            _ => {
                i += 1;
                continue;
            }
        };
        let (dst_base, dst_off, dst_width) = match &stmts[i + 1] {
            Stmt::Assign {
                target,
                value: Expr::Var(v),
            } if v == &tmp_name => match access_addr(target) {
                Some((addr, width)) => match store_addr_info(addr) {
                    Some((base, off)) => (base, off, width),
                    None => {
                        i += 1;
                        continue;
                    }
                },
                None => {
                    i += 1;
                    continue;
                }
            },
            _ => {
                i += 1;
                continue;
            }
        };
        // Mixed widths (e.g. 1-byte loads feeding 4-byte stores) are not a
        // memcpy idiom — refuse the whole run.
        if src_width != dst_width {
            i += 1;
            continue;
        }
        // Alias soundness: when both sides use the same base variable the
        // regions may overlap (or be a no-op self-copy). The interleaved
        // loads/stores are well-defined for overlap, memcpy(dst, src, n) is
        // not — refuse to fold same-base runs.
        if src_base == dst_base {
            i += 1;
            continue;
        }
        let width = src_width;
        // Found first pair, check for sequential pairs
        let mut count = 1;
        let mut last_src_off = src_off;
        let mut last_dst_off = dst_off;
        while i + count * 2 + 1 < stmts.len() {
            let src_idx = i + count * 2;
            let dst_idx = i + count * 2 + 1;
            let src_ok = match &stmts[src_idx] {
                Stmt::Assign {
                    target: Expr::Var(tmp),
                    value,
                } => match access_addr(value) {
                    Some((addr, w)) => {
                        w == width
                            && matches!(
                                store_addr_info(addr),
                                Some((base, off)) if base == src_base && off == last_src_off + width as i64
                            )
                            && tmp != &tmp_name
                    }
                    None => false,
                },
                _ => false,
            };
            let dst_ok = match &stmts[dst_idx] {
                Stmt::Assign {
                    target,
                    value: Expr::Var(v),
                } => {
                    // Need to check that v is the tmp from previous src
                    if let Stmt::Assign {
                        target: Expr::Var(tmp2),
                        ..
                    } = &stmts[src_idx]
                    {
                        if v != tmp2 {
                            false
                        } else {
                            matches!(
                                access_addr(target),
                                Some((addr, w)) if w == width && matches!(
                                    store_addr_info(addr),
                                    Some((base, off)) if base == dst_base && off == last_dst_off + width as i64
                                )
                            )
                        }
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if src_ok && dst_ok {
                count += 1;
                last_src_off += width as i64;
                last_dst_off += width as i64;
            } else {
                break;
            }
        }
        if count >= 2 {
            // Replace with memcpy call
            let src_expr = Expr::Var(src_base.clone());
            let dst_expr = Expr::Var(dst_base.clone());
            stmts[i] = Stmt::Call {
                func: "memcpy".into(),
                args: vec![dst_expr, src_expr, Expr::IntLit(count as i64 * width as i64)],
            };
            stmts.drain((i + 1)..(i + count * 2));
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
            stmts[i] = Stmt::Block(vec![original, Stmt::Comment("frame allocation".into())]);
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
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            f(then_body);
            if let Some(eb) = else_body {
                f(eb);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            f(body);
        }
        Stmt::For { body, .. } => {
            f(body);
        }
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() {
                f(&mut c.body);
            }
            if let Some(d) = default {
                f(d);
            }
        }
        Stmt::Block(inner) => {
            f(inner);
        }
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
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
        assert!(matches!(
            classify_cookie_stmt(&stmt),
            CookieKind::PureIdiom
        ));
    }

    #[test]
    fn test_security_cookie_conservative_mode() {
        // Canonical XOR idiom is removed.
        let mut f = AstFunction::new("canary_xor");
        f.body.push(Stmt::Assign {
            target: Expr::Var("v0".into()),
            value: Expr::Binary {
                op: BinOp::Xor,
                lhs: Box::new(Expr::Var("__security_cookie".into())),
                rhs: Box::new(Expr::Var("rbp".into())),
            },
        });
        f.body.push(Stmt::Call {
            func: "__security_check_cookie".into(),
            args: vec![Expr::Var("v0".into())],
        });
        recognize_patterns(&mut f);
        assert!(
            f.body.iter()
                .any(|s| matches!(s, Stmt::Comment(t) if t == "stack canary")),
            "{}",
            debug_dump(&f)
        );
        assert!(
            !f.body.iter().any(|s| matches!(s, Stmt::Call { .. })),
            "{}",
            debug_dump(&f)
        );

        // A data-flow use of the cookie is kept and annotated, not deleted.
        let mut g = AstFunction::new("cookie_as_data");
        g.body.push(Stmt::Assign {
            target: Expr::Var("v1".into()),
            value: Expr::Call {
                func: "rand".into(),
                args: vec![Expr::Var("__security_cookie".into())],
            },
        });
        g.body.push(Stmt::Return {
            value: Some(Expr::Var("v1".into())),
        });
        recognize_patterns(&mut g);
        // [note comment, assign, return] — assign must survive verbatim.
        match &g.body[1] {
            Stmt::Assign { target, value } => {
                assert_eq!(*target, Expr::Var("v1".into()));
                match value {
                    Expr::Call { func, .. } => assert_eq!(func, "rand"),
                    other => panic!("unexpected value: {other:?}"),
                }
            }
            other => panic!("statement was replaced: {other:?}"),
        }
        assert!(
            g.body.iter().any(
                |s| matches!(s, Stmt::Comment(t) if t.contains("__security_cookie"))
            ),
            "{}",
            debug_dump(&g)
        );
        assert!(
            g.body.iter().any(|s| matches!(s, Stmt::Return { .. })),
            "{}",
            debug_dump(&g)
        );
    }

    #[test]
    fn test_memset_idiom_widths_and_refusals() {
        use crate::ast::*;
        use freakre_ir::Ty;

        // ── Differential: 4-byte slots still fold to memset(dst, 0, n*4) ──
        let mk_store = |base: &str, off: i64| -> Stmt {
            Stmt::Assign {
                target: Expr::Deref(Box::new(offset_addr(base, off))),
                value: Expr::IntLit(0),
            }
        };
        let mut f = AstFunction::new("memset_i32");
        f.body = vec![mk_store("dst", 0), mk_store("dst", 4), mk_store("dst", 8)];
        recognize_patterns(&mut f);
        assert!(
            matches!(
                &f.body[0],
                Stmt::Call { func, args } if func == "memset"
                    && matches!(args.as_slice(), [_, Expr::IntLit(0), Expr::IntLit(12)])
            ),
            "{}",
            debug_dump(&f)
        );

        // ── Soundness: 1-byte accesses fold with the correct byte count ──
        let mk_store_u8 = |base: &str, off: i64| -> Stmt {
            Stmt::Assign {
                target: Expr::Deref(Box::new(Expr::Cast {
                    ty: Ty::Ptr(Box::new(Ty::UInt(8))),
                    expr: Box::new(offset_addr(base, off)),
                })),
                value: Expr::IntLit(0),
            }
        };
        let mut g = AstFunction::new("memset_u8");
        g.body = vec![
            mk_store_u8("dst", 0),
            mk_store_u8("dst", 1),
            mk_store_u8("dst", 2),
            mk_store_u8("dst", 3),
        ];
        recognize_patterns(&mut g);
        assert!(
            matches!(
                &g.body[0],
                Stmt::Call { func, args } if func == "memset"
                    && matches!(args.as_slice(), [_, Expr::IntLit(0), Expr::IntLit(4)])
            ),
            "1-byte run must fold to a 4-byte memset: {}",
            debug_dump(&g)
        );

        // ── Soundness: mixed widths fold only per-width-run — the byte
        // stores cover exactly 3 bytes, the 4-byte stores exactly 12; no
        // single call may bridge across widths ──
        let mut h = AstFunction::new("memset_mixed");
        h.body = vec![
            mk_store_u8("dst", 0),
            mk_store_u8("dst", 1),
            mk_store_u8("dst", 2),
            mk_store("dst", 4), // 4-byte store breaks the byte-stride run
            mk_store("dst", 8),
            mk_store("dst", 12),
        ];
        recognize_patterns(&mut h);
        let sizes: Vec<i64> = h
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Call { func, args } if func == "memset" => match args.as_slice() {
                    [_, _, Expr::IntLit(n)] => Some(*n),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(sizes, vec![3, 12], "{}", debug_dump(&h));

        // ── Soundness: non-zero stores are not memset material ──
        let mut k = AstFunction::new("memset_nonzero");
        k.body = vec![
            Stmt::Assign {
                target: Expr::Deref(Box::new(offset_addr("dst", 0))),
                value: Expr::IntLit(1),
            },
            Stmt::Assign {
                target: Expr::Deref(Box::new(offset_addr("dst", 4))),
                value: Expr::IntLit(0),
            },
            Stmt::Assign {
                target: Expr::Deref(Box::new(offset_addr("dst", 8))),
                value: Expr::IntLit(0),
            },
        ];
        recognize_patterns(&mut k);
        assert!(
            !k.body.iter().any(|s| matches!(
                s,
                Stmt::Call { func, .. } if func == "memset"
            )),
            "{}",
            debug_dump(&k)
        );
    }

    #[test]
    fn test_memcpy_idiom_widths_aliases_and_refusals() {
        use crate::ast::*;
        use freakre_ir::Ty;

        let mk_load = |tmp: &str, base: &str, off: i64| -> Stmt {
            Stmt::Assign {
                target: Expr::Var(tmp.to_string()),
                value: Expr::Deref(Box::new(offset_addr(base, off))),
            }
        };
        let mk_store_var = |base: &str, off: i64, v: &str| -> Stmt {
            Stmt::Assign {
                target: Expr::Deref(Box::new(offset_addr(base, off))),
                value: Expr::Var(v.to_string()),
            }
        };
        let mk_load_u8 = |tmp: &str, base: &str, off: i64| -> Stmt {
            Stmt::Assign {
                target: Expr::Var(tmp.to_string()),
                value: Expr::Deref(Box::new(Expr::Cast {
                    ty: Ty::Ptr(Box::new(Ty::UInt(8))),
                    expr: Box::new(offset_addr(base, off)),
                })),
            }
        };
        let mk_store_var_u8 = |base: &str, off: i64, v: &str| -> Stmt {
            Stmt::Assign {
                target: Expr::Deref(Box::new(Expr::Cast {
                    ty: Ty::Ptr(Box::new(Ty::UInt(8))),
                    expr: Box::new(offset_addr(base, off)),
                })),
                value: Expr::Var(v.to_string()),
            }
        };

        // ── Differential: classic 4-byte unrolled copy folds correctly ──
        let mut f = AstFunction::new("memcpy_i32");
        f.body = vec![
            mk_load("t0", "src", 0),
            mk_store_var("dst", 0, "t0"),
            mk_load("t1", "src", 4),
            mk_store_var("dst", 4, "t1"),
            mk_load("t2", "src", 8),
            mk_store_var("dst", 8, "t2"),
        ];
        recognize_patterns(&mut f);
        assert!(
            matches!(
                &f.body[0],
                Stmt::Call { func, args } if func == "memcpy"
                    && matches!(args.as_slice(), [Expr::Var(d), Expr::Var(s), Expr::IntLit(12)]
                        if d == "dst" && s == "src")
            ),
            "{}",
            debug_dump(&f)
        );

        // ── Soundness: 1-byte unrolled copy folds to the right byte count ──
        let mut g = AstFunction::new("memcpy_u8");
        g.body = vec![
            mk_load_u8("t0", "src", 0),
            mk_store_var_u8("dst", 0, "t0"),
            mk_load_u8("t1", "src", 1),
            mk_store_var_u8("dst", 1, "t1"),
            mk_load_u8("t2", "src", 2),
            mk_store_var_u8("dst", 2, "t2"),
        ];
        recognize_patterns(&mut g);
        assert!(
            matches!(
                &g.body[0],
                Stmt::Call { func, args } if func == "memcpy"
                    && matches!(args.as_slice(), [_, _, Expr::IntLit(3)])
            ),
            "1-byte run must fold to a 3-byte memcpy: {}",
            debug_dump(&g)
        );

        // ── Soundness: mixed widths (byte loads into 4-byte stores) must
        // not fold — a width-blind matcher would emit a wrong memcpy size ──
        let mut h = AstFunction::new("memcpy_mixed");
        h.body = vec![
            mk_load_u8("t0", "src", 0),
            mk_store_var("dst", 0, "t0"),
            mk_load_u8("t1", "src", 1),
            mk_store_var("dst", 4, "t1"),
        ];
        recognize_patterns(&mut h);
        assert!(
            !h.body.iter().any(|s| matches!(
                s,
                Stmt::Call { func, .. } if func == "memcpy"
            )),
            "mixed-width copy must not fold: {}",
            debug_dump(&h)
        );

        // ── Soundness: same-base copy may overlap — memcpy has UB there,
        // the interleaved copy does not, so refuse to fold ──
        let mut a = AstFunction::new("memcpy_same_base");
        a.body = vec![
            mk_load("t0", "buf", 0),
            mk_store_var("buf", 4, "t0"),
            mk_load("t1", "buf", 4),
            mk_store_var("buf", 8, "t1"),
            mk_load("t2", "buf", 8),
            mk_store_var("buf", 12, "t2"),
        ];
        recognize_patterns(&mut a);
        assert!(
            !a.body.iter().any(|s| matches!(
                s,
                Stmt::Call { func, .. } if func == "memcpy"
            )),
            "same-base copy must not fold: {}",
            debug_dump(&a)
        );

        // ── Soundness: a gap in the source stride breaks the run — only
        // the contiguous prefix folds, and only to its exact byte range ──
        let mut b = AstFunction::new("memcpy_gap");
        b.body = vec![
            mk_load("t0", "src", 0),
            mk_store_var("dst", 0, "t0"),
            mk_load("t1", "src", 4),
            mk_store_var("dst", 4, "t1"),
            mk_load("t2", "src", 12), // skips 8
            mk_store_var("dst", 8, "t2"),
        ];
        recognize_patterns(&mut b);
        // First two pairs = src[0..8] -> dst[0..8].
        assert!(
            matches!(
                &b.body[0],
                Stmt::Call { func, args } if func == "memcpy"
                    && matches!(args.as_slice(), [_, _, Expr::IntLit(8)])
            ),
            "{}",
            debug_dump(&b)
        );
        // The gapped pair survives verbatim.
        assert!(
            matches!(
                &b.body[1],
                Stmt::Assign {
                    target: Expr::Var(t),
                    ..
                } if t == "t2"
            ),
            "{}",
            debug_dump(&b)
        );
    }

    fn offset_addr(base: &str, off: i64) -> Expr {
        if off == 0 {
            Expr::Var(base.to_string())
        } else {
            Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Var(base.to_string())),
                rhs: Box::new(Expr::IntLit(off)),
            }
        }
    }

    fn debug_dump(f: &AstFunction) -> String {
        format!("{f:#?}")
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
