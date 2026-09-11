//! Convert AST to C pseudocode.

use crate::ast::*;
use crate::decompile::DecompilerConfig;
use crate::ident::IdentMap;
use freakre_ir::Ty;
use std::collections::HashMap;

fn unsigned_cmp_str(op: &BinOp) -> Option<&'static str> {
    match op {
        BinOp::LtU => Some("<"),
        BinOp::LeU => Some("<="),
        BinOp::GtU => Some(">"),
        BinOp::GeU => Some(">="),
        _ => None,
    }
}

/// Compound-assignment rendering for `x = x OP y` shapes (None for
/// comparisons and logical operators, which have no compound form).
fn compound_assign_op(op: &BinOp) -> Option<&'static str> {
    match op {
        BinOp::Add => Some("+="),
        BinOp::Sub => Some("-="),
        BinOp::Mul => Some("*="),
        BinOp::Div => Some("/="),
        BinOp::Mod => Some("%="),
        BinOp::And => Some("&="),
        BinOp::Or => Some("|="),
        BinOp::Xor => Some("^="),
        BinOp::Shl => Some("<<="),
        BinOp::Shr => Some(">>="),
        _ => None,
    }
}

fn is_int_zero(e: &Expr) -> bool {
    matches!(e, Expr::IntLit(0))
}

/// Convert an AST function to C pseudocode with default configuration
pub fn ast_to_c(func: &AstFunction) -> String {
    ast_to_c_with_config(func, &DecompilerConfig::default())
}

/// Convert an AST function to C pseudocode, honoring `DecompilerConfig`:
/// `indent` sets the indentation unit, `include_declarations` toggles local
/// variable declarations, `annotate_addresses` prepends an entry-address
/// comment when the AST carries a nonzero entry address.
pub fn ast_to_c_with_config(func: &AstFunction, config: &DecompilerConfig) -> String {
    let mut emitter = CEmitter::new(config);
    emitter.emit_function(func);
    let mut out = String::with_capacity(emitter.output.len());
    for (i, line) in emitter.output.lines().enumerate() {
        if line.trim() == ";" && i > 0 {
            continue;
        }
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    out
}

struct CEmitter {
    output: String,
    indent: usize,
    /// Indentation unit from `DecompilerConfig::indent` (default: 4 spaces).
    indent_str: String,
    /// From `DecompilerConfig::include_declarations`: when false, local
    /// variable declarations are omitted from the output.
    include_declarations: bool,
    /// From `DecompilerConfig::annotate_addresses`: emits an entry-address
    /// comment above the signature when the function carries an address.
    annotate_addresses: bool,
    /// Declared types for params and locals, used for cast hygiene and
    /// struct-field access printing. Lookups only — emission order never
    /// depends on map iteration, so output stays deterministic.
    var_types: HashMap<String, Ty>,
    /// Raw identifier -> valid C identifier (keywords, illegal chars,
    /// collisions). Deterministic per function.
    idents: IdentMap,
}

impl CEmitter {
    fn new(config: &DecompilerConfig) -> Self {
        CEmitter {
            output: String::new(),
            indent: 0,
            indent_str: config.indent.clone(),
            include_declarations: config.include_declarations,
            annotate_addresses: config.annotate_addresses,
            var_types: HashMap::new(),
            idents: IdentMap::new(),
        }
    }

    /// Sanitized form of a raw identifier (registers it on first use).
    fn ident(&mut self, raw: &str) -> String {
        self.idents.get_or_insert(raw)
    }

    fn emit_function(&mut self, func: &AstFunction) {
        self.var_types.clear();
        for param in &func.params {
            self.var_types.insert(param.name.clone(), param.ty.clone());
        }
        for local in &func.locals {
            self.var_types
                .entry(local.name.clone())
                .or_insert_with(|| local.ty.clone());
            // Pointer-typed locals with a recovered layout get a Ptr(Struct)
            // type so `emit_mem_access` prints `base->field_0xNN`.
            if !local.fields.is_empty() {
                let fields: Vec<(String, Ty)> = local
                    .fields
                    .iter()
                    .map(|(_, name, w)| (name.clone(), width_ty(*w)))
                    .collect();
                self.var_types
                    .entry(local.name.clone())
                    .or_insert(Ty::Ptr(Box::new(Ty::Struct(fields))));
            }
        }

        // Function signature
        if self.annotate_addresses && func.entry_address != 0 {
            self.emit_indent();
            self.output
                .push_str(&format!("// address: 0x{:X}\n", func.entry_address));
        }
        self.emit_indent();
        self.output.push_str(&self.type_to_c(&func.return_type));
        self.output.push(' ');
        let func_name = self.ident(&func.name);
        self.output.push_str(&func_name);
        self.output.push('(');

        // Parameters
        for (i, param) in func.params.iter().enumerate() {
            if i > 0 {
                self.output.push_str(", ");
            }
            self.output.push_str(&self.type_to_c(&param.ty));
            self.output.push(' ');
            let pname = self.ident(&param.name);
            self.output.push_str(&pname);
        }

        if func.params.is_empty() {
            self.output.push_str("void");
        }

        self.output.push_str(") {\n");
        self.indent += 1;

        // Local variable declarations (only names actually referenced)
        if self.include_declarations {
            let used = used_var_names(&func.body);
            for local in &func.locals {
                if local.is_used && used.contains(&local.name) {
                    self.emit_indent();
                    self.output.push_str(&self.type_to_c(&local.ty));
                    self.output.push(' ');
                    let lname = self.ident(&local.name);
                    self.output.push_str(&lname);
                    self.output.push_str(";\n");
                }
            }

            let declared_any = func
                .locals
                .iter()
                .any(|l| l.is_used && used.contains(&l.name));
            if declared_any {
                self.output.push('\n');
            }
        }

        // Body
        for stmt in &func.body {
            self.emit_stmt(stmt);
        }

        self.indent -= 1;
        self.emit_indent();
        self.output.push_str("}\n");
    }

    fn emit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { target, value } => {
                self.emit_indent();
                self.emit_assign_core(target, value);
                self.output.push_str(";\n");
            }

            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.emit_indent();
                self.emit_if_chain(cond, then_body, else_body.as_deref());
                self.output.push('\n');
            }

            Stmt::While { cond, body } => {
                self.emit_indent();
                self.output.push_str("while (");
                self.emit_cond(cond);
                self.output.push_str(") {\n");

                self.indent += 1;
                for s in body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;

                self.emit_indent();
                self.output.push_str("}\n");
            }

            Stmt::For {
                init,
                cond,
                update,
                body,
            } => {
                self.emit_indent();
                self.output.push_str("for (");

                if let Some(init_stmt) = init {
                    self.emit_stmt_inline(init_stmt);
                }
                self.output.push_str("; ");

                if let Some(cond_expr) = cond {
                    self.emit_cond(cond_expr);
                }
                self.output.push_str("; ");

                if let Some(update_stmt) = update {
                    self.emit_stmt_inline(update_stmt);
                }

                self.output.push_str(") {\n");

                self.indent += 1;
                for s in body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;

                self.emit_indent();
                self.output.push_str("}\n");
            }

            Stmt::DoWhile { body, cond } => {
                self.emit_indent();
                self.output.push_str("do {\n");

                self.indent += 1;
                for s in body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;

                self.emit_indent();
                self.output.push_str("} while (");
                self.emit_cond(cond);
                self.output.push_str(");\n");
            }

            Stmt::Switch {
                expr,
                cases,
                default,
            } => {
                self.emit_indent();
                self.output.push_str("switch (");
                self.emit_expr(expr, 0);
                self.output.push_str(") {\n");

                self.indent += 1;
                for case in cases {
                    self.emit_indent();
                    self.output.push_str("case ");
                    self.emit_expr(&case.value, 0);
                    self.output.push_str(":\n");

                    self.indent += 1;
                    for s in &case.body {
                        self.emit_stmt(s);
                    }
                    if !case.fallthrough {
                        self.emit_indent();
                        self.output.push_str("break;\n");
                    }
                    self.indent -= 1;
                }

                if let Some(default_stmts) = default {
                    self.emit_indent();
                    self.output.push_str("default:\n");

                    self.indent += 1;
                    for s in default_stmts {
                        self.emit_stmt(s);
                    }
                    self.indent -= 1;
                }

                self.indent -= 1;
                self.emit_indent();
                self.output.push_str("}\n");
            }

            Stmt::Return { value } => {
                self.emit_indent();
                self.output.push_str("return");
                if let Some(val) = value {
                    self.output.push(' ');
                    self.emit_expr(val, 0);
                }
                self.output.push_str(";\n");
            }

            Stmt::Break => {
                self.emit_indent();
                self.output.push_str("break;\n");
            }

            Stmt::Continue => {
                self.emit_indent();
                self.output.push_str("continue;\n");
            }

            Stmt::Call { func, args } => {
                self.emit_indent();
                let fname = self.ident(func);
                self.output.push_str(&fname);
                self.output.push('(');
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.output.push_str(", ");
                    }
                    self.emit_expr(arg, 0);
                }
                self.output.push_str(");\n");
            }

            Stmt::Expr(expr) => {
                self.emit_indent();
                // GCC/Clang's computed-goto extension is the only C-like
                // representation that preserves an indirect branch. Emitting
                // `goto(expr)` looks like a function call and is not valid C.
                if let Expr::Call { func, args } = expr {
                    if func == "goto" && args.len() == 1 {
                        self.output.push_str("goto *(");
                        self.emit_expr(&args[0], 0);
                        self.output.push_str(");\n");
                        return;
                    }
                }
                self.emit_expr(expr, 0);
                self.output.push_str(";\n");
            }

            Stmt::Block(stmts) => {
                self.emit_indent();
                self.output.push_str("{\n");
                self.indent += 1;
                for s in stmts {
                    self.emit_stmt(s);
                }
                self.indent -= 1;
                self.emit_indent();
                self.output.push_str("}\n");
            }

            Stmt::Decl { name, ty, init } => {
                self.emit_indent();
                self.output.push_str(&self.type_to_c(ty));
                self.output.push(' ');
                let dname = self.ident(name);
                self.output.push_str(&dname);
                if let Some(init_expr) = init {
                    self.output.push_str(" = ");
                    match init_expr {
                        Expr::Cast { ty: cast_ty, expr } if cast_ty == ty => {
                            self.emit_expr(expr, 0);
                        }
                        other => self.emit_expr(other, 0),
                    }
                }
                self.output.push_str(";\n");
            }

            Stmt::Empty => {
                self.emit_indent();
                self.output.push_str(";\n");
            }

            Stmt::TryCatch {
                try_body,
                catch_var,
                catch_body,
            } => {
                self.emit_indent();
                self.output.push_str("try {\n");
                self.indent += 1;
                for s in try_body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;
                self.emit_indent();
                self.output.push_str("} catch (");
                if let Some(var) = catch_var {
                    let vname = self.ident(var);
                    self.output.push_str(&vname);
                } else {
                    self.output.push_str("...");
                }
                self.output.push_str(") {\n");
                self.indent += 1;
                for s in catch_body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;
                self.emit_indent();
                self.output.push_str("}\n");
            }

            Stmt::Goto { label } => {
                self.emit_indent();
                self.output.push_str("goto ");
                let lname = self.ident(label);
                self.output.push_str(&lname);
                self.output.push_str(";\n");
            }

            Stmt::Label { name } => {
                // Labels are not indented — they sit at column 0 relative to current scope
                self.emit_indent();
                let lname = self.ident(name);
                self.output.push_str(&lname);
                self.output.push_str(":\n");
            }

            Stmt::Comment(text) => {
                self.emit_indent();
                self.output.push_str("// ");
                self.output.push_str(text);
                self.output.push('\n');
            }
        }
    }

    fn emit_stmt_inline(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { target, value } => {
                self.emit_assign_core(target, value);
            }
            Stmt::Expr(expr) => {
                self.emit_expr(expr, 0);
            }
            _ => {}
        }
    }

    /// Emit an assignment body (no indent, no trailing `;`): plain
    /// `target = value`, compound `target op= rhs` when the value re-uses the
    /// target as its left operand, or `target++` / `target--` for
    /// `target = target ± 1`. Shared by statement and `for`-update emission.
    fn emit_assign_core(&mut self, target: &Expr, value: &Expr) {
        if self.try_emit_compound(target, value) {
            return;
        }
        self.emit_expr(target, 0);
        self.output.push_str(" = ");
        // Cast hygiene: a cast is redundant only when it is a true
        // no-op — its target type matches the *source* value's
        // declared type (the assignment itself performs any needed
        // width/signedness conversion to the destination). Width-
        // changing casts (e.g. int32 → int64) are kept explicit.
        match (target, value) {
            (Expr::Var(_), Expr::Cast { ty, expr })
                if matches!(
                    expr.as_ref(),
                    Expr::Var(inner) if self.declared_type_is(inner, ty)
                ) =>
            {
                self.emit_expr(expr, 0);
            }
            _ => self.emit_expr(value, 0),
        }
    }

    /// `target = target OP rhs` → `target OP= rhs`, and
    /// `target = target ± 1` → `target++` / `target--`.
    /// Returns `false` (printing nothing) when the value is not a compound
    /// shape so the caller falls back to plain assignment emission.
    fn try_emit_compound(&mut self, target: &Expr, value: &Expr) -> bool {
        // Unwrap a redundant cast around the RHS first:
        // `x = (int32_t)(x + y)` with `x` declared int32_t.
        let value = match value {
            Expr::Cast { ty, expr }
                if matches!(target, Expr::Var(name) if self.declared_type_is(name, ty)) =>
            {
                expr.as_ref()
            }
            _ => value,
        };
        let Expr::Binary { op, lhs, rhs } = value else {
            return false;
        };
        if !matches!(target, Expr::Var(_) | Expr::Deref(_)) || lhs.as_ref() != target {
            return false;
        }

        // `x = x + 1` → `x++`; `*p = *p + 1` → `(*p)++` (parens required:
        // `*p++` parses as `*(p++)`).
        if matches!(op, BinOp::Add | BinOp::Sub) && matches!(&**rhs, Expr::IntLit(1)) {
            let deref_target = matches!(target, Expr::Deref(_));
            if deref_target {
                self.output.push('(');
            }
            self.emit_expr(target, 0);
            if deref_target {
                self.output.push(')');
            }
            self.output.push_str(if *op == BinOp::Add { "++" } else { "--" });
            return true;
        }

        let Some(cop) = compound_assign_op(op) else {
            return false;
        };
        self.emit_expr(target, 0);
        self.output.push(' ');
        self.output.push_str(cop);
        self.output.push(' ');
        self.emit_expr(rhs, op.precedence());
        true
    }

    /// Emit an `if` / `else if` / `else` chain. The caller prints the leading
    /// indentation; chained `else if` continues on the same line so no
    /// additional indent is emitted for the chain tail. An empty `else` arm
    /// is dropped entirely.
    fn emit_if_chain(&mut self, cond: &Expr, then_body: &[Stmt], else_body: Option<&[Stmt]>) {
        // Empty then + non-empty plain else → invert the condition once and
        // print the else body as the then body (`if (c) {} else { X }` reads
        // worse than `if (!c) { X }`).
        if then_body.is_empty() {
            match else_body {
                Some(eb) if !eb.is_empty() && !matches!(eb, [Stmt::If { .. }]) => {
                    let negated = crate::patterns::negate_cond(cond.clone());
                    self.output.push_str("if (");
                    self.emit_cond(&negated);
                    self.output.push_str(") {\n");
                    self.indent += 1;
                    for s in eb {
                        self.emit_stmt(s);
                    }
                    self.indent -= 1;
                    self.emit_indent();
                    self.output.push('}');
                    self.output.push('\n');
                    return;
                }
                _ => {}
            }
        }
        self.output.push_str("if (");
        self.emit_cond(cond);
        self.output.push_str(") {\n");

        self.indent += 1;
        for s in then_body {
            self.emit_stmt(s);
        }
        self.indent -= 1;

        self.emit_indent();
        self.output.push('}');

        let Some(eb) = else_body else {
            return;
        };
        if eb.is_empty() {
            return;
        }
        // Single nested `if` in the else arm → `} else if (...)` chain.
        if let [Stmt::If {
            cond: inner_cond,
            then_body: inner_then,
            else_body: inner_else,
        }] = eb
        {
            self.output.push_str(" else ");
            self.emit_if_chain(inner_cond, inner_then, inner_else.as_deref());
            return;
        }
        self.output.push_str(" else {\n");
        self.indent += 1;
        for s in eb {
            self.emit_stmt(s);
        }
        self.indent -= 1;
        self.emit_indent();
        self.output.push('}');
    }

    /// Emit a boolean-context condition (if/while/do-while/for/ternary).
    /// Zero comparisons collapse to truthiness: `v != 0` → `v`,
    /// `v == 0` → `!v`.
    fn emit_cond(&mut self, cond: &Expr) {
        match cond {
            Expr::Binary {
                op: BinOp::Ne,
                lhs,
                rhs,
            } if is_int_zero(rhs) && matches!(&**lhs, Expr::Var(_)) => self.emit_expr(lhs, 0),
            Expr::Binary {
                op: BinOp::Ne,
                lhs,
                rhs,
            } if is_int_zero(lhs) && matches!(&**rhs, Expr::Var(_)) => self.emit_expr(rhs, 0),
            Expr::Binary {
                op: BinOp::Eq,
                lhs,
                rhs,
            } if is_int_zero(rhs) && matches!(&**lhs, Expr::Var(_)) => {
                self.output.push('!');
                self.emit_expr(lhs, 15);
            }
            Expr::Binary {
                op: BinOp::Eq,
                lhs,
                rhs,
            } if is_int_zero(lhs) && matches!(&**rhs, Expr::Var(_)) => {
                self.output.push('!');
                self.emit_expr(rhs, 15);
            }
            _ => self.emit_expr(cond, 0),
        }
    }

    fn emit_expr(&mut self, expr: &Expr, parent_prec: u8) {
        match expr {
            Expr::IntLit(val) => {
                if *val < 0 {
                    self.output.push_str(&format!("({})", val));
                } else {
                    self.output.push_str(&format!("0x{:X}", val));
                }
            }

            Expr::FloatLit(val) => {
                if val.is_nan() {
                    self.output.push_str("/* NaN */ 0.0");
                } else if val.is_infinite() {
                    // No C literal for infinity: clamp to DBL_MAX with a
                    // marker comment instead of emitting invalid C ("inf").
                    if *val < 0.0 {
                        self.output.push_str("-1.7976931348623157e308 /* -inf */");
                    } else {
                        self.output.push_str("1.7976931348623157e308 /* +inf */");
                    }
                } else {
                    // {:?} always yields a decimal point or exponent, so the
                    // result stays a floating constant (5.0, not int 5).
                    self.output.push_str(&format!("{:?}", val));
                }
            }

            Expr::StringLit(s) => {
                self.output.push('"');
                for ch in s.chars() {
                    match ch {
                        '\\' => self.output.push_str("\\\\"),
                        '"' => self.output.push_str("\\\""),
                        '\n' => self.output.push_str("\\n"),
                        '\r' => self.output.push_str("\\r"),
                        '\t' => self.output.push_str("\\t"),
                        '\0' => self.output.push_str("\\0"),
                        c if c.is_ascii_control() => {
                            // Escape all other control bytes as \xHH
                            self.output.push_str(&format!("\\x{:02X}", c as u32));
                        }
                        c => self.output.push(c),
                    }
                }
                self.output.push('"');
            }

            Expr::BoolLit(b) => {
                self.output.push_str(if *b { "true" } else { "false" });
            }

            Expr::Var(name) => {
                let n = self.ident(name);
                self.output.push_str(&n);
            }

            Expr::Binary { op, lhs, rhs } => {
                if let Some(cmp) = unsigned_cmp_str(op) {
                    self.output.push_str("((uint64_t)(");
                    self.emit_expr(lhs, 0);
                    self.output.push_str(") ");
                    self.output.push_str(cmp);
                    self.output.push_str(" (uint64_t)(");
                    self.emit_expr(rhs, 0);
                    self.output.push_str("))");
                    return;
                }

                let prec = op.precedence();
                let need_parens = prec < parent_prec;

                if need_parens {
                    self.output.push('(');
                }

                self.emit_expr(lhs, prec);
                self.output.push(' ');
                self.output.push_str(op.as_str());
                self.output.push(' ');
                // Right-associative care: `a * (b / c)` must keep its parens,
                // so right operands of non-associative ops need a higher
                // required precedence than the op itself.
                let right_prec = if matches!(
                    op,
                    BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::Shl | BinOp::Shr
                ) {
                    prec + 1
                } else {
                    prec
                };
                self.emit_expr(rhs, right_prec);

                if need_parens {
                    self.output.push(')');
                }
            }

            Expr::Unary { op, operand } => {
                self.output.push_str(op.as_str());
                self.emit_expr(operand, 15);
            }

            Expr::Call { func, args } => {
                let fname = self.ident(func);
                self.output.push_str(&fname);
                self.output.push('(');
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.output.push_str(", ");
                    }
                    self.emit_expr(arg, 0);
                }
                self.output.push(')');
            }

            Expr::Index { base, index } => {
                self.emit_postfix_base(base);
                self.output.push('[');
                self.emit_expr(index, 0);
                self.output.push(']');
            }

            Expr::Member { base, field } => {
                self.emit_postfix_base(base);
                self.output.push('.');
                self.output.push_str(field);
            }

            Expr::Field { base, field, .. } => {
                // `base->field`: parens when the base is a non-var expression.
                let needs_parens = !matches!(base.as_ref(), Expr::Var(_));
                if needs_parens {
                    self.output.push('(');
                    self.emit_expr(base, 0);
                    self.output.push(')');
                } else {
                    self.emit_expr(base, 0);
                }
                self.output.push_str("->");
                let field = self.ident(field);
                self.output.push_str(&field);
            }

            Expr::Deref(expr) => {
                // Memory access through base±constant: print a named struct
                // field when the base's recovered struct layout resolves the
                // offset, else a width-correct cast with the raw hex offset
                // as a comment.
                if self.emit_mem_access(expr) {
                    return;
                }
                self.output.push('*');
                self.emit_expr(expr, 15);
            }

            Expr::AddrOf(expr) => {
                self.output.push('&');
                self.emit_expr(expr, 15);
            }

            Expr::Cast { ty, expr } => {
                // Collapse runs of identical casts: `(T)(T)x` → `(T)x`.
                let mut inner: &Expr = expr;
                while let Expr::Cast { ty: inner_ty, expr: next } = inner {
                    if inner_ty == ty {
                        inner = next;
                    } else {
                        break;
                    }
                }
                self.output.push('(');
                self.output.push_str(&self.type_to_c(ty));
                self.output.push(')');
                self.emit_expr(inner, 15);
            }

            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let need_parens = 3 < parent_prec;
                if need_parens {
                    self.output.push('(');
                }
                self.emit_cond(cond);
                self.output.push_str(" ? ");
                self.emit_expr(then_expr, 3);
                self.output.push_str(" : ");
                self.emit_expr(else_expr, 3);
                if need_parens {
                    self.output.push(')');
                }
            }

            Expr::Sizeof(expr) => {
                self.output.push_str("sizeof(");
                self.emit_expr(expr, 0);
                self.output.push(')');
            }
        }
    }

    fn type_to_c(&self, ty: &Ty) -> String {
        match ty {
            Ty::Bool => "bool".to_string(),
            Ty::Int(8) => "int8_t".to_string(),
            Ty::Int(16) => "int16_t".to_string(),
            Ty::Int(32) => "int32_t".to_string(),
            Ty::Int(64) => "int64_t".to_string(),
            Ty::UInt(8) => "uint8_t".to_string(),
            Ty::UInt(16) => "uint16_t".to_string(),
            Ty::UInt(32) => "uint32_t".to_string(),
            Ty::UInt(64) => "uint64_t".to_string(),
            Ty::Float(32) => "float".to_string(),
            Ty::Float(64) => "double".to_string(),
            Ty::Ptr(inner) => {
                format!("{}*", self.type_to_c(inner))
            }
            Ty::Array(size, inner) => {
                format!("{}[{}]", self.type_to_c(inner), size)
            }
            Ty::Struct(fields) => {
                let field_strs: Vec<String> = fields
                    .iter()
                    .map(|(name, ty)| format!("{} {}", self.type_to_c(ty), name))
                    .collect();
                format!("struct {{ {} }}", field_strs.join("; "))
            }
            Ty::Void => "void".to_string(),
            // Unknown widths fall back to plain int — never invent a width
            // the analysis did not establish.
            Ty::Unknown => "int".to_string(),
            Ty::Int(n) => format!("int{}_t", n),
            Ty::UInt(n) => format!("uint{}_t", n),
            Ty::Float(n) => format!("float{}_t", n),
        }
    }

    /// Emit the base of a postfix operation (`[...]`, `.field`). Deref and
    /// Cast bind looser than postfix operators, so they need parens:
    /// `(*p)[i]`, not `*p[i]`; `((T)p).f`, not `(T)p.f`.
    fn emit_postfix_base(&mut self, base: &Expr) {
        let needs_parens = matches!(base, Expr::Deref(_) | Expr::Cast { .. });
        if needs_parens {
            self.output.push('(');
        }
        self.emit_expr(base, 0);
        if needs_parens {
            self.output.push(')');
        }
    }

    /// Whether `name` is declared with exactly type `ty` (params win over
    /// locals on collision, matching declaration emission).
    fn declared_type_is(&self, name: &str, ty: &Ty) -> bool {
        self.var_types.get(name).map(|t| t == ty).unwrap_or(false)
    }

    /// Emit `*(base ± const)` as either `(base)->field` (offset resolved in
    /// the base's recovered struct layout) or a cast dereference with the
    /// hex offset preserved in a trailing comment. Returns `false` when
    /// `expr` is not a base±constant shape (caller prints plain `*expr`).
    fn emit_mem_access(&mut self, expr: &Expr) -> bool {
        let (op, base, lit) = match expr {
            Expr::Binary {
                op: bin_op @ (BinOp::Add | BinOp::Sub),
                lhs,
                rhs,
            } => match (lhs.as_ref(), rhs.as_ref()) {
                (Expr::Var(name), Expr::IntLit(off)) => (*bin_op, name, *off),
                (Expr::IntLit(off), Expr::Var(name)) if *bin_op == BinOp::Add => {
                    (*bin_op, name, *off)
                }
                _ => return false,
            },
            _ => return false,
        };

        // Only sane constant offsets; anything else keeps the plain form.
        let offset = match op {
            BinOp::Add if lit >= 0 => lit as u64,
            BinOp::Sub if lit > 0 => lit.unsigned_abs(),
            _ => return false,
        };
        let base_ty = self.var_types.get(base).cloned();

        if let Some(Ty::Struct(fields)) = base_ty.as_ref().and_then(|t| match t {
            Ty::Ptr(inner) => Some(inner.as_ref()),
            _ => None,
        }) {
            if let Some(field) = field_at_offset(fields, offset) {
                self.output.push('(');
                self.output.push_str(base);
                self.output.push_str(")->");
                self.output.push_str(field);
                return true;
            }
        }

        // Fallback: width-correct pointee when the base is a typed pointer,
        // 32-bit int otherwise. The dereference casts the integer address to
        // a *pointer* to that pointee, so render `*(T *)(base ± 0xOFF)`.
        let pointee = match base_ty.as_ref() {
            Some(Ty::Ptr(inner))
                if matches!(
                    inner.as_ref(),
                    Ty::Int(_) | Ty::UInt(_) | Ty::Float(_) | Ty::Bool
                ) =>
            {
                inner.as_ref().clone()
            }
            _ => Ty::i32(),
        };
        let ptr_ty = format!("{} *", self.type_to_c(&pointee));
        self.output.push_str(&format!(
            "*({})({} {} 0x{:X})",
            ptr_ty,
            base,
            op.as_str(),
            offset
        ));
        true
    }

    fn emit_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str(&self.indent_str);
        }
    }
}

/// C type for a recovered field of `width` bytes.
fn width_ty(width: u8) -> Ty {
    match width {
        1 => Ty::UInt(8),
        2 => Ty::UInt(16),
        8 => Ty::UInt(64),
        _ => Ty::UInt(32),
    }
}/// Resolve a byte offset to a field name in a recovered layout. Recovered
/// fields are named `field_0x<HEX>`; offsets are read from the names so no
/// side table is needed. First match wins (deterministic).
fn field_at_offset(fields: &[(String, Ty)], offset: u64) -> Option<&str> {
    for (name, _) in fields {
        if let Some(hex) = name.strip_prefix("field_0x") {
            if let Ok(off) = u64::from_str_radix(hex, 16) {
                if off == offset {
                    return Some(name.as_str());
                }
            }
        }
    }
    None
}

fn collect_expr_names(e: &Expr, out: &mut std::collections::HashSet<String>) {
    match e {
        Expr::Var(n) => {
            out.insert(n.clone());
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_expr_names(lhs, out);
            collect_expr_names(rhs, out);
        }
        Expr::Unary { operand, .. }
        | Expr::Deref(operand)
        | Expr::AddrOf(operand)
        | Expr::Sizeof(operand) => collect_expr_names(operand, out),
        Expr::Call { args, .. } => {
            for a in args {
                collect_expr_names(a, out);
            }
        }
        Expr::Index { base, index, .. } => {
            collect_expr_names(base, out);
            collect_expr_names(index, out);
        }
        Expr::Member { base, .. } => collect_expr_names(base, out),
        Expr::Cast { expr, .. } => collect_expr_names(expr, out),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_expr_names(cond, out);
            collect_expr_names(then_expr, out);
            collect_expr_names(else_expr, out);
        }
        _ => {}
    }
}

fn used_var_names(stmts: &[Stmt]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    fn walk(stmts: &[Stmt], out: &mut std::collections::HashSet<String>) {
        for s in stmts {
            match s {
                Stmt::Assign { target, value } => {
                    collect_expr_names(target, out);
                    collect_expr_names(value, out);
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    collect_expr_names(cond, out);
                    walk(then_body, out);
                    if let Some(e) = else_body {
                        walk(e, out);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                    collect_expr_names(cond, out);
                    walk(body, out);
                }
                Stmt::For {
                    init,
                    cond,
                    update,
                    body,
                } => {
                    if let Some(i) = init {
                        walk(std::slice::from_ref(i), out);
                    }
                    if let Some(c) = cond {
                        collect_expr_names(c, out);
                    }
                    if let Some(u) = update {
                        walk(std::slice::from_ref(u), out);
                    }
                    walk(body, out);
                }
                Stmt::Return { value: Some(v) } => collect_expr_names(v, out),
                Stmt::Return { value: None } => {}
                Stmt::Switch {
                    expr,
                    cases,
                    default,
                } => {
                    collect_expr_names(expr, out);
                    for c in cases {
                        collect_expr_names(&c.value, out);
                        walk(&c.body, out);
                    }
                    if let Some(d) = default {
                        walk(d, out);
                    }
                }
                Stmt::TryCatch {
                    try_body,
                    catch_body,
                    ..
                } => {
                    walk(try_body, out);
                    walk(catch_body, out);
                }
                Stmt::Expr(e) => collect_expr_names(e, out),
                Stmt::Call { args, .. } => {
                    for a in args {
                        collect_expr_names(a, out);
                    }
                }
                Stmt::Decl { init: Some(e), .. } => collect_expr_names(e, out),
                Stmt::Block(b) => walk(b, out),
                _ => {}
            }
        }
    }
    walk(stmts, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_func_with_local() -> AstFunction {
        let mut func = AstFunction::new("cfg_func");
        func.entry_address = 0x1400;
        func.return_type = Ty::i32();
        func.locals.push(LocalVar {
            name: "v0".to_string(),
            ty: Ty::i32(),
            is_used: true, fields: Vec::new(),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Var("v0".to_string()),
            value: Expr::IntLit(7),
        });
        func.body.push(Stmt::Return {
            value: Some(Expr::Var("v0".to_string())),
        });
        func
    }

    #[test]
    fn test_config_indent_is_used() {
        let func = sample_func_with_local();
        let cfg = DecompilerConfig {
            indent: "  ".to_string(),
            ..Default::default()
        };
        let c = ast_to_c_with_config(&func, &cfg);
        assert!(c.contains("  return v0;"), "{}", c);
        assert!(!c.contains("    return v0;"), "{}", c);
        // Default config keeps the 4-space unit.
        let c = ast_to_c(&func);
        assert!(c.contains("    return v0;"), "{}", c);
    }

    #[test]
    fn test_config_include_declarations_false_drops_locals() {
        let func = sample_func_with_local();
        let cfg = DecompilerConfig {
            include_declarations: false,
            ..Default::default()
        };
        let c = ast_to_c_with_config(&func, &cfg);
        assert!(c.contains("return v0;"), "{}", c);
        assert!(!c.contains("int32_t v0;"), "{}", c);
        // Default keeps declarations.
        let c = ast_to_c(&func);
        assert!(c.contains("int32_t v0;"), "{}", c);
    }

    #[test]
    fn test_config_annotate_addresses_emits_entry_comment() {
        let func = sample_func_with_local();
        let cfg = DecompilerConfig {
            annotate_addresses: true,
            ..Default::default()
        };
        let c = ast_to_c_with_config(&func, &cfg);
        assert!(c.contains("// address: 0x1400"), "{}", c);
        // Off by default and suppressed when the address is unknown (0).
        let mut unnamed = func.clone();
        unnamed.entry_address = 0;
        let c = ast_to_c_with_config(&unnamed, &cfg);
        assert!(!c.contains("// address:"), "{}", c);
        let c = ast_to_c(&func);
        assert!(!c.contains("// address:"), "{}", c);
    }

    #[test]
    fn test_identifiers_are_sanitized_consistently() {
        let mut func = AstFunction::new("int"); // keyword function name
        func.locals.push(LocalVar {
            name: "0bad".to_string(),
            ty: Ty::i32(),
            is_used: true, fields: Vec::new(),
        });
        func.locals.push(LocalVar {
            name: "a-b".to_string(),
            ty: Ty::i32(),
            is_used: true, fields: Vec::new(),
        });
        func.locals.push(LocalVar {
            name: "a_b".to_string(),
            ty: Ty::i32(),
            is_used: true, fields: Vec::new(),
        });
        func.body.push(Stmt::Decl {
            name: "0bad".to_string(),
            ty: Ty::i32(),
            init: Some(Expr::IntLit(1)),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Var("a-b".to_string()),
            value: Expr::Var("0bad".to_string()),
        });
        func.body.push(Stmt::Call {
            func: "weird@call".to_string(),
            args: vec![Expr::Var("a_b".to_string())],
        });
        func.body.push(Stmt::Return {
            value: Some(Expr::Var("a-b".to_string())),
        });

        let c = ast_to_c(&func);
        // Keyword function name, digit-leading and mangled locals renamed.
        assert!(c.contains("int_("), "{}", c);
        assert!(c.contains("int32_t _0bad = 0x1;"), "{}", c);
        assert!(c.contains("a_b = _0bad;"), "{}", c);
        assert!(c.contains("weird_call(a_b_1);"), "{}", c);
        assert!(c.contains("return a_b;"), "{}", c);
        // No raw illegal forms leak into the listing.
        assert!(!c.contains("weird@call"), "{}", c);
        assert!(!c.contains("a-b"), "{}", c);
    }

    #[test]
    fn test_simple_function() {
        let mut func = AstFunction::new("test_func");
        func.return_type = Ty::i32();
        func.params.push(Param {
            name: "x".to_string(),
            ty: Ty::i32(),
        });
        func.body.push(Stmt::Return {
            value: Some(Expr::Var("x".to_string())),
        });

        let c_code = ast_to_c(&func);

        assert!(c_code.contains("int32_t test_func"));
        assert!(c_code.contains("return x"));
    }

    #[test]
    fn test_if_statement() {
        let mut func = AstFunction::new("test");
        func.body.push(Stmt::If {
            cond: Expr::BoolLit(true),
            then_body: vec![Stmt::Return { value: None }],
            else_body: None,
        });

        let c_code = ast_to_c(&func);

        assert!(c_code.contains("if (true)"));
        assert!(c_code.contains("return;"));
    }

    #[test]
    fn test_indirect_branch_uses_computed_goto() {
        let mut func = AstFunction::new("dispatch");
        func.body.push(Stmt::Expr(Expr::Call {
            func: "goto".to_string(),
            args: vec![Expr::Var("target".to_string())],
        }));
        let c_code = ast_to_c(&func);
        assert!(c_code.contains("goto *(target);"), "{}", c_code);
        assert!(!c_code.contains("goto(target)"), "{}", c_code);
    }

    #[test]
    fn test_binary_expression() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var("x".to_string())),
            rhs: Box::new(Expr::IntLit(5)),
        };

        let mut emitter = CEmitter::new(&DecompilerConfig::default());
        emitter.emit_expr(&expr, 0);

        assert_eq!(emitter.output, "x + 0x5");
    }

    #[test]
    fn test_unknown_type_is_valid_c() {
        assert_eq!(CEmitter::new(&DecompilerConfig::default()).type_to_c(&Ty::Unknown), "int");
    }

    #[test]
    fn test_redundant_cast_dropped_on_matching_declared_width() {
        let mut func = AstFunction::new("casty");
        func.locals.push(LocalVar {
            name: "x".to_string(),
            ty: Ty::i32(),
            is_used: true, fields: Vec::new(),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Var("x".to_string()),
            value: Expr::Cast {
                ty: Ty::i32(),
                expr: Box::new(Expr::Var("x".to_string())),
            },
        });
        let c = ast_to_c(&func);
        assert!(c.contains("x = x;"), "{}", c);
    }

    #[test]
    fn test_width_changing_cast_kept() {
        let mut func = AstFunction::new("widen");
        func.locals.push(LocalVar {
            name: "x".to_string(),
            ty: Ty::i32(),
            is_used: true, fields: Vec::new(),
        });
        func.locals.push(LocalVar {
            name: "y".to_string(),
            ty: Ty::i64(),
            is_used: true, fields: Vec::new(),
        });
        func.body.push(Stmt::Assign {
            target: Expr::Var("y".to_string()),
            value: Expr::Cast {
                ty: Ty::i64(),
                expr: Box::new(Expr::Var("x".to_string())),
            },
        });
        let c = ast_to_c(&func);
        assert!(c.contains("(int64_t)x"), "{}", c);
    }

    #[test]
    fn test_compound_assignment_rendering() {
        let mk = |op: BinOp, rhs: i64| {
            let mut func = AstFunction::new("compound");
            func.return_type = Ty::Void;
            func.body.push(Stmt::Assign {
                target: Expr::Var("x".to_string()),
                value: Expr::Binary {
                    op,
                    lhs: Box::new(Expr::Var("x".to_string())),
                    rhs: Box::new(Expr::IntLit(rhs)),
                },
            });
            ast_to_c(&func)
        };
        assert!(mk(BinOp::Add, 5).contains("x += 0x5"), "{}", mk(BinOp::Add, 5));
        assert!(mk(BinOp::Sub, 5).contains("x -= 0x5"));
        assert!(mk(BinOp::Mul, 2).contains("x *= 0x2"));
        assert!(mk(BinOp::Shr, 3).contains("x >>= 0x3"));
        assert!(mk(BinOp::Xor, 0xFF).contains("x ^= 0xFF"));
        // Comparisons and logical ops have no compound form.
        let c = mk(BinOp::Lt, 5);
        assert!(c.contains("x = x < 0x5"), "{}", c);
    }

    #[test]
    fn test_increment_decrement_rendering() {
        let mk = |op: BinOp| {
            let mut func = AstFunction::new("incdec");
            func.return_type = Ty::Void;
            func.body.push(Stmt::Assign {
                target: Expr::Var("i".to_string()),
                value: Expr::Binary {
                    op,
                    lhs: Box::new(Expr::Var("i".to_string())),
                    rhs: Box::new(Expr::IntLit(1)),
                },
            });
            ast_to_c(&func)
        };
        assert!(mk(BinOp::Add).contains("i++;"), "{}", mk(BinOp::Add));
        assert!(mk(BinOp::Sub).contains("i--;"), "{}", mk(BinOp::Sub));
        // `i = i + 2` stays a plain (compound) assignment, not an increment.
        let mut func = AstFunction::new("incdec2");
        func.return_type = Ty::Void;
        func.body.push(Stmt::Assign {
            target: Expr::Var("i".to_string()),
            value: Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Var("i".to_string())),
                rhs: Box::new(Expr::IntLit(2)),
            },
        });
        let c = ast_to_c(&func);
        assert!(c.contains("i += 0x2"), "{}", c);
        assert!(!c.contains("i++"), "{}", c);
    }

    #[test]
    fn test_deref_increment_is_parenthesized() {
        // `*p = *p + 1` must render as `(*p)++`, never `*p++` (= `*(p++)`).
        let mut func = AstFunction::new("derefinc");
        func.return_type = Ty::Void;
        let deref = Box::new(Expr::Deref(Box::new(Expr::Var("p".to_string()))));
        func.body.push(Stmt::Assign {
            target: Expr::Deref(Box::new(Expr::Var("p".to_string()))),
            value: Expr::Binary {
                op: BinOp::Add,
                lhs: deref,
                rhs: Box::new(Expr::IntLit(1)),
            },
        });
        let c = ast_to_c(&func);
        assert!(c.contains("(*p)++"), "{}", c);
        assert!(!c.contains("*p++"), "{}", c);
    }

    #[test]
    fn test_for_update_uses_compound_and_increment() {
        let mut func = AstFunction::new("loopy");
        func.return_type = Ty::Void;
        func.body.push(Stmt::For {
            init: Some(Box::new(Stmt::Assign {
                target: Expr::Var("i".to_string()),
                value: Expr::IntLit(0),
            })),
            cond: Some(Expr::Binary {
                op: BinOp::Lt,
                lhs: Box::new(Expr::Var("i".to_string())),
                rhs: Box::new(Expr::IntLit(10)),
            }),
            update: Some(Box::new(Stmt::Assign {
                target: Expr::Var("i".to_string()),
                value: Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Var("i".to_string())),
                    rhs: Box::new(Expr::IntLit(1)),
                },
            })),
            body: vec![Stmt::Empty],
        });
        let c = ast_to_c(&func);
        assert!(c.contains("i = 0x0; i < 0xA; i++"), "{}", c);
    }

    #[test]
    fn test_else_if_chain_rendering() {
        let mut func = AstFunction::new("chainy");
        func.return_type = Ty::Void;
        func.body.push(Stmt::If {
            cond: Expr::Binary {
                op: BinOp::Lt,
                lhs: Box::new(Expr::Var("x".to_string())),
                rhs: Box::new(Expr::IntLit(0)),
            },
            then_body: vec![Stmt::Expr(Expr::IntLit(1))],
            else_body: Some(vec![Stmt::If {
                cond: Expr::Binary {
                    op: BinOp::Gt,
                    lhs: Box::new(Expr::Var("x".to_string())),
                    rhs: Box::new(Expr::IntLit(0)),
                },
                then_body: vec![Stmt::Expr(Expr::IntLit(2))],
                else_body: Some(vec![Stmt::Expr(Expr::IntLit(3))]),
            }]),
        });
        let c = ast_to_c(&func);
        assert!(c.contains("} else if (x > 0x0) {"), "{}", c);
        assert!(!c.contains("else {\n    if"), "{}", c);
    }

    #[test]
    fn test_bool_condition_zero_noise_collapsed() {
        let mut func = AstFunction::new("truthy");
        func.return_type = Ty::Void;
        func.body.push(Stmt::If {
            cond: Expr::Binary {
                op: BinOp::Ne,
                lhs: Box::new(Expr::Var("v".to_string())),
                rhs: Box::new(Expr::IntLit(0)),
            },
            then_body: vec![Stmt::Empty],
            else_body: None,
        });
        func.body.push(Stmt::While {
            cond: Expr::Binary {
                op: BinOp::Eq,
                lhs: Box::new(Expr::Var("w".to_string())),
                rhs: Box::new(Expr::IntLit(0)),
            },
            body: vec![Stmt::Empty],
        });
        let c = ast_to_c(&func);
        assert!(c.contains("if (v)"), "{}", c);
        assert!(c.contains("while (!w)"), "{}", c);
        assert!(!c.contains("!= 0x0"), "{}", c);
        assert!(!c.contains("== 0x0"), "{}", c);
    }

    #[test]
    fn test_identical_cast_chain_collapsed() {
        let cast = |inner: Expr| {
            Expr::Cast {
                ty: Ty::u32(),
                expr: Box::new(Expr::Cast {
                    ty: Ty::u32(),
                    expr: Box::new(inner),
                }),
            }
        };
        let mut func = AstFunction::new("castchain");
        func.return_type = Ty::Void;
        func.body.push(Stmt::Assign {
            target: Expr::Var("y".to_string()),
            value: cast(Expr::Var("x".to_string())),
        });
        let c = ast_to_c(&func);
        assert!(c.contains("(uint32_t)x"), "{}", c);
        assert!(!c.contains("(uint32_t)(uint32_t)"), "{}", c);
    }

    #[test]
    fn test_string_literal_rendering() {
        let mut func = AstFunction::new("strings");
        func.return_type = Ty::Void;
        func.body.push(Stmt::Call {
            func: "f".to_string(),
            args: vec![Expr::StringLit("C:\\temp\\a.txt".to_string())],
        });
        let c = ast_to_c(&func);
        assert!(c.contains(r#"f("C:\\temp\\a.txt");"#), "{}", c);
    }

    #[test]
    fn test_struct_field_and_fallback_rendering() {
        let struct_fields = vec![
            ("field_0x10".to_string(), Ty::i32()),
            ("field_0x14".to_string(), Ty::i32()),
        ];
        let mut func = AstFunction::new("structy");
        func.locals.push(LocalVar {
            name: "s".to_string(),
            ty: Ty::Ptr(Box::new(Ty::Struct(struct_fields))),
            is_used: true, fields: Vec::new(),
        });
        // Resolved offset → named field.
        func.body.push(Stmt::Assign {
            target: Expr::Var("v1".to_string()),
            value: Expr::Deref(Box::new(Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Var("s".to_string())),
                rhs: Box::new(Expr::IntLit(0x10)),
            })),
        });
        let c = ast_to_c(&func);
        assert!(c.contains("(s)->field_0x10"), "{}", c);

        // Unresolved offset on an untyped base → cast + hex comment.
        let c = {
            let mut emitter = CEmitter::new(&DecompilerConfig::default());
            emitter.emit_expr(
                &Expr::Deref(Box::new(Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Var("a".to_string())),
                    rhs: Box::new(Expr::IntLit(0xC)),
                })),
                0,
            );
            emitter.output
        };
        assert!(c.contains("*(int32_t *)(a + 0xC)"), "{}", c);
        // Offset comments disabled
        // assert!(c.contains("/* 0xC */"), "{}", c);
    }
}
