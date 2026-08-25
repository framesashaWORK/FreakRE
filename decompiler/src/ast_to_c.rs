//! Convert AST to C pseudocode.

use crate::ast::*;
use freakre_ir::Ty;

fn unsigned_cmp_str(op: &BinOp) -> Option<&'static str> {
    match op {
        BinOp::LtU => Some("<"),
        BinOp::LeU => Some("<="),
        BinOp::GtU => Some(">"),
        BinOp::GeU => Some(">="),
        _ => None,
    }
}

/// Convert an AST function to C pseudocode
pub fn ast_to_c(func: &AstFunction) -> String {
    let mut emitter = CEmitter::new();
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
}

impl CEmitter {
    fn new() -> Self {
        CEmitter {
            output: String::new(),
            indent: 0,
        }
    }
    
    fn emit_function(&mut self, func: &AstFunction) {
        // Function signature
        self.emit_indent();
        self.output.push_str(&self.type_to_c(&func.return_type));
        self.output.push(' ');
        self.output.push_str(&func.name);
        self.output.push('(');
        
        // Parameters
        for (i, param) in func.params.iter().enumerate() {
            if i > 0 {
                self.output.push_str(", ");
            }
            self.output.push_str(&self.type_to_c(&param.ty));
            self.output.push(' ');
            self.output.push_str(&param.name);
        }
        
        if func.params.is_empty() {
            self.output.push_str("void");
        }
        
        self.output.push_str(") {\n");
        self.indent += 1;
        
        // Local variable declarations (only names actually referenced)
        let used = used_var_names(&func.body);
        for local in &func.locals {
            if local.is_used && used.contains(&local.name) {
                self.emit_indent();
                self.output.push_str(&self.type_to_c(&local.ty));
                self.output.push(' ');
                self.output.push_str(&local.name);
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
                self.emit_expr(target, 0);
                self.output.push_str(" = ");
                self.emit_expr(value, 0);
                self.output.push_str(";\n");
            }
            
            Stmt::If { cond, then_body, else_body } => {
                self.emit_indent();
                self.output.push_str("if (");
                self.emit_expr(cond, 0);
                self.output.push_str(") {\n");
                
                self.indent += 1;
                for s in then_body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;
                
                self.emit_indent();
                self.output.push('}');
                
                if let Some(else_stmts) = else_body {
                    self.output.push_str(" else {\n");
                    self.indent += 1;
                    for s in else_stmts {
                        self.emit_stmt(s);
                    }
                    self.indent -= 1;
                    self.emit_indent();
                    self.output.push('}');
                }
                
                self.output.push('\n');
            }
            
            Stmt::While { cond, body } => {
                self.emit_indent();
                self.output.push_str("while (");
                self.emit_expr(cond, 0);
                self.output.push_str(") {\n");
                
                self.indent += 1;
                for s in body {
                    self.emit_stmt(s);
                }
                self.indent -= 1;
                
                self.emit_indent();
                self.output.push_str("}\n");
            }
            
            Stmt::For { init, cond, update, body } => {
                self.emit_indent();
                self.output.push_str("for (");
                
                if let Some(init_stmt) = init {
                    self.emit_stmt_inline(init_stmt);
                }
                self.output.push_str("; ");
                
                if let Some(cond_expr) = cond {
                    self.emit_expr(cond_expr, 0);
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
                self.emit_expr(cond, 0);
                self.output.push_str(");\n");
            }
            
            Stmt::Switch { expr, cases, default } => {
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
                self.output.push_str(func);
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
                self.output.push_str(name);
                if let Some(init_expr) = init {
                    self.output.push_str(" = ");
                    self.emit_expr(init_expr, 0);
                }
                self.output.push_str(";\n");
            }
            
            Stmt::Empty => {
                self.emit_indent();
                self.output.push_str(";\n");
            }
            
            Stmt::TryCatch { try_body, catch_var, catch_body } => {
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
                    self.output.push_str(var);
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
                self.output.push_str(label);
                self.output.push_str(";\n");
            }

            Stmt::Label { name } => {
                // Labels are not indented — they sit at column 0 relative to current scope
                self.emit_indent();
                self.output.push_str(name);
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
                self.emit_expr(target, 0);
                self.output.push_str(" = ");
                self.emit_expr(value, 0);
            }
            Stmt::Expr(expr) => {
                self.emit_expr(expr, 0);
            }
            _ => {}
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
                self.output.push_str(name);
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
                self.output.push_str(func);
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
            
            Expr::Deref(expr) => {
                self.output.push('*');
                self.emit_expr(expr, 15);
            }
            
            Expr::AddrOf(expr) => {
                self.output.push('&');
                self.emit_expr(expr, 15);
            }
            
            Expr::Cast { ty, expr } => {
                self.output.push('(');
                self.output.push_str(&self.type_to_c(ty));
                self.output.push(')');
                self.emit_expr(expr, 15);
            }
            
            Expr::Ternary { cond, then_expr, else_expr } => {
                let need_parens = 3 < parent_prec;
                if need_parens {
                    self.output.push('(');
                }
                self.emit_expr(cond, 4);
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
            Ty::Unknown => "uint64_t".to_string(),
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

    fn emit_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
    }
}


fn collect_expr_names(e: &Expr, out: &mut std::collections::HashSet<String>) {
    match e {
        Expr::Var(n) => { out.insert(n.clone()); }
        Expr::Binary { lhs, rhs, .. } => { collect_expr_names(lhs, out); collect_expr_names(rhs, out); }
        Expr::Unary { operand, .. } | Expr::Deref(operand) | Expr::AddrOf(operand) | Expr::Sizeof(operand) => collect_expr_names(operand, out),
        Expr::Call { args, .. } => { for a in args { collect_expr_names(a, out); } }
        Expr::Index { base, index, .. } => { collect_expr_names(base, out); collect_expr_names(index, out); }
        Expr::Member { base, .. } => collect_expr_names(base, out),
        Expr::Cast { expr, .. } => collect_expr_names(expr, out),
        Expr::Ternary { cond, then_expr, else_expr } => {
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
                Stmt::Assign { target, value } => { collect_expr_names(target, out); collect_expr_names(value, out); }
                Stmt::If { cond, then_body, else_body } => {
                    collect_expr_names(cond, out);
                    walk(then_body, out);
                    if let Some(e) = else_body { walk(e, out); }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                    collect_expr_names(cond, out);
                    walk(body, out);
                }
                Stmt::For { init, cond, update, body } => {
                    if let Some(i) = init { walk(std::slice::from_ref(i), out); }
                    if let Some(c) = cond { collect_expr_names(c, out); }
                    if let Some(u) = update { walk(std::slice::from_ref(u), out); }
                    walk(body, out);
                }
                Stmt::Return { value: Some(v) } => collect_expr_names(v, out),
                Stmt::Return { value: None } => {}
                Stmt::Switch { expr, cases, default } => {
                    collect_expr_names(expr, out);
                    for c in cases { collect_expr_names(&c.value, out); walk(&c.body, out); }
                    if let Some(d) = default { walk(d, out); }
                }
                Stmt::TryCatch { try_body, catch_body, .. } => { walk(try_body, out); walk(catch_body, out); }
                Stmt::Expr(e) => collect_expr_names(e, out),
                Stmt::Call { args, .. } => { for a in args { collect_expr_names(a, out); } }
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
    fn test_binary_expression() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var("x".to_string())),
            rhs: Box::new(Expr::IntLit(5)),
        };
        
        let mut emitter = CEmitter::new();
        emitter.emit_expr(&expr, 0);
        
        assert_eq!(emitter.output, "x + 0x5");
    }

    #[test]
    fn test_unknown_type_is_valid_c() {
        assert_eq!(CEmitter::new().type_to_c(&Ty::Unknown), "uint64_t");
    }
}