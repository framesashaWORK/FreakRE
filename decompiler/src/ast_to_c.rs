//! Convert AST to C pseudocode.

use crate::ast::*;
use bibleteks_ir::Ty;

/// Convert an AST function to C pseudocode
pub fn ast_to_c(func: &AstFunction) -> String {
    let mut emitter = CEmitter::new();
    emitter.emit_function(func);
    emitter.output
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
        
        // Local variable declarations
        for local in &func.locals {
            if local.is_used {
                self.emit_indent();
                self.output.push_str(&self.type_to_c(&local.ty));
                self.output.push(' ');
                self.output.push_str(&local.name);
                self.output.push_str(";\n");
            }
        }
        
        if !func.locals.is_empty() {
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
                self.output.push_str(&format!("{}", val));
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
                let prec = op.precedence();
                let need_parens = prec < parent_prec;
                
                if need_parens {
                    self.output.push('(');
                }
                
                self.emit_expr(lhs, prec);
                self.output.push(' ');
                self.output.push_str(op.as_str());
                self.output.push(' ');
                self.emit_expr(rhs, prec);
                
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
                self.emit_expr(base, 15);
                self.output.push('[');
                self.emit_expr(index, 0);
                self.output.push(']');
            }
            
            Expr::Member { base, field } => {
                self.emit_expr(base, 15);
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
                self.emit_expr(cond, 3);
                self.output.push_str(" ? ");
                self.emit_expr(then_expr, 3);
                self.output.push_str(" : ");
                self.emit_expr(else_expr, 3);
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
            Ty::Unknown => "/* unknown */".to_string(),
            Ty::Int(n) => format!("int{}_t", n),
            Ty::UInt(n) => format!("uint{}_t", n),
            Ty::Float(n) => format!("float{}_t", n),
        }
    }
    
    fn emit_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
    }
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
}
