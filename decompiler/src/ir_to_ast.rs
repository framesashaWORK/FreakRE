//! Convert IR to AST.

use crate::ast::*;
use crate::structuring::structure_control_flow;
use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};
use std::collections::HashMap;

/// Convert an IR function to an AST function
pub fn ir_to_ast(func: &IrFunction) -> AstFunction {
    let mut converter = IrToAstConverter::new(func);
    converter.convert()
}

pub struct IrToAstConverter<'a> {
    func: &'a IrFunction,
    var_names: HashMap<Value, String>,
    var_counter: u32,
}

impl<'a> IrToAstConverter<'a> {
    pub fn new(func: &'a IrFunction) -> Self {
        IrToAstConverter {
            func,
            var_names: HashMap::new(),
            var_counter: 0,
        }
    }
    
    fn convert(&mut self) -> AstFunction {
        let mut ast_func = AstFunction::new(&self.func.name);
        
        // Convert blocks to structured statements
        let body = structure_control_flow(self.func, self);
        ast_func.body = body;
        
        // Collect local variables
        ast_func.locals = self.collect_locals();
        
        // Set return type (default to void if not inferred)
        ast_func.return_type = self.func.metadata.return_type.clone().unwrap_or(Ty::Void);
        
        ast_func
    }
    
    /// Get or create a name for a value
    pub fn get_var_name(&mut self, value: &Value) -> String {
        if let Some(name) = self.var_names.get(value) {
            return name.clone();
        }
        
        let name = match value {
            Value::Var { id, .. } => {
                format!("v{}", id)
            }
            Value::Register { name, .. } => {
                name.clone()
            }
            Value::Symbol(sym) => {
                sym.clone()
            }
            _ => {
                let name = format!("tmp{}", self.var_counter);
                self.var_counter += 1;
                name
            }
        };
        
        self.var_names.insert(value.clone(), name.clone());
        name
    }
    
    /// Convert an IR instruction to AST statements
    pub fn convert_inst(&mut self, inst: &IrInst) -> Vec<Stmt> {
        match inst {
            IrInst::Binary { dst, op, lhs, rhs } => {
                let target = self.convert_value_to_expr(dst);
                let mut lhs_expr = self.convert_value_to_expr(lhs);
                let rhs_expr = self.convert_value_to_expr(rhs);

                if *op == OpCode::Sar {
                    if let Ty::UInt(n) = lhs.ty() {
                        lhs_expr = Expr::Cast {
                            ty: Ty::Int(n),
                            expr: Box::new(lhs_expr),
                        };
                    }
                }

                let value = match self.convert_opcode_to_binop(*op) {
                    Some(bin_op) => Expr::Binary {
                        op: bin_op,
                        lhs: Box::new(lhs_expr),
                        rhs: Box::new(rhs_expr),
                    },
                    // Unlowerable opcodes (rotates, float arithmetic) are kept
                    // as intrinsic-style calls so neither operand nor
                    // operation is silently dropped (`dst = lhs` would lie).
                    None => Expr::Call {
                        func: op.to_string(),
                        args: vec![lhs_expr, rhs_expr],
                    },
                };

                vec![Stmt::Assign { target, value }]
            }
            
            IrInst::Unary { dst, op, src } => {
                let target = self.convert_value_to_expr(dst);
                let src_expr = self.convert_value_to_expr(src);
                
                let value = match op {
                    OpCode::Neg => Expr::Unary {
                        op: UnOp::Neg,
                        operand: Box::new(src_expr),
                    },
                    OpCode::Not => Expr::Unary {
                        op: UnOp::Not,
                        operand: Box::new(src_expr),
                    },
                    OpCode::FloatToFloat | OpCode::IntToFloat | OpCode::FloatToInt => {
                        let ty = dst.ty();
                        if ty.is_float() || ty.is_integer() {
                            Expr::Cast {
                                ty,
                                expr: Box::new(src_expr),
                            }
                        } else {
                            src_expr
                        }
                    }
                    // Same intrinsic-call preservation for unary float ops.
                    OpCode::FloatNeg | OpCode::FloatAbs | OpCode::FloatSqrt => Expr::Call {
                        func: op.to_string(),
                        args: vec![src_expr],
                    },
                    _ => src_expr,
                };
                
                vec![Stmt::Assign {
                    target,
                    value,
                }]
            }
            
            IrInst::Load { dst, addr, size: _ } => {
                let target = self.convert_value_to_expr(dst);
                let addr_expr = self.convert_value_to_expr(addr);
                
                vec![Stmt::Assign {
                    target,
                    value: Expr::Deref(Box::new(addr_expr)),
                }]
            }
            
            IrInst::Store { addr, value, size: _ } => {
                let addr_expr = self.convert_value_to_expr(addr);
                let value_expr = self.convert_value_to_expr(value);
                
                vec![Stmt::Assign {
                    target: Expr::Deref(Box::new(addr_expr)),
                    value: value_expr,
                }]
            }
            
            IrInst::Call { dst, target, args } => {
                let func_name = match target {
                    Value::Symbol(sym) => sym.clone(),
                    Value::Const(addr) => format!("func_0x{:X}", addr),
                    _ => self.get_var_name(target),
                };
                
                let arg_exprs: Vec<Expr> = args.iter()
                    .map(|arg| self.convert_value_to_expr(arg))
                    .collect();
                
                if let Some(dst_val) = dst {
                    let target = self.convert_value_to_expr(dst_val);
                    vec![Stmt::Assign {
                        target,
                        value: Expr::Call {
                            func: func_name,
                            args: arg_exprs,
                        },
                    }]
                } else {
                    vec![Stmt::Call {
                        func: func_name,
                        args: arg_exprs,
                    }]
                }
            }
            
            IrInst::Return { value } => {
                let ret_value = value.as_ref().map(|v| self.convert_value_to_expr(v));
                vec![Stmt::Return { value: ret_value }]
            }
            
            IrInst::Branch { .. } | IrInst::CBranch { .. } => {
                // Handled by control flow structuring
                vec![]
            }
            
            IrInst::Phi { .. } => {
                // Phi nodes are handled during SSA deconstruction
                vec![]
            }
            
            IrInst::Nop => {
                vec![Stmt::Empty]
            }
            
            IrInst::Syscall { number, args } => {
                let arg_exprs: Vec<Expr> = args.iter()
                    .map(|arg| self.convert_value_to_expr(arg))
                    .collect();
                
                let func_name = if let Some(num) = number {
                    format!("syscall_{}", num.as_const().unwrap_or(0))
                } else {
                    "syscall".to_string()
                };
                
                vec![Stmt::Call {
                    func: func_name,
                    args: arg_exprs,
                }]
            }
            
            IrInst::IndirectBranch { target } => {
                let target_expr = self.convert_value_to_expr(target);
                vec![Stmt::Expr(Expr::Call {
                    func: "goto".to_string(),
                    args: vec![target_expr],
                })]
            }
        }
    }
    
    /// Convert an IR value to an AST expression
    pub fn convert_value_to_expr(&mut self, value: &Value) -> Expr {
        match value {
            Value::Const(val) => Expr::IntLit(*val),
            Value::WideConst(bytes) => {
                // Convert bytes to integer (simplified)
                let val = if bytes.len() <= 8 {
                    let mut result = 0i64;
                    for (i, &b) in bytes.iter().enumerate() {
                        result |= (b as i64) << (i * 8);
                    }
                    result
                } else {
                    0
                };
                Expr::IntLit(val)
            }
            Value::StringRef(s) => Expr::StringLit(s.clone()),
            Value::Symbol(sym) => Expr::Var(sym.clone()),
            _ => {
                let name = self.get_var_name(value);
                Expr::Var(name)
            }
        }
    }
    
    /// Convert IR OpCode to AST BinOp (None → caller emits an intrinsic-call
    /// form so the operation and both operands survive)
    fn convert_opcode_to_binop(&self, op: OpCode) -> Option<BinOp> {
        match op {
            OpCode::Add => Some(BinOp::Add),
            OpCode::Sub => Some(BinOp::Sub),
            OpCode::Mul => Some(BinOp::Mul),
            OpCode::Div => Some(BinOp::Div),
            OpCode::Mod => Some(BinOp::Mod),
            OpCode::And => Some(BinOp::And),
            OpCode::Or => Some(BinOp::Or),
            OpCode::Xor => Some(BinOp::Xor),
            OpCode::Shl => Some(BinOp::Shl),
            OpCode::Shr | OpCode::Sar => Some(BinOp::Shr),
            OpCode::Eq => Some(BinOp::Eq),
            OpCode::Ne => Some(BinOp::Ne),
            OpCode::LtU => Some(BinOp::LtU),
            OpCode::LeU => Some(BinOp::LeU),
            OpCode::GtU => Some(BinOp::GtU),
            OpCode::GeU => Some(BinOp::GeU),
            OpCode::LtS => Some(BinOp::Lt),
            OpCode::LeS => Some(BinOp::Le),
            OpCode::GtS => Some(BinOp::Gt),
            OpCode::GeS => Some(BinOp::Ge),
            _ => None,
        }
    }
    
    /// Collect all local variables used in the function
    fn collect_locals(&self) -> Vec<LocalVar> {
        let mut locals = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for block in &self.func.blocks {
            for inst in &block.insts {
                if let Some(Value::Var { id, ty }) = inst.dst() {
                    if seen.insert(format!("v{}", id)) {
                        locals.push(LocalVar {
                            name: format!("v{}", id),
                            ty: ty.clone(),
                            is_used: true,
                        });
                    }
                }
                for src in inst.sources() {
                    if let Value::Register { name, ty } = src {
                        if name.starts_with("flag_") || name == "rsp" || name == "esp" {
                            continue;
                        }
                        if seen.insert(name.clone()) {
                            locals.push(LocalVar {
                                name: name.clone(),
                                ty: ty.clone(),
                                is_used: true,
                            });
                        }
                    }
                }
            }
            for inst in block.insts.iter() {
                if let freakre_ir::IrInst::CBranch { cond: Value::Var { id, ty }, .. } = inst {
                    if seen.insert(format!("v{}", id)) {
                        locals.push(LocalVar {
                            name: format!("v{}", id),
                            ty: ty.clone(),
                            is_used: true,
                        });
                    }
                }
            }
        }

        locals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{OpCode, Ty};
    
    #[test]
    fn test_simple_conversion() {
        let mut func = IrFunction::new("test_func", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = func.alloc_var(Ty::i32());
        let v2 = func.alloc_var(Ty::i32());
        
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v2.clone(),
            op: OpCode::Add,
            lhs: v0.clone(),
            rhs: v1.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v2.clone()),
        });
        
        let ast = ir_to_ast(&func);
        
        assert_eq!(ast.name, "test_func");
        assert!(!ast.body.is_empty());
    }
}
