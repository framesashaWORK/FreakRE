//! Convert IR to AST.

use crate::ast::*;
use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};
use std::collections::HashMap;

/// Convert an IR function to an AST function
pub fn ir_to_ast(func: &IrFunction) -> AstFunction {
    let mut converter = IrToAstConverter::new(func);
    converter.convert()
}

/// Map an IR access size in bytes to the AST type of the pointee.
///
/// `4 => None` keeps the historical bare `Deref` form for the default slot
/// size, so existing output is unchanged; downstream passes treat a bare
/// deref as exactly 4 bytes. Other well-known widths (1, 2, 8) become an
/// explicit pointee cast so pattern passes stay sound. Unmapped sizes keep
/// the bare form rather than guessing a width.
fn access_width_ty(size_bytes: u32) -> Option<Ty> {
    match size_bytes {
        1 => Some(Ty::UInt(8)),
        2 => Some(Ty::UInt(16)),
        4 => None,
        8 => Some(Ty::Int(64)),
        _ => None,
    }
}

pub struct IrToAstConverter<'a> {
    func: &'a IrFunction,
    var_names: HashMap<Value, String>,
    var_counter: u32,
    /// (slot index, alias) of recovered parameters: every alias spelling
    /// renders as `a{slot+1}` (the IR may carry `ecx` where the canonical
    /// slot is `rcx`).
    param_regs: Vec<(usize, &'a str)>,
}

impl<'a> IrToAstConverter<'a> {
    pub fn new(func: &'a IrFunction) -> Self {
        IrToAstConverter {
            func,
            var_names: HashMap::new(),
            var_counter: 0,
            param_regs: Vec::new(),
        }
    }

    /// Index of `name` in the recovered parameter registers, if any.
    fn param_reg_index(&self, name: &str) -> Option<usize> {
        self.param_regs.iter().find(|(_, a)| *a == name).map(|(s, _)| *s)
    }

    /// Pointer-width guess: x64 lifter models registers with 64-bit types.
    fn is_64bit_arch(&self) -> bool {
        self.func.blocks.iter().any(|b| {
            b.insts.iter().any(|i| {
                i.dst().is_some_and(|d| {
                    matches!(d, Value::Register { ty: Ty::Int(64) | Ty::UInt(64), .. })
                })
            })
        })
    }

    fn convert(&mut self) -> AstFunction {
        let mut ast_func = AstFunction::new(&self.func.name);
        ast_func.entry_address = self.func.entry_address;

        // Recovered parameters: signature + a1..aN rendering of register reads.
        // Architecture comes from the lifter through the function name prefix
        // is unreliable; use the pointer width recorded on the IR (blocks
        // carry 64-bit register types on x64).
        let is_64 = self.is_64bit_arch();
        let recovered = crate::params::recover_params(self.func, is_64);
        crate::params::apply_params(&mut ast_func, &recovered);
        // Every alias spelling renders as a{slot+1}: the IR may carry `ecx`
        // where the canonical slot is `rcx`.
        self.param_regs = recovered
            .iter()
            .flat_map(|p| p.aliases.iter().map(move |a| (p.slot, *a)))
            .collect();

        // Структурировать контрольный поток.
        // Вызывающий (decompile.rs) обязан передать phi-free IR;
        // прямые тестовые вызовы строят IR без phi.
        let body = crate::structuring::structure_control_flow(self.func, self);
        ast_func.body = body;

        ast_func.locals = self.collect_locals(self.func);

        // Set return type (default to void if not inferred)
        ast_func.return_type = self.func.metadata.return_type.clone().unwrap_or(Ty::Void);

        // Consume freakre-type-propagation results: pointer typing through
        // Load/Store address usage and integer widths from memory access
        // sizes land on params/locals before any AST-level pass runs.
        let inferred = crate::types::propagated_var_types(self.func);
        crate::types::apply_propagated_types(&mut ast_func, &inferred);

        ast_func
    }

    /// Collect all local variables used in the function
    fn collect_locals(&self, func: &IrFunction) -> Vec<LocalVar> {
        let mut locals = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for block in &func.blocks {
            for inst in &block.insts {
                if let Some(Value::Var { id, ty }) = inst.dst() {
                    if seen.insert(format!("v{}", id)) {
                        locals.push(LocalVar {
                            name: format!("v{}", id),
                            ty: ty.clone(),
                            is_used: true,
                            fields: Vec::new(),
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
                            fields: Vec::new(),
                            });
                        }
                    }
                }
            }
            for inst in block.insts.iter() {
                if let freakre_ir::IrInst::CBranch {
                    cond: Value::Var { id, ty },
                    ..
                } = inst
                {
                    if seen.insert(format!("v{}", id)) {
                        locals.push(LocalVar {
                            name: format!("v{}", id),
                            ty: ty.clone(),
                            is_used: true,
                            fields: Vec::new(),
                        });
                    }
                }
            }
        }

        locals
    }

    /// Get or create a name for a value
    pub fn get_var_name(&mut self, value: &Value) -> String {
        if let Some(name) = self.var_names.get(value) {
            return name.clone();
        }
        let name = match value {
            Value::Var { id, .. } => format!("v{}", id),
            Value::Register { name, .. } => {
                // Recovered parameter registers render as `a1..aN`.
                if let Some(idx) = self.param_reg_index(name) {
                    return format!("a{}", idx + 1);
                }
                name.clone()
            }
            Value::Symbol(sym) => sym.clone(),
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
                // Identity-mask fold: the x86 lifter materializes subregister
                // mirrors as `view = And(parent, mask(view))` (e.g. a Call
                // returning in rax also defines `eax = rax & 0xFFFF_FFFF` so
                // later `mov [mem], eax` spills observe the fresh value).
                // When the mask covers the full destination width the And is
                // a no-op extract — print the plain value so the C output
                // reads `eax = rax` (a copy the simplifier coalesces) instead
                // of `eax = rax & 0xFFFFFFFF` (opaque noise). Sound: for a
                // w-bit destination, `v & ((1<<w)-1)` keeps exactly the bits
                // the assignment would keep anyway.
                if *op == OpCode::And {
                    if let (Value::Const(m), Ty::Int(w) | Ty::UInt(w)) = (rhs, dst.ty()) {
                        let full: i64 = if w >= 64 {
                            -1
                        } else {
                            (1i64 << w) - 1
                        };
                        if *m == full {
                            return vec![Stmt::Assign {
                                target,
                                value: lhs_expr,
                            }];
                        }
                    }
                }
                let value = match self.convert_opcode_to_binop(*op) {
                    Some(bin_op) => Expr::Binary {
                        op: bin_op,
                        lhs: Box::new(lhs_expr),
                        rhs: Box::new(rhs_expr),
                    },
                    None => Expr::Call {
                        func: op.to_string(),
                        args: vec![lhs_expr, rhs_expr],
                    },
                };
                vec![Stmt::Assign { target, value }]
            }
            IrInst::Adc { dst, a, b, carry } => {
                let target = self.convert_value_to_expr(dst);
                let a_expr = self.convert_value_to_expr(a);
                let b_expr = self.convert_value_to_expr(b);
                let c_expr = self.convert_value_to_expr(carry);
                let sum = Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(a_expr),
                    rhs: Box::new(b_expr),
                };
                vec![Stmt::Assign {
                    target,
                    value: Expr::Binary {
                        op: BinOp::Add,
                        lhs: Box::new(sum),
                        rhs: Box::new(c_expr),
                    },
                }]
            }
            IrInst::Sbb { dst, a, b, carry } => {
                let target = self.convert_value_to_expr(dst);
                let a_expr = self.convert_value_to_expr(a);
                let b_expr = self.convert_value_to_expr(b);
                let c_expr = self.convert_value_to_expr(carry);
                let diff = Expr::Binary {
                    op: BinOp::Sub,
                    lhs: Box::new(a_expr),
                    rhs: Box::new(b_expr),
                };
                vec![Stmt::Assign {
                    target,
                    value: Expr::Binary {
                        op: BinOp::Sub,
                        lhs: Box::new(diff),
                        rhs: Box::new(c_expr),
                    },
                }]
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
                    OpCode::FloatNeg | OpCode::FloatAbs | OpCode::FloatSqrt => Expr::Call {
                        func: op.to_string(),
                        args: vec![src_expr],
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
                    _ => src_expr,
                };
                vec![Stmt::Assign { target, value }]
            }
            IrInst::Load { dst, addr, size } => {
                let target = self.convert_value_to_expr(dst);
                let addr_expr = self.convert_value_to_expr(addr);
                // Preserve the access width when it differs from the default
                // 4-byte slot: `*(uint8_t *)addr` etc. Pattern passes rely on
                // this to stay sound (a 1-byte load is not a 4-byte value).
                let value = match access_width_ty(*size) {
                    Some(w) => Expr::Deref(Box::new(Expr::Cast {
                        ty: Ty::Ptr(Box::new(w)),
                        expr: Box::new(addr_expr),
                    })),
                    None => Expr::Deref(Box::new(addr_expr)),
                };
                vec![Stmt::Assign { target, value }]
            }
            IrInst::Store { addr, value, size } => {
                let addr_expr = self.convert_value_to_expr(addr);
                let value_expr = self.convert_value_to_expr(value);
                // Mirror the Load arm: a narrow store must not be read back
                // as a 4-byte slot by later pattern passes.
                let target = match access_width_ty(*size) {
                    Some(w) => Expr::Deref(Box::new(Expr::Cast {
                        ty: Ty::Ptr(Box::new(w)),
                        expr: Box::new(addr_expr),
                    })),
                    None => Expr::Deref(Box::new(addr_expr)),
                };
                vec![Stmt::Assign { target, value: value_expr }]
            }
            IrInst::Call { dst, target, args } => {
                let func_name = match target {
                    Value::Symbol(sym) => sym.clone(),
                    Value::Const(addr) => format!("func_0x{:X}", addr),
                    _ => self.get_var_name(target),
                };
                let arg_exprs: Vec<Expr> = args
                    .iter()
                    .map(|arg| self.convert_value_to_expr(arg))
                    .collect();
                if let Some(dst_val) = dst {
                    vec![Stmt::Assign {
                        target: self.convert_value_to_expr(dst_val),
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
                vec![Stmt::Return {
                    value: value.as_ref().map(|v| self.convert_value_to_expr(v)),
                }]
            }
            IrInst::Branch { .. } | IrInst::CBranch { .. } => vec![],
            IrInst::Nop => vec![Stmt::Empty],
            IrInst::Syscall { number, args } => {
                let arg_exprs: Vec<Expr> = args
                    .iter()
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
                vec![Stmt::Expr(Expr::Call {
                    func: "goto".to_string(),
                    args: vec![self.convert_value_to_expr(target)],
                })]
            }
            // Normally consumed by the structurer (→ Stmt::Switch). This
            // fallback keeps unstructured pipelines well-defined.
            IrInst::Switch { index, .. } => {
                vec![Stmt::Expr(Expr::Call {
                    func: "switch".to_string(),
                    args: vec![self.convert_value_to_expr(index)],
                })]
            }
            IrInst::Phi { .. } => vec![],
        }
    }

    /// Convert an IR value to an AST expression
    pub fn convert_value_to_expr(&mut self, value: &Value) -> Expr {
        match value {
            Value::Const(val) => Expr::IntLit(*val),
            Value::WideConst(bytes) => {
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

    /// Convert IR OpCode to AST BinOp (None → caller emits intrinsic-call).
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

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v2.clone(),
                op: OpCode::Add,
                lhs: v0.clone(),
                rhs: v1.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Return {
                value: Some(v2.clone()),
            },
        );

        let ast = ir_to_ast(&func);

        assert_eq!(ast.name, "test_func");
        assert!(!ast.body.is_empty());
    }
}
