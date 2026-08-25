//! Main decompiler API.

use crate::ast_to_c::ast_to_c;
use crate::ir_to_ast::ir_to_ast;
use freakre_ir::{IrFunction, IrProgram};
use thiserror::Error;

/// Decompiler configuration
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    /// Whether to include variable declarations
    pub include_declarations: bool,
    
    /// Whether to simplify expressions
    pub simplify_expressions: bool,
    
    /// Whether to add comments for addresses
    pub annotate_addresses: bool,
    
    /// Indentation string (default: 4 spaces)
    pub indent: String,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        DecompilerConfig {
            include_declarations: true,
            simplify_expressions: true,
            annotate_addresses: false,
            indent: "    ".to_string(),
        }
    }
}

/// Decompiler errors
#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("Failed to convert IR to AST: {0}")]
    IrToAstError(String),
    
    #[error("Failed to generate C code: {0}")]
    CodeGenError(String),
    
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
}

/// Decompile a single IR function to C pseudocode
pub fn decompile_function(func: &IrFunction) -> Result<String, DecompileError> {
    decompile_function_with_config(func, &DecompilerConfig::default())
}

/// Decompile a function through an explicit SSA round-trip (experimental).
///
/// The function is converted to SSA form (`freakre_ir::ssa::to_ssa`) and
/// lowered back (`from_ssa`, naive edge-copy out-of-SSA) before running the
/// regular pipeline. Falls back to the plain [`decompile_function`] path when
/// SSA construction fails (e.g. unreachable blocks). The default
/// `decompile_function` pipeline is intentionally left untouched.
pub fn decompile_function_ssa(func: &IrFunction) -> Result<String, DecompileError> {
    let default_config = DecompilerConfig::default();
    let mut lifted = func.clone();
    let ssa = match freakre_ir::ssa::to_ssa(&mut lifted) {
        Ok(ssa) => ssa,
        Err(_) => return decompile_function_with_config(func, &default_config),
    };
    let ir = freakre_ir::ssa::from_ssa(&ssa);
    decompile_function_with_config(&ir, &default_config)
}

/// Decompile a single IR function with custom configuration
pub fn decompile_function_with_config(
    func: &IrFunction,
    config: &DecompilerConfig,
) -> Result<String, DecompileError> {
    // Phase 0: IR cleanups (flag folding, temp propagation, dead flags)
    let mut ir = func.clone();
    crate::fold_flags::fold_flag_comparisons(&mut ir);
    crate::fold_flags::propagate_block_temps(&mut ir);
    crate::fold_flags::fuse_load_copies(&mut ir);

    // Phase 0.5: stack-variable recovery (rsp-relative Load/Store → locals).
    // Runs before dead-flag elimination so recovered copies stay alive.
    let stack_var_names = crate::stack_vars::recover_stack_vars(&mut ir);
    crate::fold_flags::eliminate_dead_flag_defs(&mut ir);

    // Phase 1: Convert IR to structured AST
    let mut ast = ir_to_ast(&ir);

    // Recovered slots are declared as v{id}; give them local_xx names.
    crate::stack_vars::apply_recovered_names(&mut ast, &stack_var_names);

    // Phase 2: Type reconstruction (infer types from usage)
    crate::types::reconstruct_types(&mut ast);

    // Phase 3: Expression simplification
    if config.simplify_expressions {
        crate::simplify::simplify_function(&mut ast);
    }

    // Phase 4: Compiler pattern recognition
    crate::patterns::recognize_patterns(&mut ast);

    // Phase 5: Second simplification pass after pattern transforms
    if config.simplify_expressions {
        crate::simplify::simplify_function(&mut ast);
    }

    // Phase 6: Convert AST to C pseudocode
    let c_code = ast_to_c(&ast);

    Ok(c_code)
}

/// Decompile all functions in an IR program
pub fn decompile_program(program: &IrProgram) -> Result<Vec<(String, String)>, DecompileError> {
    decompile_program_with_config(program, &DecompilerConfig::default())
}

/// Decompile all functions in an IR program with custom configuration
pub fn decompile_program_with_config(
    program: &IrProgram,
    config: &DecompilerConfig,
) -> Result<Vec<(String, String)>, DecompileError> {
    let mut results = Vec::new();
    
    for func in &program.functions {
        let c_code = decompile_function_with_config(func, config)?;
        results.push((func.name.clone(), c_code));
    }
    
    Ok(results)
}

/// Decompile a specific function by name
pub fn decompile_function_by_name(
    program: &IrProgram,
    name: &str,
) -> Result<String, DecompileError> {
    let func = program
        .function_by_name(name)
        .ok_or_else(|| DecompileError::FunctionNotFound(name.to_string()))?;
    
    decompile_function(func)
}

/// Decompile a specific function by address
pub fn decompile_function_at(
    program: &IrProgram,
    address: u64,
) -> Result<String, DecompileError> {
    let func = program
        .function_at(address)
        .ok_or_else(|| DecompileError::FunctionNotFound(format!("0x{:X}", address)))?;
    
    decompile_function(func)
}

/// High-level decompiler API
pub struct Decompiler {
    config: DecompilerConfig,
}

impl Decompiler {
    /// Create a new decompiler with default configuration
    pub fn new() -> Self {
        Decompiler {
            config: DecompilerConfig::default(),
        }
    }
    
    /// Create a new decompiler with custom configuration
    pub fn with_config(config: DecompilerConfig) -> Self {
        Decompiler { config }
    }
    
    /// Decompile a single function
    pub fn decompile(&self, func: &IrFunction) -> Result<String, DecompileError> {
        decompile_function_with_config(func, &self.config)
    }
    
    /// Decompile all functions in a program
    pub fn decompile_all(&self, program: &IrProgram) -> Result<Vec<(String, String)>, DecompileError> {
        decompile_program_with_config(program, &self.config)
    }
    
    /// Decompile a function by name
    pub fn decompile_by_name(
        &self,
        program: &IrProgram,
        name: &str,
    ) -> Result<String, DecompileError> {
        decompile_function_by_name(program, name)
    }
    
    /// Decompile a function by address
    pub fn decompile_at(
        &self,
        program: &IrProgram,
        address: u64,
    ) -> Result<String, DecompileError> {
        decompile_function_at(program, address)
    }
}

impl Default for Decompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{IrInst, OpCode, Ty};
    
    #[test]
    fn test_decompile_simple() {
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
        
        let result = decompile_function(&func);
        assert!(result.is_ok());
        
        let c_code = result.unwrap();
        assert!(c_code.contains("test_func"));
        assert!(c_code.contains("return"));
    }
    
    #[test]
    fn test_decompile_program() {
        let mut program = IrProgram::new();
        
        let mut func1 = IrFunction::new("func1", 0x1000);
        func1.push_inst(func1.entry_block, IrInst::Return { value: None });
        
        let mut func2 = IrFunction::new("func2", 0x2000);
        func2.push_inst(func2.entry_block, IrInst::Return { value: None });
        
        program.add_function(func1);
        program.add_function(func2);
        
        let result = decompile_program(&program);
        assert!(result.is_ok());
        
        let decompiled = result.unwrap();
        assert_eq!(decompiled.len(), 2);
    }
    
    #[test]
    fn test_decompiler_api() {
        let mut func = IrFunction::new("test", 0x1000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });
        
        let decompiler = Decompiler::new();
        let result = decompiler.decompile(&func);
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_decompile_function_ssa_diamond() {
        use freakre_ir::{OpCode, Value};
        
        let mut func = IrFunction::new("ssa_diamond", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let then_b = func.add_block("then");
        let else_b = func.add_block("else");
        let merge = func.add_block("merge");
        let x = Value::var(10, Ty::i32());
        
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond,
            target_true: then_b,
            target_false: else_b,
        });
        func.push_inst(then_b, IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(1),
        });
        func.push_inst(then_b, IrInst::Branch { target: merge });
        func.push_inst(else_b, IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(2),
        });
        func.push_inst(else_b, IrInst::Branch { target: merge });
        func.push_inst(merge, IrInst::Return { value: Some(x) });
        
        let result = decompile_function_ssa(&func).unwrap();
        assert!(result.contains("ssa_diamond"));
        assert!(result.contains("return"));
        
        assert_eq!(
            decompile_function(&func).unwrap(),
            decompile_function(&func.clone()).unwrap()
        );
    }
}
