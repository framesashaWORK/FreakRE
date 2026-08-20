//! Main decompiler API.

use crate::ast_to_c::ast_to_c;
use crate::ir_to_ast::ir_to_ast;
use bibleteks_ir::{IrFunction, IrProgram};
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

/// Decompile a single IR function with custom configuration
pub fn decompile_function_with_config(
    func: &IrFunction,
    _config: &DecompilerConfig,
) -> Result<String, DecompileError> {
    // Convert IR to AST
    let ast = ir_to_ast(func);
    
    // Convert AST to C
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
    use bibleteks_ir::{OpCode, Ty};
    
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
}
