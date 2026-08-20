#![allow(dead_code, unused_assignments)]
//! # Type System
//!
//! Type inference and management for decompiled code.
//! Supports C-like type definitions, automatic type propagation,
//! and integration with IDA-style type libraries.
//!
//! ## Features
//!
//! - Parse C type declarations
//! - Type inference from usage
//! - Struct layout calculation
//! - Type library management

pub mod types;
pub mod database;
pub mod builtin;
pub mod layout;
pub mod printer;

pub use types::*;
pub use database::TypeDatabase;
use thiserror::Error;

// Re-export the canonical TypeError from database module
pub use database::TypeError as DbTypeError;

#[derive(Error, Debug)]
pub enum TypeError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Unknown type: {0}")]
    UnknownType(String),
    #[error("Conflicting types: {0} vs {1}")]
    Conflict(String, String),
    #[error("Invalid struct layout: {0}")]
    InvalidLayout(String),
    #[error("Database error: {0}")]
    Database(#[from] DbTypeError),
}

pub type Result<T> = std::result::Result<T, TypeError>;

/// Type inference engine
pub struct TypeEngine {
    db: TypeDatabase,
}

impl TypeEngine {
    pub fn new() -> Self {
        Self {
            db: TypeDatabase::new(),
        }
    }

    pub fn with_database(db: TypeDatabase) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &TypeDatabase {
        &self.db
    }

    pub fn database_mut(&mut self) -> &mut TypeDatabase {
        &mut self.db
    }

    /// Parse a C-style type declaration
    pub fn parse_type(&mut self, decl: &str) -> Result<Type> {
        let parser = TypeParser::new(decl);
        parser.parse()
    }

    /// Add a struct definition using fields list
    pub fn add_struct(
        &mut self,
        name: &str,
        fields: Vec<(String, Type)>,
    ) -> std::result::Result<StructDef, TypeError> {
        let mut sdef = StructDef::new(name);
        for (fname, fty) in fields {
            sdef.add_field(fname, fty);
        }
        // Calculate offsets
        let mut offset = 0usize;
        let mut max_align = 1usize;
        for field in &mut sdef.fields {
            let align = self.align_of(&field.ty).unwrap_or(1);
            if !sdef.packed {
                offset = (offset + align - 1) & !(align - 1);
            }
            field.offset = offset;
            let size = self.size_of(&field.ty).unwrap_or(1);
            offset += size;
            max_align = max_align.max(align);
        }
        if !sdef.packed {
            offset = (offset + max_align - 1) & !(max_align - 1);
        }
        self.db.add_struct(sdef.clone()).map_err(TypeError::Database)?;
        Ok(sdef)
    }

    /// Add a struct definition directly
    pub fn add_struct_def(&mut self, def: StructDef) -> Result<()> {
        self.db.add_struct(def).map_err(TypeError::Database)
    }

    /// Add an enum definition
    pub fn add_enum(
        &mut self,
        name: &str,
        variants: Vec<(String, i64)>,
        _base: PrimitiveType,
    ) -> std::result::Result<EnumDef, TypeError> {
        let mut edef = EnumDef::new(name, Type::i32());
        for (vname, vval) in variants {
            edef.add_variant(vname, vval);
        }
        self.db.add_enum(edef.clone()).map_err(TypeError::Database)?;
        Ok(edef)
    }

    /// Add an enum definition directly
    pub fn add_enum_def(&mut self, def: EnumDef) -> Result<()> {
        self.db.add_enum(def).map_err(TypeError::Database)
    }

    /// Infer type from value
    pub fn infer_from_value(&self, value: i64) -> Type {
        if value >= i8::MIN as i64 && value <= i8::MAX as i64 {
            Type::i8()
        } else if value >= i16::MIN as i64 && value <= i16::MAX as i64 {
            Type::i16()
        } else if value >= i32::MIN as i64 && value <= i32::MAX as i64 {
            Type::i32()
        } else {
            Type::i64()
        }
    }

    /// Merge two types (for type inference)
    pub fn merge_types(&self, t1: &Type, t2: &Type) -> Result<Type> {
        if t1 == t2 {
            return Ok(t1.clone());
        }

        // Pointer + integer = pointer (with offset)
        if let Type::Pointer(inner) = t1 {
            if t2.is_integer() {
                return Ok(Type::Pointer(inner.clone()));
            }
        }

        // Integer promotion
        if t1.is_integer() && t2.is_integer() {
            let size1 = t1.bit_width().unwrap_or(0);
            let size2 = t2.bit_width().unwrap_or(0);
            if size1 >= size2 {
                return Ok(t1.clone());
            } else {
                return Ok(t2.clone());
            }
        }

        Err(TypeError::Conflict(
            format!("{:?}", t1),
            format!("{:?}", t2),
        ))
    }

    /// Calculate size of a type
    pub fn size_of(&self, ty: &Type) -> Result<usize> {
        self.db.size_of(ty).map_err(TypeError::Database)
    }

    /// Calculate alignment of a type
    pub fn align_of(&self, ty: &Type) -> Result<usize> {
        self.db.align_of(ty).map_err(TypeError::Database)
    }
}

impl Default for TypeEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple C-style type parser
struct TypeParser {
    input: String,
    pos: usize,
}

impl TypeParser {
    fn new(input: &str) -> Self {
        Self {
            input: input.trim().to_string(),
            pos: 0,
        }
    }

    fn parse(mut self) -> Result<Type> {
        self.skip_whitespace();
        self.parse_type()
    }

    fn parse_type(&mut self) -> Result<Type> {
        self.skip_whitespace();

        // Handle pointers
        let mut pointer_count = 0;
        while self.peek() == Some('*') {
            self.advance();
            pointer_count += 1;
            self.skip_whitespace();
        }

        let base_type = self.parse_base_type()?;

        // Wrap in pointers
        let mut result = base_type;
        for _ in 0..pointer_count {
            result = Type::Pointer(Box::new(result));
        }

        Ok(result)
    }

    fn parse_base_type(&mut self) -> Result<Type> {
        let token = self.read_identifier();

        match token.as_str() {
            "void" => Ok(Type::void()),
            "bool" | "_Bool" => Ok(Type::bool()),
            "char" => Ok(Type::char()),
            "int" | "long" => Ok(Type::i32()),
            "short" => Ok(Type::i16()),
            "float" => Ok(Type::f32()),
            "double" => Ok(Type::f64()),
            "int8_t" | "signed char" => Ok(Type::i8()),
            "uint8_t" | "unsigned char" => Ok(Type::u8()),
            "int16_t" => Ok(Type::i16()),
            "uint16_t" | "unsigned short" => Ok(Type::u16()),
            "int32_t" => Ok(Type::i32()),
            "uint32_t" | "unsigned int" | "unsigned" => Ok(Type::u32()),
            "int64_t" => Ok(Type::i64()),
            "uint64_t" | "unsigned long long" => Ok(Type::u64()),
            "struct" => {
                self.skip_whitespace();
                let name = self.read_identifier();
                Ok(Type::struct_type(name))
            }
            "enum" => {
                self.skip_whitespace();
                let name = self.read_identifier();
                Ok(Type::enum_type(name))
            }
            name => {
                // Assume it's a typedef or struct name
                Ok(Type::struct_type(name))
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.chars().nth(self.pos)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn skip_whitespace(&mut self) {
        while self.peek().map(|c| c.is_whitespace()).unwrap_or(false) {
            self.advance();
        }
    }

    fn read_identifier(&mut self) -> String {
        self.skip_whitespace();
        let start = self.pos;
        while self.peek().map(|c| c.is_alphanumeric() || c == '_').unwrap_or(false) {
            self.advance();
        }
        self.input[start..self.pos].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primitive() {
        let mut engine = TypeEngine::new();

        assert_eq!(engine.parse_type("int").unwrap(), Type::i32());
        assert_eq!(engine.parse_type("char").unwrap(), Type::char());
        assert_eq!(engine.parse_type("uint64_t").unwrap(), Type::u64());
    }

    #[test]
    fn test_parse_pointer() {
        let mut engine = TypeEngine::new();

        let ptr = engine.parse_type("int*").unwrap();
        assert!(matches!(ptr, Type::Pointer(_)));

        let ptr_ptr = engine.parse_type("int**").unwrap();
        assert!(matches!(ptr_ptr, Type::Pointer(_)));
    }

    #[test]
    fn test_struct_layout() {
        let mut engine = TypeEngine::new();

        let s = engine.add_struct("Point", vec![
            ("x".to_string(), Type::i32()),
            ("y".to_string(), Type::i32()),
        ]).unwrap();

        // Point has 2 x i32 = 8 bytes, alignment 4
        assert_eq!(s.fields.len(), 2);
    }

    #[test]
    fn test_struct_alignment() {
        let mut engine = TypeEngine::new();

        let s = engine.add_struct("Mixed", vec![
            ("a".to_string(), Type::u8()),
            ("b".to_string(), Type::u32()),
            ("c".to_string(), Type::u8()),
        ]).unwrap();

        // Should have proper offsets with padding
        assert_eq!(s.fields[0].offset, 0); // u8 at 0
        assert_eq!(s.fields[1].offset, 4); // u32 at 4 (aligned)
        assert_eq!(s.fields[2].offset, 8); // u8 at 8
    }

    #[test]
    fn test_enum() {
        let mut engine = TypeEngine::new();

        let e = engine.add_enum("Color", vec![
            ("Red".to_string(), 0),
            ("Green".to_string(), 1),
            ("Blue".to_string(), 2),
        ], PrimitiveType::I32).unwrap();

        assert_eq!(e.variants.len(), 3);
    }
}


