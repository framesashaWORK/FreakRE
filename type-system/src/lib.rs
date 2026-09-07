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

pub mod builtin;
pub mod database;
pub mod layout;
pub mod printer;
pub mod types;

pub use database::TypeDatabase;
use thiserror::Error;
pub use types::*;

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
        self.db
            .add_struct(sdef.clone())
            .map_err(TypeError::Database)?;
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
        self.db
            .add_enum(edef.clone())
            .map_err(TypeError::Database)?;
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

    /// Merge two types (for type inference).
    ///
    /// Deterministic rules:
    /// - pointer + integer -> the pointer itself (commutative: argument
    ///   order does not matter);
    /// - integer + integer -> the wider width wins; mixed signedness
    ///   always resolves to the *unsigned* variant of the resulting width.
    pub fn merge_types(&self, t1: &Type, t2: &Type) -> Result<Type> {
        if t1 == t2 {
            return Ok(t1.clone());
        }

        // Pointer + integer = pointer (with offset); commutative.
        if t1.is_pointer() && t2.is_integer() {
            return Ok(t1.clone());
        }
        if t2.is_pointer() && t1.is_integer() {
            return Ok(t2.clone());
        }

        // Integer promotion: larger width wins; ties and mixed sign
        // resolve to unsigned of the winning width.
        if t1.is_integer() && t2.is_integer() {
            let w1 = t1.bit_width().unwrap_or(0);
            let w2 = t2.bit_width().unwrap_or(0);
            let s1 = t1.is_signed().unwrap_or(true);
            let s2 = t2.is_signed().unwrap_or(true);
            return Ok(Type::Int {
                bits: w1.max(w2),
                signed: s1 && s2,
            });
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
///
/// The lexer operates on `char`s: `pos` is a character offset and
/// `read_identifier` rebuilds text from the char buffer, so slicing can
/// never land mid-UTF-8-character on non-ASCII identifiers.
struct TypeParser {
    input: Vec<char>,
    pos: usize,
}

impl TypeParser {
    fn new(input: &str) -> Self {
        Self {
            input: input.trim().chars().collect(),
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

        loop {
            self.skip_whitespace();
            if self.peek() == Some('*') {
                self.advance();
                result = Type::Pointer(Box::new(result));
            } else {
                break;
            }
        }

        Ok(result)
    }

    fn parse_base_type(&mut self) -> Result<Type> {
        let first = self.read_identifier();

        if first.is_empty() {
            let input: String = self.input.iter().collect();
            return Err(TypeError::Parse(format!(
                "expected a type name in {:?}",
                input
            )));
        }
        if first.chars().next().unwrap().is_ascii_digit() {
            return Err(TypeError::Parse(format!(
                "invalid type name '{}': identifiers cannot start with a digit",
                first
            )));
        }

        if matches!(first.as_str(), "struct" | "enum" | "union") {
            self.skip_whitespace();
            let name = self.read_identifier();
            if name.is_empty() {
                return Err(TypeError::Parse(format!(
                    "expected a name after '{}' keyword",
                    first
                )));
            }
            return Ok(match first.as_str() {
                "enum" => Type::enum_type(name),
                _ => Type::struct_type(name),
            });
        }

        let mut words = vec![first];
        while matches!(
            words.last().map(|s| s.as_str()),
            Some("signed") | Some("unsigned") | Some("long") | Some("short")
        ) || words.len() < 3
            && matches!(words.last().map(|s| s.as_str()), Some("int"))
            && words.len() > 1
        {
            let save = self.pos;
            self.skip_whitespace();
            let next_ok = self
                .peek()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            if !next_ok {
                self.pos = save;
                break;
            }
            let candidate = self.read_identifier();
            let combined = format!("{} {}", words.join(" "), candidate);
            const VALID: &[&str] = &[
                "unsigned char",
                "unsigned short",
                "unsigned short int",
                "unsigned int",
                "unsigned long",
                "unsigned long int",
                "unsigned long long",
                "unsigned long long int",
                "signed char",
                "signed short",
                "signed short int",
                "signed int",
                "signed long",
                "signed long int",
                "signed long long",
                "signed long long int",
                "long long",
                "long long int",
                "long int",
                "long double",
                "short int",
            ];
            if VALID.contains(&combined.as_str()) {
                words.push(candidate);
            } else {
                self.pos = save;
                break;
            }
        }

        match words.join(" ").as_str() {
            "void" => Ok(Type::void()),
            "bool" | "_Bool" => Ok(Type::bool()),
            "char" => Ok(Type::char()),
            "int" | "signed" | "signed int" | "long" | "long int" | "signed long"
            | "signed long int" => Ok(Type::i32()),
            "short" | "short int" | "signed short" | "signed short int" => Ok(Type::i16()),
            "float" => Ok(Type::f32()),
            "double" | "long double" => Ok(Type::f64()),
            "int8_t" | "signed char" => Ok(Type::i8()),
            "uint8_t" | "unsigned char" => Ok(Type::u8()),
            "int16_t" => Ok(Type::i16()),
            "uint16_t" | "unsigned short" | "unsigned short int" => Ok(Type::u16()),
            "int32_t" => Ok(Type::i32()),
            "uint32_t" | "unsigned int" | "unsigned" | "unsigned long" | "unsigned long int" => {
                Ok(Type::u32())
            }
            "int64_t"
            | "long long"
            | "long long int"
            | "signed long long"
            | "signed long long int" => Ok(Type::i64()),
            "uint64_t" | "unsigned long long" | "unsigned long long int" => Ok(Type::u64()),
            name => {
                // Assume it's a typedef or struct name
                Ok(Type::struct_type(name))
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
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
        while self
            .peek()
            .map(|c| c.is_alphanumeric() || c == '_')
            .unwrap_or(false)
        {
            self.advance();
        }
        self.input[start..self.pos].iter().collect()
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

        let s = engine
            .add_struct(
                "Point",
                vec![
                    ("x".to_string(), Type::i32()),
                    ("y".to_string(), Type::i32()),
                ],
            )
            .unwrap();

        // Point has 2 x i32 = 8 bytes, alignment 4
        assert_eq!(s.fields.len(), 2);
    }

    #[test]
    fn test_struct_alignment() {
        let mut engine = TypeEngine::new();

        let s = engine
            .add_struct(
                "Mixed",
                vec![
                    ("a".to_string(), Type::u8()),
                    ("b".to_string(), Type::u32()),
                    ("c".to_string(), Type::u8()),
                ],
            )
            .unwrap();

        // Should have proper offsets with padding
        assert_eq!(s.fields[0].offset, 0); // u8 at 0
        assert_eq!(s.fields[1].offset, 4); // u32 at 4 (aligned)
        assert_eq!(s.fields[2].offset, 8); // u8 at 8
    }

    #[test]
    fn test_enum() {
        let mut engine = TypeEngine::new();

        let e = engine
            .add_enum(
                "Color",
                vec![
                    ("Red".to_string(), 0),
                    ("Green".to_string(), 1),
                    ("Blue".to_string(), 2),
                ],
                PrimitiveType::I32,
            )
            .unwrap();

        assert_eq!(e.variants.len(), 3);
    }

    #[test]
    fn test_parse_non_ascii_identifier_does_not_panic() {
        let mut engine = TypeEngine::new();

        // Regression: peek() counted chars while read_identifier sliced
        // bytes, panicking with "byte index not a char boundary".
        let ty = engine.parse_type("тип").unwrap();
        assert_eq!(ty, Type::struct_type("тип"));

        let ptr = engine.parse_type("тип*").unwrap();
        assert_eq!(ptr, Type::pointer(Type::struct_type("тип")));

        let qualified = engine.parse_type("struct тип").unwrap();
        assert_eq!(qualified, Type::struct_type("тип"));
    }

    #[test]
    fn test_parse_signed_is_int32() {
        let mut engine = TypeEngine::new();

        assert_eq!(engine.parse_type("signed").unwrap(), Type::i32());
        assert_eq!(engine.parse_type("signed int").unwrap(), Type::i32());
        assert_eq!(engine.parse_type("char").unwrap(), Type::char());
    }

    #[test]
    fn test_parse_long_double_is_f64_sized_float() {
        let mut engine = TypeEngine::new();

        let ty = engine.parse_type("long double").unwrap();
        assert_eq!(ty, Type::f64());
        assert!(ty.is_float());
        assert_eq!(engine.size_of(&ty).unwrap(), 8);
    }

    #[test]
    fn test_merge_pointer_integer_commutative() {
        let engine = TypeEngine::new();

        let ptr = Type::pointer(Type::i32());
        let int = Type::u64();

        assert_eq!(engine.merge_types(&ptr, &int).unwrap(), ptr);
        assert_eq!(engine.merge_types(&int, &ptr).unwrap(), ptr);
    }

    #[test]
    fn test_merge_integer_deterministic_widening() {
        let engine = TypeEngine::new();

        // Mixed signedness resolves to unsigned, independent of order.
        assert_eq!(
            engine.merge_types(&Type::i32(), &Type::u32()).unwrap(),
            Type::u32()
        );
        assert_eq!(
            engine.merge_types(&Type::u32(), &Type::i32()).unwrap(),
            Type::u32()
        );

        // Larger width wins; mixed sign still resolves to unsigned.
        assert_eq!(
            engine.merge_types(&Type::i16(), &Type::i32()).unwrap(),
            Type::i32()
        );
        assert_eq!(
            engine.merge_types(&Type::i8(), &Type::i64()).unwrap(),
            Type::i64()
        );
        assert_eq!(
            engine.merge_types(&Type::u8(), &Type::i64()).unwrap(),
            Type::u64()
        );
    }

    #[test]
    fn test_parse_garbage_returns_parse_error() {
        let mut engine = TypeEngine::new();

        for garbage in ["", "   ", "*", "123", "123abc", "struct"] {
            match engine.parse_type(garbage) {
                Err(TypeError::Parse(_)) => {}
                other => panic!(
                    "parse_type({:?}) should be Parse error, got {:?}",
                    garbage, other
                ),
            }
        }
    }
}
