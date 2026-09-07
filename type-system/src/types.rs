//! Core type definitions

use serde::{Deserialize, Serialize};

/// Primitive type enumeration (for convenience matching and interop)
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrimitiveType {
    Void,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Char,
}

/// A type in the type system
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Type {
    /// Void type
    Void,
    /// Boolean
    Bool,
    /// Character (1 byte)
    Char,
    /// Signed integer with specified bit width
    Int { bits: u32, signed: bool },
    /// Floating-point with specified bit width
    Float { bits: u32 },
    /// Pointer to another type
    Pointer(Box<Type>),
    /// Array with element type and length
    Array(Box<Type>, usize),
    /// Struct type (by name reference)
    Struct(String),
    /// Union type (by name reference)
    Union(String),
    /// Enum type (by name reference)
    Enum(String),
    /// Typedef (by name reference)
    Typedef(String),
    /// Function pointer
    Function(FunctionType),
    /// Unknown/generic type
    Unknown,
}

impl Type {
    // === Convenience constructors ===

    pub fn void() -> Self {
        Type::Void
    }

    pub fn bool() -> Self {
        Type::Bool
    }

    pub fn char() -> Self {
        Type::Char
    }

    pub fn i8() -> Self {
        Type::Int {
            bits: 8,
            signed: true,
        }
    }

    pub fn u8() -> Self {
        Type::Int {
            bits: 8,
            signed: false,
        }
    }

    pub fn i16() -> Self {
        Type::Int {
            bits: 16,
            signed: true,
        }
    }

    pub fn u16() -> Self {
        Type::Int {
            bits: 16,
            signed: false,
        }
    }

    pub fn i32() -> Self {
        Type::Int {
            bits: 32,
            signed: true,
        }
    }

    pub fn u32() -> Self {
        Type::Int {
            bits: 32,
            signed: false,
        }
    }

    pub fn i64() -> Self {
        Type::Int {
            bits: 64,
            signed: true,
        }
    }

    pub fn u64() -> Self {
        Type::Int {
            bits: 64,
            signed: false,
        }
    }

    pub fn f32() -> Self {
        Type::Float { bits: 32 }
    }

    pub fn f64() -> Self {
        Type::Float { bits: 64 }
    }

    pub fn pointer(inner: Type) -> Self {
        Type::Pointer(Box::new(inner))
    }

    pub fn array(element: Type, length: usize) -> Self {
        Type::Array(Box::new(element), length)
    }

    pub fn struct_type(name: impl Into<String>) -> Self {
        Type::Struct(name.into())
    }

    pub fn union_type(name: impl Into<String>) -> Self {
        Type::Union(name.into())
    }

    pub fn enum_type(name: impl Into<String>) -> Self {
        Type::Enum(name.into())
    }

    pub fn typedef(name: impl Into<String>) -> Self {
        Type::Typedef(name.into())
    }

    /// Check if type is a primitive
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            Type::Void | Type::Bool | Type::Char | Type::Int { .. } | Type::Float { .. }
        )
    }

    /// Check if type is a pointer
    pub fn is_pointer(&self) -> bool {
        matches!(self, Type::Pointer(_))
    }

    /// Check if type is an integer
    pub fn is_integer(&self) -> bool {
        matches!(self, Type::Int { .. })
    }

    /// Check if type is a float
    pub fn is_float(&self) -> bool {
        matches!(self, Type::Float { .. })
    }

    /// Get the pointed-to type (if this is a pointer)
    pub fn pointee(&self) -> Option<&Type> {
        match self {
            Type::Pointer(inner) => Some(inner),
            _ => None,
        }
    }

    /// Dereference a pointer type
    pub fn deref(&self) -> Option<Type> {
        match self {
            Type::Pointer(inner) => Some(*inner.clone()),
            _ => None,
        }
    }

    /// Add a pointer level
    pub fn add_pointer(self) -> Self {
        Type::Pointer(Box::new(self))
    }

    /// Get the size in bits (for primitives)
    pub fn bit_width(&self) -> Option<u32> {
        match self {
            Type::Void => Some(0),
            Type::Bool => Some(8),
            Type::Char => Some(8),
            Type::Int { bits, .. } => Some(*bits),
            Type::Float { bits } => Some(*bits),
            _ => None,
        }
    }

    /// Check if integer is signed
    pub fn is_signed(&self) -> Option<bool> {
        match self {
            Type::Int { signed, .. } => Some(*signed),
            _ => None,
        }
    }
}

/// Function type (signature)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FunctionType {
    /// Return type
    pub return_type: Box<Type>,
    /// Parameter types
    pub parameters: Vec<Type>,
    /// Whether function is variadic
    pub variadic: bool,
    /// Calling convention
    pub calling_convention: CallingConvention,
}

impl FunctionType {
    pub fn new(return_type: Type, parameters: Vec<Type>) -> Self {
        Self {
            return_type: Box::new(return_type),
            parameters,
            variadic: false,
            calling_convention: CallingConvention::Cdecl,
        }
    }

    pub fn with_variadic(mut self, variadic: bool) -> Self {
        self.variadic = variadic;
        self
    }

    pub fn with_calling_convention(mut self, cc: CallingConvention) -> Self {
        self.calling_convention = cc;
        self
    }
}

/// Calling convention
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    SystemV,
    Win64,
    Unknown,
}

/// Struct definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub packed: bool,
    pub comment: Option<String>,
}

impl StructDef {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            packed: false,
            comment: None,
        }
    }

    pub fn add_field(&mut self, name: impl Into<String>, ty: Type) {
        self.fields.push(Field {
            name: name.into(),
            ty,
            offset: 0, // Will be calculated
            bit_offset: None,
            comment: None,
        });
    }

    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn get_field_at_offset(&self, offset: usize) -> Option<&Field> {
        self.fields.iter().find(|f| f.offset == offset)
    }
}

/// Struct/union field
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    pub offset: usize,
    pub bit_offset: Option<u32>,
    pub comment: Option<String>,
}

/// Union definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnionDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub comment: Option<String>,
}

impl UnionDef {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            comment: None,
        }
    }

    pub fn add_field(&mut self, name: impl Into<String>, ty: Type) {
        self.fields.push(Field {
            name: name.into(),
            ty,
            offset: 0,
            bit_offset: None,
            comment: None,
        });
    }
}

/// Enum definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnumDef {
    pub name: String,
    pub base_type: Type,
    pub variants: Vec<EnumVariant>,
    pub comment: Option<String>,
}

impl EnumDef {
    pub fn new(name: impl Into<String>, base_type: Type) -> Self {
        Self {
            name: name.into(),
            base_type,
            variants: Vec::new(),
            comment: None,
        }
    }

    pub fn add_variant(&mut self, name: impl Into<String>, value: i64) {
        self.variants.push(EnumVariant {
            name: name.into(),
            value,
            comment: None,
        });
    }

    pub fn get_variant_by_value(&self, value: i64) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.value == value)
    }

    pub fn get_variant_by_name(&self, name: &str) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.name == name)
    }
}

/// Enum variant
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
    pub comment: Option<String>,
}

/// Typedef definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypedefDef {
    pub name: String,
    pub base_type: Type,
    pub comment: Option<String>,
}

impl TypedefDef {
    pub fn new(name: impl Into<String>, base_type: Type) -> Self {
        Self {
            name: name.into(),
            base_type,
            comment: None,
        }
    }
}

/// Builder for creating structs
pub struct StructBuilder {
    name: String,
    fields: Vec<Field>,
    packed: bool,
}

impl StructBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            packed: false,
        }
    }

    pub fn add_field(mut self, name: impl Into<String>, ty: Type) -> Self {
        self.fields.push(Field {
            name: name.into(),
            ty,
            offset: 0,
            bit_offset: None,
            comment: None,
        });
        self
    }

    pub fn packed(mut self, packed: bool) -> Self {
        self.packed = packed;
        self
    }

    pub fn build(self) -> StructDef {
        StructDef {
            name: self.name,
            fields: self.fields,
            packed: self.packed,
            comment: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_types() {
        assert!(Type::i32().is_integer());
        assert!(Type::f64().is_float());
        assert!(Type::bool().is_primitive());
    }

    #[test]
    fn test_pointer() {
        let ptr = Type::pointer(Type::i32());
        assert!(ptr.is_pointer());
        assert_eq!(ptr.pointee(), Some(&Type::i32()));
        assert_eq!(ptr.deref(), Some(Type::i32()));
    }

    #[test]
    fn test_struct_builder() {
        let s = StructBuilder::new("Point")
            .add_field("x", Type::i32())
            .add_field("y", Type::i32())
            .build();

        assert_eq!(s.name, "Point");
        assert_eq!(s.fields.len(), 2);
        assert_eq!(s.fields[0].name, "x");
        assert_eq!(s.fields[1].name, "y");
    }
}
