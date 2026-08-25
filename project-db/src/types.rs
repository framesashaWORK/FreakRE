use serde::{Deserialize, Serialize};

/// A bookmark for quick navigation to important addresses.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Bookmark {
    pub address: u64,
    pub name: String,
    pub comment: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StructField {
    pub name: String,
    pub ty: Type,
    pub offset: usize,
    pub size: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StructType {
    pub name: String,
    pub fields: Vec<StructField>,
    pub total_size: usize,
    pub alignment: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnumType {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub underlying: PrimitiveType,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FunctionSignature {
    pub return_type: Box<Type>,
    pub parameters: Vec<(String, Type)>,
    pub variadic: bool,
    pub calling_convention: CallingConvention,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    SystemV,
    Microsoft,
    Custom(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Type {
    Primitive(PrimitiveType),
    Pointer(Box<Type>),
    Array(Box<Type>, usize),
    Struct(String), // reference by name
    Enum(String),   // reference by name
    Function(FunctionSignature),
    Typedef(String, Box<Type>),
    Unknown,
}

impl Type {
    pub fn size(&self, type_db: &TypeDatabase) -> Option<usize> {
        match self {
            Type::Primitive(p) => Some(match p {
                PrimitiveType::Void => 0,
                PrimitiveType::Bool | PrimitiveType::I8 | PrimitiveType::U8 | PrimitiveType::Char => 1,
                PrimitiveType::I16 | PrimitiveType::U16 => 2,
                PrimitiveType::I32 | PrimitiveType::U32 | PrimitiveType::F32 => 4,
                PrimitiveType::I64 | PrimitiveType::U64 | PrimitiveType::F64 => 8,
            }),
            Type::Pointer(_) => Some(8), // assume 64-bit
            Type::Array(inner, count) => inner
                .size(type_db)
                .and_then(|s| s.checked_mul(*count)),
            Type::Struct(name) => type_db.get_struct(name).map(|s| s.total_size),
            Type::Enum(name) => type_db.get_enum(name).map(|e| {
                match e.underlying {
                    PrimitiveType::I8 | PrimitiveType::U8 => 1,
                    PrimitiveType::I16 | PrimitiveType::U16 => 2,
                    PrimitiveType::I32 | PrimitiveType::U32 => 4,
                    PrimitiveType::I64 | PrimitiveType::U64 => 8,
                    _ => 4,
                }
            }),
            Type::Function(_) => None,
            Type::Typedef(_, inner) => inner.size(type_db),
            Type::Unknown => None,
        }
    }

    pub fn display(&self, _type_db: &TypeDatabase) -> String {
        match self {
            Type::Primitive(p) => match p {
                PrimitiveType::Void => "void".to_string(),
                PrimitiveType::Bool => "bool".to_string(),
                PrimitiveType::I8 => "int8_t".to_string(),
                PrimitiveType::U8 => "uint8_t".to_string(),
                PrimitiveType::I16 => "int16_t".to_string(),
                PrimitiveType::U16 => "uint16_t".to_string(),
                PrimitiveType::I32 => "int32_t".to_string(),
                PrimitiveType::U32 => "uint32_t".to_string(),
                PrimitiveType::I64 => "int64_t".to_string(),
                PrimitiveType::U64 => "uint64_t".to_string(),
                PrimitiveType::F32 => "float".to_string(),
                PrimitiveType::F64 => "double".to_string(),
                PrimitiveType::Char => "char".to_string(),
            },
            Type::Pointer(inner) => format!("{}*", inner.display(_type_db)),
            Type::Array(inner, size) => format!("{}[{}]", inner.display(_type_db), size),
            Type::Struct(name) => format!("struct {}", name),
            Type::Enum(name) => format!("enum {}", name),
            Type::Function(sig) => {
                let params: Vec<String> = sig.parameters.iter()
                    .map(|(name, ty)| format!("{} {}", ty.display(_type_db), name))
                    .collect();
                let params_str = if sig.variadic {
                    format!("{}, ...", params.join(", "))
                } else {
                    params.join(", ")
                };
                format!("{}({})", sig.return_type.display(_type_db), params_str)
            }
            Type::Typedef(name, _) => name.clone(),
            Type::Unknown => "???".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TypeDatabase {
    pub structs: std::collections::HashMap<String, StructType>,
    pub enums: std::collections::HashMap<String, EnumType>,
    pub typedefs: std::collections::HashMap<String, Type>,
}

impl TypeDatabase {
    pub fn new() -> Self {
        Self {
            structs: std::collections::HashMap::new(),
            enums: std::collections::HashMap::new(),
            typedefs: std::collections::HashMap::new(),
        }
    }

    pub fn add_struct(&mut self, s: StructType) {
        self.structs.insert(s.name.clone(), s);
    }

    pub fn add_enum(&mut self, e: EnumType) {
        self.enums.insert(e.name.clone(), e);
    }

    pub fn add_typedef(&mut self, name: String, ty: Type) {
        self.typedefs.insert(name.clone(), Type::Typedef(name, Box::new(ty)));
    }

    pub fn get_struct(&self, name: &str) -> Option<&StructType> {
        self.structs.get(name)
    }

    pub fn get_enum(&self, name: &str) -> Option<&EnumType> {
        self.enums.get(name)
    }

    pub fn resolve_typedef(&self, ty: &Type) -> Type {
        let mut visited = std::collections::HashSet::new();
        self.resolve_typedef_inner(ty, &mut visited)
    }

    fn resolve_typedef_inner(&self, ty: &Type, visited: &mut std::collections::HashSet<String>) -> Type {
        match ty {
            Type::Typedef(name, _) => {
                if visited.len() >= 64 || !visited.insert(name.clone()) {
                    return ty.clone();
                }
                if let Some(resolved) = self.typedefs.get(name) {
                    self.resolve_typedef_inner(resolved, visited)
                } else {
                    ty.clone()
                }
            }
            _ => ty.clone(),
        }
    }

    pub fn add_windows_types(&mut self) {
        // Common Windows types
        self.add_typedef("DWORD".to_string(), Type::Primitive(PrimitiveType::U32));
        self.add_typedef("WORD".to_string(), Type::Primitive(PrimitiveType::U16));
        self.add_typedef("BYTE".to_string(), Type::Primitive(PrimitiveType::U8));
        self.add_typedef("BOOL".to_string(), Type::Primitive(PrimitiveType::I32));
        self.add_typedef("LONG".to_string(), Type::Primitive(PrimitiveType::I32));
        self.add_typedef("ULONG".to_string(), Type::Primitive(PrimitiveType::U32));
        self.add_typedef("LONGLONG".to_string(), Type::Primitive(PrimitiveType::I64));
        self.add_typedef("ULONGLONG".to_string(), Type::Primitive(PrimitiveType::U64));
        self.add_typedef("HANDLE".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::Void))));
        self.add_typedef("PVOID".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::Void))));
        self.add_typedef("LPVOID".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::Void))));
        self.add_typedef("LPSTR".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::Char))));
        self.add_typedef("LPCSTR".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::Char))));
        self.add_typedef("LPWSTR".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::U16))));
        self.add_typedef("LPCWSTR".to_string(), Type::Pointer(Box::new(Type::Primitive(PrimitiveType::U16))));
        self.add_typedef("SIZE_T".to_string(), Type::Primitive(PrimitiveType::U64));
        self.add_typedef("UINT".to_string(), Type::Primitive(PrimitiveType::U32));
        self.add_typedef("INT".to_string(), Type::Primitive(PrimitiveType::I32));
    }

    pub fn add_posix_types(&mut self) {
        self.add_typedef("size_t".to_string(), Type::Primitive(PrimitiveType::U64));
        self.add_typedef("ssize_t".to_string(), Type::Primitive(PrimitiveType::I64));
        self.add_typedef("pid_t".to_string(), Type::Primitive(PrimitiveType::I32));
        self.add_typedef("uid_t".to_string(), Type::Primitive(PrimitiveType::U32));
        self.add_typedef("gid_t".to_string(), Type::Primitive(PrimitiveType::U32));
        self.add_typedef("off_t".to_string(), Type::Primitive(PrimitiveType::I64));
    }
}

impl Default for TypeDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_sizes() {
        let db = TypeDatabase::new();
        assert_eq!(Type::Primitive(PrimitiveType::U8).size(&db), Some(1));
        assert_eq!(Type::Primitive(PrimitiveType::U32).size(&db), Some(4));
        assert_eq!(Type::Primitive(PrimitiveType::U64).size(&db), Some(8));
    }

    #[test]
    fn test_pointer_size() {
        let db = TypeDatabase::new();
        let ptr = Type::Pointer(Box::new(Type::Primitive(PrimitiveType::U8)));
        assert_eq!(ptr.size(&db), Some(8));
    }

    #[test]
    fn test_array_size() {
        let db = TypeDatabase::new();
        let arr = Type::Array(Box::new(Type::Primitive(PrimitiveType::U32)), 10);
        assert_eq!(arr.size(&db), Some(40));
    }

    #[test]
    fn test_array_size_overflow_is_graceful() {
        let db = TypeDatabase::new();
        // usize::MAX * 8 would overflow; must yield None instead of panicking.
        let arr = Type::Array(
            Box::new(Type::Primitive(PrimitiveType::U64)),
            usize::MAX,
        );
        assert_eq!(arr.size(&db), None);
    }
}
