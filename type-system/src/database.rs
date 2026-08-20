//! Type database for managing all types in a project

use crate::{EnumDef, StructDef, TypedefDef, Type, UnionDef};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TypeError {
    #[error("Type not found: {0}")]
    NotFound(String),
    #[error("Type already exists: {0}")]
    AlreadyExists(String),
    #[error("Invalid type: {0}")]
    Invalid(String),
    #[error("Circular reference detected: {0}")]
    CircularReference(String),
}

pub type Result<T> = std::result::Result<T, TypeError>;

/// Database of all types in a project
#[derive(Clone, Debug, Default)]
pub struct TypeDatabase {
    structs: HashMap<String, StructDef>,
    unions: HashMap<String, UnionDef>,
    enums: HashMap<String, EnumDef>,
    typedefs: HashMap<String, TypedefDef>,
}

impl TypeDatabase {
    pub fn new() -> Self {
        let mut db = Self::default();
        db.register_builtins();
        db
    }

    /// Register built-in types (Windows, POSIX, etc.)
    fn register_builtins(&mut self) {
        crate::builtin::register_all(self);
    }

    /// Add a struct definition
    pub fn add_struct(&mut self, def: StructDef) -> Result<()> {
        if self.structs.contains_key(&def.name) {
            return Err(TypeError::AlreadyExists(def.name));
        }
        self.structs.insert(def.name.clone(), def);
        Ok(())
    }

    /// Get a struct by name
    pub fn get_struct(&self, name: &str) -> Option<&StructDef> {
        self.structs.get(name)
    }

    /// Update a struct
    pub fn update_struct(&mut self, def: StructDef) -> Result<()> {
        if !self.structs.contains_key(&def.name) {
            return Err(TypeError::NotFound(def.name));
        }
        self.structs.insert(def.name.clone(), def);
        Ok(())
    }

    /// Remove a struct
    pub fn remove_struct(&mut self, name: &str) -> Result<()> {
        if self.structs.remove(name).is_none() {
            return Err(TypeError::NotFound(name.to_string()));
        }
        Ok(())
    }

    /// List all structs
    pub fn list_structs(&self) -> Vec<&StructDef> {
        self.structs.values().collect()
    }

    /// Add a union definition
    pub fn add_union(&mut self, def: UnionDef) -> Result<()> {
        if self.unions.contains_key(&def.name) {
            return Err(TypeError::AlreadyExists(def.name));
        }
        self.unions.insert(def.name.clone(), def);
        Ok(())
    }

    /// Get a union by name
    pub fn get_union(&self, name: &str) -> Option<&UnionDef> {
        self.unions.get(name)
    }

    /// Add an enum definition
    pub fn add_enum(&mut self, def: EnumDef) -> Result<()> {
        if self.enums.contains_key(&def.name) {
            return Err(TypeError::AlreadyExists(def.name));
        }
        self.enums.insert(def.name.clone(), def);
        Ok(())
    }

    /// Get an enum by name
    pub fn get_enum(&self, name: &str) -> Option<&EnumDef> {
        self.enums.get(name)
    }

    /// Add a typedef
    pub fn add_typedef(&mut self, def: TypedefDef) -> Result<()> {
        if self.typedefs.contains_key(&def.name) {
            return Err(TypeError::AlreadyExists(def.name));
        }
        self.typedefs.insert(def.name.clone(), def);
        Ok(())
    }

    /// Get a typedef by name
    pub fn get_typedef(&self, name: &str) -> Option<&TypedefDef> {
        self.typedefs.get(name)
    }

    /// Resolve a type reference to its base type
    pub fn resolve_type(&self, ty: &Type) -> Result<Type> {
        self.resolve_type_inner(ty, 0)
    }

    fn resolve_type_inner(&self, ty: &Type, depth: usize) -> Result<Type> {
        const MAX_RESOLVE_DEPTH: usize = 64;
        if depth > MAX_RESOLVE_DEPTH {
            return Err(TypeError::CircularReference(format!(
                "Type resolution exceeded max depth {}: possible circular typedef",
                MAX_RESOLVE_DEPTH
            )));
        }

        match ty {
            Type::Typedef(name) => {
                if let Some(td) = self.get_typedef(name) {
                    self.resolve_type_inner(&td.base_type, depth + 1)
                } else {
                    Err(TypeError::NotFound(name.clone()))
                }
            }
            Type::Pointer(inner) => {
                let resolved = self.resolve_type_inner(inner, depth + 1)?;
                Ok(Type::Pointer(Box::new(resolved)))
            }
            Type::Array(inner, len) => {
                let resolved = self.resolve_type_inner(inner, depth + 1)?;
                Ok(Type::Array(Box::new(resolved), *len))
            }
            _ => Ok(ty.clone()),
        }
    }

    /// Calculate the size of a type in bytes
    pub fn size_of(&self, ty: &Type) -> Result<usize> {
        crate::layout::size_of(self, ty)
    }

    /// Calculate the alignment of a type
    pub fn align_of(&self, ty: &Type) -> Result<usize> {
        crate::layout::align_of(self, ty)
    }

    /// Get statistics
    pub fn stats(&self) -> TypeStats {
        TypeStats {
            struct_count: self.structs.len(),
            union_count: self.unions.len(),
            enum_count: self.enums.len(),
            typedef_count: self.typedefs.len(),
        }
    }

    /// Export all types as JSON
    pub fn export_json(&self) -> Result<String> {
        let export = TypeExport {
            structs: self.structs.values().cloned().collect(),
            unions: self.unions.values().cloned().collect(),
            enums: self.enums.values().cloned().collect(),
            typedefs: self.typedefs.values().cloned().collect(),
        };
        serde_json::to_string_pretty(&export).map_err(|e| TypeError::Invalid(e.to_string()))
    }

    /// Import types from JSON
    pub fn import_json(&mut self, json: &str) -> Result<()> {
        let export: TypeExport =
            serde_json::from_str(json).map_err(|e| TypeError::Invalid(e.to_string()))?;

        for def in export.structs {
            self.add_struct(def)?;
        }
        for def in export.unions {
            self.add_union(def)?;
        }
        for def in export.enums {
            self.add_enum(def)?;
        }
        for def in export.typedefs {
            self.add_typedef(def)?;
        }

        Ok(())
    }
}

/// Type database statistics
#[derive(Debug, Clone)]
pub struct TypeStats {
    pub struct_count: usize,
    pub union_count: usize,
    pub enum_count: usize,
    pub typedef_count: usize,
}

/// Export format for serialization
#[derive(serde::Serialize, serde::Deserialize)]
struct TypeExport {
    structs: Vec<StructDef>,
    unions: Vec<UnionDef>,
    enums: Vec<EnumDef>,
    typedefs: Vec<TypedefDef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructBuilder;

    #[test]
    fn test_add_and_get_struct() {
        let mut db = TypeDatabase::new();
        let s = StructBuilder::new("Point")
            .add_field("x", Type::i32())
            .add_field("y", Type::i32())
            .build();

        db.add_struct(s).unwrap();
        let retrieved = db.get_struct("Point").unwrap();
        assert_eq!(retrieved.name, "Point");
    }

    #[test]
    fn test_duplicate_struct() {
        let mut db = TypeDatabase::new();
        let s1 = StructBuilder::new("Point").build();
        let s2 = StructBuilder::new("Point").build();

        db.add_struct(s1).unwrap();
        assert!(db.add_struct(s2).is_err());
    }

    #[test]
    fn test_resolve_typedef() {
        let mut db = TypeDatabase::new();
        db.add_typedef(TypedefDef::new("DWORD", Type::u32())).unwrap();

        let resolved = db.resolve_type(&Type::typedef("DWORD")).unwrap();
        assert_eq!(resolved, Type::u32());
    }
}
