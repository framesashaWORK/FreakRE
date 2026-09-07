//! Type database for managing all types in a project

use crate::{EnumDef, StructDef, Type, TypedefDef, UnionDef};
use std::collections::{HashMap, HashSet};
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

    /// Import types from JSON.
    ///
    /// The entire batch is validated up-front — both against the current
    /// database contents and for duplicates within the batch itself — so a
    /// failing import can never leave the database half-filled.
    pub fn import_json(&mut self, json: &str) -> Result<()> {
        let export: TypeExport =
            serde_json::from_str(json).map_err(|e| TypeError::Invalid(e.to_string()))?;

        {
            let mut struct_names: HashSet<&str> = HashSet::new();
            for def in &export.structs {
                if !struct_names.insert(def.name.as_str()) || self.structs.contains_key(&def.name) {
                    return Err(TypeError::AlreadyExists(def.name.clone()));
                }
            }
            let mut union_names: HashSet<&str> = HashSet::new();
            for def in &export.unions {
                if !union_names.insert(def.name.as_str()) || self.unions.contains_key(&def.name) {
                    return Err(TypeError::AlreadyExists(def.name.clone()));
                }
            }
            let mut enum_names: HashSet<&str> = HashSet::new();
            for def in &export.enums {
                if !enum_names.insert(def.name.as_str()) || self.enums.contains_key(&def.name) {
                    return Err(TypeError::AlreadyExists(def.name.clone()));
                }
            }
            let mut typedef_names: HashSet<&str> = HashSet::new();
            for def in &export.typedefs {
                if !typedef_names.insert(def.name.as_str()) || self.typedefs.contains_key(&def.name)
                {
                    return Err(TypeError::AlreadyExists(def.name.clone()));
                }
            }
        }

        // Validation passed: the inserts below cannot fail.
        for def in export.structs {
            self.structs.insert(def.name.clone(), def);
        }
        for def in export.unions {
            self.unions.insert(def.name.clone(), def);
        }
        for def in export.enums {
            self.enums.insert(def.name.clone(), def);
        }
        for def in export.typedefs {
            self.typedefs.insert(def.name.clone(), def);
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
        db.add_typedef(TypedefDef::new("MY_DWORD", Type::u32()))
            .unwrap();

        let resolved = db.resolve_type(&Type::typedef("MY_DWORD")).unwrap();
        assert_eq!(resolved, Type::u32());
    }

    #[test]
    fn test_import_json_is_atomic_on_duplicate() {
        let mut db = TypeDatabase::new();
        db.add_struct(StructBuilder::new("Existing").build())
            .unwrap();

        // "Existing" collides with the pre-defined struct; the valid
        // entries before it must not be applied (no partial import).
        let json = r#"{
            "structs": [
                {"name":"Fresh","fields":[],"packed":false,"comment":null},
                {"name":"Existing","fields":[],"packed":false,"comment":null}
            ],
            "unions": [],
            "enums": [],
            "typedefs": []
        }"#;

        match db.import_json(json) {
            Err(TypeError::AlreadyExists(name)) => assert_eq!(name, "Existing"),
            other => panic!("expected AlreadyExists error, got {:?}", other),
        }

        assert!(
            db.get_struct("Fresh").is_none(),
            "partial import leaked an entry"
        );
        assert!(db.get_struct("Existing").is_some());
    }

    #[test]
    fn test_import_json_rejects_duplicates_within_batch() {
        let mut db = TypeDatabase::new();

        let json = r#"{
            "structs": [
                {"name":"Dup","fields":[],"packed":false,"comment":null},
                {"name":"Dup","fields":[],"packed":false,"comment":null}
            ],
            "unions": [],
            "enums": [],
            "typedefs": []
        }"#;

        assert!(matches!(
            db.import_json(json),
            Err(TypeError::AlreadyExists(_))
        ));
        assert!(db.get_struct("Dup").is_none());
    }

    #[test]
    fn test_import_json_success() {
        let mut db = TypeDatabase::new();

        let json = r#"{
            "structs": [{"name":"A","fields":[],"packed":false,"comment":null}],
            "unions": [],
            "enums": [],
            "typedefs": [{"name":"MY_T","base_type":{"Int":{"bits":32,"signed":true}},"comment":null}]
        }"#;

        db.import_json(json).unwrap();
        assert!(db.get_struct("A").is_some());
        assert!(db.get_typedef("MY_T").is_some());
    }
}
