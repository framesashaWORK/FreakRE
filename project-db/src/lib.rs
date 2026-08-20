#![allow(dead_code, unused_assignments)]
//! # Project Database
//!
//! Persistent storage for FreakRE reverse engineering projects.
//! Similar to IDA's .idb or Ghidra's .rep files.
//!
//! ## Features
//!
//! - **Function management**: Create, update, delete functions
//! - **Labels & Comments**: User-defined names and annotations
//! - **Bookmarks**: Quick navigation to important addresses
//! - **Type system**: Struct definitions and type information
//! - **Cross-references**: Bidirectional xref tracking
//! - **Undo/Redo**: Full history of all modifications
//!
//! ## Example
//!
//! ```rust,no_run
//! use project_db::{ProjectDatabase, FunctionEntry, ProjectMetadata};
//! use std::path::PathBuf;
//!
//! let db = ProjectDatabase::create(
//!     "./my_project.bdb",
//!     PathBuf::from("binary.exe"),
//!     "abc123".to_string(),
//!     "x86_64".to_string(),
//!     "PE".to_string(),
//! ).unwrap();
//!
//! // Add a function
//! let func = FunctionEntry {
//!     address: 0x401000,
//!     name: "main".to_string(),
//!     size: 256,
//!     ..Default::default()
//! };
//! db.add_function(func).unwrap();
//! ```

pub mod types;
pub mod functions;
pub mod xrefs;
pub mod undo;

pub use types::*;
pub use functions::*;
pub use xrefs::*;
// undo module provides UndoStack, Action, and extends ProjectDatabase with undo/redo
pub use undo::{UndoStack, Action, ActionExecutor};

use sled::Db;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Function not found: 0x{0:X}")]
    FunctionNotFound(u64),
    #[error("Invalid address: 0x{0:X}")]
    InvalidAddress(u64),
    #[error("Label already exists at 0x{0:X}")]
    LabelExists(u64),
    #[error("Type not found: {0}")]
    TypeNotFound(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

/// Project metadata stored in the database
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectMetadata {
    pub id: uuid::Uuid,
    pub name: String,
    pub binary_hash: String,
    pub binary_path: PathBuf,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub modified_at: chrono::DateTime<chrono::Utc>,
    pub architecture: String,
    pub file_format: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

/// Main project database
pub struct ProjectDatabase {
    db: Db,
    metadata: ProjectMetadata,
    undo_stack: UndoStack,
    functions_tree: sled::Tree,
    labels_tree: sled::Tree,
    comments_tree: sled::Tree,
    bookmarks_tree: sled::Tree,
    xrefs_tree: sled::Tree,
    types_tree: sled::Tree,
    history_tree: sled::Tree,
}

impl ProjectDatabase {
    /// Open an existing project database
    pub fn open<P: AsRef<Path>>(path: P, metadata: ProjectMetadata) -> Result<Self> {
        let db = sled::open(path)?;
        
        let functions_tree = db.open_tree("functions")?;
        let labels_tree = db.open_tree("labels")?;
        let comments_tree = db.open_tree("comments")?;
        let bookmarks_tree = db.open_tree("bookmarks")?;
        let xrefs_tree = db.open_tree("xrefs")?;
        let types_tree = db.open_tree("types")?;
        let history_tree = db.open_tree("history")?;

        Ok(Self {
            db,
            metadata,
            undo_stack: UndoStack::new(1000),
            functions_tree,
            labels_tree,
            comments_tree,
            bookmarks_tree,
            xrefs_tree,
            types_tree,
            history_tree,
        })
    }

    /// Create a new project database
    pub fn create<P: AsRef<Path>>(
        path: P,
        binary_path: PathBuf,
        binary_hash: String,
        arch: String,
        format: String,
    ) -> Result<Self> {
        let metadata = ProjectMetadata {
            id: uuid::Uuid::new_v4(),
            name: binary_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            binary_hash,
            binary_path,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            architecture: arch,
            file_format: format,
            description: None,
            tags: Vec::new(),
        };

        Self::open(path, metadata)
    }

    /// Get project metadata
    pub fn metadata(&self) -> &ProjectMetadata {
        &self.metadata
    }

    /// Update project metadata
    pub fn update_metadata(&mut self, metadata: ProjectMetadata) -> Result<()> {
        self.metadata = metadata;
        self.update_modified();
        Ok(())
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Get database statistics
    pub fn stats(&self) -> DatabaseStats {
        DatabaseStats {
            function_count: self.functions_tree.len(),
            label_count: self.labels_tree.len(),
            comment_count: self.comments_tree.len(),
            bookmark_count: self.bookmarks_tree.len(),
            xref_count: self.xrefs_tree.len(),
            type_count: self.types_tree.len(),
            disk_usage: self.db.size_on_disk().unwrap_or(0),
        }
    }

    fn update_modified(&mut self) {
        self.metadata.modified_at = chrono::Utc::now();
    }

    // === Undo/Redo (delegated to undo.rs impl) ===

    pub fn can_undo(&self) -> bool {
        self.undo_stack.can_undo()
    }

    pub fn can_redo(&self) -> bool {
        self.undo_stack.can_redo()
    }

    /// Get description of the next undo action
    pub fn undo_description(&self) -> Option<String> {
        self.undo_stack.undo_description()
    }

    /// Get description of the next redo action
    pub fn redo_description(&self) -> Option<String> {
        self.undo_stack.redo_description()
    }

    // === Bookmarks ===

    pub fn add_bookmark(&mut self, bookmark: Bookmark) -> Result<()> {
        let key = bookmark.address.to_le_bytes();
        let value = bincode::serialize(&bookmark)?;
        self.bookmarks_tree.insert(key, value)?;
        
        self.undo_stack.push(Action::AddBookmark {
            address: bookmark.address,
            bookmark: bookmark.clone(),
        });
        
        self.update_modified();
        Ok(())
    }

    pub fn get_bookmark(&self, address: u64) -> Result<Option<Bookmark>> {
        let key = address.to_le_bytes();
        match self.bookmarks_tree.get(key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn remove_bookmark(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.bookmarks_tree.remove(key)? {
            let old_bookmark: Bookmark = bincode::deserialize(&old_bytes)?;
            self.undo_stack.push(Action::RemoveBookmark {
                address,
                bookmark: old_bookmark,
            });
            self.update_modified();
        }
        Ok(())
    }

    pub fn list_bookmarks(&self) -> Result<Vec<Bookmark>> {
        let mut bookmarks = Vec::new();
        for entry in self.bookmarks_tree.iter() {
            let (_, value) = entry?;
            let bookmark: Bookmark = bincode::deserialize(&value)?;
            bookmarks.push(bookmark);
        }
        Ok(bookmarks)
    }

    // === Functions ===

    pub fn add_function(&mut self, func: FunctionEntry) -> Result<()> {
        let key = func.address.to_le_bytes();
        let value = bincode::serialize(&func)?;
        self.functions_tree.insert(key, value)?;
        
        self.undo_stack.push(Action::CreateFunction {
            address: func.address,
            func: func.clone(),
        });
        
        self.update_modified();
        Ok(())
    }

    pub fn get_function(&self, address: u64) -> Result<Option<FunctionEntry>> {
        let key = address.to_le_bytes();
        match self.functions_tree.get(key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn update_function(&mut self, address: u64, func: FunctionEntry) -> Result<()> {
        let old_func = self.get_function(address)?;
        
        let key = address.to_le_bytes();
        let value = bincode::serialize(&func)?;
        self.functions_tree.insert(key, value)?;
        
        self.undo_stack.push(Action::UpdateFunction {
            address,
            old: old_func,
            new: func,
        });
        
        self.update_modified();
        Ok(())
    }

    pub fn delete_function(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.functions_tree.remove(key)? {
            let old_func: FunctionEntry = bincode::deserialize(&old_bytes)?;
            self.undo_stack.push(Action::DeleteFunction {
                address,
                func: old_func,
            });
            self.update_modified();
        }
        Ok(())
    }

    pub fn list_functions(&self) -> Result<Vec<FunctionEntry>> {
        let mut functions = Vec::new();
        for entry in self.functions_tree.iter() {
            let (_, value) = entry?;
            let func: FunctionEntry = bincode::deserialize(&value)?;
            functions.push(func);
        }
        Ok(functions)
    }

    // === Labels ===

    pub fn set_label(&mut self, address: u64, label: String) -> Result<()> {
        let key = address.to_le_bytes();
        let old_label = self.get_label(address)?;
        
        self.labels_tree.insert(key, label.as_bytes())?;
        
        self.undo_stack.push(Action::SetLabel {
            address,
            old: old_label,
            new: Some(label),
        });
        
        self.update_modified();
        Ok(())
    }

    pub fn get_label(&self, address: u64) -> Result<Option<String>> {
        let key = address.to_le_bytes();
        match self.labels_tree.get(key)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    pub fn remove_label(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.labels_tree.remove(key)? {
            let old_label = String::from_utf8_lossy(&old_bytes).to_string();
            self.undo_stack.push(Action::SetLabel {
                address,
                old: Some(old_label),
                new: None,
            });
            self.update_modified();
        }
        Ok(())
    }

    pub fn list_labels(&self) -> Result<std::collections::HashMap<u64, String>> {
        let mut labels = std::collections::HashMap::new();
        for entry in self.labels_tree.iter() {
            let (key_bytes, value_bytes) = entry?;
            let key_slice: [u8; 8] = match key_bytes.as_ref().try_into() {
                Ok(arr) => arr,
                Err(_) => continue, // Skip malformed keys instead of panicking
            };
            let addr = u64::from_le_bytes(key_slice);
            let label = String::from_utf8_lossy(&value_bytes).to_string();
            labels.insert(addr, label);
        }
        Ok(labels)
    }

    // === Comments ===

    pub fn set_comment(&mut self, address: u64, comment: String) -> Result<()> {
        let key = address.to_le_bytes();
        let old_comment = self.get_comment(address)?;
        
        self.comments_tree.insert(key, comment.as_bytes())?;
        
        self.undo_stack.push(Action::SetComment {
            address,
            old: old_comment,
            new: Some(comment),
        });
        
        self.update_modified();
        Ok(())
    }

    pub fn get_comment(&self, address: u64) -> Result<Option<String>> {
        let key = address.to_le_bytes();
        match self.comments_tree.get(key)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    pub fn remove_comment(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.comments_tree.remove(key)? {
            let old_comment = String::from_utf8_lossy(&old_bytes).to_string();
            self.undo_stack.push(Action::SetComment {
                address,
                old: Some(old_comment),
                new: None,
            });
            self.update_modified();
        }
        Ok(())
    }

    // === Xrefs ===

    pub fn add_xref(&mut self, xref: Xref) -> Result<()> {
        let key = format!("f:{:016X}", xref.from);
        let mut xrefs: Vec<Xref> = self.get_xrefs_from(xref.from)?;
        xrefs.push(xref.clone());
        let value = bincode::serialize(&xrefs)?;
        self.xrefs_tree.insert(key.as_bytes(), value)?;

        let key_to = format!("t:{:016X}", xref.to);
        let mut xrefs_to: Vec<Xref> = self.get_xrefs_to(xref.to)?;
        xrefs_to.push(xref);
        let value_to = bincode::serialize(&xrefs_to)?;
        self.xrefs_tree.insert(key_to.as_bytes(), value_to)?;

        self.update_modified();
        Ok(())
    }

    pub fn get_xrefs_from(&self, address: u64) -> Result<Vec<Xref>> {
        let key = format!("f:{:016X}", address);
        match self.xrefs_tree.get(key.as_bytes())? {
            Some(bytes) => Ok(bincode::deserialize(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn get_xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        let key = format!("t:{:016X}", address);
        match self.xrefs_tree.get(key.as_bytes())? {
            Some(bytes) => Ok(bincode::deserialize(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn callers(&self, address: u64) -> Result<Vec<u64>> {
        Ok(self.get_xrefs_to(address)?
            .iter()
            .filter(|x| x.xref_type == XrefType::Call)
            .map(|x| x.from)
            .collect())
    }

    pub fn callees(&self, address: u64) -> Result<Vec<u64>> {
        Ok(self.get_xrefs_from(address)?
            .iter()
            .filter(|x| x.xref_type == XrefType::Call)
            .map(|x| x.to)
            .collect())
    }

    // === Types ===

    pub fn set_type(&mut self, address: u64, ty: Type) -> Result<()> {
        let key = address.to_le_bytes();
        let old_type = self.get_type(address)?;
        let value = bincode::serialize(&ty)?;
        self.types_tree.insert(key, value)?;
        
        self.undo_stack.push(Action::SetType {
            address,
            old_type,
            new_type: Some(ty),
        });
        
        self.update_modified();
        Ok(())
    }

    pub fn get_type(&self, address: u64) -> Result<Option<Type>> {
        let key = address.to_le_bytes();
        match self.types_tree.get(key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn remove_type(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.types_tree.remove(key)? {
            let old_type: Type = bincode::deserialize(&old_bytes)?;
            self.undo_stack.push(Action::SetType {
                address,
                old_type: Some(old_type),
                new_type: None,
            });
            self.update_modified();
        }
        Ok(())
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub function_count: usize,
    pub label_count: usize,
    pub comment_count: usize,
    pub bookmark_count: usize,
    pub xref_count: usize,
    pub type_count: usize,
    pub disk_usage: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_open() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.bdb");
        
        let metadata = ProjectMetadata {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            binary_hash: "abc123".to_string(),
            binary_path: PathBuf::from("test.exe"),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            architecture: "x86_64".to_string(),
            file_format: "PE".to_string(),
            description: None,
            tags: vec![],
        };

        // Create
        let db = ProjectDatabase::open(&db_path, metadata.clone()).unwrap();
        drop(db);

        // Reopen
        let db = ProjectDatabase::open(&db_path, metadata).unwrap();
        assert_eq!(db.metadata().name, "test");
    }

    #[test]
    fn test_stats() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.bdb");
        
        let metadata = ProjectMetadata {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            binary_hash: "abc123".to_string(),
            binary_path: PathBuf::from("test.exe"),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            architecture: "x86_64".to_string(),
            file_format: "PE".to_string(),
            description: None,
            tags: vec![],
        };

        let db = ProjectDatabase::open(&db_path, metadata).unwrap();
        let stats = db.stats();
        
        assert_eq!(stats.function_count, 0);
        assert_eq!(stats.label_count, 0);
    }
}


