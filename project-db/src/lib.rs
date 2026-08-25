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
//! let mut db = ProjectDatabase::create(
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
use serde::de::DeserializeOwned;
use bincode::Options;
use sled::transaction::{ConflictableTransactionError, TransactionError};
use std::path::{Path, PathBuf};
use thiserror::Error;

const META_KEY: &[u8] = b"meta";

/// Hard upper bound (in bytes) for a single record read back from storage.
///
/// Encoded slices larger than this are rejected *before* deserialization and
/// bincode is additionally configured with the same read limit, so a corrupted
/// or hostile database file cannot trigger unbounded allocations through
/// length-prefixed collections (Vec/String capacity reservation).
pub const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

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
    #[error("Record too large: {size} bytes (limit is {limit} bytes)")]
    RecordTooLarge { size: usize, limit: usize },
    #[error("Project database already exists at '{0}'")]
    AlreadyExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, DbError>;

/// Deserialize a value that was written with `bincode::serialize` (fixint
/// encoding), enforcing [`MAX_RECORD_BYTES`] on both the encoded slice and
/// the amount of data bincode may consume while decoding.
///
/// This keeps the on-disk format byte-for-byte identical to the default
/// free-function configuration while bounding allocations from untrusted
/// length fields.
pub(crate) fn bounded_deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DbError::RecordTooLarge {
            size: bytes.len(),
            limit: MAX_RECORD_BYTES,
        });
    }
    let opts = bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_RECORD_BYTES as u64);
    opts.deserialize::<T>(bytes).map_err(DbError::Serialization)
}

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
}

impl ProjectDatabase {
    /// Open an existing project database
    pub fn open<P: AsRef<Path>>(path: P, metadata: ProjectMetadata) -> Result<Self> {
        Self::open_inner(path, metadata, false)
    }

    /// Create a new project database
    ///
    /// Returns [`DbError::AlreadyExists`] if the path already contains a
    /// project database with metadata, instead of silently adopting it.
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

        Self::open_inner(path, metadata, true)
    }

    fn open_inner<P: AsRef<Path>>(
        path: P,
        fallback_metadata: ProjectMetadata,
        require_new: bool,
    ) -> Result<Self> {
        let path_ref = path.as_ref();
        let db = sled::open(path_ref)?;

        let functions_tree = db.open_tree("functions")?;
        let labels_tree = db.open_tree("labels")?;
        let comments_tree = db.open_tree("comments")?;
        let bookmarks_tree = db.open_tree("bookmarks")?;
        let xrefs_tree = db.open_tree("xrefs")?;
        let types_tree = db.open_tree("types")?;

        let metadata = match db.get(META_KEY)? {
            Some(bytes) => {
                if require_new {
                    return Err(DbError::AlreadyExists(path_ref.to_path_buf()));
                }
                bounded_deserialize::<ProjectMetadata>(&bytes)?
            }
            None => {
                let bytes = bincode::serialize(&fallback_metadata)?;
                db.insert(META_KEY, bytes)?;
                fallback_metadata
            }
        };

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
        })
    }

    /// Get project metadata
    pub fn metadata(&self) -> &ProjectMetadata {
        &self.metadata
    }

    /// Update project metadata
    pub fn update_metadata(&mut self, mut metadata: ProjectMetadata) -> Result<()> {
        metadata.modified_at = chrono::Utc::now();
        let bytes = bincode::serialize(&metadata)?;
        self.db.insert(META_KEY, bytes)?;
        self.metadata = metadata;
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

    /// Mark the project as modified: update the in-memory timestamp and
    /// persist [`META_KEY`] so `modified_at` survives a reopen.
    ///
    /// Best-effort by design: the mutation that triggered this call has
    /// already been committed to its tree, so a metadata-write failure here
    /// must not abort (or roll back) it. The timestamp is refreshed again on
    /// the next mutation either way.
    fn update_modified(&mut self) {
        self.metadata.modified_at = chrono::Utc::now();
        if let Ok(bytes) = bincode::serialize(&self.metadata) {
            let _ = self.db.insert(META_KEY, bytes);
        }
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
            Some(bytes) => Ok(Some(bounded_deserialize::<Bookmark>(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn remove_bookmark(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.bookmarks_tree.remove(key)? {
            let old_bookmark: Bookmark = bounded_deserialize(&old_bytes)?;
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
            let bookmark: Bookmark = bounded_deserialize(&value)?;
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
            Some(bytes) => Ok(Some(bounded_deserialize::<FunctionEntry>(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn update_function(&mut self, address: u64, mut func: FunctionEntry) -> Result<()> {
        let old_func = self.get_function(address)?;

        // Normalize: the stored payload must agree with the key it is filed
        // under, otherwise undo/redo would re-apply it under `func.address`.
        func.address = address;
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
            let old_func: FunctionEntry = bounded_deserialize(&old_bytes)?;
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
            let func: FunctionEntry = bounded_deserialize(&value)?;
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
        if self.get_xrefs_from(xref.from)?.contains(&xref) {
            return Ok(());
        }

        let key_from = format!("f:{:016X}", xref.from);
        let key_to = format!("t:{:016X}", xref.to);

        let result: std::result::Result<(), TransactionError<DbError>> =
            self.xrefs_tree.transaction(|tree| {
                let mut xrefs: Vec<Xref> = match tree.get(key_from.as_bytes())? {
                    Some(bytes) => bounded_deserialize(bytes.as_ref())
                        .map_err(ConflictableTransactionError::Abort)?,
                    None => Vec::new(),
                };
                if !xrefs.contains(&xref) {
                    xrefs.push(xref.clone());
                }
                let value = bincode::serialize(&xrefs)
                    .map_err(|e| ConflictableTransactionError::Abort(DbError::from(e)))?;
                tree.insert(key_from.as_bytes(), value.as_slice())?;

                let mut xrefs_to: Vec<Xref> = match tree.get(key_to.as_bytes())? {
                    Some(bytes) => bounded_deserialize(bytes.as_ref())
                        .map_err(ConflictableTransactionError::Abort)?,
                    None => Vec::new(),
                };
                if !xrefs_to.contains(&xref) {
                    xrefs_to.push(xref.clone());
                }
                let value_to = bincode::serialize(&xrefs_to)
                    .map_err(|e| ConflictableTransactionError::Abort(DbError::from(e)))?;
                tree.insert(key_to.as_bytes(), value_to.as_slice())?;

                Ok(())
            });
        match result {
            Ok(()) => {}
            Err(TransactionError::Storage(e)) => return Err(e.into()),
            Err(TransactionError::Abort(e)) => return Err(e),
        }

        self.undo_stack.push(Action::AddXref { xref });

        self.update_modified();
        Ok(())
    }

    pub fn get_xrefs_from(&self, address: u64) -> Result<Vec<Xref>> {
        let key = format!("f:{:016X}", address);
        match self.xrefs_tree.get(key.as_bytes())? {
            Some(bytes) => Ok(bounded_deserialize::<Vec<Xref>>(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn get_xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        let key = format!("t:{:016X}", address);
        match self.xrefs_tree.get(key.as_bytes())? {
            Some(bytes) => Ok(bounded_deserialize::<Vec<Xref>>(&bytes)?),
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
            Some(bytes) => Ok(Some(bounded_deserialize::<Type>(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn remove_type(&mut self, address: u64) -> Result<()> {
        let key = address.to_le_bytes();
        if let Some(old_bytes) = self.types_tree.remove(key)? {
            let old_type: Type = bounded_deserialize(&old_bytes)?;
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

/// Fuzz/test helper: deserialize a FunctionEntry from untrusted bytes.
///
/// Uses the exact bounded-deserialization path used when loading records from
/// disk (see [`bounded_deserialize`]), so fuzz targets exercise the hardened
/// path without constructing a database.
#[doc(hidden)]
pub fn decode_function_entry(bytes: &[u8]) -> Result<FunctionEntry> {
    bounded_deserialize::<FunctionEntry>(bytes)
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

    fn test_metadata(name: &str) -> ProjectMetadata {
        ProjectMetadata {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            binary_hash: "abc123".to_string(),
            binary_path: PathBuf::from("test.exe"),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            architecture: "x86_64".to_string(),
            file_format: "PE".to_string(),
            description: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_metadata_persisted() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("meta.bdb");

        let mut db = ProjectDatabase::open(&db_path, test_metadata("original")).unwrap();
        let mut updated = test_metadata("renamed");
        updated.id = db.metadata().id;
        db.update_metadata(updated).unwrap();
        db.flush().unwrap();
        drop(db);

        let reopened = ProjectDatabase::open(
            &db_path,
            ProjectMetadata {
                name: "ignored-default".to_string(),
                id: uuid::Uuid::new_v4(),
                binary_hash: String::new(),
                binary_path: PathBuf::new(),
                created_at: chrono::Utc::now(),
                modified_at: chrono::Utc::now(),
                architecture: "x86".to_string(),
                file_format: "ELF".to_string(),
                description: None,
                tags: vec![],
            },
        )
        .unwrap();
        assert_eq!(reopened.metadata().name, "renamed");
    }

    #[test]
    fn test_set_type_undo_redo() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("types.bdb");
        let mut db = ProjectDatabase::open(&db_path, test_metadata("t")).unwrap();

        let ty = Type::Primitive(PrimitiveType::U32);
        db.set_type(0x1000, ty.clone()).unwrap();
        assert_eq!(db.get_type(0x1000).unwrap(), Some(ty.clone()));

        db.undo().unwrap();
        assert_eq!(db.get_type(0x1000).unwrap(), None);

        db.redo().unwrap();
        assert_eq!(db.get_type(0x1000).unwrap(), Some(ty));
    }

    #[test]
    fn test_remove_type_undo() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("types2.bdb");
        let mut db = ProjectDatabase::open(&db_path, test_metadata("t")).unwrap();

        db.set_type(0x2000, Type::Pointer(Box::new(Type::Primitive(PrimitiveType::U8)))).unwrap();
        db.remove_type(0x2000).unwrap();
        assert_eq!(db.get_type(0x2000).unwrap(), None);

        db.undo().unwrap();
        assert!(db.get_type(0x2000).unwrap().is_some());
    }

    #[test]
    fn test_add_xref_dedup_and_undo() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("xrefs.bdb");
        let mut db = ProjectDatabase::open(&db_path, test_metadata("x")).unwrap();

        let xref = Xref::new(0x1000, 0x2000, XrefType::Call);
        db.add_xref(xref.clone()).unwrap();
        db.add_xref(xref.clone()).unwrap();
        assert_eq!(db.get_xrefs_from(0x1000).unwrap().len(), 1);
        assert_eq!(db.get_xrefs_to(0x2000).unwrap().len(), 1);

        db.undo().unwrap();
        assert!(db.get_xrefs_from(0x1000).unwrap().is_empty());
        assert!(db.get_xrefs_to(0x2000).unwrap().is_empty());

        db.redo().unwrap();
        assert_eq!(db.get_xrefs_from(0x1000).unwrap(), vec![xref]);
        assert_eq!(db.get_xrefs_to(0x2000).unwrap().len(), 1);
    }

    #[test]
    fn test_create_over_existing_errors() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("dup.bdb");

        {
            let _db = ProjectDatabase::create(
                &db_path,
                PathBuf::from("a.exe"),
                "hash".to_string(),
                "x86".to_string(),
                "PE".to_string(),
            )
            .unwrap();
            // _db dropped here so sled releases its file lock
        }

        match ProjectDatabase::create(
            &db_path,
            PathBuf::from("b.exe"),
            "hash2".to_string(),
            "arm".to_string(),
            "ELF".to_string(),
        ) {
            Err(DbError::AlreadyExists(p)) => assert_eq!(p, db_path),
            Err(e) => panic!("expected AlreadyExists, got: {}", e),
            Ok(_) => panic!("expected AlreadyExists, got Ok"),
        }
    }

    #[test]
    fn test_update_function_normalizes_address() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("norm.bdb");
        let mut db = ProjectDatabase::open(&db_path, test_metadata("n")).unwrap();

        db.add_function(FunctionEntry {
            address: 0x401000,
            name: "main".to_string(),
            ..Default::default()
        })
        .unwrap();

        // Caller passes a payload whose `address` field disagrees with the key.
        db.update_function(0x401000, FunctionEntry {
            address: 0xDEADBEEF,
            name: "renamed".to_string(),
            ..Default::default()
        })
        .unwrap();

        let stored = db.get_function(0x401000).unwrap().expect("entry at key");
        assert_eq!(stored.address, 0x401000);
        assert_eq!(stored.name, "renamed");
        // No stray record filed under the stale payload address.
        assert!(db.get_function(0xDEADBEEF).unwrap().is_none());

        // Undo must restore under the recorded address as well.
        db.undo().unwrap();
        let restored = db.get_function(0x401000).unwrap().expect("restored entry");
        assert_eq!(restored.address, 0x401000);
        assert_eq!(restored.name, "main");
        assert!(db.get_function(0xDEADBEEF).unwrap().is_none());
        db.redo().unwrap();
        assert_eq!(
            db.get_function(0x401000).unwrap().expect("redo entry").name,
            "renamed"
        );
    }

    #[test]
    fn test_modified_at_persisted_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("mtime.bdb");
        let mut db = ProjectDatabase::open(&db_path, test_metadata("m")).unwrap();

        db.set_label(0x1000, "lbl".to_string()).unwrap();
        let modified_in_memory = db.metadata().modified_at;
        drop(db);

        let reopened = ProjectDatabase::open(&db_path, test_metadata("ignored")).unwrap();
        assert_eq!(reopened.metadata().modified_at, modified_in_memory);
    }
}


