use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError};
use crate::functions::FunctionEntry;
use crate::Xref;

/// An action that can be undone/redone
#[allow(clippy::large_enum_variant)] // boxing FunctionEntry would complicate serde round-trips
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Action {
    CreateFunction {
        address: u64,
        func: FunctionEntry,
    },
    DeleteFunction {
        address: u64,
        func: FunctionEntry,
    },
    UpdateFunction {
        address: u64,
        old: Option<FunctionEntry>,
        new: FunctionEntry,
    },
    SetLabel {
        address: u64,
        old: Option<String>,
        new: Option<String>,
    },
    SetComment {
        address: u64,
        old: Option<String>,
        new: Option<String>,
    },
    AddBookmark {
        address: u64,
        bookmark: crate::Bookmark,
    },
    RemoveBookmark {
        address: u64,
        bookmark: crate::Bookmark,
    },
    SetType {
        address: u64,
        old_type: Option<crate::Type>,
        new_type: Option<crate::Type>,
    },
    AddXref {
        xref: crate::Xref,
    },
    /// Batch of multiple actions
    Batch {
        actions: Vec<Action>,
        description: String,
    },
}

impl Action {
    fn truncate_chars(s: &str, max: usize) -> String {
        s.chars().take(max).collect()
    }

    pub fn description(&self) -> String {
        match self {
            Action::CreateFunction { address, func } => {
                format!("Create function '{}' at 0x{:X}", func.name, address)
            }
            Action::DeleteFunction { address, func } => {
                format!("Delete function '{}' at 0x{:X}", func.name, address)
            }
            Action::UpdateFunction { address, new, .. } => {
                format!("Update function '{}' at 0x{:X}", new.name, address)
            }
            Action::SetLabel { address, new, .. } => {
                let label = new.as_deref().unwrap_or("(removed)");
                format!("Set label '{}' at 0x{:X}", label, address)
            }
            Action::SetComment { address, new, .. } => {
                let preview = new.as_deref()
                    .map(|s| Self::truncate_chars(s, 30))
                    .unwrap_or_else(|| "(removed)".to_string());
                format!("Set comment '{}' at 0x{:X}", preview, address)
            }
            Action::AddBookmark { address, bookmark } => {
                format!("Add bookmark '{}' at 0x{:X}", bookmark.name, address)
            }
            Action::RemoveBookmark { address, bookmark } => {
                format!("Remove bookmark '{}' at 0x{:X}", bookmark.name, address)
            }
            Action::SetType { address, new_type, .. } => {
                let type_str = new_type.as_ref()
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_else(|| "(none)".to_string());
                format!("Set type '{}' at 0x{:X}", type_str, address)
            }
            Action::AddXref { xref } => {
                format!(
                    "Add xref 0x{:X} -> 0x{:X} ({})",
                    xref.from, xref.to, xref.xref_type
                )
            }
            Action::Batch { description, .. } => description.clone(),
        }
    }
}

/// Stack for undo/redo operations
pub struct UndoStack {
    undo: Vec<Action>,
    redo: Vec<Action>,
    max_size: usize,
}

impl UndoStack {
    pub fn new(max_size: usize) -> Self {
        Self {
            undo: Vec::new(),
            redo: Vec::new(),
            max_size,
        }
    }

    /// Push a new action onto the undo stack
    pub fn push(&mut self, action: Action) {
        self.undo.push(action);
        self.redo.clear(); // new action invalidates redo stack
        
        // Trim if too large
        if self.undo.len() > self.max_size {
            self.undo.remove(0);
        }
    }

    /// Pop the last action for undo
    pub fn pop_undo(&mut self) -> Option<Action> {
        self.undo.pop()
    }

    /// Push an undone action onto the redo stack
    pub fn push_redo(&mut self, action: Action) {
        self.redo.push(action);
    }

    /// Restore an action to the top of the undo stack after a failed revert,
    /// without disturbing the redo stack (unlike [`UndoStack::push`]).
    pub fn restore_undo(&mut self, action: Action) {
        self.undo.push(action);
        if self.undo.len() > self.max_size {
            self.undo.remove(0);
        }
    }

    /// Restore an action to the top of the redo stack after a failed re-apply.
    pub fn restore_redo(&mut self, action: Action) {
        self.redo.push(action);
    }

    /// Pop the last action for redo
    pub fn pop_redo(&mut self) -> Option<Action> {
        self.redo.pop()
    }

    /// Push a redone action back onto the undo stack
    pub fn push_undo_from_redo(&mut self, action: Action) {
        self.undo.push(action);
        if self.undo.len() > self.max_size {
            self.undo.remove(0);
        }
    }

    /// Check if undo is available
    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    /// Check if redo is available
    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Get description of the next undo action
    pub fn undo_description(&self) -> Option<String> {
        self.undo.last().map(|a| a.description())
    }

    /// Get description of the next redo action
    pub fn redo_description(&self) -> Option<String> {
        self.redo.last().map(|a| a.description())
    }

    /// Get number of undo actions available
    pub fn undo_count(&self) -> usize {
        self.undo.len()
    }

    /// Get number of redo actions available
    pub fn redo_count(&self) -> usize {
        self.redo.len()
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.undo.clear();
        self.redo.clear();
    }

    /// Get all undo descriptions (most recent last)
    pub fn undo_history(&self) -> Vec<String> {
        self.undo.iter().map(|a| a.description()).collect()
    }

    /// Get all redo descriptions (most recent last)
    pub fn redo_history(&self) -> Vec<String> {
        self.redo.iter().map(|a| a.description()).collect()
    }
}

/// Trait for objects that can apply/revert actions
pub trait ActionExecutor {
    fn apply(&mut self, action: &Action) -> crate::Result<()>;
    fn revert(&mut self, action: &Action) -> crate::Result<()>;
}

impl crate::ProjectDatabase {
    /// Undo the last action.
    ///
    /// The action is only moved to the redo stack after a *successful*
    /// revert; on failure it is restored so history is never destroyed.
    pub fn undo(&mut self) -> crate::Result<Option<String>> {
        let action = match self.undo_stack.pop_undo() {
            Some(action) => action,
            None => return Ok(None),
        };
        let description = action.description();
        if let Err(e) = self.revert_action(&action) {
            // Revert failed: put the action back where it was.
            self.undo_stack.restore_undo(action);
            return Err(e);
        }
        self.undo_stack.push_redo(action);
        Ok(Some(description))
    }

    /// Redo the last undone action.
    ///
    /// The action is only moved back onto the undo stack after a *successful*
    /// apply; on failure it is restored so history is never destroyed.
    pub fn redo(&mut self) -> crate::Result<Option<String>> {
        let action = match self.undo_stack.pop_redo() {
            Some(action) => action,
            None => return Ok(None),
        };
        let description = action.description();
        if let Err(e) = self.apply_action(&action) {
            // Apply failed: put the action back where it was.
            self.undo_stack.restore_redo(action);
            return Err(e);
        }
        self.undo_stack.push_undo_from_redo(action);
        Ok(Some(description))
    }

    /// Apply an action to the database
    fn apply_action(&mut self, action: &Action) -> crate::Result<()> {
        match action {
            Action::CreateFunction { func, .. } => {
                self.add_function_internal(func.clone())?;
            }
            Action::DeleteFunction { address, .. } => {
                self.delete_function_internal(*address)?;
            }
            Action::UpdateFunction { address, new, .. } => {
                // Normalize so the payload is stored under the same key the
                // action was recorded for.
                let mut normalized = new.clone();
                normalized.address = *address;
                self.update_function_internal(normalized)?;
            }
            Action::SetLabel { address, new, .. } => {
                if let Some(label) = new {
                    self.set_label_internal(*address, label.clone())?;
                } else {
                    self.remove_label_internal(*address)?;
                }
            }
            Action::SetComment { address, new, .. } => {
                if let Some(comment) = new {
                    self.set_comment_internal(*address, comment.clone())?;
                } else {
                    self.remove_comment_internal(*address)?;
                }
            }
            Action::AddBookmark { bookmark, .. } => {
                self.add_bookmark_internal(bookmark.clone())?;
            }
            Action::RemoveBookmark { address, .. } => {
                self.remove_bookmark_internal(*address)?;
            }
            Action::SetType { address, new_type, .. } => {
                self.set_type_internal(*address, new_type.clone())?;
            }
            Action::AddXref { xref } => {
                self.add_xref_internal(xref.clone())?;
            }
            Action::Batch { actions, .. } => {
                // FIXED: Atomic batch — if any sub-action fails, revert all
                // previously applied sub-actions to maintain consistency.
                let mut applied = Vec::new();
                for sub_action in actions {
                    if let Err(e) = self.apply_action(sub_action) {
                        // Revert all previously applied sub-actions in reverse order
                        for prev in applied.iter().rev() {
                            let _ = self.revert_action(prev);
                        }
                        return Err(e);
                    }
                    applied.push(sub_action.clone());
                }
            }
        }
        Ok(())
    }

    /// Revert an action
    fn revert_action(&mut self, action: &Action) -> crate::Result<()> {
        match action {
            Action::CreateFunction { address, .. } => {
                self.delete_function_internal(*address)?;
            }
            Action::DeleteFunction { func, .. } => {
                self.add_function_internal(func.clone())?;
            }
            Action::UpdateFunction { old, address, .. } => {
                if let Some(old_func) = old {
                    // Normalize so the payload is stored under the same key
                    // the action was recorded for.
                    let mut normalized = old_func.clone();
                    normalized.address = *address;
                    self.update_function_internal(normalized)?;
                } else {
                    self.delete_function_internal(*address)?;
                }
            }
            Action::SetLabel { address, old, .. } => {
                if let Some(label) = old {
                    self.set_label_internal(*address, label.clone())?;
                } else {
                    self.remove_label_internal(*address)?;
                }
            }
            Action::SetComment { address, old, .. } => {
                if let Some(comment) = old {
                    self.set_comment_internal(*address, comment.clone())?;
                } else {
                    self.remove_comment_internal(*address)?;
                }
            }
            Action::AddBookmark { address, .. } => {
                self.remove_bookmark_internal(*address)?;
            }
            Action::RemoveBookmark { bookmark, .. } => {
                self.add_bookmark_internal(bookmark.clone())?;
            }
            Action::SetType { address, old_type, .. } => {
                self.set_type_internal(*address, old_type.clone())?;
            }
            Action::AddXref { xref } => {
                self.remove_xref_internal(xref)?;
            }
            Action::Batch { actions, .. } => {
                // Revert in reverse order
                for sub_action in actions.iter().rev() {
                    self.revert_action(sub_action)?;
                }
            }
        }
        Ok(())
    }

    // Internal methods that don't push to undo stack
    
    fn add_function_internal(&mut self, func: FunctionEntry) -> crate::Result<()> {
        let key = func.address.to_le_bytes();
        let value = bincode::serialize(&func)?;
        self.functions_tree.insert(key, value)?;
        self.update_modified();
        Ok(())
    }

    fn delete_function_internal(&mut self, address: u64) -> crate::Result<()> {
        let key = address.to_le_bytes();
        self.functions_tree.remove(key)?;
        self.update_modified();
        Ok(())
    }

    fn update_function_internal(&mut self, func: FunctionEntry) -> crate::Result<()> {
        let key = func.address.to_le_bytes();
        let value = bincode::serialize(&func)?;
        self.functions_tree.insert(key, value)?;
        self.update_modified();
        Ok(())
    }

    fn set_label_internal(&mut self, address: u64, label: String) -> crate::Result<()> {
        let key = address.to_le_bytes();
        self.labels_tree.insert(key, label.as_bytes())?;
        self.update_modified();
        Ok(())
    }

    fn remove_label_internal(&mut self, address: u64) -> crate::Result<()> {
        let key = address.to_le_bytes();
        self.labels_tree.remove(key)?;
        self.update_modified();
        Ok(())
    }

    fn set_comment_internal(&mut self, address: u64, comment: String) -> crate::Result<()> {
        let key = address.to_le_bytes();
        self.comments_tree.insert(key, comment.as_bytes())?;
        self.update_modified();
        Ok(())
    }

    fn remove_comment_internal(&mut self, address: u64) -> crate::Result<()> {
        let key = address.to_le_bytes();
        self.comments_tree.remove(key)?;
        self.update_modified();
        Ok(())
    }

    fn add_bookmark_internal(&mut self, bookmark: crate::Bookmark) -> crate::Result<()> {
        let key = bookmark.address.to_le_bytes();
        let value = bincode::serialize(&bookmark)?;
        self.bookmarks_tree.insert(key, value)?;
        self.update_modified();
        Ok(())
    }

    fn remove_bookmark_internal(&mut self, address: u64) -> crate::Result<()> {
        let key = address.to_le_bytes();
        self.bookmarks_tree.remove(key)?;
        self.update_modified();
        Ok(())
    }

    fn set_type_internal(&mut self, address: u64, ty: Option<crate::Type>) -> crate::Result<()> {
        let key = address.to_le_bytes();
        match ty {
            Some(t) => {
                let value = bincode::serialize(&t)?;
                self.types_tree.insert(key, value)?;
            }
            None => {
                self.types_tree.remove(key)?;
            }
        }
        self.update_modified();
        Ok(())
    }

    fn add_xref_internal(&mut self, xref: crate::Xref) -> crate::Result<()> {
        let key_from = format!("f:{:016X}", xref.from);
        let key_to = format!("t:{:016X}", xref.to);

        // Both index entries (forward + backward) must change together.
        let result: std::result::Result<(), TransactionError<crate::DbError>> =
            self.xrefs_tree.transaction(|tree| {
                let mut xrefs: Vec<Xref> = match tree.get(key_from.as_bytes())? {
                    Some(bytes) => crate::bounded_deserialize(bytes.as_ref())
                        .map_err(ConflictableTransactionError::Abort)?,
                    None => Vec::new(),
                };
                if !xrefs.contains(&xref) {
                    xrefs.push(xref.clone());
                }
                let value = bincode::serialize(&xrefs)
                    .map_err(|e| ConflictableTransactionError::Abort(crate::DbError::from(e)))?;
                tree.insert(key_from.as_bytes(), value.as_slice())?;

                let mut xrefs_to: Vec<Xref> = match tree.get(key_to.as_bytes())? {
                    Some(bytes) => crate::bounded_deserialize(bytes.as_ref())
                        .map_err(ConflictableTransactionError::Abort)?,
                    None => Vec::new(),
                };
                if !xrefs_to.contains(&xref) {
                    xrefs_to.push(xref.clone());
                }
                let value_to = bincode::serialize(&xrefs_to)
                    .map_err(|e| ConflictableTransactionError::Abort(crate::DbError::from(e)))?;
                tree.insert(key_to.as_bytes(), value_to.as_slice())?;

                Ok(())
            });
        match result {
            Ok(()) => {}
            Err(TransactionError::Storage(e)) => return Err(e.into()),
            Err(TransactionError::Abort(e)) => return Err(e),
        }
        self.update_modified();
        Ok(())
    }

    fn remove_xref_internal(&mut self, xref: &crate::Xref) -> crate::Result<()> {
        let key_from = format!("f:{:016X}", xref.from);
        let key_to = format!("t:{:016X}", xref.to);
        let owned = xref.clone();

        // Both index entries (forward + backward) must change together.
        let result: std::result::Result<(), TransactionError<crate::DbError>> =
            self.xrefs_tree.transaction(move |tree| {
                if let Some(bytes) = tree.get(key_from.as_bytes())? {
                    let mut xrefs: Vec<Xref> = crate::bounded_deserialize(bytes.as_ref())
                        .map_err(ConflictableTransactionError::Abort)?;
                    xrefs.retain(|x| *x != owned);
                    if xrefs.is_empty() {
                        tree.remove(key_from.as_bytes())?;
                    } else {
                        let value = bincode::serialize(&xrefs).map_err(|e| {
                            ConflictableTransactionError::Abort(crate::DbError::from(e))
                        })?;
                        tree.insert(key_from.as_bytes(), value.as_slice())?;
                    }
                }

                if let Some(bytes) = tree.get(key_to.as_bytes())? {
                    let mut xrefs_to: Vec<Xref> = crate::bounded_deserialize(bytes.as_ref())
                        .map_err(ConflictableTransactionError::Abort)?;
                    xrefs_to.retain(|x| *x != owned);
                    if xrefs_to.is_empty() {
                        tree.remove(key_to.as_bytes())?;
                    } else {
                        let value = bincode::serialize(&xrefs_to).map_err(|e| {
                            ConflictableTransactionError::Abort(crate::DbError::from(e))
                        })?;
                        tree.insert(key_to.as_bytes(), value.as_slice())?;
                    }
                }

                Ok(())
            });
        match result {
            Ok(()) => {}
            Err(TransactionError::Storage(e)) => return Err(e.into()),
            Err(TransactionError::Abort(e)) => return Err(e),
        }
        self.update_modified();
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_undo_stack_basic() {
        let mut stack = UndoStack::new(100);
        
        assert!(!stack.can_undo());
        assert!(!stack.can_redo());
        
        stack.push(Action::SetLabel {
            address: 0x1000,
            old: None,
            new: Some("main".to_string()),
        });
        
        assert!(stack.can_undo());
        assert!(!stack.can_redo());
        
        let action = stack.pop_undo().unwrap();
        stack.push_redo(action);
        
        assert!(!stack.can_undo());
        assert!(stack.can_redo());
    }

    #[test]
    fn test_undo_stack_max_size() {
        let mut stack = UndoStack::new(3);
        
        for i in 0..5 {
            stack.push(Action::SetLabel {
                address: i,
                old: None,
                new: Some(format!("label_{}", i)),
            });
        }
        
        assert_eq!(stack.undo_count(), 3);
    }

    #[test]
    fn test_new_action_clears_redo() {
        let mut stack = UndoStack::new(100);
        
        stack.push(Action::SetLabel {
            address: 0x1000,
            old: None,
            new: Some("a".to_string()),
        });
        
        let action = stack.pop_undo().unwrap();
        stack.push_redo(action);
        assert!(stack.can_redo());
        
        // New action should clear redo
        stack.push(Action::SetLabel {
            address: 0x2000,
            old: None,
            new: Some("b".to_string()),
        });
        
        assert!(!stack.can_redo());
    }
}
