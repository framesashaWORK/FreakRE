use serde::{Deserialize, Serialize};
use crate::functions::FunctionEntry;

/// An action that can be undone/redone
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
    /// Batch of multiple actions
    Batch {
        actions: Vec<Action>,
        description: String,
    },
}

impl Action {
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
                    .map(|s| if s.len() > 30 { &s[..30] } else { s })
                    .unwrap_or("(removed)");
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
    /// Undo the last action
    pub fn undo(&mut self) -> crate::Result<Option<String>> {
        if let Some(action) = self.undo_stack.pop_undo() {
            let description = action.description();
            self.revert_action(&action)?;
            self.undo_stack.push_redo(action);
            Ok(Some(description))
        } else {
            Ok(None)
        }
    }

    /// Redo the last undone action
    pub fn redo(&mut self) -> crate::Result<Option<String>> {
        if let Some(action) = self.undo_stack.pop_redo() {
            let description = action.description();
            self.apply_action(&action)?;
            self.undo_stack.push_undo_from_redo(action);
            Ok(Some(description))
        } else {
            Ok(None)
        }
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
            Action::UpdateFunction { new, .. } => {
                self.update_function_internal(new.clone())?;
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
            Action::SetType { .. } => {
                // TODO: implement type storage
            }
            Action::Batch { actions, .. } => {
                for sub_action in actions {
                    self.apply_action(sub_action)?;
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
                    self.update_function_internal(old_func.clone())?;
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
            Action::SetType { .. } => {
                // TODO: implement type storage revert
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
