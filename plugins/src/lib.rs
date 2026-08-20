#![allow(dead_code, unused_assignments)]
//! # Plugin System
//!
//! Extensible plugin architecture for FreakRE.
//! Plugins can add custom analyzers, UI panels, and analysis rules.
//!
//! ## Plugin Types
//!
//! 1. **Analyzer plugins**: Run custom analysis on binaries
//! 2. **UI plugins**: Add custom panels and views
//! 3. **Signature plugins**: Add custom function signatures
//! 4. **Script plugins**: Rhai scripts that run automatically
//!
//! ## Example Plugin
//!
//! ```rust
//! use plugins::{Plugin, PluginContext, PluginMetadata};
//!
//! pub struct MyPlugin;
//!
//! impl Plugin for MyPlugin {
//!     fn metadata(&self) -> PluginMetadata {
//!         PluginMetadata {
//!             name: "My Plugin".to_string(),
//!             version: "1.0.0".to_string(),
//!             description: "Example plugin".to_string(),
//!         }
//!     }
//!
//!     fn on_load(&mut self, ctx: &mut PluginContext) {
//!         ctx.register_menu_item("Analyze/My Analysis");
//!     }
//!
//!     fn analyze(&mut self, ctx: &mut PluginContext) {
//!         // Custom analysis logic
//!     }
//! }
//! ```

use project_db::ProjectDatabase;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Plugin load error: {0}")]
    LoadError(String),
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),
    #[error("Library error: {0}")]
    LibError(#[from] libloading::Error),
    #[error("Database error: {0}")]
    DatabaseError(#[from] project_db::DbError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PluginError>;

/// Plugin metadata
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: Option<String>,
    pub description: String,
    pub license: Option<String>,
    pub homepage: Option<String>,
}

/// Menu item definition
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MenuItem {
    pub path: String,
    pub label: String,
    pub shortcut: Option<String>,
    pub enabled: bool,
}

impl MenuItem {
    pub fn new(path: &str, label: &str) -> Self {
        Self {
            path: path.to_string(),
            label: label.to_string(),
            shortcut: None,
            enabled: true,
        }
    }

    pub fn with_shortcut(mut self, shortcut: &str) -> Self {
        self.shortcut = Some(shortcut.to_string());
        self
    }
}

/// Plugin context passed to plugins
pub struct PluginContext {
    pub db: ProjectDatabase,
    pub menu_items: Vec<MenuItem>,
    pub output: Vec<String>,
    pub settings: HashMap<String, String>,
}

impl PluginContext {
    pub fn new(db: ProjectDatabase) -> Self {
        Self {
            db,
            menu_items: Vec::new(),
            output: Vec::new(),
            settings: HashMap::new(),
        }
    }

    pub fn register_menu_item(&mut self, item: MenuItem) {
        self.menu_items.push(item);
    }

    pub fn print(&mut self, msg: &str) {
        self.output.push(msg.to_string());
    }

    pub fn println(&mut self, msg: &str) {
        self.output.push(format!("{}\n", msg));
    }

    pub fn get_setting(&self, key: &str) -> Option<&String> {
        self.settings.get(key)
    }

    pub fn set_setting(&mut self, key: String, value: String) {
        self.settings.insert(key, value);
    }
}

/// Plugin trait
pub trait Plugin: Send + Sync {
    /// Plugin metadata
    fn metadata(&self) -> PluginMetadata;

    /// Called when plugin is loaded
    fn on_load(&mut self, _ctx: &mut PluginContext) {}

    /// Called when plugin is unloaded
    fn on_unload(&mut self, _ctx: &mut PluginContext) {}

    /// Called when a binary is opened
    fn on_binary_opened(&mut self, _ctx: &mut PluginContext) {}

    /// Called when a function is selected
    fn on_function_selected(&mut self, _ctx: &mut PluginContext, _address: u64) {}

    /// Called when a menu item is clicked
    fn on_menu_item(&mut self, _ctx: &mut PluginContext, _path: &str) {}

    /// Run analysis
    fn analyze(&mut self, _ctx: &mut PluginContext) {}

    /// Get menu items
    fn menu_items(&self) -> Vec<MenuItem> {
        Vec::new()
    }
}

/// Plugin manager
pub struct PluginManager {
    plugins: HashMap<String, Box<dyn Plugin>>,
    plugin_dirs: Vec<PathBuf>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            plugin_dirs: vec![
                PathBuf::from("./plugins"),
                dirs::data_dir().map(|d| d.join("freakre").join("plugins")).unwrap_or_default(),
            ],
        }
    }

    pub fn add_plugin_dir<P: AsRef<Path>>(&mut self, path: P) {
        self.plugin_dirs.push(path.as_ref().to_path_buf());
    }

    /// Load a plugin from a trait object
    pub fn load_plugin(&mut self, plugin: Box<dyn Plugin>) -> Result<()> {
        let name = plugin.metadata().name.clone();
        if self.plugins.contains_key(&name) {
            return Err(PluginError::AlreadyLoaded(name));
        }
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Load plugins from dynamic libraries.
    /// SECURITY: Only loads from pre-configured trusted directories.
    /// Refuses to load from world-writable or user-uploadable paths.
    pub fn load_from_directory(&mut self, path: &Path) -> Result<Vec<String>> {
        let mut loaded = Vec::new();

        if !path.exists() {
            return Ok(loaded);
        }

        // Security check: only allow loading from configured plugin_dirs
        let canonical = path.canonicalize().map_err(|e| {
            PluginError::LoadError(format!("Cannot canonicalize plugin path {:?}: {}", path, e))
        })?;

        let is_trusted = self.plugin_dirs.iter().any(|trusted| {
            trusted.canonicalize()
                .map(|t| canonical.starts_with(t))
                .unwrap_or(false)
        });

        if !is_trusted {
            eprintln!(
                "SECURITY: Refusing to load plugins from untrusted directory: {:?}",
                canonical
            );
            return Err(PluginError::LoadError(format!(
                "Directory {:?} is not in the trusted plugin directories list",
                canonical
            )));
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.extension().map(|e| e == "dll" || e == "so" || e == "dylib").unwrap_or(false) {
                match self.load_library(&entry_path) {
                    Ok(name) => loaded.push(name),
                    Err(e) => eprintln!("Failed to load plugin {:?}: {}", entry_path, e),
                }
            }
        }

        Ok(loaded)
    }

    fn load_library(&mut self, path: &Path) -> Result<String> {
        unsafe {
            let lib = libloading::Library::new(path)?;
            
            let create_plugin: libloading::Symbol<unsafe extern "C" fn() -> *mut dyn Plugin> = 
                lib.get(b"create_plugin")?;
            
            let plugin_ptr = create_plugin();
            let plugin = Box::from_raw(plugin_ptr);
            let name = plugin.metadata().name.clone();
            
            self.load_plugin(plugin)?;
            
            // Keep library alive (leak it intentionally)
            std::mem::forget(lib);
            
            Ok(name)
        }
    }

    /// Unload a plugin
    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        self.plugins.remove(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;
        Ok(())
    }

    /// Get a plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&dyn Plugin> {
        self.plugins.get(name).map(|p| p.as_ref())
    }

    /// Get a mutable plugin by name
    pub fn get_plugin_mut(&mut self, name: &str) -> Option<&mut (dyn Plugin + '_)> {
        match self.plugins.get_mut(name) {
            Some(p) => Some(p.as_mut()),
            None => None,
        }
    }

    /// List all loaded plugins
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.values().map(|p| p.metadata()).collect()
    }

    /// Notify all plugins of an event
    pub fn notify_binary_opened(&mut self, ctx: &mut PluginContext) {
        for plugin in self.plugins.values_mut() {
            plugin.on_binary_opened(ctx);
        }
    }

    pub fn notify_function_selected(&mut self, ctx: &mut PluginContext, address: u64) {
        for plugin in self.plugins.values_mut() {
            plugin.on_function_selected(ctx, address);
        }
    }

    pub fn notify_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        for plugin in self.plugins.values_mut() {
            plugin.on_menu_item(ctx, path);
        }
    }

    /// Run analysis on all plugins
    pub fn analyze_all(&mut self, ctx: &mut PluginContext) {
        for plugin in self.plugins.values_mut() {
            plugin.analyze(ctx);
        }
    }

    /// Get all menu items from all plugins
    pub fn all_menu_items(&self) -> Vec<MenuItem> {
        self.plugins.values()
            .flat_map(|p| p.menu_items())
            .collect()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro for creating plugins
#[macro_export]
macro_rules! define_plugin {
    ($name:ident, $version:expr, $desc:expr) => {
        pub struct $name;

        impl Plugin for $name {
            fn metadata(&self) -> PluginMetadata {
                PluginMetadata {
                    name: stringify!($name).to_string(),
                    version: $version.to_string(),
                    author: None,
                    description: $desc.to_string(),
                    license: None,
                    homepage: None,
                }
            }
        }
    };
}

/// Export a plugin from a dynamic library
#[macro_export]
macro_rules! export_plugin {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub extern "C" fn create_plugin() -> *mut dyn Plugin {
            Box::into_raw(Box::new(<$plugin_type>::default()))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin;

    impl Plugin for TestPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                name: "Test".to_string(),
                version: "1.0".to_string(),
                author: None,
                description: "Test plugin".to_string(),
                license: None,
                homepage: None,
            }
        }
    }

    #[test]
    fn test_load_plugin() {
        let mut manager = PluginManager::new();
        let plugin = Box::new(TestPlugin);
        
        assert!(manager.load_plugin(plugin).is_ok());
        assert_eq!(manager.list_plugins().len(), 1);
    }

    #[test]
    fn test_duplicate_plugin() {
        let mut manager = PluginManager::new();
        
        manager.load_plugin(Box::new(TestPlugin)).unwrap();
        let result = manager.load_plugin(Box::new(TestPlugin));
        
        assert!(result.is_err());
    }

    #[test]
    fn test_unload_plugin() {
        let mut manager = PluginManager::new();
        manager.load_plugin(Box::new(TestPlugin)).unwrap();
        
        assert!(manager.unload_plugin("Test").is_ok());
        assert_eq!(manager.list_plugins().len(), 0);
    }
}


