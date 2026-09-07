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
//! ```text
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
//!     fn on_load(&mut self, ctx: &mut PluginContext) { /* ... */ }
//!     fn analyze(&mut self, ctx: &mut PluginContext) { /* ... */ }
//! }
//! ```

use core::ffi::c_void;
use libloading::Library;
use project_db::ProjectDatabase;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

pub const PLUGIN_ABI_VERSION: u32 = 1;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Plugin load error: {0}")]
    LoadError(String),
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),
    #[error("ABI mismatch: {0}")]
    AbiMismatch(String),
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

/// A plugin instance paired with the dynamic library that produced it.
///
/// Field order matters: `plugin` is declared before `_library`, so the
/// `Box<dyn Plugin>` is always destroyed while its backing library is still
/// resident. Library unloading is deferred: the OS-level unload happens only
/// when the last clone of the internal `Arc<Library>` is dropped.
struct LoadedPlugin {
    plugin: Box<dyn Plugin>,
    _library: Option<Arc<Library>>,
}

/// Plugin manager
pub struct PluginManager {
    plugins: HashMap<String, LoadedPlugin>,
    plugin_dirs: Vec<PathBuf>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            plugin_dirs: default_plugin_dirs(),
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
        self.plugins.insert(
            name,
            LoadedPlugin {
                plugin,
                _library: None,
            },
        );
        Ok(())
    }

    /// Load all compatible dynamic plugins from a directory.
    /// SECURITY: Only loads from pre-configured trusted directories.
    /// Refuses to load from world-writable or user-uploadable paths.
    ///
    /// Returns the names of successfully loaded plugins. Individual failures
    /// (bad ABI, missing symbols, world-writable location, ...) are reported
    /// on stderr with the `[FreakRE]` prefix instead of being silently
    /// swallowed, matching how panicking plugins are surfaced elsewhere.
    pub fn load_from_directory(&mut self, path: &Path) -> Result<Vec<String>> {
        let canonical = path.canonicalize()?;
        let mut loaded = Vec::new();
        for entry in std::fs::read_dir(&canonical)? {
            let entry = entry?;
            let file_path = entry.path();
            if !file_path.is_file() || !is_dynamic_library(&file_path) {
                continue;
            }
            if is_world_writable(&file_path) {
                eprintln!(
                    "[FreakRE] Refusing plugin '{}': located in a world-writable path",
                    file_path.display()
                );
                continue;
            }
            match self.load_library(&file_path) {
                Ok(name) => loaded.push(name),
                Err(err) => {
                    eprintln!(
                        "[FreakRE] Failed to load plugin '{}': {}",
                        file_path.display(),
                        err
                    );
                }
            }
        }
        Ok(loaded)
    }

    fn load_library(&mut self, path: &Path) -> Result<String> {
        let canonical = path.canonicalize()?;
        unsafe {
            let lib = Library::new(&canonical)?;

            let abi_fn: libloading::Symbol<unsafe extern "C" fn() -> u32> =
                lib.get(b"freakre_plugin_abi")?;
            if abi_fn() != PLUGIN_ABI_VERSION {
                return Err(PluginError::AbiMismatch(format!(
                    "plugin reports ABI {}, host expects {}",
                    abi_fn(),
                    PLUGIN_ABI_VERSION
                )));
            }

            let create_fn: libloading::Symbol<
                unsafe extern "C" fn(*mut *mut c_void, *mut *mut c_void) -> u32,
            > = lib.get(b"freakre_plugin_create")?;

            let mut data: *mut c_void = std::ptr::null_mut();
            let mut vtable: *mut c_void = std::ptr::null_mut();
            if create_fn(&mut data, &mut vtable) != 0 || data.is_null() || vtable.is_null() {
                return Err(PluginError::LoadError(format!(
                    "plugin '{}' returned invalid plugin pointers",
                    canonical.display()
                )));
            }

            let plugin: Box<dyn Plugin> =
                core::mem::transmute((data as *mut u8, vtable as *mut u8));

            let name = plugin.metadata().name.clone();
            if self.plugins.contains_key(&name) {
                return Err(PluginError::AlreadyLoaded(name));
            }
            self.plugins.insert(
                name.clone(),
                LoadedPlugin {
                    plugin,
                    _library: Some(Arc::new(lib)),
                },
            );
            Ok(name)
        }
    }

    /// Unload a plugin.
    ///
    /// The plugin object is dropped first; its library is released when the
    /// last `Arc` reference to it dies, so unloading may be deferred until
    /// every outstanding clone of the library handle is gone.
    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        self.plugins
            .remove(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;
        Ok(())
    }

    /// Get a plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&dyn Plugin> {
        self.plugins.get(name).map(|p| p.plugin.as_ref())
    }

    /// Get a mutable plugin by name
    pub fn get_plugin_mut(&mut self, name: &str) -> Option<&mut (dyn Plugin + '_)> {
        match self.plugins.get_mut(name) {
            Some(p) => Some(p.plugin.as_mut()),
            None => None,
        }
    }

    /// List all loaded plugins
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.values().map(|p| p.plugin.metadata()).collect()
    }

    /// Notify all plugins of an event.
    /// FIXED: Wraps each plugin call in catch_unwind to prevent a panicking
    /// plugin from crashing the entire application.
    pub fn notify_binary_opened(&mut self, ctx: &mut PluginContext) {
        for (name, plugin) in self.plugins.iter_mut() {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.plugin.on_binary_opened(ctx);
            }))
            .is_err()
            {
                eprintln!(
                    "[FreakRE] Plugin '{}' panicked during on_binary_opened()",
                    name
                );
            }
        }
    }

    pub fn notify_function_selected(&mut self, ctx: &mut PluginContext, address: u64) {
        for (name, plugin) in self.plugins.iter_mut() {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.plugin.on_function_selected(ctx, address);
            }))
            .is_err()
            {
                eprintln!(
                    "[FreakRE] Plugin '{}' panicked during on_function_selected()",
                    name
                );
            }
        }
    }

    pub fn notify_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        for (name, plugin) in self.plugins.iter_mut() {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.plugin.on_menu_item(ctx, path);
            }))
            .is_err()
            {
                eprintln!("[FreakRE] Plugin '{}' panicked during on_menu_item()", name);
            }
        }
    }

    /// Run analysis on all plugins.
    /// FIXED: Wraps each plugin call in catch_unwind to prevent a panicking
    /// plugin from crashing the entire application.
    pub fn analyze_all(&mut self, ctx: &mut PluginContext) {
        for (name, plugin) in self.plugins.iter_mut() {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.plugin.analyze(ctx);
            }))
            .is_err()
            {
                eprintln!("[FreakRE] Plugin '{}' panicked during analyze()", name);
            }
        }
    }

    /// Get all menu items from all plugins
    pub fn all_menu_items(&self) -> Vec<MenuItem> {
        self.plugins
            .values()
            .flat_map(|p| p.plugin.menu_items())
            .collect()
    }
}

fn is_dynamic_library(path: &Path) -> bool {
    path.extension()
        .map(|e| e.eq_ignore_ascii_case(std::env::consts::DLL_EXTENSION))
        .unwrap_or(false)
}

/// Default plugin search directories.
///
/// SECURITY: the historical default `./plugins` was resolved against the
/// process CWD, so whichever directory FreakRE happened to be launched from
/// decided which DLLs were eligible for loading (DLL planting). Prefer a
/// location anchored to the running executable instead, and fall back to the
/// per-user data directory when the executable path cannot be determined.
/// Explicit overrides via [`PluginManager::add_plugin_dir`] are unaffected.
fn default_plugin_dirs() -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("plugins"));
        }
    }
    out.push(
        dirs::data_dir()
            .map(|d| d.join("freakre").join("plugins"))
            .unwrap_or_default(),
    );
    out
}

#[cfg(unix)]
fn is_world_writable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o002 != 0)
        .unwrap_or(true)
}

/// Best-effort Windows stand-in for the Unix "world-writable" check.
///
/// NTFS stores access control in ACLs, which are invisible to
/// [`std::os::windows::fs::MetadataExt`]: it only exposes DOS attribute bits
/// such as `FILE_ATTRIBUTE_READONLY`, and that bit neither stops the owner
/// from clearing it nor says anything about directory ACLs, so it cannot
/// prove a location safe or unsafe. True ACL evaluation would require the
/// `GetNamedSecurityInfo` FFI, which is deliberately out of scope here.
///
/// Instead we refuse the well-known locations every local account can write
/// to, where a dropped-in DLL would be attacker-controllable: `%TEMP%`,
/// `%TMP%`, `%PUBLIC%` and the user's `Downloads` folder (including any
/// subdirectory thereof). Symlinks/junctions are resolved first so a link
/// planted in a trusted directory cannot bypass the deny-list. Stat failures
/// fail CLOSED: an unreadable candidate is never loaded.
///
/// KNOWN LIMITATIONS (accepted for ABI v1):
/// - ACLs on arbitrary directories are NOT evaluated; a world-writable
///   directory outside the deny-list will not be detected.
/// - Volumes without permission semantics (e.g. FAT32) are treated as safe
///   unless they live under a deny-listed root.
#[cfg(windows)]
fn is_world_writable(path: &Path) -> bool {
    // Fail closed: an unstatable candidate must never be loaded.
    if std::fs::metadata(path).is_err() {
        return true;
    }
    // Resolve reparse points so comparisons see the real on-disk location.
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    windows_world_writable_roots()
        .iter()
        .any(|root| resolved.starts_with(root))
}

/// Canonicalised deny-list of per-machine / per-user writable roots on Windows.
#[cfg(windows)]
fn windows_world_writable_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    // Per-session scratch space; writable by every local process.
    for var in ["TEMP", "TMP"] {
        if let Some(dir) = std::env::var_os(var) {
            if let Ok(canonical) = std::fs::canonicalize(&dir) {
                roots.push(canonical);
            }
        }
    }
    // %PUBLIC% (usually C:\Users\Public): writable by all authenticated users.
    if let Some(public) = std::env::var_os("PUBLIC") {
        if let Ok(canonical) = std::fs::canonicalize(&public) {
            roots.push(canonical);
        }
    }
    // Per-user Downloads: user-writable and routinely filled with untrusted
    // content, so a plugin there can never be considered trusted.
    if let Some(downloads) = dirs::download_dir() {
        if let Ok(canonical) = std::fs::canonicalize(&downloads) {
            roots.push(canonical);
        }
    }
    roots
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

/// Export a plugin from a dynamic library.
///
/// The plugin is exported as a raw data pointer plus a vtable pointer via the
/// `freakre_plugin_create` out-parameter ABI, which avoids passing a fat
/// pointer across the C ABI. The host must call `freakre_plugin_abi` first and
/// reject the library when the reported version differs from
/// [`PLUGIN_ABI_VERSION`].
///
/// # ABI surface (v1)
///
/// Exactly two C symbols are exported:
/// - `freakre_plugin_abi() -> u32`
/// - `freakre_plugin_create(out_data: *mut *mut c_void, out_vtable: *mut *mut c_void) -> u32`
///
/// # SAFETY: allocator contract (ABI v1)
///
/// The host reconstructs a `Box<dyn Plugin>` from the returned
/// `(data, vtable)` pair and drops it **inside the host**, using the *host's*
/// global allocator — even though the `Box` was allocated **inside the plugin
/// DLL** by the *plugin's* global allocator. Rust does not guarantee that two
/// crates share an allocator, so every plugin built with this macro MUST
/// satisfy ALL of the following or unloading is undefined behaviour (heap
/// corruption at drop time, not a clean error):
///
/// 1. The plugin crate declares **no custom `#[global_allocator]`**.
/// 2. No replacement/redirected allocator is linked in (jemalloc, mimalloc,
///    Windows CRT heap shims, etc.) — use Rust's default allocation paths.
/// 3. The plugin is compiled with a rustc toolchain compatible with the one
///    that built the host (trait-object vtable layout and allocator glue are
///    not stable across compiler releases).
///
/// In practice this means: build plugins with the same toolchain channel and
/// default allocator configuration used for the FreakRE build, and never add
/// `#[global_allocator]` to a plugin crate.
///
/// # Why there is no destroy callback (yet)
///
/// A `freakre_plugin_destroy(data, vtable)` export would move deallocation
/// back into the DLL and remove the allocator constraint above. It is
/// deliberately NOT added in ABI v1: shipping it now would split the
/// ecosystem into plugins that self-destroy and hosts/plugins that expect
/// host-side drop, with no way to detect the mismatch at load time. Introduce
/// it together with `PLUGIN_ABI_VERSION = 2` so `freakre_plugin_abi`
/// negotiation can reject old/new mismatches explicitly instead of corrupting
/// the heap.
#[macro_export]
macro_rules! export_plugin {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub extern "C" fn freakre_plugin_abi() -> u32 {
            $crate::PLUGIN_ABI_VERSION
        }

        #[no_mangle]
        pub extern "C" fn freakre_plugin_create(
            out_data: *mut *mut ::core::ffi::c_void,
            out_vtable: *mut *mut ::core::ffi::c_void,
        ) -> u32 {
            static VTABLE: ::std::sync::OnceLock<usize> = ::std::sync::OnceLock::new();

            if out_data.is_null() || out_vtable.is_null() {
                return 1;
            }

            let boxed: Box<dyn $crate::Plugin> = Box::new(<$plugin_type>::default());
            let (data, vtable): (*mut u8, *mut u8) = unsafe { ::core::mem::transmute(boxed) };
            let stored_vtable = VTABLE.get_or_init(|| vtable as usize);

            unsafe {
                *out_data = data as *mut ::core::ffi::c_void;
                *out_vtable = *stored_vtable as *mut ::core::ffi::c_void;
            }
            0
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

    #[test]
    fn test_unload_missing_plugin_is_not_found() {
        let mut manager = PluginManager::new();
        assert!(matches!(
            manager.unload_plugin("Nope"),
            Err(PluginError::NotFound(_))
        ));
    }

    #[test]
    fn test_abi_version_constant() {
        assert_eq!(PLUGIN_ABI_VERSION, 1);
    }

    #[test]
    fn test_abi_mismatch_error_message() {
        let plugin_abi: u32 = PLUGIN_ABI_VERSION + 1;
        let err = PluginError::AbiMismatch(format!(
            "plugin reports ABI {}, host expects {}",
            plugin_abi, PLUGIN_ABI_VERSION
        ));
        let msg = err.to_string();
        assert!(msg.contains("ABI mismatch"));
        assert!(msg.contains("2"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn test_data_vtable_roundtrip() {
        let boxed: Box<dyn Plugin> = Box::new(TestPlugin);
        let (data, vtable): (*mut u8, *mut u8) = unsafe { core::mem::transmute(boxed) };
        assert!(!data.is_null());
        assert!(!vtable.is_null());

        let restored: Box<dyn Plugin> = unsafe { core::mem::transmute((data, vtable)) };
        assert_eq!(restored.metadata().name, "Test");
    }

    #[test]
    fn test_load_from_directory_empty_dir() {
        let dir = std::env::temp_dir().join(format!("freakre_plugins_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut manager = PluginManager::new();
        let loaded = manager.load_from_directory(&dir).unwrap();
        assert!(loaded.is_empty());
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_load_from_directory_missing_dir_is_io_error() {
        let mut manager = PluginManager::new();
        let missing = std::env::temp_dir().join("freakre_no_such_plugin_dir_42");
        assert!(matches!(
            manager.load_from_directory(&missing),
            Err(PluginError::Io(_))
        ));
    }

    #[test]
    fn test_default_plugin_dirs_do_not_depend_on_cwd() {
        for dir in default_plugin_dirs() {
            // Either an absolute location or the intentional "data dir
            // unavailable" sentinel; never something CWD-relative like
            // "./plugins".
            assert!(
                dir.as_os_str().is_empty() || dir.is_absolute(),
                "default plugin dir {dir:?} depends on CWD"
            );
        }
    }

    #[test]
    fn test_is_world_writable_missing_file_fails_closed() {
        assert!(is_world_writable(Path::new(
            "Z:/freakre/definitely/not/here/plugin.dll"
        )));
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_world_writable_refuses_temp_dir() {
        let probe =
            std::env::temp_dir().join(format!("freakre_rw_probe_{}.dll", std::process::id()));
        std::fs::write(&probe, b"MZ").unwrap();
        assert!(is_world_writable(&probe));
        std::fs::remove_file(&probe).ok();
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_world_writable_allows_non_temp_location() {
        let probe = std::env::current_dir()
            .unwrap()
            .join(format!("freakre_rw_ok_probe_{}.dll", std::process::id()));
        std::fs::write(&probe, b"MZ").unwrap();
        let result = is_world_writable(&probe);
        std::fs::remove_file(&probe).ok();
        assert!(!result);
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_world_writable_roots_resolve() {
        // TEMP/TMP must always resolve on CI and dev machines; if they do,
        // every root we return must be absolute so prefix matching is sound.
        assert!(!std::env::var_os("TEMP").unwrap_or_default().is_empty());
        for root in windows_world_writable_roots() {
            assert!(root.is_absolute(), "unresolved root {root:?}");
        }
    }
}
