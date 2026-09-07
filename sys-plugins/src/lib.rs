#![allow(dead_code, unused_assignments)]
//! # FreakRE System Plugins
//!
//! Four built-in analysis plugins that ship with FreakRE:
//!
//! 1. **CryptoFinderPlugin** — Finds known crypto constants (AES, SHA-256, MD5, etc.)
//! 2. **StringAnalyzerPlugin** — Classifies strings (URLs, IPs, APIs, crypto material)
//! 3. **FuncClassifierPlugin** — Classifies functions (thunk/stub/leaf/recursive/complex)
//! 4. **EntropyMapperPlugin** — Sliding-window entropy mapping for packed region detection

pub mod crypto_finder;
pub mod entropy_mapper;
pub mod func_classifier;
pub mod string_analyzer;
pub mod util;

pub use crypto_finder::CryptoFinderPlugin;
pub use entropy_mapper::EntropyMapperPlugin;
pub use func_classifier::FuncClassifierPlugin;
pub use string_analyzer::StringAnalyzerPlugin;

use plugins::PluginManager;

/// Register all system plugins into a PluginManager
pub fn register_system_plugins(manager: &mut PluginManager) {
    let _ = manager.load_plugin(Box::new(CryptoFinderPlugin));
    let _ = manager.load_plugin(Box::new(StringAnalyzerPlugin));
    let _ = manager.load_plugin(Box::new(FuncClassifierPlugin));
    let _ = manager.load_plugin(Box::new(EntropyMapperPlugin));
}

/// Get metadata for all system plugins
pub fn system_plugin_names() -> Vec<&'static str> {
    vec![
        "Crypto Constants Finder",
        "String Analyzer",
        "Function Classifier",
        "Entropy Mapper",
    ]
}
