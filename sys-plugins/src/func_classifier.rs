//! # Function Classifier Plugin
//!
//! Classifies functions by behavior: thunks, wrappers, leaf functions,
//! recursive, high-complexity, potential main(), etc. Uses heuristics
//! on function size, call patterns, and instruction mix.

use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};
use project_db::FunctionEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FuncClass {
    /// Single JMP instruction — import thunk or trampoline
    Thunk,
    /// Very small (< 16 bytes), likely a wrapper/stub
    Stub,
    /// No CALL instructions — leaf function
    Leaf,
    /// Calls itself (direct recursion detected)
    Recursive,
    /// Large function with many branches — complex logic
    Complex,
    /// Calls __main/WinMain/mainCRTStartup patterns
    EntryPoint,
    /// Standard library pattern (prologue + epilogue only)
    LibStub,
    /// Normal function
    Normal,
}

impl std::fmt::Display for FuncClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuncClass::Thunk => write!(f, "thunk"),
            FuncClass::Stub => write!(f, "stub"),
            FuncClass::Leaf => write!(f, "leaf"),
            FuncClass::Recursive => write!(f, "recursive"),
            FuncClass::Complex => write!(f, "complex"),
            FuncClass::EntryPoint => write!(f, "entry_point"),
            FuncClass::LibStub => write!(f, "lib_stub"),
            FuncClass::Normal => write!(f, "normal"),
        }
    }
}

pub struct FuncClassifierPlugin;
impl Default for FuncClassifierPlugin { fn default() -> Self { Self } }

impl Plugin for FuncClassifierPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Function Classifier".into(),
            version: "1.0.0".into(),
            author: Some("FreakRE Team".into()),
            description: "Classifies functions as thunk/stub/leaf/recursive/complex/entry_point.".into(),
            license: Some("MIT".into()),
            homepage: None,
        }
    }
    fn menu_items(&self) -> Vec<MenuItem> {
        vec![MenuItem::new("Analyze/Classify Functions", "Classify All Functions").with_shortcut("Ctrl+Shift+F")]
    }
    fn on_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        if path == "Analyze/Classify Functions" { self.analyze(ctx); }
    }
    fn analyze(&mut self, ctx: &mut PluginContext) {
        ctx.println("[FuncClassifier] Classifying functions...");

        let functions = match ctx.db.list_functions() {
            Ok(f) => f, Err(e) => { ctx.println(&format!("Error: {}", e)); return; }
        };

        let mut counts = std::collections::HashMap::new();

        for func in &functions {
            let class = classify_function(func);
            *counts.entry(class).or_insert(0usize) += 1;

            // Add classification as comment
            let _ = ctx.db.set_comment(
                func.address,
                format!("[class: {}]", class),
            );

            // Auto-label special classes
            match class {
                FuncClass::Thunk => {
                    let existing = ctx.db.get_label(func.address).ok().flatten().unwrap_or_default();
                    if existing.is_empty() || existing.starts_with("sub_") {
                        let _ = ctx.db.set_label(func.address, format!("thunk_{:X}", func.address));
                    }
                }
                FuncClass::EntryPoint => {
                    let _ = ctx.db.set_label(func.address, "entry_point".into());
                }
                _ => {}
            }
        }

        ctx.println(&format!("[FuncClassifier] Classified {} functions:", functions.len()));
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (class, count) in sorted {
            ctx.println(&format!("  {:12} : {}", class.to_string(), count));
        }
    }
}

fn classify_function(func: &FunctionEntry) -> FuncClass {
    let code = match &func.code_bytes {
        Some(b) => b.as_slice(),
        None => return FuncClass::Normal,
    };

    let size = code.len();

    // Thunk: single JMP rel32 (FF 25 or E9) or JMP [mem]
    if size <= 6 {
        if code.first() == Some(&0xE9) || (code.len() >= 2 && code[0] == 0xFF && (code[1] & 0x38) == 0x20) {
            return FuncClass::Thunk;
        }
        if size <= 4 {
            return FuncClass::Stub;
        }
    }

    // Count CALL instructions (E8 xx xx xx xx)
    let mut call_count = 0usize;
    let mut has_self_call = false;
    let mut i = 0;
    while i < code.len() {
        if code[i] == 0xE8 && i + 5 <= code.len() {
            call_count += 1;
            let rel = i32::from_le_bytes([code[i+1], code[i+2], code[i+3], code[i+4]]);
            let target = (i as i64 + 5 + rel as i64) as usize;
            if target == 0 {
                has_self_call = true;
            }
            i += 5;
        } else {
            i += 1;
        }
    }

    // Leaf: no calls at all
    if call_count == 0 && size > 6 {
        return FuncClass::Leaf;
    }

    // Recursive
    if has_self_call {
        return FuncClass::Recursive;
    }

    // Complex: large function (> 512 bytes) with many calls
    if size > 512 && call_count > 10 {
        return FuncClass::Complex;
    }

    // Entry point heuristics: calls __scrt_common_main_seh, WinMain, etc.
    // Check for common entry point string references in the code
    if size > 100 && call_count > 3 {
        // Look for patterns typical of CRT startup
        let has_crt_pattern = code.windows(3).any(|w| w == [0x55, 0x89, 0xE5]) // push ebp; mov ebp, esp
            && code.windows(1).any(|w| w == [0xE8]) // has calls
            && size > 200;
        if has_crt_pattern && func.address < 0x10000 {
            return FuncClass::EntryPoint;
        }
    }

    // Library stub: very short with just prologue + ret
    if size <= 16 && code.last() == Some(&0xC3) {
        return FuncClass::LibStub;
    }

    FuncClass::Normal
}
