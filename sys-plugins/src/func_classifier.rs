//! # Function Classifier Plugin
//!
//! Classifies functions by behavior: thunks, wrappers, leaf functions,
//! recursive, high-complexity, potential main(), etc. Uses heuristics
//! on function size, call patterns, and instruction mix.

use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};
use project_db::FunctionEntry;
use crate::util;
use freakre_x86::{Mnemonic, Operand};

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

            // Add classification as an append-style comment (never clobbers
            // user text; re-runs refresh only our own "[class:" line).
            util::upsert_tagged_comment(
                &mut ctx.db,
                func.address,
                "[class:",
                &format!("[class: {}]", class),
            );

            // Auto-label special classes — but never overwrite user labels.
            match class {
                FuncClass::Thunk => {
                    util::set_label_if_free(
                        &mut ctx.db,
                        func.address,
                        format!("thunk_{:X}", func.address),
                    );
                }
                FuncClass::EntryPoint => {
                    util::set_label_if_free(&mut ctx.db, func.address, "entry_point".into());
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

    // Count CALL instructions via real instruction decoding, so 0xE8 bytes
    // that are actually immediates/displacements of other instructions don't
    // inflate the count.
    let scan = scan_calls(code);
    let call_count = scan.count;
    let has_self_call = scan.self_call;

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
            && call_count > 0 // has decoded CALL instructions
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

/// Result of a decoded CALL scan over a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallScan {
    /// Number of decoded CALL instructions (direct and indirect).
    pub count: usize,
    /// True when a direct relative call targets the function's own start.
    pub self_call: bool,
}

/// Linear instruction-level scan of `code` counting real CALL instructions.
///
/// Uses the `freakre-x86` decoder instead of matching raw 0xE8 bytes: an 0xE8
/// appearing as part of another instruction's immediate/displacement no longer
/// counts as a call. Decode errors step forward one byte so malformed/padded
/// regions can't stall the scan.
fn scan_calls(code: &[u8]) -> CallScan {
    let mut result = CallScan { count: 0, self_call: false };
    let mut off = 0usize;
    while off < code.len() {
        match freakre_x86::decode(&code[off..], false) {
            Ok(insn) => {
                if insn.mnemonic == Mnemonic::Call {
                    result.count += 1;
                    // `decode()` uses base address 0, so a direct rel32 call's
                    // Rel operand is the target offset relative to the slice
                    // start; adding the instruction offset gives the target
                    // relative to the function start. Zero → call to self.
                    if let Some(Operand::Rel(target)) = insn.operands.first() {
                        if (off as i64).wrapping_add(*target as i64) == 0 {
                            result.self_call = true;
                        }
                    }
                }
                off += insn.length.max(1);
            }
            Err(_) => {
                off += 1;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_calls_real_call_counted() {
        // call rel32 (+5 → 0x0A); ret  — one real CALL
        let code = [0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3];
        let scan = scan_calls(&code);
        assert_eq!(scan.count, 1);
        assert!(!scan.self_call);
    }

    #[test]
    fn test_scan_calls_embedded_e8_not_counted() {
        // mov eax, 0x909090E8 — the 0xE8 is an immediate byte of a MOV,
        // not an instruction; the old raw-byte scanner miscounted this.
        let code = [0xB8, 0xE8, 0x90, 0x90, 0x90, 0xC3];
        let scan = scan_calls(&code);
        assert_eq!(scan.count, 0);

        // Same byte stream prefixed so 0xE8 lands mid-instruction as a
        // displacement: mov [eax+0xE8...], ... style — use lea with disp8.
        // lea eax, [ecx*1+0xE8] would need SIB; simpler: cmp dword [eax+0xE8], imm8
        // 83 B8 E8 00 00 00 07 = cmp dword ptr [eax + 0xE8], 7
        let code2 = [0x83, 0xB8, 0xE8, 0x00, 0x00, 0x00, 0x07, 0xC3];
        assert_eq!(scan_calls(&code2).count, 0);
    }

    #[test]
    fn test_scan_calls_self_call_detected() {
        // Function starting with: nop; nop; nop; nop; nop; nop;
        // then `call -11` (target = offset 6+5-11 = 0 → self), then ret.
        let code = [
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0xE8, 0xF5, 0xFF, 0xFF, 0xFF,
            0xC3,
        ];
        let scan = scan_calls(&code);
        assert_eq!(scan.count, 1);
        assert!(scan.self_call);

        // classify_function should report Recursive for it.
        let mut func = FunctionEntry { address: 0x1000, ..Default::default() };
        func.code_bytes = Some(code.to_vec());
        assert_eq!(classify_function(&func), FuncClass::Recursive);
    }

    #[test]
    fn test_scan_calls_indirect_call_counted() {
        // call eax (FF D0); ret — indirect call must count too.
        let code = [0xFF, 0xD0, 0xC3];
        assert_eq!(scan_calls(&code).count, 1);
    }

    #[test]
    fn test_leaf_classification_uses_decoded_calls() {
        // >6 bytes containing only an embedded 0xE8 immediate and no real
        // call → leaf, not "has calls".
        let mut func =
            FunctionEntry { address: 0x2000, ..Default::default() };
        func.code_bytes = Some(vec![0xB8, 0xE8, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3]);
        assert_eq!(classify_function(&func), FuncClass::Leaf);
    }
}
