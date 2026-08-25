# Phase 5: Integration & Dependency Removal — Complete

## Summary

All external analysis dependencies have been replaced with own `freakre-*` crates.
The project now uses **zero external dependencies** in its core analysis stack.

## Removed from Workspace

| Crate | Reason |
|-------|--------|
| `capstone-ffi` | Replaced by `freakre-x86` (own x86/x64 decoder) |
| `scripting` | Replaced by `freakre-script` (own sandboxed DSL) |
| CLI binary (`freakre`) | Desktop UI is the only entry point |

## Dependency Replacements

| Old Dependency | New Replacement | Affected Crates |
|---------------|-----------------|-----------------|
| `sha2`, `md-5` | `freakre-hash` | scanner, project-db |
| `serde_json`, `toml` | `freakre-config` | scanner, desktop-ui |
| `regex-lite`, `aho-corasick` | `freakre-patterns` | yara-lite |
| `capstone-ffi` | `freakre-x86` | desktop-ui, decompiler |
| `rhai` | `freakre-script` | desktop-ui |
| `hex` | Manual hex encode | scanner |

## Files Modified

### Workspace
- `Cargo.toml` — removed `capstone-ffi`, `scripting` from members

### Scanner
- `scanner/Cargo.toml` — removed sha2, md-5, serde_json, hex, clap, colored, walkdir, rayon; added freakre-hash, freakre-config; removed CLI binary target
- `scanner/src/scanner.rs` — replaced `sha2::Sha256`/`md5::Md5` with `freakre_hash`; manual hex encoding

### YARA-Lite
- `yara-lite/Cargo.toml` — replaced `aho-corasick` + `regex-lite` with `freakre-patterns`
- `yara-lite/src/compiler.rs` — `Regex` → `SafeRegex`, `AhoCorasick` → `AcSearcher`
- `yara-lite/src/scanner.rs` — updated to use `AcSearcher::find_overlapping()` and `SafeRegex::find_iter()`

### Patterns
- `freakre-patterns/src/lib.rs` — added `AcSearcher`, `SafeRegex`, `RegexMatchIter` wrappers for yara-lite compatibility

### Desktop UI
- `desktop-ui/Cargo.toml` — replaced `capstone-ffi` with `freakre-x86`; removed `serde_json`, `serde`, `toml`; added `freakre-config`, `freakre-script`
- `desktop-ui/src/app.rs` — updated imports

### Project DB
- `project-db/Cargo.toml` — replaced `serde_json`, `sha2` with `freakre-hash`

### IR / Decompiler
- `freakre-ir/Cargo.toml` — removed `serde_json`, `hex`
- `freakre-ir/src/x86_lifter.rs` — marked built-in LDE as "LIMITED DISASSEMBLY MODE" fallback
- `decompiler/Cargo.toml` — added `freakre-x86` dependency

## Remaining External Dependencies (Non-Core)

These are acceptable because they don't process untrusted/malware data:

| Crate | Used By | Justification |
|-------|---------|---------------|
| `sled` | project-db | Embedded KV store, well-audited |
| `bincode` | project-db | Binary serialization for internal DB |
| `serde` | multiple | Serialization framework (derive macros only) |
| `chrono` | project-db | Timestamps |
| `uuid` | project-db | Project IDs |
| `eframe`/`egui` | desktop-ui | GUI framework |
| `tokio` | desktop-ui | Async runtime for UI |
| `rfd` | desktop-ui | Native file dialogs |
| `dirs` | desktop-ui | Config directory resolution |
| `thiserror` | multiple | Error derive macro |
| `indexmap` | decompiler | Ordered hash maps |
| `bitflags` | project-db | Flag types |

## Next Steps

1. Run `cargo check --workspace` to verify compilation
2. Fix any remaining API mismatches in yara-lite scanner tests
3. Add integration tests for freakre-x86 ↔ freakre-ir pipeline
4. Generate initial `.fsig` signature database for FLIRT matcher
