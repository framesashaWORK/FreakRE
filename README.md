# FreakRE

Modular reverse engineering framework written in Rust. Multi-format binary analysis with built-in decompiler, plugin system, and native desktop UI.

## Prerequisites

### Required

- **Rust** ≥ 1.75 ([rustup.rs](https://rustup.rs))
- **C/C++ compiler** — MSVC or MinGW on Windows, GCC/Clang on Linux/macOS
  - Needed by `libloading` (plugin system), `cc` build scripts, and FFI crates
  - Ubuntu/Debian: `sudo apt install build-essential`
  - Fedora: `sudo dnf install gcc-c++ make`
  - macOS: `xcode-select --install`
  - Windows: Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with "Desktop development with C++"

### Linux Desktop UI Dependencies

The `freakre-desktop` crate uses `eframe` (egui) which requires system libraries on Linux:

```bash
# Ubuntu/Debian
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev

# Fedora
sudo dnf install gtk3-devel libxkbcommon-devel openssl-devel
```

Not needed for CLI.

### Optional: Capstone Disassembly Engine

FreakRE includes a built-in length-disassembler fallback. For full Capstone disassembly support:

| Platform | Command |
|----------|---------|
| Ubuntu/Debian | `sudo apt install libcapstone-dev` |
| Fedora | `sudo dnf install capstone-devel` |
| macOS | `brew install capstone` |
| Windows (vcpkg) | `vcpkg install capstone:x64-windows` |
| Windows (manual) | Set `CAPSTONE_LIB_DIR` env var to directory containing `capstone.lib` |

Without Capstone, the `capstone-ffi` crate gracefully falls back to the internal LDE.

## Architecture

```
freakre-desktop  (egui native app,   pkg: freakre-desktop)
freakre          (CLI binary,         pkg: freakre-scanner)
freakre-server   (HTTP API on :8080,  pkg: freakre-server)
│
├── freakre-scanner     ← Orchestrator with weighted signal correlation
├── pe-parser           ← PE32/PE32+ parser with malware anomaly detection
├── elf-parser          ← ELF32/ELF64 parser with security warnings
├── macho-parser        ← Mach-O parser with load command analysis
├── coff-parser         ← COFF object/parse support
├── dex-parser          ← Android DEX parser
├── wasm-parser         ← WebAssembly module parser
├── pdf-analyzer / dotnet-analyzer / pyc-parser / firmware-analyzer / memdump-analyzer / dll-analyzer
├── entropy-rs          ← Shannon entropy + sliding window analysis
├── str-extract         ← ASCII/UTF-16 string extraction with byte offsets
├── import-analyzer     ← Import table analysis with 8+ detection categories
├── yara-lite           ← YARA-subset engine (hex/text/regex + conditions)
├── backdoor-analyzer   ← Backdoor detection with MITRE ATT&CK mapping
├── shellcode-analyzer  ← Shellcode detection + API hash resolution
├── xrefs               ← Cross-reference database for strings and imports
├── cfg-builder         ← Control Flow Graph construction + anomaly detection
├── func-finder         ← Function boundary detection (recursive descent + patterns)
├── func-sigs           ← FLIRT-style signature matching + .fsig/.fbd databases + malware family engine
├── capstone-ffi        ← Capstone disassembly bindings with fallback LDE
├── freakre-ir          ← IR with SSA + SCCP; x86/x64, ARM, DEX, PPC lifters
├── emulator-x86        ← x86/x64 emulation engine (decryption traces, call resolution)
├── dataflow            ← Live variables, reaching definitions, use-def chains (pkg: dataflow)
├── type-propagation    ← Type inference and constraint propagation (pkg: freakre-type-propagation)
├── type-system         ← Type database, layout computation, builtin types
├── decompiler          ← IR → AST → C decompilation pipeline (pkg: decompiler)
├── diffing             ← Binary diffing engine
├── project-db          ← Sled-backed project database with undo/redo + bookmarks
├── scripting           ← Rhai scripting engine integration
├── plugins             ← Dynamic plugin loading via libloading
├── freakre-sys-plugins ← Built-in plugins (crypto finder, entropy mapper, string analyzer)
└── ml-detection        ← Feature-based binary classification with decision trees
```

All analysis libraries are written from scratch in safe Rust with zero-copy parsing where possible. The only `unsafe` usage is in FFI bindings (`capstone-ffi`, `libloading`) and isolated low-level helpers.

## Quick Start

### CLI

```bash
cargo build --release -p freakre-scanner

# Scan a file
./target/release/freakre suspicious.exe

# Scan a directory
./target/release/freakre /path/to/samples/

# With YARA rules
./target/release/freakre -r rules.yar target.exe

# JSON output
./target/release/freakre -f json target.exe

# CSV output
./target/release/freakre -f csv target.exe > results.csv

# Filter by severity
./target/release/freakre --findings-only --min-severity high ./samples/

# Parallel scanning
./target/release/freakre -j 8 ./large_directory/
```

### Desktop UI

```bash
cargo run -p freakre-desktop --release
```

Native egui application with sidebar navigation, hex viewer, disassembler, CFG graph, theme switching, and settings persistence.

## Modules

### Binary Parsers

| Module | Formats | Key Features |
|--------|---------|-------------|
| `pe-parser` | PE32, PE32+ | RWX sections, overlapping regions, anomalous headers, TLS callbacks, delay imports |
| `elf-parser` | ELF32, ELF64 | Executable stack, missing NX, static linking, suspicious interpreter, section anomalies |
| `macho-parser` | Mach-O 32/64 | Load commands, dylib dependencies, code signatures, encryption info |

### Analysis Engines

| Module | Description |
|--------|------------|
| `entropy-rs` | Shannon entropy with zero-alloc histogram; sliding window for packed region detection |
| `str-extract` | ASCII + UTF-16LE + UTF-16BE in single pass with byte offset tracking |
| `import-analyzer` | 8+ rule categories: process injection, hollowing, APC injection, persistence, anti-debug, dynamic resolve, C2/network, ransomware crypto, keylogging, credential theft |
| `yara-lite` | Hex patterns with wildcards, text/regex with modifiers, integer functions (`uint8/16/32`, `entrypoint`), boolean conditions, Aho-Corasick multi-pattern matching |
| `backdoor-analyzer` | Import + string based backdoor detection with MITRE ATT&CK T-code mapping |
| `shellcode-analyzer` | Shellcode pattern detection + API hash resolution (CRC32, MD5, ROR13) |
| `func-sigs` | Known function signatures (crypto, compression, network) + compiler fingerprinting (MSVC, GCC, Clang, Delphi, Go) |
| `ml-detection` | 96-feature vector extraction + rule-based heuristic scoring engine with feature importance output |

### Intermediate Representation & Decompilation

| Module | Description |
|--------|------------|
| `capstone-ffi` | Capstone disassembly FFI with graceful fallback to built-in length-disassembler |
| `freakre-ir` | Platform-independent IR with SSA + SCCP constant propagation; x86/x64, ARM, DEX and PPC lifters; jump-table/switch recovery |
| `emulator-x86` | x86/x64 emulation: decryption traces, indirect-call resolution for the decompiler |
| `dataflow` | Live variable analysis, reaching definitions, use-def chain construction |
| `type-propagation` | Constraint-based type inference across IR |
| `type-system` | Type database with layout computation and builtin type definitions |
| `decompiler` | IR → AST → C with CFG structuring, SCCP, param/struct-field recovery, cross-function type propagation, string literals, jump-table switches |
| `cfg-builder` | Control flow graph construction with unreachable code and branching anomaly detection |
| `xrefs` | Cross-reference database mapping strings and imports to code locations |

### Signature Databases

`func-sigs` ships a FLIRT-style signature pipeline with a custom binary format:

- **.fsig** — text signature base (6/7-field lines, optional semantic tags)
- **.fbd** — memory-mapped binary overlay with a prebuilt hash-index ladder (oct/quint/triple/pair/single); loads 1.2M signatures in ~0.1s vs ~4s for text parsing
- **Family engine** — separate malware-family signatures (icedid, magniber, ...) auto-loaded as `malware-families.fbd`
- **Tiers** — `low` / `basic` / `freak` signature tiers selectable via `--sigs-tier` in the CLI and the desktop UI settings

### HTTP API

`freakre-server` exposes the scanner on `:8080`, including `/api/decompile` (function decompilation with emulation-assisted indirect-call resolution, recovered parameters, typed locals and string literals).

### Project Management & Extensibility

| Module | Description |
|--------|------------|
| `project-db` | Sled-backed persistent storage with undo/redo history and bookmarks |
| `plugins` | Runtime plugin loading via `libloading` with trait-based API |
| `freakre-sys-plugins` | Built-in plugins: crypto constant finder, entropy mapper, function classifier, string analyzer |
| `scripting` | Rhai scripting engine for custom analysis scripts |
| `diffing` | Binary diffing for comparing two binaries |

### Scanner Orchestrator

Combines all modules into a unified report with **weighted signal correlation**:

- **Base signals**: import score (25%), backdoor score (25%)
- **Content signals**: shellcode (25%), YARA matches, high entropy regions
- **Structural signals**: RWX sections, overlapping regions, CFG anomalies
- **Diminishing returns**: repeated low-severity findings don't scale linearly
- **Signal compounding bonus**: 3+ active signal categories add bonus weight
- **Hard overrides**: critical findings and shellcode force Malicious verdict

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean |
| `1` | Suspicious files found |
| `2` | Malicious files found |

## Testing

```bash
# All workspace tests
cargo test --workspace

# Specific module
cargo test -p yara-lite
cargo test -p pe-parser
cargo test -p freakre-scanner

# With output
cargo test --workspace -- --nocapture
```

## Fuzzing

Fuzz targets for all parsers are in the `fuzz/` directory:

```bash
cd fuzz
cargo fuzz run fuzz_pe_parser
cargo fuzz run fuzz_elf_parser
cargo fuzz run fuzz_macho_parser
cargo fuzz run fuzz_yara
cargo fuzz run fuzz_entropy
cargo fuzz run fuzz_import_analyzer
cargo fuzz run fuzz_str_extract
```

## License

MIT
