# FreakRE

Modular reverse engineering framework written in Rust. Multi-format binary analysis with built-in decompiler, plugin system, and dual UI (native desktop + web).

## Architecture

```
freakre-desktop (egui native app)
bibleteks-web   (axum web server)
bibleteks       (CLI binary)
│
├── scanner            ← Orchestrator with weighted signal correlation
├── pe-parser          ← PE32/PE32+ parser with malware anomaly detection
├── elf-parser         ← ELF32/ELF64 parser with security warnings
├── macho-parser       ← Mach-O parser with load command analysis
├── entropy-rs         ← Shannon entropy + sliding window analysis
├── str-extract        ← ASCII/UTF-16 string extraction with byte offsets
├── import-analyzer    ← Import table analysis with 8+ detection categories
├── yara-lite          ← YARA-subset engine (hex/text/regex + conditions)
├── backdoor-analyzer  ← Backdoor detection with MITRE ATT&CK mapping
├── shellcode-analyzer ← Shellcode detection + API hash resolution
├── xrefs              ← Cross-reference database for strings and imports
├── cfg-builder        ← Control Flow Graph construction + anomaly detection
├── func-sigs          ← Function signature matching + compiler identification
├── func-finder        ← Function boundary detection (recursive descent + patterns)
├── capstone-ffi       ← Capstone disassembly bindings with fallback LDE
├── freakre-ir         ← Intermediate representation with SSA + x86/ARM lifters
├── dataflow           ← Dataflow analysis (live variables, reaching definitions, use-def chains)
├── type-propagation   ← Type inference and constraint propagation
├── type-system        ← Type database, layout computation, builtin types
├── decompiler         ← IR → AST → C decompilation pipeline
├── diffing            ← Binary diffing engine
├── project-db         ← Sled-backed project database with undo/redo + bookmarks
├── scripting          ← Rhai scripting engine integration
├── plugins            ← Dynamic plugin loading via libloading
├── sys-plugins        ← Built-in plugins (crypto finder, entropy mapper, string analyzer)
└── ml-detection       ← Feature-based binary classification with decision trees
```

All libraries are written from scratch, zero-copy where possible, no unsafe in hot paths.

## Quick Start

### CLI

```bash
cargo build --release -p bibleteks-scanner

# Scan a file
./target/release/bibleteks suspicious.exe

# Scan a directory
./target/release/bibleteks /path/to/samples/

# With YARA rules
./target/release/bibleteks -r rules.yar target.exe

# JSON output
./target/release/bibleteks -f json target.exe

# CSV output
./target/release/bibleteks -f csv target.exe > results.csv

# Filter by severity
./target/release/bibleteks --findings-only --min-severity high ./samples/

# Parallel scanning
./target/release/bibleteks -j 8 ./large_directory/
```

### Desktop UI

```bash
cargo run -p freakre-desktop --release
```

Native egui application with sidebar navigation, hex viewer, disassembler, CFG graph, theme switching, and settings persistence.

### Web UI

```bash
cargo run -p bibleteks-web --release
# Open http://127.0.0.1:3000
```

Axum-based web server with drag-and-drop upload and HTML report rendering.

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
| `ml-detection` | 96-feature vector extraction + decision tree classifier with feature importance |

### Intermediate Representation & Decompilation

| Module | Description |
|--------|------------|
| `capstone-ffi` | Capstone disassembly FFI with graceful fallback to built-in length-disassembler |
| `freakre-ir` | Platform-independent IR with SSA form; x86/x64 and ARM lifters |
| `dataflow` | Live variable analysis, reaching definitions, use-def chain construction |
| `type-propagation` | Constraint-based type inference across IR |
| `type-system` | Type database with layout computation and builtin type definitions |
| `decompiler` | IR → AST → C decompilation with control flow structuring |
| `cfg-builder` | Control flow graph construction with unreachable code and branching anomaly detection |
| `xrefs` | Cross-reference database mapping strings and imports to code locations |

### Project Management & Extensibility

| Module | Description |
|--------|------------|
| `project-db` | Sled-backed persistent storage with undo/redo history and bookmarks |
| `plugins` | Runtime plugin loading via `libloading` with trait-based API |
| `sys-plugins` | Built-in plugins: crypto constant finder, entropy mapper, function classifier, string analyzer |
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
cargo test -p bibleteks-scanner

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
