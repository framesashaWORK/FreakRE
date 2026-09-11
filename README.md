# FreakRE

Modular reverse engineering framework written in Rust. From raw bytes to
readable C: multi-format parsers, a platform-independent IR with SSA and
SCCP constant propagation, a structured decompiler, a FLIRT-style signature
engine with a memory-mapped binary database, malware-family detection,
emulation-assisted analysis, an HTTP API and a native desktop UI.

Everything is written from scratch in safe Rust with zero-copy parsing where
possible. The only `unsafe` lives in FFI bindings (`capstone-ffi`,
`libloading`) and a handful of isolated low-level helpers.

---

## Highlights

- **Real decompiler** — x86/x64 (plus ARM, DEX, PPC lifters) → IR → SSA →
  SCCP → CFG structuring (`if`/`while`/`for`/`switch`, short-circuit
  `&&`/`||`) → typed C with recovered parameters, struct fields, string
  literals and named call targets.
- **Jump-table / switch recovery** in the lifter: `cmp idx,N; ja default;
  jmp [tbl+idx*scale]` and the MSVC two-level form (`mov ecx,[idx*4+jtbl];
  add rcx,base; jmp rcx`) become `switch (x) { case 0: ... }`.
- **Emulation-assisted decompilation** — one bounded emulation run resolves
  dynamic `call reg` sites (vtable dispatch, function-pointer tables) whose
  observed targets agree across executions.
- **FLIRT-style signature engine** — ~3M signatures with a custom
  memory-mapped `.fbd` format and a prebuilt hash-index ladder; 1.2M
  signatures load in ~0.1s (vs ~4s for text parsing, a 32× speedup).
- **Malware-family engine** — a dedicated signature DB auto-built from
  quarantine corpora (`fsig-gen --families`), detecting families such as
  icedid / magniber / mafia by function-level patterns.
- **Signature tiers** — `low` (~1.2M) / `basic` (~2.7M) / `freak` (~2.9M)
  selectable at runtime for a speed/recall tradeoff.
- **Backdoor detection with provenance** — a serializable
  `BackdoorReport` contract (JSON/SARIF-ready) with MITRE ATT&CK mapping,
  semantic import tags (source/sink/role) and weighted signal correlation.
- **YARA-subset engine** — hex with wildcards, text/regex with modifiers,
  integer functions, boolean conditions, Aho-Corasick matching.
- **HTTP API** — scan, strings, entropy, xrefs, SARIF, explain and
  function-level decompilation over multipart uploads.
- **48-crate workspace** — parsers for PE, ELF, Mach-O, COFF, DEX, WASM,
  PDF, .NET, Pyc, firmware, memory dumps; 117 test suites, fuzz contracts
  for IR soundness.

## Architecture

```
                    ┌────────────────────────────────────────────┐
                    │  freakre-desktop (egui app, pkg: freakre-desktop)
                    │  freakre           (CLI,  pkg: freakre-scanner)
                    │  freakre-server    (HTTP API on :8080)
                    └─────────────────────┬──────────────────────┘
                                          │
                 ┌────────────────────────▼─────────────────────────┐
                 │  freakre-scanner — orchestrator, weighted signal  │
                 │  correlation, single canonical BackdoorReport     │
                 └──┬──────────┬──────────┬──────────┬─────────────┘
                    │          │          │          │
        ┌───────────▼──┐ ┌─────▼────┐ ┌───▼────┐ ┌───▼──────────┐
        │ parsers      │ │ engines  │ │ sigs   │ │ decompiler   │
        │ PE ELF Mach-O│ │ entropy  │ │ func-  │ │ freakre-ir   │
        │ COFF DEX WASM│ │ strings  │ │ sigs   │ │ decompiler   │
        │ PDF .NET Pyc │ │ imports  │ │ yara-  │ │ dataflow     │
        │ firmware ... │ │ xrefs    │ │ lite   │ │ type-*       │
        └──────────────┘ └──────────┘ └────────┘ └──────────────┘
```

### The decompilation pipeline

```
bytes ──► disassembler ──► x86 lifter ──► IR
                                            │
   ┌────────────────────────────────────────┘
   │  1. lift_function (registers, flags, calls with recovered arguments)
   │  2. jump-table recovery  : IndirectBranch → IrInst::Switch
   │  3. strip_call_shadows   : push/pop call-shadow cleanup
   │  4. prune_unreachable    : BlockId-remapped reachability cleanup
   │  5. SSA: to_ssa → remove_trivial_phis → SCCP → from_ssa
   │  6. CFG structuring      : if/else, loops, short-circuit && / ||,
   │  │                         switch dispatch
   ▼  7. params.rs           : arg registers / stack slots → a1..aN
      8. stack_vars.rs       : Mem2Reg for stack slots
      9. struct_fields.rs    : *(T*)(base+off) → base->field_0xNN
     10. types.rs            : constraint solving + interproc summaries
     11. strings.rs          : IntLit(va) → "literal"
     12. simplify.rs         : dead locals, compound assigns, idioms
     13. ast_to_c            : readable C emission
```

`freakre-ir` keeps the IR honest: width-aware memory access, SCCP with a
monotone lattice and restart-style propagation, and a block-graph that
remaps `BlockId`s correctly when unreachable code is pruned.

### Signature engine

```
tools/fsig-gen
├── fsig-gen          (default)   export-based signatures for library bases
├── fsig-gen --families           malware family signatures from quarantine
│                                 corpora: func-finder detection, entropy
│                                 gate (packed skip), cross-family and
│                                 --against-base filtering, provenance names
├── fsig-clean                    curator: dedup, conflict resolution
│                                 (survivor gains aka=), junk gating,
│                                 tier generation (low/basic/freak)
└── fsig-pack                     .fsig → .fbd (memory-mapped binary DB)
```

- **.fsig** — text base: `lib|arch|name|min_len|conf|pattern`, optional
  `|meta=role=...;cc=...;source=...;sink=...` semantic tags.
- **.fbd** — mmap overlay, 128-byte header, open-addressed probe tables
  keyed by a packed byte ladder (oct → quint → triple → pair → single →
  slow). Zero-copy: the scanner reads the DB straight from the OS page
  cache.
- **Family engine** — separate `FAMILY_DB`, auto-loaded from
  `malware-families.fbd`; hits surface in `libraries_found`.
- **Tiers** — `--sigs-tier low|basic|freak` (CLI) or a settings dropdown
  (desktop UI); `FREAKRE_SIGS_TIER` env var is honored everywhere.

## Quick Start

### CLI

```bash
cargo build --release -p freakre-scanner

# Scan a file / directory
./target/release/freakre suspicious.exe
./target/release/freakre /path/to/samples/

# All formats: pretty, json, csv, html
./target/release/freakre -f json target.exe > report.json
./target/release/freakre -f html target.exe > report.html

# With YARA rules
./target/release/freakre -r rules.yar target.exe

# Filter output
./target/release/freakre --findings-only --min-severity high ./samples/

# Parallel scanning (0 = auto)
./target/release/freakre -j 8 ./large_directory/

# Signature tier
./target/release/freakre --sigs-tier freak target.exe
```

Full flag list: `-r/--rules`, `-f/--format`, `-d/--depth`, `-j/--threads`,
`--findings-only`, `--min-severity`, `-o/--output`, `-q/--quiet`,
`-v/--verbose`, `--sigs-tier`.

Exit codes: `0` clean, `1` suspicious, `2` malicious.

### HTTP server

```bash
cargo run --release -p freakre-server
```

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | liveness |
| `/api/capabilities` | GET | feature discovery |
| `/api/scan` | POST | multipart scan (full report) |
| `/api/scan/base64` | POST | base64-body scan |
| `/api/scan/path` | POST | scan a server-side path |
| `/api/strings` | POST | string extraction |
| `/api/entropy` | POST | entropy profile |
| `/api/xrefs` | POST | cross-references |
| `/api/decompile` | POST | function decompilation to C |
| `/api/explain` | POST | plain-language verdict explanation |
| `/api/sarif` | POST | SARIF output |
| `/api/jobs/scan`, `/api/jobs/:id` | POST/GET | async scan jobs |

`/api/decompile` runs the full pipeline: func-finder → x86 lifter (with
image context for jump tables) → emulation-assisted indirect-call
resolution → decompiler → C with parameters, typed locals, struct fields
and string literals.

### Desktop UI

```bash
cargo run -p freakre-desktop --release
```

Native egui application: sidebar navigation, hex viewer, disassembler, CFG
graph, signature-tier selector, theme switching and settings persistence.

### Building your own signature bases

```bash
cargo build --release -p fsig-gen

# Library base from a directory of clean DLLs
fsig-gen --out mybase.fsig --jobs 3 ./libs/

# Malware family signatures from a quarantine folder
fsig-gen --families --out families.fsig --against mybase.fsig \
         --families-max-funcs 8 --jobs 4 ./quarantine/

# Clean, dedup and split into tiers
fsig-clean --in mybase.fsig --out mybase-clean.fsig \
           --low-target 1200000 --basic-target 2700000

# Pack to the mmap format
fsig-pack mybase-clean.fsig mybase-clean.fbd
```

Point the scanner at a directory containing `generated-*.fbd` (or set
`FREAKRE_SIGS_DIR`) and select the tier.

## Modules

### Binary Parsers

| Module | Formats | Key Features |
|--------|---------|-------------|
| `pe-parser` | PE32, PE32+ | RWX sections, overlapping regions, anomalous headers, TLS callbacks, delay imports |
| `elf-parser` | ELF32, ELF64 | Executable stack, missing NX, static linking, suspicious interpreter, section anomalies |
| `macho-parser` | Mach-O 32/64 | Load commands, dylib dependencies, code signatures, encryption info |
| `coff-parser` | COFF | object/symbol parsing |
| `dex-parser` | Android DEX | classes, methods, bytecode for the DEX lifter |
| `wasm-parser` | WebAssembly | module sections, imports/exports |
| `pdf-analyzer` / `dotnet-analyzer` / `pyc-parser` / `firmware-analyzer` / `memdump-analyzer` / `dll-analyzer` | — | format-specific analyzers |

### Analysis Engines

| Module | Description |
|--------|------------|
| `entropy-rs` | Shannon entropy with zero-alloc histogram; sliding window for packed-region detection |
| `str-extract` | ASCII + UTF-16LE/BE in a single pass with byte offsets |
| `import-analyzer` | 8+ rule categories: injection, hollowing, APC, persistence, anti-debug, dynamic resolve, C2, ransomware crypto, keylogging, credential theft |
| `yara-lite` | Hex wildcards, text/regex modifiers, `uint8/16/32`, `entrypoint`, boolean conditions, Aho-Corasick |
| `backdoor-analyzer` | Import/string backdoor detection with MITRE ATT&CK T-codes; canonical serializable report |
| `shellcode-analyzer` | Shellcode patterns + API hash resolution (CRC32, MD5, ROR13) |
| `cfg-builder` | CFG construction, unreachable code and branching anomalies |
| `xrefs` | Cross-reference database for strings and imports |
| `diffing` | Binary diffing engine |
| `ml-detection` | 96-feature vector + heuristic decision scoring with feature importance |

### IR & Decompilation

| Module | Description |
|--------|------------|
| `capstone-ffi` | Capstone FFI with graceful fallback to the built-in length-disassembler |
| `freakre-ir` | SSA + SCCP, x86/x64/ARM/DEX/PPC lifters, jump-table recovery, emulation-assisted call resolution hooks |
| `emulator-x86` | Bounded x86/x64 emulation: decryption traces, indirect-call resolution |
| `dataflow` | Live variables, reaching definitions, use-def chains |
| `type-propagation` | Constraint-based type inference across IR |
| `type-system` | Type database, layout computation, builtins |
| `decompiler` | IR → AST → C pipeline (structuring, params, stack vars, struct fields, types, strings, simplify) |
| `func-finder` | Function boundary detection (recursive descent + patterns) |

### Extensibility

| Module | Description |
|--------|------------|
| `project-db` | Sled-backed storage with undo/redo and bookmarks |
| `plugins` | Runtime plugin loading via `libloading` with a trait API |
| `freakre-sys-plugins` | Built-ins: crypto constant finder, entropy mapper, function classifier, string analyzer |
| `scripting` | Rhai scripting engine for custom analyses |

### Scanner Orchestrator

Combines every module into a unified report with **weighted signal
correlation**:

- **Base signals** — import score (25%), backdoor score (25%)
- **Content signals** — shellcode (25%), YARA matches, high-entropy regions
- **Structural signals** — RWX sections, overlapping regions, CFG anomalies
- **Diminishing returns** — repeated low-severity findings don't scale
  linearly
- **Compounding bonus** — 3+ active signal categories add bonus weight
- **Hard overrides** — critical findings and shellcode force a Malicious
  verdict

The report is computed once (`BackdoorReport`, serde + provenance +
suppression metadata) and reused by pretty/JSON/CSV/HTML outputs, `/api/explain`
and `/api/sarif` — one data source, no divergence.

## Measured Results

Honest numbers from the committed benchmark harness (`tmp/bench`,
`decomp_bench` bin, MSVC `/O0` toy corpus + real Windows DLLs):

| Suite | Avg similarity | Structural |
|-------|---------------:|-----------:|
| Pure C toys (10 files) | **38.7%** | **59.2%** |
| Python via Cython→native | 33.3% | 54.4% |

System32 sample (40 DLLs > 120KB, 24,362 decompiled functions):
parameters recovered in 52.6%, struct fields in 47.2%, loops in 16.2%,
typed pointer casts in 39.5%.

Self-hosting (decomp_bench on itself, 13,366 functions): 0 lift failures,
66.1% named calls, 54.2% typed pointer casts, 41.6% typed locals.

Java remains out of scope: only JVM bytecode is available and the lifter
consumes native machine code (DEX ≠ JVM).

## Prerequisites

### Required

- **Rust** ≥ 1.75 (toolchain pinned by `rust-toolchain.toml`) —
  [rustup.rs](https://rustup.rs)
- **C/C++ compiler** — MSVC or MinGW on Windows, GCC/Clang on Linux/macOS
  (needed by `libloading`, `cc` build scripts, and FFI crates)
  - Ubuntu/Debian: `sudo apt install build-essential`
  - Fedora: `sudo dnf install gcc-c++ make`
  - macOS: `xcode-select --install`
  - Windows: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
    with "Desktop development with C++"

### Linux Desktop UI Dependencies

```bash
# Ubuntu/Debian
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
                 libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
# Fedora
sudo dnf install gtk3-devel libxkbcommon-devel openssl-devel
```

Not needed for the CLI.

### Optional: Capstone Disassembly Engine

A built-in length-disassembler fallback is always available. For full
Capstone support:

| Platform | Command |
|----------|---------|
| Ubuntu/Debian | `sudo apt install libcapstone-dev` |
| Fedora | `sudo dnf install capstone-devel` |
| macOS | `brew install capstone` |
| Windows (vcpkg) | `vcpkg install capstone:x64-windows` |
| Windows (manual) | `CAPSTONE_LIB_DIR` env var pointing at `capstone.lib` |

## Testing

```bash
cargo test --workspace          # 117 test suites

cargo test -p decompiler        # pipeline + emission
cargo test -p freakre-ir        # IR, SSA, SCCP, lifters, jump tables

# IR soundness smoke fuzzer: random IR graphs through the SCCP pipeline,
# contract-checked (no panics, no undeclared temps, consistent CFG)
cd fuzz && cargo run --release --bin smoke_decompiler_ir -- 2017
```

Fuzz targets for all parsers live in `fuzz/`:

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
