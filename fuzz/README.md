# FreakRE Fuzzing Suite

Fuzz targets for FreakRE parsers to ensure they don't panic on malformed input.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

## Running Fuzzers

### PE Parser (most critical — handles untrusted binaries)
```bash
cargo +nightly fuzz run fuzz_pe_parser --jobs 8
```

### ELF Parser
```bash
cargo +nightly fuzz run fuzz_elf_parser --jobs 8
```

### Mach-O Parser
```bash
cargo +nightly fuzz run fuzz_macho_parser --jobs 8
```

### Import Analyzer
```bash
cargo +nightly fuzz run fuzz_import_analyzer --jobs 8
```

### String Extraction
```bash
cargo +nightly fuzz run fuzz_str_extract --jobs 8
```

### Entropy Calculation
```bash
cargo +nightly fuzz run fuzz_entropy --jobs 8
```

### YARA Rules Parser
```bash
cargo +nightly fuzz run fuzz_yara --jobs 8
```

## Seed Corpus

For better fuzzing, provide seed corpus with real binaries.

Seed inputs are committed under `fuzz/corpus/seeds/` (the only corpus
subdirectory tracked by git — everything else under `corpus/` is generated
output and ignored):

```bash
mkdir -p fuzz/corpus/seeds
# Add real PE files to the committed seed corpus
cp /path/to/samples/*.exe fuzz/corpus/seeds/

cargo +nightly fuzz run fuzz_pe_parser fuzz/corpus/seeds
```

### Synthetic malformed PE smoke corpus

The repository includes a small, deterministic corpus generator for parser
smoke checks. It creates only synthetic bytes, does not download or execute
anything, and writes to the ignored `fuzz/corpus/generated-pe/` directory.
Run it from the repository root:

```powershell
powershell -NoProfile -File .\fuzz\generate-malformed-pe-seeds.ps1
powershell -NoProfile -File .\fuzz\generate-malformed-pe-seeds.ps1 -WriteFiles
```

The first command is a dry run. Keep generated files out of
`fuzz/corpus/seeds/`; that directory is reserved for reviewed committed
inputs. To perform a short bounded libFuzzer smoke check without installing
`cargo-fuzz`, use an existing compatible cargo-fuzz installation and an
explicit time limit:

```powershell
cargo fuzz run fuzz_pe_parser .\fuzz\corpus\generated-pe -- -max_total_time=5 -timeout=2
```

For a bounded smoke check that does not require `cargo-fuzz` or nightly Rust,
run the standalone harness from this directory:

```powershell
cargo run --bin smoke_pe_parser --quiet
```

It generates a fixed set of malformed PE-shaped byte buffers in memory and,
for every input that parses successfully, calls `exports`, `base_relocations`,
`runtime_functions`, `dotnet_info`, `tls_callbacks`, `delay_imports`,
`rich_header`, and `overlay_data`. The run processes a fixed number of seeds
and exits; it does not execute the input bytes or start an unbounded process.

Do not omit the time limit in automation. The generator is intentionally
separate from `pe-parser/src/lib.rs` and `tools/fsig-gen`.

## CI Integration

Add to your CI pipeline (GitHub Actions example):

```yaml
- name: Run fuzzers (1 minute each)
  run: |
    cargo install cargo-fuzz
    cargo +nightly fuzz run fuzz_pe_parser -- -max_total_time=60
    cargo +nightly fuzz run fuzz_elf_parser -- -max_total_time=60
    cargo +nightly fuzz run fuzz_macho_parser -- -max_total_time=60
```

## Why Fuzz?

Malware analyzers process **untrusted input** (malicious binaries). A panic in the parser = crash = DoS.

Fuzzing finds:
- Buffer overflows
- Integer overflows
- Out-of-bounds reads
- Infinite loops
- Stack overflows

## Known Issues Found

Run fuzzers regularly to catch regressions. Document any crashes found:

| Date | Target | Input | Issue | Fixed |
|------|--------|-------|-------|-------|
| - | - | - | - | - |
# PE parser fuzzing

The PE target is intentionally outside the workspace. Build and run it from
this directory so fuzzing uses its own lockfile and target directory:

```powershell
cargo install cargo-fuzz
cargo fuzz build fuzz_pe_parser
cargo fuzz run fuzz_pe_parser -- -timeout=10 -rss_limit_mb=2048
```

For a long unattended run, use a bounded wall-clock job and preserve the
corpus/artifacts:

```powershell
cargo fuzz run fuzz_pe_parser -- -max_total_time=3600 -timeout=10 -rss_limit_mb=2048
```

The harness must never assume a valid PE and should only call safe parser
entry points. Crash artifacts are written under `fuzz/artifacts/` by
`cargo-fuzz`; add minimized regressions to `fuzz/corpus/fuzz_pe_parser/`.
