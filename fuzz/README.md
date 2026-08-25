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
