#![allow(dead_code, unused_assignments)]
//! # func-sigs — FLIRT-like Function Signature Matching
//!
//! Identifies known library functions in compiled binaries using byte-pattern
//! signatures, similar to IDA Pro's FLIRT and Ghidra's Function ID.
//!
//! ## How it works
//! 1. **Signature database**: precomputed CRC16/CRC32 hashes + lengths of known
//!    function prologues from standard libraries (MSVCRT, OpenSSL, zlib, etc.)
//! 2. **Scanning**: slide over executable sections, compute hash of first N bytes,
//!    compare against signature database
//! 3. **Compiler detection**: identify compiler/linker by characteristic prologue
//!    patterns and section layouts
//!
//! ## Analogue
//! IDA Pro FLIRT signatures; Ghidra Function ID / FID
//!
//! ## Database
//! Beyond the 12 legacy CRC signatures below, the crate ships a curated
//! masked-pattern database in `db/*.fsig` (see [`db`): hundreds of entries
//! across MSVC/CRT (x86 + x64), MinGW/GCC/glibc, zlib, OpenSSL, libcurl,
//! libpng/libjpeg/SQLite, Delphi/VB6/MFC, Go and packer stubs. `??` marks
//! relocation-dependent bytes (call targets, absolute addresses); every
//! entry carries at least 8 bytes / 4 fixed bytes to keep false positives
//! near zero on real code.
//!
//! The machine-harvested `db/generated-*.fsig` (~1.5M Windows-API patterns
//! from `tools/fsig-gen`: entry prefixes plus interior anchors) is
//! deliberately NOT embedded — a ~230 MB blob inside binaries trips
//! antivirus heuristics — and loads at runtime via
//! [`db::load_overlay_dir`] / [`db::auto_load_overlay`]. Applications
//! should call `auto_load_overlay()` once at startup; matching transparently
//! covers both databases afterwards.

pub mod db;
pub mod fdb;

use serde::Serialize;
use std::collections::HashMap;

pub use db::{
    auto_load_overlay, auto_load_overlay_with_tier, db_entries, db_libraries, db_load_errors,
    db_signature_count, find_overlay_dir, load_overlay_dir, load_overlay_file, load_overlay_text,
    overlay_memory_stats, overlay_signature_count, resolve_hit, resolve_metadata,
    scan_db_for_arch, tier_from_env, validation_fills, DbMemoryStats, SigsTier,
};

// ─── Types ────────────────────────────────────────────────────────────

/// A known function signature.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionSignature {
    /// CRC32 of the first `pattern_len` bytes of the function.
    pub crc32: u32,
    /// Number of bytes used for the signature.
    pub pattern_len: usize,
    /// Library name (e.g., "msvcrt", "openssl", "zlib").
    pub library: &'static str,
    /// Function name.
    pub function_name: &'static str,
    /// Minimum total function length (for validation).
    pub min_func_len: usize,
}

/// A matched function found in the binary.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureMatch {
    /// Offset within the scanned region where the match was found.
    pub offset: usize,
    /// The matched signature.
    pub signature: FunctionSignature,
    /// Confidence score [0.0 – 1.0].
    pub confidence: f64,
    pub semantic_role: &'static str,
    pub calling_convention: &'static str,
    pub sources: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
}

impl std::fmt::Display for SignatureMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{} @ 0x{:X} (confidence: {:.0}%)",
            self.signature.library,
            self.signature.function_name,
            self.offset,
            self.confidence * 100.0
        )
    }
}

/// Detected compiler/linker information.
#[derive(Debug, Clone, Serialize)]
pub struct CompilerInfo {
    /// Compiler name (e.g., "MSVC", "GCC", "MinGW", "Borland").
    pub compiler: String,
    /// Optional version string.
    pub version: Option<String>,
    /// Evidence: what patterns triggered this detection.
    pub evidence: Vec<String>,
}

/// Result of signature scanning.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureScanResult {
    /// All matched functions.
    pub matches: Vec<SignatureMatch>,
    /// Detected compiler/linker (if any).
    pub compiler_info: Option<CompilerInfo>,
    /// Libraries identified in the binary.
    pub libraries_found: Vec<String>,
}

impl SignatureScanResult {
    /// Return semantic source/sink tags collected from PE signatures. This is
    /// intentionally separate from `libraries_found`: a library name is not
    /// evidence of behavior, while an explicit signature tag is.
    pub fn semantic_sources(&self) -> Vec<&'static str> {
        self.matches.iter().flat_map(|m| m.sources.iter().copied()).collect()
    }

    pub fn semantic_sinks(&self) -> Vec<&'static str> {
        self.matches.iter().flat_map(|m| m.sinks.iter().copied()).collect()
    }
}

// ─── CRC32 Implementation (no external deps) ────────────────────────

const CRC32_TABLE: [u32; 256] = generate_crc32_table();

const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// Compute CRC32 of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    crc ^ 0xFFFFFFFF
}

// ─── Built-in Signature Database ─────────────────────────────────────

/// Known function signatures from common libraries.
/// In production, this would be loaded from an external .sig file.
/// These are representative samples for demonstration.
const SIGNATURES: &[FunctionSignature] = &[
    // ─── MSVC CRT (x86) ─────────────────────────────────────────────
    FunctionSignature {
        crc32: 0x0A5EECB7, // push ebp; mov ebp,esp; sub esp,0x44; push ebx; push esi; push edi
        pattern_len: 16,
        library: "msvcrt",
        function_name: "mainCRTStartup",
        min_func_len: 64,
    },
    FunctionSignature {
        crc32: 0xF95D6819, // push ebp; mov ebp,esp; push esi; push [ebp+8]; call
        pattern_len: 16,
        library: "msvcrt",
        function_name: "_malloc",
        min_func_len: 32,
    },
    FunctionSignature {
        crc32: 0x88AC7B9E, // push ebp; mov ebp,esp; push esi; mov esi,[ebp+8]; test esi,esi
        pattern_len: 16,
        library: "msvcrt",
        function_name: "_free",
        min_func_len: 32,
    },
    // ─── MSVC CRT (x64) ─────────────────────────────────────────────
    FunctionSignature {
        crc32: 0x705D5233, // sub rsp,0x38; mov rax,[rip]; xor rax,rsp
        pattern_len: 24,
        library: "msvcrt",
        function_name: "mainCRTStartup_x64",
        min_func_len: 48,
    },
    // ─── GCC / MinGW (x86) ───────────────────────────────────────────
    FunctionSignature {
        crc32: 0x127C37BF, // push ebp; mov ebp,esp; sub esp,0x18; mov dword [esp],1; call
        pattern_len: 16,
        library: "mingw",
        function_name: "__mingw_CRTStartup",
        min_func_len: 48,
    },
    // ─── MinGW (x64) ────────────────────────────────────────────────
    FunctionSignature {
        crc32: 0x7B81C2EE, // sub rsp,0x28; mov dword [rsp+0x20],1; call
        pattern_len: 16,
        library: "mingw",
        function_name: "__mingw_CRTStartup_x64",
        min_func_len: 32,
    },
    // ─── OpenSSL (x86) ──────────────────────────────────────────────
    FunctionSignature {
        crc32: 0xAAF13C2E, // push ebp; push edi; push esi; push ebx; sub esp,0x3c
        pattern_len: 24,
        library: "openssl",
        function_name: "SSL_CTX_new",
        min_func_len: 128,
    },
    FunctionSignature {
        crc32: 0xECE64B65, // push ebp; push edi; push esi; push ebx; sub esp,0x1c
        pattern_len: 24,
        library: "openssl",
        function_name: "SSL_connect",
        min_func_len: 96,
    },
    // ─── zlib (x86) ─────────────────────────────────────────────────
    FunctionSignature {
        crc32: 0xA81E6706, // push ebp; mov ebp,esp; sub esp,0x28; mov [ebp-0x0c],ebx
        pattern_len: 16,
        library: "zlib",
        function_name: "inflateInit_",
        min_func_len: 64,
    },
    FunctionSignature {
        crc32: 0x5176AD8C, // push ebp; mov ebp,esp; push edi; push esi; push ebx; sub esp,0x4c
        pattern_len: 24,
        library: "zlib",
        function_name: "deflate",
        min_func_len: 128,
    },
    // ─── libcurl (x86) ──────────────────────────────────────────────
    FunctionSignature {
        crc32: 0x8B8A817A, // push ebp; mov ebp,esp; push ebx; sub esp,0x14; call; call
        pattern_len: 20,
        library: "libcurl",
        function_name: "curl_easy_init",
        min_func_len: 48,
    },
    FunctionSignature {
        crc32: 0x59AF7E88, // push ebp; mov ebp,esp; push edi; push esi; push ebx; sub esp,0x3c
        pattern_len: 20,
        library: "libcurl",
        function_name: "curl_easy_perform",
        min_func_len: 256,
    },
];

// ─── Compiler Detection Patterns ─────────────────────────────────────

struct CompilerPattern {
    compiler: &'static str,
    version: Option<&'static str>,
    /// Byte pattern to search for.
    pattern: &'static [u8],
    description: &'static str,
}

const COMPILER_PATTERNS: &[CompilerPattern] = &[
    // MSVC x86 typical function prologue: push ebp; mov ebp, esp; sub esp, N
    CompilerPattern {
        compiler: "MSVC",
        version: None,
        pattern: &[0x55, 0x8B, 0xEC, 0x83, 0xEC],
        description: "MSVC x86 prologue (push ebp; mov ebp,esp; sub esp,N)",
    },
    // MSVC x64 typical: sub rsp, N (no frame pointer)
    CompilerPattern {
        compiler: "MSVC",
        version: Some("x64"),
        pattern: &[0x48, 0x83, 0xEC],
        description: "MSVC x64 prologue (sub rsp,N)",
    },
    // GCC x86: push ebp; mov ebp, esp; push edi; push esi
    CompilerPattern {
        compiler: "GCC",
        version: None,
        pattern: &[0x55, 0x89, 0xE5, 0x57, 0x56],
        description: "GCC x86 prologue (push ebp; mov ebp,esp; push edi; push esi)",
    },
    // GCC x64: push rbp; mov rbp, rsp
    CompilerPattern {
        compiler: "GCC",
        version: Some("x64"),
        pattern: &[0x55, 0x48, 0x89, 0xE5],
        description: "GCC x64 prologue (push rbp; mov rbp,rsp)",
    },
    // Borland/Embarcadero: push ebp; mov ebp, esp; add esp, -N
    CompilerPattern {
        compiler: "Borland",
        version: None,
        pattern: &[0x55, 0x8B, 0xEC, 0x83, 0xC4],
        description: "Borland prologue (push ebp; mov ebp,esp; add esp,-N)",
    },
    // MinGW: similar to GCC but with __mingw markers
    CompilerPattern {
        compiler: "MinGW",
        version: None,
        pattern: &[0x55, 0x89, 0xE5, 0x83, 0xEC],
        description: "MinGW x86 prologue",
    },
    // Delphi: pushes the SEH frame (push fs:[eax]; mov fs:[eax], esp)
    CompilerPattern {
        compiler: "Delphi",
        version: None,
        pattern: &[0x64, 0xFF, 0x30, 0x64, 0x89, 0x20],
        description: "Delphi SEH frame setup (push fs:[eax]; mov fs:[eax],esp)",
    },
    // Go (amd64, module-aware TLS): stack-guard check against SI
    CompilerPattern {
        compiler: "Go",
        version: None,
        pattern: &[0x48, 0x3B, 0x6E, 0x10],
        description: "Go stack-guard check (cmp rsp,[rsi+0x10])",
    },
    // Go (amd64, 1.18+): stack-guard check against R14
    CompilerPattern {
        compiler: "Go",
        version: Some("1.18+"),
        pattern: &[0x49, 0x3B, 0x66, 0x10],
        description: "Go stack-guard check (cmp rsp,[r14+0x10])",
    },
    // Watcom C: register convention pushes every GPR in order
    CompilerPattern {
        compiler: "Watcom",
        version: None,
        pattern: &[0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55],
        description: "Watcom register prologue (push eax,ebx,ecx,edx,esi,edi,ebp)",
    },
];

// ─── Scanner ──────────────────────────────────────────────────────────

/// Configuration for signature scanning.
#[derive(Debug, Clone)]
pub struct SigScanConfig {
    /// Step size for sliding window (in bytes). Use 1 for exhaustive, 16 for fast.
    pub step: usize,
    /// Maximum number of matches to return.
    pub max_matches: usize,
    /// Enable compiler detection.
    pub detect_compiler: bool,
}

impl Default for SigScanConfig {
    fn default() -> Self {
        Self {
            step: 16,
            max_matches: 1000,
            detect_compiler: true,
        }
    }
}

/// Scan a code region for known function signatures.
pub fn scan_signatures(
    code: &[u8],
    base_offset: usize,
    config: &SigScanConfig,
) -> SignatureScanResult {
    scan_signatures_with_arch(code, base_offset, config, SIGNATURES, None)
}

/// Scan signatures while restricting the masked database to `arch`.
/// Legacy CRC signatures remain available because they predate architecture
/// metadata; callers should use this API when scanning a known PE machine.
pub fn scan_signatures_for_arch(
    code: &[u8],
    base_offset: usize,
    config: &SigScanConfig,
    arch: &str,
) -> SignatureScanResult {
    scan_signatures_with_arch(code, base_offset, config, SIGNATURES, Some(arch))
}

fn scan_signatures_with(
    code: &[u8],
    base_offset: usize,
    config: &SigScanConfig,
    signatures: &[FunctionSignature],
) -> SignatureScanResult {
    scan_signatures_with_arch(code, base_offset, config, signatures, None)
}

fn scan_signatures_with_arch(
    code: &[u8],
    base_offset: usize,
    config: &SigScanConfig,
    signatures: &[FunctionSignature],
    arch: Option<&str>,
) -> SignatureScanResult {
    let mut matches = Vec::new();
    let mut libraries_found: Vec<String> = Vec::new();

    // Clamp step to >= 1 so the sliding loop always makes progress
    let step = config.step.max(1);
    debug_assert!(step >= 1, "SigScanConfig.step must be at least 1");

    // Masked-pattern database phase. Runs over the same sliding offsets so
    // `step` keeps its meaning; hits convert to SignatureMatch with the
    // entry's own confidence.
    if !code.is_empty() {
        // Family database phase first: tiny table, exhaustive scan, and the
        // dedicated engine reports malware-family hits in addition to
        // library-level matches from the main overlay below.
        for hit in db::scan_families_for_arch(
            code,
            base_offset,
            config.max_matches.saturating_sub(matches.len()),
            arch,
        ) {
            let (library, name, pattern_len, min_len, confidence) =
                db::resolve_family_hit(&hit);
            let (semantic_role, calling_convention, sources, sinks) =
                db::resolve_family_metadata(&hit);
            let remaining = code.len() - (hit.offset - base_offset);
            if remaining >= min_len {
                matches.push(SignatureMatch {
                    offset: hit.offset,
                    signature: FunctionSignature {
                        crc32: 0,
                        pattern_len,
                        library,
                        function_name: name,
                        min_func_len: min_len,
                    },
                    confidence,
                    semantic_role,
                    calling_convention,
                    sources,
                    sinks,
                });
                if !libraries_found.contains(&library.to_string()) {
                    libraries_found.push(library.to_string());
                }
            }
            if matches.len() >= config.max_matches {
                break;
            }
        }

        for hit in db::scan_db_for_arch(
            code,
            base_offset,
            step,
            config.max_matches.saturating_sub(matches.len()),
            arch,
        ) {
            let (library, name, pattern_len, min_len, confidence) = db::resolve_hit(&hit);
            let (semantic_role, calling_convention, sources, sinks) = db::resolve_metadata(&hit);
            let remaining = code.len() - (hit.offset - base_offset);
            if remaining >= min_len {
                matches.push(SignatureMatch {
                    offset: hit.offset,
                    signature: FunctionSignature {
                        crc32: 0,
                        pattern_len,
                        library,
                        function_name: name,
                        min_func_len: min_len,
                    },
                    confidence,
                    semantic_role,
                    calling_convention,
                    sources,
                    sinks,
                });
                if !libraries_found.contains(&library.to_string()) {
                    libraries_found.push(library.to_string());
                }
            }
            if matches.len() >= config.max_matches {
                break;
            }
        }
    }

    // Slide over code and compute CRC32 at each position.
    // Bound by code.len() (not the global max pattern length) so shorter
    // signatures are still tested against the trailing bytes.
    let mut offset = 0;
    while offset < code.len() && matches.len() < config.max_matches {
        // Try each signature length
        for sig in signatures {
            if offset + sig.pattern_len > code.len() {
                continue;
            }

            let window = &code[offset..offset + sig.pattern_len];
            let hash = crc32(window);

            if hash == sig.crc32 {
                // Verify minimum function length if possible
                let remaining = code.len() - offset;
                if remaining >= sig.min_func_len {
                    matches.push(SignatureMatch {
                        offset: base_offset + offset,
                        signature: sig.clone(),
                        confidence: 0.85, // Base confidence; could be refined
                        semantic_role: "",
                        calling_convention: "",
                        sources: Vec::new(),
                        sinks: Vec::new(),
                    });

                    if !libraries_found.contains(&sig.library.to_string()) {
                        libraries_found.push(sig.library.to_string());
                    }
                }
            }
        }

        offset += step;
    }

    // Deduplicate matches at same offset. Winner: highest confidence, then
    // longest pattern (more specific bytes beat generic frames), then library
    // and name ascending for determinism (overlapping harvested patterns from
    // several DLLs otherwise resolve by scan order).
    matches.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.signature.pattern_len.cmp(&a.signature.pattern_len))
            .then_with(|| a.signature.library.cmp(b.signature.library))
            .then_with(|| a.signature.function_name.cmp(b.signature.function_name))
    });
    matches.dedup_by_key(|m| m.offset);

    // Compiler detection
    let compiler_info = if config.detect_compiler {
        detect_compiler(code)
    } else {
        None
    };

    SignatureScanResult {
        matches,
        compiler_info,
        libraries_found,
    }
}

/// Detect compiler/linker from code patterns.
fn detect_compiler(code: &[u8]) -> Option<CompilerInfo> {
    let mut evidence = Vec::new();
    let mut compiler_counts: HashMap<&str, usize> = HashMap::new();

    for pattern in COMPILER_PATTERNS {
        if find_pattern(code, pattern.pattern).is_some() {
            *compiler_counts.entry(pattern.compiler).or_insert(0) += 1;
            evidence.push(pattern.description.to_string());
        }
    }

    // Pick compiler with most pattern matches; break ties deterministically
    // by count descending, then name ascending
    let mut candidates: Vec<(&str, usize)> = compiler_counts.into_iter().collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    candidates.first().map(|(compiler, _)| CompilerInfo {
        compiler: compiler.to_string(),
        version: None,
        evidence,
    })
}

/// Find first occurrence of a byte pattern.
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Compute CRC32 of a function's first N bytes (utility for building signature databases).
pub fn compute_function_signature(code: &[u8], pattern_len: usize) -> u32 {
    let len = pattern_len.min(code.len());
    crc32(&code[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_known_value() {
        // CRC32 of empty string is 0x00000000
        assert_eq!(crc32(b""), 0x00000000);

        // CRC32 of "123456789" is 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_crc32_deterministic() {
        let data = b"Hello, World!";
        assert_eq!(crc32(data), crc32(data));
    }

    #[test]
    fn test_find_pattern() {
        let data = vec![0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00];
        assert_eq!(find_pattern(&data, &[0x55, 0x8B, 0xEC]), Some(1));
        assert_eq!(find_pattern(&data, &[0xFF, 0xFF]), None);
    }

    #[test]
    fn test_scan_empty_code() {
        let config = SigScanConfig::default();
        let result = scan_signatures(&[], 0, &config);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_compiler_detection_msvc() {
        // Simulate MSVC x86 prologue
        let code = vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90, 0x90];
        let info = detect_compiler(&code);
        assert!(info.is_some());
        assert_eq!(info.unwrap().compiler, "MSVC");
    }

    #[test]
    fn test_compute_function_signature() {
        let code = vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let sig = compute_function_signature(&code, 16);
        // Just verify it doesn't panic and returns non-zero for non-trivial input
        assert_ne!(sig, 0);
    }

    #[test]
    fn test_tail_window_signature_match() {
        // A short signature (pattern_len = 4) placed in the tail of a buffer
        // whose length excludes the global max pattern length (24) must still match.
        let body = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut code = vec![0x90u8; 14];
        code.extend_from_slice(&body);
        code.extend_from_slice(&[0x90u8; 8]);
        assert_eq!(code.len(), 26); // 26 < 24 + 24: old global-max bound stopped at offset 2

        let short_sig = FunctionSignature {
            crc32: crc32(&body),
            pattern_len: 4,
            library: "test",
            function_name: "tail_func",
            min_func_len: 4,
        };
        let long_dummy = FunctionSignature {
            crc32: 0xFFFF_FFFF,
            pattern_len: 24,
            library: "test",
            function_name: "long_dummy",
            min_func_len: usize::MAX,
        };

        let config = SigScanConfig {
            step: 1,
            max_matches: 100,
            detect_compiler: false,
        };
        let result = scan_signatures_with(&code, 0x1000, &config, &[short_sig, long_dummy]);

        assert_eq!(result.matches.len(), 1, "tail-window match was missed");
        assert_eq!(result.matches[0].offset, 0x1000 + 14);
        assert_eq!(result.matches[0].signature.function_name, "tail_func");
    }

    #[test]
    fn test_step_zero_is_clamped() {
        // step == 0 previously made the slide loop spin forever when no match
        // ever fired; it must be clamped so the scan terminates.
        let code = vec![0x90u8; 64];
        let config = SigScanConfig {
            step: 0,
            max_matches: 100,
            detect_compiler: false,
        };
        let result = scan_signatures(&code, 0, &config);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_detect_compiler_tie_determinism() {
        // One MSVC x86 prologue and one GCC x86 prologue: equal votes (1 vs 1).
        // Winner must be resolved deterministically by name (GCC < MSVC).
        let mut code = vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        code.extend_from_slice(&[0x55, 0x89, 0xE5, 0x57, 0x56]);

        let first = detect_compiler(&code).expect("compiler should be detected");
        assert_eq!(first.compiler, "GCC", "tie must resolve by name ascending");
        assert_eq!(first.evidence.len(), 2);

        for _ in 0..16 {
            assert_eq!(detect_compiler(&code).unwrap().compiler, "GCC");
        }
    }

    #[test]
    fn test_library_deduplication() {
        let config = SigScanConfig {
            step: 1,
            max_matches: 100,
            detect_compiler: false,
        };
        // Even if multiple signatures from same library match,
        // libraries_found should not contain duplicates
        let result = scan_signatures(&[0u8; 256], 0, &config);
        let libs = &result.libraries_found;
        let unique: std::collections::HashSet<_> = libs.iter().collect();
        assert_eq!(libs.len(), unique.len());
    }
}
