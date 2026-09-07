//! Shellcode detection engine.
//!
//! Design goals:
//! - High precision: a single weak heuristic (a high-entropy region, an INT3
//!   padding block, a lone PEB/GetPC pattern) is NOT enough to flag a binary
//!   as shellcode. Those occur constantly in legitimate compiled code (MSVC
//!   padding, normal .text/.rsrc entropy, gs:[0x60] PEB access for module
//!   enumeration, etc.).
//! - Strong, specific signals (resolved API hashes, XOR decoder loops, egg
//!   hunters, XOR-encoded blobs, FPU GetPC, long NOP sleds, alphanumeric
//!   encoders) are emitted as findings.
//! - Correlation: weak signals only matter when they co-occur, e.g. PEB/GetPC
//!   (position-independent code) inside a genuinely random (entropy >= 7.0)
//!   region.

use crate::api_hashes;
use crate::report::{ShellcodeFinding, ShellcodeReport, ShellcodeVerdict};

/// Configuration for shellcode detection sensitivity.
#[derive(Debug, Clone)]
pub struct ShellcodeConfig {
    pub min_blob_size: usize,
    pub max_blob_size: usize,
    pub window_size: usize,
    pub window_step: usize,
    pub min_entropy: f64,
    pub min_api_hashes: usize,
    /// File-offset ranges (start, end) that belong to non-code sections
    /// (e.g. `.rsrc`, `.data`, `.reloc`). High entropy there is normal
    /// (icons, compressed resources, constants) and must NOT be treated as
    /// packing/shellcode.
    pub ignore_ranges: Vec<(usize, usize)>,
}

impl Default for ShellcodeConfig {
    fn default() -> Self {
        Self {
            min_blob_size: 32,
            max_blob_size: 0x100000,
            window_size: 256,
            window_step: 64,
            min_entropy: 5.5,
            min_api_hashes: 2,
            ignore_ranges: Vec::new(),
        }
    }
}

/// True if `off` lies within any of the configured ignore ranges.
fn in_ignore(ranges: &[(usize, usize)], off: usize) -> bool {
    ranges.iter().any(|(s, e)| off >= *s && off < *e)
}

/// Accumulates weak (non-conclusive) indicators during a scan. These only
/// matter when several correlate, so they never produce lone noisy findings.
#[derive(Default)]
struct WeakSignals {
    has_getpc: bool,
    has_peb: bool,
    has_int3_run: bool,
    max_entropy: f64,
    high_entropy_bytes: usize,
}

/// Detect shellcode in raw binary data.
pub fn detect_shellcode(data: &[u8], config: &ShellcodeConfig) -> ShellcodeReport {
    let mut findings: Vec<ShellcodeFinding> = Vec::new();
    let mut weak = WeakSignals::default();

    // Phase 1: Resolved API hashes (strongest signal; almost never in legit code).
    let api_hash_results = api_hashes::scan_for_api_hashes(data);
    let min_api_hashes = config.min_api_hashes.max(1);
    if api_hash_results.len() >= min_api_hashes {
        let apis: Vec<String> = api_hash_results
            .iter()
            .map(|(off, resolved)| {
                format!(
                    "{}!{} @ 0x{:X}",
                    resolved.dll_name, resolved.function_name, off
                )
            })
            .collect();

        findings.push(ShellcodeFinding::new(
            "SHELLCODE_API_HASHES",
            format!(
                "Found {} resolved Windows API hashes (shellcode indicator)",
                api_hash_results.len()
            ),
            apis,
            api_hash_results[0].0,
            0.9,
        ));
    }

    check_shellcode_patterns(data, &mut findings, &mut weak, config);
    check_entropy_regions(data, config, &mut findings, &mut weak);
    check_int3_padding(data, &mut weak);
    check_encoder_stubs(data, &mut findings, &mut weak);
    check_egg_hunters(data, &mut findings, &mut weak);
    check_encoded_blobs(data, &mut findings, &mut weak, config);
    correlate_weak(&mut findings, &weak);

    let verdict = if findings.is_empty() {
        ShellcodeVerdict::NoShellcode
    } else {
        let max_confidence = findings
            .iter()
            .map(|f| f.confidence)
            .fold(0.0_f64, f64::max);
        if max_confidence >= 0.7 {
            ShellcodeVerdict::ShellcodeLikely
        } else {
            ShellcodeVerdict::Suspicious
        }
    };

    ShellcodeReport {
        findings,
        verdict,
        total_api_hashes_found: api_hash_results.len(),
    }
}

// ─── Pattern Detection ───────────────────────────────────────────────

fn check_shellcode_patterns(
    data: &[u8],
    findings: &mut Vec<ShellcodeFinding>,
    weak: &mut WeakSignals,
    config: &ShellcodeConfig,
) {
    let getpc_patterns: &[(&[u8], &str)] = &[
        (
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],
            "call $+5 / pop eax (GetPC)",
        ),
        (
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B],
            "call $+5 / pop ebx (GetPC)",
        ),
        (
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x59],
            "call $+5 / pop ecx (GetPC)",
        ),
        (
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A],
            "call $+5 / pop edx (GetPC)",
        ),
        (
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E],
            "call $+5 / pop esi (GetPC)",
        ),
        (
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F],
            "call $+5 / pop edi (GetPC)",
        ),
        (&[0xD9, 0xE0], "fnstenv (FPU GetPC)"),
        (&[0xEB, 0x00], "jmp $+2 (short jump NOP sled)"),
    ];
    for (pattern, _desc) in getpc_patterns {
        if let Some(off) = find_pattern(data, pattern) {
            if !in_ignore(&config.ignore_ranges, off) {
                weak.has_getpc = true;
            }
        }
    }

    let peb_patterns: &[(&[u8], &str)] = &[
        (
            &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            "mov eax, fs:[0x30] (PEB access x86)",
        ),
        (
            &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            "mov rax, gs:[0x60] (PEB access x64)",
        ),
        (&[0x6A, 0x60, 0x5A], "push 0x60 / pop edx (PEB offset)"),
        (&[0x64, 0x8B, 0x35], "mov esi, fs:[...] (TEB/PEB access)"),
        (
            &[0x33, 0xC0, 0x64, 0x8B],
            "xor eax,eax / mov eax,fs:[...] (x86 PEB)",
        ),
    ];
    for (pattern, _desc) in peb_patterns {
        if let Some(off) = find_pattern(data, pattern) {
            if !in_ignore(&config.ignore_ranges, off) {
                weak.has_peb = true;
            }
        }
    }

    let hash_resolution: &[(&[u8], &str)] = &[
        (
            &[0x60, 0x8B, 0x45, 0x3C],
            "pushad / mov eax, [ebp+0x3C] (PE header parsing)",
        ),
        (
            &[0x60, 0x8B, 0x75, 0x7C],
            "pushad / mov esi, [ebp+0x7C] (export table access)",
        ),
    ];
    for (pattern, _desc) in hash_resolution {
        if let Some(off) = find_pattern(data, pattern) {
            if !in_ignore(&config.ignore_ranges, off) {
                weak.has_getpc = true;
            }
        }
    }

    check_nop_sled(data, findings);
}

fn check_nop_sled(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    let min_sled_len = 32;
    let mut i = 0;

    while i < data.len() {
        if data[i] == 0x90 {
            let start = i;
            while i < data.len() && data[i] == 0x90 {
                i += 1;
            }
            let len = i - start;
            if len >= min_sled_len {
                findings.push(ShellcodeFinding::new(
                    "SHELLCODE_NOP_SLED",
                    format!("NOP sled detected ({} bytes)", len),
                    vec![format!("offset 0x{:X}, length {}", start, len)],
                    start,
                    0.5,
                ));
            }
        } else {
            i += 1;
        }
    }

    let nop_equivalents: &[[u8; 2]] = &[
        [0x89, 0xC0],
        [0x89, 0xDB],
        [0x89, 0xC9],
        [0x89, 0xD2],
        [0x89, 0xF6],
        [0x89, 0xFF],
    ];

    for equiv in nop_equivalents {
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] == equiv[0] && data[i + 1] == equiv[1] {
                let start = i;
                let mut count = 0;
                while i + 1 < data.len() && data[i] == equiv[0] && data[i + 1] == equiv[1] {
                    i += 2;
                    count += 1;
                }
                if count >= 8 {
                    findings.push(ShellcodeFinding::new(
                        "SHELLCODE_NOP_SLED",
                        format!(
                            "Multi-byte NOP sled detected ({} repetitions of 0x{:02X}{:02X})",
                            count, equiv[0], equiv[1]
                        ),
                        vec![format!("offset 0x{:X}, {} bytes", start, count * 2)],
                        start,
                        0.45,
                    ));
                }
            } else {
                i += 1;
            }
        }
    }
}

/// Records INT3 padding runs (a normal MSVC artifact) as a weak signal only.
fn check_int3_padding(data: &[u8], weak: &mut WeakSignals) {
    let mut cc_count = 0;
    for &byte in data {
        if byte == 0xCC {
            cc_count += 1;
        } else {
            if cc_count >= 8 {
                weak.has_int3_run = true;
            }
            cc_count = 0;
        }
    }
    if cc_count >= 8 {
        weak.has_int3_run = true;
    }
}

// ─── Encoder/Decoder Stub Detection ───────────────────────────────────

fn check_encoder_stubs(data: &[u8], findings: &mut Vec<ShellcodeFinding>, _weak: &mut WeakSignals) {
    if data.len() < 20 {
        return;
    }

    // XOR-based decoder loops.
    for i in 0..data.len().saturating_sub(8) {
        if data[i] == 0x80 {
            let modrm = data[i + 1];
            let mod_field = (modrm >> 6) & 0x03;
            let reg_field = (modrm >> 3) & 0x07;
            let rm_field = modrm & 0x07;

            if mod_field == 0 && reg_field == 6 {
                // Locate the imm8 operand. For mod=00 the ModR/M byte is
                // followed by: disp32 when rm=101, or a SIB byte when rm=100
                // (whose base=101 adds another disp32) before the imm8.
                let mut op = i + 2;
                if rm_field == 5 {
                    op += 4;
                } else if rm_field == 4 && op < data.len() {
                    let sib_base = data[op] & 0x07;
                    op += 1;
                    if sib_base == 5 {
                        op += 4;
                    }
                }

                if op < data.len() {
                    let xor_key = data[op];
                    if xor_key != 0 && xor_key != 0xFF {
                        // A lone `xor [reg], imm8` is extremely common in normal
                        // code (buffer zeroing, obfuscation). A real XOR *decoder*
                        // is a tight loop: the pointer register is advanced (inc /
                        // add / lods) and control loops back. Require that loop
                        // structure so we don't flag coincidental byte patterns.
                        let has_loop = (i > 0 && is_short_jump_back(data[i - 1]))
                            || is_xor_decoder_loop(data, op + 1, modrm & 0x07);

                        if has_loop {
                            let reg_idx = modrm & 0x07;
                            let reg_name = match reg_idx {
                                0 => "eax",
                                1 => "ecx",
                                2 => "edx",
                                3 => "ebx",
                                4 => "esp",
                                5 => "ebp",
                                6 => "esi",
                                7 => "edi",
                                _ => "?",
                            };
                            findings.push(ShellcodeFinding::new(
                                "SHELLCODE_XOR_DECODER",
                                format!(
                                    "XOR decoder stub: xor [{}], 0x{:02X} (encoder detected)",
                                    reg_name, xor_key
                                ),
                                vec![
                                    format!("decoder at offset 0x{:X}", i),
                                    format!("XOR key: 0x{:02X}", xor_key),
                                ],
                                i,
                                0.75,
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    check_alphanumeric_shellcode(data, findings);

    let fpu_getpc: &[(&[u8], &str)] = &[
        (
            &[0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4],
            "fldz / fnstenv [esp-0xC] (FPU GetPC)",
        ),
        (
            &[0xD9, 0xE1, 0xD9, 0x74, 0x24, 0xF4],
            "fldpi / fnstenv [esp-0xC] (FPU GetPC)",
        ),
        (
            &[0xD9, 0xE0, 0xD9, 0x74, 0x24, 0xF4],
            "fchs / fnstenv [esp-0xC] (FPU GetPC)",
        ),
        (
            &[0xD9, 0xE8, 0xD9, 0x74, 0x24, 0xF4],
            "fucomip / fnstenv [esp-0xC] (FPU GetPC)",
        ),
    ];

    for (pattern, _desc) in fpu_getpc {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding::new(
                "SHELLCODE_FPU_GETPC",
                format!("FPU GetPC technique: {}", _desc),
                vec![format!("offset 0x{:X}", offset)],
                offset,
                0.85,
            ));
        }
    }

    for i in 0..data.len().saturating_sub(7) {
        if data[i] == 0xE8 {
            let offset_bytes =
                i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let target_rel = offset_bytes;
            if (0..16).contains(&target_rel) {
                let pop_offset = (5 + target_rel) as usize;
                if i + pop_offset < data.len() {
                    let next_byte = data[i + pop_offset];
                    if (0x58..=0x5F).contains(&next_byte)
                        && next_byte != 0x5C
                        && next_byte != 0x5D
                        && target_rel != 0
                    {
                        let reg = match next_byte {
                            0x58 => "eax",
                            0x59 => "ecx",
                            0x5A => "edx",
                            0x5B => "ebx",
                            0x5E => "esi",
                            0x5F => "edi",
                            _ => "?",
                        };
                        findings.push(ShellcodeFinding::new(
                            "SHELLCODE_GETPC",
                            format!(
                                "call $+{} / pop {} (non-standard GetPC)",
                                target_rel + 5,
                                reg
                            ),
                            vec![format!("offset 0x{:X}", i)],
                            i,
                            0.7,
                        ));
                    }
                }
            }
        }
    }
}

fn is_short_jump_back(byte: u8) -> bool {
    byte == 0x75 || byte == 0x74 || byte == 0xEB || byte == 0x7C || byte == 0x7E
}

/// Returns true when the bytes following a `xor r/m8, imm8` instruction form a
/// real decode loop: the pointer register is advanced (inc / add / lods / stos)
/// and control branches backward (short/conditional jump or LOOP). `search_start`
/// is the offset just past the whole instruction (opcode + ModR/M + any
/// disp32/SIB + imm8).
fn is_xor_decoder_loop(data: &[u8], search_start: usize, reg: u8) -> bool {
    let end = (search_start + 16).min(data.len());
    let mut advanced = false;
    let mut back_jump = false;
    let mut j = search_start;
    while j < end {
        let b = data[j];
        // inc reg32
        if b == 0x40 | reg
            // add reg32, imm8 / imm32  (0x83/0x81, /0)
            || ((b == 0x83 || b == 0x81)
                && j + 1 < data.len()
                && (data[j + 1] & 0x38) == (reg << 3))
            // lods (advances esi) / stos (advances edi)
            || (reg == 6 && (b == 0xAC || b == 0xAD))
            || (reg == 7 && (b == 0xAA || b == 0xAB))
        {
            advanced = true;
        }
        // backward short/conditional jump or LOOP
        if (0x70..=0x7F).contains(&b) || b == 0xEB {
            if j + 1 < data.len() && (data[j + 1] as i8) < 0 {
                back_jump = true;
            }
        } else if (0xE0..=0xE3).contains(&b) {
            back_jump = true;
        }
        if advanced && back_jump {
            return true;
        }
        j += 1;
    }
    false
}

/// Detect alphanumeric (alpha-mixed) encoded shellcode.
/// A 64+ byte run of purely alphanumeric bytes is very suspicious (legitimate
/// strings almost always contain non-alphanumeric characters such as : / . = +).
fn check_alphanumeric_shellcode(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    let min_run = 64;
    let mut run_start: Option<usize> = None;
    let mut run_len = 0;

    for (i, &byte) in data.iter().enumerate() {
        let is_alnum = byte.is_ascii_alphanumeric();
        if is_alnum {
            if run_start.is_none() {
                run_start = Some(i);
            }
            run_len += 1;
        } else {
            if run_len >= min_run {
                if let Some(start) = run_start {
                    findings.push(ShellcodeFinding::new(
                        "SHELLCODE_ALPHANUMERIC",
                        format!("Alphanumeric-encoded shellcode region ({} bytes)", run_len),
                        vec![format!("offset 0x{:X}, length {}", start, run_len)],
                        start,
                        0.6,
                    ));
                }
            }
            run_start = None;
            run_len = 0;
        }
    }

    if run_len >= min_run {
        if let Some(start) = run_start {
            findings.push(ShellcodeFinding::new(
                "SHELLCODE_ALPHANUMERIC",
                format!("Alphanumeric-encoded shellcode region ({} bytes)", run_len),
                vec![format!("offset 0x{:X}, length {}", start, run_len)],
                start,
                0.6,
            ));
        }
    }
}

// ─── Egg Hunter Detection ─────────────────────────────────────────────

fn check_egg_hunters(data: &[u8], findings: &mut Vec<ShellcodeFinding>, _weak: &mut WeakSignals) {
    let egg_patterns: &[(&[u8], &str)] = &[
        (
            &[0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52],
            "or dx, 0x0FFF / inc edx / push edx (egg hunter page alignment)",
        ),
        (
            &[0x6A, 0x02, 0x58, 0xCD, 0x2E, 0x3C, 0x05],
            "push 2 / pop eax / int 0x2E / cmp al, 5 (egg hunter syscall)",
        ),
        (
            &[0x6A, 0x43, 0x58, 0xCD, 0x2E],
            "push 0x43 / pop eax / int 0x2E (NtDisplayString egg hunter)",
        ),
    ];

    for (pattern, _desc) in egg_patterns {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding::new(
                "SHELLCODE_EGG_HUNTER",
                format!("Egg hunter pattern: {}", _desc),
                vec![format!("offset 0x{:X}", offset)],
                offset,
                0.85,
            ));
        }
    }

    for i in 0..data.len().saturating_sub(8) {
        if data[i] == 0x81 {
            let modrm = data[i + 1];
            let mod_field = (modrm >> 6) & 0x03;
            let reg_field = (modrm >> 3) & 0x07;
            if mod_field == 0 && reg_field == 7 && i + 6 < data.len() {
                let egg = u32::from_le_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]]);
                let low_word = (egg & 0xFFFF) as u16;
                let high_word = ((egg >> 16) & 0xFFFF) as u16;
                if low_word == high_word
                    && low_word != 0
                    && low_word != 0xFFFF
                    && i + 6 < data.len()
                {
                    let next = data[i + 6];
                    if next == 0x75 || next == 0x74 || next == 0xEB {
                        findings.push(ShellcodeFinding::new(
                            "SHELLCODE_EGG_HUNTER",
                            format!("Egg hunter: cmp [reg], 0x{:08X} (egg tag search)", egg),
                            vec![
                                format!("offset 0x{:X}", i),
                                format!("egg tag: 0x{:08X}", egg),
                            ],
                            i,
                            0.7,
                        ));
                        break;
                    }
                }
            }
        }
    }
}

// ─── Encoded Blob Detection ───────────────────────────────────────────

fn check_encoded_blobs(
    data: &[u8],
    findings: &mut Vec<ShellcodeFinding>,
    _weak: &mut WeakSignals,
    config: &ShellcodeConfig,
) {
    if data.len() < 64 {
        return;
    }

    let max_scan_size: usize = config.max_blob_size;
    let scan_data = if data.len() > max_scan_size {
        &data[..max_scan_size]
    } else {
        data
    };

    let window = 128;
    let step = 64;
    let mut offset = 0;

    // A single-byte XOR is a permutation of the byte alphabet, so it preserves
    // Shannon entropy exactly — an "encoded high entropy dropping after decode"
    // check can never fire. Instead we brute-force every key and look for a
    // *decoded* region that contains a strong shellcode indicator: the classic
    // PEB/`fs` access preamble, an FPU/relative GetPC, or a cluster of resolved
    // API-hash DWORDs. Such a pattern appearing after a single-byte XOR is the
    // real signature of XOR-staged shellcode.
    let mut buf = vec![0u8; window];

    // Budget: brute-forcing 255 keys per window is expensive; cap the number
    // of windows that undergo the full decode sweep so multi-MB inputs stay
    // bounded (64 windows * 255 keys * 128 bytes ≈ 2M byte ops max).
    let max_bruteforce_windows = 64usize;
    let mut bruteforced_windows = 0usize;

    while offset + window <= scan_data.len() {
        if in_ignore(&config.ignore_ranges, offset) {
            offset += step;
            continue;
        }
        if bruteforced_windows >= max_bruteforce_windows {
            break;
        }
        bruteforced_windows += 1;

        let region = &scan_data[offset..offset + window];

        let mut found_key: Option<u8> = None;
        let mut decoded_hits: Vec<String> = Vec::new();

        for key in 0x01u8..=0xFFu8 {
            for (i, b) in region.iter().enumerate() {
                buf[i] = b ^ key;
            }

            let has_peb = buf
                .windows(6)
                .any(|w| w == [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]);
            let has_gs = buf.windows(4).any(|w| w == [0x65, 0x33, 0x00, 0x00]);
            let has_fpu_getpc = buf
                .windows(6)
                .any(|w| w == [0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4]);
            let has_getpc = buf.windows(5).any(|w| {
                w[0] == 0xE8 && w[1] == 0x00 && w[2] == 0x00 && w[3] == 0x00 && w[4] == 0x00
            });
            // The full API-hash DB scan is expensive; only run it when a cheap
            // preamble already matched, otherwise a 255-key brute force over a
            // large binary would scan the entire DB on every window/key.
            let api_hashes_found = if has_peb || has_gs || has_fpu_getpc || has_getpc {
                api_hashes::scan_for_api_hashes(&buf).len()
            } else {
                0
            };

            let mut reasons = Vec::new();
            if has_peb {
                reasons.push("PEB/fs access preamble".to_string());
            }
            if has_gs {
                reasons.push("gs segment access".to_string());
            }
            if has_fpu_getpc {
                reasons.push("FPU GetPC".to_string());
            }
            if has_getpc {
                reasons.push("E8 call GetPC".to_string());
            }
            if api_hashes_found >= 2 {
                reasons.push(format!("{} resolved API hashes", api_hashes_found));
            }

            if !reasons.is_empty() {
                found_key = Some(key);
                decoded_hits = reasons;
                break;
            }
        }

        if let Some(key) = found_key {
            findings.push(ShellcodeFinding::new(
                "SHELLCODE_XOR_ENCODED",
                format!("XOR-encoded shellcode detected (key=0x{:02X})", key),
                {
                    let mut v = vec![
                        format!("encoded region at offset 0x{:X}", offset),
                        format!("XOR key: 0x{:02X}", key),
                    ];
                    v.extend(decoded_hits.iter().cloned());
                    v
                },
                offset,
                0.9,
            ));
            offset += window;
            continue;
        }

        offset += step;
    }
}

// ─── Entropy Region Detection ────────────────────────────────────────

/// Records entropy statistics in `weak`. A single low-severity finding is
/// emitted only for genuinely random regions (entropy >= 7.0), i.e. packing or
/// encryption, which never occurs in normal compiled code or resources.
fn check_entropy_regions(
    data: &[u8],
    config: &ShellcodeConfig,
    findings: &mut Vec<ShellcodeFinding>,
    weak: &mut WeakSignals,
) {
    if data.len() < config.window_size {
        return;
    }

    let mut current_run_start: Option<usize> = None;
    let mut current_run_len = 0usize;
    let mut last_run_start = 0usize;
    let mut offset = 0;

    while offset + config.window_size <= data.len() {
        // Skip windows that fall inside non-code sections (resources, data).
        if in_ignore(&config.ignore_ranges, offset) {
            if let Some(_start) = current_run_start {
                if current_run_len >= config.min_blob_size {
                    weak.high_entropy_bytes += current_run_len;
                }
            }
            current_run_start = None;
            current_run_len = 0;
            offset += config.window_step;
            continue;
        }

        let window = &data[offset..offset + config.window_size];
        let entropy_result = entropy_rs::calculate_entropy(window);

        if entropy_result.entropy >= config.min_entropy {
            weak.max_entropy = weak.max_entropy.max(entropy_result.entropy);
            if current_run_start.is_none() {
                current_run_start = Some(offset);
                last_run_start = offset;
            }
            current_run_len += config.window_step;
        } else {
            if let Some(_start) = current_run_start {
                if current_run_len >= config.min_blob_size {
                    weak.high_entropy_bytes += current_run_len;
                }
            }
            current_run_start = None;
            current_run_len = 0;
        }

        offset += config.window_step;
    }

    if let Some(_start) = current_run_start {
        if current_run_len >= config.min_blob_size {
            weak.high_entropy_bytes += current_run_len;
        }
    }

    if weak.max_entropy >= 7.0 && weak.high_entropy_bytes >= 512 {
        findings.push(ShellcodeFinding::new(
            "SHELLCODE_HIGH_ENTROPY",
            format!(
                "High-entropy region (max entropy {:.2}, ~{} bytes) consistent with packing/encryption",
                weak.max_entropy, weak.high_entropy_bytes
            ),
            vec![format!("offset=0x{:X} size={}", last_run_start, weak.high_entropy_bytes)],
            last_run_start,
            0.4,
        ));
    }
}

// ─── Weak-signal correlation ──────────────────────────────────────────

/// Emits at most ONE finding when weak indicators correlate into something that
/// looks like position-independent shellcode: PEB/GetPC access inside a
/// genuinely random (entropy >= 7.0) region.
fn correlate_weak(findings: &mut Vec<ShellcodeFinding>, weak: &WeakSignals) {
    if weak.max_entropy >= 7.0 && (weak.has_getpc || weak.has_peb) {
        let mut indicators = Vec::new();
        if weak.has_getpc {
            indicators.push("GetPC pattern");
        }
        if weak.has_peb {
            indicators.push("PEB access");
        }
        if weak.has_int3_run {
            indicators.push("INT3 padding");
        }
        findings.push(ShellcodeFinding::new(
            "SHELLCODE_PIC_HIGH_ENTROPY",
            format!(
                "Position-independent code ({}) inside high-entropy region (entropy {:.2}) - possible shellcode bootstrap",
                indicators.join(", "),
                weak.max_entropy
            ),
            vec![format!("max entropy: {:.2}", weak.max_entropy)],
            0,
            0.55,
        ));
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peb_access_not_false_positive() {
        let mut data = vec![0u8; 128];
        data[32] = 0x64;
        data[33] = 0xA1;
        data[34] = 0x30;
        data[35] = 0x00;
        data[36] = 0x00;
        data[37] = 0x00;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.description.contains("PEB")),
            "Lone PEB access should not be flagged: {:?}",
            report.findings
        );
    }

    #[test]
    fn test_pic_high_entropy_correlation() {
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(31).wrapping_add(7)) as u8;
        }
        let off = 1024;
        data[off..off + 9].copy_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "SHELLCODE_PIC_HIGH_ENTROPY"),
            "Expected PIC+high-entropy correlation. Findings: {:?}",
            report
                .findings
                .iter()
                .map(|f| &f.rule_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_clean_data_no_findings() {
        let data = vec![0u8; 256];
        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert_eq!(report.verdict, ShellcodeVerdict::NoShellcode);
    }

    #[test]
    fn test_nop_sled_detection() {
        let mut data = vec![0xFFu8; 128];
        data[40..72].fill(0x90);

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(report
            .findings
            .iter()
            .any(|f| f.description.contains("NOP sled")));
    }

    #[test]
    fn test_api_hash_detection() {
        // Place two genuine ROR13 API-hash DWORDs (computed from the live DB).
        let h1 = api_hashes::compute_ror13("CreateThread");
        let h2 = api_hashes::compute_ror13("VirtualAlloc");

        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&h1.to_le_bytes());
        data[4..8].copy_from_slice(&h2.to_le_bytes());

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            report.total_api_hashes_found >= 2,
            "expected >=2 api hashes, got {}",
            report.total_api_hashes_found
        );
        assert!(report
            .findings
            .iter()
            .any(|f| f.description.contains("API hash")));
    }

    #[test]
    fn test_encoder_stub_detection() {
        let mut data = vec![0x90u8; 128];
        data[50] = 0x80;
        data[51] = 0x33;
        data[52] = 0x41;
        data[53] = 0x43;
        data[54] = 0xEB;
        data[55] = 0xF9;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.description.contains("XOR decoder")),
            "Should detect XOR decoder stub. Findings: {:?}",
            report
                .findings
                .iter()
                .map(|f| &f.description)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_xor_decoder_modrm_disp32() {
        // xor dword ptr [0xDEADBEEF], 0x37 → 80 /6, mod=00 rm=101 (disp32).
        let mut data = vec![0x90u8; 64];
        data[10..17].copy_from_slice(&[0x80, 0x35, 0xEF, 0xBE, 0xAD, 0xDE, 0x37]);
        data[17] = 0x45; // inc ebp
        data[18] = 0xEB; // jmp short back
        data[19] = 0xF9;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        let f = report
            .findings
            .iter()
            .find(|f| f.description.contains("XOR decoder"))
            .expect("disp32 xor decoder must be detected");
        assert!(
            f.evidence.iter().any(|e| e.contains("0x37")),
            "imm8 must be read past the disp32, evidence: {:?}",
            f.evidence
        );
    }

    #[test]
    fn test_xor_decoder_modrm_sib() {
        // xor dword ptr [ds:0xDEADBEEF], 0x37 → 80 /6, mod=00 rm=100 with
        // SIB base=101 (disp32 follows the SIB byte).
        let mut data = vec![0x90u8; 64];
        data[19] = 0xEB; // jmp short back (loop structure before the stub)
        data[20..28].copy_from_slice(&[0x80, 0x34, 0x25, 0xEF, 0xBE, 0xAD, 0xDE, 0x37]);

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        let f = report
            .findings
            .iter()
            .find(|f| f.description.contains("XOR decoder"))
            .expect("SIB xor decoder must be detected");
        assert!(
            f.evidence.iter().any(|e| e.contains("0x37")),
            "imm8 must be read past SIB+disp32, evidence: {:?}",
            f.evidence
        );
    }

    #[test]
    fn test_fpu_getpc_detection() {
        let mut data = vec![0u8; 128];
        data[20] = 0xD9;
        data[21] = 0xEE;
        data[22] = 0xD9;
        data[23] = 0x74;
        data[24] = 0x24;
        data[25] = 0xF4;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.description.contains("FPU GetPC")),
            "Should detect FPU GetPC"
        );
    }

    #[test]
    fn test_alphanumeric_shellcode() {
        let mut data = vec![0u8; 128];
        let alnum = b"ABCDEFGHabcdefgh12345678ABCDEFGHabcdefghABCDEFGHabcdefgh12345678";
        data[10..10 + alnum.len()].copy_from_slice(alnum);

        let mut findings = Vec::new();
        check_alphanumeric_shellcode(&data, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("Alphanumeric")),
            "Should detect alphanumeric run"
        );
    }

    #[test]
    fn test_xor_encoded_blob() {
        let shellcode: Vec<u8> = vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C];
        let key = 0x42u8;
        let encoded: Vec<u8> = shellcode.iter().map(|b| b ^ key).collect();

        let mut data = vec![0u8; 256];
        data[50..50 + encoded.len()].copy_from_slice(&encoded);

        let mut findings = Vec::new();
        let mut weak = WeakSignals::default();
        check_encoded_blobs(&data, &mut findings, &mut weak, &ShellcodeConfig::default());
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("XOR-encoded")),
            "Should detect XOR-encoded shellcode. Findings: {:?}",
            findings.iter().map(|f| &f.description).collect::<Vec<_>>()
        );
    }
}
