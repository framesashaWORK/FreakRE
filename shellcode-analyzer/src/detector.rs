//! Shellcode detection engine.
//! Identifies raw shellcode blobs within binary data using multiple heuristics:
//! - Instruction pattern matching (x86/x64)
//! - Entropy analysis
//! - API hash presence
//! - Characteristic byte sequences
//! - Encoder/decoder stub detection (XOR loops, alpha-mixed encoders)
//! - Egg hunter patterns
//! - Anti-analysis tricks in shellcode context

use crate::api_hashes;
use crate::report::{ShellcodeFinding, ShellcodeReport, ShellcodeVerdict};

/// Configuration for shellcode detection sensitivity.
#[derive(Debug, Clone)]
pub struct ShellcodeConfig {
    /// Minimum blob size to consider as potential shellcode.
    pub min_blob_size: usize,
    /// Maximum blob size to scan (prevents scanning entire large files).
    pub max_blob_size: usize,
    /// Sliding window size for entropy-based detection.
    pub window_size: usize,
    /// Step size for sliding window.
    pub window_step: usize,
    /// Minimum entropy threshold for shellcode candidate regions.
    pub min_entropy: f64,
    /// Minimum number of resolved API hashes to trigger detection.
    pub min_api_hashes: usize,
}

impl Default for ShellcodeConfig {
    fn default() -> Self {
        Self {
            min_blob_size: 32,
            max_blob_size: 0x100000, // 1 MB
            window_size: 256,
            window_step: 64,
            min_entropy: 5.5,
            min_api_hashes: 2,
        }
    }
}

/// Detect shellcode in raw binary data.
pub fn detect_shellcode(data: &[u8], config: &ShellcodeConfig) -> ShellcodeReport {
    let mut findings: Vec<ShellcodeFinding> = Vec::new();

    // Phase 1: Scan for API hashes (strongest signal)
    let api_hash_results = api_hashes::scan_for_api_hashes(data);
    if api_hash_results.len() >= config.min_api_hashes {
        let apis: Vec<String> = api_hash_results
            .iter()
            .map(|(off, resolved)| format!("{}!{} @ 0x{:X}", resolved.dll_name, resolved.function_name, off))
            .collect();

        findings.push(ShellcodeFinding {
            description: format!(
                "Found {} resolved Windows API hashes (shellcode indicator)",
                api_hash_results.len()
            ),
            evidence: apis,
            offset: api_hash_results[0].0,
            confidence: 0.9,
        });
    }

    // Phase 2: Check for characteristic shellcode patterns
    check_shellcode_patterns(data, &mut findings);

    // Phase 3: Entropy-based region detection
    check_entropy_regions(data, config, &mut findings);

    // Phase 4: Check for common shellcode prologues/epilogues
    check_prologue_epilogue(data, &mut findings);

    // Phase 5: Encoder/decoder stub detection (NEW — handles obfuscated shellcode)
    check_encoder_stubs(data, &mut findings);

    // Phase 6: Egg hunter patterns (NEW — multi-stage shellcode indicator)
    check_egg_hunters(data, &mut findings);

    // Phase 7: XOR-encoded blob detection (NEW — detects encoded shellcode bodies)
    check_encoded_blobs(data, &mut findings);

    let verdict = if findings.is_empty() {
        ShellcodeVerdict::NoShellcode
    } else {
        let max_confidence = findings.iter().map(|f| f.confidence).fold(0.0_f64, f64::max);
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

fn check_shellcode_patterns(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    // Common x86 shellcode patterns

    // GetPC via call/pop or fnstenv
    let getpc_patterns: &[(&[u8], &str)] = &[
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58], "call $+5 / pop eax (GetPC)"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B], "call $+5 / pop ebx (GetPC)"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x59], "call $+5 / pop ecx (GetPC)"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A], "call $+5 / pop edx (GetPC)"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E], "call $+5 / pop esi (GetPC)"),
        (&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F], "call $+5 / pop edi (GetPC)"),
        (&[0xD9, 0xE0], "fnstenv (FPU GetPC)"),
        (&[0xEB, 0x00], "jmp $+2 (short jump NOP sled)"),
    ];

    for (pattern, desc) in getpc_patterns {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding {
                description: format!("Shellcode GetPC pattern: {}", desc),
                evidence: vec![format!("pattern at offset 0x{:X}", offset)],
                offset,
                confidence: 0.6,
            });
        }
    }

    // PEB access patterns (Windows shellcode hallmark)
    let peb_patterns: &[(&[u8], &str)] = &[
        (&[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00], "mov eax, fs:[0x30] (PEB access x86)"),
        (&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00], "mov rax, gs:[0x60] (PEB access x64)"),
        (&[0x6A, 0x60, 0x5A], "push 0x60 / pop edx (PEB offset)"),
        (&[0x64, 0x8B, 0x35], "mov esi, fs:[...] (TEB/PEB access)"),
        (&[0x33, 0xC0, 0x64, 0x8B], "xor eax,eax / mov eax,fs:[...] (x86 PEB)"),
    ];

    for (pattern, desc) in peb_patterns {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding {
                description: format!("PEB access pattern: {}", desc),
                evidence: vec![format!("pattern at offset 0x{:X}", offset)],
                offset,
                confidence: 0.8,
            });
        }
    }

    // API hash resolution loop patterns
    // Typical: loop iterating over export table, computing hash
    // Common: mov esi, [ebp+XX]  →  lodsd  →  hash computation →  cmp
    let hash_resolution: &[(&[u8], &str)] = &[
        // Metasploit-style hash resolution: pushad/popad around the loop
        (&[0x60, 0x8B, 0x45, 0x3C], "pushad / mov eax, [ebp+0x3C] (PE header parsing)"),
        (&[0x60, 0x8B, 0x75, 0x7C], "pushad / mov esi, [ebp+0x7C] (export table access)"),
    ];

    for (pattern, desc) in hash_resolution {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding {
                description: format!("API hash resolution: {}", desc),
                evidence: vec![format!("pattern at offset 0x{:X}", offset)],
                offset,
                confidence: 0.75,
            });
        }
    }

    // NOP sled detection (long sequences of 0x90 or equivalent)
    check_nop_sled(data, findings);
}

fn check_nop_sled(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    let min_sled_len = 16;
    let mut i = 0;

    // Classic NOP sleds: 0x90 (NOP)
    while i < data.len() {
        if data[i] == 0x90 {
            let start = i;
            while i < data.len() && data[i] == 0x90 {
                i += 1;
            }
            let len = i - start;
            if len >= min_sled_len {
                findings.push(ShellcodeFinding {
                    description: format!("NOP sled detected ({} bytes)", len),
                    evidence: vec![format!("offset 0x{:X}, length {}", start, len)],
                    offset: start,
                    confidence: 0.5,
                });
            }
        } else {
            i += 1;
        }
    }

    // Multi-byte NOP-equivalent sleds (used to evade simple NOP sled detection)
    // xchg eax,eax = 0x90 (same as NOP, already covered)
    // mov eax,eax = 0x89 0xC0 or 0x8B 0xC0
    // mov ebx,ebx = 0x89 0xDB or 0x8B 0xDB
    let nop_equivalents: &[[u8; 2]] = &[
        [0x89, 0xC0], // mov eax,eax
        [0x89, 0xDB], // mov ebx,ebx
        [0x89, 0xC9], // mov ecx,ecx
        [0x89, 0xD2], // mov edx,edx
        [0x89, 0xF6], // mov esi,esi
        [0x89, 0xFF], // mov edi,edi
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
                if count >= 8 { // 8 repetitions = 16 bytes
                    findings.push(ShellcodeFinding {
                        description: format!(
                            "Multi-byte NOP sled detected ({} repetitions of 0x{:02X}{:02X})",
                            count, equiv[0], equiv[1]
                        ),
                        evidence: vec![format!("offset 0x{:X}, {} bytes", start, count * 2)],
                        offset: start,
                        confidence: 0.45,
                    });
                }
            } else {
                i += 1;
            }
        }
    }
}

fn check_prologue_epilogue(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    // Check for int3 padding (0xCC) which suggests debug/breakpoint artifacts
    let mut cc_count = 0;
    let mut cc_start = None;
    for (i, &byte) in data.iter().enumerate() {
        if byte == 0xCC {
            if cc_start.is_none() {
                cc_start = Some(i);
            }
            cc_count += 1;
        } else {
            if cc_count >= 8 {
                if let Some(start) = cc_start {
                    findings.push(ShellcodeFinding {
                        description: format!("INT3 padding block ({} bytes)", cc_count),
                        evidence: vec![format!("offset 0x{:X}", start)],
                        offset: start,
                        confidence: 0.3,
                    });
                }
            }
            cc_count = 0;
            cc_start = None;
        }
    }
}

// ─── Encoder/Decoder Stub Detection ───────────────────────────────────

/// Detect common shellcode encoder/decoder stubs.
/// These are small loops that decode an encoded payload at runtime,
/// commonly used by Metasploit, Cobalt Strike, and custom encoders.
fn check_encoder_stubs(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    if data.len() < 20 {
        return;
    }

    // ─── XOR-based decoder loops ─────────────────────────────
    // Pattern: XOR [reg], imm8 / inc reg / cmp reg, end / jne loop
    // Common in Shikata Ga Nai and similar polymorphic encoders.
    //
    // Byte patterns for XOR decoder stubs:
    //   80 30 XX    — xor byte [eax], XX
    //   80 31 XX    — xor byte [ecx], XX
    //   80 33 XX    — xor byte [ebx], XX
    //   80 34 XX XX — xor byte [si+XX], XX  (with SIB)
    //   80 35 XX..  — xor byte [imm32], XX  (direct address)
    //
    // Full stub: setup + XOR loop + counter

    let _xor_decoder_patterns: &[(u8, &str)] = &[
        (0x30, "xor [eax], imm8 (XOR decoder stub)"),
        (0x31, "xor [ecx], imm8 (XOR decoder stub)"),
        (0x32, "xor [edx], imm8 (XOR decoder stub)"),
        (0x33, "xor [ebx], imm8 (XOR decoder stub)"),
        (0x34, "xor [esp], imm8 (XOR decoder stub)"),
        (0x35, "xor [ebp], imm8 (XOR decoder stub)"),
        (0x36, "xor [esi], imm8 (XOR decoder stub)"),
        (0x37, "xor [edi], imm8 (XOR decoder stub)"),
    ];

    for i in 0..data.len().saturating_sub(8) {
        // Check for: 0x80 (group 1, 8-bit operand), ModRM with 00 (indirect), opcode extension 110 (XOR)
        // ModRM: 00 rr r 000 where rr is register → 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38
        // But actually: 80 XX YY where XX is ModRM byte
        // ModRM for [reg] indirect: bits 7-6 = 00, bits 5-3 = opcode extension, bits 2-0 = reg
        // XOR has opcode extension 110 in the ModRM, so bits 5-3 = 110
        // So ModRM byte = 00 110 rrr = 0x30 | reg
        if data[i] == 0x80 {
            let modrm = data[i + 1];
            let mod_field = (modrm >> 6) & 0x03;
            let reg_field = (modrm >> 3) & 0x07;

            // mod=00 (indirect), reg=110 (XOR)
            if mod_field == 0 && reg_field == 6 {
                let xor_key = data[i + 2];
                // Only flag if the XOR key is non-zero and non-trivial
                if xor_key != 0 && xor_key != 0xFF {
                    // Check if this is near a loop (look for conditional jumps nearby)
                    let has_loop = (i > 0 && is_short_jump_back(data[i - 1]))
                        || (i + 3 < data.len() && has_loop_after(&data[i + 3..]));

                    if has_loop {
                        let reg_idx = modrm & 0x07;
                        let reg_name = match reg_idx {
                            0 => "eax", 1 => "ecx", 2 => "edx", 3 => "ebx",
                            4 => "esp", 5 => "ebp", 6 => "esi", 7 => "edi",
                            _ => "?",
                        };
                        findings.push(ShellcodeFinding {
                            description: format!(
                                "XOR decoder stub: xor [{}], 0x{:02X} (encoder detected)",
                                reg_name, xor_key
                            ),
                            evidence: vec![
                                format!("decoder at offset 0x{:X}", i),
                                format!("XOR key: 0x{:02X}", xor_key),
                            ],
                            offset: i,
                            confidence: 0.75,
                        });
                        // Don't flood findings — one per region is enough
                        break;
                    }
                }
            }
        }
    }

    // ─── Alpha-mixed / alphanumeric encoder stubs ──────────
    // These use only ASCII alphanumeric bytes to evade content filters.
    // Common pattern: sequence of bytes all in [0x30-0x39, 0x41-0x5A, 0x61-0x7A]
    // for 30+ bytes is highly suspicious in a binary.
    check_alphanumeric_shellcode(data, findings);

    // ─── FPU-based GetPC techniques ─────────────────────────
    // fnstenv stores FPU state, and the instruction pointer is saved at offset 12.
    // Pattern: fldz / fnstenv [esp-12] / pop ecx
    let fpu_getpc: &[(&[u8], &str)] = &[
        (&[0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4], "fldz / fnstenv [esp-0xC] (FPU GetPC)"),
        (&[0xD9, 0xE1, 0xD9, 0x74, 0x24, 0xF4], "fldpi / fnstenv [esp-0xC] (FPU GetPC)"),
        (&[0xD9, 0xE0, 0xD9, 0x74, 0x24, 0xF4], "fchs / fnstenv [esp-0xC] (FPU GetPC)"),
        (&[0xD9, 0xE8, 0xD9, 0x74, 0x24, 0xF4], "fucomip / fnstenv [esp-0xC] (FPU GetPC)"),
    ];

    for (pattern, desc) in fpu_getpc {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding {
                description: format!("FPU GetPC technique: {}", desc),
                evidence: vec![format!("offset 0x{:X}", offset)],
                offset,
                confidence: 0.85,
            });
        }
    }

    // ─── Call $+N / pop (non-standard offsets) ──────────────
    // call $+5 / pop is the most common, but malware uses other offsets to evade
    for i in 0..data.len().saturating_sub(7) {
        if data[i] == 0xE8 {
            let offset_bytes = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let _call_size = 5i32;
            // call target = (i + 5) + offset_bytes
            // We want: call target == i + 5 + offset_bytes, which lands somewhere after the call
            // Pop should follow the call target
            let target_rel = offset_bytes;
            // If offset is small and positive (0..16), the call lands nearby
            // and the next instruction at that offset should be a pop
            if target_rel >= 0 && target_rel < 16 {
                let pop_offset = (5 + target_rel) as usize;
                if i + pop_offset < data.len() {
                    let next_byte = data[i + pop_offset];
                    // pop eax=0x58, ecx=0x59, edx=0x5A, ebx=0x5B, esi=0x5E, edi=0x5F
                    if (0x58..=0x5F).contains(&next_byte) && next_byte != 0x5C && next_byte != 0x5D {
                        if target_rel != 0 { // Skip call $+5 (already detected above)
                            let reg = match next_byte {
                                0x58 => "eax", 0x59 => "ecx", 0x5A => "edx",
                                0x5B => "ebx", 0x5E => "esi", 0x5F => "edi",
                                _ => "?",
                            };
                            findings.push(ShellcodeFinding {
                                description: format!(
                                    "call $+{} / pop {} (non-standard GetPC)",
                                    target_rel + 5, reg
                                ),
                                evidence: vec![format!("offset 0x{:X}", i)],
                                offset: i,
                                confidence: 0.7,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Check if a byte is a short backward jump (used to detect loop patterns).
fn is_short_jump_back(byte: u8) -> bool {
    // jne/jnz short: 0x75 XX where XX < 0x80 (backward)
    // jmp short: 0xEB XX where XX < 0x80 (backward)
    // je/jz short: 0x74 XX
    // But we just check the byte before our pattern — this is called with data[i-1]
    // so we check if the PREVIOUS byte could be a backward jump offset
    // Actually we check if the byte IS a conditional jump opcode that precedes our pattern
    byte == 0x75 || byte == 0x74 || byte == 0xEB || byte == 0x7C || byte == 0x7E
}

/// Check if there's a backward conditional jump after a given slice.
fn has_loop_after(data: &[u8]) -> bool {
    // Check first 8 bytes for a backward short jump
    for i in 0..data.len().min(8) {
        match data[i] {
            0x74 | 0x75 | 0x7C | 0x7D | 0x7E | 0x7F | 0xEB => {
                // Next byte should be a negative offset (backward jump)
                if i + 1 < data.len() {
                    let offset = data[i + 1] as i8;
                    if offset < 0 {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Detect alphanumeric (alpha-mixed) encoded shellcode.
/// These encoders produce output using only [0-9A-Za-z] bytes.
/// A 32+ byte run of purely alphanumeric bytes in a binary blob is very suspicious.
fn check_alphanumeric_shellcode(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    let min_run = 32;
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
                    findings.push(ShellcodeFinding {
                        description: format!(
                            "Alphanumeric-encoded shellcode region ({} bytes)",
                            run_len
                        ),
                        evidence: vec![format!("offset 0x{:X}, length {}", start, run_len)],
                        offset: start,
                        confidence: 0.6,
                    });
                }
            }
            run_start = None;
            run_len = 0;
        }
    }

    // Flush last run
    if run_len >= min_run {
        if let Some(start) = run_start {
            findings.push(ShellcodeFinding {
                description: format!(
                    "Alphanumeric-encoded shellcode region ({} bytes)",
                    run_len
                ),
                evidence: vec![format!("offset 0x{:X}, length {}", start, run_len)],
                offset: start,
                confidence: 0.6,
            });
        }
    }
}

// ─── Egg Hunter Detection ─────────────────────────────────────────────

/// Detect egg hunter patterns.
/// Egg hunters are tiny shellcode stubs (typically 32 bytes) that search
/// memory for a specific 4-byte "egg" tag to locate the main shellcode body.
fn check_egg_hunters(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    // Classic Windows egg hunter patterns:
    // Uses NtAccessCheckAndAuditAlarm (syscall 0x0C) or
    // IsBadReadPtr / VirtualQuery to validate memory before checking for the egg.

    // Common egg hunter prologue:
    // 66 81 CB xx xx  — or bx, xxxx (page alignment)
    // 43              — inc ebx
    // 53              — push ebx
    // 6A 02           — push 2
    // 58              — pop eax
    // CD 2E           — int 0x2E (syscall gate)
    // 3C 05           — cmp al, 5 (check for ACCESS_VIOLATION)
    // 5A              — pop edx
    // 74 EF           — jz back to page alignment

    let egg_patterns: &[(&[u8], &str)] = &[
        // NtAccessCheckAndAuditAlarm egg hunter (Skape)
        (
            &[0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52],
            "or dx, 0x0FFF / inc edx / push edx (egg hunter page alignment)",
        ),
        // int 0x2e syscall-based egg hunter
        (
            &[0x6A, 0x02, 0x58, 0xCD, 0x2E, 0x3C, 0x05],
            "push 2 / pop eax / int 0x2E / cmp al, 5 (egg hunter syscall)",
        ),
        // NtDisplayString egg hunter
        (
            &[0x6A, 0x43, 0x58, 0xCD, 0x2E],
            "push 0x43 / pop eax / int 0x2E (NtDisplayString egg hunter)",
        ),
    ];

    for (pattern, desc) in egg_patterns {
        if let Some(offset) = find_pattern(data, pattern) {
            findings.push(ShellcodeFinding {
                description: format!("Egg hunter pattern: {}", desc),
                evidence: vec![format!("offset 0x{:X}", offset)],
                offset,
                confidence: 0.85,
            });
        }
    }

    // Generic egg hunter: look for the characteristic 4-byte egg tag comparison
    // Pattern: cmp dword [reg], EGG_TAG / jne loop
    // The egg tag is typically a 4-byte value like 0x50905090 ("push eax / nop / push eax / nop")
    for i in 0..data.len().saturating_sub(8) {
        // cmp [ebx], imm32 = 81 3B XX XX XX XX
        // cmp [ecx], imm32 = 81 39 XX XX XX XX
        // cmp [edx], imm32 = 81 3A XX XX XX XX
        if data[i] == 0x81 {
            let modrm = data[i + 1];
            let mod_field = (modrm >> 6) & 0x03;
            let reg_field = (modrm >> 3) & 0x07;
            // mod=00, reg=111 (CMP), r/m=any
            if mod_field == 0 && reg_field == 7 {
                // This is a cmp [reg], imm32 instruction
                if i + 6 < data.len() {
                    let egg = u32::from_le_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]]);
                    // Check if the egg value looks like a valid egg tag (not a normal pointer)
                    // Egg tags are usually carefully chosen values like:
                    //   0x50905090, 0x6A5B6A5B, etc. — repeated 2-byte patterns
                    let low_word = (egg & 0xFFFF) as u16;
                    let high_word = ((egg >> 16) & 0xFFFF) as u16;
                    if low_word == high_word && low_word != 0 && low_word != 0xFFFF {
                        // Check for backward jump after this comparison
                        if i + 6 < data.len() {
                            let next = data[i + 6];
                            if next == 0x75 || next == 0x74 || next == 0xEB {
                                findings.push(ShellcodeFinding {
                                    description: format!(
                                        "Egg hunter: cmp [reg], 0x{:08X} (egg tag search)",
                                        egg
                                    ),
                                    evidence: vec![
                                        format!("offset 0x{:X}", i),
                                        format!("egg tag: 0x{:08X}", egg),
                                    ],
                                    offset: i,
                                    confidence: 0.7,
                                });
                                break; // One per region is enough
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── Encoded Blob Detection ───────────────────────────────────────────

/// Detect XOR-encoded or ADD/SUB-encoded shellcode bodies.
/// Strategy: try XOR-ing the data with each possible single-byte key (0x01..0xFF)
/// and check if the result has significantly lower entropy or contains
/// recognizable shellcode patterns.
fn check_encoded_blobs(data: &[u8], findings: &mut Vec<ShellcodeFinding>) {
    if data.len() < 64 {
        return;
    }

    // Respect max_blob_size from config to prevent DoS on large files.
    // Use a reasonable default if called without config context.
    let max_scan_size: usize = 0x100000; // 1 MB default
    let scan_data = if data.len() > max_scan_size {
        &data[..max_scan_size]
    } else {
        data
    };

    // Only scan high-entropy regions (encoded shellcode has high entropy)
    let window = 128;
    let step = 64;
    let mut offset = 0;

    while offset + window <= scan_data.len() {
        let region = &scan_data[offset..offset + window];
        let entropy_result = entropy_rs::calculate_entropy(region);

        // Only check regions with entropy > 6.5 (likely encoded/encrypted)
        if entropy_result.entropy > 6.5 {
            // Try XOR decoding with common keys
            for key in 0x01u8..=0xFFu8 {
                let decoded: Vec<u8> = region.iter().map(|b| b ^ key).collect();
                let decoded_entropy = entropy_rs::calculate_entropy(&decoded).entropy;

                // If XOR decoding significantly reduces entropy, it was likely encoded
                if decoded_entropy < entropy_result.entropy - 2.0 && decoded_entropy < 5.5 {
                    // Check for shellcode patterns in decoded data
                    let has_peb = decoded.windows(6).any(|w| {
                        w == &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]
                    });
                    let has_getpc = decoded.windows(5).any(|w| {
                        w[0] == 0xE8 && w[1] == 0x00 && w[2] == 0x00 && w[3] == 0x00 && w[4] == 0x00
                    });

                    if has_peb || has_getpc {
                        findings.push(ShellcodeFinding {
                            description: format!(
                                "XOR-encoded shellcode detected (key=0x{:02X})",
                                key
                            ),
                            evidence: vec![
                                format!("encoded region at offset 0x{:X}", offset),
                                format!("XOR key: 0x{:02X}", key),
                                format!("encoded entropy: {:.2} → decoded entropy: {:.2}", entropy_result.entropy, decoded_entropy),
                            ],
                            offset,
                            confidence: 0.9,
                        });
                        // Skip this region — we found the encoding
                        offset += window;
                        continue;
                    }
                }
            }
        }

        offset += step;
    }
}

// ─── Entropy Region Detection ────────────────────────────────────────

fn check_entropy_regions(data: &[u8], config: &ShellcodeConfig, findings: &mut Vec<ShellcodeFinding>) {
    if data.len() < config.window_size {
        return;
    }

    let mut high_entropy_runs = Vec::new();
    let mut current_run_start: Option<usize> = None;
    let mut current_run_len = 0usize;

    let mut offset = 0;
    while offset + config.window_size <= data.len() {
        let window = &data[offset..offset + config.window_size];
        let entropy_result = entropy_rs::calculate_entropy(window);

        if entropy_result.entropy >= config.min_entropy {
            if current_run_start.is_none() {
                current_run_start = Some(offset);
            }
            current_run_len += config.window_step;
        } else {
            if let Some(start) = current_run_start {
                if current_run_len >= config.min_blob_size {
                    high_entropy_runs.push((start, current_run_len));
                }
            }
            current_run_start = None;
            current_run_len = 0;
        }

        offset += config.window_step;
    }

    // Flush last run
    if let Some(start) = current_run_start {
        if current_run_len >= config.min_blob_size {
            high_entropy_runs.push((start, current_run_len));
        }
    }

    for (start, len) in high_entropy_runs {
        findings.push(ShellcodeFinding {
            description: format!(
                "High-entropy region ({} bytes at 0x{:X}) consistent with shellcode/encrypted payload",
                len, start
            ),
            evidence: vec![format!("offset=0x{:X} size={}", start, len)],
            offset: start,
            confidence: 0.4,
        });
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
    fn test_detect_peb_access() {
        let mut data = vec![0u8; 128];
        // Insert x86 PEB access pattern at offset 32
        data[32] = 0x64;
        data[33] = 0xA1;
        data[34] = 0x30;
        data[35] = 0x00;
        data[36] = 0x00;
        data[37] = 0x00;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(!report.findings.is_empty());
        assert!(report.findings.iter().any(|f| f.description.contains("PEB")));
    }

    #[test]
    fn test_clean_data_no_findings() {
        let data = vec![0u8; 256]; // All zeros
        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert_eq!(report.verdict, ShellcodeVerdict::NoShellcode);
    }

    #[test]
    fn test_nop_sled_detection() {
        let mut data = vec![0xFFu8; 128];
        // Insert 32-byte NOP sled
        for i in 40..72 {
            data[i] = 0x90;
        }

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(report.findings.iter().any(|f| f.description.contains("NOP sled")));
    }

    #[test]
    fn test_api_hash_detection() {
        let mut data = vec![0u8; 128];
        // Place two known API hashes
        // VirtualAlloc ROR13 = 0x519E5A8
        data[0] = 0xA8; data[1] = 0xE5; data[2] = 0x9E; data[3] = 0x05;
        // Sleep ROR13 = 0x6A7694F8
        data[4] = 0xF8; data[5] = 0x94; data[6] = 0x76; data[7] = 0x6A;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(report.total_api_hashes_found >= 2);
        assert!(report.findings.iter().any(|f| f.description.contains("API hash")));
    }

    #[test]
    fn test_encoder_stub_detection() {
        let mut data = vec![0x90u8; 128];
        // Insert XOR decoder stub: xor [ebx], 0x41 / inc ebx / jmp back
        // 80 33 41 — xor byte [ebx], 0x41
        // 43       — inc ebx
        // EB F9    — jmp -7 (back to xor)
        data[50] = 0x80;
        data[51] = 0x33; // mod=00, reg=110(XOR), rm=011(ebx)
        data[52] = 0x41; // XOR key
        data[53] = 0x43; // inc ebx
        data[54] = 0xEB; // jmp short
        data[55] = 0xF9; // -7 (backward)

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            report.findings.iter().any(|f| f.description.contains("XOR decoder")),
            "Should detect XOR decoder stub. Findings: {:?}",
            report.findings.iter().map(|f| &f.description).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fpu_getpc_detection() {
        let mut data = vec![0u8; 128];
        // fldz / fnstenv [esp-0xC]
        data[20] = 0xD9;
        data[21] = 0xEE;
        data[22] = 0xD9;
        data[23] = 0x74;
        data[24] = 0x24;
        data[25] = 0xF4;

        let config = ShellcodeConfig::default();
        let report = detect_shellcode(&data, &config);
        assert!(
            report.findings.iter().any(|f| f.description.contains("FPU GetPC")),
            "Should detect FPU GetPC"
        );
    }

    #[test]
    fn test_alphanumeric_shellcode() {
        // 40 bytes of pure alphanumeric data in a binary blob context
        let mut data = vec![0u8; 64];
        let alnum = b"ABCDEFGHabcdefgh12345678ABCDEFGHabcdefgh";
        data[10..10 + alnum.len()].copy_from_slice(alnum);

        let mut findings = Vec::new();
        check_alphanumeric_shellcode(&data, &mut findings);
        assert!(
            findings.iter().any(|f| f.description.contains("Alphanumeric")),
            "Should detect alphanumeric run"
        );
    }

    #[test]
    fn test_xor_encoded_blob() {
        // Create a small PEB access pattern, XOR-encode it, embed in data
        let shellcode: Vec<u8> = vec![
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30]
            0x8B, 0x40, 0x0C,                    // mov eax, [eax+0x0C]
        ];
        let key = 0x42u8;
        let encoded: Vec<u8> = shellcode.iter().map(|b| b ^ key).collect();

        let mut data = vec![0u8; 256];
        data[50..50 + encoded.len()].copy_from_slice(&encoded);

        let mut findings = Vec::new();
        check_encoded_blobs(&data, &mut findings);
        // This should detect the XOR-encoded shellcode
        assert!(
            findings.iter().any(|f| f.description.contains("XOR-encoded")),
            "Should detect XOR-encoded shellcode. Findings: {:?}",
            findings.iter().map(|f| &f.description).collect::<Vec<_>>()
        );
    }
}
