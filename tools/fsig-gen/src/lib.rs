//! # fsig-gen — harvest FLIRT signatures from PE export tables
//!
//! Turns named DLL exports into masked `.fsig` patterns without needing a
//! second build for relocation diffing. Masking is *operand-aware*: the
//! harvester decodes each instruction (via `freakre-x86`) and wildcards only
//! bytes that provably encode addresses:
//!
//! - relative branch/call targets (`rel8`/`rel32`) — trailing bytes by form;
//! - RIP-relative / absolute displacements (`base == None`);
//! - immediates that look like addresses (`>= 1 MiB` or inside the image).
//!
//! Small constants, frame offsets (`[rbp-0x20]`) and opcodes are kept exact.
//!
//! ## Foreseen problems (and where they are handled)
//! 1. **Forwarded exports** (`kernel32!X -> KERNELBASE!X`): detected by RVA
//!    landing inside the export directory; resolved by the driver (`main.rs`)
//!    which loads the target DLL. Both names are kept (`aka`).
//! 2. **Jump thunks** (`FF 25 ...`): skipped — thunks are not functions.
//! 3. **Unknown function length**: patterns are capped at 32 leading bytes
//!    and stop at `int3` padding, decode errors or section end. A truncated
//!    pattern is still a valid *prefix*; over-long tails risk false
//!    *negatives* on other versions, never false positives.
//! 4. **Internal `ret`s**: do NOT stop the harvest (multi-exit functions).
//! 5. **Pattern collisions** (same bytes, several names): merged, aliases in
//!    `aka`, so the database never contradicts itself.
//! 6. **Self false-positives**: every emitted pattern is scanned against
//!    degenerate fills (zeros, NOPs, `int3`, `0xFF`, PRNG stream); any hit
//!    drops the entry before it ships.
//! 7. **Data exports**: decode fails fast on data, and even if a data export
//!    yields bytes, it lives outside executable sections at scan time.
//! 8. **Determinism**: no threads, no hash iteration; output sorted by
//!    `(lib, name)`.

use freakre_x86::types::Register;
use freakre_x86::{decode_mode, Instruction, Mode, Mnemonic, Operand};
use pe_parser::PeFile;

// ─── Configuration ────────────────────────────────────────────────

/// Harvest tuning. Defaults are chosen for system-DLL harvesting.
#[derive(Debug, Clone)]
pub struct HarvestConfig {
    /// Maximum pattern length in bytes (FLIRT-classic 32).
    pub max_prefix_len: usize,
    /// Minimum pattern length (matches the `.fsig` parser floor).
    pub min_pattern_len: usize,
    /// Minimum fixed bytes (matches the `.fsig` parser floor).
    pub min_fixed: usize,
    /// Immediates `>= threshold` are treated as addresses and masked.
    /// 1 MiB keeps real constants (counts, LCG multipliers) exact while
    /// catching every mapped image address (PEs never load that low).
    pub addr_threshold: u64,
    /// Long patterns get this confidence, short ones `conf_short`.
    pub conf_long: f64,
    /// Confidence for patterns shorter than 16 bytes.
    pub conf_short: f64,
    /// Cap on exports processed per DLL (0 = unlimited). Safety brake.
    pub max_exports_per_dll: usize,
}

impl Default for HarvestConfig {
    fn default() -> Self {
        Self {
            max_prefix_len: 32,
            min_pattern_len: 8,
            min_fixed: 4,
            addr_threshold: 0x10_0000,
            conf_long: 0.8,
            conf_short: 0.65,
            max_exports_per_dll: 0,
        }
    }
}

// ─── Types ────────────────────────────────────────────────────────

/// One harvested (not yet merged/validated) signature.
#[derive(Debug, Clone)]
pub struct RawEntry {
    /// DLL stem, lowercased, no extension (`kernel32`, `ntdll`).
    pub lib: String,
    /// Primary export name.
    pub name: String,
    /// Alias names (forwarder chains, cross-DLL duplicates).
    pub aka: Vec<String>,
    /// `x86` or `x64`.
    pub arch: String,
    /// Pattern bytes (wildcard slots hold `0x00`).
    pub bytes: Vec<u8>,
    /// `true` = byte must match exactly.
    pub mask: Vec<bool>,
    /// Decoded prefix length; doubles as minimum function length.
    pub min_len: usize,
    /// Confidence assigned by length class.
    pub confidence: f64,
}

impl RawEntry {
    pub fn fixed_count(&self) -> usize {
        self.mask.iter().filter(|&&m| m).count()
    }
}

/// A named export pointing at real code.
#[derive(Debug, Clone)]
pub struct CodeExport {
    pub name: String,
    pub ordinal: u16,
    pub rva: u32,
}

/// A forwarder reference (`DLL.Name` or `DLL.#ordinal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwarderRef {
    pub from_name: String,
    pub target_dll: String,
    pub target_name: String,
}

/// Per-DLL harvest outcome (entries + forwarder refs + drop statistics).
#[derive(Debug, Default)]
pub struct DllHarvest {
    pub lib: String,
    pub arch: String,
    pub entries: Vec<RawEntry>,
    pub forwarders: Vec<ForwarderRef>,
    pub exports_total: usize,
    pub skipped_unnamed: usize,
    pub skipped_thunk: usize,
    pub skipped_short: usize,
    pub skipped_loose: usize,
    pub skipped_data: usize,
    pub skipped_decode: usize,
}

/// Split `DLL.Name` / `DLL.#ord` forwarder strings. Returns
/// `(dll_stem_lowercased, name_or_#ord)`.
pub fn parse_forwarder(s: &str) -> Option<(String, String)> {
    let dot = s.find('.')?;
    let (dll, name) = s.split_at(dot);
    let name = &name[1..];
    if dll.is_empty() || name.is_empty() {
        return None;
    }
    Some((dll.to_ascii_lowercase(), name.to_string()))
}

// ─── Single-DLL harvest ───────────────────────────────────────────

/// Harvest one PE image. `lib` is the DLL stem used for attribution.
/// Returns entries plus forwarder refs for the driver to resolve.
pub fn harvest_pe(data: &[u8], lib: &str, cfg: &HarvestConfig) -> Result<DllHarvest, String> {
    let pe = PeFile::parse(data).map_err(|e| format!("pe parse: {e:?}"))?;
    let arch = if pe.is_64bit { "x64" } else { "x86" };
    let mode = if pe.is_64bit { Mode::X64 } else { Mode::X86 };
    let (dll_name, exports) = pe.exports();
    let lib = if lib.is_empty() {
        dll_name
            .as_deref()
            .unwrap_or("unknown")
            .trim_end_matches(['.', 'd', 'l'])
            .to_ascii_lowercase()
    } else {
        lib.to_ascii_lowercase()
    };
    // Image VA range, for the address heuristic.
    let img_lo = pe.image_base;
    let img_hi = pe.sections.iter().fold(img_lo, |hi, s| {
        let end = pe.image_base.wrapping_add(s.virtual_address as u64).wrapping_add(
            (s.virtual_size.max(s.raw_data_size)) as u64,
        );
        hi.max(end)
    });

    let exp_range = pe.export_directory();
    let mut out = DllHarvest { lib: lib.clone(), arch: arch.to_string(), ..Default::default() };
    out.exports_total = exports.len();

    let mut budget = if cfg.max_exports_per_dll == 0 { usize::MAX } else { cfg.max_exports_per_dll };
    for (ordinal, name, rva) in &exports {
        if budget == 0 {
            break;
        }
        budget -= 1;
        if name.starts_with("ord_") {
            out.skipped_unnamed += 1;
            continue;
        }
        // Forwarder: RVA lands inside the export directory.
        if let Some((er, es)) = exp_range {
            if *rva >= er && (*rva - er) < es {
                if let Some(off) = pe.rva_to_offset(*rva) {
                    if let Some(target) = read_cstr(data, off) {
                        if let Some((dll, tname)) = parse_forwarder(&target) {
                            out.forwarders.push(ForwarderRef {
                                from_name: name.clone(),
                                target_dll: dll,
                                target_name: tname,
                            });
                            continue;
                        }
                    }
                }
                out.skipped_decode += 1;
                continue;
            }
        }
        let Some(off) = pe.rva_to_offset(*rva) else {
            out.skipped_data += 1;
            continue;
        };
        // Must live in an executable section.
        if !pe.sections.iter().any(|s| {
            let lo = s.virtual_address;
            let hi = lo.saturating_add(s.virtual_size.max(s.raw_data_size));
            *rva >= lo && *rva < hi && s.is_executable()
        }) {
            out.skipped_data += 1;
            continue;
        }
        match harvest_function(data, off, *rva, mode, img_lo, img_hi, cfg) {
            Ok(Some(e)) => out.entries.push(RawEntry {
                lib: lib.clone(),
                name: name.clone(),
                aka: Vec::new(),
                arch: arch.to_string(),
                ..e
            }),
            Ok(None) => out.skipped_thunk += 1,
            Err(DropReason::Short) => out.skipped_short += 1,
            Err(DropReason::Loose) => out.skipped_loose += 1,
            Err(DropReason::Decode) => out.skipped_decode += 1,
        }
        let _ = ordinal;
    }
    Ok(out)
}

fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    let end = data.get(off..)?.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&data[off..off + end]).ok().map(|s| s.to_string())
}

enum DropReason {
    Short,
    Loose,
    Decode,
}

/// Decode a function prefix starting at file `off` (RVA `rva`).
/// `Ok(None)` = jump thunk (not a function). `Err` = drop reason.
fn harvest_function(
    data: &[u8],
    off: usize,
    rva: u32,
    mode: Mode,
    img_lo: u64,
    img_hi: u64,
    cfg: &HarvestConfig,
) -> Result<Option<RawEntry>, DropReason> {
    let mut bytes: Vec<u8> = Vec::with_capacity(cfg.max_prefix_len);
    let mut mask: Vec<bool> = Vec::with_capacity(cfg.max_prefix_len);
    let mut cur = off;
    let mut va = rva as u64;
    let mut first = true;

    while bytes.len() < cfg.max_prefix_len {
        let slice = data.get(cur..).ok_or(DropReason::Decode)?;
        if slice.first() == Some(&0xCC) {
            break; // int3 padding: function (or alignment) ends here.
        }
        let insn =
            decode_mode(slice, img_lo.wrapping_add(va), mode).map_err(|_| DropReason::Decode)?;
        if insn.length == 0 || insn.length > 15 {
            return Err(DropReason::Decode);
        }
        if matches!(insn.mnemonic, Mnemonic::Unknown) {
            break;
        }
        // Thunk: the function IS a single unconditional jump.
        if first && insn.mnemonic.is_unconditional_jump() {
            return Ok(None);
        }
        first = false;
        let raw = &slice[..insn.length];
        let mut m = vec![true; insn.length];
        mask_instruction(&insn, raw, mode, img_lo, img_hi, cfg, &mut m);
        bytes.extend_from_slice(raw);
        mask.extend_from_slice(&m);
        cur += insn.length;
        va = va.wrapping_add(insn.length as u64);
        let _ = va;
    }

    if bytes.len() < cfg.min_pattern_len {
        return Err(DropReason::Short);
    }
    let fixed = mask.iter().filter(|&&m| m).count();
    if fixed < cfg.min_fixed {
        return Err(DropReason::Loose);
    }
    let confidence = if bytes.len() >= 16 { cfg.conf_long } else { cfg.conf_short };
    let min_len = bytes.len();
    Ok(Some(RawEntry {
        lib: String::new(),
        name: String::new(),
        aka: Vec::new(),
        arch: String::new(),
        bytes,
        mask,
        min_len,
        confidence,
    }))
}

/// Wildcard address-encoding bytes of one instruction in `m` (in/out, all
/// `true` on entry). Only *narrows* fixed bytes; never touches opcodes that
/// the rules below do not cover.
fn mask_instruction(
    insn: &Instruction,
    raw: &[u8],
    _mode: Mode,
    img_lo: u64,
    img_hi: u64,
    cfg: &HarvestConfig,
    m: &mut [bool],
) {
    let looks_like_addr = |v: i64| {
        // Negative values (`push -1`, `[ebp-4]`) are never addresses.
        v >= 0 && {
            let u = v as u64;
            (u >= cfg.addr_threshold) || (u >= img_lo && u < img_hi)
        }
    };
    let has_rel = insn.operands.iter().any(|o| matches!(o, Operand::Rel(_)));
    let mem_disp = insn.operands.iter().find_map(|o| match o {
        Operand::Mem(mem) => Some((
            mem.base.is_none()
                || matches!(mem.base, Some(Register::Rip | Register::Eip)),
            mem.displacement,
        )),
        _ => None,
    });
    let has_imm_addr = insn.operands.iter().any(|o| match o {
        Operand::Imm(v) => looks_like_addr(*v),
        _ => false,
    });

    // 1. Relative branch/call targets: trailing bytes by form.
    //    E8/E9/0F8x/FF15/FF25 -> disp32; EB/70-7F/E0-E3 -> disp8.
    if has_rel {
        let n = match raw.len() {
            2 => 1,
            5 | 6 => 4,
            _ if raw.len() > 2 => 4,
            _ => 0,
        };
        for i in 0..n.min(m.len()) {
            m[m.len() - 1 - i] = false;
        }
        return;
    }

    // 2. Memory displacement handling.
    if let Some((no_base, disp)) = mem_disp {
        if no_base {
            // RIP-relative (x64) or absolute moffs (x86): disp32 is trailing
            // unless an immediate follows it (C7/81/83/69 group + test).
            let imm_tail = imm_tail_len(insn, raw);
            let dpos = raw.len().saturating_sub(imm_tail + 4);
            if raw.len() > imm_tail + 4 {
                for i in 0..4 {
                    m[dpos + i] = false;
                }
            }
        } else if disp != 0 && looks_like_addr(disp) && !has_imm_addr {
            // Absolute-looking disp32 with a base register: trailing 4,
            // only when the encoding plausibly holds disp32 (len >= 6).
            if raw.len() >= 6 {
                for i in 0..4 {
                    m[m.len() - 1 - i] = false;
                }
            }
        }
    }

    // 3. Address-like immediates: trailing imm span.
    if has_imm_addr {
        let k = imm_tail_len(insn, raw);
        if k > 0 && k < m.len() {
            for i in 0..k {
                m[m.len() - 1 - i] = false;
            }
        }
    }
}

/// Trailing immediate size for Mem+Imm / Imm instructions: 8 for `movabs`,
/// 1 for short forms, else 4. Returns 0 when no immediate is present.
fn imm_tail_len(insn: &Instruction, raw: &[u8]) -> usize {
    let has_imm = insn.operands.iter().any(|o| matches!(o, Operand::Imm(_)));
    if !has_imm {
        return 0;
    }
    if raw.len() == 10 {
        return 8; // mov reg, imm64
    }
    // imm8 forms: 83-group ALU, 6A push, 6B imul, C6 mov, F6 test, E0-E3.
    // Distinguish by length: imm8 encodings are short (<= 4 bytes without
    // displacement); imm32 encodings are longer.
    if raw.len() <= 4 {
        return 1;
    }
    4
}

// ─── Merge / validate / emit ────────────────────────────────────────

/// Merge identical `(bytes, mask, arch)` patterns, collecting alias names.
/// Deterministic: input order decides the primary name; aka sorted.
pub fn merge_entries(mut entries: Vec<RawEntry>) -> Vec<RawEntry> {
    let mut map: std::collections::HashMap<(Vec<u8>, Vec<bool>, String), usize> =
        std::collections::HashMap::new();
    let mut out: Vec<RawEntry> = Vec::new();
    for e in entries.drain(..) {
        let key = (e.bytes.clone(), e.mask.clone(), e.arch.clone());
        if let Some(&idx) = map.get(&key) {
            let slot = &mut out[idx];
            for n in std::iter::once(e.name).chain(e.aka) {
                if n != slot.name && !slot.aka.contains(&n) {
                    slot.aka.push(n);
                }
            }
            slot.confidence = slot.confidence.max(e.confidence);
            // Keep the smallest lib id clash-free: prefer the shorter lib
            // name (usually the real owner, e.g. kernelbase < kernel32? no:
            // keep first-seen; aka preserves the rest).
        } else {
            map.insert(key, out.len());
            out.push(e);
        }
    }
    for e in &mut out {
        e.aka.sort();
        e.aka.dedup();
    }
    out.sort_by(|a, b| a.lib.cmp(&b.lib).then_with(|| a.name.cmp(&b.name)));
    out
}

/// Degenerate fills every shipped pattern must avoid. Shared with the
/// `.fsig` self-FP gate: predictable xorshift64 stream, fixed seed.
pub fn validation_fills() -> Vec<Vec<u8>> {
    let mut fills = vec![
        vec![0x00u8; 4096],
        vec![0x90u8; 4096],
        vec![0xCCu8; 4096],
        vec![0xFFu8; 4096],
    ];
    let mut rnd = vec![0u8; 8192];
    let mut x: u64 = 0x1234_5678_9ABC_DEF0;
    for b in rnd.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    fills.push(rnd);
    fills
}

/// Returns true when the entry matches anywhere inside `fill`.
fn entry_hits(entry: &RawEntry, fill: &[u8]) -> bool {
    if entry.bytes.len() > fill.len() {
        return false;
    }
    for start in 0..=fill.len() - entry.bytes.len() {
        let mut ok = true;
        for (i, &b) in entry.bytes.iter().enumerate() {
            if entry.mask[i] && fill[start + i] != b {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

/// Drop entries that hit degenerate fills. Returns `(kept, dropped_names)`.
pub fn validate_entries(entries: Vec<RawEntry>) -> (Vec<RawEntry>, Vec<String>) {
    let fills = validation_fills();
    let mut kept = Vec::with_capacity(entries.len());
    let mut dropped = Vec::new();
    for e in entries {
        if fills.iter().any(|f| entry_hits(&e, f)) {
            dropped.push(format!("{}!{}", e.lib, e.name));
        } else {
            kept.push(e);
        }
    }
    (kept, dropped)
}

fn hex_line(bytes: &[u8], mask: &[bool]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        if mask[i] {
            s.push_str(&format!("{b:02X}"));
        } else {
            s.push_str("??");
        }
    }
    s
}

/// Emit `.fsig` text (sorted by caller via [`merge_entries`]).
/// Adds the optional 7th field `aka=a,b` when aliases exist.
pub fn emit_fsig(entries: &[RawEntry]) -> String {
    let mut out = String::new();
    out.push_str("# Generated by fsig-gen — harvested PE export prefixes.\n");
    out.push_str("# lib|arch|name|min_len|confidence|hex [|aka=a,b]\n");
    for e in entries {
        out.push_str(&format!(
            "{}|{}|{}|{}|{:.2}|{}",
            e.lib,
            e.arch,
            e.name,
            e.min_len,
            e.confidence,
            hex_line(&e.bytes, &e.mask)
        ));
        if !e.aka.is_empty() {
            out.push_str("|aka=");
            out.push_str(&e.aka.join(","));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HarvestConfig {
        HarvestConfig::default()
    }

    #[test]
    fn forwarder_parsing() {
        assert_eq!(
            parse_forwarder("KERNELBASE.CreateFileW"),
            Some(("kernelbase".to_string(), "CreateFileW".to_string()))
        );
        assert_eq!(
            parse_forwarder("api-ms-win-core-x.#12"),
            Some(("api-ms-win-core-x".to_string(), "#12".to_string()))
        );
        assert!(parse_forwarder("NoDotHere").is_none());
        assert!(parse_forwarder(".Empty").is_none());
        assert!(parse_forwarder("DLL.").is_none());
    }

    // call rel32: E8 <disp32> — disp must be masked, opcode kept.
    #[test]
    fn mask_call_rel32() {
        let code = [0xE8, 0x78, 0x56, 0x34, 0x12];
        let insn = decode_mode(&code, 0, Mode::X86).unwrap();
        let c = cfg();
        let mut m = vec![true; 5];
        mask_instruction(&insn, &code, Mode::X86, 0, 0, &c, &mut m);
        assert_eq!(m, vec![true, false, false, false, false]);
    }

    // push imm32 of a small constant: kept exact.
    #[test]
    fn mask_small_imm_kept() {
        let code = [0x6A, 0x0C];
        let insn = decode_mode(&code, 0, Mode::X86).unwrap();
        let c = cfg();
        let mut m = vec![true; 2];
        mask_instruction(&insn, &code, Mode::X86, 0, 0, &c, &mut m);
        assert_eq!(m, vec![true, true]);
    }

    // mov eax, 0x7FF81234 (image address): imm masked.
    #[test]
    fn mask_big_imm() {
        let code = [0xB8, 0x34, 0x12, 0xF8, 0x7F];
        let insn = decode_mode(&code, 0, Mode::X86).unwrap();
        let c = cfg();
        let mut m = vec![true; 5];
        mask_instruction(&insn, &code, Mode::X86, 0x7FF0_0000, 0x8000_0000, &c, &mut m);
        assert_eq!(m, vec![true, false, false, false, false]);
    }

    // Same bytes, constant below the threshold and outside the image: kept.
    #[test]
    fn mask_lcg_const_kept() {
        // imul eax, 0x343FD (214013, MSVC rand LCG)
        let code = [0x69, 0xC0, 0xFD, 0x43, 0x03, 0x00];
        let insn = decode_mode(&code, 0, Mode::X86).unwrap();
        let c = cfg();
        let mut m = vec![true; 6];
        mask_instruction(&insn, &code, Mode::X86, 0x7000_0000, 0x8000_0000, &c, &mut m);
        assert!(m.iter().all(|&x| x), "LCG constant must stay exact: {m:?}");
    }

    // RIP-relative lea (x64): disp32 masked.
    #[test]
    fn mask_rip_relative() {
        let code = [0x48, 0x8D, 0x05, 0x11, 0x22, 0x33, 0x44];
        let insn = decode_mode(&code, 0, Mode::X64).unwrap();
        assert!(insn.operands.iter().any(|o| matches!(o, Operand::Mem(_))));
        let c = cfg();
        let mut m = vec![true; 7];
        mask_instruction(&insn, &code, Mode::X64, 0, 0, &c, &mut m);
        assert_eq!(m, vec![true, true, true, false, false, false, false]);
    }

    // RIP-relative with a Rip base register (not None): disp32 masked.
    #[test]
    fn mask_rip_base_register() {
        // mov rax, [rip+0x2CCC] — cookie load shape from real DLLs.
        let code = [0x48, 0x8B, 0x05, 0xCC, 0x2C, 0x00, 0x00];
        let insn = decode_mode(&code, 0, Mode::X64).unwrap();
        let c = cfg();
        let mut m = vec![true; 7];
        mask_instruction(&insn, &code, Mode::X64, 0, 0, &c, &mut m);
        assert_eq!(m, vec![true, true, true, false, false, false, false]);
    }

    // Frame offset [rbp-0x20]: stable, kept.
    #[test]
    fn mask_frame_disp_kept() {
        // mov eax, [rbp-0x20]
        let code = [0x8B, 0x45, 0xE0];
        let insn = decode_mode(&code, 0, Mode::X86).unwrap();
        let c = cfg();
        let mut m = vec![true; 3];
        mask_instruction(&insn, &code, Mode::X86, 0x7000_0000, 0x8000_0000, &c, &mut m);
        assert_eq!(m, vec![true, true, true]);
    }

    // call rax (FF D0): register target, nothing masked.
    #[test]
    fn mask_indirect_reg_call_kept() {
        let code = [0xFF, 0xD0];
        let insn = decode_mode(&code, 0, Mode::X86).unwrap();
        let c = cfg();
        let mut m = vec![true; 2];
        mask_instruction(&insn, &code, Mode::X86, 0, 0, &c, &mut m);
        assert_eq!(m, vec![true, true]);
    }

    #[test]
    fn merge_collects_aka() {
        let mk = |name: &str, aka: Vec<&str>| RawEntry {
            lib: "ntdll".into(),
            name: name.into(),
            aka: aka.into_iter().map(|s| s.into()).collect(),
            arch: "x64".into(),
            bytes: vec![0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56],
            mask: vec![true; 8],
            min_len: 8,
            confidence: 0.8,
        };
        let merged = merge_entries(vec![mk("ZwCreateFile", vec![]), mk("NtCreateFile", vec!["X"])]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "ZwCreateFile");
        assert_eq!(merged[0].aka, vec!["NtCreateFile", "X"]);
    }

    #[test]
    fn validate_drops_degenerate_matcher() {
        // 8 NOPs would match a NOP sled: must be dropped.
        let bad = RawEntry {
            lib: "t".into(),
            name: "nops".into(),
            aka: vec![],
            arch: "x86".into(),
            bytes: vec![0x90; 8],
            mask: vec![true; 8],
            min_len: 8,
            confidence: 0.8,
        };
        let good = RawEntry {
            bytes: vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56],
            name: "real".into(),
            ..bad.clone()
        };
        let (kept, dropped) = validate_entries(vec![bad, good]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "real");
        assert_eq!(dropped, vec!["t!nops"]);
    }

    #[test]
    fn emit_round_trip_shape() {
        let e = RawEntry {
            lib: "kernel32".into(),
            name: "CreateFileW".into(),
            aka: vec!["KBCreate".into()],
            arch: "x64".into(),
            bytes: vec![0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x11, 0x22, 0x33],
            mask: vec![true, true, true, true, true, false, false, false, false],
            min_len: 9,
            confidence: 0.8,
        };
        let text = emit_fsig(&[e]);
        let line = text.lines().find(|l| !l.starts_with('#')).unwrap();
        assert_eq!(
            line,
            "kernel32|x64|CreateFileW|9|0.80|48 83 EC 28 E8 ?? ?? ?? ??|aka=KBCreate"
        );
    }
}
