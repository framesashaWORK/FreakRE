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
use freakre_x86::{decode_len, decode_mode, Instruction, Mnemonic, Mode, Operand};
use pe_parser::PeFile;

// ─── Configuration ────────────────────────────────────────────────

/// Harvest tuning. Defaults are chosen for system-DLL harvesting.
#[derive(Debug, Clone)]
pub struct HarvestConfig {
    /// Maximum pattern length in bytes (FLIRT-classic 32).
    pub max_prefix_len: usize,
    /// Minimum pattern length (matches the `.fsig` parser floor).
    pub min_pattern_len: usize,
    /// Minimum emitted pattern length. Mirrors the overlay load gate
    /// (`func-sigs` `OVERLAY_MIN_PATTERN_LEN` = 16): shorter generated
    /// patterns never ship, so emitting them only bloats the database.
    pub min_emit_len: usize,
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
    /// Decode window per function for interior anchors (default 288).
    /// Larger windows find more branch targets; costs harvest time.
    pub harvest_window: usize,
    /// Extra interior patterns per function beyond the entry prefix
    /// (default 9). Anchors: branch targets first, then earliest
    /// instruction starts. Each needs 16+ remaining bytes.
    pub max_extra_anchors: usize,
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
            min_emit_len: 16,
            max_exports_per_dll: 0,
            harvest_window: 288,
            max_extra_anchors: 9,
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
    pub semantic_role: String,
    pub calling_convention: String,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
}

fn semantic_metadata(name: &str, arch: &str) -> (String, String, Vec<String>, Vec<String>) {
    let cc = if arch == "x64" { "win64" } else { "stdcall" };
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let role = match name.to_ascii_lowercase().as_str() {
        "recv" | "recvfrom" | "internetreadfile" | "winhttpreaddata" => {
            sources.push("network".into()); "source"
        }
        "createprocessa" | "createprocessw" | "winexec" | "shellexecutea" | "shellexecutew" => {
            sinks.push("process_execution".into()); "execution_sink"
        }
        "virtualallocex" | "writeprocessmemory" | "createremotethread" => {
            sinks.push("remote_process".into()); "injection_sink"
        }
        "openprocess" | "openprocesstoken" => { sinks.push("process_access".into()); "access" }
        "regsetvaluea" | "regsetvaluew" => { sinks.push("registry_write".into()); "persistence_sink" }
        "minidumpwritedump" => { sinks.push("credential_dump".into()); "credential_sink" }
        _ => "",
    };
    (role.into(), cc.into(), sources, sinks)
}

impl RawEntry {
    pub fn fixed_count(&self) -> usize {
        self.mask.iter().filter(|&&m| m).count()
    }

    /// Re-score a merged pattern using specificity and collision signals.
    /// Keep the original harvest confidence as an upper bound so a malformed
    /// or overly generic pattern cannot appear more reliable after merging.
    pub fn quality_confidence(&self) -> f64 {
        let len = self.bytes.len().max(1) as f64;
        let fixed_ratio = self.fixed_count() as f64 / len;
        let alias_penalty = 1.0 / (1.0 + (self.aka.len() as f64 / 16.0).sqrt());
        let score = self.confidence * (0.55 + 0.45 * fixed_ratio) * alias_penalty;
        score.clamp(0.0, 1.0)
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
    let arch = match pe.nt_headers.file_header.machine {
        pe_parser::MachineType::Arm => "arm32",
        pe_parser::MachineType::Arm64 => "arm64",
        _ if pe.is_64bit => "x64",
        _ => "x86",
    };
    let mode = if pe.is_64bit { Mode::X64 } else { Mode::X86 };
    let (dll_name, exports) = pe.exports();
    let lib = if lib.is_empty() {
        let raw = dll_name.as_deref().unwrap_or("unknown");
        // Strip a file extension properly ("a.dll" -> "a", but "old" stays).
        let stem = raw
            .rsplit_once('.')
            .map(|(s, _)| s)
            .filter(|s| !s.is_empty())
            .unwrap_or(raw);
        stem.to_ascii_lowercase()
    } else {
        lib.to_ascii_lowercase()
    };
    // Image VA range, for the address heuristic.
    let img_lo = pe.image_base;
    let img_hi = pe.sections.iter().fold(img_lo, |hi, s| {
        let end = pe
            .image_base
            .wrapping_add(s.virtual_address as u64)
            .wrapping_add((s.virtual_size.max(s.raw_data_size)) as u64);
        hi.max(end)
    });

    let exp_range = pe.export_directory();
    let mut out = DllHarvest {
        lib: lib.clone(),
        arch: arch.to_string(),
        ..Default::default()
    };
    out.exports_total = exports.len();

    let mut budget = if cfg.max_exports_per_dll == 0 {
        usize::MAX
    } else {
        cfg.max_exports_per_dll
    };
    for (_, name, rva) in &exports {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let unnamed = name.starts_with("ord_");
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
        let boundary = pe
            .runtime_functions()
            .into_iter()
            .find(|rf| *rva >= rf.begin_rva && *rva < rf.end_rva)
            .and_then(|rf| pe.unwind_info(&rf).map(|_| rf.end_rva))
            .or_else(|| {
                exports
                    .iter()
                    .filter_map(|(_, _, other)| (*other > *rva).then_some(*other))
                    .min()
            });
        let harvested = if arch == "arm32" || arch == "arm64" {
            let section_limit = pe
                .sections
                .iter()
                .filter_map(|s| {
                    let end = s.virtual_address.checked_add(s.raw_data_size)?;
                    (*rva >= s.virtual_address && *rva < end && s.is_executable())
                        .then_some((end - *rva) as usize)
                })
                .min();
            let boundary_limit = boundary.map(|end| end.saturating_sub(*rva) as usize);
            let limit = section_limit
                .into_iter()
                .chain(boundary_limit)
                .min()
                .unwrap_or(cfg.max_prefix_len);
            let mut bounded = cfg.clone();
            bounded.max_prefix_len = bounded.max_prefix_len.min(limit);
            #[cfg(feature = "arm-capstone")]
            {
                harvest_arm_with_capstone(data, off, *rva, arch, &bounded)
                    .or_else(|_| harvest_fixed_width(data, off, &bounded))
            }
            #[cfg(not(feature = "arm-capstone"))]
            {
                harvest_fixed_width(data, off, &bounded)
            }
        } else {
            let mut bounded = cfg.clone();
            if let Some(end_rva) = boundary {
                let distance = end_rva.saturating_sub(*rva) as usize;
                bounded.harvest_window = bounded.harvest_window.min(distance);
                bounded.max_prefix_len = bounded.max_prefix_len.min(distance);
            }
            harvest_function(data, off, *rva, mode, img_lo, img_hi, &bounded)
        };
        match harvested {
            Ok(Some(parts)) => {
                for mut e in parts {
                    // Interior parts carry a "+0x.." suffix from harvest.
                    e.name = if e.name.is_empty() {
                        name.clone()
                    } else {
                        format!("{name}{}", e.name)
                    };
                    e.lib = lib.clone();
                    e.arch = arch.to_string();
                    let (role, cc, sources, sinks) = semantic_metadata(&e.name, &e.arch);
                    e.semantic_role = role;
                    e.calling_convention = cc;
                    e.sources = sources;
                    e.sinks = sinks;
                    out.entries.push(e);
                }
            }
            Ok(None) => out.skipped_thunk += 1,
            Err(DropReason::Short) => out.skipped_short += 1,
            Err(DropReason::Loose) => out.skipped_loose += 1,
            Err(DropReason::Decode) => out.skipped_decode += 1,
        }
        if unnamed {
            out.skipped_unnamed += 1;
        }
    }
    Ok(out)
}

/// Conservative ARM/ARM64 fallback. The x86 decoder cannot be used for PE
/// images of these architectures, so retain fixed-width instruction bytes and
/// avoid masking values without an architecture-aware decoder. This produces
/// useful exact signatures without inventing unsafe relocation rules.
fn harvest_fixed_width(
    data: &[u8],
    off: usize,
    cfg: &HarvestConfig,
) -> Result<Option<Vec<RawEntry>>, DropReason> {
    let width = 4usize;
    let available = data.get(off..).ok_or(DropReason::Decode)?;
    let len = (cfg.max_prefix_len / width * width).min(available.len() / width * width);
    if len < cfg.min_emit_len.max(width) {
        return Err(DropReason::Short);
    }
    let bytes = available[..len].to_vec();
    let mask = vec![true; len];
    Ok(Some(vec![RawEntry {
        lib: String::new(),
        name: String::new(),
        aka: Vec::new(),
        arch: String::new(),
        bytes,
        mask,
        min_len: len,
        confidence: cfg.conf_long,
        semantic_role: String::new(),
        calling_convention: String::new(),
        sources: Vec::new(),
        sinks: Vec::new(),
    }]))
}

#[cfg(feature = "arm-capstone")]
fn harvest_arm_with_capstone(
    data: &[u8],
    off: usize,
    rva: u32,
    arch: &str,
    cfg: &HarvestConfig,
) -> Result<Option<Vec<RawEntry>>, DropReason> {
    use capstone_ffi::{best_engine_for, Arch, Mode};

    let (decoder_arch, mode) = if arch == "arm64" {
        (Arch::ARM64, Mode::Mode64)
    } else {
        // PE ARM entries are ARM-state by default. Thumb-specific exports
        // still use the exact fallback until their mode is explicit in the
        // PE metadata; guessing here would create false boundaries.
        (Arch::ARM, Mode::Arm)
    };
    let available = data.get(off..).ok_or(DropReason::Decode)?;
    let max_bytes = cfg.max_prefix_len.min(available.len());
    let engine = best_engine_for(decoder_arch, mode);
    let instructions = engine
        .disasm(&available[..max_bytes], rva as u64, 0)
        .map_err(|_| DropReason::Decode)?;
    let len = instructions.iter().try_fold(0usize, |sum, instruction| {
        sum.checked_add(instruction.size).ok_or(DropReason::Decode)
    })?;
    let len = len.min(max_bytes);
    if len < cfg.min_emit_len.max(4) {
        return Err(DropReason::Short);
    }
    let bytes = available[..len].to_vec();
    Ok(Some(vec![RawEntry {
        lib: String::new(),
        name: String::new(),
        aka: Vec::new(),
        arch: arch.to_string(),
        bytes,
        mask: vec![true; len],
        min_len: len,
        confidence: cfg.conf_long,
    }]))
}

fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    let end = data.get(off..)?.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&data[off..off + end])
        .ok()
        .map(|s| s.to_string())
}

#[derive(Debug)]
enum DropReason {
    Short,
    Loose,
    Decode,
}

/// One decoded instruction inside the harvest window.
struct WindowInsn {
    /// Offset relative to the function start.
    rel: usize,
    /// Raw bytes (masked where address-encoding was detected).
    bytes: Vec<u8>,
    /// Per-byte exactness.
    mask: Vec<bool>,
    /// Direct branch/call target as a function-relative offset, when the
    /// target lands inside the harvest window.
    target_rel: Option<usize>,
}

/// Decode a function starting at file `off` (RVA `rva`) and cut prefix +
/// interior patterns. `Ok(None)` = jump thunk (not a function).
/// `Err` = drop reason (applies to the whole export).
///
/// Interior anchors (branch targets first, then earliest instruction
/// starts) capture the function body the way real FLIRT does with multiple
/// patterns per function: prologues collide across DLLs, interiors rarely do.
fn harvest_function(
    data: &[u8],
    off: usize,
    rva: u32,
    mode: Mode,
    img_lo: u64,
    img_hi: u64,
    cfg: &HarvestConfig,
) -> Result<Option<Vec<RawEntry>>, DropReason> {
    let window = cfg.harvest_window.max(cfg.max_prefix_len);
    let mut recs: Vec<WindowInsn> = Vec::new();
    let mut cur = off;
    let mut va = rva as u64;
    let mut decoded_len = 0usize;
    let mut first = true;
    // Consecutive length-only steps (SIMD/packed opcodes the full decoder
    // does not model). Past a few in a row this is data, not code.
    let mut lde_streak: u32 = 0;

    while decoded_len < window {
        let slice = data.get(cur..).ok_or(DropReason::Decode)?;
        if slice.first() == Some(&0xCC) {
            break; // int3 padding: function (or alignment) ends here.
        }
        let abs_va = img_lo.wrapping_add(va);
        let decoded = decode_mode(slice, abs_va, mode);
        // Thunk: the function IS a single unconditional jump. Only the
        // first instruction can disqualify the whole export.
        if first {
            first = false;
            let is_thunk = match &decoded {
                Ok(insn) => insn.mnemonic.is_unconditional_jump(),
                Err(_) => matches!(slice.first(), Some(0xE9 | 0xEB)),
            };
            if is_thunk {
                return Ok(None);
            }
        }
        let (raw, masked, target_rel): (&[u8], Vec<bool>, Option<usize>) = match decoded {
            Ok(insn)
                if (1..=15).contains(&insn.length)
                    && !matches!(insn.mnemonic, Mnemonic::Unknown) =>
            {
                lde_streak = 0;
                let raw = &slice[..insn.length];
                let mut m = vec![true; insn.length];
                mask_instruction(&insn, raw, mode, img_lo, img_hi, cfg, &mut m);
                let target_rel = insn.branch_target().and_then(|t| {
                    let rel = t.wrapping_sub(img_lo.wrapping_add(rva as u64)) as usize;
                    (rel < window).then_some(rel)
                });
                (raw, m, target_rel)
            }
            _ => {
                // Length-only fallback: keep bytes exact (an address kept
                // fixed risks a false *negative* later, never a positive).
                lde_streak += 1;
                if lde_streak > 4 {
                    break;
                }
                match decode_len(slice, mode) {
                    Ok(len) if (1..=15).contains(&len) && len <= slice.len() => {
                        (&slice[..len], vec![true; len], None)
                    }
                    _ => return Err(DropReason::Decode),
                }
            }
        };
        recs.push(WindowInsn {
            rel: decoded_len,
            bytes: raw.to_vec(),
            mask: masked,
            target_rel,
        });
        decoded_len += raw.len();
        cur += raw.len();
        va = va.wrapping_add(raw.len() as u64);
    }

    if decoded_len < cfg.min_pattern_len {
        return Err(DropReason::Short);
    }

    // Anchor order: entry prefix, branch targets inside the window, then
    // earliest instruction starts. Cap extras; each needs min_emit_len
    // DECODED bytes left (the window is only a decode cap).
    let mut anchors = vec![0usize];
    let mut targets: Vec<usize> = recs.iter().filter_map(|r| r.target_rel).collect();
    targets.sort_unstable();
    targets.dedup();
    for t in targets {
        // NOTE: `t` was bounded by the decode *window*, but decoding may
        // have stopped early (int3); re-check against what was decoded.
        if t != 0 && t < decoded_len && decoded_len - t >= cfg.min_emit_len && !anchors.contains(&t)
        {
            anchors.push(t);
        }
    }
    for r in &recs {
        if anchors.len() > cfg.max_extra_anchors {
            break;
        }
        if r.rel != 0 && decoded_len - r.rel >= cfg.min_emit_len && !anchors.contains(&r.rel) {
            anchors.push(r.rel);
        }
    }

    // Cut up to max_prefix_len bytes per anchor along instruction edges.
    let mut out = Vec::with_capacity(anchors.len());
    let mut seen: Vec<(Vec<u8>, Vec<bool>)> = Vec::with_capacity(anchors.len());
    for (ai, &anchor) in anchors.iter().enumerate() {
        let mut bytes: Vec<u8> = Vec::new();
        let mut mask: Vec<bool> = Vec::new();
        for r in recs.iter().filter(|r| r.rel >= anchor) {
            // Anchor must sit on an instruction start, not mid-instruction.
            if r.rel > anchor && bytes.is_empty() {
                break;
            }
            if bytes.len() + r.bytes.len() > cfg.max_prefix_len {
                break;
            }
            bytes.extend_from_slice(&r.bytes);
            mask.extend_from_slice(&r.mask);
        }
        if bytes.len() < cfg.min_emit_len {
            continue;
        }
        let fixed = mask.iter().filter(|&&m| m).count();
        if fixed < cfg.min_fixed {
            continue;
        }
        if seen.iter().any(|(b, m)| *b == bytes && *m == mask) {
            continue; // same shape twice (e.g. repeated padding): keep one.
        }
        seen.push((bytes.clone(), mask.clone()));
        let confidence = if bytes.len() >= 16 {
            cfg.conf_long
        } else {
            cfg.conf_short
        };
        let min_len = bytes.len();
        out.push(RawEntry {
            lib: String::new(),
            // Interior names carry their offset; the caller sets the base.
            name: if ai == 0 {
                String::new()
            } else {
                format!("+{anchor:#x}")
            },
            aka: Vec::new(),
            arch: String::new(),
            bytes,
            mask,
            min_len,
            confidence,
            semantic_role: String::new(),
            calling_convention: String::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    }
    if out.is_empty() {
        return Err(DropReason::Loose);
    }
    Ok(Some(out))
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
            mem.base.is_none() || matches!(mem.base, Some(Register::Rip | Register::Eip)),
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
            if slot.semantic_role.is_empty() {
                slot.semantic_role = e.semantic_role;
            }
            if slot.calling_convention.is_empty() {
                slot.calling_convention = e.calling_convention;
            }
            for source in e.sources {
                if !slot.sources.contains(&source) {
                    slot.sources.push(source);
                }
            }
            for sink in e.sinks {
                if !slot.sinks.contains(&sink) {
                    slot.sinks.push(sink);
                }
            }
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
        e.confidence = e.quality_confidence();
    }
    out.sort_by(|a, b| a.lib.cmp(&b.lib).then_with(|| a.name.cmp(&b.name)));
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityIssue {
    pub library: String,
    pub name: String,
    pub kind: String,
    pub detail: String,
}

/// Report suspicious PE signature entries without dropping them. This is
/// intended for CI/release review of generated `.fsig` tiers.
pub fn quality_report(entries: &[RawEntry]) -> Vec<QualityIssue> {
    let mut issues = Vec::new();
    let mut patterns = std::collections::HashMap::<(Vec<u8>, Vec<bool>, String), Vec<&RawEntry>>::new();
    for entry in entries {
        let key = (entry.bytes.clone(), entry.mask.clone(), entry.arch.clone());
        patterns.entry(key).or_default().push(entry);
        if entry.bytes.len() < 16 {
            issues.push(QualityIssue {
                library: entry.lib.clone(),
                name: entry.name.clone(),
                kind: "short_pattern".into(),
                detail: format!("{} bytes", entry.bytes.len()),
            });
        }
        if entry.fixed_count() < 8 {
            issues.push(QualityIssue {
                library: entry.lib.clone(),
                name: entry.name.clone(),
                kind: "low_specificity".into(),
                detail: format!("{} fixed bytes", entry.fixed_count()),
            });
        }
        if entry.quality_confidence() < 0.5 {
            issues.push(QualityIssue {
                library: entry.lib.clone(),
                name: entry.name.clone(),
                kind: "low_confidence".into(),
                detail: format!("{:.3}", entry.quality_confidence()),
            });
        }
    }
    for group in patterns.values().filter(|group| group.len() > 1) {
        issues.push(QualityIssue {
            library: group[0].lib.clone(),
            name: group[0].name.clone(),
            kind: "collision".into(),
            detail: group.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>().join(", "),
        });
    }
    issues
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

// ─── Family signatures (malware corpus) ───────────────────────────

/// Extract a malware family name from a quarantine-style file stem.
///
/// Accepts classification-shaped names (`worm.win32.fipp`,
/// `trojan.html.iframe`), strips copy-tool collision suffixes (`_1`),
/// and rejects stems that carry no family information: hash dumps
/// (`virussign.com_<md5>`, bare sha256) and non-classification shapes.
/// Returns `None` when the stem is unusable — such samples must not
/// contribute "sack of potatoes" signatures.
pub fn family_from_stem(stem: &str) -> Option<String> {
    let mut s = stem.trim().to_ascii_lowercase();
    loop {
        match s.rsplit_once('_') {
            Some((base, tail))
                if !tail.is_empty()
                    && tail.len() <= 3
                    && tail.bytes().all(|b| b.is_ascii_digit()) =>
            {
                s = base.to_string();
            }
            _ => break,
        }
    }

    // `<date>_<md5>_<family>` (VirusShare / malware-bazaar dumps): adopt the
    // trailing segment when everything before it looks like a date/hash chunk.
    // Without this the md5 alone triggers the hash-name rejection below and
    // whole corpora would be skipped as "no family info".
    if let Some((head, fam)) = s.rsplit_once('_') {
        if !fam.is_empty() && fam.bytes().all(|b| b.is_ascii_alphanumeric()) {
            let hashish = head.contains('-')
                || head.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 32;
            if hashish && !fam.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(fam.to_string());
            }
        }
    }
    if s.is_empty() {
        return None;
    }
    let hex_run = s.bytes().filter(|b| b.is_ascii_hexdigit()).count();
    if hex_run >= 16 {
        return None; // virussign.com_<md5>, sha-dumps: no family info.
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 3 {
        return None; // require classification.shape.name
    }
    if parts
        .iter()
        .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return None;
    }
    let fam = parts[parts.len() - 1];
    if fam.len() >= 8 && fam.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None; // last part is a hash, not a name
    }
    Some(s)
}

/// Shannon entropy of a byte slice, in bits per byte (0.0..=8.0).
/// Used to reject packed code sections before wasting time on function
/// detection over compressed garbage.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Knobs for family harvesting. Defaults keep the output compact and
/// scan-time cheap: a few entry-prefix patterns per sample, only from
/// substantial functions.
#[derive(Debug, Clone)]
pub struct FamilyConfig {
    pub harvest: HarvestConfig,
    /// At most this many detected functions per sample (largest first).
    pub max_funcs_per_file: usize,
    /// Functions smaller than this are layout noise (stubs, padding).
    pub min_func_len: usize,
    /// Base confidence for a pattern seen in a single sample.
    pub confidence: f64,
    /// Confidence added per extra corroborating sample (same family).
    pub corroborate_bonus: f64,
    /// Confidence ceiling.
    pub corroborate_cap: f64,
    /// Samples whose largest executable section has entropy above this
    /// are treated as packed and skipped entirely (0 disables the gate).
    pub max_code_entropy: f64,
    /// Candidate pool multiplier: harvest this × max_funcs functions,
    /// then keep the best `max_funcs` by pattern quality.
    pub candidate_mult: usize,
}

impl Default for FamilyConfig {
    fn default() -> Self {
        Self {
            harvest: HarvestConfig {
                max_extra_anchors: 0, // entry prefix only
                ..HarvestConfig::default()
            },
            max_funcs_per_file: 8,
            min_func_len: 48,
            confidence: 0.55,
            corroborate_bonus: 0.1,
            corroborate_cap: 0.9,
            max_code_entropy: 7.2,
            candidate_mult: 4,
        }
    }
}

/// Result of family harvesting one sample.
#[derive(Debug, Default)]
pub struct FamilyHarvest {
    pub family: String,
    pub arch: String,
    pub entries: Vec<RawEntry>,
    pub funcs_total: usize,
    pub funcs_used: usize,
}

/// Harvest entry-prefix signatures from detected functions of one sample.
///
/// Function starts come from `func-finder` (prologue scan + recursive
/// descent from the PE entry and export RVAs) — never from raw slicing —
/// then every start goes through the same operand-aware
/// [`harvest_function`] as export harvesting, including thunk rejection.
pub fn harvest_family_pe(
    data: &[u8],
    family: &str,
    sample_key: &str,
    cfg: &FamilyConfig,
) -> Result<FamilyHarvest, String> {
    let pe = PeFile::parse(data).map_err(|e| format!("pe parse: {e:?}"))?;
    let arch_s = if pe.is_64bit { "x64" } else { "x86" };
    let mode = if pe.is_64bit { Mode::X64 } else { Mode::X86 };
    let machine = pe.nt_headers.file_header.machine;
    if !matches!(
        machine,
        pe_parser::MachineType::Amd64 | pe_parser::MachineType::I386
    ) {
        return Err("family harvest: only x86/x64".into());
    }

    // Largest executable raw-backed section: the code container.
    let sec = pe
        .sections
        .iter()
        .filter(|s| s.is_executable() && s.raw_data_size > 0)
        .max_by_key(|s| s.raw_data_size)
        .ok_or("family harvest: no executable section")?;
    let code = sec.raw_data(data);
    if code.is_empty() {
        return Err("family harvest: empty code section".into());
    }
    // Packed samples: high-entropy "code" yields garbage function starts.
    if cfg.max_code_entropy > 0.0 {
        let ent = shannon_entropy(code);
        if ent > cfg.max_code_entropy {
            return Err(format!("family harvest: packed (code entropy {ent:.2})"));
        }
    }
    let sec_file_off = pe
        .rva_to_offset(sec.virtual_address)
        .ok_or("family harvest: section not raw-mapped")?;

    // Seeds for recursive descent, in section-offset space (code_base = 0).
    let mut seeds: Vec<u64> = Vec::new();
    let in_sec = |rva: u32| {
        rva >= sec.virtual_address
            && (rva as u64) < u64::from(sec.virtual_address) + code.len() as u64
    };
    if pe.entry_point != 0 && in_sec(pe.entry_point) {
        seeds.push(u64::from(pe.entry_point - sec.virtual_address));
    }
    let (_, exports) = pe.exports();
    for (_, _, rva) in exports.iter().take(64) {
        if in_sec(*rva) && !seeds.contains(&(u64::from(*rva - sec.virtual_address))) {
            seeds.push(u64::from(*rva - sec.virtual_address));
        }
    }

    let finder_arch = if pe.is_64bit {
        func_finder::Architecture::X86_64
    } else {
        func_finder::Architecture::X86
    };
    let detected = func_finder::FunctionFinder::new(finder_arch)
        .find_all(code, &seeds)
        .map_err(|e| format!("family harvest: function detection: {e}"))?;

    let funcs_total = detected.len();
    let mut candidates: Vec<&func_finder::DetectedFunction> = detected
        .iter()
        .filter(|f| f.size >= cfg.min_func_len)
        .collect();
    // Candidate pool: prefer the largest functions (they carry real logic),
    // but over-select so quality ranking has room to work.
    candidates.sort_by_key(|f| std::cmp::Reverse(f.size));
    candidates.truncate(cfg.max_funcs_per_file.saturating_mul(cfg.candidate_mult));

    // Image VA range for the address heuristic (same fold as harvest_pe).
    let img_lo = pe.image_base;
    let img_hi = pe.sections.iter().fold(img_lo, |hi, s| {
        let end = pe
            .image_base
            .wrapping_add(s.virtual_address as u64)
            .wrapping_add((s.virtual_size.max(s.raw_data_size)) as u64);
        hi.max(end)
    });

    let mut out = FamilyHarvest {
        family: family.to_string(),
        arch: arch_s.to_string(),
        funcs_total,
        ..Default::default()
    };
    // Light-harvest every candidate (entry prefix only — decode cost is
    // bounded by the prefix window), then keep the best `max_funcs` by
    // pattern quality: fixed-byte ratio first, larger functions as tiebreak.
    struct Cand {
        rva: u32,
        size: usize,
        entry: Option<RawEntry>,
        fixed: usize,
    }
    let mut pool: Vec<Cand> = Vec::with_capacity(candidates.len());
    for f in candidates {
        let start = f.start as usize;
        if start >= code.len() {
            continue;
        }
        let rva = sec.virtual_address + start as u32;
        let mut bounded = cfg.harvest.clone();
        let distance = f.size;
        bounded.harvest_window = bounded.harvest_window.min(distance);
        bounded.max_prefix_len = bounded.max_prefix_len.min(distance);
        let entry = match harvest_function(
            data,
            sec_file_off + start,
            rva,
            mode,
            img_lo,
            img_hi,
            &bounded,
        ) {
            Ok(Some(mut parts)) => {
                if parts.len() != 1 {
                    continue;
                }
                let mut e = parts.remove(0);
                e.confidence = cfg.confidence;
                Some(e)
            }
            Ok(None) | Err(_) => None,
        };
        let fixed = entry.as_ref().map_or(0, |e| e.mask.iter().filter(|&&m| m).count());
        pool.push(Cand {
            rva,
            size: f.size,
            entry,
            fixed,
        });
    }
    pool.sort_by_key(|c| {
        (
            std::cmp::Reverse(c.entry.is_some()),
            std::cmp::Reverse(c.fixed),
            std::cmp::Reverse(c.size),
        )
    });
    let mut used = 0usize;
    for c in pool {
        if used >= cfg.max_funcs_per_file {
            break;
        }
        if let Some(mut e) = c.entry {
            e.lib = family.to_string();
            e.arch = arch_s.to_string();
            e.name = if sample_key.is_empty() {
                format!("f_{:x}", c.rva)
            } else {
                format!("f_{:x}@{}", c.rva, sample_key)
            };
            out.entries.push(e);
            used += 1;
        }
    }
    out.funcs_used = used;
    Ok(out)
}

/// Emit `.fsig` text (sorted by caller via [`merge_entries`]).
/// Adds the optional 7th field `aka=a,b` when aliases exist.
pub fn emit_fsig(entries: &[RawEntry]) -> String {    let mut out = Vec::new();
    emit_fsig_into(entries, &mut out).expect("writing to a Vec cannot fail");
    String::from_utf8(out).expect("fsig output is UTF-8")
}

/// Stream `.fsig` text into `w` — same format as [`emit_fsig`], without
/// materializing the whole database as one `String` (the 4.6M-entry harvest
/// is ~760 MB of text).
pub fn emit_fsig_into(entries: &[RawEntry], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    w.write_all("# Generated by fsig-gen — harvested PE export prefixes.\n".as_bytes())?;
    w.write_all("# lib|arch|name|min_len|confidence|hex [|aka=a,b] [|meta=role=...;cc=...;source=...;sink=...]\n".as_bytes())?;
    for e in entries {
        write!(w, "{}|{}|{}|{}|{:.2}|", e.lib, e.arch, e.name, e.min_len, e.confidence)?;
        for (i, (&byte, &fixed)) in e.bytes.iter().zip(e.mask.iter()).enumerate() {
            if i > 0 {
                w.write_all(b" ")?;
            }
            if fixed {
                write!(w, "{byte:02X}")?;
            } else {
                w.write_all(b"??")?;
            }
        }
        if !e.aka.is_empty() {
            write!(w, "|aka={}", e.aka.join(","))?;
        }
        if !e.semantic_role.is_empty()
            || !e.calling_convention.is_empty()
            || !e.sources.is_empty()
            || !e.sinks.is_empty()
        {
            write!(w, "|meta=")?;
            let mut first = true;
            for (key, value) in [
                ("role", e.semantic_role.as_str()),
                ("cc", e.calling_convention.as_str()),
            ] {
                if !value.is_empty() {
                    if !first { w.write_all(b";")?; }
                    write!(w, "{key}={value}")?;
                    first = false;
                }
            }
            for (key, values) in [("source", &e.sources), ("sink", &e.sinks)] {
                if !values.is_empty() {
                    if !first { w.write_all(b";")?; }
                    write!(w, "{key}={}", values.join(","))?;
                    first = false;
                }
            }
        }
        w.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_names_from_stems() {
        // Good classification-shaped stems.
        assert_eq!(
            family_from_stem("worm.win32.fipp"),
            Some("worm.win32.fipp".into())
        );
        assert_eq!(
            family_from_stem("TROJAN.HTML.IFRAME"),
            Some("trojan.html.iframe".into())
        );
        // Copy-tool collision suffixes are stripped.
        assert_eq!(
            family_from_stem("worm.win32.fipp_1"),
            Some("worm.win32.fipp".into())
        );
        assert_eq!(
            family_from_stem("worm.win32.fipp_12"),
            Some("worm.win32.fipp".into())
        );
        // Hash-like stems carry no family info.
        assert_eq!(family_from_stem("virussign.com_fffea3f698adde5f2b88090511c3b20e"), None);
        assert_eq!(
            family_from_stem("9428b1127316a987a7738658b4505d8a93534d3fb5f337ee7dfeb3da75a60444"),
            None
        );
        // Not classification-shaped.
        assert_eq!(family_from_stem("sample"), None);
        assert_eq!(family_from_stem("a.b"), None);
        assert_eq!(family_from_stem("worm.win32."), None);
        assert_eq!(family_from_stem(""), None);
        // Family part that is itself a hash.
        assert_eq!(family_from_stem("worm.win32.01234567"), None);
        assert_eq!(family_from_stem("worm.win32.cafe"), Some("worm.win32.cafe".into()));
        // <date>_<md5>_<family> (VirusShare/malware-bazaar style).
        assert_eq!(
            family_from_stem("2022-12-25_00b480a5f0e137c8d392fed7d9017da7_icedid"),
            Some("icedid".into())
        );
        // Same style, hash-only tail: no family info.
        assert_eq!(family_from_stem("2022-12-25_00b480a5f0e137c8d392fed7d9017da7"), None);
    }

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
        mask_instruction(
            &insn,
            &code,
            Mode::X86,
            0x7FF0_0000,
            0x8000_0000,
            &c,
            &mut m,
        );
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
        mask_instruction(
            &insn,
            &code,
            Mode::X86,
            0x7000_0000,
            0x8000_0000,
            &c,
            &mut m,
        );
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
        mask_instruction(
            &insn,
            &code,
            Mode::X86,
            0x7000_0000,
            0x8000_0000,
            &c,
            &mut m,
        );
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
    fn interior_anchors_cover_branch_targets() {
        // call +3 (target rel 8) ; 3x nop ; 16-byte body ; int3 padding.
        let mut code = vec![
            0xE8, 0x03, 0x00, 0x00, 0x00, // call +3 -> rel 8
            0x90, 0x90, 0x90, // filler
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, // body @8
            0x57, 0x8B, 0x7D, 0x08, 0x8B, 0x75, 0x0C, 0xC3,
        ];
        code.extend(std::iter::repeat_n(0xCC, 64));
        let parts = harvest_function(&code, 0, 0x1000, Mode::X86, 0x400_000, 0x500_000, &cfg())
            .expect("harvest")
            .expect("not a thunk");
        assert!(
            parts.len() >= 3,
            "want prefix + target + grid, got {}",
            parts.len()
        );
        assert!(parts[0].name.is_empty(), "first part is the prefix");
        assert!(
            parts.iter().any(|p| p.name == "+0x8"),
            "branch target anchor missing: {:?}",
            parts.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
        for p in &parts {
            assert!(p.bytes.len() >= 16, "anchor {} too short", p.name);
        }
    }

    #[test]
    fn early_stop_never_underflows_anchors() {
        // call +32 (target rel 37) but int3 wall at rel 13: the target
        // outlives the decoded bytes; anchor math must not underflow.
        let mut code = vec![0xE8, 0x20, 0x00, 0x00, 0x00];
        code.extend([0x90; 8]);
        code.push(0xCC);
        code.extend([0x90; 64]);
        let res = harvest_function(&code, 0, 0x1000, Mode::X86, 0x400_000, 0x500_000, &cfg());
        // 13 decoded bytes < emit floor: clean Loose, no panic.
        assert!(res.is_err(), "expected Loose, got {res:?}");
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
            semantic_role: String::new(),
            calling_convention: String::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
        };
        let merged = merge_entries(vec![
            mk("ZwCreateFile", vec![]),
            mk("NtCreateFile", vec!["X"]),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "ZwCreateFile");
        assert_eq!(merged[0].aka, vec!["NtCreateFile", "X"]);
    }

    #[test]
    fn merge_preserves_semantic_metadata_and_quality_reports_collision() {
        let first = RawEntry {
            lib: "kernel32".into(),
            name: "CreateProcessW".into(),
            aka: Vec::new(),
            arch: "x64".into(),
            bytes: vec![0x48; 16],
            mask: vec![true; 16],
            min_len: 16,
            confidence: 0.8,
            semantic_role: "execution_sink".into(),
            calling_convention: "win64".into(),
            sources: Vec::new(),
            sinks: vec!["process_execution".into()],
        };
        let mut second = first.clone();
        second.name = "CreateProcessA".into();
        second.semantic_role.clear();
        second.sinks.clear();
        let quality = quality_report(&[first.clone(), second.clone()]);
        let merged = merge_entries(vec![first, second]);
        assert_eq!(merged[0].semantic_role, "execution_sink");
        assert_eq!(merged[0].sinks, vec!["process_execution"]);
        assert!(quality.iter().any(|issue| issue.kind == "collision"));
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
            semantic_role: String::new(),
            calling_convention: String::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
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
            semantic_role: "persistence_sink".into(),
            calling_convention: "win64".into(),
            sources: Vec::new(),
            sinks: vec!["registry_write".into()],
        };
        let text = emit_fsig(std::slice::from_ref(&e));
        let line = text.lines().find(|l| !l.starts_with('#')).unwrap();
        assert_eq!(
            line,
            "kernel32|x64|CreateFileW|9|0.80|48 83 EC 28 E8 ?? ?? ?? ??|aka=KBCreate|meta=role=persistence_sink;cc=win64;sink=registry_write"
        );
        let mut streamed = Vec::new();
        emit_fsig_into(&[e], &mut streamed).unwrap();
        assert_eq!(String::from_utf8(streamed).unwrap(), text);
    }
}
