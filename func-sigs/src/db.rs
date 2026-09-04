//! # func-sigs FLIRT database (`.fsig` files)
//!
//! The built-in database lives in `func-sigs/db/*.fsig` and is embedded with
//! `include_str!`, so matching needs no filesystem access and no new
//! dependencies. Each line is one function entry:
//!
//! ```text
//! lib|arch|name|min_len|confidence|hex bytes, `??` = wildcard [|aka=a,b]
//! msvcrt|x86|memcpy|24|0.80|55 8B EC 57 8B 7D ?? 8B 75 ?? 8B 4D ?? F3 A5
//! ```
//!
//! Rules the parser enforces (a bad line is *rejected*, never guessed):
//! - exactly 6 `|`-separated fields, non-empty lib/arch/name;
//! - hex body: even number of nibbles, `??` (any case) for wildcards;
//! - at least [`MIN_PATTERN_LEN`] bytes and [`MIN_CONCRETE_BYTES`] fixed
//!   bytes — shorter/looser patterns false-positive on real code;
//! - `0.0 < confidence <= 1.0`, `min_len >= 1`.
//!
//! Matching is anchored the FLIRT way: the caller is expected to run the
//! scan over executable code (ideally per function body, see `func-finder`);
//! every fixed byte of every entry is verified, wildcards match anything.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Minimum pattern length in bytes (FP guard).
pub const MIN_PATTERN_LEN: usize = 8;
/// Minimum number of fixed (non-wildcard) bytes per entry (FP guard).
pub const MIN_CONCRETE_BYTES: usize = 4;

/// One parsed database entry. Strings are interned to `&'static str` so
/// matches convert into [`crate::FunctionSignature`] without cloning.
pub struct DbEntry {
    /// Pattern bytes (wildcard positions hold `0x00`, see `mask`).
    pub bytes: Vec<u8>,
    /// `true` = position must match exactly.
    pub mask: Vec<bool>,
    pub library: &'static str,
    pub function_name: &'static str,
    pub arch: &'static str,
    pub min_func_len: usize,
    pub confidence: f64,
    /// Alias names (`aka=a,b` 7th field): forwarder chains and merged
    /// cross-DLL duplicates. Informational; matching uses `function_name`.
    pub aka: Vec<&'static str>,
}

impl DbEntry {
    /// Number of fixed bytes (cheap specificity measure).
    pub fn concrete_len(&self) -> usize {
        self.mask.iter().filter(|&&m| m).count()
    }

    /// Verify the entry against `code` at `start`. All bounds checked.
    pub fn matches_at(&self, code: &[u8], start: usize) -> bool {
        if start.saturating_add(self.bytes.len()) > code.len() {
            return false;
        }
        for (i, &b) in self.bytes.iter().enumerate() {
            if self.mask[i] && code[start + i] != b {
                return false;
            }
        }
        true
    }
}

/// A parse rejection: file, line number, reason. Returned in bulk so a bad
/// database fails loudly instead of silently matching less.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbParseError {
    pub file: &'static str,
    pub line: usize,
    pub reason: String,
}

impl std::fmt::Display for DbParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.reason)
    }
}

fn intern(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

/// Parse one `.fsig` text. `file` is only used for error messages.
pub fn parse_fsig(text: &str, file: &'static str) -> (Vec<DbEntry>, Vec<DbParseError>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok(e) => entries.push(e),
            Err(reason) => errors.push(DbParseError { file, line: line_no, reason }),
        }
    }
    (entries, errors)
}

fn parse_line(line: &str) -> Result<DbEntry, String> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 6 && parts.len() != 7 {
        return Err(format!("expected 6 '|' fields (+optional aka=), got {}", parts.len()));
    }
    let (lib, arch, name, min_len_s, conf_s, hex) =
        (parts[0].trim(), parts[1].trim(), parts[2].trim(), parts[3].trim(), parts[4].trim(), parts[5]);
    let mut aka: Vec<&'static str> = Vec::new();
    if parts.len() == 7 {
        let a = parts[6].trim();
        let list = a.strip_prefix("aka=").ok_or_else(|| format!("bad 7th field {a:?}, want aka=a,b"))?;
        if list.is_empty() {
            return Err("empty aka list".to_string());
        }
        for n in list.split(',') {
            let n = n.trim();
            if n.is_empty() || n.contains('|') {
                return Err(format!("bad aka name {n:?}"));
            }
            aka.push(intern(n));
        }
    }
    if lib.is_empty() || arch.is_empty() || name.is_empty() {
        return Err("lib/arch/name must be non-empty".to_string());
    }
    // Real DLL stems contain dots and occasionally spaces
    // (`analog.shell.broker`, `Microsoft.UI.Xaml`); only the `|` separator
    // and control characters are forbidden.
    if lib.contains(|c: char| c == '|' || c.is_control()) {
        return Err(format!("bad lib id {lib:?}"));
    }
    let min_func_len: usize =
        min_len_s.parse().map_err(|_| format!("bad min_len {min_len_s:?}"))?;
    if min_func_len == 0 {
        return Err("min_len must be >= 1".to_string());
    }
    let confidence: f64 =
        conf_s.parse().map_err(|_| format!("bad confidence {conf_s:?}"))?;
    if !(confidence > 0.0 && confidence <= 1.0) {
        return Err(format!("confidence {confidence} out of (0, 1]"));
    }

    let dense: String = hex.split_whitespace().collect();
    if dense.is_empty() || !dense.len().is_multiple_of(2) {
        return Err("hex body must be a non-empty even nibble run".to_string());
    }
    let mut bytes = Vec::with_capacity(dense.len() / 2);
    let mut mask = Vec::with_capacity(dense.len() / 2);
    let raw = dense.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let pair = &raw[i..i + 2];
        if pair.eq_ignore_ascii_case(b"??") {
            bytes.push(0x00);
            mask.push(false);
        } else {
            let s = std::str::from_utf8(pair).map_err(|_| "non-ascii hex".to_string())?;
            let b = u8::from_str_radix(s, 16).map_err(|_| format!("bad hex pair {s:?}"))?;
            bytes.push(b);
            mask.push(true);
        }
        i += 2;
    }
    if bytes.len() < MIN_PATTERN_LEN {
        return Err(format!(
            "pattern too short ({} < {MIN_PATTERN_LEN})",
            bytes.len()
        ));
    }
    let concrete = mask.iter().filter(|&&m| m).count();
    if concrete < MIN_CONCRETE_BYTES {
        return Err(format!(
            "only {concrete} fixed bytes (< {MIN_CONCRETE_BYTES})"
        ));
    }

    Ok(DbEntry {
        bytes,
        mask,
        library: intern(lib),
        function_name: intern(name),
        arch: intern(arch),
        min_func_len,
        confidence,
        aka,
    })
}

// ─── Embedded database ────────────────────────────────────────────────

macro_rules! db_files {
    ($($file:literal),* $(,)?) => {
        &[$(($file, include_str!(concat!("../db/", $file)))),*]
    };
}

/// All shipped `.fsig` files. Add a new file here to extend the database.
const DB_FILES: &[(&str, &str)] = db_files!(
    "crt_x86.fsig",
    "crt_x64.fsig",
    "mingw_gcc.fsig",
    "zlib.fsig",
    "openssl.fsig",
    "curl_img_db.fsig",
    "delphi_vb_mfc.fsig",
    "go.fsig",
    "packers.fsig",
    // NOTE: the machine-harvested `generated.fsig` (~180k entries) is NOT
    // embedded (AV heuristics flag 27 MB blobs inside binaries). It loads at
    // runtime via `load_overlay_file` / `auto_load_overlay`.
);

struct Db {
    entries: Vec<DbEntry>,
    /// First-fixed-byte index: (byte value, position in pattern) -> entries.
    /// Entries whose every byte is a wildcard cannot be indexed and are
    /// rejected by the parser (`MIN_CONCRETE_BYTES`), so this is total.
    index: HashMap<(u8, usize), Vec<usize>>,
    /// Largest first-fixed-byte position (bounds the probe loop).
    max_pos: usize,
    errors: Vec<DbParseError>,
}

fn build_db(files: &[(&'static str, &str)]) -> Db {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (file, text) in files {
        let (mut es, mut errs) = parse_fsig(text, file);
        entries.append(&mut es);
        errors.append(&mut errs);
    }
    let mut index: HashMap<(u8, usize), Vec<usize>> = HashMap::new();
    let mut max_pos = 0usize;
    // Index by the FIRST fixed byte only: one probe per code offset.
    for (idx, e) in entries.iter().enumerate() {
        if let Some(pos) = e.mask.iter().position(|&m| m) {
            max_pos = max_pos.max(pos);
            index.entry((e.bytes[pos], pos)).or_default().push(idx);
        }
    }
    Db { entries, index, max_pos, errors }
}

fn loaded_db() -> &'static Db {
    static DB: OnceLock<Db> = OnceLock::new();
    DB.get_or_init(|| build_db(DB_FILES))
}

// ─── Runtime overlay (machine-harvested database) ─────────────────
//
// The `fsig-gen` harvest (`db/generated.fsig`, ~180k entries) is NOT
// embedded: a 27 MB string blob inside every binary trips antivirus
// heuristics on user machines (observed: `Exploit:Win64/Torkehem!dha` on a
// test binary) and bloats every consumer. Instead it loads from disk once,
// on demand, and is consulted alongside the embedded curated database.

static OVERLAY: std::sync::RwLock<Option<Db>> = std::sync::RwLock::new(None);

/// Load (or replace) the overlay database from `.fsig` text.
/// Strict: any malformed line aborts the whole load with the errors.
pub fn load_overlay_text(text: &str, file: &'static str) -> Result<usize, Vec<DbParseError>> {
    let db = build_db(&[(file, text)]);
    if !db.errors.is_empty() {
        return Err(db.errors);
    }
    let n = db.entries.len();
    *OVERLAY.write().unwrap_or_else(|e| e.into_inner()) = Some(db);
    Ok(n)
}

/// Load (or replace) the overlay database from a `.fsig` file.
pub fn load_overlay_file(path: &std::path::Path) -> Result<usize, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    // The file content must outlive the process: leak once per load.
    let owned: &'static str = Box::leak(text.into_boxed_str());
    load_overlay_text(owned, "generated.fsig").map_err(|errs| {
        let mut s = format!("{} malformed line(s): ", errs.len());
        for e in errs.iter().take(5) {
            s.push_str(&format!("{e}; "));
        }
        s
    })
}

/// Drop the overlay (tests only).
#[cfg(test)]
pub(crate) fn clear_overlay() {
    *OVERLAY.write().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Overlay entry count (0 when not loaded).
pub fn overlay_signature_count() -> usize {
    OVERLAY.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|d| d.entries.len()).unwrap_or(0)
}

/// Candidate overlay path, for applications: `$FREAKRE_GENERATED_SIGS`, else
/// `generated.fsig` next to the current executable, else the in-tree
/// development layouts (`target/debug/../func-sigs/db`, `./func-sigs/db`),
/// else `./generated.fsig`. Returns the first path that exists.
///
/// Deployments should copy `func-sigs/db/generated.fsig` next to the
/// application binary (or point `$FREAKRE_GENERATED_SIGS` at it).
pub fn find_overlay_file() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("FREAKRE_GENERATED_SIGS") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("generated.fsig"));
            // Cargo dev layout: <root>/target/debug/<exe> -> <root>/func-sigs/db/.
            candidates.push(dir.join("../func-sigs/db/generated.fsig"));
            candidates.push(dir.join("../../func-sigs/db/generated.fsig"));
        }
    }
    candidates.push(std::path::PathBuf::from("generated.fsig"));
    candidates.push(std::path::PathBuf::from("func-sigs/db/generated.fsig"));
    candidates.into_iter().find(|p| p.is_file())
}

static AUTO_LOADED: OnceLock<Option<usize>> = OnceLock::new();

/// Load the overlay once via [`find_overlay_file`] (no-op when absent).
/// Safe to call from every consumer at startup; returns the entry count.
pub fn auto_load_overlay() -> Option<usize> {
    *AUTO_LOADED.get_or_init(|| find_overlay_file().and_then(|p| load_overlay_file(&p).ok()))
}

/// All parsed entries (empty when every `.fsig` file is missing — the files
/// are `include_str!`'d, so in practice this is the full database).
pub fn db_entries() -> &'static [DbEntry] {
    &loaded_db().entries
}

/// Rejections collected while loading the embedded database. Non-empty means
/// the shipped database has a malformed line; tests assert it is empty.
pub fn db_load_errors() -> &'static [DbParseError] {
    &loaded_db().errors
}

/// Number of loaded signatures (embedded + overlay).
pub fn db_signature_count() -> usize {
    loaded_db().entries.len() + overlay_signature_count()
}

/// Library ids present in the database (embedded + overlay), sorted.
pub fn db_libraries() -> Vec<&'static str> {
    let mut libs: Vec<&'static str> = loaded_db().entries.iter().map(|e| e.library).collect();
    if let Some(ov) = OVERLAY.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        libs.extend(ov.entries.iter().map(|e| e.library));
    }
    libs.sort_unstable();
    libs.dedup();
    libs
}

/// Resolve a [`DbHit`] to match data. Returns only `'static` / `Copy` data
/// so overlay hits are safe without holding the lock.
pub fn resolve_hit(hit: &DbHit) -> (&'static str, &'static str, usize, usize, f64) {
    if hit.overlay {
        let guard = OVERLAY.read().unwrap_or_else(|e| e.into_inner());
        let e = &guard.as_ref().expect("overlay hit without overlay").entries[hit.entry];
        (e.library, e.function_name, e.bytes.len(), e.min_func_len, e.confidence)
    } else {
        let e = &loaded_db().entries[hit.entry];
        (e.library, e.function_name, e.bytes.len(), e.min_func_len, e.confidence)
    }
}

/// Scan `code` for database entries. `base_offset` is added to match offsets
/// (same convention as [`crate::scan_signatures`]).
///
/// Only offsets `o` with `o % step == 0` are tested. At most `max_matches`
/// matches are returned; callers needing per-function anchoring should slice
/// function bodies first (see `func-finder`).
pub fn scan_db(code: &[u8], base_offset: usize, step: usize, max_matches: usize) -> Vec<DbHit> {
    let mut out = Vec::new();
    if code.is_empty() {
        return out;
    }
    scan_one(loaded_db(), false, code, base_offset, step, max_matches, &mut out);
    if out.len() < max_matches {
        if let Some(ov) = OVERLAY.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            scan_one(ov, true, code, base_offset, step, max_matches, &mut out);
        }
    }
    out
}

fn scan_one(
    db: &Db,
    overlay: bool,
    code: &[u8],
    base_offset: usize,
    step: usize,
    max_matches: usize,
    out: &mut Vec<DbHit>,
) {
    let step = step.max(1);
    if db.entries.is_empty() {
        return;
    }
    let mut offset = 0usize;
    while offset < code.len() && out.len() < max_matches {
        let b = code[offset];
        // Probe: every entry whose first fixed byte sits at this offset.
        // `pos` ranges over pattern positions, so candidate starts vary.
        for pos in 0..=offset.min(db.max_pos) {
            let Some(list) = db.index.get(&(b, pos)) else {
                continue;
            };
            let start = offset - pos;
            if !start.is_multiple_of(step) {
                continue;
            }
            for &idx in list {
                let e = &db.entries[idx];
                if start + e.bytes.len() > code.len() {
                    continue;
                }
                if code.len() - start < e.min_func_len {
                    continue;
                }
                if e.matches_at(code, start) {
                    out.push(DbHit { offset: base_offset + start, entry: idx, overlay });
                    if out.len() >= max_matches {
                        return;
                    }
                }
            }
        }
        offset += 1;
    }
}

/// Degenerate fills used by the shipped-DB false-positive tests (zeros,
/// NOPs, `int3`, `0xFF`, deterministic xorshift64 stream with the same seed
/// the `fsig-gen` harvester validates against). Every shipped pattern must
/// avoid all of them.
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

/// A database hit: match offset plus the entry index. `overlay` selects the
/// runtime overlay database; use [`resolve_hit`] to read the entry (or
/// [`db_entries`] for embedded hits with `overlay == false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbHit {
    pub offset: usize,
    pub entry: usize,
    pub overlay: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# comment line
msvcrt|x86|memcpy|24|0.80|55 8B EC 57 8B 7D ?? 8B 75 ?? 8B 4D ?? F3 A5
bad|line
zlib|x86|short|8|0.5|90 90
wild|x86|loose|8|0.5|?? ?? ?? ?? ?? ?? ?? ??
toolow|x86|t|8|0.0|55 8B EC 83 EC 10 90 90
";

    #[test]
    fn parse_accepts_good_rejects_bad() {
        let (entries, errors) = parse_fsig(SAMPLE, "sample.fsig");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].function_name, "memcpy");
        assert_eq!(entries[0].bytes.len(), 15);
        assert_eq!(entries[0].concrete_len(), 12);
        assert_eq!(errors.len(), 4, "all four bad lines must be reported: {errors:?}");
    }

    #[test]
    fn parse_aka_field() {
        let (entries, errors) = parse_fsig(
            "kernel32|x64|CreateFileW|9|0.80|48 83 EC 28 E8 ?? ?? ?? ??|aka=KBCreate,BaseCreate\n\
             kernel32|x64|Bad|9|0.80|48 83 EC 28 E8 ?? ?? ?? ??|alias=X\n",
            "a.fsig",
        );
        assert!(errors.iter().any(|e| e.line == 2), "bad 7th field must error: {errors:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].aka, vec!["KBCreate", "BaseCreate"]);
    }

    #[test]
    fn matches_at_respects_wildcards_and_bounds() {
        let (entries, _) = parse_fsig(SAMPLE, "s.fsig");
        let e = &entries[0];
        let mut good = vec![0x55, 0x8B, 0xEC, 0x57, 0x8B, 0x7D, 0xAA, 0x8B, 0x75, 0xBB, 0x8B, 0x4D, 0xCC, 0xF3];
        good.push(0xA5);
        assert!(e.matches_at(&good, 0));
        good[6] = 0x00; // wildcard position: any value ok
        assert!(e.matches_at(&good, 0));
        good[0] = 0x00; // fixed position: mismatch
        assert!(!e.matches_at(&good, 0));
        assert!(!e.matches_at(&good, 1)); // overruns
        assert!(!e.matches_at(&[], 0));
    }

    #[test]
    fn shipped_db_loads_without_errors() {
        assert!(
            db_load_errors().is_empty(),
            "malformed .fsig lines: {:?}",
            &db_load_errors()[..db_load_errors().len().min(5)]
        );
    }

    #[test]
    fn shipped_db_is_huge() {
        let n = super::db_signature_count();
        assert!(n >= 400, "database shrunk to {n} entries, want >= 400");
        let libs = super::db_libraries();
        for want in ["msvcrt", "zlib", "openssl", "curl", "go", "delphi", "mingw", "glibc"] {
            assert!(libs.contains(&want), "library {want} missing from {libs:?}");
        }
    }

    #[test]
    fn shipped_db_no_match_on_zeros_nops_random() {
        // Every entry carries >= 4 fixed bytes, so any hit here is a bad
        // pattern. (Also covers the overlay once another test loads it:
        // the harvester pre-validates these exact fills.)
        for (i, fill) in super::validation_fills().iter().enumerate() {
            let hits = super::scan_db(fill, 0, 1, 10_000);
            assert!(hits.is_empty(), "fill {i} matched {:?}", &hits[..hits.len().min(3)]);
        }
    }

    #[test]
    fn shipped_db_finds_embedded_patterns() {
        // Splice three real entries into NOP sleds; all must be found at the
        // exact offsets with the right names.
        let pick = ["rand_lcg", "strlen_repscas", "RC4_set_key_zero"];
        let mut code = vec![0x90u8; 512];
        let mut want = Vec::new();
        let mut off = 64usize;
        for name in pick {
            let e = super::db_entries().iter().find(|e| e.function_name == name).expect(name);
            let mut body = e.bytes.clone();
            // Wildcards stand for addresses: fill with arbitrary bytes.
            for (i, b) in body.iter_mut().enumerate() {
                if !e.mask[i] {
                    *b = 0x42;
                }
            }
            code[off..off + body.len()].copy_from_slice(&body);
            want.push((off, name));
            off += 128;
        }
        let hits = super::scan_db(&code, 0x1000, 1, 100);
        for (off, name) in want {
            assert!(
                hits.iter().any(|h| {
                    h.offset == 0x1000 + off && super::resolve_hit(h).1 == name
                }),
                "missing {name} @ {off:#x} in {hits:?}"
            );
        }
    }

    #[test]
    fn overlay_generated_loads_and_holds_target() {
        // The fsig-gen harvest ships as data (db/generated.fsig), loaded at
        // runtime so no binary embeds the 27 MB blob (AV heuristics flag it).
        let path = std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/db/generated.fsig"
        ));
        let n = super::load_overlay_file(&path).expect("generated.fsig must load");
        assert!(n >= 18_000, "harvest shrunk to {n} entries, want >= 18000");
        assert_eq!(n, super::overlay_signature_count());
        let libs = super::db_libraries();
        for want in ["kernel32", "ntdll", "ucrtbase"] {
            assert!(libs.contains(&want), "overlay library {want} missing");
        }
        // The full database (embedded + overlay) stays clean on degenerate
        // fills: the harvester self-validates, this pins it in-tree.
        for fill in super::validation_fills() {
            let hits = super::scan_db(&fill, 0, 1, 1000);
            assert!(hits.is_empty(), "overlay hit degenerate fill: {hits:?}");
        }
    }
}
