//! fsig-gen driver: harvest PE export prefixes into one `.fsig` file.
//!
//! ```text
//! fsig-gen --out func-sigs/db/generated.fsig --dlls C:\Windows\System32 [--dlls ...]
//! fsig-gen --summary file.fsig            # statistics of an existing base
//! ```
//!
//! - Every `*.dll` (plus explicitly named files like `ntoskrnl.exe`) is
//!   harvested. `api-ms-win-*` / `ext-ms-*` API-set stubs are harvested too
//!   but only to build the API-set → host mapping; their forwarders are never
//!   emitted as entries (their names live in import tables already).
//! - Forwarders (`KERNELBASE.Foo`) resolve against harvested DLLs (same
//!   directory preferred, then every `--dlls` dir); chains cap at 3 hops and
//!   every failure is classified precisely in the forwarder report.
//! - Output is deterministic: inputs sorted + deduped, entries merged and
//!   sorted, all fallback lookups iterate sorted maps.
//! - Robustness: Ctrl+C cancels cleanly (no partial output), the `.fsig` is
//!   written to a temp file and atomically renamed, the forwarder PE byte
//!   cache is bounded by `--max-memory`.

use fsig_gen::{
    emit_fsig_into, family_from_stem, harvest_family_pe, harvest_pe, merge_entries,
    validate_entries, DllHarvest, FamilyConfig, FamilyHarvest, ForwarderRef, HarvestConfig,
    RawEntry,
};
use sha2::Digest;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn usage() -> ! {
    eprintln!(
        "usage: fsig-gen --out <file.fsig> --dlls <dir> [--dlls <dir>...] [--extra <file>...] \
[--recursive] [--jobs <N>] [--no-adaptive] [--max-memory <MB>] [--stats <file.json>] \
[--report-forwarders <file.json>] [--collision-report <file.json>] [--no-apisets]\n\
       fsig-gen --families --out <file.fsig> --dlls <dir> [--against <base.fsig>] \
[--families-max-funcs <N>] [--families-min-len <N>]\n\
       fsig-gen --summary <file.fsig|dir> [--stats <file.json>]"
    );
    std::process::exit(2);
}

// ─── Cancellation (Ctrl+C) ────────────────────────────────────────

pub static CANCELLED: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn install_cancel_handler() {
    // Dependency-free console handler: CTRL_C / CTRL_BREAK set the flag;
    // the batch loops poll it between files and unwind without writing a
    // partial database.
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }
    extern "system" fn handler(ctl: u32) -> i32 {
        // 0=CTRL_C, 1=CTRL_BREAK, 2=CTRL_CLOSE. CLOSE cannot be vetoed, but
        // flagging it still lets us skip the (long) emit phase while the
        // process is being torn down.
        if ctl <= 2 {
            CANCELLED.store(true, Ordering::SeqCst);
            return 1; // handled: default termination suppressed where possible.
        }
        0
    }
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(not(windows))]
fn install_cancel_handler() {}

// ─── Adaptive CPU scheduler ───────────────────────────────────────

/// Target CPU band for the harvest. Above it we shed workers, below we add
/// them back — the generator must keep the machine responsive.
const BAND_HIGH: f64 = 85.0;
const BAND_LOW: f64 = 50.0;
/// Hysteresis: consecutive out-of-band EMA samples required before the
/// worker count changes (prevents constant ±1 flapping).
const STREAK_NEEDED: u32 = 3;
/// Minimum interval between worker-count changes.
const ADJUST_COOLDOWN: Duration = Duration::from_secs(2);

struct AdaptiveJobs {
    current: AtomicUsize,
    max: usize,
    min: usize,
}

impl AdaptiveJobs {
    fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(max.clamp(1, 4)),
            max,
            min: 1,
        }
    }

    fn batch_size(&self) -> usize {
        self.current.load(Ordering::Relaxed).max(1)
    }

    fn get(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
}

#[cfg(windows)]
fn cpu_load_percent() -> Option<f64> {
    // Keep the generator dependency-free. Windows exposes a cheap aggregate
    // counter through GetSystemTimes; the first sample establishes a delta.
    // Called once per batch, the delta spans the whole batch: an accurate
    // batch-average load, for free.
    use std::sync::OnceLock;
    static PREV: OnceLock<std::sync::Mutex<(u64, u64)>> = OnceLock::new();
    let mut idle = 0u64;
    let mut kernel = 0u64;
    let mut user = 0u64;
    unsafe extern "system" {
        fn GetSystemTimes(idle: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    }
    if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
        return None;
    }
    let total = kernel.saturating_add(user);
    let state = PREV.get_or_init(|| std::sync::Mutex::new((idle, total)));
    let mut previous = state.lock().ok()?;
    let di = idle.saturating_sub(previous.0) as f64;
    let dt = total.saturating_sub(previous.1) as f64;
    *previous = (idle, total);
    (dt > 0.0).then_some(((dt - di).max(0.0) / dt * 100.0).clamp(0.0, 100.0))
}

#[cfg(not(windows))]
fn cpu_load_percent() -> Option<f64> {
    None
}

/// CPU bookkeeping shared by the adaptive scheduler and `stats.json`
/// (works with `--no-adaptive` too: sampling costs one syscall per batch).
#[derive(Default)]
struct CpuTracker {
    inner: Mutex<CpuState>,
}

#[derive(Default)]
struct CpuState {
    ema: f64,
    sum: f64,
    samples: u64,
    min: f64,
    max: f64,
    high_streak: u32,
    low_streak: u32,
    last_change: Option<Instant>,
}

impl CpuTracker {
    /// Record one load sample; returns `(ema, high_streak, low_streak,
    /// cooldown_elapsed)` for the scheduler decision.
    fn record(&self, load: f64) -> (f64, u32, u32, bool) {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if s.samples == 0 {
            s.ema = load;
            s.min = load;
            s.max = load;
        } else {
            s.ema = 0.7 * s.ema + 0.3 * load;
            s.min = s.min.min(load);
            s.max = s.max.max(load);
        }
        s.sum += load;
        s.samples += 1;
        if s.ema > BAND_HIGH {
            s.high_streak += 1;
            s.low_streak = 0;
        } else if s.ema < BAND_LOW {
            s.low_streak += 1;
            s.high_streak = 0;
        } else {
            s.high_streak = 0;
            s.low_streak = 0;
        }
        let cooldown_ok = s
            .last_change
            .map(|t| t.elapsed() >= ADJUST_COOLDOWN)
            .unwrap_or(true);
        (s.ema, s.high_streak, s.low_streak, cooldown_ok)
    }

    fn mark_change(&self) {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.last_change = Some(Instant::now());
        s.high_streak = 0;
        s.low_streak = 0;
    }

    fn snapshot(&self) -> CpuStats {
        let s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        CpuStats {
            samples: s.samples,
            avg: if s.samples > 0 {
                s.sum / s.samples as f64
            } else {
                0.0
            },
            min: s.min,
            max: s.max,
            ema: s.ema,
        }
    }
}

/// Pure scheduler decision — separated for unit testing. `Some(next)` when
/// the hysteresis says the worker count must change.
fn next_jobs(
    old: usize,
    max: usize,
    min: usize,
    high_streak: u32,
    low_streak: u32,
    cooldown_ok: bool,
) -> Option<usize> {
    if !cooldown_ok {
        return None;
    }
    if high_streak >= STREAK_NEEDED {
        let next = old.saturating_sub(1).max(min);
        (next != old).then_some(next)
    } else if low_streak >= STREAK_NEEDED {
        let next = old.saturating_add(1).min(max);
        (next != old).then_some(next)
    } else {
        None
    }
}

#[derive(Debug, Default, Serialize)]
struct CpuStats {
    samples: u64,
    avg: f64,
    min: f64,
    max: f64,
    ema: f64,
}

#[derive(Debug, Default, Serialize)]
struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    disk_read_errors: u64,
}

// ─── On-demand PE source with a bounded byte cache ────────────────

/// Lazy PE byte source for forwarder resolution. Phase 1 no longer keeps
/// every image's bytes in RAM (that was tens of GB on big trees); instead
/// targets are loaded on demand through an LRU bounded by `--max-memory`.
struct PeSource {
    /// stem|arch -> path (first seen wins; inputs are sorted, so this is
    /// deterministic).
    paths: HashMap<String, PathBuf>,
    /// stem -> known paths (any arch), pre-sorted.
    stem_paths: HashMap<String, Vec<PathBuf>>,
    /// Unique sorted parent dirs of every input file.
    dirs: Vec<PathBuf>,
    /// Per-stem candidate path lists (same-dir first), memoized.
    cand_cache: HashMap<String, Vec<PathBuf>>,
    /// LRU byte cache keyed by path.
    cache: HashMap<PathBuf, (Vec<u8>, u64)>,
    cache_bytes: usize,
    max_cache_bytes: usize,
    stamp: u64,
    stats: CacheStats,
}

impl PeSource {
    fn new(max_cache_bytes: usize) -> Self {
        Self {
            paths: HashMap::new(),
            stem_paths: HashMap::new(),
            dirs: Vec::new(),
            cand_cache: HashMap::new(),
            cache: HashMap::new(),
            cache_bytes: 0,
            max_cache_bytes,
            stamp: 0,
            stats: CacheStats::default(),
        }
    }

    fn index_paths(&mut self, results: &[(PathBuf, Option<DllHarvest>)]) {
        let mut dirs: HashSet<PathBuf> = HashSet::new();
        for (path, harvest) in results {
            let Some(h) = harvest else { continue };
            let key = path_key(&h.lib, Some(&h.arch));
            self.paths.entry(key).or_insert_with(|| path.clone());
            self.stem_paths
                .entry(h.lib.clone())
                .or_default()
                .push(path.clone());
            if let Some(parent) = path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        self.dirs = dirs.into_iter().collect();
        self.dirs.sort();
    }

    /// Candidate files for a target stem: harvested copies first (sorted,
    /// the same-dir variant first when `from_dir` matches), then
    /// `<input dir>\<stem>.dll` for every input directory.
    fn candidates(&mut self, stem: &str, from_dir: Option<&Path>) -> Vec<PathBuf> {
        if let Some(c) = self.cand_cache.get(stem) {
            return c.clone();
        }
        let mut out: Vec<PathBuf> = Vec::new();
        if let Some(known) = self.stem_paths.get(stem) {
            out.extend(known.iter().cloned());
        }
        for d in &self.dirs {
            let p = d.join(format!("{stem}.dll"));
            if !out.contains(&p) {
                out.push(p);
            }
        }
        // Same directory as the forwarding DLL wins: forwarders almost never
        // cross version boundaries, and siblings pin the matching build.
        if let Some(dir) = from_dir {
            if let Some(pos) = out.iter().position(|p| p.parent() == Some(dir)) {
                let same = out.remove(pos);
                out.insert(0, same);
            }
        }
        self.cand_cache.insert(stem.to_string(), out.clone());
        out
    }

    /// Load a file into the cache (no-op when already cached). Returns false
    /// when the file cannot be read.
    fn ensure(&mut self, path: &Path) -> bool {
        if self.cache.contains_key(path) {
            self.stats.hits += 1;
            return true;
        }
        self.stats.misses += 1;
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                self.stats.disk_read_errors += 1;
                return false;
            }
        };
        self.stamp += 1;
        self.cache_bytes += data.len();
        self.cache.insert(path.to_path_buf(), (data, self.stamp));
        // LRU trim by stamp (insertion order; forwarder resolution is a
        // phase-2 sequential pass, so stamp order == recency order).
        while self.cache_bytes > self.max_cache_bytes && self.cache.len() > 1 {
            let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, (_, st))| *st)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some((d, _)) = self.cache.remove(&oldest) {
                self.cache_bytes -= d.len();
                self.stats.evictions += 1;
            }
        }
        true
    }

    fn get(&self, path: &Path) -> Option<&Vec<u8>> {
        self.cache.get(path).map(|(d, _)| d)
    }
}

// ─── Forwarder resolution with precise failure classes ────────────

/// Every way a forwarder can stay unresolved. The report carries both the
/// class (stable id for aggregation) and a human detail string.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unresolved {
    /// No file for the target stem anywhere in the input set / dirs.
    DllMissing(String),
    /// Files exist but none could be read from disk.
    DllUnreadable(String),
    /// Read but not parseable as PE.
    DllUnparseable(String),
    /// Target is an api-ms-/ext-ms- set without a known host mapping.
    ApiSetUnmapped(String),
    /// `#NNN` beyond the target's export range.
    OrdinalOutOfRange(String, u64),
    /// Named export absent from the target's export table.
    ExportMissing(String, String),
    /// Export exists and points at code, but the harvester dropped it
    /// (data, thunk, too short/loose) — nothing to point at.
    ExportNotHarvestable(String, String),
    /// Forwarder chain revisited a (dll, name) pair.
    Cycle(String, String),
    /// Chain longer than the hop budget.
    DepthExceeded(String, String),
    /// Forwarder target string unparsable (`DLL.Name` / `DLL.#ord`).
    MalformedTarget(String, String),
}

impl Unresolved {
    fn class(&self) -> &'static str {
        match self {
            Unresolved::DllMissing(_) => "dll-missing",
            Unresolved::DllUnreadable(_) => "dll-unreadable",
            Unresolved::DllUnparseable(_) => "dll-unparseable",
            Unresolved::ApiSetUnmapped(_) => "api-set-unmapped",
            Unresolved::OrdinalOutOfRange(..) => "ordinal-out-of-range",
            Unresolved::ExportMissing(..) => "export-missing",
            Unresolved::ExportNotHarvestable(..) => "export-not-harvestable",
            Unresolved::Cycle(..) => "forwarder-cycle",
            Unresolved::DepthExceeded(..) => "chain-depth-exceeded",
            Unresolved::MalformedTarget(..) => "malformed-target",
        }
    }

    fn detail(&self) -> String {
        match self {
            Unresolved::DllMissing(t) => format!("target DLL {t} not found in input set"),
            Unresolved::DllUnreadable(t) => format!("target DLL {t} unreadable from disk"),
            Unresolved::DllUnparseable(t) => format!("target DLL {t} is not a parseable PE"),
            Unresolved::ApiSetUnmapped(t) => {
                format!("target {t} is an API set with no host mapping")
            }
            Unresolved::OrdinalOutOfRange(t, o) => {
                format!("ordinal #{o} out of range in {t}")
            }
            Unresolved::ExportMissing(t, n) => format!("export {n} missing in {t}"),
            Unresolved::ExportNotHarvestable(t, n) => {
                format!("export {n} in {t} exists but is not harvestable code")
            }
            Unresolved::Cycle(t, n) => format!("forwarder cycle at {t}!{n}"),
            Unresolved::DepthExceeded(t, n) => format!("chain depth exceeded at {t}!{n}"),
            Unresolved::MalformedTarget(t, n) => format!("malformed forwarder target {t}!{n}"),
        }
    }
}

/// API-set mapping: `api-ms-*`/`ext-ms-*` stub DLLs contain only forwarders
/// to their hosts; harvesting them gives us the mapping for free (the OS
/// build's own apisetschema, without parsing its binary format).
/// Keyed per arch (hosts are arch-specific) with an any-arch fallback.
#[derive(Default)]
struct ApisetMap {
    per_arch: BTreeMap<(String, String), String>,
    any: BTreeMap<String, String>,
}

fn is_apiset(lib: &str) -> bool {
    lib.starts_with("api-ms-") || lib.starts_with("ext-ms-")
}

impl ApisetMap {
    fn build(harvests: &[(String, String, Vec<ForwarderRef>)]) -> Self {
        let mut m = Self::default();
        for (lib, arch, forwarders) in harvests {
            if !is_apiset(lib) {
                continue;
            }
            // Sorted input order → first forwarder is deterministic.
            for f in forwarders {
                m.per_arch
                    .entry((lib.clone(), arch.clone()))
                    .or_insert_with(|| f.target_dll.clone());
                m.any
                    .entry(lib.clone())
                    .or_insert_with(|| f.target_dll.clone());
            }
        }
        m
    }

    /// Resolve an API-set name to a host DLL stem (following chained sets,
    /// e.g. an `ext-ms-*` set hosted by an `api-ms-*` set).
    fn host(&self, set: &str, arch: &str) -> Option<String> {
        let mut cur = set.to_string();
        for _ in 0..3 {
            let next = self
                .per_arch
                .get(&(cur.clone(), arch.to_string()))
                .or_else(|| self.any.get(&cur))?;
            if *next == cur {
                return None; // self-hosted: no mapping
            }
            cur = next.clone();
            if !is_apiset(&cur) {
                return Some(cur);
            }
        }
        None
    }
}

/// Resolve one forwarder chain to real code entries.
///
/// Lookup order per target stem: harvested copies (same dir as the forwarder
/// first), then `<input dir>\<stem>.dll`. Inside a target, an exact
/// `(stem, from_arch)` index is preferred, then other arches of the same
/// stem, then (last resort, deterministic) any library exporting the name.
#[allow(clippy::too_many_arguments)]
fn resolve_forwarder(
    fw: &ForwarderRef,
    from_arch: &str,
    from_dir: Option<&Path>,
    src: &mut PeSource,
    apisets: &ApisetMap,
    by_dll: &BTreeMap<String, BTreeMap<String, Vec<u32>>>,
    entries: &[RawEntry],
    hops: usize,
    path: &mut Vec<(String, String)>,
) -> Result<Vec<RawEntry>, Unresolved> {
    if hops == 0 {
        return Err(Unresolved::DepthExceeded(
            fw.target_dll.clone(),
            fw.target_name.clone(),
        ));
    }
    // Transparent API-set substitution: mapping does not consume a hop.
    let mut target_dll = fw.target_dll.clone();
    if is_apiset(&target_dll) {
        target_dll = apisets
            .host(&target_dll, from_arch)
            .ok_or_else(|| Unresolved::ApiSetUnmapped(fw.target_dll.clone()))?;
    }

    let key = (target_dll.clone(), fw.target_name.clone());
    if path.contains(&key) {
        return Err(Unresolved::Cycle(key.0, key.1));
    }
    path.push(key);
    let result = resolve_forwarder_inner(
        fw,
        from_arch,
        from_dir,
        &target_dll,
        src,
        apisets,
        by_dll,
        entries,
        hops,
        path,
    );
    path.pop();
    result
}

#[allow(clippy::too_many_arguments)]
fn resolve_forwarder_inner(
    fw: &ForwarderRef,
    from_arch: &str,
    from_dir: Option<&Path>,
    target_dll: &str,
    src: &mut PeSource,
    _apisets: &ApisetMap,
    by_dll: &BTreeMap<String, BTreeMap<String, Vec<u32>>>,
    entries: &[RawEntry],
    hops: usize,
    path: &mut Vec<(String, String)>,
) -> Result<Vec<RawEntry>, Unresolved> {
    let candidates = src.candidates(target_dll, from_dir);
    if candidates.is_empty() {
        return Err(Unresolved::DllMissing(fw.target_dll.clone()));
    }
    // Read + parse the first candidate that works.
    let (data, cand_path) = {
        let mut got = None;
        for cand in &candidates {
            if src.ensure(cand) {
                if let Some(d) = src.get(cand) {
                    got = Some((d.clone(), cand.clone()));
                    break;
                }
            }
        }
        got.ok_or_else(|| Unresolved::DllUnreadable(fw.target_dll.clone()))?
    };
    let pe = pe_parser::PeFile::parse(&data)
        .map_err(|_| Unresolved::DllUnparseable(fw.target_dll.clone()))?;
    let (_, exports) = pe.exports();
    // Target by name or by #ordinal.
    let (rva, real_name) = if let Some(ord) = fw
        .target_name
        .strip_prefix('#')
        .and_then(|s| s.parse::<u64>().ok())
    {
        let found = exports
            .iter()
            .find(|(o, _, _)| *o as u64 == ord)
            .map(|&(_, ref n, r)| (r, n.clone()));
        match found {
            Some(v) => v,
            None => return Err(Unresolved::OrdinalOutOfRange(fw.target_dll.clone(), ord)),
        }
    } else {
        let found = exports
            .iter()
            .find(|(_, n, _)| n == &fw.target_name)
            .map(|&(_, _, r)| (r, fw.target_name.clone()));
        match found {
            Some(v) => v,
            None => {
                return Err(Unresolved::ExportMissing(
                    fw.target_dll.clone(),
                    fw.target_name.clone(),
                ))
            }
        }
    };
    // Chained forwarder? Recurse, keeping the ORIGINAL caller name outside.
    if let Some((er, es)) = pe.export_directory() {
        if rva >= er && (rva - er) < es {
            let off = pe.rva_to_offset(rva).ok_or_else(|| {
                Unresolved::MalformedTarget(fw.target_dll.clone(), fw.target_name.clone())
            })?;
            let end = data
                .get(off..)
                .and_then(|s| s.iter().position(|&b| b == 0))
                .ok_or_else(|| {
                    Unresolved::MalformedTarget(fw.target_dll.clone(), fw.target_name.clone())
                })?;
            let s = std::str::from_utf8(&data[off..off + end]).map_err(|_| {
                Unresolved::MalformedTarget(fw.target_dll.clone(), fw.target_name.clone())
            })?;
            let (dll, name) = fsig_gen::parse_forwarder(s).ok_or_else(|| {
                Unresolved::MalformedTarget(fw.target_dll.clone(), fw.target_name.clone())
            })?;
            let next = ForwarderRef {
                from_name: fw.from_name.clone(),
                target_dll: dll,
                target_name: name,
            };
            let dir = cand_path.parent().map(Path::to_path_buf);
            return resolve_forwarder(
                &next,
                from_arch,
                dir.as_deref(),
                src,
                _apisets,
                by_dll,
                entries,
                hops - 1,
                path,
            );
        }
    }
    // Real code: fetch entries by the implementation's base name.
    let found = lookup_entries(by_dll, entries, target_dll, from_arch, &real_name);
    if found.is_empty() {
        return Err(Unresolved::ExportNotHarvestable(
            fw.target_dll.clone(),
            real_name,
        ));
    }
    Ok(found)
}

/// Deterministic entry lookup: exact stem+arch, then other arches of the
/// stem, then (last resort) any library exporting the name.
fn lookup_entries(
    by_dll: &BTreeMap<String, BTreeMap<String, Vec<u32>>>,
    entries: &[RawEntry],
    target_dll: &str,
    from_arch: &str,
    name: &str,
) -> Vec<RawEntry> {
    let fetch = |idxs: &Vec<u32>| -> Vec<RawEntry> {
        idxs.iter().map(|&i| entries[i as usize].clone()).collect()
    };
    let exact = format!("{}|{}", target_dll, from_arch);
    if let Some(names) = by_dll.get(&exact) {
        if let Some(idxs) = names.get(name) {
            return fetch(idxs);
        }
    }
    // Other arches of the same stem (sorted for determinism).
    let prefix = format!("{}|", target_dll);
    let mut arch_keys: Vec<&String> = by_dll
        .keys()
        .filter(|k| k.starts_with(&prefix) && *k != &exact)
        .collect();
    arch_keys.sort();
    for k in arch_keys {
        if let Some(idxs) = by_dll[k].get(name) {
            return fetch(idxs);
        }
    }
    // Cross-library fallback, first library in sorted order.
    for names in by_dll.values() {
        if let Some(idxs) = names.get(name) {
            return fetch(idxs);
        }
    }
    Vec::new()
}

fn path_key(lib: &str, arch: Option<&str>) -> String {
    format!("{}|{}", lib, arch.unwrap_or("unknown"))
}

// ─── .fsig summary (--summary) ────────────────────────────────────

#[derive(Debug, Default, Serialize)]
struct SummaryStats {
    file: String,
    data_lines: u64,
    comment_lines: u64,
    empty_lines: u64,
    malformed: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    malformed_samples: Vec<String>,
    libraries: usize,
    architectures: BTreeMap<String, u64>,
    entries_with_aliases: u64,
    total_aliases: u64,
    max_aliases: u64,
    pattern_len_min: usize,
    pattern_len_max: usize,
    pattern_len_avg: f64,
    fixed_min: usize,
    fixed_max: usize,
    fixed_avg: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    top_libraries: Vec<TopLib>,
}

#[derive(Debug, Serialize)]
struct TopLib {
    lib: String,
    entries: u64,
}

struct SummaryAcc {
    libraries: BTreeMap<String, u64>,
    architectures: BTreeMap<String, u64>,
    entries_with_aliases: u64,
    total_aliases: u64,
    max_aliases: u64,
    len_sum: u64,
    len_min: usize,
    len_max: usize,
    fixed_sum: u64,
    fixed_min: usize,
    fixed_max: usize,
    malformed_samples: Vec<String>,
}

impl SummaryAcc {
    fn new() -> Self {
        Self {
            libraries: BTreeMap::new(),
            architectures: BTreeMap::new(),
            entries_with_aliases: 0,
            total_aliases: 0,
            max_aliases: 0,
            len_sum: 0,
            len_min: usize::MAX,
            len_max: 0,
            fixed_sum: 0,
            fixed_min: usize::MAX,
            fixed_max: 0,
            malformed_samples: Vec::new(),
        }
    }

    fn finish(mut self, file: &str, counts: &LineCounts, top: usize) -> SummaryStats {
        let n = counts.data_lines.max(1) as f64;
        let mut top_libs: Vec<TopLib> = self
            .libraries
            .iter()
            .map(|(l, c)| TopLib {
                lib: l.clone(),
                entries: *c,
            })
            .collect();
        top_libs.sort_by(|a, b| b.entries.cmp(&a.entries).then(a.lib.cmp(&b.lib)));
        top_libs.truncate(top);
        SummaryStats {
            file: file.to_string(),
            data_lines: counts.data_lines,
            comment_lines: counts.comment_lines,
            empty_lines: counts.empty_lines,
            malformed: counts.malformed,
            malformed_samples: std::mem::take(&mut self.malformed_samples),
            libraries: self.libraries.len(),
            architectures: self.architectures,
            entries_with_aliases: self.entries_with_aliases,
            total_aliases: self.total_aliases,
            max_aliases: self.max_aliases,
            pattern_len_min: if self.len_min == usize::MAX {
                0
            } else {
                self.len_min
            },
            pattern_len_max: self.len_max,
            pattern_len_avg: self.len_sum as f64 / n,
            fixed_min: if self.fixed_min == usize::MAX {
                0
            } else {
                self.fixed_min
            },
            fixed_max: self.fixed_max,
            fixed_avg: self.fixed_sum as f64 / n,
            top_libraries: top_libs,
        }
    }
}

struct LineCounts {
    data_lines: u64,
    comment_lines: u64,
    empty_lines: u64,
    malformed: u64,
}

/// Validate one `.fsig` line the way the func-sigs parser does and collect
/// pattern stats. Returns `Err(reason)` for malformed lines.
fn summarize_line(line: &str, acc: &mut SummaryAcc) -> Result<(), String> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 6 && parts.len() != 7 {
        return Err(format!("expected 6 '|' fields, got {}", parts.len()));
    }
    let (lib, arch, name, min_len_s, conf_s, hex) =
        (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
    if lib.is_empty() || arch.is_empty() || name.is_empty() {
        return Err("lib/arch/name must be non-empty".into());
    }
    let min_len: usize = min_len_s
        .parse()
        .map_err(|_| format!("bad min_len {min_len_s:?}"))?;
    if min_len == 0 {
        return Err("min_len must be >= 1".into());
    }
    let conf: f64 = conf_s
        .parse()
        .map_err(|_| format!("bad confidence {conf_s:?}"))?;
    if !(conf > 0.0 && conf <= 1.0) {
        return Err(format!("confidence {conf} out of (0, 1]"));
    }
    let mut n_bytes = 0usize;
    let mut fixed = 0usize;
    for tok in hex.split_whitespace() {
        if tok == "??" {
            n_bytes += 1;
            continue;
        }
        if tok.len() != 2 || !tok.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("bad hex token {tok:?}"));
        }
        n_bytes += 1;
        fixed += 1;
    }
    if n_bytes < 8 {
        return Err(format!("pattern too short ({n_bytes} < 8)"));
    }
    if fixed < 4 {
        return Err(format!("only {fixed} fixed bytes (< 4)"));
    }
    let mut aliases = 0usize;
    if parts.len() == 7 {
        let list = parts[6]
            .strip_prefix("aka=")
            .ok_or_else(|| format!("bad 7th field {:?}, want aka=a,b", parts[6]))?;
        if list.is_empty() {
            return Err("empty aka list".into());
        }
        for n in list.split(',') {
            if n.is_empty() || n.contains('|') {
                return Err(format!("bad aka name {n:?}"));
            }
            aliases += 1;
        }
    }
    *acc.libraries.entry(lib.to_string()).or_insert(0) += 1;
    *acc.architectures.entry(arch.to_string()).or_insert(0) += 1;
    if aliases > 0 {
        acc.entries_with_aliases += 1;
        acc.total_aliases += aliases as u64;
        acc.max_aliases = acc.max_aliases.max(aliases as u64);
    }
    acc.len_sum += n_bytes as u64;
    acc.len_min = acc.len_min.min(n_bytes);
    acc.len_max = acc.len_max.max(n_bytes);
    acc.fixed_sum += fixed as u64;
    acc.fixed_min = acc.fixed_min.min(fixed);
    acc.fixed_max = acc.fixed_max.max(fixed);
    Ok(())
}

/// Stream a `.fsig` file, counting every line kind. Memory stays O(1):
/// the 760 MB base is read line-by-line.
fn summarize_file(
    path: &Path,
    acc: &mut SummaryAcc,
    sample_limit: usize,
) -> std::io::Result<LineCounts> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display()))
    })?;
    let mut counts = LineCounts {
        data_lines: 0,
        comment_lines: 0,
        empty_lines: 0,
        malformed: 0,
    };
    for (idx, raw) in BufReader::with_capacity(1 << 20, std::io::BufReader::new(f))
        .lines()
        .enumerate()
    {
        let raw = raw?;
        let line = raw.trim();
        if line.is_empty() {
            counts.empty_lines += 1;
        } else if line.starts_with('#') {
            counts.comment_lines += 1;
        } else {
            counts.data_lines += 1;
            if let Err(reason) = summarize_line(line, acc) {
                counts.malformed += 1;
                if acc.malformed_samples.len() < sample_limit {
                    acc.malformed_samples.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        idx + 1,
                        reason
                    ));
                }
            }
        }
    }
    Ok(counts)
}

/// `--summary` mode: statistics of one `.fsig` file or every `.fsig` in a
/// directory (aggregated). Prints JSON to stdout; `--stats` saves it too.
fn run_summary(target: &Path, stats_path: Option<&Path>) -> i32 {
    let mut acc = SummaryAcc::new();
    let mut total = LineCounts {
        data_lines: 0,
        comment_lines: 0,
        empty_lines: 0,
        malformed: 0,
    };
    let mut files: Vec<PathBuf> = Vec::new();
    if target.is_dir() {
        match std::fs::read_dir(target) {
            Ok(rd) => {
                for ent in rd.flatten() {
                    let p = ent.path();
                    if p.extension()
                        .map(|e| e.eq_ignore_ascii_case("fsig"))
                        .unwrap_or(false)
                    {
                        files.push(p);
                    }
                }
            }
            Err(e) => {
                eprintln!("cannot list {}: {e}", target.display());
                return 1;
            }
        }
        files.sort();
        if files.is_empty() {
            eprintln!("no .fsig files in {}", target.display());
            return 1;
        }
    } else {
        files.push(target.to_path_buf());
    }
    for f in &files {
        match summarize_file(f, &mut acc, 5) {
            Ok(c) => {
                eprintln!(
                    "{}: {} entries ({} malformed)",
                    f.display(),
                    c.data_lines,
                    c.malformed
                );
                total.data_lines += c.data_lines;
                total.comment_lines += c.comment_lines;
                total.empty_lines += c.empty_lines;
                total.malformed += c.malformed;
            }
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        }
    }
    let label = files
        .len()
        .checked_sub(1)
        .map(|_| target.display().to_string())
        .unwrap_or_else(|| files[0].display().to_string());
    let summary = acc.finish(&label, &total, 20);
    match serde_json::to_string_pretty(&summary) {
        Ok(json) => {
            println!("{json}");
            if let Some(p) = stats_path {
                if let Err(e) = write_json_file(p, json.as_bytes()) {
                    eprintln!("cannot write {}: {e}", p.display());
                    return 1;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("cannot serialize summary: {e}");
            1
        }
    }
}

// ─── Atomic file output ───────────────────────────────────────────

/// Write `bytes` to `<path>.tmp-<pid>` and atomically rename over `path`,
/// so a crash never leaves a partially written database.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_sibling(path);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Stream `write` output to a temp sibling and atomically rename.
fn write_stream_atomic(
    path: &Path,
    write: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let tmp = temp_sibling(path);
    {
        let mut f = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?);
        write(&mut f)?;
        f.flush()?;
        let file = f.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn temp_sibling(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tmp-{}", path.display(), std::process::id()))
}

fn write_json_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    write_file_atomic(path, bytes)
}

// ─── Reports / stats ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ForwarderReport {
    from_lib: String,
    from_name: String,
    target_dll: String,
    target_name: String,
    class: &'static str,
    reason: String,
}

#[derive(Debug, Serialize)]
struct Stats {
    files_seen: usize,
    images_harvested: usize,
    exports: usize,
    raw_entries: usize,
    skipped_read: u64,
    skipped_read_permission_denied: u64,
    skipped_parse: u64,
    walk_dirs_denied: u64,
    walk_dirs_unreadable: u64,
    api_sets_harvested: usize,
    api_set_targets_resolved: u64,
    forwarders: usize,
    forwarders_resolved: usize,
    forwarders_unresolved: usize,
    forwarders_unresolved_by_class: BTreeMap<String, usize>,
    merged_patterns: usize,
    patterns_with_aliases: usize,
    max_aliases: usize,
    collision_groups: usize,
    kept_patterns: usize,
    dropped_self_fp: usize,
    jobs: usize,
    adaptive: bool,
    max_memory_mb: usize,
    cache: CacheStats,
    cpu: CpuStats,
    cancelled: bool,
    elapsed_secs: f64,
}

#[derive(Debug, Serialize)]
struct CollisionReport {
    merged_patterns: usize,
    patterns_with_aliases: usize,
    max_aliases: usize,
    alias_histogram: BTreeMap<usize, usize>,
    groups: Vec<CollisionGroup>,
}

#[derive(Debug, Serialize)]
struct CollisionGroup {
    arch: String,
    primary_lib: String,
    primary_name: String,
    aliases: Vec<String>,
    pattern: String,
}

fn collision_report(entries: &[RawEntry]) -> CollisionReport {
    const MAX_GROUPS: usize = 1000;

    let mut histogram = BTreeMap::new();
    for e in entries {
        *histogram.entry(e.aka.len()).or_insert(0) += 1;
    }
    let mut groups: Vec<&RawEntry> = entries.iter().filter(|e| !e.aka.is_empty()).collect();
    groups.sort_by(|a, b| {
        b.aka
            .len()
            .cmp(&a.aka.len())
            .then_with(|| a.arch.cmp(&b.arch))
            .then_with(|| a.lib.cmp(&b.lib))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.bytes.cmp(&b.bytes))
            .then_with(|| a.mask.cmp(&b.mask))
    });
    let groups = groups
        .into_iter()
        .take(MAX_GROUPS)
        .map(|e| CollisionGroup {
            arch: e.arch.clone(),
            primary_lib: e.lib.clone(),
            primary_name: e.name.clone(),
            aliases: e.aka.clone(),
            pattern: pattern_hex(&e.bytes, &e.mask),
        })
        .collect();
    CollisionReport {
        merged_patterns: entries.len(),
        patterns_with_aliases: entries.iter().filter(|e| !e.aka.is_empty()).count(),
        max_aliases: entries.iter().map(|e| e.aka.len()).max().unwrap_or(0),
        alias_histogram: histogram,
        groups,
    }
}

fn pattern_hex(bytes: &[u8], mask: &[bool]) -> String {
    bytes
        .iter()
        .zip(mask)
        .map(|(&byte, &fixed)| {
            if fixed {
                format!("{byte:02X}")
            } else {
                "??".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── main ─────────────────────────────────────────────────────────

struct SkipLog {
    read: u64,
    read_denied: u64,
    parse: u64,
    samples: Vec<String>,
}

impl SkipLog {
    fn new() -> Self {
        Self {
            read: 0,
            read_denied: 0,
            parse: 0,
            samples: Vec::new(),
        }
    }

    fn push(&mut self, line: String) {
        // First 20 problems keep their detail; the rest are counters so the
        // log stays readable on 45k-file runs.
        if self.samples.len() < 20 {
            self.samples.push(line);
        }
    }
}

#[derive(Debug, Serialize)]
struct FamilyStats {
    files_input: usize,
    files_with_family: usize,
    files_no_family: usize,
    files_harvested: usize,
    files_failed: usize,
    files_dup_skipped: usize,
    files_label_conflict: usize,
    unique_binaries: usize,
    funcs_detected: u64,
    funcs_used: u64,
    patterns_raw: u64,
    patterns_unique: u64,
    cross_family_dropped: u64,
    lib_like_dropped: u64,
    fills_dropped: u64,
    emitted: u64,
    families: u64,
    top_families: Vec<(String, u64)>,
    elapsed_secs: f64,
}

/// `--families` pipeline: malware-family identification signatures.
///
/// Quality contract (why the output is not a "sack of potatoes"):
/// 1. Function starts come from `func-finder` (prologue scan + recursive
///    descent), never raw slicing; thunks and sub-48-byte stubs are skipped.
/// 2. Patterns are operand-aware entry prefixes (same masking as exports).
/// 3. A pattern shared by samples of *different* families is dropped —
///    it is shared CRT/packer code, useless for family attribution.
/// 4. Every survivor passes the degenerate-fill self-FP gate.
/// 5. Same-family corroboration raises confidence (bounded).
///
/// `FamilyJob` groups the `--families` CLI knobs so the worker signature stays
/// under clippy's argument-count gate.
struct FamilyJob<'a> {
    files: &'a [PathBuf],
    pool: &'a rayon::ThreadPool,
    cpu: &'a std::sync::Arc<CpuTracker>,
    adaptive: &'a AdaptiveJobs,
    no_adaptive: bool,
    fam_max_funcs: usize,
    fam_min_len: usize,
    against_path: Option<&'a Path>,
    out: &'a Path,
    stats_path: Option<&'a Path>,
    started: Instant,
}

#[allow(clippy::too_many_arguments)]
fn run_family_mode(
    job: FamilyJob<'_>,
) -> i32 {
    let files = job.files;
    let pool = job.pool;
    let cpu = job.cpu;
    let adaptive = job.adaptive;
    let no_adaptive = job.no_adaptive;
    let fam_max_funcs = job.fam_max_funcs;
    let fam_min_len = job.fam_min_len;
    let against_path = job.against_path;
    let out = job.out;
    let stats_path = job.stats_path;
    let started = job.started;
    let fam_cfg = FamilyConfig {
        max_funcs_per_file: fam_max_funcs,
        min_func_len: fam_min_len,
        ..FamilyConfig::default()
    };
    eprintln!(
        "family mode: max-funcs={} min-func-len={} confidence={:.2} entropy-gate={:.2}{}",
        fam_cfg.max_funcs_per_file,
        fam_cfg.min_func_len,
        fam_cfg.confidence,
        fam_cfg.max_code_entropy,
        against_path.map(|_| " against=loaded").unwrap_or_default()
    );

    // Reference base for the junk gate: family patterns matching legit
    // library code (CRT stubs, .NET headers, packer runtime) are useless —
    // they already match the system base and carry no family signal.
    let against_patterns: Option<std::collections::HashSet<(u64, String)>> =
        against_path.and_then(|p| match std::fs::read(p) {
            Ok(text) => {
                let set: std::collections::HashSet<(u64, String)> =
                    String::from_utf8_lossy(&text)
                        .lines()
                        .filter_map(|line| {
                        let line = line.strip_prefix('#').map_or(line, |l| l);
                        let fields: Vec<&str> = line.split('|').collect();
                        if fields.len() < 6 {
                            return None;
                        }
                        Some((fnv1a_hex(fields[5]), fields[1].to_ascii_lowercase()))
                    })
                    .collect();
                eprintln!("family mode: against-base loaded: {} patterns", set.len());
                Some(set)
            }
            Err(e) => {
                eprintln!("family mode: cannot read --against {}: {e} (gate disabled)", p.display());
                None
            }
        });

    let mut family_files: Vec<(usize, &PathBuf, String)> = Vec::new();
    let mut no_family = 0usize;
    for (idx, f) in files.iter().enumerate() {
        match f
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(family_from_stem)
        {
            Some(fam) => family_files.push((idx, f, fam)),
            None => no_family += 1,
        }
    }
    eprintln!(
        "family mode: {} files with family names, {} skipped (no usable family in name)",
        family_files.len(),
        no_family
    );

    let mut harvested: Vec<(usize, FamilyHarvest)> = Vec::new();
    let mut failed = 0usize;
    let mut failed_samples: Vec<String> = Vec::new();
    let mut funcs_total: u64 = 0;
    let mut funcs_used: u64 = 0;
    let mut patterns_raw: u64 = 0;
    let mut sha_seen: std::collections::HashMap<[u8; 32], (usize, String)> =
        std::collections::HashMap::new();
    let mut dup_samples = 0usize;
    let mut label_conflicts = 0usize;

    for chunk in family_files.chunks(adaptive.batch_size()) {
        if CANCELLED.load(Ordering::SeqCst) {
            break;
        }
        let batch: Vec<_> = pool.install(|| {
            chunk
                .par_iter()
                .map(|(idx, path, fam)| match std::fs::read(path) {
                    Err(e) => (*idx, *path, fam.clone(), Err(format!("read: {e:?}"))),
                    Ok(data) => {
                        let digest = sha2::Sha256::digest(&data).into();
                        match harvest_family_pe(&data, fam, &hex_short(&digest), &fam_cfg) {
                            Ok(h) => (*idx, *path, fam.clone(), Ok((digest, h))),
                            Err(e) => (*idx, *path, fam.clone(), Err(e)),
                        }
                    }
                })
                .collect()
        });
        for (idx, path, fam, res) in batch {
            match res {
                Ok((digest, h)) => match sha_seen.get(&digest) {
                    // Same bytes already harvested: keep the first family's
                    // attribution; conflicting labels mean the corpus is
                    // inconsistent — do not let the copy add corroboration
                    // (and never let it poison the first sample as
                    // "cross-family").
                    Some((first_idx, first_fam)) => {
                        dup_samples += 1;
                        if first_fam != &fam {
                            label_conflicts += 1;
                            eprintln!(
                                "dup {}: same bytes as #{} but family {fam} != {first_fam} — copy ignored",
                                path.display(),
                                first_idx
                            );
                        }
                        let _ = first_idx;
                    }
                    None => {
                        sha_seen.insert(digest, (idx, fam));
                        funcs_total += h.funcs_total as u64;
                        funcs_used += h.funcs_used as u64;
                        patterns_raw += h.entries.len() as u64;
                        eprintln!(
                            "{}: family={} funcs={}/{} entries={}",
                            path.display(),
                            h.family,
                            h.funcs_used,
                            h.funcs_total,
                            h.entries.len()
                        );
                        harvested.push((idx, h));
                    }
                },
                Err(e) => {
                    failed += 1;
                    failed_samples.push(format!("skip {}: {}", path.display(), e));
                }
            }
        }
        if let Some(load) = cpu_load_percent() {
            let (ema, high, low, cd) = cpu.record(load);
            if !no_adaptive {
                if let Some(next) =
                    next_jobs(adaptive.get(), adaptive.max, adaptive.min, high, low, cd)
                {
                    adaptive.current.store(next, Ordering::Relaxed);
                    eprintln!("adaptive jobs: cpu_ema={ema:.1}% jobs={next}");
                    cpu.mark_change();
                }
            }
        }
    }
    for s in &failed_samples {
        eprintln!("{s}");
    }
    eprintln!(
        "family mode: dedup — {} duplicate samples ignored, {} label conflicts, {} unique binaries",
        dup_samples,
        label_conflicts,
        sha_seen.len()
    );
    if CANCELLED.load(Ordering::SeqCst) {
        eprintln!("cancelled by user — no output written");
        return 130;
    }

    // Aggregate by pattern; cross-family and duplicate occurrences resolve
    // here. Deterministic: family_files is in sorted-file order and batches
    // are collected in order.
    /// Pattern key → (family, sample indices, merged entry).
    type SeenMap = std::collections::HashMap<(Vec<u8>, Vec<bool>, String), (String, std::collections::HashSet<usize>, RawEntry)>;
    let mut seen: SeenMap = std::collections::HashMap::new();
    let mut cross_keys: std::collections::HashSet<
        (Vec<u8>, Vec<bool>, String),
    > = std::collections::HashSet::new();
    let harvested_count = harvested.len();
    for (idx, mut h) in std::mem::take(&mut harvested) {
        for mut e in std::mem::take(&mut h.entries) {
            let key = (std::mem::take(&mut e.bytes), std::mem::take(&mut e.mask), e.arch.clone());
            match seen.get_mut(&key) {
                Some((fam, files, _slot)) => {
                    if *fam != e.lib {
                        cross_keys.insert(key);
                        continue;
                    }
                    files.insert(idx);
                    // Keep the earliest occurrence verbatim.
                    let _ = e;
                }
                None => {
                    // `e` had its bytes moved out into `key` — restore them.
                    e.bytes = key.0.clone();
                    e.mask = key.1.clone();
                    seen.insert(key, (e.lib.clone(), std::iter::once(idx).collect(), e));
                }
            }
        }
    }
    let mut cross_family_dropped: u64 = 0;
    let mut lib_like_dropped: u64 = 0;
    let mut kept: Vec<RawEntry> = Vec::with_capacity(seen.len());
    for (key, (_fam, files, mut e)) in seen {
        if cross_keys.contains(&key) {
            cross_family_dropped += 1;
            continue;
        }
        if let Some(against) = &against_patterns {
            if against.contains(&(fnv1a_hex(&pattern_text(&e)), e.arch.to_ascii_lowercase())) {
                lib_like_dropped += 1;
                continue;
            }
        }
        e.confidence = (fam_cfg.confidence
            + fam_cfg.corroborate_bonus * (files.len().saturating_sub(1) as f64))
        .min(fam_cfg.corroborate_cap);
        kept.push(e);
    }
    let patterns_unique = kept.len() as u64;

    let (validated, fills_dropped_names) = validate_entries(kept);
    let fills_dropped = fills_dropped_names.len() as u64;
    let mut entries = validated;
    entries.sort_by(|a, b| a.lib.cmp(&b.lib).then_with(|| a.name.cmp(&b.name)));

    if let Err(e) = write_stream_atomic(out, |w| emit_fsig_into(&entries, w)) {
        eprintln!("cannot write {}: {e}", out.display());
        return 1;
    }

    let mut per_family: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    for e in &entries {
        *per_family.entry(e.lib.as_str()).or_insert(0) += 1;
    }
    let mut top: Vec<(String, u64)> = per_family
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(20);

    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "family mode done: emitted={} patterns from {} families (raw={} unique={} cross-family-dropped={} lib-like-dropped={} fills-dropped={}) in {:.1}s",
        entries.len(),
        per_family_count(&entries),
        patterns_raw,
        patterns_unique,
        cross_family_dropped,
        lib_like_dropped,
        fills_dropped,
        elapsed
    );
    eprintln!("top families:");
    for (fam, n) in &top {
        eprintln!("  {fam}: {n}");
    }

    if let Some(sp) = stats_path {
        let stats = FamilyStats {
            files_input: files.len(),
            files_with_family: family_files.len(),
            files_no_family: no_family,
            files_harvested: harvested_count,
            files_failed: failed,
            files_dup_skipped: dup_samples,
            files_label_conflict: label_conflicts,
            unique_binaries: sha_seen.len(),
            funcs_detected: funcs_total,
            funcs_used,
            patterns_raw,
            patterns_unique,
            cross_family_dropped,
            lib_like_dropped,
            fills_dropped,
            emitted: entries.len() as u64,
            families: per_family_count(&entries) as u64,
            top_families: top,
            elapsed_secs: elapsed,
        };
        match serde_json::to_vec_pretty(&stats) {
            Ok(bytes) => {
                if let Err(e) = write_json_file(sp, &bytes) {
                    eprintln!("cannot write stats {}: {e}", sp.display());
                }
            }
            Err(e) => eprintln!("cannot serialize family stats: {e}"),
        }
    }
    0
}

fn per_family_count(entries: &[RawEntry]) -> usize {
    let mut set = std::collections::HashSet::new();
    for e in entries {
        set.insert(e.lib.as_str());
    }
    set.len()
}

/// First 8 hex chars of a SHA-256 digest — short sample provenance tag.
fn hex_short(digest: &[u8; 32]) -> String {
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// FNV-1a 64 over a string (pattern text / arch keys for the against set).
fn fnv1a_hex(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Render a pattern exactly as it appears in `.fsig` text (`AB ?? CD`).
fn pattern_text(e: &RawEntry) -> String {
    let mut s = String::with_capacity(e.bytes.len() * 3);
    for (i, (&byte, &fixed)) in e.bytes.iter().zip(e.mask.iter()).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        if fixed {
            s.push_str(&format!("{byte:02X}"));
        } else {
            s.push_str("??");
        }
    }
    s
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // --summary mode: read statistics of an existing base, no harvesting.
    let mut summary_target: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut dll_dirs: Vec<PathBuf> = Vec::new();
    let mut extra: Vec<PathBuf> = Vec::new();
    let mut recursive = false;
    let mut jobs = 0usize;
    let mut no_adaptive = false;
    let mut max_memory_mb = 512usize;
    let mut stats_path: Option<PathBuf> = None;
    let mut forwarder_report_path: Option<PathBuf> = None;
    let mut collision_report_path: Option<PathBuf> = None;
    let mut no_apisets = false;
    let mut families_mode = false;
    let mut fam_max_funcs = 8usize;
    let mut fam_min_len = 48usize;
    let mut against_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--summary" => {
                i += 1;
                summary_target = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--dlls" => {
                i += 1;
                if let Some(d) = args.get(i) {
                    dll_dirs.push(PathBuf::from(d));
                }
            }
            "--recursive" => {
                recursive = true;
            }
            "--jobs" => {
                i += 1;
                jobs = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--no-adaptive" => {
                no_adaptive = true;
            }
            "--max-memory" => {
                i += 1;
                let mb: usize = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
                max_memory_mb = mb.max(16);
            }
            "--extra" => {
                i += 1;
                if let Some(f) = args.get(i) {
                    extra.push(PathBuf::from(f));
                }
            }
            "--stats" => {
                i += 1;
                stats_path = args.get(i).map(PathBuf::from);
            }
            "--report-forwarders" => {
                i += 1;
                forwarder_report_path = args.get(i).map(PathBuf::from);
            }
            "--collision-report" => {
                i += 1;
                collision_report_path = args.get(i).map(PathBuf::from);
            }
            "--no-apisets" => {
                no_apisets = true;
            }
            "--families" => {
                families_mode = true;
            }
            "--families-max-funcs" => {
                i += 1;
                fam_max_funcs = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(8).max(1);
            }
            "--families-min-len" => {
                i += 1;
                fam_min_len = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(48).max(8);
            }
            "--against" => {
                i += 1;
                against_path = args.get(i).map(PathBuf::from);
            }
            _ => usage(),
        }
        i += 1;
    }
    if let Some(target) = summary_target {
        let code = run_summary(&target, stats_path.as_deref());
        std::process::exit(code);
    }
    let out = out.unwrap_or_else(|| usage());
    if dll_dirs.is_empty() && extra.is_empty() {
        usage();
    }

    let started = Instant::now();
    install_cancel_handler();

    let cfg = HarvestConfig::default();
    let jobs = if jobs == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        jobs
    }
    .clamp(1, 64);
    let adaptive = AdaptiveJobs::new(jobs);
    let cpu = std::sync::Arc::new(CpuTracker::default());
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("cannot create Rayon thread pool: {e}");
            std::process::exit(1);
        });
    eprintln!(
        "harvesting with jobs={} adaptive={} max-memory={}MB",
        jobs, !no_adaptive, max_memory_mb
    );

    // Collect candidate files (sorted + deduped for determinism; case-folded
    // dedup so the same DLL never enters twice through differing case).
    let mut walk_stats = WalkStats::default();
    fn walk(dir: &Path, recursive: bool, into: &mut Vec<PathBuf>, st: &mut WalkStats) {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    st.dirs_denied += 1;
                } else {
                    st.dirs_unreadable += 1;
                    st.samples
                        .push(format!("cannot list {}: {e}", dir.display()));
                }
                return;
            }
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                if recursive {
                    // Do not follow Windows junctions/reparse points. They
                    // commonly mirror System32 into ProgramData/Users and
                    // otherwise cause duplicate scans and access-denied spam.
                    if ent
                        .metadata()
                        .map(|m| !m.file_type().is_symlink())
                        .unwrap_or(false)
                        && !is_ignored_directory(&p)
                    {
                        walk(&p, recursive, into, st);
                    }
                }
                continue;
            }
            let has_pe_extension = p
                .extension()
                .map(|e| {
                    e.eq_ignore_ascii_case("dll")
                        || e.eq_ignore_ascii_case("sys")
                        || e.eq_ignore_ascii_case("exe")
                        || e.eq_ignore_ascii_case("ocx")
                        || e.eq_ignore_ascii_case("cpl")
                        || e.eq_ignore_ascii_case("ax")
                })
                .unwrap_or(false);
            // Malware collections often rename samples with a dotted family
            // name plus hash rather than a real extension. Probe every file
            // with an unknown name so those PE samples are not silently
            // reported as zero inputs.
            let is_unknown_name_pe = !has_pe_extension && is_probable_pe(&p);
            if has_pe_extension || is_unknown_name_pe {
                into.push(p);
            }
        }
    }

    fn is_probable_pe(path: &Path) -> bool {
        let Ok(mut file) = std::fs::File::open(path) else {
            return false;
        };
        let mut dos = [0u8; 64];
        if std::io::Read::read_exact(&mut file, &mut dos).is_err()
            || dos[0] != b'M'
            || dos[1] != b'Z'
        {
            return false;
        }
        let pe_offset = u32::from_le_bytes([dos[0x3c], dos[0x3d], dos[0x3e], dos[0x3f]]) as u64;
        if pe_offset > 16 * 1024 * 1024
            || std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(pe_offset)).is_err()
        {
            return false;
        }
        let mut signature = [0u8; 4];
        std::io::Read::read_exact(&mut file, &mut signature).is_ok() && signature == *b"PE\0\0"
    }

    fn is_ignored_directory(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "application data"
                        | "appdata"
                        | "cookies"
                        | "history"
                        | "local settings"
                        | "nethood"
                        | "printhood"
                        | "recent"
                        | "sendto"
                        | "temporary internet files"
                        | "start menu"
                        | "программы"
                        | "systemdata"
                        | "windows defender advanced threat protection"
                        | "classification"
                        | "cyber"
                        | "datacollection"
                        | "dlp"
                        | "downloads"
                        | "platform"
                        | "sensecm"
                        | "sensenndr"
                        | "temp"
                        | "all users"
                        | "default user"
                        | "главное меню"
                        | "рабочий стол"
                        | "документы"
                        | "шаблоны"
                )
            })
            .unwrap_or(false)
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for dir in &dll_dirs {
        walk(dir, recursive, &mut files, &mut walk_stats);
    }
    files.extend(extra);
    // Sort + dedup (byte-exact first, then case-insensitive on the folded
    // path so `C:\X.dll` and `c:\x.dll` collapse on Windows).
    files.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    files.dedup_by(|a, b| a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase());
    let api_sets_skipped = if no_apisets {
        files.retain(|p| {
            !p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| is_apiset(&s.to_ascii_lowercase()))
                .unwrap_or(false)
        });
        0
    } else {
        0
    };
    let _ = api_sets_skipped;
    eprintln!(
        "input: {} files ({} dirs denied, {} unreadable)",
        files.len(),
        walk_stats.dirs_denied,
        walk_stats.dirs_unreadable
    );
    for s in &walk_stats.samples {
        eprintln!("{s}");
    }

    // ─── Family mode: signatures for malware-family identification ────
    // Runs a dedicated pipeline (no exports/forwarders/API-sets): function
    // detection → operand-aware entry prefixes → cross-family junk drop →
    // corroboration-boosted confidence → degenerate-fill self-FP gate.
    if families_mode {
        let code = run_family_mode(FamilyJob {
            files: &files,
            pool: &pool,
            cpu: &cpu,
            adaptive: &adaptive,
            no_adaptive,
            fam_max_funcs,
            fam_min_len,
            against_path: against_path.as_deref(),
            out: &out,
            stats_path: stats_path.as_deref(),
            started,
        });
        std::process::exit(code);
    }

    // Phase 1: harvest every image. Bytes are NOT retained — the forwarder
    // phase loads targets on demand through the bounded cache.
    let (harvested, skip): (Vec<(PathBuf, Option<DllHarvest>)>, SkipLog) = pool.install(|| {
        let mut results = Vec::with_capacity(files.len());
        let mut skip = SkipLog::new();
        for chunk in files.chunks(adaptive.batch_size()) {
            if CANCELLED.load(Ordering::SeqCst) {
                break;
            }
            let batch: Vec<_> = chunk
                .par_iter()
                .map(|f| match std::fs::read(f) {
                    Err(e) => (f.clone(), None, Err(format!("read: {e:?}"))),
                    Ok(data) => {
                        let stem = f
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_ascii_lowercase();
                        match harvest_pe(&data, &stem, &cfg) {
                            Ok(h) => {
                                eprintln!(
                                    "{}: exports={} entries={} fwd={} (thunk={} short={} loose={} data={} dec={} unnamed={})",
                                    stem,
                                    h.exports_total,
                                    h.entries.len(),
                                    h.forwarders.len(),
                                    h.skipped_thunk,
                                    h.skipped_short,
                                    h.skipped_loose,
                                    h.skipped_data,
                                    h.skipped_decode,
                                    h.skipped_unnamed
                                );
                                (f.clone(), Some(h), Ok(()))
                            }
                            Err(e) => (f.clone(), None, Err(format!("pe parse: {e}"))),
                        }
                    }
                })
                .collect();
            for (path, harvest, err) in batch {
                match (harvest, err) {
                    (h, Ok(())) => results.push((path, h)),
                    (_, Err(e)) => {
                        // Classify read vs parse failures.
                        let detail = e.split_once(": ").map(|x| x.1).unwrap_or(&e).to_string();
                        if e.starts_with("read:") {
                            skip.read += 1;
                        } else {
                            skip.parse += 1;
                        }
                        skip.push(format!("skip {}: {}", path.display(), detail));
                    }
                }
            }
            // CPU stats once per batch; adaptation only when enabled.
            if let Some(load) = cpu_load_percent() {
                let (ema, high, low, cd) = cpu.record(load);
                if !no_adaptive {
                    if let Some(next) = next_jobs(
                        adaptive.get(),
                        adaptive.max,
                        adaptive.min,
                        high,
                        low,
                        cd,
                    ) {
                        adaptive.current.store(next, Ordering::Relaxed);
                        eprintln!("adaptive jobs: cpu_ema={ema:.1}% jobs={next}");
                        cpu.mark_change();
                    }
                }
            }
        }
    eprintln!(
        "phase 1 done: harvested={} read_errors={} (denied={}) parse_errors={}",
        results.len(),
        skip.read,
        skip.read_denied,
        skip.parse
    );
    for s in &skip.samples {
        eprintln!("{s}");
    }
    (results, skip)
});
    if CANCELLED.load(Ordering::SeqCst) {
        eprintln!("cancelled by user — no output written");
        write_stats(
            stats_path.as_deref(),
            &Stats {
                files_seen: files.len(),
                images_harvested: harvested.len(),
                exports: 0,
                raw_entries: 0,
                skipped_read: 0,
                skipped_read_permission_denied: 0,
                skipped_parse: 0,
                walk_dirs_denied: walk_stats.dirs_denied,
                walk_dirs_unreadable: walk_stats.dirs_unreadable,
                api_sets_harvested: 0,
                api_set_targets_resolved: 0,
                forwarders: 0,
                forwarders_resolved: 0,
                forwarders_unresolved: 0,
                forwarders_unresolved_by_class: BTreeMap::new(),
                merged_patterns: 0,
                patterns_with_aliases: 0,
                max_aliases: 0,
                collision_groups: 0,
                kept_patterns: 0,
                dropped_self_fp: 0,
                jobs,
                adaptive: !no_adaptive,
                max_memory_mb,
                cache: CacheStats::default(),
                cpu: cpu.snapshot(),
                cancelled: true,
                elapsed_secs: started.elapsed().as_secs_f64(),
            },
        );
        std::process::exit(130);
    }

    // Index file locations + directories for on-demand loading.
    let mut src = PeSource::new(max_memory_mb * 1024 * 1024);
    src.index_paths(&harvested);

    // Separate API-set stubs (mapping sources) from real libraries.
    let mut harvests: Vec<DllHarvest> = Vec::new();
    let mut api_set_count = 0usize;
    for (_, h) in harvested {
        if let Some(h) = h {
            if is_apiset(&h.lib) {
                api_set_count += 1;
                if no_apisets {
                    continue;
                }
            }
            harvests.push(h);
        }
    }
    harvests.sort_by(|a, b| a.lib.cmp(&b.lib).then(a.arch.cmp(&b.arch)));

    // Move entries out (no clone): by_dll indexes into this vector. Each
    // harvest records its slice so (lib, arch) attribution survives; the
    // (lib, arch, forwarders) triples feed pending + the API-set map.
    let mut entries: Vec<RawEntry> = Vec::new();
    let mut slices: Vec<(usize, usize, String, String)> = Vec::new();
    let mut harvest_forwarders: Vec<(String, String, Vec<ForwarderRef>)> = Vec::new();
    let mut exports_total = 0usize;
    for h in harvests {
        exports_total += h.exports_total;
        harvest_forwarders.push((h.lib.clone(), h.arch.clone(), h.forwarders));
        let start = entries.len();
        entries.extend(h.entries);
        slices.push((start, entries.len(), h.lib, h.arch));
    }

    // Phase 2: resolve forwarders (chains up to 3 hops, on-demand PE loads).
    let mut by_dll: BTreeMap<String, BTreeMap<String, Vec<u32>>> = BTreeMap::new();
    for (start, end, lib, arch) in &slices {
        let key = path_key(lib, Some(arch));
        let slot = by_dll.entry(key).or_default();
        for (i, e) in entries[*start..*end].iter().enumerate() {
            slot.entry(e.name.clone())
                .or_default()
                .push((start + i) as u32);
        }
    }
    let apisets = ApisetMap::build(&harvest_forwarders);
    let mut all: Vec<RawEntry> = entries;
    let mut resolved = 0usize;
    let mut unresolved = 0usize;
    let mut unresolved_by_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut unresolved_report: Vec<ForwarderReport> = Vec::new();
    let mut api_set_targets_resolved = 0u64;
    let pending: Vec<(String, String, ForwarderRef)> = {
        let mut out = Vec::new();
        for (lib, arch, forwarders) in &harvest_forwarders {
            if is_apiset(lib) {
                continue; // names live in import tables; hosts already harvested
            }
            for f in forwarders {
                out.push((lib.clone(), arch.clone(), f.clone()));
            }
        }
        out
    };
    for (from_lib, from_arch, fw) in &pending {
        match resolve_forwarder(
            fw,
            from_arch,
            None,
            &mut src,
            &apisets,
            &by_dll,
            &all,
            3,
            &mut Vec::new(),
        ) {
            Ok(found) => {
                for (offset, mut e) in found.into_iter().enumerate() {
                    // Preserve the implementation's interior names under the
                    // name imported from the forwarder DLL.
                    let implementation_name = e.name.clone();
                    e.name = if offset == 0 {
                        fw.from_name.clone()
                    } else {
                        format!("{}+0x{:X}", fw.from_name, offset)
                    };
                    e.aka.insert(0, implementation_name);
                    e.lib = from_lib.clone();
                    all.push(e);
                }
                resolved += 1;
                if is_apiset(&fw.target_dll) {
                    api_set_targets_resolved += 1;
                }
            }
            Err(u) => {
                unresolved += 1;
                *unresolved_by_class
                    .entry(u.class().to_string())
                    .or_insert(0) += 1;
                unresolved_report.push(ForwarderReport {
                    from_lib: from_lib.clone(),
                    from_name: fw.from_name.clone(),
                    target_dll: fw.target_dll.clone(),
                    target_name: fw.target_name.clone(),
                    class: u.class(),
                    reason: u.detail(),
                });
            }
        }
    }
    eprintln!(
        "forwarders: resolved={resolved} (api-set targets: {api_set_targets_resolved}) unresolved={unresolved}"
    );
    for (class, n) in &unresolved_by_class {
        eprintln!("  unresolved {class}: {n}");
    }
    let cache_stats = std::mem::take(&mut src.stats);

    if CANCELLED.load(Ordering::SeqCst) {
        eprintln!("cancelled by user — no output written");
        std::process::exit(130);
    }

    // Phase 3: merge, self-validate, emit (atomically).
    let pre_merge_entries = all.len();
    let merged = merge_entries(all);
    let collision = collision_report(&merged);
    eprintln!("merged patterns: {}", merged.len());
    let (kept, dropped) = validate_entries(merged);
    eprintln!(
        "self-FP validation: kept={} dropped={}",
        kept.len(),
        dropped.len()
    );
    for d in dropped.iter().take(20) {
        eprintln!("  dropped {d}");
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let emit_result = write_stream_atomic(&out, |w| fsig_gen::emit_fsig_into(&kept, w));
    if let Err(e) = emit_result {
        eprintln!("cannot write {}: {e}", out.display());
        std::process::exit(1);
    }
    if let Some(path) = forwarder_report_path {
        write_json_file(
            &path,
            serde_json::to_vec_pretty(&unresolved_report)
                .unwrap_or_default()
                .as_slice(),
        )
        .unwrap_or_else(|e| eprintln!("cannot write {}: {e}", path.display()));
    }
    if let Some(path) = collision_report_path {
        write_json_file(
            &path,
            serde_json::to_vec_pretty(&collision)
                .unwrap_or_default()
                .as_slice(),
        )
        .unwrap_or_else(|e| eprintln!("cannot write {}: {e}", path.display()));
    }
    write_stats(
        stats_path.as_deref(),
        &Stats {
            files_seen: files.len(),
            images_harvested: slices.len(),
            exports: exports_total,
            raw_entries: pre_merge_entries,
            skipped_read: skip.read,
            skipped_read_permission_denied: skip.read_denied,
            skipped_parse: skip.parse,
            walk_dirs_denied: walk_stats.dirs_denied,
            walk_dirs_unreadable: walk_stats.dirs_unreadable,
            api_sets_harvested: api_set_count,
            api_set_targets_resolved,
            forwarders: pending.len(),
            forwarders_resolved: resolved,
            forwarders_unresolved: unresolved,
            forwarders_unresolved_by_class: unresolved_by_class,
            merged_patterns: collision.merged_patterns,
            patterns_with_aliases: collision.patterns_with_aliases,
            max_aliases: collision.max_aliases,
            collision_groups: collision.groups.len(),
            kept_patterns: kept.len(),
            dropped_self_fp: dropped.len(),
            jobs,
            adaptive: !no_adaptive,
            max_memory_mb,
            cache: cache_stats,
            cpu: cpu.snapshot(),
            cancelled: false,
            elapsed_secs: started.elapsed().as_secs_f64(),
        },
    );
    eprintln!(
        "wrote {} entries -> {} ({:.1}s)",
        kept.len(),
        out.display(),
        started.elapsed().as_secs_f64()
    );
}

fn write_stats(path: Option<&Path>, stats: &Stats) {
    if let Some(path) = path {
        match serde_json::to_vec_pretty(stats) {
            Ok(data) => {
                if let Err(e) = write_json_file(path, &data) {
                    eprintln!("cannot write {}: {e}", path.display());
                }
            }
            Err(e) => eprintln!("cannot serialize {}: {e}", path.display()),
        }
    }
}

#[derive(Default)]
struct WalkStats {
    dirs_denied: u64,
    dirs_unreadable: u64,
    samples: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(index: usize, aliases: usize) -> RawEntry {
        RawEntry {
            lib: format!("lib{index:04}"),
            name: format!("name{index:04}"),
            aka: (0..aliases).map(|i| format!("alias{i:04}")).collect(),
            arch: "x64".into(),
            bytes: vec![0x48, index as u8, 0x90],
            mask: vec![true, false, true],
            min_len: 3,
            confidence: 0.8,
            semantic_role: String::new(),
            calling_convention: String::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
        }
    }

    #[test]
    fn collision_report_is_deterministic_and_contains_alias_groups() {
        let report = collision_report(&[entry(0, 0), entry(1, 2), entry(2, 1)]);

        assert_eq!(
            report.alias_histogram.into_iter().collect::<Vec<_>>(),
            vec![(0, 1), (1, 1), (2, 1)]
        );
        assert_eq!(report.groups.len(), 2);
        assert_eq!(report.groups[0].arch, "x64");
        assert_eq!(report.groups[0].primary_lib, "lib0001");
        assert_eq!(report.groups[0].primary_name, "name0001");
        assert_eq!(report.groups[0].aliases, vec!["alias0000", "alias0001"]);
        assert_eq!(report.groups[0].pattern, "48 ?? 90");
        assert!(report.groups.iter().all(|group| !group.aliases.is_empty()));
    }

    #[test]
    fn collision_report_caps_groups() {
        let entries: Vec<_> = (0..1001).map(|i| entry(i, 1)).collect();
        let report = collision_report(&entries);

        assert_eq!(report.patterns_with_aliases, 1001);
        assert_eq!(report.groups.len(), 1000);
    }

    // ── scheduler hysteresis ──

    #[test]
    fn scheduler_needs_streak_and_cooldown() {
        // In band: no change.
        assert_eq!(next_jobs(4, 8, 1, 0, 0, true), None);
        // Two high samples: hysteresis holds.
        assert_eq!(next_jobs(4, 8, 1, 2, 0, true), None);
        // Three in a row: shed a worker.
        assert_eq!(next_jobs(4, 8, 1, 3, 0, true), Some(3));
        // Already at min: no change.
        assert_eq!(next_jobs(1, 8, 1, 3, 0, true), None);
        // Low band symmetric.
        assert_eq!(next_jobs(4, 8, 1, 0, 2, true), None);
        assert_eq!(next_jobs(4, 8, 1, 0, 3, true), Some(5));
        assert_eq!(next_jobs(8, 8, 1, 0, 3, true), None);
        // Cooldown blocks everything.
        assert_eq!(next_jobs(4, 8, 1, 3, 0, false), None);
    }

    // ── summary line validation ──

    #[test]
    fn summary_accepts_valid_line_and_counts_aliases() {
        let mut acc = SummaryAcc::new();
        summarize_line(
            "kernel32|x64|CreateFileW|9|0.80|48 83 EC 28 E8 ?? ?? ?? ??|aka=A,B",
            &mut acc,
        )
        .unwrap();
        assert_eq!(acc.libraries["kernel32"], 1);
        assert_eq!(acc.architectures["x64"], 1);
        assert_eq!(acc.entries_with_aliases, 1);
        assert_eq!(acc.total_aliases, 2);
        assert_eq!(acc.len_max, 9);
        assert_eq!(acc.fixed_max, 5);
    }

    #[test]
    fn summary_rejects_bad_lines() {
        let mut acc = SummaryAcc::new();
        assert!(summarize_line("bad|line", &mut acc).is_err());
        assert!(summarize_line("a|x86|n|0|0.8|55 8B EC 83 EC 10 90 90", &mut acc).is_err());
        assert!(summarize_line("a|x86|n|8|0.0|55 8B EC 83 EC 10 90 90", &mut acc).is_err());
        assert!(summarize_line("a|x86|n|8|0.8|90 90", &mut acc).is_err());
        assert!(summarize_line("a|x86|n|8|0.8|?? ?? ?? ?? ?? ?? ?? ??", &mut acc).is_err());
        assert!(summarize_line("a|x86|n|8|0.8|55 8B EC 83 EC 10 90 90|alias=X", &mut acc).is_err());
        assert!(summarize_line("a|x86||8|0.8|55 8B EC 83 EC 10 90 90", &mut acc).is_err());
    }

    #[test]
    fn summary_finish_produces_top_libraries() {
        let mut acc = SummaryAcc::new();
        for i in 0..30 {
            summarize_line(
                &format!("lib{i:02}|x64|n|8|0.8|55 8B EC 83 EC 10 90 90"),
                &mut acc,
            )
            .unwrap();
        }
        let counts = LineCounts {
            data_lines: 30,
            comment_lines: 0,
            empty_lines: 0,
            malformed: 0,
        };
        let s = acc.finish("x", &counts, 20);
        assert_eq!(s.data_lines, 30);
        assert_eq!(s.libraries, 30);
        assert_eq!(s.top_libraries.len(), 20);
        assert_eq!(s.pattern_len_min, 8);
        assert_eq!(s.pattern_len_max, 8);
        assert_eq!(s.fixed_min, 8);
    }

    // ── apiset mapping ──

    fn fw(from_name: &str, dll: &str, name: &str) -> ForwarderRef {
        ForwarderRef {
            from_name: from_name.into(),
            target_dll: dll.into(),
            target_name: name.into(),
        }
    }

    #[test]
    fn apiset_map_builds_and_resolves_hosts() {
        let hs = vec![
            (
                "api-ms-win-core-com-l1-1-0".to_string(),
                "x64".to_string(),
                vec![fw("CComObject", "combase", "CComObject")],
            ),
            (
                "api-ms-win-core-com-l1-1-0".to_string(),
                "x86".to_string(),
                vec![fw("CComObject", "combase", "CComObject")],
            ),
            (
                "ext-ms-win-shell-shell32-l1-2-0".to_string(),
                "x64".to_string(),
                vec![fw(
                    "SHOpenFolder",
                    "api-ms-win-core-com-l1-1-0",
                    "SHOpenFolder",
                )],
            ),
        ];
        let m = ApisetMap::build(&hs);
        assert_eq!(
            m.host("api-ms-win-core-com-l1-1-0", "x64"),
            Some("combase".into())
        );
        assert_eq!(
            m.host("ext-ms-win-shell-shell32-l1-2-0", "x64"),
            Some("combase".into())
        );
        assert_eq!(m.host("api-ms-win-core-nosuch-l1-1-0", "x64"), None);
    }

    #[test]
    fn unresolved_classes_are_stable() {
        assert_eq!(Unresolved::DllMissing("a".into()).class(), "dll-missing");
        assert_eq!(
            Unresolved::OrdinalOutOfRange("a".into(), 9).class(),
            "ordinal-out-of-range"
        );
        assert_eq!(
            Unresolved::ExportNotHarvestable("a".into(), "b".into()).class(),
            "export-not-harvestable"
        );
        assert_eq!(
            Unresolved::Cycle("a".into(), "b".into()).class(),
            "forwarder-cycle"
        );
    }
}
