//! Binary overlay database (`.fbd`) with a prebuilt open-addressed index,
//! memory-mapped at load time.
//!
//! Loading a 500 MB `.fsig` text overlay costs seconds of hex parsing plus a
//! full index rebuild on every process start. `.fbd` moves that work to pack
//! time: the file stores the entries plus six ready-made hash tables (the
//! same oct/quint/triple/pair/single/slow ladder the text database uses),
//! and the loader just `mmap`s the file and validates the header вЂ” zero
//! parsing, zero index building, zero per-entry allocation. All reads are
//! bounds- and alignment-checked views into the mapping; nothing is copied.
//!
//! Layout (little-endian; section offsets are u64):
//!
//! ```text
//! 0   "FRBD" version n_entries n_strings
//! 16  9 x u64: string_blob, string_offsets, entries, patterns,
//!     mask_offsets, mask_blob, runs, run_ranges, aka_ids
//! 88  n_aka u32, max_slow_pos u32
//! 96  6 x { n_keys u32, slots u32, table_off u64 }   // oct..slow, fixed order
//! 192 6 x u64: refs_off per kind
//! 240 -- string blob, string_offsets (n_strings+1)
//!     -- entry records: 13 u32 (lib, name, arch, min_len, conf*1e6,
//!        aka_first, aka_count, role, cc, sources, sinks, pat_off, pat_len)
//!     -- patterns blob, mask_offsets (n_entries+1), mask bitsets
//!     -- runs (u32: start<<16|end), run_ranges (n_entries+1), aka ids
//!     -- per kind: table (slots x 16B: key u64, off u32, len u32), refs u32
//! ```
//!
//! Tables use linear probing, load factor <= 0.5; `len == 0` marks an empty
//! slot (every real bucket holds at least one ref).

use crate::db::{DbEntry, DbHit, MAX_PAIR_GAP};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

pub const FDB_MAGIC: &[u8; 4] = b"FRBD";
pub const FDB_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 240;

const KIND_OCT: usize = 0;
const KIND_QUINT: usize = 1;
const KIND_TRIPLE: usize = 2;
const KIND_PAIR: usize = 3;
const KIND_SINGLE: usize = 4;
const KIND_SLOW: usize = 5;
const KIND_COUNT: usize = 6;

// в”Ђв”Ђв”Ђ Packing в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn align8(out: &mut Vec<u8>) {
    while out.len() % 8 != 0 {
        out.push(0);
    }
}

fn next_pow2(n: usize) -> usize {
    let mut s = 1usize;
    while s < n.max(2) * 2 {
        s <<= 1;
    }
    s
}

/// Same mixer family as fxhash for u64 keys.
#[inline]
fn mix(key: u64) -> u64 {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
    let mut h = SEED ^ key;
    h = h.wrapping_mul(SEED);
    h ^ (h >> 29)
}

/// Pack one index key into u64 (same encoding on write and probe).
fn pack_key(kind: usize, b: &[u8], gap_or_pos: usize) -> u64 {
    match kind {
        KIND_OCT => u64::from_le_bytes(b.try_into().unwrap()),
        KIND_QUINT => {
            let mut k = 0u64;
            for i in (0..5).rev() {
                k = (k << 8) | b[i] as u64;
            }
            k
        }
        KIND_TRIPLE => (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16),
        KIND_PAIR => (b[0] as u64) | ((b[1] as u64) << 8) | ((gap_or_pos as u64) << 16),
        KIND_SINGLE => b[0] as u64,
        _ => (b[0] as u64) | ((gap_or_pos as u64) << 8), // slow: byte | pos<<8
    }
}

/// Classify one entry into the index ladder (same rules as the text path).
fn entry_index_key(e: &DbEntry) -> (usize, u64) {
    let mut fixed = e.mask.iter().enumerate().filter(|(_, &m)| m).map(|(p, _)| p);
    if e.mask.len() > 7 && e.mask[..8].iter().all(|&m| m) {
        return (KIND_OCT, pack_key(KIND_OCT, &e.bytes[..8], 0));
    }
    if e.mask.len() > 4 && e.mask[..5].iter().all(|&m| m) {
        return (KIND_QUINT, pack_key(KIND_QUINT, &e.bytes[..5], 0));
    }
    match (fixed.next(), fixed.next()) {
        (Some(0), Some(1)) if e.mask.len() > 2 && e.mask[2] => {
            (KIND_TRIPLE, pack_key(KIND_TRIPLE, &e.bytes[..3], 0))
        }
        (Some(0), Some(p1)) if p1 <= MAX_PAIR_GAP => {
            (KIND_PAIR, pack_key(KIND_PAIR, &[e.bytes[0], e.bytes[p1]], p1))
        }
        (Some(0), _) => (KIND_SINGLE, pack_key(KIND_SINGLE, &e.bytes[..1], 0)),
        (Some(p0), _) => (KIND_SLOW, pack_key(KIND_SLOW, &[e.bytes[p0]], p0)),
        (None, _) => (KIND_SINGLE, pack_key(KIND_SINGLE, &e.bytes[..1], 0)),
    }
}

struct FlatTable {
    keys: Vec<u64>,
    offs: Vec<u32>,
    lens: Vec<u32>,
    slots: usize,
}

impl FlatTable {
    /// `items` must be sorted by key; buckets are concatenated into `refs`.
    fn build(items: &[(u64, Vec<u32>)], refs: &mut Vec<u32>) -> Self {
        let slots = next_pow2(items.len());
        let mut keys = vec![0u64; slots];
        let mut offs = vec![0u32; slots];
        let mut lens = vec![0u32; slots];
        let mut off = 0u32;
        for (key, bucket) in items {
            refs.extend_from_slice(bucket);
            let mut i = (mix(*key) & (slots as u64 - 1)) as usize;
            while lens[i] != 0 {
                i = (i + 1) & (slots - 1);
            }
            keys[i] = *key;
            offs[i] = off;
            lens[i] = bucket.len() as u32;
            off += bucket.len() as u32;
        }
        FlatTable {
            keys,
            offs,
            lens,
            slots,
        }
    }
}

/// Serialize parsed entries as an `.fbd` file. Entries should already be
/// gated/curated вЂ” the loader applies no filtering.
pub fn write_fdb(entries: &[DbEntry], w: &mut impl std::io::Write) -> std::io::Result<()> {
    struct Rec {
        ids: [u32; 7], // lib, name, arch, role, cc, sources, sinks
        min_len: u32,
        conf: u32,
        aka_first: u32,
        aka_count: u32,
        pat_off: u32,
        pat_len: u32,
    }

    let mut strings: Vec<String> = Vec::new();
    let mut intern: HashMap<String, u32> = HashMap::new();
    let mut blob: Vec<u8> = Vec::new();
    let mut soff: Vec<u32> = vec![0];
    fn sid(
        s: &str,
        strings: &mut Vec<String>,
        intern: &mut HashMap<String, u32>,
        blob: &mut Vec<u8>,
        soff: &mut Vec<u32>,
    ) -> u32 {
        if let Some(&id) = intern.get(s) {
            return id;
        }
        let id = strings.len() as u32;
        blob.extend_from_slice(s.as_bytes());
        soff.push(blob.len() as u32);
        strings.push(s.to_string());
        intern.insert(s.to_string(), id);
        id
    }

    let mut recs: Vec<Rec> = Vec::with_capacity(entries.len());
    let mut aka_ids: Vec<u32> = Vec::new();
    let mut patterns: Vec<u8> = Vec::new();
    let mut mask_bits: Vec<u8> = Vec::new();
    let mut mask_offsets: Vec<u32> = vec![0];
    let mut runs: Vec<u32> = Vec::new();
    let mut run_ranges: Vec<u32> = vec![0];

    for e in entries {
        let lib = sid(e.library, &mut strings, &mut intern, &mut blob, &mut soff);
        let name = sid(e.function_name, &mut strings, &mut intern, &mut blob, &mut soff);
        let arch = sid(e.arch, &mut strings, &mut intern, &mut blob, &mut soff);
        let role = sid(e.semantic_role, &mut strings, &mut intern, &mut blob, &mut soff);
        let cc = sid(e.calling_convention, &mut strings, &mut intern, &mut blob, &mut soff);
        let sources = sid(e.sources, &mut strings, &mut intern, &mut blob, &mut soff);
        let sinks = sid(e.sinks, &mut strings, &mut intern, &mut blob, &mut soff);
        let aka_first = aka_ids.len() as u32;
        for a in &e.aka {
            aka_ids.push(sid(a, &mut strings, &mut intern, &mut blob, &mut soff));
        }
        let pat_off = patterns.len() as u32;
        patterns.extend_from_slice(&e.bytes);
        let bit_base = mask_bits.len();
        mask_bits.extend(std::iter::repeat(0u8).take(e.bytes.len().div_ceil(8)));
        for (i, &m) in e.mask.iter().enumerate() {
            if m {
                mask_bits[bit_base + i / 8] |= 1 << (i % 8);
            }
        }
        mask_offsets.push(mask_bits.len() as u32);
        let mut i = 0;
        while i < e.mask.len() {
            if e.mask[i] {
                let s = i;
                while i < e.mask.len() && e.mask[i] {
                    i += 1;
                }
                runs.push(((s as u32) << 16) | (i as u32));
            } else {
                i += 1;
            }
        }
        run_ranges.push(runs.len() as u32);
        recs.push(Rec {
            ids: [lib, name, arch, role, cc, sources, sinks],
            min_len: e.min_func_len as u32,
            conf: (e.confidence.clamp(0.0, 1.0) * 1_000_000.0) as u32,
            aka_first,
            aka_count: e.aka.len() as u32,
            pat_off,
            pat_len: e.bytes.len() as u32,
        });
    }

    // Build the six tables (dedup keys, sort, place).
    let mut by_kind: Vec<Vec<(u64, Vec<u32>)>> = vec![Vec::new(); KIND_COUNT];
    for (idx, e) in entries.iter().enumerate() {
        let (kind, key) = entry_index_key(e);
        by_kind[kind].push((key, vec![idx as u32]));
    }
    let mut tables: Vec<FlatTable> = Vec::with_capacity(KIND_COUNT);
    let mut table_refs: Vec<Vec<u32>> = Vec::with_capacity(KIND_COUNT);
    let mut nkeys_per_kind = [0u32; KIND_COUNT];
    for (kind, list) in by_kind.iter_mut().enumerate() {
        list.sort_by_key(|(k, _)| *k);
        let mut merged: Vec<(u64, Vec<u32>)> = Vec::with_capacity(list.len());
        for (k, mut b) in list.drain(..) {
            if let Some(last) = merged.last_mut() {
                if last.0 == k {
                    last.1.append(&mut b);
                    continue;
                }
            }
            merged.push((k, b));
        }
        nkeys_per_kind[kind] = merged.len() as u32;
        let mut refs = Vec::with_capacity(entries.len());
        tables.push(FlatTable::build(&merged, &mut refs));
        table_refs.push(refs);
    }

    // Assemble the file.
    let mut out: Vec<u8> = Vec::with_capacity(1 << 20);
    out.extend_from_slice(FDB_MAGIC);
    put_u32(&mut out, FDB_VERSION);
    put_u32(&mut out, entries.len() as u32);
    put_u32(&mut out, strings.len() as u32);
    for _ in 0..(HEADER_LEN - 16) / 4 {
        put_u32(&mut out, 0);
    }
    debug_assert_eq!(out.len(), HEADER_LEN);

    let string_blob_off = out.len() as u64;
    out.extend_from_slice(&blob);
    align8(&mut out);
    let string_offsets_off = out.len() as u64;
    for v in &soff {
        put_u32(&mut out, *v);
    }
    align8(&mut out);
    let entries_off = out.len() as u64;
    for r in &recs {
        put_u32(&mut out, r.ids[0]);
        put_u32(&mut out, r.ids[1]);
        put_u32(&mut out, r.ids[2]);
        put_u32(&mut out, r.min_len);
        put_u32(&mut out, r.conf);
        put_u32(&mut out, r.aka_first);
        put_u32(&mut out, r.aka_count);
        put_u32(&mut out, r.ids[3]);
        put_u32(&mut out, r.ids[4]);
        put_u32(&mut out, r.ids[5]);
        put_u32(&mut out, r.ids[6]);
        put_u32(&mut out, r.pat_off);
        put_u32(&mut out, r.pat_len);
    }
    align8(&mut out);
    let patterns_off = out.len() as u64;
    out.extend_from_slice(&patterns);
    align8(&mut out);
    let mask_offsets_off = out.len() as u64;
    for v in &mask_offsets {
        put_u32(&mut out, *v);
    }
    align8(&mut out);
    let mask_blob_off = out.len() as u64;
    out.extend_from_slice(&mask_bits);
    align8(&mut out);
    let runs_off = out.len() as u64;
    for v in &runs {
        put_u32(&mut out, *v);
    }
    align8(&mut out);
    let run_ranges_off = out.len() as u64;
    for v in &run_ranges {
        put_u32(&mut out, *v);
    }
    align8(&mut out);
    let aka_ids_off = out.len() as u64;
    for v in &aka_ids {
        put_u32(&mut out, *v);
    }
    align8(&mut out);

    let mut table_offs = [0u64; KIND_COUNT];
    for (kind, t) in tables.iter().enumerate() {
        table_offs[kind] = out.len() as u64;
        for s in 0..t.slots {
            put_u64(&mut out, t.keys[s]);
            put_u32(&mut out, t.offs[s]);
            put_u32(&mut out, t.lens[s]);
        }
        align8(&mut out);
    }
    let mut refs_offs = [0u64; KIND_COUNT];
    for (kind, refs) in table_refs.iter().enumerate() {
        refs_offs[kind] = out.len() as u64;
        for v in refs {
            put_u32(&mut out, *v);
        }
        align8(&mut out);
    }

    // Patch the header.
    let mut hdr: Vec<u8> = Vec::with_capacity(HEADER_LEN);
    hdr.extend_from_slice(FDB_MAGIC);
    put_u32(&mut hdr, FDB_VERSION);
    put_u32(&mut hdr, entries.len() as u32);
    put_u32(&mut hdr, strings.len() as u32);
    put_u64(&mut hdr, string_blob_off);
    put_u64(&mut hdr, string_offsets_off);
    put_u64(&mut hdr, entries_off);
    put_u64(&mut hdr, patterns_off);
    put_u64(&mut hdr, mask_offsets_off);
    put_u64(&mut hdr, mask_blob_off);
    put_u64(&mut hdr, runs_off);
    put_u64(&mut hdr, run_ranges_off);
    put_u64(&mut hdr, aka_ids_off);
    put_u32(&mut hdr, aka_ids.len() as u32);
    put_u32(&mut hdr, 0); // max_slow_pos (unused by loader probe walk; kept for parity)
    for (kind, t) in tables.iter().enumerate() {
        put_u32(&mut hdr, nkeys_per_kind[kind]);
        put_u32(&mut hdr, t.slots as u32);
        put_u64(&mut hdr, table_offs[kind]);
    }
    for v in refs_offs {
        put_u64(&mut hdr, v);
    }
    debug_assert_eq!(hdr.len(), HEADER_LEN);
    out[..HEADER_LEN].copy_from_slice(&hdr);

    w.write_all(&out)
}

// в”Ђв”Ђв”Ђ Loading в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// A memory-mapped `.fbd` overlay. Cheap to construct: header validation
/// only; every accessor is bounds-checked against precomputed section ends.
/// The mapping is leaked (`Box::leak`) so returned strings are `&'static`.
pub struct FdbOverlay {
    mmap: &'static memmap2::Mmap,
    n_entries: usize,
    n_strings: usize,
    string_offsets: (usize, usize), // slice of u32 (n_strings+1)
    string_blob_start: usize,
    entries: (usize, usize),        // slice of u32 (13 per entry)
    patterns_start: usize,
    mask_offsets: (usize, usize), // slice of u32 (n_entries+1)
    mask_blob_start: usize,
    runs: (usize, usize),       // slice of u32
    run_ranges: (usize, usize), // slice of u32 (n_entries+1)
    aka_ids: (usize, usize),    // slice of u32
    n_aka: usize,
    max_slow_pos: usize,
    tables: [(usize, usize, usize); KIND_COUNT], // nkeys, table_off, slots
    refs_off: [usize; KIND_COUNT],
    refs_end: [usize; KIND_COUNT],
}

fn u32s<'a>(data: &'a [u8], range: (usize, usize)) -> &'a [u32] {
    let sl = &data[range.0..range.1];
    let (head, mid, tail) = unsafe { sl.align_to::<u32>() };
    debug_assert!(head.is_empty() && tail.is_empty(), "unaligned u32 section");
    mid
}

fn u64s<'a>(data: &'a [u8], range: (usize, usize)) -> &'a [u64] {
    let sl = &data[range.0..range.1];
    let (head, mid, tail) = unsafe { sl.align_to::<u64>() };
    debug_assert!(head.is_empty() && tail.is_empty(), "unaligned u64 section");
    mid
}

fn rd_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn rd_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// A hit from the dedicated family database. `offset` is absolute in the
/// scanned buffer (`start + base_offset`), `entry` indexes the family overlay.
#[derive(Clone, Copy, Debug)]
pub struct FamilyHit {
    pub offset: usize,
    pub entry: usize,
}

/// Resolve a family hit to (`library/family`, `function name`, `min_func_len`,
/// `pattern_len`, `confidence`).
pub fn resolve_family_hit(hit: &FamilyHit) -> (&'static str, &'static str, usize, usize, f64) {
    FAMILY_DB
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|ov| {
            (
                ov.library(hit.entry),
                ov.function_name(hit.entry),
                ov.min_func_len(hit.entry),
                ov.pattern_len(hit.entry),
                ov.confidence(hit.entry),
            )
        })
        .unwrap_or(("", "", 0, 0, 0.0))
}

/// Semantic metadata for a family hit (`role`, `calling convention`,
/// `sources`, `sinks`) — same shape as [`crate::db::resolve_metadata`].
pub fn resolve_family_metadata(hit: &FamilyHit) -> (&'static str, &'static str, Vec<&'static str>, Vec<&'static str>) {
    FAMILY_DB
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|ov| ov.resolve_metadata(hit.entry))
        .unwrap_or(("", "", Vec::new(), Vec::new()))
}

/// Scan the loaded family database. Family hits are reported in addition to
/// the main database / overlay hits.
pub fn scan_families_for_arch(
    code: &[u8],
    base_offset: usize,
    max_matches: usize,
    arch: Option<&str>,
) -> Vec<FamilyHit> {
    let ov = FAMILY_DB.read().unwrap_or_else(|e| e.into_inner()).clone();
    match ov {
        Some(ov) => ov.scan_families(code, base_offset, max_matches, arch),
        None => Vec::new(),
    }
}

/// Load the dedicated family database (`.fbd`). Replaces any previous one.
pub fn load_family_fbd(path: &std::path::Path) -> Result<usize, String> {
    let ov = FdbOverlay::load(path)?;
    let n = ov.len();
    *FAMILY_DB.write().unwrap_or_else(|e| e.into_inner()) = Some(ov);
    Ok(n)
}

/// Number of entries in the loaded family database (0 when none).
pub fn family_signature_count() -> usize {
    FAMILY_DB
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|ov| ov.len())
        .unwrap_or(0)
}

/// Dedicated family database — separate from the main overlay so family
/// matching stays a small, self-contained engine.
static FAMILY_DB: std::sync::RwLock<Option<std::sync::Arc<FdbOverlay>>> =
    std::sync::RwLock::new(None);

impl FdbOverlay {
    /// mmap + validate. The mapping is leaked; treat `.fbd` as immutable.
    pub fn load(path: &std::path::Path) -> Result<Arc<Self>, String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        // SAFETY: read-only mapping of an immutable input file.
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .map_err(|e| format!("cannot mmap {}: {e}", path.display()))?;
        let mmap: &'static memmap2::Mmap = Box::leak(Box::new(mmap));
        let data = &mmap[..];
        if data.len() < HEADER_LEN {
            return Err(format!("{}: too small for FRBD header", path.display()));
        }
        if &data[0..4] != FDB_MAGIC {
            return Err(format!("{}: bad magic (not an .fbd)", path.display()));
        }
        let version = rd_u32(data, 4);
        if version != FDB_VERSION {
            return Err(format!("{}: unsupported FRBD version {version}", path.display()));
        }
        let n_entries = rd_u32(data, 8) as usize;
        let n_strings = rd_u32(data, 12) as usize;
        let mut sec = [0u64; 9];
        for (i, s) in sec.iter_mut().enumerate() {
            *s = rd_u64(data, 16 + i * 8);
        }
        let so = |o: u64| -> Result<usize, String> {
            usize::try_from(o).map_err(|_| format!("{}: bad section offset", path.display()))
        };
        let n_aka = rd_u32(data, 88) as usize;
        let max_slow_pos = rd_u32(data, 92) as usize;
        let mut tables = [(0usize, 0usize, 0usize); KIND_COUNT];
        for (k, t) in tables.iter_mut().enumerate() {
            let base = 96 + k * 16;
            let nkeys = rd_u32(data, base) as usize;
            let slots = rd_u32(data, base + 4) as usize;
            let toff = rd_u64(data, base + 8) as usize;
            if slots != 0 && (!slots.is_power_of_two() || toff + slots * 16 > data.len()) {
                return Err(format!("{}: index table {k} invalid", path.display()));
            }
            *t = (nkeys, toff, slots);
        }
        let mut refs_off = [0usize; KIND_COUNT];
        for (k, r) in refs_off.iter_mut().enumerate() {
            *r = rd_u64(data, 192 + k * 8) as usize;
        }
        let string_offsets = (so(sec[1])?, so(sec[1])? + (n_strings + 1) * 4);
        let entries = (so(sec[2])?, so(sec[2])? + n_entries * 13 * 4);
        let mask_offsets = (so(sec[4])?, so(sec[4])? + (n_entries + 1) * 4);
        let runs = (so(sec[6])?, so(sec[7])?);
        let run_ranges = (so(sec[7])?, so(sec[7])? + (n_entries + 1) * 4);
        let aka_ids = (so(sec[8])?, so(sec[8])? + n_aka * 4);
        let refs_end: [usize; KIND_COUNT] = std::array::from_fn(|k| {
            refs_off
                .iter()
                .filter(|&&o| o > refs_off[k])
                .min()
                .copied()
                .unwrap_or(data.len())
        });
        // Sanity: all referenced sections land inside the file.
        let sections = [
            string_offsets, entries, mask_offsets, runs, run_ranges, aka_ids,
        ];
        for r in sections {
            if r.1 > data.len() {
                return Err(format!("{}: truncated section", path.display()));
            }
        }
        for (nkeys, toff, slots) in tables {
            let _ = nkeys;
            if toff + slots * 16 > data.len() {
                return Err(format!("{}: index table out of bounds", path.display()));
            }
        }
        for k in 0..KIND_COUNT {
            if refs_off[k] > data.len() || refs_end[k] > data.len() {
                return Err(format!("{}: index refs out of bounds", path.display()));
            }
        }
        Ok(Arc::new(FdbOverlay {
            mmap,
            n_entries,
            n_strings,
            string_offsets,
            string_blob_start: so(sec[0])?,
            entries,
            patterns_start: so(sec[3])?,
            mask_offsets,
            mask_blob_start: so(sec[5])?,
            runs,
            run_ranges,
            aka_ids,
            n_aka,
            max_slow_pos,
            tables,
            refs_off,
            refs_end,
        }))
    }

    pub fn len(&self) -> usize {
        self.n_entries
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn is_empty(&self) -> bool {
        self.n_entries == 0
    }

    pub fn file_len(&self) -> usize {
        self.mmap.len()
    }

    fn string(&self, id: u32) -> &'static str {
        let data = &self.mmap[..];
        let id = id as usize;
        if id >= self.n_strings {
            return "";
        }
        let so = u32s(data, self.string_offsets);
        let start = self.string_blob_start + so[id] as usize;
        let end = self.string_blob_start + so[id + 1] as usize;
        std::str::from_utf8(&data[start..end]).unwrap_or("")
    }

    #[inline]
    fn rec(&self, idx: usize) -> &[u32] {
        let all = u32s(&self.mmap[..], self.entries);
        &all[idx * 13..idx * 13 + 13]
    }

    pub fn library(&self, idx: usize) -> &'static str {
        self.string(self.rec(idx)[0])
    }

    /// Unique library labels in entry order (dedup caller-side).
    pub fn libraries(&self) -> Vec<&'static str> {
        (0..self.len()).map(|i| self.library(i)).collect()
    }

    pub fn function_name(&self, idx: usize) -> &'static str {
        self.string(self.rec(idx)[1])
    }

    pub fn arch(&self, idx: usize) -> &'static str {
        self.string(self.rec(idx)[2])
    }

    pub fn min_func_len(&self, idx: usize) -> usize {
        self.rec(idx)[3] as usize
    }

    /// Total pattern bytes for entry `idx`.
    pub fn pattern_len(&self, idx: usize) -> usize {
        self.rec(idx)[12] as usize
    }

    /// Fixed-run span summary `(first_run_start, last_run_end)` for entry
    /// `idx` — enough for `hit_fixed_count`-style summaries.
    pub fn run_range(&self, idx: usize) -> (usize, usize) {
        let data = &self.mmap[..];
        let rr = u32s(data, self.run_ranges);
        let runs = u32s(data, self.runs);
        let lo = rr[idx] as usize;
        let hi = rr[idx + 1] as usize;
        if lo >= hi {
            return (0, 0);
        }
        let first = runs[lo];
        let last = runs[hi - 1];
        (first as usize, last as usize)
    }

    pub fn confidence(&self, idx: usize) -> f64 {
        self.rec(idx)[4] as f64 / 1_000_000.0
    }

    pub fn aka(&self, idx: usize) -> Vec<&'static str> {
        let r = self.rec(idx);
        let (first, count) = (r[5] as usize, r[6] as usize);
        let ids = u32s(&self.mmap[..], self.aka_ids);
        (first..first + count)
            .filter(|&i| i < self.n_aka)
            .map(|i| self.string(ids[i]))
            .collect()
    }

    pub fn resolve_metadata(
        &self,
        idx: usize,
    ) -> (&'static str, &'static str, Vec<&'static str>, Vec<&'static str>) {
        let r = self.rec(idx);
        let split = |s: &'static str| s.split(',').filter(|v| !v.is_empty()).collect();
        (
            self.string(r[7]),
            self.string(r[8]),
            split(self.string(r[9])),
            split(self.string(r[10])),
        )
    }

    fn verify_at(&self, idx: usize, code: &[u8], start: usize) -> bool {
        let r = self.rec(idx);
        let plen = r[12] as usize;
        if start + plen > code.len() {
            return false;
        }
        let pat = r[11] as usize + self.patterns_start;
        let data = &self.mmap[..];
        let rr = u32s(data, self.run_ranges);
        let runs = u32s(data, self.runs);
        for &packed in &runs[rr[idx] as usize..rr[idx + 1] as usize] {
            // packed = (start << 16) | end, matching the writer.
            let s = (packed >> 16) as usize;
            let e = (packed & 0xFFFF) as usize;
            if code[start + s..start + e] != data[pat + s..pat + e] {
                return false;
            }
        }
        true
    }

    /// Linear probe into one index table. `len == 0` marks an empty slot.
    fn probe(&self, kind: usize, key: u64) -> Option<&[u32]> {
        let (nkeys, table_off, slots) = self.tables[kind];
        if slots == 0 || nkeys == 0 {
            return None;
        }
        let data = &self.mmap[..];
        let mut i = (mix(key) & (slots as u64 - 1)) as usize;
        for _ in 0..slots {
            let slot_base = table_off + i * 16;
            let len = rd_u32(data, slot_base + 12) as usize;
            if len == 0 {
                return None; // empty slot: key never inserted
            }
            if rd_u64(data, slot_base) == key {
                let off = rd_u32(data, slot_base + 8) as usize;
                let refs = u32s(data, (self.refs_off[kind], self.refs_end[kind]));
                if off + len <= refs.len() {
                    return Some(&refs[off..off + len]);
                }
                return None;
            }
            i = (i + 1) & (slots - 1);
        }
        None
    }

    /// Exhaustive FLIRT scan (mirrors the text-path ladder walk).
    pub fn scan_code(
        &self,
        code: &[u8],
        base_offset: usize,
        max_matches: usize,
        arch: Option<&str>,
    ) -> Vec<DbHit> {
        let mut out = Vec::new();
        self.scan_into(code, base_offset, max_matches, arch, &mut out);
        out
    }

    /// Family-scan: same matcher, but produces [`FamilyHit`]s and tolerates
    /// small tables scanning every offset (the family table is tiny, so the
    /// engine keeps full-verify semantics without ladder shortcuts).
    pub fn scan_families(
        &self,
        code: &[u8],
        base_offset: usize,
        max_matches: usize,
        arch: Option<&str>,
    ) -> Vec<FamilyHit> {
        let mut out = Vec::new();
        if self.n_entries == 0 || code.is_empty() || max_matches == 0 {
            return out;
        }
        for start in 0..code.len() {
            for idx in 0..self.n_entries {
                if arch.is_some_and(|w| self.arch(idx) != w) {
                    continue;
                }
                let rec = self.rec(idx);
                if start + rec[12] as usize > code.len() {
                    continue;
                }
                if code.len() - start < rec[3] as usize {
                    continue;
                }
                if self.verify_at(idx, code, start) {
                    out.push(FamilyHit {
                        offset: start + base_offset,
                        entry: idx,
                    });
                    if out.len() >= max_matches {
                        return out;
                    }
                }
            }
        }
        out
    }

    pub fn scan_into(
        &self,
        code: &[u8],
        base_offset: usize,
        max_matches: usize,
        arch: Option<&str>,
        out: &mut Vec<DbHit>,
    ) {
        if self.n_entries == 0 || code.is_empty() || max_matches == 0 {
            return;
        }
        let mut offset = 0usize;
        macro_rules! verify {
            ($list:expr, $start:expr) => {
                for &raw_idx in $list {
                    let idx = raw_idx as usize;
                    if arch.is_some_and(|wanted| self.arch(idx) != wanted) {
                        continue;
                    }
                    let start: usize = $start;
                    if start + self.rec(idx)[12] as usize > code.len() {
                        continue;
                    }
                    if code.len() - start < self.rec(idx)[3] as usize {
                        continue;
                    }
                    if self.verify_at(idx, code, start) {
                        out.push(DbHit {
                            offset: base_offset + start,
                            entry: idx,
                            overlay: true,
                        });
                        if out.len() >= max_matches {
                            return;
                        }
                    }
                }
            };
        }
        while offset < code.len() && out.len() < max_matches {
            let b = code[offset];
            if offset + 7 < code.len() {
                let key = u64::from_le_bytes(code[offset..offset + 8].try_into().unwrap());
                if let Some(list) = self.probe(KIND_OCT, key) {
                    verify!(list, offset);
                }
            }
            if offset + 4 < code.len() {
                let mut k = 0u64;
                for i in (0..5).rev() {
                    k = (k << 8) | code[offset + i] as u64;
                }
                if let Some(list) = self.probe(KIND_QUINT, k) {
                    verify!(list, offset);
                }
            }
            if offset + 2 < code.len() {
                let key = (b as u64)
                    | ((code[offset + 1] as u64) << 8)
                    | ((code[offset + 2] as u64) << 16);
                if let Some(list) = self.probe(KIND_TRIPLE, key) {
                    verify!(list, offset);
                }
            }
            let max_gap = MAX_PAIR_GAP.min(code.len().saturating_sub(offset + 1));
            for gap in 1..=max_gap {
                let key = (b as u64)
                    | ((code[offset + gap] as u64) << 8)
                    | ((gap as u64) << 16);
                if let Some(list) = self.probe(KIND_PAIR, key) {
                    verify!(list, offset);
                }
            }
            if let Some(list) = self.probe(KIND_SINGLE, b as u64) {
                verify!(list, offset);
            }
            for pos in 1..=offset.min(self.max_slow_pos) {
                let key = (b as u64) | ((pos as u64) << 8);
                if let Some(list) = self.probe(KIND_SLOW, key) {
                    let start = offset - pos;
                    verify!(list, start);
                }
            }
            offset += 1;
        }
    }
}

/// Pack text entries to `.fbd` (convenience for the fsig-pack tool).
pub fn pack_entries(entries: &[DbEntry], path: &std::path::Path) -> Result<(), String> {
    let file = std::fs::File::create(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let mut bw = std::io::BufWriter::new(file);
    write_fdb(entries, &mut bw).map_err(|e| format!("write {}: {e}", path.display()))?;
    bw.flush().map_err(|e| format!("flush {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "msvcrt|x64|memcpy|24|0.80|55 8B EC 57 8B 7D ?? 8B 75 ?? 8B 4D ?? F3 A5\n\
                          zlib|x64|inflateInit_|20|0.90|48 89 5C 24 08 57 48 83 EC 20\n\
                          ntdll|x86|CmdTail|12|0.70|E8 ?? ?? ?? ?? 8B 45 FC\n";

    fn parse_sample() -> Vec<DbEntry> {
        let (entries, errors) = crate::db::parse_fsig(SAMPLE, "test");
        assert!(errors.is_empty(), "{errors:?}");
        entries
    }

    #[test]
    fn roundtrip_matches_text_path() {
        let entries = parse_sample();
        let path = std::env::temp_dir().join("func-sigs-fdb-test.fbd");
        pack_entries(&entries, &path).unwrap();

        let ov = FdbOverlay::load(&path).unwrap();
        assert_eq!(ov.len(), 3);
        for k in 0..KIND_COUNT {
            eprintln!("kind={k} nkeys={} slots={}", ov.tables[k].0, ov.tables[k].2);
        }

        // Code containing the memcpy prologue (wildcards filled arbitrarily).
        // Padded past min_len=24 so the length gate accepts the hit.
        let mut code = vec![0x90u8; 17];
        code.extend_from_slice(&[
            0x55, 0x8B, 0xEC, 0x57, 0x8B, 0x7D, 0x11, 0x8B, 0x75, 0x22, 0x8B, 0x4D, 0x33,
            0xF3, 0xA5, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ]);
        let hits = ov.scan_code(&code, 0, 10, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 17);
        assert_eq!(ov.function_name(hits[0].entry), "memcpy");
        assert_eq!(ov.library(hits[0].entry), "msvcrt");

        // Arch filter works.
        let hits = ov.scan_code(&code, 0, 10, Some("x86"));
        assert!(hits.is_empty());

        // A near-miss (fixed byte differs) must NOT match.
        let mut code2 = vec![0x90u8; 4];
        code2.extend_from_slice(&[
            0x55, 0x8B, 0x99, 0x57, 0x8B, 0x7D, 0x11, 0x8B, 0x75, 0x22, 0x8B, 0x4D, 0x33,
            0xF3, 0xA5,
        ]);
        let hits = ov.scan_code(&code2, 0, 10, None);
        assert!(hits.is_empty(), "fixed byte 0x99 must reject the match");

        // The x86 ntdll pattern goes through the pair ladder (E8 ?? ?? ?? ??),
        // and its 12-byte min_len gate keeps the short filler from matching.
        let mut code3 = vec![0xCCu8; 2];
        code3.extend_from_slice(&[0xE8, 0x11, 0x22, 0x33, 0x44, 0x8B, 0x45, 0xFC]);
        let hits = ov.scan_code(&code3, 0, 10, None);
        assert!(hits.is_empty(), "min_len gate must reject short match");
        code3.extend(std::iter::repeat(0x90u8).take(6));
        let hits = ov.scan_code(&code3, 0, 10, None);
        assert_eq!(hits.len(), 1, "pair-ladder hit");
        assert_eq!(ov.function_name(hits[0].entry), "CmdTail");

        let _ = std::fs::remove_file(&path);
    }
}

