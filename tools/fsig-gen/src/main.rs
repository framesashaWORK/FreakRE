//! fsig-gen driver: harvest PE export prefixes into one `.fsig` file.
//!
//! ```text
//! fsig-gen --out func-sigs/db/generated.fsig --dlls C:\Windows\System32 [--dlls ...]
//! ```
//!
//! - Every `*.dll` (plus explicitly named files like `ntoskrnl.exe`) is
//!   harvested; `api-ms-win-*` pure-forwarder sets are skipped by design
//!   (their names live in import tables already).
//! - Forwarders (`KERNELBASE.Foo`) resolve against already-loaded DLLs
//!   (same directory first, then every `--dlls` dir); chains cap at 3 hops.
//! - Output is deterministic: DLLs sorted, entries merged and sorted.

use fsig_gen::{harvest_pe, merge_entries, validate_entries, DllHarvest, ForwarderRef, HarvestConfig, RawEntry};
use std::collections::HashMap;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: fsig-gen --out <file.fsig> --dlls <dir> [--dlls <dir>...] [--extra <file>...]");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out: Option<PathBuf> = None;
    let mut dll_dirs: Vec<PathBuf> = Vec::new();
    let mut extra: Vec<PathBuf> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
            "--extra" => {
                i += 1;
                if let Some(f) = args.get(i) {
                    extra.push(PathBuf::from(f));
                }
            }
            _ => usage(),
        }
        i += 1;
    }
    let out = out.unwrap_or_else(|| usage());
    if dll_dirs.is_empty() && extra.is_empty() {
        usage();
    }

    let cfg = HarvestConfig::default();

    // Collect candidate files (sorted for determinism).
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in &dll_dirs {
        let rd = std::fs::read_dir(dir).unwrap_or_else(|e| {
            eprintln!("cannot list {}: {e}", dir.display());
            std::process::exit(1);
        });
        for ent in rd.flatten() {
            let p = ent.path();
            let is_pe = p
                .extension()
                .map(|e| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("sys"))
                .unwrap_or(false);
            if is_pe {
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if stem.to_ascii_lowercase().starts_with("api-ms-win-") {
                    continue; // pure forwarder sets: names live in imports.
                }
                files.push(p);
            }
        }
    }
    files.extend(extra);
    files.sort();

    // Phase 1: harvest every image; cache parsed bytes by lowercased stem.
    let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
    let mut harvests: Vec<DllHarvest> = Vec::new();
    for f in &files {
        let data = match std::fs::read(f) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("skip {}: {e}", f.display());
                continue;
            }
        };
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
                cache.insert(stem, data);
                harvests.push(h);
            }
            Err(e) => eprintln!("skip {}: {e}", f.display()),
        }
    }

    // Phase 2: resolve forwarders (same stem cache; chains up to 3 hops).
    // Index harvested entries once: stem -> export name -> entry.
    let mut by_dll: HashMap<String, HashMap<String, RawEntry>> = HashMap::new();
    for h in &harvests {
        let slot = by_dll.entry(h.lib.clone()).or_default();
        for e in &h.entries {
            slot.insert(e.name.clone(), e.clone());
        }
    }
    let mut all: Vec<RawEntry> = harvests.iter().flat_map(|h| h.entries.clone()).collect();
    let mut resolved = 0usize;
    let mut unresolved = 0usize;
    let pending: Vec<(String, ForwarderRef)> = harvests
        .iter()
        .flat_map(|h| h.forwarders.iter().map(|f| (h.lib.clone(), f.clone())).collect::<Vec<_>>())
        .collect();
    for (from_lib, fw) in &pending {
        match resolve_forwarder(fw, &cache, &by_dll, 3) {
            Some(mut e) => {
                // Primary name = the name user binaries import.
                e.aka.insert(0, e.name.clone());
                e.name = fw.from_name.clone();
                e.lib = from_lib.clone();
                all.push(e);
                resolved += 1;
            }
            None => unresolved += 1,
        }
    }
    eprintln!("forwarders: resolved={resolved} unresolved={unresolved}");

    // Phase 3: merge, self-validate, emit.
    let merged = merge_entries(all);
    eprintln!("merged patterns: {}", merged.len());
    let (kept, dropped) = validate_entries(merged);
    eprintln!("self-FP validation: kept={} dropped={}", kept.len(), dropped.len());
    for d in dropped.iter().take(20) {
        eprintln!("  dropped {d}");
    }
    let text = fsig_gen::emit_fsig(&kept);
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    std::fs::write(&out, text).unwrap_or_else(|e| {
        eprintln!("cannot write {}: {e}", out.display());
        std::process::exit(1);
    });
    eprintln!("wrote {} entries -> {}", kept.len(), out.display());
}

/// Follow a forwarder chain to real code via the phase-1 index (no
/// re-harvest). Returns the entry under the implementation's own name;
/// the caller renames it to the forwarder name user binaries import.
fn resolve_forwarder(
    fw: &ForwarderRef,
    cache: &HashMap<String, Vec<u8>>,
    by_dll: &HashMap<String, HashMap<String, RawEntry>>,
    hops: usize,
) -> Option<RawEntry> {
    if hops == 0 {
        return None;
    }
    let data = cache.get(&fw.target_dll)?;
    let pe = pe_parser::PeFile::parse(data).ok()?;
    let (_, exports) = pe.exports();
    // Target by name or by #ordinal.
    let (rva, real_name) = if let Some(ord) =
        fw.target_name.strip_prefix('#').and_then(|s| s.parse::<u16>().ok())
    {
        let (_, n, r) = exports.into_iter().find(|(o, _, _)| *o == ord)?;
        (r, n)
    } else {
        let (_, _, r) = exports.iter().find(|(_, n, _)| n == &fw.target_name)?;
        (*r, fw.target_name.clone())
    };
    // Chained forwarder? Recurse, keeping the ORIGINAL caller name outside.
    if let Some((er, es)) = pe.export_directory() {
        if rva >= er && (rva - er) < es {
            let off = pe.rva_to_offset(rva)?;
            let end = data.get(off..)?.iter().position(|&b| b == 0)?;
            let s = std::str::from_utf8(&data[off..off + end]).ok()?;
            let (dll, name) = fsig_gen::parse_forwarder(s)?;
            let next = ForwarderRef {
                from_name: fw.from_name.clone(),
                target_dll: dll,
                target_name: name,
            };
            return resolve_forwarder(&next, cache, by_dll, hops - 1);
        }
    }
    by_dll.get(&fw.target_dll)?.get(&real_name).cloned()
}
