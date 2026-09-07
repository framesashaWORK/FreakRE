//! `fsig-pack` — compile a curated `.fsig` text base into a binary `.fbd`
//! overlay (FRBD format: prebuilt hash indexes + mmap loader).
//!
//! ```text
//! fsig-pack <in.fsig> [more.fsig ...] --out <out.fbd> [--families]
//! ```
//!
//! Multiple inputs are merged (later files win on duplicate keys, matching
//! `load_overlay_dir` precedence) and gated with the same sanity rules the
//! text loader applies at runtime, so packing never smuggles in entries the
//! matcher would silently drop.

use func_sigs::db::{parse_fsig, DbEntry, OVERLAY_MIN_PATTERN_LEN};
use std::io::{BufWriter, Write as _};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!(
            "usage: fsig-pack <in.fsig> [more.fsig ...] --out <out.fbd> [--families]\n\
             packs text overlay(s) into a binary FRBD file with prebuilt indexes"
        );
        std::process::exit(2);
    }
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut out = PathBuf::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => {
                i += 1;
                out = PathBuf::from(&args[i]);
            }
            other => inputs.push(PathBuf::from(other)),
        }
        i += 1;
    }
    if inputs.is_empty() || out.as_os_str().is_empty() {
        eprintln!("fsig-pack: need --out and at least one input");
        std::process::exit(2);
    }

    let mut entries: Vec<DbEntry> = Vec::new();
    let mut total_lines = 0usize;
    for inp in &inputs {
        let text = match std::fs::read_to_string(inp) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("fsig-pack: cannot read {}: {e}", inp.display());
                std::process::exit(1);
            }
        };
        let file_label: &'static str = Box::leak(inp.display().to_string().into_boxed_str());
        let (mut es, errors) = parse_fsig(&text, file_label);
        total_lines += text.lines().count();
        let n_err = errors.len();
        eprintln!("  {}: {} entries ({} parse errors)", inp.display(), es.len(), n_err);
        entries.append(&mut es);
    }

    // Dedup by (lib, name, pattern) — merged overlays may repeat entries.
    entries.sort_by(|a, b| {
        (
            a.library,
            a.function_name,
            a.bytes.as_slice(),
            a.mask.as_slice(),
        )
            .cmp(&(
                b.library,
                b.function_name,
                b.bytes.as_slice(),
                b.mask.as_slice(),
            ))
    });
    entries.dedup_by(|a, b| {
        a.library == b.library
            && a.function_name == b.function_name
            && a.bytes == b.bytes
            && a.mask == b.mask
    });

    // Same gate the text loader applies at parse time; the binary loader
    // trusts the file, so the packer must run it instead.
    let before = entries.len();
    entries.retain(|e| e.bytes.len() >= OVERLAY_MIN_PATTERN_LEN);
    eprintln!(
        "packed {} entries (from {} lines, {} dropped by gate) -> {}",
        entries.len(),
        total_lines,
        before - entries.len(),
        out.display()
    );

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let tmp = out.with_extension("fbd.tmp");
    {
        let f = std::fs::File::create(&tmp).expect("create tmp file");
        let mut w = BufWriter::with_capacity(1 << 20, f);
        func_sigs::fdb::write_fdb(&entries, &mut w).expect("write fdb");
        w.flush().expect("flush");
    }
    std::fs::rename(&tmp, &out).expect("atomic rename");
}
