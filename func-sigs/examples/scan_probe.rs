//! Scratch verification (deleted before commit): scan a real .text with the
//! full DB (overlay dir loaded from an explicit path) and print statistics.
//! Usage: scan_probe <overlay-dir> <target.dll>
use func_sigs::db;
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = db::load_overlay_dir(std::path::Path::new(&args[1])).expect("overlay load");
    println!("overlay entries: {n}");

    let data = std::fs::read(&args[2]).expect("read target");
    let pe = pe_parser::PeFile::parse(&data).expect("pe parse");
    let text = pe
        .sections
        .iter()
        .find(|s| s.name_string() == ".text")
        .expect(".text");
    let off = text.raw_data_offset as usize;
    let len = (text.raw_data_size as usize).min(2_000_000);
    let code = &data[off..off + len];
    println!("target: {} bytes, 64bit={}", code.len(), pe.is_64bit);

    let (_, exports) = pe.exports();
    let stem = std::path::Path::new(&args[2])
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let self_lib = if stem.eq_ignore_ascii_case("kb") {
        "kernel32"
    } else {
        stem
    };
    let text_rva = text.virtual_address as usize;
    let exp_at: HashMap<usize, &String> = exports
        .iter()
        .map(|(_, n, r)| ((*r as usize).wrapping_sub(text_rva), n))
        .collect();

    // Split `Name+0xNN` interior anchors: the effective base is offset-rel.
    fn split_anchor(name: &str) -> (&str, usize) {
        match name.rsplit_once('+') {
            Some((base, rel)) if rel.starts_with("0x") => (
                base,
                usize::from_str_radix(rel.trim_start_matches("0x"), 16).unwrap_or(0),
            ),
            _ => (name, 0),
        }
    }

    let t = std::time::Instant::now();
    let hits = db::scan_db(code, 0, 1, 500_000);
    println!("scan: {:?}, db hits={}", t.elapsed(), hits.len());

    let (mut exact, mut misattr, mut self_noexp) = (0, 0, 0);
    let (mut shared, mut fp) = (0, 0);
    let mut fp_names: Vec<String> = Vec::new();
    for h in &hits {
        let (lib, name, _, _, _) = db::resolve_hit(h);
        let (base, rel) = split_anchor(name);
        let eff = h.offset.wrapping_sub(rel);
        let on_export = exp_at.contains_key(&eff);
        let same_name = exp_at.get(&eff).map(|n| *n == base).unwrap_or(false);
        if lib == self_lib {
            if same_name {
                exact += 1;
            } else if on_export {
                misattr += 1;
            } else {
                self_noexp += 1;
            }
        } else if on_export {
            shared += 1;
        } else {
            fp += 1;
            if fp_names.len() < 8 {
                fp_names.push(format!("0x{:06X} {lib}::{name}", h.offset));
            }
        }
    }
    println!("self-lib {self_lib}: exact={exact} misattributed={misattr} no-export={self_noexp}");
    println!("cross-lib: shared-code={shared} true-fp={fp}");
    for f in &fp_names {
        println!("  FP?: {f}");
    }
}
