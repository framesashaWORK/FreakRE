//! Decompile every function of the bench PEs and dump C files.
//!
//! Usage: decomp_bench <pe_or_dir> <out_dir>
//! For each input PE (recursively for dirs), detects functions in `.text`,
//! decompiles each one and writes `<stem>_sub_<ADDR>.c` into `<out_dir>`.

use std::path::PathBuf;

fn collect_pes(path: &PathBuf, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                collect_pes(&e.path(), out);
            }
        }
    } else if path.extension().is_some_and(|e| e == "exe" || e == "dll") {
        out.push(path.clone());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: decomp_bench <pe_or_dir> <out_dir> [va1,va2,...]");
        std::process::exit(2);
    }
    let mut pes = Vec::new();
    collect_pes(&PathBuf::from(&args[1]), &mut pes);
    let out_dir = PathBuf::from(&args[2]);
    std::fs::create_dir_all(&out_dir).expect("out dir");
    // Optional function filter `VA:SIZE_HEX,VA:SIZE_HEX,...` (image-absolute
    // VA + byte size, from a linker map): decompile exactly those functions.
    let mut addrs: Vec<(u64, usize)> = Vec::new();
    if let Some(spec) = args.get(3) {
        for pair in spec.split(',') {
            let mut it = pair.split(':');
            let (Some(va), Some(sz)) = (it.next(), it.next()) else {
                continue;
            };
            let va = u64::from_str_radix(va.trim_start_matches("0x"), 16);
            let sz = usize::from_str_radix(sz.trim_start_matches("0x"), 16);
            if let (Ok(va), Ok(sz)) = (va, sz) {
                addrs.push((va, sz));
            }
        }
    }

    let mut total_funcs = 0usize;
    let mut ok_files = 0usize;
    for pe_path in &pes {
        let stem = pe_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("mod")
            .to_string();
        let Ok(data) = std::fs::read(pe_path) else {
            eprintln!("{}: unreadable", stem);
            continue;
        };
        if !addrs.is_empty() {
            let mut funcs = 0usize;
            for (va, sz) in &addrs {
                match freakre_scanner::decompile_api::decompile_pe_function_sized(&data, *va, *sz) {
                    Ok(f) => {
                        let name = format!("{}_sub_{:X}.c", stem, f.address);
                        std::fs::write(out_dir.join(&name), &f.c_code).expect("write c");
                        funcs += 1;
                    }
                    Err(e) => eprintln!("{} @ {:X}: {}", stem, va, e),
                }
            }
            eprintln!("{}: {} of {} addrs decompiled", stem, funcs, addrs.len());
            total_funcs += funcs;
            ok_files += 1;
            continue;
        }
        match freakre_scanner::decompile_api::decompile_pe_all_functions(&data) {
            Ok(funcs) if !funcs.is_empty() => {
                for f in &funcs {
                    let name = format!("{}_sub_{:X}.c", stem, f.address);
                    std::fs::write(out_dir.join(&name), &f.c_code).expect("write c");
                }
                eprintln!("{}: {} functions decompiled", stem, funcs.len());
                total_funcs += funcs.len();
                ok_files += 1;
            }
            Ok(_) => eprintln!("{}: no functions decompiled", stem),
            Err(e) => eprintln!("{}: {}", stem, e),
        }
    }
    eprintln!("---- {} files, {} functions ----", ok_files, total_funcs);
}
