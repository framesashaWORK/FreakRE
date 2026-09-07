//! `fsig-clean` — curator for harvested `.fsig` signature databases.
//!
//! Loads every `.fsig` given on the command line (or a whole directory),
//! finds and removes garbage, then re-emits clean databases split into
//! quality tiers for the UI picker:
//!
//! - `low`    (~1.2M entries): highest-confidence core — popular libraries,
//!   strong patterns, no conflicts.
//! - `basic`  (~2.7M entries): low + the good medium tier.
//! - `freak`  (everything): basic + the long tail.
//!
//! What counts as garbage:
//! - exact duplicate lines (same lib|arch|name|min_len|conf|pattern),
//! - duplicate patterns mapping to different names (ambiguity — only the
//!   most specific, highest-confidence candidate survives),
//! - too-generic patterns (fixed-byte ratio below threshold) and entries
//!   shorter than the overlay loader's 16-byte gate (dead weight),
//! - harvester-artifact names (`ordinal_*`, `#...`, control chars),
//! - aka-lists repeating the entry's own name.
//!
//! By default the tool never touches the inputs: it writes
//! `generated-low.fsig` / `generated-basic.fsig` / `generated-freak.fsig`
//! into `--out` plus a JSON report. With `--in-place` it instead rewrites
//! the `generated-*.fsig` inputs in place (curated files are never
//! rewritten) and skips tier files.

use func_sigs::db::parse_fsig;
use std::collections::{HashMap, HashSet};
use std::io::Write as _;

/// Patterns with fewer fixed bytes than this ratio are noise-prone junk.
const GENERIC_RATIO: f64 = 0.35;
/// The overlay loader silently drops patterns shorter than this; keeping
/// them in a generated database is dead weight.
const OVERLAY_MIN_PATTERN_LEN: usize = 16;
/// min_len larger than this cannot be a real function bound.
const MAX_SANE_MIN_LEN: usize = 4096;

#[derive(Clone)]
struct Loaded {
    line: String,
    file: String,
    is_generated: bool,
    lib: String,
    arch: u8,
    name: String,
    min_len: usize,
    conf: f64,
    bytes_len: usize,
    concrete: usize,
    pattern_key: u64,
    pop: usize,
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn arch_id(s: &str) -> u8 {
    match s {
        "x86" => 1,
        "x64" => 2,
        "arm64" => 3,
        "arm" => 4,
        _ => 0,
    }
}

fn is_junk_name(name: &str) -> bool {
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.starts_with("ordinal_") || lower.starts_with('#')
}

fn quality(e: &Loaded) -> u64 {
    let specificity = if e.bytes_len > 0 {
        e.concrete as f64 / e.bytes_len as f64
    } else {
        0.0
    };
    (e.conf * 1000.0) as u64
        + (specificity * 100.0) as u64
        + (e.bytes_len.min(64) as u64)
}

/// Load all files, aligning each parsed entry with its source line.
/// `parse_fsig` skips blank/`#` lines, so the alignment must mirror that.
fn load_files(paths: &[std::path::PathBuf]) -> (Vec<Loaded>, usize) {
    let mut out = Vec::new();
    let mut parse_errors = 0usize;
    for p in paths {
        let text = match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("skip {}: {e}", p.display());
                continue;
            }
        };
        let fname = p.display().to_string();
        let is_generated = p
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.starts_with("generated"))
            .unwrap_or(false);
        let (entries, errors) = parse_fsig(&text, "fsig-clean");
        parse_errors += errors.len();
        let mut it = entries.into_iter();
        for raw in text.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some(_e) = it.next() else { break };
            let parts: Vec<&str> = raw.split('|').collect();
            if parts.len() < 6 {
                continue;
            }
            let body: String = parts[5]
                .split_whitespace()
                .collect::<String>()
                .to_ascii_lowercase();
            out.push(Loaded {
                line: raw.to_string(),
                file: fname.clone(),
                is_generated,
                lib: parts[0].trim().to_string(),
                arch: arch_id(parts[1].trim()),
                name: parts[2].trim().to_string(),
                min_len: parts[3].trim().parse().unwrap_or(0),
                conf: parts[4].trim().parse().unwrap_or(0.0),
                bytes_len: body.len() / 2,
                concrete: body.bytes().filter(|&b| b != b'?').count() / 2,
                pattern_key: fnv1a(body.as_bytes()),
                pop: 0,
            });
        }
    }
    (out, parse_errors)
}

struct Stats {
    dup_lines: usize,
    junk_names: usize,
    conflicts: usize,
    merged_variants: usize,
    too_generic: usize,
    aka_fixed: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut inputs: Vec<std::path::PathBuf> = Vec::new();
    let mut out_dir = std::path::PathBuf::from("tmp/fsig-clean");
    let mut in_place = false;
    let mut report_path: Option<std::path::PathBuf> = None;
    let mut low_target: usize = 1_200_000;
    let mut basic_target: usize = 2_700_000;
    let mut min_ratio = GENERIC_RATIO;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_dir = std::path::PathBuf::from(args.get(i).map(String::as_str).unwrap_or(""));
            }
            "--report" => {
                i += 1;
                report_path = Some(std::path::PathBuf::from(
                    args.get(i).map(String::as_str).unwrap_or(""),
                ));
            }
            "--low-target" => {
                i += 1;
                low_target = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(low_target);
            }
            "--basic-target" => {
                i += 1;
                basic_target = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(basic_target);
            }
            "--min-ratio" => {
                i += 1;
                min_ratio = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(min_ratio);
            }
            "--in-place" => in_place = true,
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => inputs.push(std::path::PathBuf::from(other)),
        }
        i += 1;
    }
    if inputs.is_empty() {
        print_help();
        std::process::exit(2);
    }

    // Expand directories: every *.fsig inside (sorted for determinism).
    let mut files = Vec::new();
    for p in &inputs {
        if p.is_dir() {
            let mut kids: Vec<std::path::PathBuf> = std::fs::read_dir(p)
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.path())
                        .filter(|c| {
                            c.extension()
                                .map(|e| e.eq_ignore_ascii_case("fsig"))
                                .unwrap_or(false)
                        })
                        .collect()
                })
                .unwrap_or_default();
            kids.sort();
            files.extend(kids);
        } else {
            files.push(p.clone());
        }
    }

    eprintln!("loading {} file(s)...", files.len());
    let t0 = std::time::Instant::now();
    let (all, parse_errors) = load_files(&files);
    let total_before = all.len();
    eprintln!(
        "loaded {total_before} entries, {parse_errors} parse errors skipped in {:?}",
        t0.elapsed()
    );

    let mut st = Stats {
        dup_lines: 0,
        junk_names: 0,
        conflicts: 0,
        merged_variants: 0,
        too_generic: 0,
        aka_fixed: 0,
    };

    // Pass 1: exact duplicate lines.
    let mut seen_line: HashSet<u64> = HashSet::with_capacity(all.len());
    let mut p1 = Vec::with_capacity(all.len());
    for e in all {
        if seen_line.insert(fnv1a(e.line.as_bytes())) {
            p1.push(e);
        } else {
            st.dup_lines += 1;
        }
    }

    // Pass 2: junk names.
    let mut p2 = Vec::with_capacity(p1.len());
    for e in p1 {
        if is_junk_name(&e.name) {
            st.junk_names += 1;
        } else {
            p2.push(e);
        }
    }

    // Pass 3: same pattern (per arch) -> conflicting names. Keep the best
    // candidate; count name disagreements as conflicts, same-name variants
    // (different min_len/conf) as merges.
    let mut groups: HashMap<(u64, u8), Vec<Loaded>> = HashMap::with_capacity(p2.len());
    for e in p2 {
        groups.entry((e.pattern_key, e.arch)).or_default().push(e);
    }
    let mut p3 = Vec::with_capacity(groups.len());
    for (_, mut group) in groups {
        group.sort_by(|a, b| quality(b).cmp(&quality(a)).then(a.name.cmp(&b.name)));
        let mut best = group.swap_remove(0);
        if !group.is_empty() {
            let mut saw_conflict = false;
            let mut aka_names: Vec<String> = Vec::new();
            let mut seen_aka: HashSet<String> = HashSet::new();
            if let Some(ak) = best.line.find("|aka=") {
                for n in best.line[ak + 5..].split(',') {
                    if seen_aka.insert(n.to_string()) {
                        aka_names.push(n.to_string());
                    }
                }
            }
            for o in &group {
                if o.name != best.name {
                    saw_conflict = true;
                    if seen_aka.insert(o.name.clone()) {
                        aka_names.push(o.name.clone());
                    }
                }
            }
            if saw_conflict {
                st.conflicts += group.len();
                // Preserve the losing names as aliases on the survivor
                // (bounded so no line explodes).
                aka_names.truncate(8);
                if !aka_names.is_empty() {
                    match best.line.find("|aka=") {
                        Some(ak) => best.line.replace_range(ak + 5.., &aka_names.join(",")),
                        None => {
                            best.line.push_str("|aka=");
                            best.line.push_str(&aka_names.join(","));
                        }
                    }
                }
            } else {
                st.merged_variants += group.len();
            }
        }
        best.pop = 0;
        p3.push(best);
    }

    // Pass 4: too-generic patterns, dead-short generated entries, insane
    // min_len. Curated hand-written databases are exempt from the ratio and
    // length gates (their entries are tuned and the embedded loader allows
    // shorter patterns).
    let mut p4 = Vec::with_capacity(p3.len());
    for e in p3 {
        let ratio = if e.bytes_len > 0 {
            e.concrete as f64 / e.bytes_len as f64
        } else {
            0.0
        };
        let dead_short = e.is_generated && e.bytes_len < OVERLAY_MIN_PATTERN_LEN;
        if e.min_len > MAX_SANE_MIN_LEN || dead_short || (e.is_generated && ratio < min_ratio) {
            st.too_generic += 1;
        } else {
            p4.push(e);
        }
    }

    // Pass 5: aka lists that repeat the entry's own name get rewritten.
    let mut clean = Vec::with_capacity(p4.len());
    for mut e in p4 {
        if let Some(aka_idx) = e.line.find("|aka=") {
            let head = e.line[..aka_idx].to_string();
            let aka_part = &e.line[aka_idx + 5..];
            let raw_count = aka_part.split(',').count();
            let names: Vec<&str> = aka_part
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty() && *n != e.name)
                .collect();
            if names.len() != raw_count {
                st.aka_fixed += 1;
                e.line = if names.is_empty() {
                    head
                } else {
                    format!("{head}|aka={}", names.join(","))
                };
            }
        }
        clean.push(e);
    }

    // Tiers: popularity-first, then quality, then name for stability.
    let mut pop: HashMap<String, usize> = HashMap::with_capacity(clean.len() / 8);
    for e in &clean {
        *pop.entry(e.lib.clone()).or_default() += 1;
    }
    for e in &mut clean {
        e.pop = pop.get(&e.lib).copied().unwrap_or(0);
    }
    clean.sort_by(|a, b| {
        b.pop
            .cmp(&a.pop)
            .then_with(|| quality(b).cmp(&quality(a)))
            .then_with(|| a.name.cmp(&b.name))
    });

    let basic_len = basic_target.min(clean.len());
    let low_len = low_target.min(basic_len);

    std::fs::create_dir_all(&out_dir).unwrap_or_else(|e| {
        eprintln!("cannot create {}: {e}", out_dir.display());
        std::process::exit(1);
    });

    let write_tier = |name: &str, slice: &[Loaded]| -> std::path::PathBuf {
        let path = out_dir.join(format!("{name}.fsig"));
        let f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap_or_else(|e| {
            eprintln!("cannot create {}: {e}", path.display());
            std::process::exit(1);
        }));
        let mut w = f;
        writeln!(w, "# {name} tier: {} entries, curated by fsig-clean", slice.len())
            .unwrap_or_else(|e| {
                eprintln!("write failed: {e}");
                std::process::exit(1);
            });
        for e in slice {
            writeln!(w, "{}", e.line).unwrap_or_else(|e| {
                eprintln!("write failed: {e}");
                std::process::exit(1);
            });
        }
        path
    };

    let mut low_p = None;
    let mut basic_p = None;
    let mut freak_p = None;
    if in_place {
        // Rewrite each generated-*.fsig input in place with only its own
        // surviving entries; curated files stay untouched.
        let mut by_file: HashMap<String, Vec<&Loaded>> = HashMap::new();
        for e in &clean {
            if e.is_generated {
                by_file.entry(e.file.clone()).or_default().push(e);
            }
        }
        let mut order: Vec<&String> = by_file.keys().collect();
        order.sort();
        for fname in order {
            let list = &by_file[fname];
            let path = std::path::PathBuf::from(fname);
            let tmp = path.with_extension("fsig.clean-tmp");
            {
                let f = std::io::BufWriter::new(
                    std::fs::File::create(&tmp).unwrap_or_else(|e| {
                        eprintln!("cannot create {}: {e}", tmp.display());
                        std::process::exit(1);
                    }),
                );
                let mut w = f;
                for e in list {
                    writeln!(w, "{}", e.line).unwrap_or_else(|e| {
                        eprintln!("write failed: {e}");
                        std::process::exit(1);
                    });
                }
            }
            std::fs::rename(&tmp, &path).unwrap_or_else(|e| {
                eprintln!("rename failed: {e}");
                std::process::exit(1);
            });
        }
    } else {
        low_p = Some(write_tier("generated-low", &clean[..low_len]));
        basic_p = Some(write_tier("generated-basic", &clean[..basic_len]));
        freak_p = Some(write_tier("generated-freak", &clean));
    }

    let report = serde_json::json!({
        "input_files": files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "entries_loaded": total_before,
        "parse_errors_skipped": parse_errors,
        "removed_or_fixed": {
            "exact_duplicate_lines": st.dup_lines,
            "junk_names": st.junk_names,
            "pattern_name_conflicts_dropped": st.conflicts,
            "same_name_variants_merged": st.merged_variants,
            "too_generic_or_dead": st.too_generic,
            "aka_self_references_fixed": st.aka_fixed,
        },
        "entries_clean": clean.len(),
        "tiers": {
            "low": { "target": low_target, "emitted": low_len,
                     "path": low_p.as_ref().map(|p| p.display().to_string()) },
            "basic": { "target": basic_target, "emitted": basic_len,
                       "path": basic_p.as_ref().map(|p| p.display().to_string()) },
            "freak": { "emitted": clean.len(),
                       "path": freak_p.as_ref().map(|p| p.display().to_string()) },
        },
        "elapsed_secs": t0.elapsed().as_secs_f64(),
    });
    let report_json = serde_json::to_string_pretty(&report).unwrap_or_default();
    let rp = report_path.unwrap_or_else(|| out_dir.join("clean-report.json"));
    std::fs::write(&rp, &report_json).unwrap_or_else(|e| {
        eprintln!("cannot write {}: {e}", rp.display());
        std::process::exit(1);
    });

    println!("{report_json}");
}

fn print_help() {
    eprintln!(
        "fsig-clean — curate .fsig signature databases\n\n\
USAGE:\n  fsig-clean [FLAGS] <file.fsig | dir> ...\n\n\
FLAGS:\n\
  --out <dir>          output dir for low/basic/freak tiers (default tmp/fsig-clean)\n\
  --report <path>      JSON report path (default <out>/clean-report.json)\n\
  --low-target <N>     low-tier entry cap (default 1200000)\n\
  --basic-target <N>   basic-tier entry cap (default 2700000)\n\
  --min-ratio <R>      min fixed-byte ratio for generated entries (default 0.35)\n\
  --in-place           rewrite generated-*.fsig inputs in place instead of tier files\n\
  -h, --help\n\n\
TIERS:\n\
  low    ~1.2M best entries (quick scans)\n\
  basic  ~2.7M entries (default UI mode)\n\
  freak  everything clean (full coverage)"
    );
}
