//! Standalone smoke runner for the decompiler IR fuzzer.
//!
//! `cargo fuzz` (libFuzzer + sanitizer runtimes) is not available in every
//! environment, so this binary exercises the exact same generator and
//! contract as `fuzz_decompiler_ir` over a deterministic sweep of seeds:
//! structured seeds first, then a byte-noise sweep. Run it after any
//! decompiler change; any panic or printed violation is a real bug.
//!
//! Usage: `cargo run --release -p freakre-fuzz --bin smoke_decompiler_ir [N]`
//! (N = byte-noise cases, default 2000; `--` separated).

use ir_gen::{Seed, XorShift};

#[path = "fuzz_targets/ir_gen.rs"]
mod ir_gen;

fn main() {
    let mut cases: Vec<(String, Seed, Vec<u8>)> = Vec::new();

    // 1. Structured seeds: small graphs with targeted shapes.
    for opcode in 0u8..12 {
        cases.push((
            format!("structured-op{opcode}"),
            [opcode, 1, 2, 3],
            vec![opcode, 0, 4, opcode, 7, 0, opcode, 3, 1],
        ));
    }
    // Self-loop and dangling-target shapes.
    cases.push((
        "self-loop".into(),
        [0x77, 0x77, 0x77, 0x77],
        vec![3, 0, 0], // Branch b0 -> b0 (block_count + 3 modulo => b0)
    ));
    cases.push((
        "dangling-cbranch".into(),
        [0xAA, 0x55, 0xAA, 0x55],
        vec![4, 1, 0, 0, 9, 0],
    ));
    cases.push((
        "phi-bogus-preds".into(),
        [0x11, 0x22, 0x33, 0x44],
        vec![7, 5, 6, 6, 9, 0, 7, 6, 5],
    ));
    cases.push((
        "indirect-and-syscall".into(),
        [0xDE, 0xAD, 0xBE, 0xEF],
        vec![8, 2, 0, 9, 3, 1, 6, 0, 0],
    ));
    cases.push((
        "empty-body".into(),
        [0, 0, 0, 0],
        Vec::new(),
    ));

    let noise_cases: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(2000);

    // 2. Byte-noise sweep: same distribution as the libFuzzer target.
    for i in 0..noise_cases {
        let seed: Seed =
            ((i as u64).wrapping_mul(0x9E3779B97F4A7C15)).to_le_bytes()[..4].try_into().unwrap();
        let mut rng = XorShift::from_seed(&seed);
        let len = 1 + rng.below(60) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
        cases.push((format!("noise-{i}"), seed, data));
    }

    let mut decompiled = 0usize;
    let mut rejected = 0usize;
    for (name, seed, data) in &cases {
        let mut rng = XorShift::from_seed(seed);
        let func = ir_gen::build_random_ir(&mut rng, data);
        match ir_gen::run_contract(&func, seed) {
            Ok(_) => decompiled += 1,
            Err(v) => {
                if v.starts_with("rejected: ") {
                    rejected += 1;
                } else {
                    eprintln!("VIOLATION in case '{name}': {v}");
                    eprintln!("seed: {seed:?}, body: {data:?}");
                    eprintln!("---- C ----");
                    // Best effort: dump the emitted C for triage.
                    if let Ok(c) = ir_gen::reproduce_c(&func) {
                        eprintln!("{c}");
                    }
                    std::process::exit(1);
                }
            }
        }
    }

    println!(
        "smoke_decompiler_ir: {} cases ({} decompiled, {} rejected, 0 violations)",
        cases.len(),
        decompiled,
        rejected
    );
}
