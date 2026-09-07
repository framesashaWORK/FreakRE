#![no_main]

//! Fuzz the decompiler front door with randomly generated (often malformed)
//! IR functions: dangling block references, cycles, missing terminators,
//! phi nodes with bogus predecessors, huge constants, unicode symbols.
//!
//! Contract: `decompile_function` may return `Err` (limits, IR/AST errors),
//! but must never panic, hang, or emit C containing NUL bytes.
//!
//! The generator and the contract live in `ir_gen.rs`, shared with
//! `smoke_decompiler_ir.rs`, so violations found by either runner
//! reproduce with the other.

#[path = "ir_gen.rs"]
mod ir_gen;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let seed: ir_gen::Seed = [data[0], data[1], data[2], data[3]];
    let mut rng = ir_gen::XorShift::from_seed(&seed);

    let func = ir_gen::build_random_ir(&mut rng, &data[4..]);
    if let Err(violation) = ir_gen::run_contract(&func, &seed) {
        // "rejected: ..." entries are expected failure paths, not violations.
        if !violation.starts_with("rejected: ") {
            panic!("decompiler contract violation: {violation}");
        }
    }
});
