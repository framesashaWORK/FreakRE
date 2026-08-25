#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz DEX parser — must never panic on malformed DEX files
    let _ = dex_parser::parse_dex(data);
});
