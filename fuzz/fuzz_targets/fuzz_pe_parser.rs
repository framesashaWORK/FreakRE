#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz PE parser — must never panic on malformed input
    let _ = pe_parser::PeFile::parse(data);
});
