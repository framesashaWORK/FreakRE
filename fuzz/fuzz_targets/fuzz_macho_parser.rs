#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Mach-O parser — must never panic on malformed input
    let _ = macho_parser::MachoFile::parse(data);
    let _ = macho_parser::parse_fat_header(data);
});
