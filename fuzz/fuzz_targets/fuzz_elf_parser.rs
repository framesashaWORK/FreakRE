#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz ELF parser — must never panic on malformed input
    let _ = elf_parser::ElfFile::parse(data);
});
