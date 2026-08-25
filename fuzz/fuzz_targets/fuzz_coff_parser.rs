#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz COFF parser — must never panic on malformed object files
    if let Ok(coff) = coff_parser::parse_coff(data) {
        let _ = coff.machine_name();
        let _ = coff.functions();
        let _ = coff.externals();
    }
});
