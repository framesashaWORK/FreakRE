#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz string extraction
    let config = str_extract::ExtractConfig::windows_pe(4);
    let _ = str_extract::extract_strings(data, &config);
});
