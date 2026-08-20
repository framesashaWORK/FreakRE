#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz YARA parser — must not panic on malformed rules
    if let Ok(source) = std::str::from_utf8(data) {
        if let Ok(parsed) = yara_lite::parse_rules(source) {
            // Try to compile each rule
            for rule in &parsed {
                let _ = yara_lite::compile_rule(rule);
            }
        }
    }
});
