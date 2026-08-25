#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Intel HEX / Motorola S-Record parsers — must never panic on
    // malformed text. Both formats are textual; non-hex input simply yields Err.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(hex) = flat_binary::IntelHex::parse(text) {
            let bin = hex.to_flat_binary(0x0040_0000);
            let _ = bin.entropy();
        }
        if let Ok(srec) = flat_binary::SRecord::parse(text) {
            let bin = srec.to_flat_binary(0x0040_0000);
            let _ = bin.size();
        }
    }
});
