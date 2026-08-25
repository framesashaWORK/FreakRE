#![no_main]

use freakre_x86::types::Mode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz x86/x64 LDE + full decoder — must never panic on malformed code.
    // First 2 bytes select the mode, the rest is treated as instruction bytes.
    if data.len() < 3 {
        return;
    }
    let mode = if (u16::from_le_bytes([data[0], data[1]]) & 1) == 0 {
        Mode::X64
    } else {
        Mode::X86
    };
    let code = &data[2..];

    if let Ok(len) = freakre_x86::lde::decode_len(code, mode) {
        // Invariant: neither the LDE nor the full decoder may panic;
        // malformed input must always produce Err instead.
        let len = len.min(code.len());
        let _ = freakre_x86::decoder::decode(&code[..len], 0x401000, mode);
    }
});
