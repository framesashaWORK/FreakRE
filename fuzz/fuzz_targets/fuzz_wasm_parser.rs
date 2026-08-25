#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz WASM parser — must never panic on malformed modules
    if let Ok(module) = wasm_parser::parse_wasm(data) {
        // Touch derived accessors on successfully parsed modules
        let _ = module.total_functions();
        let _ = module.imported_function_names();
        let _ = module.exported_function_names();
        let _ = module.total_code_size();
    }
});
