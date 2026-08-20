#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz entropy calculation — should never panic
    let result = entropy_rs::calculate_entropy(data);
    let _ = result.classify();
});
