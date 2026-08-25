#![no_main]

use freakre_ir::Lifter as _;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz x86/x64 IR lifting — random bytes lifted as a fake function body
    // must never panic. First byte selects the mode, rest is machine code.
    if data.is_empty() {
        return;
    }
    let is_64bit = (data[0] & 1) == 0;
    let lifter = freakre_ir::x86_lifter::X86Lifter::new(is_64bit);
    // Errors (invalid instructions, limits) are expected; panics are not.
    let _ = lifter.lift_function(&data[1..], 0x401000, "fuzz_func");
});
