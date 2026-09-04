//! String recovery from guest-written memory: a tiny stub materialises
//! "Hi!" at a known address; recovery must find it with the right VA.
use emulator_x86::env::DefaultEnv;
use emulator_x86::{recover_written_strings, Emulator};
use freakre_ir::lifter::Lifter;

#[test]
fn recovers_runtime_written_string() {
    // mov rax, 0x2000; mov dword [rax], 0x00216948 ('H','i','!'); ret
    let code = [
        0x48, 0xB8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x2000
        0xC7, 0x00, 0x48, 0x69, 0x21, 0x00, // mov dword [rax], 'Hi!\0'
        0xC3, // ret
    ];
    let func = freakre_ir::x86_lifter::X86Lifter::new(true)
        .lift_function(&code, 0x1000, "stub")
        .expect("lift");
    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&func, 0x1000, 0, 1_000);
    assert_eq!(res.exit_reason, emulator_x86::ExitReason::Return);

    let strings = recover_written_strings(&emu, 2);
    assert!(
        strings.iter().any(|s| s.address == 0x2000 && s.text == "Hi!"),
        "expected 'Hi!' @ 0x2000, got: {strings:?}"
    );
}

#[test]
fn empty_run_recovers_nothing() {
    // ret immediately: no writes, no strings.
    let code = [0xC3];
    let func = freakre_ir::x86_lifter::X86Lifter::new(true)
        .lift_function(&code, 0x1000, "empty")
        .expect("lift");
    let mut emu = Emulator::new(DefaultEnv::new());
    emu.run(&func, 0x1000, 0, 100);
    assert!(recover_written_strings(&emu, 2).is_empty());
}
