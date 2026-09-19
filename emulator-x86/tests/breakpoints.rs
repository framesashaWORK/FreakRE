//! Breakpoints, run-to-address and block coverage.
use emulator_x86::env::DefaultEnv;
use emulator_x86::{block_coverage, Emulator, ExitReason};
use freakre_ir::lifter::Lifter;

fn lift(code: &[u8], base: u64) -> freakre_ir::IrFunction {
    freakre_ir::x86_lifter::X86Lifter::new(true)
        .lift_function(code, base, "t")
        .expect("lift")
}

#[test]
fn breakpoint_at_entry_stops_before_first_block() {
    // mov eax, 2; add eax, 3; ret
    let code = [0xB8, 0x02, 0x00, 0x00, 0x00, 0x83, 0xC0, 0x03, 0xC3];
    let func = lift(&code, 0x1000);
    let mut emu = Emulator::new(DefaultEnv::new());
    emu.add_breakpoint(0x1000);
    let res = emu.run(&func, 0x1000, 0, 1_000);
    assert_eq!(res.exit_reason, ExitReason::Breakpoint { addr: 0x1000 });
    assert_eq!(res.steps, 0, "breakpoint fires before any instruction");
    // State is inspectable and execution resumes after removal.
    assert!(emu.remove_breakpoint(0x1000));
    assert!(
        !emu.remove_breakpoint(0x1000),
        "second remove reports absence"
    );
    let res = emu.run(&func, 0x1000, 0, 1_000);
    assert_eq!(res.exit_reason, ExitReason::Return);
    assert_eq!(res.registers["rax"], 5);
}

#[test]
fn run_to_mid_function_stops_there() {
    // jmp +2 (over two NOPs); ret. The forward-jump target (base+4) lies in
    // the middle of the fall-through block; repair links it to the
    // containing block, so the plain run executes the ret (previously the
    // target dangled and the body was pruned as unreachable → FellOffEnd).
    let code = [0xEB, 0x02, 0x90, 0x90, 0xC3];
    let func = lift(&code, 0x2000);
    let mut emu = Emulator::new(DefaultEnv::new());
    // run_to a block entry still stops with the temp breakpoint removed.
    let res = emu.run_to(&func, 0x2000, 0, 0x2002, 1_000);
    assert_eq!(res.exit_reason, ExitReason::Breakpoint { addr: 0x2002 });
    // Temporary breakpoint is always removed, even though the run stopped.
    assert!(emu.breakpoints().is_empty());
    // A plain run now reaches and executes the ret.
    let res = emu.run(&func, 0x2000, 0, 1_000);
    assert_eq!(res.exit_reason, ExitReason::Return);
}

#[test]
fn clear_breakpoints_lists_and_drops() {
    let code = [0xC3];
    let func = lift(&code, 0x3000);
    let mut emu = Emulator::new(DefaultEnv::new());
    emu.add_breakpoint(0x3000);
    emu.add_breakpoint(0x3001);
    assert_eq!(emu.breakpoints(), vec![0x3000, 0x3001]);
    emu.clear_breakpoints();
    assert!(emu.breakpoints().is_empty());
    let res = emu.run(&func, 0x3000, 0, 10);
    assert_eq!(res.exit_reason, ExitReason::Return);
}

#[test]
fn coverage_marks_executed_blocks() {
    // mov eax, 1; ret — single block at base.
    let code = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
    let func = lift(&code, 0x4000);
    let mut emu = Emulator::new(DefaultEnv::new());
    emu.run(&func, 0x4000, 0, 100);
    let cov = block_coverage(&emu.trace());
    assert!(cov.contains(&0x4000), "entry block covered: {cov:X?}");
    assert_eq!(
        cov,
        {
            let mut v = cov.clone();
            v.sort_unstable();
            v.dedup();
            v
        },
        "coverage is deduplicated"
    );
}
