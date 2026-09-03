//! Demo tests: real x86-64 byte sequences lifted with `X86Lifter` and
//! emulated end-to-end over the lifted IR.

use emulator_x86::{DefaultEnv, Emulator, ExitReason, MemRegion};
use freakre_ir::lifter::Lifter;
use freakre_ir::x86_lifter::X86Lifter;

/// xor byte ptr [rdi+rax], 0x37 ; inc rax ; cmp rax, 8 ; jl 0 ; ret
const XOR_LOOP: [u8; 14] = [
    0x80, 0x34, 0x07, 0x37, // 00: xor byte ptr [rdi+rax*1], 0x37
    0x48, 0xFF, 0xC0, // 04: inc rax
    0x48, 0x83, 0xF8, 0x08, // 07: cmp rax, 8
    0x7C, 0xF3, // 0B: jl -13 -> offset 0
    0xC3, // 0D: ret
];

const BASE: u64 = 0x0040_1000;
const DATA: u64 = 0x2000_0000;
const CIPHER: [u8; 8] = [0x53, 0xF6, 0x54, 0xE1, 0x99, 0x42, 0x77, 0x0F];
const KEY: u8 = 0x37;

#[test]
fn xor_loop_decodes_payload() {
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&XOR_LOOP, BASE, "xor_stub").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    emu.init_mem(DATA, &CIPHER);
    emu.set_reg("rdi", DATA);
    emu.set_reg("rax", 0);

    let res = emu.run(&func, BASE, 0, 100_000);

    assert_eq!(res.exit_reason, ExitReason::Return, "loop must run to ret");
    assert!(res.steps > 8 && res.steps < 100_000, "steps={}", res.steps);

    // Plaintext landed in guest memory.
    let mut out = [0u8; 8];
    emu.memory().read_bytes(DATA, &mut out);
    let expected: Vec<u8> = CIPHER.iter().map(|b| b ^ KEY).collect();
    assert_eq!(&out, &expected[..], "decoded payload mismatch");

    // Write tracking saw exactly the payload region.
    assert_eq!(
        res.written_regions,
        vec![MemRegion { start: DATA, len: CIPHER.len() as u64 }]
    );

    // Loop counter ended at the compare bound.
    assert_eq!(res.registers["rax"], CIPHER.len() as u64);

    // Trace ring recorded the loop.
    let trace = emu.trace();
    assert!(!trace.is_empty());
    assert!(trace.iter().any(|t| t.text.contains("XOR")));
}

#[test]
fn entry_offset_starts_mid_image() {
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&XOR_LOOP, BASE, "xor_stub").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    emu.init_mem(DATA, &CIPHER);
    emu.set_reg("rdi", DATA);
    emu.set_reg("rax", 4); // resume decode from index 4

    let res = emu.run(&func, BASE, 0x04, 100_000); // start at `inc rax`

    assert_eq!(res.exit_reason, ExitReason::Return);
    let mut out = [0u8; 8];
    emu.memory().read_bytes(DATA, &mut out);
    for i in 0..8 {
        let want = if i < 4 { CIPHER[i] } else { CIPHER[i] ^ KEY };
        assert_eq!(out[i], want, "byte {i}");
    }
}

/// movabs rax, PATCH ; mov byte [rax], 0x5A ; mov dl, [rax] ; ret
///
/// Exercises write-tracking of runtime stores and store->load round-trip.
/// NOTE: the interpreter executes statically lifted IR, so a store onto code
/// bytes is tracked as data but does NOT re-lift control flow (documented
/// limitation in lib.rs).
#[test]
fn self_writing_code_write_tracking() {
    const PATCH: u64 = 0x3000_0100;
    let mut patch_addr = [0u8; 8];
    patch_addr.copy_from_slice(&PATCH.to_le_bytes());

    let mut code = vec![0x48, 0xB8]; // movabs rax, imm64
    code.extend_from_slice(&patch_addr);
    code.extend_from_slice(&[
        0xC6, 0x00, 0x5A, // mov byte ptr [rax], 0x5A
        0x8A, 0x10, // mov dl, byte ptr [rax]
        0xC3, // ret
    ]);

    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&code, BASE, "smc").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&func, BASE, 0, 10_000);

    assert_eq!(res.exit_reason, ExitReason::Return);

    // The store was tracked as exactly one written region...
    assert_eq!(
        res.written_regions,
        vec![MemRegion { start: PATCH, len: 1 }]
    );
    // ...observed by the environment hook...
    assert_eq!(emu.env().external_writes, vec![(PATCH, 1)]);
    // ...and the patched byte is visible to subsequent loads (dl = 0x5A).
    assert_eq!(res.registers["rdx"] & 0xFF, 0x5A);

    // Guest memory actually holds the patch.
    let mut b = [0u8; 1];
    emu.memory().read_bytes(PATCH, &mut b);
    assert_eq!(b[0], 0x5A);
}

/// call rel32 (+2) ; ret -- callee is stubbed: recorded, RAX zeroed,
/// execution continues at the fall-through.
#[test]
fn call_recorded_and_stubbed() {
    let code = [
        0xE8, 0x02, 0x00, 0x00, 0x00, // 00: call +2 -> base+7
        0xC3, // 05: ret
        0xCC, // 06: pad
        0xC3, // 07: would-be callee
    ];
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&code, BASE, "caller").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&func, BASE, 0, 10_000);

    assert_eq!(res.exit_reason, ExitReason::Return);
    let calls = emu.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].target, Some(BASE + 7));
    assert_eq!(calls[0].symbol.as_deref(), Some("func_401007"));
    assert_eq!(res.registers["rax"], 0, "stubbed callee returns RAX=0");
}

/// Code ending without RET halts cleanly with FellOffEnd.
#[test]
fn fell_off_end_without_ret() {
    let code = [0x90, 0x90]; // nop nop
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&code, BASE, "noret").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&func, BASE, 0, 100);

    assert_eq!(res.exit_reason, ExitReason::FellOffEnd);
    assert_eq!(res.steps, 2);
}

/// Syscall IR reaches the environment and its result lands in RAX.
#[test]
fn syscall_logged_via_env() {
    use freakre_ir::{IrFunction, IrInst, Ty, Value};

    let mut f = IrFunction::new("sys", BASE);
    f.push_inst(
        f.entry_block,
        IrInst::Syscall {
            number: Some(Value::Const(60)),
            args: vec![Value::reg("rdi", Ty::i64())],
        },
    );
    f.push_inst(f.entry_block, IrInst::Return { value: None });

    let mut emu = Emulator::new(DefaultEnv::new());
    emu.set_reg("rdi", 42);
    let res = emu.run(&f, BASE, 0, 100);

    assert_eq!(res.exit_reason, ExitReason::Return);
    assert_eq!(res.registers["rax"], 0, "DefaultEnv syscalls return 0");
    assert_eq!(emu.env().syscalls.len(), 1);
    assert_eq!(emu.env().syscalls[0].number, Some(60));
    assert_eq!(emu.env().syscalls[0].args, vec![42]);
}
