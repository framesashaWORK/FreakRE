//! Adversarial / guard tests: hostile IR and budget exhaustion must always
//! produce a clean, classified stop -- never a panic.

use emulator_x86::{BudgetKind, DefaultEnv, Emulator, ExitReason};
use freakre_ir::ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use freakre_ir::Ty;
use freakre_ir::lifter::Lifter;
use freakre_ir::x86_lifter::X86Lifter;

const BASE: u64 = 0x0040_1000;

/// Push a Binary inst onto the entry block.
fn bin(f: &mut IrFunction, dst: &Value, op: OpCode, l: Value, r: Value) {
    f.push_inst(
        f.entry_block,
        IrInst::Binary {
            dst: dst.clone(),
            op,
            lhs: l,
            rhs: r,
        },
    );
}

fn store_const(f: &mut IrFunction, addr: &Value, val: i64, size: u32) {
    f.push_inst(f.entry_block, IrInst::Store {
        addr: addr.clone(),
        value: Value::Const(val),
        size,
    });
}

#[test]
fn div_by_zero_is_unsupported_not_panic() {
    let mut f = IrFunction::new("divz", BASE);
    let v = f.alloc_var(Ty::i64());
    bin(&mut f, &v, OpCode::Div, Value::Const(1), Value::Const(0));
    f.push_inst(f.entry_block, IrInst::Return { value: Some(v) });

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&f, BASE, 0, 100);

    match res.exit_reason {
        ExitReason::Unsupported { what, .. } => assert!(what.contains("divis"), "{what}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn modulo_by_zero_is_unsupported() {
    let mut f = IrFunction::new("modz", BASE);
    let v = f.alloc_var(Ty::i64());
    bin(&mut f, &v, OpCode::Mod, Value::Const(7), Value::Const(0));
    f.push_inst(f.entry_block, IrInst::Return { value: Some(v) });

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&f, BASE, 0, 100);
    assert!(matches!(res.exit_reason, ExitReason::Unsupported { .. }));
}

#[test]
fn dangling_branch_stops_safely() {
    let mut f = IrFunction::new("dangle", BASE);
    f.push_inst(f.entry_block, IrInst::Branch { target: BlockId(42) });

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&f, BASE, 0, 100);

    match res.exit_reason {
        ExitReason::Unsupported { what, .. } => assert!(what.contains("undefined block")),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn indirect_branch_and_phi_are_unsupported() {
    for inst in [
        IrInst::IndirectBranch { target: Value::Const(0x1000) },
        IrInst::Phi {
            dst: Value::var(0, Ty::i64()),
            incoming: vec![(BlockId(0), Value::Const(1))],
        },
    ] {
        let mut f = IrFunction::new("bad", BASE);
        f.push_inst(f.entry_block, inst);
        let mut emu = Emulator::new(DefaultEnv::new());
        let res = emu.run(&f, BASE, 0, 100);
        assert!(matches!(res.exit_reason, ExitReason::Unsupported { .. }));
    }
}

#[test]
fn infinite_jmp_hits_step_budget() {
    // jmp $ (infinite self-loop)
    let code = [0xEB, 0xFE];
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&code, BASE, "spin").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&func, BASE, 0, 1_000);

    assert_eq!(res.exit_reason, ExitReason::BudgetExhausted(BudgetKind::Steps));
    assert_eq!(res.steps, 1_001); // limit + the step that tripped it
}

#[test]
fn memory_budget_guard_trips() {
    // Store to page 0, then to page +4096 with a one-page memory budget.
    let mut f = IrFunction::new("hog", BASE);
    let v = f.alloc_var(Ty::i64());
    f.push_inst(f.entry_block, IrInst::Binary {
        dst: v.clone(),
        op: OpCode::Copy,
        lhs: Value::Const(0x10_0000),
        rhs: Value::Const(0),
    });
    store_const(&mut f, &v, 0xAA, 1);
    let w = f.alloc_var(Ty::i64());
    bin(&mut f, &w, OpCode::Add, v.clone(), Value::Const(0x1000));
    store_const(&mut f, &w, 0xBB, 1);
    f.push_inst(f.entry_block, IrInst::Return { value: None });

    let mut emu = Emulator::with_limits(DefaultEnv::new(), 4096, 128);
    let res = emu.run(&f, BASE, 0, 1_000);

    assert_eq!(res.exit_reason, ExitReason::BudgetExhausted(BudgetKind::Memory));
}

/// Garbage widths / shift counts / truncations must saturate sanely.
#[test]
fn hostile_arithmetic_saturates_without_panic() {
    const OUT: u64 = 0x5000_0000;
    let mut f = IrFunction::new("hostile", BASE);

    // v_shl = 1 << 500  (count masked to 52 -> 1<<52)
    let shl = f.alloc_var(Ty::i64());
    bin(&mut f, &shl, OpCode::Shl, Value::Const(1), Value::Const(500));

    // v_sar = i64::MIN >>> arithmetic 63 -> -1
    let sar = f.alloc_var(Ty::i64());
    bin(&mut f, &sar, OpCode::Sar, Value::Const(i64::MIN), Value::Const(63));

    // v_trunc = 0x11223344 truncated to 8 bits
    let tr_dst = Value::var(90, Ty::u8());
    f.push_inst(f.entry_block, IrInst::Unary {
        dst: tr_dst.clone(),
        op: OpCode::Trunc,
        src: Value::Const(0x1122_3344),
    });

    // v_sext = sign-extend 0xFF from 8 bits (use i8 var as source to encode 8-bit width)
    let sx_src = f.alloc_var(Ty::i8());
    f.push_inst(f.entry_block, IrInst::Unary {
        dst: sx_src.clone(),
        op: OpCode::Copy,
        src: Value::Const(0xFF),
    });
    let sx_dst = Value::var(91, Ty::i64());
    f.push_inst(f.entry_block, IrInst::Unary {
        dst: sx_dst.clone(),
        op: OpCode::Sext,
        src: sx_src,
    });

    let base = f.alloc_var(Ty::i64());
    f.push_inst(f.entry_block, IrInst::Binary {
        dst: base.clone(),
        op: OpCode::Copy,
        lhs: Value::Const(OUT as i64),
        rhs: Value::Const(0),
    });

    // scratch = OUT; store results at increasing offsets.
    let t = f.alloc_var(Ty::i64());
    f.push_inst(f.entry_block, IrInst::Binary {
        dst: t.clone(),
        op: OpCode::Add,
        lhs: base.clone(),
        rhs: Value::Const(0),
    });
    f.push_inst(f.entry_block, IrInst::Store { addr: t.clone(), value: shl, size: 8 });
    let t2 = f.alloc_var(Ty::i64());
    bin(&mut f, &t2, OpCode::Add, base.clone(), Value::Const(8));
    f.push_inst(f.entry_block, IrInst::Store { addr: t2, value: sar, size: 8 });
    let t3 = f.alloc_var(Ty::i64());
    bin(&mut f, &t3, OpCode::Add, base.clone(), Value::Const(16));
    f.push_inst(f.entry_block, IrInst::Store { addr: t3.clone(), value: tr_dst.clone(), size: 1 });
    let t4 = f.alloc_var(Ty::i64());
    bin(&mut f, &t4, OpCode::Add, base, Value::Const(24));
    f.push_inst(f.entry_block, IrInst::Store { addr: t4, value: sx_dst, size: 8 });

    f.push_inst(f.entry_block, IrInst::Return { value: None });

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&f, BASE, 0, 1_000);
    assert_eq!(res.exit_reason, ExitReason::Return);

    let rd = |off: u64, n: usize| {
        let mut b = vec![0u8; n];
        emu.memory().read_bytes(OUT + off, &mut b);
        b
    };
    assert_eq!(rd(0, 8), (1u64 << 52).to_le_bytes()); // shift count masked &63 (500 & 63 = 52)
    assert_eq!(rd(8, 8), (-1i64 as u64).to_le_bytes()); // Sar is arithmetic
    assert_eq!(rd(16, 1), vec![0x44]); // Trunc to 8 bits
    assert_eq!(rd(24, 8), (-1i64 as u64).to_le_bytes()); // Sext 0xFF -> -1
}

#[test]
fn zero_entry_offset_outside_image_errors_cleanly() {
    let code = [0xC3];
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&code, BASE, "r").unwrap();

    let mut emu = Emulator::new(DefaultEnv::new());
    let res = emu.run(&func, BASE + 0x99, 0x33, 10);
    assert!(matches!(res.exit_reason, ExitReason::Unsupported { .. }));
}
