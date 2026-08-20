//! Benchmarks for IR operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use bibleteks_ir::*;

fn bench_ir_function_creation(c: &mut Criterion) {
    c.bench_function("ir_function_100_insts", |b| {
        b.iter(|| {
            let mut func = IrFunction::new("bench_func", 0x401000);
            for i in 0..100 {
                let v = func.alloc_var(Ty::i64());
                func.push_inst(func.entry_block, IrInst::Binary {
                    dst: v,
                    op: OpCode::Add,
                    lhs: Value::reg("rax", Ty::i64()),
                    rhs: Value::Const(i),
                });
            }
            black_box(func)
        });
    });
}

fn bench_cfg_construction(c: &mut Criterion) {
    c.bench_function("ir_cfg_50_blocks", |b| {
        b.iter(|| {
            let mut func = IrFunction::new("cfg_bench", 0x0);
            let mut prev = func.entry_block;
            for i in 0..50 {
                let bb = func.add_block(&format!("bb_{}", i));
                let cond = Value::var(i, Ty::Bool);
                func.push_inst(prev, IrInst::CBranch {
                    cond,
                    target_true: bb,
                    target_false: func.add_block(&format!("else_{}", i)),
                });
                func.push_inst(bb, IrInst::Return { value: None });
                prev = bb;
            }
            func.build_cfg();
            black_box(func)
        });
    });
}

fn bench_ir_serialization(c: &mut Criterion) {
    let mut prog = IrProgram::new();
    let mut func = IrFunction::new("serial_bench", 0x401000);
    for i in 0..100 {
        let v = func.alloc_var(Ty::i64());
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v,
            op: OpCode::Add,
            lhs: Value::reg("rax", Ty::i64()),
            rhs: Value::Const(i),
        });
    }
    prog.add_function(func);

    c.bench_function("ir_serialize_100_insts", |b| {
        b.iter(|| {
            let json = prog.to_json().unwrap();
            black_box(json)
        });
    });
}

fn bench_x86_lift(c: &mut Criterion) {
    use bibleteks_ir::lifter::Lifter;
    use bibleteks_ir::x86_lifter::X86Lifter;

    let lifter = X86Lifter::new(true);
    // Typical function: push rbp; mov rbp, rsp; sub rsp, 32; ... ; leave; ret
    let code = vec![
        0x55,                                   // push rbp
        0x48, 0x89, 0xE5,                      // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,               // sub rsp, 32
        0x48, 0x89, 0x4D, 0x10,               // mov [rbp+0x10], rcx
        0x90, 0x90, 0x90, 0x90, 0x90,         // 5x nop
        0x90, 0x90, 0x90, 0x90, 0x90,         // 5x nop
        0xC9,                                   // leave
        0xC3,                                   // ret
    ];

    c.bench_function("x86_lift_function", |b| {
        b.iter(|| {
            let func = lifter.lift_function(black_box(&code), 0x401000, "bench").unwrap();
            black_box(func)
        });
    });
}

criterion_group!(
    benches,
    bench_ir_function_creation,
    bench_cfg_construction,
    bench_ir_serialization,
    bench_x86_lift,
);
criterion_main!(benches);
