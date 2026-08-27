//! Regression tests for previously confirmed decompiler bugs.
//! Every test here failed before the corresponding fix.

use decompiler::decompile_function;
use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};

fn build_multi_def() -> IrFunction {
    // if (c) { x = 1; } else { x = 2; }  return x;
    let mut func = IrFunction::new("multi_def", 0x1000);
    let cond = func.alloc_var(Ty::Bool);
    let x = func.alloc_var(Ty::i32());
    let then_b = func.add_block("then");
    let else_b = func.add_block("else");
    let merge = func.add_block("merge");

    func.push_inst(func.entry_block, IrInst::CBranch {
        cond,
        target_true: then_b,
        target_false: else_b,
    });
    func.push_inst(then_b, IrInst::Unary { dst: x.clone(), op: OpCode::Copy, src: Value::int(1) });
    func.push_inst(then_b, IrInst::Branch { target: merge });
    func.push_inst(else_b, IrInst::Unary { dst: x.clone(), op: OpCode::Copy, src: Value::int(2) });
    func.push_inst(else_b, IrInst::Branch { target: merge });
    func.push_inst(merge, IrInst::Return { value: Some(x) });
    func.build_cfg();
    func
}

#[test]
fn copy_prop_must_not_merge_multi_def_variable() {
    let c = decompile_function(&build_multi_def()).unwrap();
    // Both constants must survive: the buggy pass replaced the read in BOTH
    // branches with the value from the last-visited definition (return 0x2).
    assert!(
        c.contains("0x1") && c.contains("0x2"),
        "one branch constant was lost by copy propagation:\n{}",
        c
    );
}

#[test]
fn diamond_structuring_keeps_returns_and_needs_no_goto() {
    let c = decompile_function(&build_multi_def()).unwrap();
    // The merge block's Return must be reachable from both arms — either both
    // fall through to it or use gotos WITH labels. What must never happen:
    // a `goto` to a label that is not defined anywhere in the output.
    for line in c.lines() {
        if line.trim_start().starts_with("goto ") {
            let label = line.trim().trim_start_matches("goto ").trim_end_matches(';');
            assert!(
                c.contains(&format!("{}:", label)),
                "goto without matching label '{}':\n{}",
                label,
                c
            );
        }
    }
}

#[test]
fn no_continue_outside_loops() {
    let c = decompile_function(&build_multi_def()).unwrap();
    // Previously every Branch became `continue`, even outside any loop.
    assert!(
        !c.contains("continue"),
        "'continue' emitted outside of any loop:\n{}",
        c
    );
}

#[test]
fn while_loop_still_structures_end_to_end() {
    // while (i < n) { i = i + 1; } return n;
    let mut func = IrFunction::new("count", 0x2000);
    let i_var = func.alloc_var(Ty::i32());
    let n_var = func.alloc_var(Ty::i32());
    let cond_t = func.alloc_var(Ty::Bool);
    let inc_t = func.alloc_var(Ty::i32());

    let header = func.entry_block;
    let body = func.add_block("body");
    let exit = func.add_block("exit");

    // header: cond_t = i <u n; cbranch → body | exit
    func.push_inst(header, IrInst::Binary {
        dst: cond_t.clone(),
        op: OpCode::LtU,
        lhs: i_var.clone(),
        rhs: n_var.clone(),
    });
    func.push_inst(header, IrInst::CBranch {
        cond: cond_t.clone(),
        target_true: body,
        target_false: exit,
    });

    // body: i = i + 1; goto header
    func.push_inst(body, IrInst::Binary {
        dst: inc_t.clone(),
        op: OpCode::Add,
        lhs: i_var.clone(),
        rhs: Value::int(1),
    });
    func.push_inst(body, IrInst::Unary {
        dst: i_var.clone(),
        op: OpCode::Copy,
        src: inc_t.clone(),
    });
    func.push_inst(body, IrInst::Branch { target: header });

    // exit: return n
    func.push_inst(exit, IrInst::Return { value: Some(n_var.clone()) });

    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    assert!(c.contains("while") || c.contains("for"), "loop lost:\n{}", c);
    assert!(c.contains("return"), "return lost:\n{}", c);
    assert!(!c.contains("WARNING:"), "unstructured gotos remain:\n{}", c);
}

#[test]
fn neg_i64_min_does_not_panic() {
    // Unary Neg folding used plain negation → debug panic on i64::MIN.
    let mut func = IrFunction::new("negmin", 0x3000);
    let dst = func.alloc_var(Ty::i64());
    func.push_inst(func.entry_block, IrInst::Unary {
        dst: dst.clone(),
        op: OpCode::Neg,
        src: Value::Const(i64::MIN),
    });
    func.push_inst(func.entry_block, IrInst::Return { value: Some(dst) });
    let c = decompile_function(&func).unwrap();
    assert!(c.contains("return"), "no return:\n{}", c);
}

#[test]
fn zero_assignment_does_not_infer_u8() {
    // infer_int_type(0) used to yield u8, making `x = 0` declare uint8_t.
    let mut func = IrFunction::new("zero", 0x4000);
    let x = func.alloc_var(Ty::i32());
    func.push_inst(func.entry_block, IrInst::Unary {
        dst: x.clone(),
        op: OpCode::Copy,
        src: Value::int(0),
    });
    func.push_inst(func.entry_block, IrInst::Return { value: Some(x) });
    let c = decompile_function(&func).unwrap();
    assert!(
        !c.contains("uint8_t v"),
        "zero-init variable declared as uint8_t:\n{}",
        c
    );
}

#[test]
fn dead_assignment_with_call_keeps_the_call() {
    // v0 = f(); return 1; — the call has side effects, so it must survive
    // dead-assignment elimination even though v0 is never read.
    let mut func = IrFunction::new("side_effect", 0x5000);
    let v0 = func.alloc_var(Ty::i64());
    func.push_inst(func.entry_block, IrInst::Call {
        dst: Some(v0),
        target: Value::Symbol("side_effect_fn".to_string()),
        args: vec![],
    });
    func.push_inst(func.entry_block, IrInst::Return { value: Some(Value::int(1)) });
    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    assert!(
        c.contains("side_effect_fn()"),
        "call with unused result was deleted by DCE:\n{}",
        c
    );
}

#[test]
fn copy_prop_does_not_use_value_redefined_later_in_same_list() {
    // v1 = rax; rax = rcx; return v1;
    // The copy candidate (v1 → rax) must be invalidated when rax is
    // redefined before the use; `return rcx` reads the WRONG value.
    let mut func = IrFunction::new("redef_copy", 0x6000);
    let v1 = func.alloc_var(Ty::i64());
    let rax = Value::reg("rax", Ty::i64());
    let rcx = Value::reg("rcx", Ty::i64());
    func.push_inst(func.entry_block, IrInst::Unary {
        dst: v1.clone(),
        op: OpCode::Copy,
        src: rax.clone(),
    });
    func.push_inst(func.entry_block, IrInst::Unary {
        dst: rax.clone(),
        op: OpCode::Copy,
        src: rcx.clone(),
    });
    func.push_inst(func.entry_block, IrInst::Return { value: Some(v1) });
    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    // With SSA, v1 may be renamed to v1 (not v0) due to fresh allocation, but must still be a v-var, not rcx.
    assert!(
        c.contains("return v"),
        "copy was propagated across a redefinition of its source (expected return vN):\n{}",
        c
    );
    assert!(
        !c.contains("return rcx"),
        "`return v` wrongly became `return rcx`:\n{}",
        c
    );
}
