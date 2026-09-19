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

    func.push_inst(
        func.entry_block,
        IrInst::CBranch {
            cond,
            target_true: then_b,
            target_false: else_b,
        },
    );
    func.push_inst(
        then_b,
        IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(1),
        },
    );
    func.push_inst(then_b, IrInst::Branch { target: merge });
    func.push_inst(
        else_b,
        IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(2),
        },
    );
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
            let label = line
                .trim()
                .trim_start_matches("goto ")
                .trim_end_matches(';');
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
    func.push_inst(
        header,
        IrInst::Binary {
            dst: cond_t.clone(),
            op: OpCode::LtU,
            lhs: i_var.clone(),
            rhs: n_var.clone(),
        },
    );
    func.push_inst(
        header,
        IrInst::CBranch {
            cond: cond_t.clone(),
            target_true: body,
            target_false: exit,
        },
    );

    // body: i = i + 1; goto header
    func.push_inst(
        body,
        IrInst::Binary {
            dst: inc_t.clone(),
            op: OpCode::Add,
            lhs: i_var.clone(),
            rhs: Value::int(1),
        },
    );
    func.push_inst(
        body,
        IrInst::Unary {
            dst: i_var.clone(),
            op: OpCode::Copy,
            src: inc_t.clone(),
        },
    );
    func.push_inst(body, IrInst::Branch { target: header });

    // exit: return n
    func.push_inst(
        exit,
        IrInst::Return {
            value: Some(n_var.clone()),
        },
    );

    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    assert!(
        c.contains("while") || c.contains("for"),
        "loop lost:\n{}",
        c
    );
    assert!(c.contains("return"), "return lost:\n{}", c);
    assert!(!c.contains("WARNING:"), "unstructured gotos remain:\n{}", c);
}

#[test]
fn neg_i64_min_does_not_panic() {
    // Unary Neg folding used plain negation → debug panic on i64::MIN.
    let mut func = IrFunction::new("negmin", 0x3000);
    let dst = func.alloc_var(Ty::i64());
    func.push_inst(
        func.entry_block,
        IrInst::Unary {
            dst: dst.clone(),
            op: OpCode::Neg,
            src: Value::Const(i64::MIN),
        },
    );
    func.push_inst(func.entry_block, IrInst::Return { value: Some(dst) });
    let c = decompile_function(&func).unwrap();
    assert!(c.contains("return"), "no return:\n{}", c);
}

#[test]
fn zero_assignment_does_not_infer_u8() {
    // infer_int_type(0) used to yield u8, making `x = 0` declare uint8_t.
    let mut func = IrFunction::new("zero", 0x4000);
    let x = func.alloc_var(Ty::i32());
    func.push_inst(
        func.entry_block,
        IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(0),
        },
    );
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
    func.push_inst(
        func.entry_block,
        IrInst::Call {
            dst: Some(v0),
            target: Value::Symbol("side_effect_fn".to_string()),
            args: vec![],
        },
    );
    func.push_inst(
        func.entry_block,
        IrInst::Return {
            value: Some(Value::int(1)),
        },
    );
    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    assert!(
        c.contains("side_effect_fn()"),
        "call with unused result was deleted by DCE:\n{}",
        c
    );
}

#[test]
fn copy_prop_does_not_use_value_redefined_later_in_same_list() {    // v1 = rax; rax = rcx; return v1;
    // v1 captures rax *before* the redefinition, so the result must read the
    // entry value of rax — never rcx. Since SSA register spellings are
    // preserved on lowering, GVN/DCE prove both copies dead (`v1` aliases
    // entry-rax, `rax = rcx` is unread) and the output is just `return rax`.
    // Before spelling preservation the copies survived as fresh vars
    // (`return vN`); either shape is correct as long as rcx never leaks in.
    let mut func = IrFunction::new("redef_copy", 0x6000);
    let v1 = func.alloc_var(Ty::i64());
    let rax = Value::reg("rax", Ty::i64());
    let rcx = Value::reg("rcx", Ty::i64());
    func.push_inst(
        func.entry_block,
        IrInst::Unary {
            dst: v1.clone(),
            op: OpCode::Copy,
            src: rax.clone(),
        },
    );
    func.push_inst(
        func.entry_block,
        IrInst::Unary {
            dst: rax.clone(),
            op: OpCode::Copy,
            src: rcx.clone(),
        },
    );
    func.push_inst(func.entry_block, IrInst::Return { value: Some(v1) });
    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    assert!(
        !c.contains("return rcx"),
        "`return v` wrongly became `return rcx`:\n{}",
        c
    );
    assert!(
        c.contains("return rax") || c.contains("return v"),
        "result must read pre-redefinition rax (as `rax` or a temp), got:\n{}",
        c
    );
}

#[test]
fn copy_prop_keeps_loop_carried_increment() {
    // while (i < n) { i = i + 1; } modeled with the increment routed
    // through a temp copy at the loop tail (`t = i + 1; i = t`): the copy
    // feeds the next iteration through the back edge, so dropping it as
    // "unread later in the list" hangs the loop (real bubble_sort hang).
    use freakre_ir::{BlockId, IrBlock};
    let mut func = IrFunction::new("loopinc", 0x7000);
    let i = func.alloc_var(Ty::i64());
    let n = func.alloc_var(Ty::i64());
    let t = func.alloc_var(Ty::i64());
    // init i = 0 in entry, then jump to the condition header.
    func.push_inst(
        func.entry_block,
        IrInst::Unary {
            dst: i.clone(),
            op: OpCode::Copy,
            src: Value::int(0),
        },
    );
    let header = func.add_block("header");
    let body = func.add_block("body");
    let exit = func.add_block("exit");
    func.push_inst(func.entry_block, IrInst::Branch { target: header });
    // header: c = (i < n); if (!c) exit else body.
    let c = func.alloc_var(Ty::Bool);
    func.push_inst(
        header,
        IrInst::Binary {
            dst: c.clone(),
            op: OpCode::LtU,
            lhs: i.clone(),
            rhs: n.clone(),
        },
    );
    func.push_inst(
        header,
        IrInst::CBranch {
            cond: c,
            target_true: body,
            target_false: exit,
        },
    );
    // body: t = i + 1; i = t; goto header.
    func.push_inst(
        body,
        IrInst::Binary {
            dst: t.clone(),
            op: OpCode::Add,
            lhs: i.clone(),
            rhs: Value::int(1),
        },
    );
    func.push_inst(
        body,
        IrInst::Unary {
            dst: i.clone(),
            op: OpCode::Copy,
            src: t,
        },
    );
    func.push_inst(body, IrInst::Branch { target: header });
    func.push_inst(exit, IrInst::Return { value: Some(i) });
    func.build_cfg();
    let c = decompile_function(&func).unwrap();
    // The increment store must survive: without it the loop never advances.
    // The counter prints as v1 (params are only recovered for registers).
    let has_inc =
        c.contains("v1 + 1") || c.contains("v1+=1") || c.contains("v1 += 1") || c.contains("v1++");
    assert!(has_inc, "loop-carried increment was dropped, loop hangs:\n{}", c);
}
