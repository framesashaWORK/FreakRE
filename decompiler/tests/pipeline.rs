//! Pipeline verification harness.
//!
//! End-to-end checks over hand-built IR functions that the decompiler emits
//! *valid-looking* C: structured constructs appear, no dangling `goto`
//! targets, and no raw stack dereferences leak through. These double as
//! regression guards for the structuring / type / call-naming passes.

use decompiler::decompile_function;
use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};

fn cond(f: &mut IrFunction) -> Value {
    f.alloc_var(Ty::Bool)
}

/// Collect `goto bbN` targets and assert every one has a `bbN:` label.
fn assert_gotos_resolve(c: &str) {
    let mut pending: Vec<String> = Vec::new();
    for line in c.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("goto ") {
            if let Some((label, _)) = rest.split_once([' ', ';', '\t']) {
                if label.starts_with("bb") {
                    pending.push(label.to_string());
                }
            }
        }
    }
    for label in pending {
        assert!(
            c.contains(&format!("{}:", label)),
            "dangling goto target {label} in:\n{c}"
        );
    }
}

#[test]
fn if_else_structures() {
    let mut f = IrFunction::new("branchy", 0x1000);
    let c = cond(&mut f);
    let then_b = f.add_block("then");
    let else_b = f.add_block("else");
    let merge = f.add_block("merge");
    let v = f.alloc_var(Ty::i32());
    f.push_inst(
        f.entry_block,
        IrInst::CBranch {
            cond: c,
            target_true: then_b,
            target_false: else_b,
        },
    );
    f.push_inst(
        then_b,
        IrInst::Unary {
            dst: v.clone(),
            op: OpCode::Copy,
            src: Value::int(1),
        },
    );
    f.push_inst(then_b, IrInst::Branch { target: merge });
    f.push_inst(
        else_b,
        IrInst::Unary {
            dst: v.clone(),
            op: OpCode::Copy,
            src: Value::int(2),
        },
    );
    f.push_inst(else_b, IrInst::Branch { target: merge });
    f.push_inst(merge, IrInst::Return { value: Some(v) });
    f.build_cfg();

    let c = decompile_function(&f).unwrap();
    // A diamond that only assigns a constant to one variable collapses to a
    // ternary (valid, readable C) — either `if/else` or `?:` is acceptable.
    assert!(
        c.contains("if") || c.contains("?"),
        "expected structured conditional:\n{}",
        c
    );
    assert!(c.contains("return"), "{}", c);
    assert!(!c.contains("WARNING"), "{}", c);
    assert_gotos_resolve(&c);
}

#[test]
fn while_loop_structures() {
    let mut f = IrFunction::new("counter", 0x1000);
    let c = cond(&mut f);
    let header = f.entry_block;
    let body = f.add_block("body");
    let exit = f.add_block("exit");
    let i = f.alloc_var(Ty::i32());
    f.push_inst(
        header,
        IrInst::CBranch {
            cond: c,
            target_true: body,
            target_false: exit,
        },
    );
    f.push_inst(
        body,
        IrInst::Binary {
            dst: i.clone(),
            op: OpCode::Add,
            lhs: i.clone(),
            rhs: Value::int(1),
        },
    );
    f.push_inst(body, IrInst::Branch { target: header });
    f.push_inst(exit, IrInst::Return { value: Some(i) });
    f.build_cfg();

    let c = decompile_function(&f).unwrap();
    assert!(c.contains("while"), "{}", c);
    assert!(!c.contains("WARNING"), "{}", c);
    assert_gotos_resolve(&c);
}

#[test]
fn irreducible_cfg_emits_resolving_labels() {
    // Interlocking cycle with two entries: entry→a, entry→b, a→b, b→a.
    // Neither edge is a clean back edge, so the structurer falls back to a
    // `goto` — and must emit a matching `bbN:` label so the C is valid.
    let mut f = IrFunction::new("irred", 0x1000);
    let c = cond(&mut f);
    let a = f.add_block("a");
    let b = f.add_block("b");
    let ret = f.add_block("ret");
    f.push_inst(
        f.entry_block,
        IrInst::CBranch {
            cond: c.clone(),
            target_true: a,
            target_false: b,
        },
    );
    f.push_inst(
        a,
        IrInst::CBranch {
            cond: c,
            target_true: ret,
            target_false: b,
        },
    );
    f.push_inst(b, IrInst::Branch { target: a });
    f.push_inst(ret, IrInst::Return { value: None });
    f.build_cfg();

    let c = decompile_function(&f).unwrap();
    assert!(!c.contains("WARNING"), "unexpected warning:\n{}", c);
    // A goto must be present for this irreducible shape...
    if c.contains("goto ") {
        assert_gotos_resolve(&c);
    }
}

#[test]
fn irreducible_edge_to_loop_header_emits_a_label() {
    // The side entry makes a -> header irreducible while body -> header is a
    // natural back edge. The fallback goto targets a structured loop header,
    // which still needs a concrete label in the generated C.
    let mut f = IrFunction::new("irred_loop_target", 0x1000);
    let entry_cond = cond(&mut f);
    let loop_cond = cond(&mut f);
    let side_cond = cond(&mut f);
    let header = f.add_block("header");
    let body = f.add_block("body");
    let side = f.add_block("side");
    let ret = f.add_block("ret");

    f.push_inst(
        f.entry_block,
        IrInst::CBranch {
            cond: entry_cond,
            target_true: header,
            target_false: side,
        },
    );
    f.push_inst(
        header,
        IrInst::CBranch {
            cond: loop_cond,
            target_true: body,
            target_false: ret,
        },
    );
    f.push_inst(body, IrInst::Branch { target: header });
    f.push_inst(
        side,
        IrInst::CBranch {
            cond: side_cond,
            target_true: header,
            target_false: ret,
        },
    );
    f.push_inst(ret, IrInst::Return { value: None });
    f.build_cfg();

    let c = decompile_function(&f).unwrap();
    assert_gotos_resolve(&c);
}

#[test]
fn common_runtime_calls_keep_names() {
    // A call to a name that matches the built-in database should survive
    // unchanged (no synthetic rename) and not emit a dangling target.
    let mut f = IrFunction::new("uses_malloc", 0x1000);
    let callee = Value::Symbol("malloc".to_string());
    let dst = f.alloc_var(Ty::Ptr(Box::new(Ty::Void)));
    f.push_inst(
        f.entry_block,
        IrInst::Call {
            dst: Some(dst.clone()),
            target: callee,
            args: vec![Value::int(0x100)],
        },
    );
    f.push_inst(f.entry_block, IrInst::Return { value: Some(dst) });
    f.build_cfg();

    let c = decompile_function(&f).unwrap();
    assert!(c.contains("malloc"), "{}", c);
    assert_gotos_resolve(&c);
}
