use decompiler::decompile_function;
use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};

#[test]
fn probe_lognot_pipeline() {
    // v1 = (rcx != 1); if (!v1) { return; } return;
    let mut func = IrFunction::new("p", 0x1000);
    let rcx = Value::Register {
        name: "rcx".into(),
        ty: Ty::i32(),
    };
    let v1 = func.alloc_var(Ty::Bool);
    let then_b = func.add_block("then");
    let exit_b = func.add_block("exit");

    func.push_inst(
        func.entry_block,
        IrInst::Binary {
            dst: v1.clone(),
            op: OpCode::Ne,
            lhs: rcx,
            rhs: Value::int(1),
        },
    );
    func.push_inst(
        func.entry_block,
        IrInst::CBranch {
            cond: v1.clone(),
            target_true: exit_b,
            target_false: then_b,
        },
    );
    func.push_inst(then_b, IrInst::Return { value: None });
    func.push_inst(exit_b, IrInst::Return { value: None });
    func.build_cfg();

    let c = decompile_function(&func).unwrap();
    println!("---- output ----\n{}", c);
}
