use freakre_ir::{to_ssa, BlockId, IrFunction, IrInst, SsaError, Value};

fn malformed(seed: u32) -> IrFunction {
    let mut function = IrFunction::new("property", 0x1000);
    let block = BlockId(0);
    let target = BlockId(seed % 4 + 1);
    function.push_inst(block, if seed & 1 == 0 {
        IrInst::Branch { target }
    } else {
        IrInst::CBranch {
            cond: Value::Const(seed as i64),
            target_true: target,
            target_false: BlockId(seed % 3 + 5),
        }
    });
    function
}

#[test]
fn malformed_cfg_is_rejected_without_panicking() {
    for seed in 0..256 {
        let mut function = malformed(seed);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            to_ssa(&mut function)
        }));
        assert!(result.is_ok(), "to_ssa panicked for seed {seed}");
        assert!(matches!(result.unwrap(), Err(SsaError::UnknownBlock(_))));
    }
}

#[test]
fn malformed_cfg_error_is_deterministic() {
    for seed in 0..64 {
        let mut first_function = malformed(seed);
        let mut second_function = malformed(seed);
        let first = to_ssa(&mut first_function).unwrap_err().to_string();
        let second = to_ssa(&mut second_function).unwrap_err().to_string();
        assert_eq!(first, second, "seed {seed}");
    }
}
