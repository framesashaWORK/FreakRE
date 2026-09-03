use decompiler::ast::{Expr, Stmt};
use decompiler::decompile_function;
use freakre_ir::x86_lifter::X86Lifter;
use freakre_ir::Lifter;

fn count_stmts(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .map(|s| {
            let inner = match s {
                Stmt::If { then_body, else_body, .. } => {
                    count_stmts(then_body) + else_body.as_ref().map(|b| count_stmts(b)).unwrap_or(0)
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                    count_stmts(body)
                }
                Stmt::Switch { cases, default, .. } => {
                    cases.iter().map(|c| count_stmts(&c.body)).sum::<usize>()
                        + default.as_ref().map(|b| count_stmts(b)).unwrap_or(0)
                }
                Stmt::Block(b) => count_stmts(b),
                Stmt::TryCatch { try_body, catch_body, .. } => {
                    count_stmts(try_body) + count_stmts(catch_body)
                }
                _ => 0,
            };
            1 + inner
        })
        .sum()
}

#[allow(dead_code)] // probe helper, kept for manual debugging sessions
fn has_call(stmts: &[Stmt]) -> bool {
    let mut found = false;
    for s in stmts {
        let exprs: Vec<&Expr> = match s {
            Stmt::Assign { value, .. } => vec![value],
            Stmt::Return { value } => value.iter().collect(),
            Stmt::Call { args, .. } | Stmt::Expr(Expr::Call { args, .. }) => args.iter().collect(),
            Stmt::Expr(e) => vec![e],
            _ => vec![],
        };
        for e in exprs {
            match e {
                Expr::Call { .. } => found = true,
                Expr::Binary { lhs, rhs, .. } | Expr::Index { base: lhs, index: rhs } => {
                    found |= has_call(std::slice::from_ref(&Stmt::Expr((**lhs).clone())))
                        || has_call(std::slice::from_ref(&Stmt::Expr((**rhs).clone())));
                }
                _ => {}
            }
        }
    }
    found
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: phase_probe <exe> <offset-hex>");
    let offset = usize::from_str_radix(
        std::env::args().nth(2).expect("offset").trim_start_matches("0x"),
        16,
    )
    .expect("bad offset");

    let data = std::fs::read(&path).expect("read");
    let pe = pe_parser::PeFile::parse(&data).expect("pe");
    let text = pe.sections.iter().find(|s| s.name_string() == ".text").expect(".text");
    let raw = text.raw_data(&data);
    let mut off = offset.saturating_sub(text.raw_data_offset as usize);
    let prologues: [&[u8]; 4] = [
        &[0x48, 0x89, 0x5C, 0x24],
        &[0x48, 0x89, 0x4C, 0x24],
        &[0x40, 0x53],
        &[0x48, 0x83, 0xEC],
    ];
    'found: while off < raw.len() {
        for p in prologues {
            if raw[off..].starts_with(p) {
                break 'found;
            }
        }
        off += 1;
    }

    let code = &raw[off..];
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(code, 0x140000C000u64, "probe").expect("lift");
    let total: usize = func.blocks.iter().map(|b| b.insts.len()).sum();
    let init_calls: usize = func
        .blocks
        .iter()
        .map(|b| b.insts.iter().filter(|i| matches!(i, freakre_ir::IrInst::Call { .. })).count())
        .sum();
    eprintln!("[probe] blocks={} insts={} initial_calls={}", func.blocks.len(), total, init_calls);

    // Phase 0 variants
    let mut ir = func.clone();
    let count_calls = |ir: &freakre_ir::IrFunction| -> usize {
        ir.blocks
            .iter()
            .map(|b| b.insts.iter().filter(|i| matches!(i, freakre_ir::IrInst::Call { .. })).count())
            .sum()
    };
    eprintln!("[calls] initial={}", count_calls(&ir));
    decompiler::fold_flags::fold_flag_comparisons(&mut ir);
    eprintln!("[calls] after fold_flag_comparisons={}", count_calls(&ir));
    decompiler::fold_flags::propagate_block_temps(&mut ir);
    eprintln!("[calls] after propagate_block_temps={}", count_calls(&ir));
    decompiler::fold_flags::fuse_load_copies(&mut ir);
    let after_fuse: usize = ir.blocks.iter().map(|b| b.insts.len()).sum();
    eprintln!("[phase] after fold/fuse insts={after_fuse} calls={}", count_calls(&ir));
    decompiler::stack_vars::recover_stack_vars(&mut ir);
    let after_sv: usize = ir.blocks.iter().map(|b| b.insts.len()).sum();
    eprintln!("[phase] after stack_vars insts={after_sv} calls={}", count_calls(&ir));
    decompiler::fold_flags::eliminate_dead_flag_defs(&mut ir);
    let after_flags: usize = ir.blocks.iter().map(|b| b.insts.len()).sum();
    eprintln!("[phase] after dead_flag insts={after_flags} calls={}", count_calls(&ir));

    // Phase 1
    let ast = decompiler::ir_to_ast::ir_to_ast(&ir);
    eprintln!("[phase] after ir_to_ast stmts={}", count_stmts(&ast.body));

    // Phase 2-5 step by step
    let mut ast2 = ast.clone();
    decompiler::types::reconstruct_types(&mut ast2);
    eprintln!("[phase] after types stmts={}", count_stmts(&ast2.body));

    let mut ast3 = ast2.clone();
    decompiler::simplify::simplify_function(&mut ast3);
    eprintln!("[phase] after simplify#1 stmts={}", count_stmts(&ast3.body));

    let mut ast4 = ast3.clone();
    decompiler::patterns::recognize_patterns(&mut ast4);
    eprintln!("[phase] after patterns stmts={}", count_stmts(&ast4.body));

    let mut ast5 = ast4.clone();
    decompiler::simplify::simplify_function(&mut ast5);
    eprintln!("[phase] after simplify#2 stmts={}", count_stmts(&ast5.body));

    println!("{}", decompile_function(&func).unwrap());
}
