use decompiler::decompile_function;
use freakre_ir::x86_lifter::X86Lifter;
use freakre_ir::Lifter;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: demo <exe> <offset-hex>");
    let offset = usize::from_str_radix(
        std::env::args()
            .nth(2)
            .expect("offset")
            .trim_start_matches("0x"),
        16,
    )
    .expect("bad offset");
    let count: usize = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    let data = std::fs::read(&path).expect("read");
    let pe = pe_parser::PeFile::parse(&data).expect("pe");
    let text = pe
        .sections
        .iter()
        .find(|s| s.name_string() == ".text")
        .expect(".text");
    let raw = text.raw_data(&data);
    let mut off = offset.saturating_sub(text.raw_data_offset as usize);

    let prologues: [&[u8]; 4] = [
        &[0x48, 0x89, 0x5C, 0x24],
        &[0x48, 0x89, 0x4C, 0x24],
        &[0x40, 0x53],
        &[0x48, 0x83, 0xEC],
    ];
    let orig = off;
    'found: while off < raw.len() {
        for p in prologues {
            if raw[off..].starts_with(p) {
                break 'found;
            }
        }
        off += 1;
        if off > orig + 0x40000 {
            off = orig;
            break 'found;
        }
    }
    eprintln!(
        "[demo] lifted from file offset {:#X} (rva {:#X})",
        text.raw_data_offset as usize + off,
        off
    );
    let code = &raw[off..];

    let lifter = X86Lifter::new(true);
    let func = lifter
        .lift_function(code, 0x140001000u64, "demo")
        .expect("lift");
    let total_insts: usize = func.blocks.iter().map(|b| b.insts.len()).sum();
    eprintln!(
        "[ir] blocks={} insts={} entry={:?}",
        func.blocks.len(),
        total_insts,
        func.entry_block
    );
    for b in func.blocks.iter() {
        use freakre_ir::IrInst;
        let term = match b.terminator() {
            Some(t) => t.clone(),
            None => continue,
        };
        let name_of = |id: freakre_ir::BlockId| -> String {
            format!(
                "{}({},{:?})",
                id.0,
                func.blocks[id.0 as usize].insts.len(),
                func.blocks[id.0 as usize].label
            )
        };
        match term {
            IrInst::Branch { target } => eprintln!("[t] b{} -> {}", b.id.0, name_of(target)),
            IrInst::CBranch {
                target_true,
                target_false,
                ..
            } => {
                eprintln!(
                    "[t] b{} -> T:{} F:{}",
                    b.id.0,
                    name_of(target_true),
                    name_of(target_false)
                )
            }
            other => eprintln!("[t] b{} term={:?}", b.id.0, other),
        }
    }

    for b in func.blocks.iter().take(8) {
        eprintln!(
            "[ir] block {} preds={:?} succ={:?} insts={}",
            b.id.0,
            b.predecessors,
            b.successors,
            b.insts.len()
        );
    }

    match decompile_function(&func) {
        Ok(c) => println!("{}", c),
        Err(e) => println!("error: {}", e),
    }
    let _ = count;
}
