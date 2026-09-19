use pyc_parser::{Instruction, Opcode};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file.pyc>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    let report = match pyc_parser::analyze_python(&data) {
        Some(r) => r,
        None => {
            eprintln!("Not a Python bytecode file (.pyc)");
            std::process::exit(1);
        }
    };

    println!("=== Python Bytecode Analysis ===");
    println!("Kind: {:?}", report.kind);
    if let Some(version) = report.python_version {
        println!("Python Version: {}", version);
    }
    if let Some(path) = report.source_path {
        println!("Source path: {}", path);
    }

    println!("\n=== Strings Found ===");
    for s in report.suspicious_strings.iter().take(15) {
        println!("  {}", s);
    }

    println!("\n=== Imports ===");
    for imp in report.imports.iter().take(15) {
        println!("  {}", imp);
    }

    println!("\n=== High-Risk Imports ===");
    for imp in report.high_risk_imports.iter() {
        eprintln!("  [!] {}", imp);
    }

    println!("\n=== Pseudocode ===");
    for (i, (insts, consts)) in report.code_objects.iter().enumerate() {
        println!("\nFunction {}:", i + 1);
        generate_pseudocode(insts, consts);
    }
}

fn generate_pseudocode(insts: &[Instruction], consts: &[String]) {
    let mut i = 0;
    let mut indent = 0;
    let mut line_count = 0;

    while i < insts.len() && line_count < 100 {
        line_count += 1;
        let inst = &insts[i];
        let indent_str = "  ".repeat(indent);

        // Skip common stack manipulation ops
        if matches!(inst.opcode, Opcode::PopTop | Opcode::RotTwo | Opcode::RotThree) {
            i += 1;
            continue;
        }

        match inst.opcode {
            Opcode::ForIter => {
                println!("{}for ... in iterable:", indent_str);
                indent += 1;
                i += 1;
                continue;
            }
            Opcode::PopTop => {
                i += 1;
                continue;
            }
            Opcode::LoadName => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                let name = consts.get(idx).cloned().unwrap_or("?".to_string());
                println!("{}# load {}", indent_str, name);
            }
            Opcode::StoreName => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                let name = consts.get(idx).cloned().unwrap_or("?".to_string());
                println!("{}{} = ...", indent_str, name);
            }
            Opcode::CallFunction => {
                let nargs = inst.arg.map(|a| a / 2).unwrap_or(0);
                println!("{}# call({})", indent_str, nargs);
            }
            Opcode::CompareOp => {
                let cmp = match inst.arg.unwrap_or(0) {
                    0 => "==", 1 => "!=", 2 => "<", 3 => "<=", 4 => ">", 5 => ">=",
                    6 => "is", 7 => "is not", 8 => "in", 9 => "not in", _ => "?",
                };
                println!("{}# cmp {}", indent_str, cmp);
            }
            Opcode::JumpIfTrueOrPop | Opcode::JumpIfFalseOrPop => {
                println!("{}if ...:", indent_str);
                indent += 1;
            }
            Opcode::StoreAttr => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                let name = consts.get(idx).cloned().unwrap_or("?".to_string());
                println!("{}# obj.{} = ...", indent_str, name);
            }
            Opcode::LoadConst => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                let val = consts.get(idx).cloned().unwrap_or("?".to_string());
                println!("{}# const: {}", indent_str, val);
            }
            Opcode::BinaryAdd => println!("{}# +", indent_str),
            Opcode::BinarySubtract => println!("{}# -", indent_str),
            Opcode::BinaryMultiply => println!("{}# *", indent_str),
            Opcode::BinaryModulo => println!("{}# %", indent_str),
            Opcode::BinaryAnd => println!("{}# &", indent_str),
            Opcode::BinaryOr => println!("{}# |", indent_str),
            _ => {
                let opcode = format!("{:?}", inst.opcode);
                let arg = inst.arg.map(|a| a.to_string()).unwrap_or("?".to_string());
                println!("{}# {:15} arg={}", indent_str, opcode, arg);
            }
        }

        i += 1;
    }
}
