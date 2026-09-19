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
    for s in report.suspicious_strings.iter().take(20) {
        println!("  \"{}\"", s);
    }

    println!("\n=== Imports ===");
    for imp in report.imports.iter().take(20) {
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

    while i < insts.len() {
        let inst = &insts[i];
        let indent_str = "  ".repeat(indent);

        match inst.opcode {
            // === STACK OPERATIONS ===
            Opcode::PopTop => {
                i += 1;
                continue;
            }
            Opcode::RotTwo => {
                i += 1;
                continue;
            }
            Opcode::RotThree => {
                i += 1;
                continue;
            }
            Opcode::DupTop => {
                i += 1;
                continue;
            }
            Opcode::DupTopTwo => {
                i += 1;
                continue;
            }

            // === LOOP/ITERATION ===
            Opcode::ForIter => {
                println!("{}for _ in iterable:", indent_str);
                indent += 1;
                i += 1;
                continue;
            }
            Opcode::IterNext => {
                i += 1;
                continue;
            }

            // === CONTROL FLOW ===
            Opcode::JumpForward => {
                println!("{}# jump_forward: {}", indent_str, inst.arg.unwrap_or(0));
                i += 1;
                continue;
            }
            Opcode::JumpIfTrueOrPop => {
                println!("{}if ...:", indent_str);
                indent += 1;
                i += 1;
                continue;
            }
            Opcode::JumpIfFalseOrPop => {
                println!("{}if ...:", indent_str);
                indent += 1;
                i += 1;
                continue;
            }
            Opcode::StopCode | Opcode::PopExcept | Opcode::PopBlock => {
                if indent > 0 { indent -= 1; }
                i += 1;
                continue;
            }

            // === IMPORTS ===
            Opcode::ImportName => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}import {}", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::ImportFrom => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}from {} import *", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::ImportAll => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}from {} import *", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }

            // === NAME OPERATIONS ===
            Opcode::LoadName => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# load: {}", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::StoreName => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}{} = ...", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::DeleteName => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# del: {}", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }

            // === ATTRIBUTE OPERATIONS ===
            Opcode::LoadAttr => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# obj.{}", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::StoreAttr => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# obj.{} = ...", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::DeleteAttr => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# del obj.{}", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }

            // === CONSTANT OPERATIONS ===
            Opcode::LoadConst => {
                let idx = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# const: {}", indent_str, consts.get(idx).unwrap_or(&"?".to_string()));
                i += 1;
                continue;
            }
            Opcode::LoadMap => {
                println!("{}# load_map", indent_str);
                i += 1;
                continue;
            }

            // === CALL OPERATIONS ===
            Opcode::CallFunction => {
                let nargs = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# call({})", indent_str, nargs);
                i += 1;
                continue;
            }
            Opcode::CallFunctionEx => {
                let nargs = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# call_ex({})", indent_str, nargs);
                i += 1;
                continue;
            }

            // === FUNCTION OPERATIONS ===
            Opcode::MakeFunction => {
                let nargs = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# make_function({})", indent_str, nargs);
                i += 1;
                continue;
            }

            // === COMPARISON OPERATIONS ===
            Opcode::CompareOp => {
                let cmp = match inst.arg.unwrap_or(0) {
                    0 => "==", 1 => "!=", 2 => "<", 3 => "<=", 4 => ">", 5 => ">=",
                    6 => "is", 7 => "is not", 8 => "in", 9 => "not in", 10 => "issubclass",
                    11 => "isinstance", _ => "?",
                };
                println!("{}# cmp: {}", indent_str, cmp);
                i += 1;
                continue;
            }

            // === BINARY OPERATIONS ===
            Opcode::BinaryAdd => {
                println!("{}# +", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinarySubtract => {
                println!("{}# -", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinaryMultiply => {
                println!("{}# *", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinaryModulo => {
                println!("{}# %", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinaryAnd => {
                println!("{}# &", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinaryOr => {
                println!("{}# |", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinaryXor => {
                println!("{}# ^", indent_str);
                i += 1;
                continue;
            }
            Opcode::BinaryFloorDivide => {
                println!("{}# //", indent_str);
                i += 1;
                continue;
            }

            // === INPLACE OPERATIONS ===
            Opcode::InplaceAdd => {
                println!("{}# +=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceSubtract => {
                println!("{}# -=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceMultiply => {
                println!("{}# *=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceModulo => {
                println!("{}# %=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplacePower => {
                println!("{}# **=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceAnd => {
                println!("{}# &=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceOr => {
                println!("{}# |=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceXor => {
                println!("{}# ^=", indent_str);
                i += 1;
                continue;
            }
            Opcode::InplaceFloorDivide => {
                println!("{}# //=", indent_str);
                i += 1;
                continue;
            }

            // === STRUCTURE OPERATIONS ===
            Opcode::UnpackSequence => {
                let count = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# unpack {} items", indent_str, count);
                i += 1;
                continue;
            }
            Opcode::UnpackEx => {
                let count = inst.arg.map(|a| a as usize).unwrap_or(0);
                println!("{}# unpack_ex({})", indent_str, count);
                i += 1;
                continue;
            }
            Opcode::StoreSubst => {
                println!("{}# store_subst", indent_str);
                i += 1;
                continue;
            }

            // === FALLBACK ===
            _ => {
                let opcode = format!("{:?}", inst.opcode);
                let arg = inst.arg.map(|a| a.to_string()).unwrap_or("?".to_string());
                println!("{}# {:20} arg={}", indent_str, opcode, arg);
            }
        }

        i += 1;
    }
}
