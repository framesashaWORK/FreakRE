//! Bytecode decompiler: disassemble Python bytecode to pseudocode.
//!
//! This is a minimal decompiler that focuses on:
//! - Control flow reconstruction (if/for/while)
//! - Function structure recovery
//! - High-level operations (assignments, comparisons, calls)

use pyc_parser::{CodeObject, Instruction, Opcode};

/// Line of pseudocode output.
pub struct Line {
    pub offset: usize,
    pub code: String,
}

/// Decompile a code object to pseudocode.
pub fn decompile(obj: &CodeObject) -> Vec<Line> {
    let mut out = Vec::new();

    // Function header
    let func_name = obj
        .source_path
        .as_ref()
        .and_then(|p| p.rsplit('\\').next())
        .unwrap_or("<unknown>");

    out.push(Line {
        offset: 0,
        code: format!("def {}() {{", func_name),
    });

    let mut indent = 0;
    let mut i = 0;
    let instructions = &obj.instructions;

    while i < instructions.len() {
        let inst = &instructions[i];
        let indent_str = "    ".repeat(indent);

        // Check for function patterns
        if inst.opcode == Opcode::LoadConst && inst.arg.is_some() {
            // Look for: LOAD_CONST + LOAD_NAME + CALL_FUNCTION
            if i + 2 < instructions.len() {
                let next1 = &instructions[i + 1];
                let next2 = &instructions[i + 2];

                if next1.opcode == Opcode::LoadName && next2.opcode == Opcode::CallFunction {
                    // Print pattern!
                    let const_val = obj
                        .constants
                        .get(inst.arg.map(|a| a as usize).unwrap_or(0))
                        .cloned()
                        .unwrap_or_else(|| "?".to_string());
                    out.push(Line {
                        offset: inst.offset,
                        code: format!("{}print(\"{}\")", indent_str, const_val),
                    });
                    i += 3;
                    continue;
                }
            }
        }

        // For loop pattern
        if inst.opcode == Opcode::ForIter {
            indent += 1;
            out.push(Line {
                offset: inst.offset,
                code: format!("{}for ...", indent_str),
            });
            i += 1;
            continue;
        }

        // StoreName -> assignment
        if inst.opcode == Opcode::StoreName && inst.arg.is_some() {
            let name = obj
                .names
                .get(inst.arg.map(|a| a as usize).unwrap_or(0))
                .cloned()
                .unwrap_or_else(|| "_".to_string());
            out.push(Line {
                offset: inst.offset,
                code: format!("{}{} = ...", indent_str, name),
            });
            i += 1;
            continue;
        }

        // Call function
        if inst.opcode == Opcode::CallFunction && inst.arg.is_some() {
            let arg_count = (inst.arg.unwrap() / 2) as usize;
            out.push(Line {
                offset: inst.offset,
                code: format!("{}call (...)  # {} args", indent_str, arg_count),
            });
            i += 1;
            continue;
        }

        // Jump instructions
        if inst.opcode == Opcode::JumpForward && inst.arg.is_some() {
            out.push(Line {
                offset: inst.offset,
                code: format!("{}jump +{}", indent_str, inst.arg.unwrap()),
            });
            i += 1;
            continue;
        }

        // PopJump instructions (conditionals)
        if matches!(inst.opcode, Opcode::JumpIfTrueOrPop | Opcode::JumpIfFalseOrPop) {
            out.push(Line {
                offset: inst.offset,
                code: format!("{}if ...", indent_str),
            });
            i += 1;
            continue;
        }

        // Default: show opcode
        out.push(Line {
            offset: inst.offset,
            code: format!("{}{:?} # arg={:}", indent_str, inst.opcode, 
                inst.arg.map(|a| a.to_string()).unwrap_or("?".to_string())),
        });
        i += 1;
    }

    // Close function
    out.push(Line {
        offset: usize::MAX,
        code: "}".to_string(),
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_empty() {
        let obj = CodeObject {
            arg_count: 0,
            constants: vec![],
            names: vec![],
            instructions: vec![],
            source_path: Some("test.py".to_string()),
            co_code: vec![],
        };

        let lines = decompile(&obj);
        assert_eq!(lines.len(), 2); // def + closing brace
    }
}
