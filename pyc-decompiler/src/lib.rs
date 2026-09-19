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
    out.push(Line {
        offset: 0,
        code: format!(
            "def {}{} ({} args) {{",
            obj.source_path
                .as_ref()
                .and_then(|p| p.rsplit('/').next())
                .unwrap_or("<unknown>"),
            if obj.arg_count > 0 {
                format!("({})", obj.arg_count)
            } else {
                String::new()
            },
            obj.arg_count
        ),
    });

    let mut indent = 1;
    let mut jump_targets: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();

    // Build jump target map first
    for inst in &obj.instructions {
        if let Some(arg) = inst.arg {
            let target = inst.offset + (arg as usize);
            jump_targets.insert(target, indent);
        }
    }

    // Emit instructions as pseudocode
    for inst in &obj.instructions {
        let indent_str = "    ".repeat(indent);

        // Handle jump targets
        if let Some(&target_indent) = jump_targets.get(&inst.offset) {
            if target_indent < indent {
                let indent_str = "    ".repeat(target_indent);
                out.push(Line {
                    offset: inst.offset,
                    code: "}}".to_string(),
                });
                indent = target_indent;
            } else if target_indent > indent {
                indent = target_indent;
                let indent_str = "    ".repeat(indent - 1);
                out.push(Line {
                    offset: inst.offset,
                    code: format!("{}{{", indent_str),
                });
                continue;
            }
        }

        let code = match inst.opcode {
            Opcode::LoadName => {
                if let Some(arg) = inst.arg {
                    format!(
                        "{}_ = {} # {} ({})",
                        indent_str,
                        obj.names.get(arg as usize).map(|s| s.as_str()).unwrap_or("?"),
                        arg,
                        obj.names.get(arg as usize).map(|s| s.as_str()).unwrap_or("?")
                    )
                } else {
                    format!("{}_ = ?", indent_str)
                }
            }
            Opcode::StoreName => {
                if let Some(arg) = inst.arg {
                    format!(
                        "{}store {} # {}",
                        indent_str,
                        obj.names.get(arg as usize).map(|s| s.as_str()).unwrap_or("?"),
                        arg
                    )
                } else {
                    format!("{}store ?", indent_str)
                }
            }
            Opcode::CallFunction => {
                if let Some(arg) = inst.arg {
                    let args = (arg / 2) as usize; // Python 3.x: arg is num args * 2
                    format!("{}call {} args", indent_str, args)
                } else {
                    format!("{}call ?", indent_str)
                }
            }
            Opcode::JumpForward => {
                if let Some(arg) = inst.arg {
                    format!(
                        "{}jump +{}",
                        indent_str,
                        arg
                    )
                } else {
                    format!("{}jump ?", indent_str)
                }
            }
            Opcode::CompareOp => {
                format!("{}compare", indent_str)
            }
            Opcode::BinaryAdd => {
                format!("{}add", indent_str)
            }
            Opcode::BinarySubtract => {
                format!("{}subtract", indent_str)
            }
            Opcode::BinaryMultiply => {
                format!("{}multiply", indent_str)
            }
            Opcode::ForIter => {
                indent += 1;
                format!("{}for", indent_str)
            }
            Opcode::LoadConst => {
                let const_idx = inst
                    .arg
                    .map(|a| a as usize)
                    .unwrap_or(0);
                if let Some(const_val) = obj.constants.get(const_idx) {
                    format!("{}load const \"{}\"", indent_str, const_val)
                } else {
                    format!("{}load const #{}", indent_str, const_idx)
                }
            }
            Opcode::UnpackSequence => {
                format!("{}unpack", indent_str)
            }
            _ => {
                format!("{}{:?}", indent_str, inst.opcode)
            }
        };

        out.push(Line {
            offset: inst.offset,
            code,
        });
    }

    // Close function
    out.push(Line {
        offset: usize::MAX,
        code: "}}".to_string(),
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
        };

        let lines = decompile(&obj);
        assert_eq!(lines.len(), 2); // def + closing brace
    }
}