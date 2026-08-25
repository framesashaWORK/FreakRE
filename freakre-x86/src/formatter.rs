//! Intel-syntax instruction formatter.

use crate::types::*;

/// Format an instruction in Intel syntax.
pub fn format_instruction(insn: &Instruction) -> String {
    let mut out = String::with_capacity(64);

    // Prefixes
    if insn.prefixes.lock { out.push_str("lock "); }
    if insn.prefixes.rep { out.push_str("rep "); }
    if insn.prefixes.repne { out.push_str("repne "); }

    // Mnemonic
    out.push_str(insn.mnemonic.as_str());

    // Operands
    for (i, op) in insn.operands.iter().enumerate() {
        if i == 0 { out.push(' '); } else { out.push_str(", "); }
        format_operand(&mut out, op);
    }

    out
}

fn format_operand(out: &mut String, op: &Operand) {
    match op {
        Operand::Reg(reg) => out.push_str(reg.name()),
        Operand::Imm(val) => {
            if *val < 0 {
                out.push_str(&format!("-0x{:x}", val.wrapping_neg() as u64));
            } else {
                out.push_str(&format!("0x{:x}", val));
            }
        }
        Operand::Rel(addr) => {
            out.push_str(&format!("0x{:x}", addr));
        }
        Operand::Mem(mem) => {
            // Size prefix
            match mem.size {
                OperandSize::Byte => out.push_str("byte ptr "),
                OperandSize::Word => out.push_str("word ptr "),
                OperandSize::Dword => out.push_str("dword ptr "),
                OperandSize::Qword => out.push_str("qword ptr "),
                _ => {}
            }

            // Segment override
            if let Some(seg) = mem.segment {
                out.push_str(seg.name());
                out.push(':');
            }

            out.push('[');
            let mut need_plus = false;

            if let Some(base) = mem.base {
                out.push_str(base.name());
                need_plus = true;
            }

            if let Some(index) = mem.index {
                if need_plus { out.push('+'); }
                out.push_str(index.name());
                if mem.scale > 1 {
                    out.push_str(&format!("*{}", mem.scale));
                }
                need_plus = true;
            }

            if mem.displacement != 0 || (!need_plus) {
                if mem.displacement < 0 {
                    out.push_str(&format!("-0x{:x}", mem.displacement.wrapping_neg() as u64));
                } else {
                    if need_plus { out.push('+'); }
                    out.push_str(&format!("0x{:x}", mem.displacement));
                }
            }

            out.push(']');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_nop() {
        let insn = Instruction {
            mnemonic: Mnemonic::Nop,
            operands: vec![],
            prefixes: Prefixes::default(),
            rex: None,
            length: 1,
            address: 0,
        };
        assert_eq!(format_instruction(&insn), "nop");
    }

    #[test]
    fn test_format_mov_reg_imm() {
        let insn = Instruction {
            mnemonic: Mnemonic::Mov,
            operands: vec![
                Operand::Reg(Register::Eax),
                Operand::Imm(0x12345678),
            ],
            prefixes: Prefixes::default(),
            rex: None,
            length: 5,
            address: 0,
        };
        assert_eq!(format_instruction(&insn), "mov eax, 0x12345678");
    }

    #[test]
    fn test_format_mem_operand() {
        let insn = Instruction {
            mnemonic: Mnemonic::Mov,
            operands: vec![
                Operand::Reg(Register::Rax),
                Operand::Mem(MemOperand {
                    base: Some(Register::Rbp),
                    index: None,
                    scale: 1,
                    displacement: -8,
                    segment: None,
                    size: OperandSize::Qword,
                }),
            ],
            prefixes: Prefixes::default(),
            rex: None,
            length: 4,
            address: 0,
        };
        assert_eq!(format_instruction(&insn), "mov rax, qword ptr [rbp-0x8]");
    }
}
