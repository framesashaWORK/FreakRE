//! Intel-syntax instruction formatter.

use crate::types::*;

/// Format an instruction in Intel syntax.
pub fn format_instruction(insn: &Instruction) -> String {
    let mut out = String::with_capacity(64);

    // Prefixes
    if insn.prefixes.lock { out.push_str("lock "); }
    let is_pause = matches!(insn.mnemonic, Mnemonic::Raw(ref s) if s == "pause");
    if insn.prefixes.rep && !is_pause { out.push_str("rep "); }
    if insn.prefixes.repne { out.push_str("repne "); }

    // Mnemonic
    out.push_str(&insn.mnemonic.as_str());

    // Operands
    for (i, op) in insn.operands.iter().enumerate() {
        if i == 0 { out.push(' '); } else { out.push_str(", "); }
        format_operand(&mut out, op);
    }

    out
}

fn format_operand(out: &mut String, op: &Operand) {
    match op {
        Operand::Reg(reg) => out.push_str(&reg.name()),
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
                OperandSize::Fword => out.push_str("fword ptr "),
                OperandSize::Tbyte => out.push_str("tbyte ptr "),
                OperandSize::Oword => out.push_str("oword ptr "),
                OperandSize::Yword => out.push_str("yword ptr "),
                OperandSize::Zword => out.push_str("zword ptr "),
                _ => {}
            }

            // Segment override
            if let Some(seg) = mem.segment {
                out.push_str(&seg.name());
                out.push(':');
            }

            out.push('[');
            let mut need_plus = false;

            if let Some(base) = mem.base {
                out.push_str(&base.name());
                need_plus = true;
            }

            if let Some(index) = mem.index {
                if need_plus { out.push('+'); }
                out.push_str(&index.name());
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

/// Format an instruction in AT&T (GNU) syntax.
/// Operands are reversed (source first) and prefixed with `%`/`$`; a size
/// suffix (`b`/`w`/`l`/`q`) is appended to the mnemonic when unambiguous.
pub fn format_instruction_att(insn: &Instruction) -> String {
    let mut out = String::with_capacity(64);

    if insn.prefixes.lock { out.push_str("lock "); }
    let is_pause = matches!(insn.mnemonic, Mnemonic::Raw(ref s) if s == "pause");
    if insn.prefixes.rep && !is_pause { out.push_str("rep "); }
    if insn.prefixes.repne { out.push_str("repne "); }

    out.push_str(&insn.mnemonic.as_str());
    if let Some(suf) = att_size_suffix(insn) {
        out.push(suf);
    }

    let n = insn.operands.len();
    for (i, _op) in insn.operands.iter().enumerate() {
        let op = &insn.operands[n - 1 - i];
        if i == 0 { out.push(' '); } else { out.push_str(", "); }
        format_operand_att(&mut out, op);
    }

    out
}

fn att_size_suffix(insn: &Instruction) -> Option<char> {
    for op in &insn.operands {
        let sz = match op {
            Operand::Reg(r) => r.size(),
            Operand::Mem(m) => Some(m.size),
            _ => None,
        };
        if let Some(s) = sz {
            return match s {
                OperandSize::Byte => Some('b'),
                OperandSize::Word => Some('w'),
                OperandSize::Dword => Some('l'),
                OperandSize::Qword => Some('q'),
                _ => None,
            };
        }
    }
    None
}

fn format_operand_att(out: &mut String, op: &Operand) {
    match op {
        Operand::Reg(r) => {
            out.push('%');
            out.push_str(&r.name());
        }
        Operand::Imm(v) => {
            out.push('$');
            if *v < 0 {
                out.push_str(&format!("-0x{:x}", v.wrapping_neg() as u64));
            } else {
                out.push_str(&format!("0x{:x}", v));
            }
        }
        Operand::Rel(a) => {
            out.push_str(&format!("0x{:x}", a));
        }
        Operand::Mem(m) => {
            if let Some(seg) = m.segment {
                out.push_str(&seg.name());
                out.push(':');
            }
            let has_base = m.base.is_some();
            let has_index = m.index.is_some();
            if m.displacement != 0 || (!has_base && !has_index) {
                if m.displacement < 0 {
                    out.push_str(&format!("-0x{:x}", m.displacement.wrapping_neg() as u64));
                } else {
                    out.push_str(&format!("0x{:x}", m.displacement));
                }
            }
            if has_base || has_index {
                out.push('(');
                if let Some(b) = m.base {
                    out.push('%');
                    out.push_str(&b.name());
                }
                if let Some(idx) = m.index {
                    out.push(',');
                    out.push('%');
                    out.push_str(&idx.name());
                    out.push(',');
                    out.push_str(&m.scale.to_string());
                }
                out.push(')');
            }
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
            bytes: [0u8; 15],
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
            bytes: [0u8; 15],
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
            bytes: [0u8; 15],
        };
        assert_eq!(format_instruction(&insn), "mov rax, qword ptr [rbp-0x8]");
    }
}
