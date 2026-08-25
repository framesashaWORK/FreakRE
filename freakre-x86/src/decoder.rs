//! Full x86/x64 instruction decoder.

use crate::types::*;

/// Decode a single instruction from bytes at the given address.
pub fn decode(code: &[u8], address: u64, mode: Mode) -> Result<Instruction, DecodeError> {
    let len = super::lde::decode_len(code, mode)?;
    if len > code.len() {
        return Err(DecodeError::TooShort);
    }
    let bytes = &code[..len];
    let is_64 = mode == Mode::X64;

    let mut pos = 0usize;
    let mut prefixes = Prefixes::default();
    let mut rex: Option<RexPrefix> = None;

    // Parse prefixes
    loop {
        if pos >= bytes.len() { return Err(DecodeError::TooShort); }
        match bytes[pos] {
            0xF0 => { prefixes.lock = true; pos += 1; }
            0xF2 => { prefixes.repne = true; pos += 1; }
            0xF3 => { prefixes.rep = true; pos += 1; }
            0x2E => { prefixes.cs = true; pos += 1; }
            0x36 => { prefixes.ss = true; pos += 1; }
            0x3E => { prefixes.ds = true; pos += 1; }
            0x26 => { prefixes.es = true; pos += 1; }
            0x64 => { prefixes.fs = true; pos += 1; }
            0x65 => { prefixes.gs = true; pos += 1; }
            0x66 => { prefixes.operand_size_override = true; pos += 1; }
            0x67 => { prefixes.address_size_override = true; pos += 1; }
            _ => break,
        }
    }

    // REX prefix (must be the last prefix before the opcode)
    if is_64 && pos < bytes.len() && (bytes[pos] & 0xF0) == 0x40 {
        rex = Some(RexPrefix {
            w: (bytes[pos] & 0x08) != 0,
            r: (bytes[pos] & 0x04) != 0,
            x: (bytes[pos] & 0x02) != 0,
            b: (bytes[pos] & 0x01) != 0,
        });
        pos += 1;
    }

    if pos >= bytes.len() { return Err(DecodeError::TooShort); }

    let rex_w = rex.is_some_and(|r| r.w);
    let p66 = prefixes.operand_size_override;

    // Default operand size
    let default_op_size: OperandSize = if rex_w { OperandSize::Qword }
        else if p66 { OperandSize::Word }
        else { OperandSize::Dword };

    // In long mode stack operations default to 64-bit (only 66 shrinks them)
    let stack_op_size: OperandSize = if is_64 {
        if p66 { OperandSize::Word } else { OperandSize::Qword }
    } else {
        if p66 { OperandSize::Word } else { OperandSize::Dword }
    };

    let (mnemonic, operands) = decode_opcode(
        bytes, pos + 1, address, len, is_64, rex,
        default_op_size, stack_op_size, p66,
    )?;

    Ok(Instruction {
        mnemonic,
        operands,
        prefixes,
        rex,
        length: len,
        address,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_opcode(
    bytes: &[u8], pos: usize, address: u64, insn_len: usize,
    is_64: bool, rex: Option<RexPrefix>,
    op_size: OperandSize, stack_size: OperandSize, p66: bool,
) -> Result<(Mnemonic, Vec<Operand>), DecodeError> {
    let opcode = bytes[pos - 1];
    let rex_w = rex.is_some_and(|r| r.w);
    let rex_b = rex.is_some_and(|r| r.b);
    let rex_present = rex.is_some();

    let reg = |idx: u8, ext: bool, size: OperandSize| pick_reg(idx, ext, size, rex_present);

    Ok(match opcode {
        // в”Ђв”Ђ Misc / system в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x90 => (Mnemonic::Nop, vec![]),
        0x98 => {
            let m = if is_64 && rex_w { Mnemonic::Cdqe }
                else if p66 { Mnemonic::Cbw }
                else { Mnemonic::Cwde };
            (m, vec![])
        }
        0x99 => (Mnemonic::Cdq, vec![]),
        0xD7 => (Mnemonic::Xlat, vec![]),
        0xC3 => (Mnemonic::Ret, vec![]),
        0xCB => (Mnemonic::Ret, vec![]), // far ret
        0xC9 => (Mnemonic::Leave, vec![]),
        0xC2 => {
            let imm = read_u16(bytes, pos)?;
            (Mnemonic::Ret, vec![Operand::Imm(imm as i64)])
        }
        0xC8 => {
            let a = read_u16(bytes, pos)? as i64;
            let b = read_u8(bytes, pos + 2)? as i64;
            (Mnemonic::Enter, vec![Operand::Imm(a), Operand::Imm(b)])
        }
        0xF8 => (Mnemonic::Stc, vec![]),
        0xF9 => (Mnemonic::Cmc, vec![]),
        0xFA => (Mnemonic::Cli, vec![]),
        0xFB => (Mnemonic::Sti, vec![]),
        0xFC => (Mnemonic::Cld, vec![]),
        0xFD => (Mnemonic::Std, vec![]),

        // в”Ђв”Ђ Segment push/pop в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x06 => (Mnemonic::Push, vec![Operand::Reg(Register::Es)]),
        0x0E => (Mnemonic::Push, vec![Operand::Reg(Register::Cs)]),
        0x16 => (Mnemonic::Push, vec![Operand::Reg(Register::Ss)]),
        0x1E => (Mnemonic::Push, vec![Operand::Reg(Register::Ds)]),
        0x07 => (Mnemonic::Pop, vec![Operand::Reg(Register::Es)]),
        0x17 => (Mnemonic::Pop, vec![Operand::Reg(Register::Ss)]),
        0x1F => (Mnemonic::Pop, vec![Operand::Reg(Register::Ds)]),

        // в”Ђв”Ђ Stack operations: 64-bit by default in long mode в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x50..=0x57 => (
            Mnemonic::Push,
            vec![Operand::Reg(reg(opcode - 0x50, rex_b, stack_size))],
        ),
        0x58..=0x5F => (
            Mnemonic::Pop,
            vec![Operand::Reg(reg(opcode - 0x58, rex_b, stack_size))],
        ),
        0x68 => (Mnemonic::Push, vec![Operand::Imm(read_i32(bytes, pos)? as i64)]),
        0x6A => (Mnemonic::Push, vec![Operand::Imm(read_i8(bytes, pos)? as i64)]),

        // в”Ђв”Ђ inc/dec r (32-bit mode only; in x64 these are REX slots) в”Ђ
        0x40..=0x47 if !is_64 => (
            Mnemonic::Inc,
            vec![Operand::Reg(reg(opcode - 0x40, false, op_size))],
        ),
        0x48..=0x4F if !is_64 => (
            Mnemonic::Dec,
            vec![Operand::Reg(reg(opcode - 0x48, false, op_size))],
        ),

        // в”Ђв”Ђ mov r, imm в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xB8..=0xBF => {
            let r = reg(opcode - 0xB8, rex_b, op_size);
            let imm = if rex_w && is_64 { read_i64(bytes, pos)? } else { read_i32(bytes, pos)? as i64 };
            (Mnemonic::Mov, vec![Operand::Reg(r), Operand::Imm(imm)])
        }
        0xB0..=0xB7 => {
            let r = reg8_for_index(opcode - 0xB0, rex_present, rex_b);
            (Mnemonic::Mov, vec![Operand::Reg(r), Operand::Imm(read_u8(bytes, pos)? as i64)])
        }

        // в”Ђв”Ђ ALU reg/mem forms (00-3D) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        // +0: r/m8, r8   +1: r/m, r   +2: r8, r/m8   +3: r, r/m
        // +4: al, imm8   +5: acc, imm
        0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B |
        0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B => {
            let alu = alu_mnemonic(opcode >> 3);
            let is_byte = (opcode & 1) == 0;
            let dir_to_rm = (opcode & 2) == 0; // +0/+1: dst = r/m
            let sz = if is_byte { OperandSize::Byte } else { op_size };
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, sz, sz)?;
            if dir_to_rm {
                (alu, vec![rm, Operand::Reg(r)])
            } else {
                (alu, vec![Operand::Reg(r), rm])
            }
        }
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => (
            alu_mnemonic(opcode >> 3),
            vec![Operand::Reg(Register::Al), Operand::Imm(read_u8(bytes, pos)? as i64)],
        ),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => (
            alu_mnemonic(opcode >> 3),
            vec![
                Operand::Reg(accumulator(op_size)),
                Operand::Imm(read_i32(bytes, pos)? as i64),
            ],
        ),

        // в”Ђв”Ђ test в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x84 => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, OperandSize::Byte, OperandSize::Byte)?;
            (Mnemonic::Test, vec![rm, Operand::Reg(r)])
        }
        0x85 => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, op_size, op_size)?;
            (Mnemonic::Test, vec![rm, Operand::Reg(r)])
        }
        0xA8 => (Mnemonic::Test, vec![Operand::Reg(Register::Al), Operand::Imm(read_u8(bytes, pos)? as i64)]),
        0xA9 => (Mnemonic::Test, vec![
            Operand::Reg(accumulator(op_size)),
            Operand::Imm(read_i32(bytes, pos)? as i64),
        ]),

        // в”Ђв”Ђ mov r/m forms в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x88 => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, OperandSize::Byte, OperandSize::Byte)?;
            (Mnemonic::Mov, vec![rm, Operand::Reg(r)])
        }
        0x89 => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, op_size, op_size)?;
            (Mnemonic::Mov, vec![rm, Operand::Reg(r)])
        }
        0x8A => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, OperandSize::Byte, OperandSize::Byte)?;
            (Mnemonic::Mov, vec![Operand::Reg(r), rm])
        }
        0x8B => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, op_size, op_size)?;
            (Mnemonic::Mov, vec![Operand::Reg(r), rm])
        }
        0x8D => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, op_size, op_size)?;
            (Mnemonic::Lea, vec![Operand::Reg(r), rm])
        }

        // в”Ђв”Ђ moffs moves в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xA0..=0xA3 => {
            let (addr, sz) = read_moffs(bytes, pos, is_64, rex_w, p66)?;
            let mem = Operand::Mem(MemOperand {
                base: None, index: None, scale: 1,
                displacement: addr, segment: None, size: sz,
            });
            match opcode {
                0xA0 => (Mnemonic::Mov, vec![Operand::Reg(Register::Al), mem]),
                0xA1 => (Mnemonic::Mov, vec![Operand::Reg(accumulator(sz)), mem]),
                0xA2 => (Mnemonic::Mov, vec![mem, Operand::Reg(Register::Al)]),
                _ => (Mnemonic::Mov, vec![mem, Operand::Reg(accumulator(sz))]),
            }
        }

        // в”Ђв”Ђ movsxd (x64) / arpl (x86, unsupported) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x63 if is_64 => {
            let (r, rm, _) = decode_modrm(bytes, pos, is_64, rex, op_size, OperandSize::Dword)?;
            (Mnemonic::Movsxd, vec![Operand::Reg(r), rm])
        }

        // в”Ђв”Ђ imul with immediate в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x69 => {
            let (r, rm, next) = decode_modrm(bytes, pos, is_64, rex, op_size, op_size)?;
            let imm = read_i32(bytes, next)? as i64;
            (Mnemonic::Imul, vec![Operand::Reg(r), rm, Operand::Imm(imm)])
        }
        0x6B => {
            let (r, rm, next) = decode_modrm(bytes, pos, is_64, rex, op_size, op_size)?;
            let imm = read_i8(bytes, next)? as i64;
            (Mnemonic::Imul, vec![Operand::Reg(r), rm, Operand::Imm(imm)])
        }

        // в”Ђв”Ђ String operations в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xA4 => (Mnemonic::Movsb, vec![]),
        0xA5 => str_op(is_64, rex_w, p66, (Mnemonic::Movsw, Mnemonic::Movsd, Mnemonic::Movsq)),
        0xA6 => (Mnemonic::Cmpsb, vec![]),
        0xA7 => str_op(is_64, rex_w, p66, (Mnemonic::Cmpsw, Mnemonic::Cmpsd, Mnemonic::Cmpsq)),
        0xAA => (Mnemonic::Stosb, vec![]),
        0xAB => str_op(is_64, rex_w, p66, (Mnemonic::Stosw, Mnemonic::Stosd, Mnemonic::Stosq)),
        0xAC => (Mnemonic::Lodsb, vec![]),
        0xAD => str_op(is_64, rex_w, p66, (Mnemonic::Lodsw, Mnemonic::Lodsd, Mnemonic::Lodsq)),
        0xAE => (Mnemonic::Scasb, vec![]),
        0xAF => str_op(is_64, rex_w, p66, (Mnemonic::Scasw, Mnemonic::Scasd, Mnemonic::Scasq)),

        // в”Ђв”Ђ Control flow в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x70..=0x7F => {
            let rel = read_i8(bytes, pos)? as i64;
            (jcc_mnemonic(opcode - 0x70), vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        0xE8 => {
            let rel = read_i32(bytes, pos)? as i64;
            (Mnemonic::Call, vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        0xE9 => {
            let rel = read_i32(bytes, pos)? as i64;
            (Mnemonic::Jmp, vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        0xEB => {
            let rel = read_i8(bytes, pos)? as i64;
            (Mnemonic::Jmp, vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }

        // в”Ђв”Ђ Group 1: add/or/adc/sbb/and/sub/xor/cmp, imm в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x80 | 0x82 => {
            let (rf, dst, next) = modrm_group(bytes, pos, is_64, rex, OperandSize::Byte)?;
            (alu_mnemonic(rf), vec![dst, Operand::Imm(read_u8(bytes, next)? as i64)])
        }
        0x81 => {
            let (rf, dst, next) = modrm_group(bytes, pos, is_64, rex, op_size)?;
            (alu_mnemonic(rf), vec![dst, Operand::Imm(read_i32(bytes, next)? as i64)])
        }
        0x83 => {
            let (rf, dst, next) = modrm_group(bytes, pos, is_64, rex, op_size)?;
            (alu_mnemonic(rf), vec![dst, Operand::Imm(read_i8(bytes, next)? as i64)])
        }

        // в”Ђв”Ђ Shift groups в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xC0 | 0xC1 => {
            let sz = if opcode == 0xC0 { OperandSize::Byte } else { op_size };
            let (rf, dst, next) = modrm_group(bytes, pos, is_64, rex, sz)?;
            (shift_mnemonic(rf), vec![dst, Operand::Imm(read_u8(bytes, next)? as i64)])
        }
        0xD0 | 0xD1 => {
            let sz = if opcode == 0xD0 { OperandSize::Byte } else { op_size };
            let (rf, dst, _) = modrm_group(bytes, pos, is_64, rex, sz)?;
            (shift_mnemonic(rf), vec![dst, Operand::Imm(1)])
        }
        0xD2 | 0xD3 => {
            let sz = if opcode == 0xD2 { OperandSize::Byte } else { op_size };
            let (rf, dst, _) = modrm_group(bytes, pos, is_64, rex, sz)?;
            (shift_mnemonic(rf), vec![dst, Operand::Reg(Register::Cl)])
        }

        // в”Ђв”Ђ Group 11: mov r/m, imm в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xC6 => {
            let (_, dst, next) = modrm_group(bytes, pos, is_64, rex, OperandSize::Byte)?;
            (Mnemonic::Mov, vec![dst, Operand::Imm(read_u8(bytes, next)? as i64)])
        }
        0xC7 => {
            let (_, dst, next) = modrm_group(bytes, pos, is_64, rex, op_size)?;
            (Mnemonic::Mov, vec![dst, Operand::Imm(read_i32(bytes, next)? as i64)])
        }

        // в”Ђв”Ђ Group 3 (F6/F7): test/not/neg/mul/imul/div/idiv в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xF6 | 0xF7 => {
            let sz = if opcode == 0xF6 { OperandSize::Byte } else { op_size };
            let (rf, dst, next) = modrm_group(bytes, pos, is_64, rex, sz)?;
            match rf {
                0 | 1 => {
                    let imm = if opcode == 0xF6 {
                        read_u8(bytes, next)? as i64
                    } else {
                        read_i32(bytes, next)? as i64
                    };
                    (Mnemonic::Test, vec![dst, Operand::Imm(imm)])
                }
                2 => (Mnemonic::Not, vec![dst]),
                3 => (Mnemonic::Neg, vec![dst]),
                4 => (Mnemonic::Mul, vec![dst]),
                5 => (Mnemonic::Imul, vec![dst]),
                6 => (Mnemonic::Div, vec![dst]),
                _ => (Mnemonic::Idiv, vec![dst]),
            }
        }

        // в”Ђв”Ђ Group 5 (FF): inc/dec/call/jmp/push r/m в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xFF if pos < bytes.len() => {
            let rf = (bytes[pos] >> 3) & 7;
            let sz = match rf {
                6 => stack_size,           // push r/m uses stack width
                2 | 4 => OperandSize::Qword, // indirect call/jmp are full-width
                _ => op_size,
            };
            let (_, dst, _) = modrm_group(bytes, pos, is_64, rex, sz)?;
            match rf {
                0 => (Mnemonic::Inc, vec![dst]),
                1 => (Mnemonic::Dec, vec![dst]),
                2 => (Mnemonic::Call, vec![dst]),
                4 => (Mnemonic::Jmp, vec![dst]),
                6 => (Mnemonic::Push, vec![dst]),
                _ => (Mnemonic::Unknown, vec![]),
            }
        }
        0xFE if pos < bytes.len() => {
            let (_, dst, _) = modrm_group(bytes, pos, is_64, rex, OperandSize::Byte)?;
            match (bytes[pos] >> 3) & 7 {
                0 => (Mnemonic::Inc, vec![dst]),
                1 => (Mnemonic::Dec, vec![dst]),
                _ => (Mnemonic::Unknown, vec![]),
            }
        }

        // в”Ђв”Ђ Two-byte opcodes (0F xx) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x0F if pos < bytes.len() => {
            let op2 = bytes[pos];
            let inner_pos = pos + 1;
            match op2 {
                0x05 => (Mnemonic::Syscall, vec![]),
                0x0B => (Mnemonic::Ud2, vec![]),
                0x1F => {
                    let (_, _, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, op_size)?;
                    (Mnemonic::Nop, vec![])
                }
                0x31 => (Mnemonic::Rdtsc, vec![]),
                0xA2 => (Mnemonic::Cpuid, vec![]),
                0x40..=0x4F => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, op_size)?;
                    (cmovcc_mnemonic(op2 - 0x40), vec![Operand::Reg(r), rm])
                }
                0x80..=0x8F => {
                    let rel = read_i32(bytes, inner_pos)? as i64;
                    (jcc_mnemonic(op2 - 0x80), vec![Operand::Rel(rel_target(address, insn_len, rel))])
                }
                0xAF => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, op_size)?;
                    (Mnemonic::Imul, vec![Operand::Reg(r), rm])
                }
                0xB6 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, OperandSize::Byte)?;
                    (Mnemonic::Movzx, vec![Operand::Reg(r), rm])
                }
                0xB7 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, OperandSize::Word)?;
                    (Mnemonic::Movzx, vec![Operand::Reg(r), rm])
                }
                0xBE => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, OperandSize::Byte)?;
                    (Mnemonic::Movsx, vec![Operand::Reg(r), rm])
                }
                0xBF => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, OperandSize::Word)?;
                    (Mnemonic::Movsx, vec![Operand::Reg(r), rm])
                }
                0xA3 | 0xAB | 0xB3 | 0xBB => {
                    // bt/bts/btr/btc r/m, r
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, op_size)?;
                    let m = match op2 {
                        0xA3 => Mnemonic::Bt,
                        0xAB => Mnemonic::Bts,
                        0xB3 => Mnemonic::Btr,
                        _ => Mnemonic::Btc,
                    };
                    (m, vec![rm, Operand::Reg(r)])
                }
                0xBC | 0xBD => {
                    // bsf/bsr r, r/m
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, is_64, rex, op_size, op_size)?;
                    let m = if op2 == 0xBC { Mnemonic::Bsf } else { Mnemonic::Bsr };
                    (m, vec![Operand::Reg(r), rm])
                }
                0xBA => {
                    // group 8: bt/bts/btr/btc r/m, imm8
                    let (rf, dst, next) = modrm_group(bytes, inner_pos, is_64, rex, op_size)?;
                    let m = match rf {
                        4 => Mnemonic::Bt,
                        5 => Mnemonic::Bts,
                        6 => Mnemonic::Btr,
                        7 => Mnemonic::Btc,
                        _ => Mnemonic::Unknown,
                    };
                    (m, vec![dst, Operand::Imm(read_i8(bytes, next)? as i64)])
                }
                0xC8..=0xCF => (
                    Mnemonic::Bswap,
                    vec![Operand::Reg(reg(op2 - 0xC8, rex_b, op_size))],
                ),
                _ => (Mnemonic::Unknown, vec![]),
            }
        }

        _ => (Mnemonic::Unknown, vec![]),
    })
}

fn str_op(is_64: bool, rex_w: bool, p66: bool, variants: (Mnemonic, Mnemonic, Mnemonic)) -> (Mnemonic, Vec<Operand>) {
    let m = if is_64 && rex_w {
        variants.2
    } else if p66 {
        variants.0
    } else {
        variants.1
    };
    (m, vec![])
}

fn accumulator(size: OperandSize) -> Register {
    match size {
        OperandSize::Qword => Register::Rax,
        OperandSize::Word => Register::Ax,
        _ => Register::Eax,
    }
}

fn rel_target(address: u64, insn_len: usize, rel: i64) -> u64 {
    (address as i64 + insn_len as i64 + rel) as u64
}

/// moffs displacement: sized by operand size (REX.W в†’ 8, 66 в†’ 2, else 4).
fn read_moffs(code: &[u8], pos: usize, is_64: bool, rex_w: bool, p66: bool) -> Result<(i64, OperandSize), DecodeError> {
    let (n, sz) = if rex_w && is_64 {
        (8usize, OperandSize::Qword)
    } else if p66 {
        (2, OperandSize::Word)
    } else {
        (4, OperandSize::Dword)
    };
    if pos + n > code.len() { return Err(DecodeError::TooShort); }
    let mut v: u64 = 0;
    for i in 0..n {
        v |= (code[pos + i] as u64) << (i * 8);
    }
    Ok((v as i64, sz))
}

fn alu_mnemonic(base: u8) -> Mnemonic {
    match base {
        0 => Mnemonic::Add,
        1 => Mnemonic::Or,
        2 => Mnemonic::Adc,
        3 => Mnemonic::Sbb,
        4 => Mnemonic::And,
        5 => Mnemonic::Sub,
        6 => Mnemonic::Xor,
        _ => Mnemonic::Cmp,
    }
}

fn shift_mnemonic(reg_field: u8) -> Mnemonic {
    match reg_field {
        0 => Mnemonic::Rol,
        1 => Mnemonic::Ror,
        4 | 6 => Mnemonic::Shl, // /6 = SAL alias
        5 => Mnemonic::Shr,
        7 => Mnemonic::Sar,
        _ => Mnemonic::Unknown, // rcl/rcr unsupported
    }
}

// в”Ђв”Ђ Helper functions в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn read_u8(code: &[u8], pos: usize) -> Result<u8, DecodeError> {
    code.get(pos).copied().ok_or(DecodeError::TooShort)
}

fn read_i8(code: &[u8], pos: usize) -> Result<i8, DecodeError> {
    code.get(pos).map(|&b| b as i8).ok_or(DecodeError::TooShort)
}

fn read_u16(code: &[u8], pos: usize) -> Result<u16, DecodeError> {
    if pos + 2 > code.len() { return Err(DecodeError::TooShort); }
    Ok(u16::from_le_bytes([code[pos], code[pos + 1]]))
}

fn read_i32(code: &[u8], pos: usize) -> Result<i32, DecodeError> {
    if pos + 4 > code.len() { return Err(DecodeError::TooShort); }
    Ok(i32::from_le_bytes([code[pos], code[pos+1], code[pos+2], code[pos+3]]))
}

fn read_i64(code: &[u8], pos: usize) -> Result<i64, DecodeError> {
    if pos + 8 > code.len() { return Err(DecodeError::TooShort); }
    Ok(i64::from_le_bytes([
        code[pos], code[pos+1], code[pos+2], code[pos+3],
        code[pos+4], code[pos+5], code[pos+6], code[pos+7],
    ]))
}

fn pick_reg(idx: u8, ext: bool, size: OperandSize, rex_present: bool) -> Register {
    match size {
        OperandSize::Byte => reg8_for_index(idx, rex_present, ext),
        _ => reg_for_index(idx, ext, size),
    }
}

fn reg_for_index(idx: u8, rex_ext: bool, size: OperandSize) -> Register {
    let extended = if rex_ext { idx + 8 } else { idx };
    match size {
        OperandSize::Qword => match extended {
            0 => Register::Rax, 1 => Register::Rcx, 2 => Register::Rdx, 3 => Register::Rbx,
            4 => Register::Rsp, 5 => Register::Rbp, 6 => Register::Rsi, 7 => Register::Rdi,
            8 => Register::R8, 9 => Register::R9, 10 => Register::R10, 11 => Register::R11,
            12 => Register::R12, 13 => Register::R13, 14 => Register::R14, 15 => Register::R15,
            _ => Register::Rax,
        },
        OperandSize::Dword => match extended {
            0 => Register::Eax, 1 => Register::Ecx, 2 => Register::Edx, 3 => Register::Ebx,
            4 => Register::Esp, 5 => Register::Ebp, 6 => Register::Esi, 7 => Register::Edi,
            8 => Register::R8d, 9 => Register::R9d, 10 => Register::R10d, 11 => Register::R11d,
            12 => Register::R12d, 13 => Register::R13d, 14 => Register::R14d, 15 => Register::R15d,
            _ => Register::Eax,
        },
        OperandSize::Word => match extended {
            0 => Register::Ax, 1 => Register::Cx, 2 => Register::Dx, 3 => Register::Bx,
            4 => Register::Sp, 5 => Register::Bp, 6 => Register::Si, 7 => Register::Di,
            8 => Register::R8w, 9 => Register::R9w, 10 => Register::R10w, 11 => Register::R11w,
            12 => Register::R12w, 13 => Register::R13w, 14 => Register::R14w, 15 => Register::R15w,
            _ => Register::Ax,
        },
        _ => Register::Eax,
    }
}

/// Byte registers. With a REX prefix present, the high bytes (AH/CH/DH/BH)
/// become SPL/BPL/SIL/DIL; REX.B selects r8bвЂ“r15b instead.
fn reg8_for_index(idx: u8, rex_present: bool, rex_ext: bool) -> Register {
    if rex_ext {
        return match idx + 8 {
            8 => Register::R8b, 9 => Register::R9b, 10 => Register::R10b, 11 => Register::R11b,
            12 => Register::R12b, 13 => Register::R13b, 14 => Register::R14b, 15 => Register::R15b,
            _ => Register::Al,
        };
    }
    match idx {
        0 => Register::Al, 1 => Register::Cl, 2 => Register::Dl, 3 => Register::Bl,
        4 => if rex_present { Register::Spl } else { Register::Ah },
        5 => if rex_present { Register::Bpl } else { Register::Ch },
        6 => if rex_present { Register::Sil } else { Register::Dh },
        7 => if rex_present { Register::Dil } else { Register::Bh },
        _ => Register::Al,
    }
}

fn jcc_mnemonic(cc: u8) -> Mnemonic {
    match cc {
        0 => Mnemonic::Jo, 1 => Mnemonic::Jno, 2 => Mnemonic::Jb, 3 => Mnemonic::Jnb,
        4 => Mnemonic::Je, 5 => Mnemonic::Jne, 6 => Mnemonic::Jbe, 7 => Mnemonic::Ja,
        8 => Mnemonic::Js, 9 => Mnemonic::Jns, 0xA => Mnemonic::Jp, 0xB => Mnemonic::Jnp,
        0xC => Mnemonic::Jl, 0xD => Mnemonic::Jge, 0xE => Mnemonic::Jle, 0xF => Mnemonic::Jg,
        _ => Mnemonic::Jcc,
    }
}

fn cmovcc_mnemonic(cc: u8) -> Mnemonic {
    match cc {
        0 => Mnemonic::Cmovo, 1 => Mnemonic::Cmovno, 2 => Mnemonic::Cmovb, 3 => Mnemonic::Cmovae,
        4 => Mnemonic::Cmove, 5 => Mnemonic::Cmovne, 6 => Mnemonic::Cmovbe, 7 => Mnemonic::Cmova,
        8 => Mnemonic::Cmovs, 9 => Mnemonic::Cmovns, 0xA => Mnemonic::Cmovp, 0xB => Mnemonic::Cmovnp,
        0xC => Mnemonic::Cmovl, 0xD => Mnemonic::Cmovge, 0xE => Mnemonic::Cmovle, 0xF => Mnemonic::Cmovg,
        _ => Mnemonic::Cmovcc,
    }
}

/// Decode ModR/M (+SIB+disp). Returns (reg-field operand, r/m operand, next position).
fn decode_modrm(
    code: &[u8], pos: usize, is_64: bool, rex: Option<RexPrefix>,
    reg_size: OperandSize, rm_size: OperandSize,
) -> Result<(Register, Operand, usize), DecodeError> {
    if pos >= code.len() { return Err(DecodeError::TooShort); }
    let modrm = code[pos];
    let r#mod = (modrm >> 6) & 3;
    let reg_f = (modrm >> 3) & 7;
    let rm = modrm & 7;

    let rex_r = rex.is_some_and(|r| r.r);
    let rex_b = rex.is_some_and(|r| r.b);
    let rex_x = rex.is_some_and(|r| r.x);
    let rex_present = rex.is_some();

    let reg_operand = pick_reg(reg_f, rex_r, reg_size, rex_present);
    let mut next_pos = pos + 1;

    let mem_operand = if r#mod == 3 {
        Operand::Reg(pick_reg(rm, rex_b, rm_size, rex_present))
    } else {
        let mut base: Option<Register> = None;
        let mut index: Option<Register> = None;
        let mut scale: u8 = 1;
        let mut disp: i64 = 0;

        if rm == 4 {
            // SIB byte
            if next_pos >= code.len() { return Err(DecodeError::TooShort); }
            let sib = code[next_pos];
            next_pos += 1;
            let sib_base = sib & 7;
            let sib_idx = (sib >> 3) & 7;
            let sib_scale = (sib >> 6) & 3;
            scale = 1 << sib_scale;

            if sib_base == 5 && r#mod == 0 {
                disp = read_i32(code, next_pos)? as i64;
                next_pos += 4;
            } else if is_64 {
                // Addressing always uses full-width registers in long mode
                base = Some(reg_for_index(sib_base, rex_b, OperandSize::Qword));
            } else {
                base = Some(reg_for_index(sib_base, rex_b, rm_size));
            }

            if sib_idx != 4 {
                index = Some(if is_64 {
                    reg_for_index(sib_idx, rex_x, OperandSize::Qword)
                } else {
                    reg_for_index(sib_idx, rex_x, rm_size)
                });
            }
        } else if rm == 5 && r#mod == 0 {
            if is_64 {
                base = Some(Register::Rip);
            }
            disp = read_i32(code, next_pos)? as i64;
            next_pos += 4;
        } else if is_64 {
            base = Some(reg_for_index(rm, rex_b, OperandSize::Qword));
        } else {
            base = Some(reg_for_index(rm, rex_b, rm_size));
        }

        match r#mod {
            1 => { disp = read_i8(code, next_pos)? as i64; next_pos += 1; }
            2 => { disp = read_i32(code, next_pos)? as i64; next_pos += 4; }
            _ => {}
        }

        Operand::Mem(MemOperand {
            base, index, scale, displacement: disp,
            segment: None, size: rm_size,
        })
    };

    Ok((reg_operand, mem_operand, next_pos))
}

/// ModR/M group instruction: reg field selects the operation.
fn modrm_group(
    code: &[u8], pos: usize, is_64: bool, rex: Option<RexPrefix>, op_size: OperandSize,
) -> Result<(u8, Operand, usize), DecodeError> {
    if pos >= code.len() { return Err(DecodeError::TooShort); }
    let reg_field = (code[pos] >> 3) & 7;
    let (_, operand, next_pos) = decode_modrm(code, pos, is_64, rex, op_size, op_size)?;
    Ok((reg_field, operand, next_pos))
}

