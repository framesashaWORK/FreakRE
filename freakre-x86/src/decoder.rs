//! Full x86/x64/x16 instruction decoder.

use crate::simd;
use crate::types::*;

/// Decode context: mode flags derived once in [`decode`] and threaded
/// through every helper so 16/32/64-bit behavior can never drift.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ctx {
    pub is_64: bool,
    pub is_16: bool,
    /// True when effective address width is 16 bits (16-bit mode default,
    /// or 0x67 override in 32-bit mode; never true in long mode where 0x67
    /// selects 32-bit addresses instead).
    pub addr16: bool,
    /// True when effective operand width is 16 bits (toggled by 0x66 in
    /// every mode; REX.W in long mode forces 64-bit instead).
    pub op16: bool,
}

/// 64-bit context for VEX/EVEX helpers (only reachable in long mode).
fn ctx64() -> Ctx {
    Ctx { is_64: true, is_16: false, addr16: false, op16: false }
}

/// Decode a single instruction from bytes at the given address.
pub fn decode(code: &[u8], address: u64, mode: Mode) -> Result<Instruction, DecodeError> {
    let len = super::lde::decode_len(code, mode)?;
    if len > code.len() {
        return Err(DecodeError::TooShort);
    }
    let bytes = &code[..len];
    let is_64 = mode == Mode::X64;
    let is_16 = mode == Mode::X16;

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

    // REX prefix (64-bit mode only; in 16/32-bit 0x40-0x4F are inc/dec).
    // Must be the last prefix before the opcode.
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
    let addr_override = prefixes.address_size_override;
    let ctx = Ctx {
        is_64,
        is_16,
        addr16: match mode {
            Mode::X16 => !addr_override,
            Mode::X86 => addr_override,
            Mode::X64 => false,
        },
        op16: if is_16 { !p66 } else { p66 },
    };

    // Default operand size
    let default_op_size: OperandSize = if rex_w && is_64 {
        OperandSize::Qword
    } else if ctx.op16 {
        OperandSize::Word
    } else {
        OperandSize::Dword
    };

    // Stack width follows the mode (only 0x66 toggles it)
    let stack_op_size: OperandSize = match mode {
        Mode::X16 => if p66 { OperandSize::Dword } else { OperandSize::Word },
        Mode::X86 => if p66 { OperandSize::Word } else { OperandSize::Dword },
        Mode::X64 => if p66 { OperandSize::Word } else { OperandSize::Qword },
    };

    let (mnemonic, operands) = decode_opcode(
        bytes, pos + 1, address, len, ctx, rex,
        default_op_size, stack_op_size, prefixes,
    )?;

    let mut raw = [0u8; 15];
    raw[..len].copy_from_slice(bytes);

    Ok(Instruction {
        mnemonic,
        operands,
        prefixes,
        rex,
        length: len,
        address,
        bytes: raw,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_opcode(
    bytes: &[u8], pos: usize, address: u64, insn_len: usize,
    ctx: Ctx, rex: Option<RexPrefix>,
    op_size: OperandSize, stack_size: OperandSize, prefixes: Prefixes,
) -> Result<(Mnemonic, Vec<Operand>), DecodeError> {
    let opcode = bytes[pos - 1];
    let is_64 = ctx.is_64;
    let is_16 = ctx.is_16;
    let p66 = prefixes.operand_size_override;
    let pp = if p66 { 1 } else if prefixes.rep { 2 } else if prefixes.repne { 3 } else { 0 };
    let rex_w = rex.is_some_and(|r| r.w);
    let rex_r = rex.is_some_and(|r| r.r);
    let rex_x = rex.is_some_and(|r| r.x);
    let rex_b = rex.is_some_and(|r| r.b);
    let rex_present = rex.is_some();

    let reg = |idx: u8, ext: bool, size: OperandSize| pick_reg(idx, ext, size, rex_present);

    // FPU x87 (escape bytes D8..DF)
    if (0xD8..=0xDF).contains(&opcode) {
        return decode_fpu(opcode, bytes, pos, ctx);
    }

    // VEX / EVEX (only in 64-bit mode; in 32-bit C4/C5 are LES/LDS, 62 is BOUND)
    if is_64 && (opcode == 0xC4 || opcode == 0xC5) {
        return decode_vex(opcode, bytes, pos, is_64);
    }
    if is_64 && opcode == 0x62 {
        return decode_evex(bytes, pos, is_64);
    }

    Ok(match opcode {
        // в”Ђв”Ђ Misc / system в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x90 => {
            if prefixes.rep {
                (Mnemonic::Raw("pause".to_string()), vec![])
            } else {
                (Mnemonic::Nop, vec![])
            }
        }
        0x9E => (Mnemonic::Lahf, vec![]),
        0x9F => (Mnemonic::Sahf, vec![]),
        0xF4 => (Mnemonic::Hlt, vec![]),
        0xE0 => {
            let disp = read_i8(bytes, pos)? as i64;
            let t = rel_target(address, pos + 1, disp);
            (Mnemonic::Loopne, vec![Operand::Rel(t)])
        }
        0xE1 => {
            let disp = read_i8(bytes, pos)? as i64;
            let t = rel_target(address, pos + 1, disp);
            (Mnemonic::Loope, vec![Operand::Rel(t)])
        }
        0xE2 => {
            let disp = read_i8(bytes, pos)? as i64;
            let t = rel_target(address, pos + 1, disp);
            (Mnemonic::Loop, vec![Operand::Rel(t)])
        }
        0xE3 => {
            let disp = read_i8(bytes, pos)? as i64;
            let t = rel_target(address, pos + 1, disp);
            (Mnemonic::Jecxz, vec![Operand::Rel(t)])
        }
        0x98 => {
            let m = if is_64 && rex_w { Mnemonic::Cdqe }
                else if p66 != is_16 { Mnemonic::Cbw }
                else { Mnemonic::Cwde };
            (m, vec![])
        }
        0x99 => (
            if is_16 && !p66 { Mnemonic::Cwd } else { Mnemonic::Cdq },
            vec![],
        ),
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
        0x68 => {
            // push imm: 16-bit in 16-bit mode, 32-bit otherwise
            // (REX.W does not widen it in long mode).
            let imm = if ctx.op16 { read_u16(bytes, pos)? as i64 } else { read_i32(bytes, pos)? as i64 };
            (Mnemonic::Push, vec![Operand::Imm(imm)])
        }
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
            let imm = if rex_w && is_64 {
                read_i64(bytes, pos)?
            } else if ctx.op16 {
                read_u16(bytes, pos)? as i64
            } else {
                read_i32(bytes, pos)? as i64
            };
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
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, sz, sz)?;
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
                Operand::Imm(read_imm_opsize(bytes, pos, ctx)?),
            ],
        ),

        // в”Ђв”Ђ test в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x84 => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, OperandSize::Byte, OperandSize::Byte)?;
            (Mnemonic::Test, vec![rm, Operand::Reg(r)])
        }
        0x85 => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            (Mnemonic::Test, vec![rm, Operand::Reg(r)])
        }
        0xA8 => (Mnemonic::Test, vec![Operand::Reg(Register::Al), Operand::Imm(read_u8(bytes, pos)? as i64)]),
        0xA9 => (Mnemonic::Test, vec![
            Operand::Reg(accumulator(op_size)),
            Operand::Imm(read_imm_opsize(bytes, pos, ctx)?),
        ]),

        // в”Ђв”Ђ mov r/m forms в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x88 => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, OperandSize::Byte, OperandSize::Byte)?;
            (Mnemonic::Mov, vec![rm, Operand::Reg(r)])
        }
        0x89 => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            (Mnemonic::Mov, vec![rm, Operand::Reg(r)])
        }
        0x8A => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, OperandSize::Byte, OperandSize::Byte)?;
            (Mnemonic::Mov, vec![Operand::Reg(r), rm])
        }
        0x8B => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            (Mnemonic::Mov, vec![Operand::Reg(r), rm])
        }
        0x8C => {
            let reg_f = (bytes[pos] >> 3) & 7;
            let (_, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            (Mnemonic::Mov, vec![rm, Operand::Reg(seg_reg(reg_f))])
        }
        0x8E => {
            let reg_f = (bytes[pos] >> 3) & 7;
            let (_, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            (Mnemonic::Mov, vec![Operand::Reg(seg_reg(reg_f)), rm])
        }
        0x8D => {
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            (Mnemonic::Lea, vec![Operand::Reg(r), rm])
        }

        // в”Ђв”Ђ moffs moves в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xA0..=0xA3 => {
            let (addr, sz) = read_moffs(bytes, pos, ctx, rex_w, op_size)?;
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
            let (r, rm, _) = decode_modrm(bytes, pos, ctx, rex, op_size, OperandSize::Dword)?;
            (Mnemonic::Movsxd, vec![Operand::Reg(r), rm])
        }

        // в”Ђв”Ђ imul with immediate в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x69 => {
            let (r, rm, next) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            let imm = read_imm_opsize(bytes, next, ctx)?;
            (Mnemonic::Imul, vec![Operand::Reg(r), rm, Operand::Imm(imm)])
        }
        0x6B => {
            let (r, rm, next) = decode_modrm(bytes, pos, ctx, rex, op_size, op_size)?;
            let imm = read_i8(bytes, next)? as i64;
            (Mnemonic::Imul, vec![Operand::Reg(r), rm, Operand::Imm(imm)])
        }

        // в”Ђв”Ђ String operations в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xA4 => (Mnemonic::Movsb, vec![]),
        0xA5 => str_op(ctx, rex_w, p66, (Mnemonic::Movsw, Mnemonic::Movsd, Mnemonic::Movsq)),
        0xA6 => (Mnemonic::Cmpsb, vec![]),
        0xA7 => str_op(ctx, rex_w, p66, (Mnemonic::Cmpsw, Mnemonic::Cmpsd, Mnemonic::Cmpsq)),
        0xAA => (Mnemonic::Stosb, vec![]),
        0xAB => str_op(ctx, rex_w, p66, (Mnemonic::Stosw, Mnemonic::Stosd, Mnemonic::Stosq)),
        0xAC => (Mnemonic::Lodsb, vec![]),
        0xAD => str_op(ctx, rex_w, p66, (Mnemonic::Lodsw, Mnemonic::Lodsd, Mnemonic::Lodsq)),
        0xAE => (Mnemonic::Scasb, vec![]),
        0xAF => str_op(ctx, rex_w, p66, (Mnemonic::Scasw, Mnemonic::Scasd, Mnemonic::Scasq)),

        // в”Ђв”Ђ Control flow в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x70..=0x7F => {
            let rel = read_i8(bytes, pos)? as i64;
            (jcc_mnemonic(opcode - 0x70), vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        0xE8 => {
            // call rel: 16-bit in 16-bit mode, 32-bit otherwise (0x66 toggles).
            let rel = read_rel_opsize(bytes, pos, ctx)? as i64;
            (Mnemonic::Call, vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        0xE9 => {
            let rel = read_rel_opsize(bytes, pos, ctx)? as i64;
            (Mnemonic::Jmp, vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        0xEB => {
            let rel = read_i8(bytes, pos)? as i64;
            (Mnemonic::Jmp, vec![Operand::Rel(rel_target(address, insn_len, rel))])
        }
        // Far jump/call (16/32-bit only): ptr16:16 (5 bytes) / ptr16:32 (7 bytes).
        // Operands intentionally empty — segment:offset has no Operand form.
        0xEA | 0x9A if !is_64 => {
            let need = if is_16 { 4 } else { 6 };
            if pos + need > bytes.len() { return Err(DecodeError::TooShort); }
            (if opcode == 0xEA { Mnemonic::Jmp } else { Mnemonic::Call }, vec![])
        }

        // в”Ђв”Ђ Group 1: add/or/adc/sbb/and/sub/xor/cmp, imm в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0x80 | 0x82 => {
            let (rf, dst, next) = modrm_group(bytes, pos, ctx, rex, OperandSize::Byte)?;
            (alu_mnemonic(rf), vec![dst, Operand::Imm(read_u8(bytes, next)? as i64)])
        }
        0x81 => {
            let (rf, dst, next) = modrm_group(bytes, pos, ctx, rex, op_size)?;
            (alu_mnemonic(rf), vec![dst, Operand::Imm(read_imm_opsize(bytes, next, ctx)?)])
        }
        0x83 => {
            let (rf, dst, next) = modrm_group(bytes, pos, ctx, rex, op_size)?;
            (alu_mnemonic(rf), vec![dst, Operand::Imm(read_i8(bytes, next)? as i64)])
        }

        // в”Ђв”Ђ Shift groups в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xC0 | 0xC1 => {
            let sz = if opcode == 0xC0 { OperandSize::Byte } else { op_size };
            let (rf, dst, next) = modrm_group(bytes, pos, ctx, rex, sz)?;
            (shift_mnemonic(rf), vec![dst, Operand::Imm(read_u8(bytes, next)? as i64)])
        }
        0xD0 | 0xD1 => {
            let sz = if opcode == 0xD0 { OperandSize::Byte } else { op_size };
            let (rf, dst, _) = modrm_group(bytes, pos, ctx, rex, sz)?;
            (shift_mnemonic(rf), vec![dst, Operand::Imm(1)])
        }
        0xD2 | 0xD3 => {
            let sz = if opcode == 0xD2 { OperandSize::Byte } else { op_size };
            let (rf, dst, _) = modrm_group(bytes, pos, ctx, rex, sz)?;
            (shift_mnemonic(rf), vec![dst, Operand::Reg(Register::Cl)])
        }

        // в”Ђв”Ђ Group 11: mov r/m, imm в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xC6 => {
            let (_, dst, next) = modrm_group(bytes, pos, ctx, rex, OperandSize::Byte)?;
            (Mnemonic::Mov, vec![dst, Operand::Imm(read_u8(bytes, next)? as i64)])
        }
        0xC7 => {
            let (_, dst, next) = modrm_group(bytes, pos, ctx, rex, op_size)?;
            (Mnemonic::Mov, vec![dst, Operand::Imm(read_imm_opsize(bytes, next, ctx)?)])
        }

        // в”Ђв”Ђ Group 3 (F6/F7): test/not/neg/mul/imul/div/idiv в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        0xF6 | 0xF7 => {
            let sz = if opcode == 0xF6 { OperandSize::Byte } else { op_size };
            let (rf, dst, next) = modrm_group(bytes, pos, ctx, rex, sz)?;
            match rf {
                0 | 1 => {
                    let imm = if opcode == 0xF6 {
                        read_u8(bytes, next)? as i64
                    } else {
                        read_imm_opsize(bytes, next, ctx)?
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
            let (_, dst, _) = modrm_group(bytes, pos, ctx, rex, sz)?;
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
            let (_, dst, _) = modrm_group(bytes, pos, ctx, rex, OperandSize::Byte)?;
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

            // Three-byte escape maps (0F 38 / 0F 3A)
            if op2 == 0x38 || op2 == 0x3A {
                if inner_pos < bytes.len() {
                    let _op3 = bytes[inner_pos];
                    let map = if op2 == 0x38 { 1 } else { 2 };
                    let st = simd::sse_state(map, pp, rex_w, rex_r, rex_x, rex_b);
                    if let Some(r) = simd::decode_simd(&st, bytes, inner_pos, ctx) {
                        return Ok(r);
                    }
                }
                return Ok((Mnemonic::Unknown, vec![]));
            }

            // emms (0F 77) has no ModR/M
            if op2 == 0x77 {
                return Ok((Mnemonic::Raw("emms".to_string()), vec![]));
            }

            // 0F AE group: fxsave/fxrstor/ldmxcsr/stmxcsr/xsave/lfence/mfence/sfence
            if op2 == 0xAE {
                if inner_pos < bytes.len() {
                    let rf = (bytes[inner_pos] >> 3) & 7;
                    let name = match rf {
                        0 => "fxsave", 1 => "fxrstor", 2 => "ldmxcsr", 3 => "stmxcsr",
                        4 => "xsave", 5 => "lfence", 6 => "mfence", 7 => "sfence",
                        _ => return Ok((Mnemonic::Unknown, vec![])),
                    };
                    let (_, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    return Ok((Mnemonic::Raw(name.to_string()), vec![rm]));
                }
                return Ok((Mnemonic::Unknown, vec![]));
            }

            // SSE / SSE2 / SSE3 / SSE4 (0F map)
            let st = simd::sse_state(0, pp, rex_w, rex_r, rex_x, rex_b);
            if let Some(r) = simd::decode_simd(&st, bytes, pos, ctx) {
                return Ok(r);
            }

            match op2 {
                0x05 => (Mnemonic::Syscall, vec![]),
                0x0B => (Mnemonic::Ud2, vec![]),
                0x1F => {
                    let (_, _, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Nop, vec![])
                }
                0x31 => (Mnemonic::Rdtsc, vec![]),
                0xA2 => (Mnemonic::Cpuid, vec![]),
                0x40..=0x4F => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (cmovcc_mnemonic(op2 - 0x40), vec![Operand::Reg(r), rm])
                }
                0x80..=0x8F => {
                    let rel = read_rel_opsize(bytes, inner_pos, ctx)? as i64;
                    (jcc_mnemonic(op2 - 0x80), vec![Operand::Rel(rel_target(address, insn_len, rel))])
                }
                0xAF => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Imul, vec![Operand::Reg(r), rm])
                }
                0xB6 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, OperandSize::Byte)?;
                    (Mnemonic::Movzx, vec![Operand::Reg(r), rm])
                }
                0xB7 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, OperandSize::Word)?;
                    (Mnemonic::Movzx, vec![Operand::Reg(r), rm])
                }
                0xBE => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, OperandSize::Byte)?;
                    (Mnemonic::Movsx, vec![Operand::Reg(r), rm])
                }
                0xBF => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, OperandSize::Word)?;
                    (Mnemonic::Movsx, vec![Operand::Reg(r), rm])
                }
                0xA3 | 0xAB | 0xB3 | 0xBB => {
                    // bt/bts/btr/btc r/m, r
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
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
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    let m = if op2 == 0xBC { Mnemonic::Bsf } else { Mnemonic::Bsr };
                    (m, vec![Operand::Reg(r), rm])
                }
                0xBA => {
                    // group 8: bt/bts/btr/btc r/m, imm8
                    let (rf, dst, next) = modrm_group(bytes, inner_pos, ctx, rex, op_size)?;
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
                0x90..=0x9F => {
                    let (_, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, OperandSize::Byte, OperandSize::Byte)?;
                    (setcc_mnemonic(op2 - 0x90), vec![rm])
                }
                0xA0 => (Mnemonic::Push, vec![Operand::Reg(Register::Fs)]),
                0xA1 => (Mnemonic::Pop, vec![Operand::Reg(Register::Fs)]),
                0xA8 => (Mnemonic::Push, vec![Operand::Reg(Register::Gs)]),
                0xA9 => (Mnemonic::Pop, vec![Operand::Reg(Register::Gs)]),
                0xA4 => {
                    let (r, rm, next) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Raw("shld".to_string()), vec![rm, Operand::Reg(r), Operand::Imm(read_u8(bytes, next)? as i64)])
                }
                0xA5 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Raw("shld".to_string()), vec![rm, Operand::Reg(r), Operand::Reg(Register::Cl)])
                }
                0xAC => {
                    let (r, rm, next) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Raw("shrd".to_string()), vec![rm, Operand::Reg(r), Operand::Imm(read_u8(bytes, next)? as i64)])
                }
                0xAD => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Raw("shrd".to_string()), vec![rm, Operand::Reg(r), Operand::Reg(Register::Cl)])
                }
                0xB0 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, OperandSize::Byte, OperandSize::Byte)?;
                    (Mnemonic::Cmpxchg, vec![rm, Operand::Reg(r)])
                }
                0xB1 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Cmpxchg, vec![rm, Operand::Reg(r)])
                }
                0xC0 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, OperandSize::Byte, OperandSize::Byte)?;
                    (Mnemonic::Xadd, vec![rm, Operand::Reg(r)])
                }
                0xC1 => {
                    let (r, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                    (Mnemonic::Xadd, vec![rm, Operand::Reg(r)])
                }
                0xC7 if inner_pos < bytes.len() => {
                    let rf = (bytes[inner_pos] >> 3) & 7;
                    if rf == 1 {
                        let (_, rm, _) = decode_modrm(bytes, inner_pos, ctx, rex, op_size, op_size)?;
                        (Mnemonic::Cmpxchg8b, vec![rm])
                    } else {
                        (Mnemonic::Unknown, vec![])
                    }
                }
                _ => (Mnemonic::Unknown, vec![]),
            }
        }

        _ => (Mnemonic::Unknown, vec![]),
    })
}

fn str_op(ctx: Ctx, rex_w: bool, p66: bool, variants: (Mnemonic, Mnemonic, Mnemonic)) -> (Mnemonic, Vec<Operand>) {
    // variants are (word, dword, qword) forms: 16-bit mode defaults to word.
    let word = if ctx.is_16 { !p66 } else { p66 };
    let m = if ctx.is_64 && rex_w {
        variants.2
    } else if word {
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
fn read_moffs(code: &[u8], pos: usize, ctx: Ctx, rex_w: bool, op_size: OperandSize) -> Result<(i64, OperandSize), DecodeError> {
    // moffs address width follows the *address* size: 16-bit -> 2 bytes,
    // REX.W in long mode -> 8 bytes, otherwise 4. The operand size rides
    // along separately (this also fixes 0x66 A0-A3 in 32-bit mode, which
    // previously miscounted the address as 2 bytes).
    let n = if ctx.addr16 {
        2usize
    } else if rex_w && ctx.is_64 {
        8usize
    } else {
        4usize
    };
    if pos + n > code.len() { return Err(DecodeError::TooShort); }
    let mut v: u64 = 0;
    for i in 0..n {
        v |= (code[pos + i] as u64) << (i * 8);
    }
    Ok((v as i64, op_size))
}

/// Immediate sized by the effective operand width: 16-bit when op16,
/// else 32-bit. (REX.W does not widen these forms; B8-BF is handled
/// separately with read_i64.)
fn read_imm_opsize(code: &[u8], pos: usize, ctx: Ctx) -> Result<i64, DecodeError> {
    if ctx.op16 {
        read_u16(code, pos).map(|v| v as i64)
    } else {
        read_i32(code, pos).map(|v| v as i64)
    }
}

/// Branch displacement sized like the operand width: rel16 in 16-bit mode,
/// rel32 otherwise (0x66 toggles in both directions).
fn read_rel_opsize(code: &[u8], pos: usize, ctx: Ctx) -> Result<i32, DecodeError> {
    if ctx.op16 {
        read_u16(code, pos).map(|v| v as i16 as i32)
    } else {
        read_i32(code, pos)
    }
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

pub(crate) fn reg_for_index(idx: u8, rex_ext: bool, size: OperandSize) -> Register {
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
pub(crate) fn decode_modrm(
    code: &[u8], pos: usize, ctx: Ctx, rex: Option<RexPrefix>,
    reg_size: OperandSize, rm_size: OperandSize,
) -> Result<(Register, Operand, usize), DecodeError> {
    if pos >= code.len() { return Err(DecodeError::TooShort); }
    let modrm = code[pos];
    let r#mod = (modrm >> 6) & 3;
    let reg_f = (modrm >> 3) & 7;
    let rm = modrm & 7;

    let is_64 = ctx.is_64;
    let rex_r = rex.is_some_and(|r| r.r);
    let rex_b = rex.is_some_and(|r| r.b);
    let rex_x = rex.is_some_and(|r| r.x);
    let rex_present = rex.is_some();

    let reg_operand = pick_reg(reg_f, rex_r, reg_size, rex_present);
    let mut next_pos = pos + 1;

    // 16-bit addressing: no SIB, distinct r/m mapping with disp16.
    if ctx.addr16 && r#mod != 3 {
        return Ok((reg_operand, decode_modrm16(code, &mut next_pos, r#mod, rm, rm_size)?, next_pos));
    }

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

/// 16-bit ModR/M addressing (no SIB).
/// r/m map: 0 BX+SI, 1 BX+DI, 2 BP+SI, 3 BP+DI, 4 SI, 5 DI, 6 BP(disp16 if mod==0), 7 BX.
fn decode_modrm16(
    code: &[u8], next_pos: &mut usize, r#mod: u8, rm: u8, rm_size: OperandSize,
) -> Result<Operand, DecodeError> {
    use Register::*;
    let (base, index) = match rm {
        0 => (Some(Bx), Some(Si)),
        1 => (Some(Bx), Some(Di)),
        2 => (Some(Bp), Some(Si)),
        3 => (Some(Bp), Some(Di)),
        4 => (Some(Si), None),
        5 => (Some(Di), None),
        6 if r#mod != 0 => (Some(Bp), None),
        7 => (Some(Bx), None),
        _ => (None, None), // rm==6, mod==0: disp16-only
    };
    let mut disp: i64 = 0;
    match r#mod {
        0 if rm == 6 => {
            disp = read_u16(code, *next_pos)? as i64;
            *next_pos += 2;
        }
        1 => {
            disp = read_i8(code, *next_pos)? as i64;
            *next_pos += 1;
        }
        2 => {
            disp = read_u16(code, *next_pos)? as i64;
            *next_pos += 2;
        }
        _ => {}
    }
    Ok(Operand::Mem(MemOperand {
        base, index, scale: 1, displacement: disp,
        segment: None, size: rm_size,
    }))
}

/// ModR/M group instruction: reg field selects the operation.
fn modrm_group(
    code: &[u8], pos: usize, ctx: Ctx, rex: Option<RexPrefix>, op_size: OperandSize,
) -> Result<(u8, Operand, usize), DecodeError> {
    if pos >= code.len() { return Err(DecodeError::TooShort); }
    let reg_field = (code[pos] >> 3) & 7;
    let (_, operand, next_pos) = decode_modrm(code, pos, ctx, rex, op_size, op_size)?;
    Ok((reg_field, operand, next_pos))
}

// ---- Helpers for newly-added families ----

fn setcc_mnemonic(cc: u8) -> Mnemonic {
    let s = match cc {
        0 => "seto", 1 => "setno", 2 => "setb", 3 => "setae",
        4 => "sete", 5 => "setne", 6 => "setbe", 7 => "seta",
        8 => "sets", 9 => "setns", 0xA => "setp", 0xB => "setnp",
        0xC => "setl", 0xD => "setge", 0xE => "setle", 0xF => "setg",
        _ => "setcc",
    };
            Mnemonic::Raw(s.to_string())
}

fn seg_reg(idx: u8) -> Register {
    match idx & 7 {
        0 => Register::Es, 1 => Register::Cs, 2 => Register::Ss,
        3 => Register::Ds, 4 => Register::Fs, 5 => Register::Gs,
        _ => Register::Ds,
    }
}

// ---- x87 FPU ----

fn fpu_mem_size(opcode: u8, reg: u8) -> OperandSize {
    match opcode {
        0xD8..=0xDB => {
            if opcode == 0xDB && (reg == 5 || reg == 7) { OperandSize::Qword } else { OperandSize::Dword }
        }
        0xDC | 0xDD => OperandSize::Qword,
        0xDE => OperandSize::Word,
        0xDF => if reg == 5 || reg == 7 { OperandSize::Tbyte } else { OperandSize::Word },
        _ => OperandSize::Dword,
    }
}

fn fpu_mem(opcode: u8, reg: u8, mem: Operand) -> Option<(String, Vec<Operand>)> {
    let s = match (opcode, reg) {
        (0xD8, 0) => "fadd", (0xD8, 1) => "fmul", (0xD8, 2) => "fcom", (0xD8, 3) => "fcomp",
        (0xD8, 4) => "fsub", (0xD8, 5) => "fsubr", (0xD8, 6) => "fdiv", (0xD8, 7) => "fdivr",
        (0xDC, 0) => "fadd", (0xDC, 1) => "fmul", (0xDC, 2) => "fcom", (0xDC, 3) => "fcomp",
        (0xDC, 4) => "fsub", (0xDC, 5) => "fsubr", (0xDC, 6) => "fdiv", (0xDC, 7) => "fdivr",
        (0xDA, 0) => "fiadd", (0xDA, 1) => "fimul", (0xDA, 2) => "ficom", (0xDA, 3) => "ficomp",
        (0xDA, 4) => "fisub", (0xDA, 5) => "fisubr", (0xDA, 6) => "fidiv", (0xDA, 7) => "fidivr",
        (0xDE, 0) => "fiadd", (0xDE, 1) => "fimul", (0xDE, 2) => "ficom", (0xDE, 3) => "ficomp",
        (0xDE, 4) => "fisub", (0xDE, 5) => "fisubr", (0xDE, 6) => "fidiv", (0xDE, 7) => "fidivr",
        (0xD9, 0) => "fld", (0xD9, 2) => "fst", (0xD9, 3) => "fstp",
        (0xD9, 4) => "fldenv", (0xD9, 5) => "fstenv", (0xD9, 6) => "fsave", (0xD9, 7) => "fstcw",
        (0xDB, 0) => "fild", (0xDB, 2) => "fist", (0xDB, 3) => "fistp", (0xDB, 5) => "fild", (0xDB, 7) => "fistp",
        (0xDD, 0) => "fld", (0xDD, 2) => "fst", (0xDD, 3) => "fstp", (0xDD, 1) => "frstor", (0xDD, 6) => "fsave", (0xDD, 7) => "fstsw",
        (0xDF, 0) => "fild", (0xDF, 2) => "fist", (0xDF, 3) => "fistp", (0xDF, 5) => "fbld", (0xDF, 7) => "fbstp",
        _ => return None,
    };
    Some((s.to_string(), vec![mem]))
}

fn fpu_reg3(opcode: u8, reg: u8, rm: u8) -> Option<(String, Vec<Operand>)> {
    let st_i = Operand::Reg(Register::St(rm));
    let st_0 = Operand::Reg(Register::St(0));
    let bin = |s: &str| Some((s.to_string(), vec![st_0.clone(), st_i.clone()]));
    let un = |s: &str| Some((s.to_string(), vec![st_i.clone()]));
    match (opcode, reg) {
        (0xD8, 0) => bin("fadd"), (0xD8, 1) => bin("fmul"), (0xD8, 2) => un("fcom"),
        (0xD8, 3) => un("fcomp"), (0xD8, 4) => bin("fsub"), (0xD8, 5) => bin("fsubr"),
        (0xD8, 6) => bin("fdiv"), (0xD8, 7) => bin("fdivr"),
        (0xD9, 0) => un("fld"), (0xD9, 1) => un("fxch"), (0xD9, 2) => un("fst"),
        (0xD9, 3) => un("fstp"), (0xD9, 4) => un("fnop"), (0xD9, 5) => un("fchs"),
        (0xD9, 6) => un("fabs"), (0xD9, 7) => un("fstp"),
        (0xDA, 0) => bin("fcmovb"), (0xDA, 1) => bin("fcmove"), (0xDA, 2) => bin("fcmovbe"),
        (0xDA, 3) => bin("fcmovu"), (0xDA, 5) => bin("fucompp"),
        (0xDB, 0) => bin("fcmovnb"), (0xDB, 1) => bin("fcmovne"), (0xDB, 2) => bin("fcmovnbe"),
        (0xDB, 3) => bin("fcmovnu"),
        (0xDC, 0) => bin("faddp"), (0xDC, 1) => bin("fmulp"), (0xDC, 4) => bin("fsubp"),
        (0xDC, 5) => bin("fsubrp"), (0xDC, 6) => bin("fdivp"), (0xDC, 7) => bin("fdivrp"),
        (0xDD, 0) => un("ffree"), (0xDD, 2) => un("fst"), (0xDD, 3) => un("fstp"),
        (0xDD, 4) => un("fucom"), (0xDD, 5) => un("fucomp"),
        (0xDE, 0) => bin("faddp"), (0xDE, 1) => bin("fmulp"), (0xDE, 4) => bin("fsubp"),
        (0xDE, 5) => bin("fsubrp"), (0xDE, 6) => bin("fdivp"), (0xDE, 7) => bin("fdivrp"),
        (0xDF, 0) => un("ffreep"), (0xDF, 4) => bin("fucomip"), (0xDF, 5) => bin("fcomip"),
        _ => None,
    }
}

fn decode_fpu(opcode: u8, bytes: &[u8], pos: usize, ctx: Ctx) -> Result<(Mnemonic, Vec<Operand>), DecodeError> {
    if pos >= bytes.len() { return Err(DecodeError::TooShort); }
    let modrm = bytes[pos];
    let r#mod = (modrm >> 6) & 3;
    let reg = (modrm >> 3) & 7;
    let rm = modrm & 7;
    let mem_size = fpu_mem_size(opcode, reg);
    let (name, operands) = if r#mod == 3 {
        match fpu_reg3(opcode, reg, rm) {
            Some(x) => x,
            None => return Ok((Mnemonic::Unknown, vec![])),
        }
    } else {
        let (_, m, _) = decode_modrm(bytes, pos, ctx, None, mem_size, mem_size)?;
        let m = match m { Operand::Mem(mut mm) => { mm.size = mem_size; Operand::Mem(mm) }, _ => unreachable!() };
        match fpu_mem(opcode, reg, m) {
            Some(x) => x,
            None => return Ok((Mnemonic::Unknown, vec![])),
        }
    };
    Ok((Mnemonic::Raw(name.to_string()), operands))
}

// ---- VEX (AVX/AVX2) ----

fn decode_vex(opcode: u8, bytes: &[u8], pos: usize, _is_64: bool) -> Result<(Mnemonic, Vec<Operand>), DecodeError> {
    // `pos` points just past the leading VEX opcode (0xC4/0xC5).
    // C5: [opcode, b1,     op, modrm]
    // C4: [opcode, b1, b2, op, modrm]
    let (op, map, pp, w, r_bit, x_bit, b_bit, vvvv, vl, modrm_pos) = if opcode == 0xC5 {
        let b1 = *bytes.get(pos).ok_or(DecodeError::TooShort)?;
        let op = *bytes.get(pos + 1).ok_or(DecodeError::TooShort)?;
        ( op, 0u8, b1 & 3, false,
          ((b1 >> 7) & 1) == 0, false, false,
          ((b1 >> 3) & 7) ^ 7, (b1 >> 2) & 1, pos + 2 )
    } else {
        let b1 = *bytes.get(pos).ok_or(DecodeError::TooShort)?;
        let b2 = *bytes.get(pos + 1).ok_or(DecodeError::TooShort)?;
        let mmmmm = b1 & 0x1F;
        if mmmmm == 0 { return Ok((Mnemonic::Unknown, vec![])); }
        let op = *bytes.get(pos + 2).ok_or(DecodeError::TooShort)?;
        ( op, mmmmm - 1, b2 & 3, (b2 >> 7) & 1 != 0,
          ((b1 >> 7) & 1) == 0, ((b1 >> 6) & 1) == 0, ((b1 >> 5) & 1) == 0,
          ((b2 >> 3) & 7) ^ 7, (b2 >> 2) & 1, pos + 3 )
    };
    if op == 0x77 && map == 0 {
        let name = if vl == 1 { "vzeroall" } else { "vzeroupper" };
        return Ok((Mnemonic::Raw(name.to_string()), vec![]));
    }
    let st = crate::simd::SimdState { map, pp, w, vl, vvvv: Some(vvvv), r_bit, x_bit, b_bit, evex: false, mask: None };
    match crate::simd::decode_simd(&st, bytes, modrm_pos - 1, ctx64()) {
        Some(r) => Ok(r),
        None => Ok((Mnemonic::Unknown, vec![])),
    }
}

// ---- EVEX (AVX-512) ----
// `pos` points just past the leading 0x62 byte:
// [opcode, p0, p1, p2, op, modrm]

fn decode_evex(bytes: &[u8], pos: usize, _is_64: bool) -> Result<(Mnemonic, Vec<Operand>), DecodeError> {
    let p0 = *bytes.get(pos).ok_or(DecodeError::TooShort)?;
    let p1 = *bytes.get(pos + 1).ok_or(DecodeError::TooShort)?;
    let p2 = *bytes.get(pos + 2).ok_or(DecodeError::TooShort)?;
    let _op = *bytes.get(pos + 3).ok_or(DecodeError::TooShort)?;
    let modrm_pos = pos + 4;
    let mmmmm = p0 & 7;
    let map = mmmmm;
    let r_bit = ((p0 >> 7) & 1) == 0;
    let x_bit = ((p0 >> 6) & 1) == 0;
    let b_bit = ((p0 >> 5) & 1) == 0;
    let w = (p1 >> 7) & 1 != 0;
    let pp = p1 & 3;
    let vlow = (p1 >> 3) & 7;
    let vhigh = (p2 >> 7) & 1;
    let vvvv = (vlow ^ 7) | (((vhigh ^ 1) & 1) << 3);
    let vl = (p2 >> 2) & 3;
    let aaa = p2 & 7;
    let st = crate::simd::SimdState { map, pp, w, vl, vvvv: Some(vvvv), r_bit, x_bit, b_bit, evex: true, mask: Some(aaa) };
    match crate::simd::decode_simd(&st, bytes, modrm_pos - 1, ctx64()) {
        Some(r) => Ok(r),
        None => Ok((Mnemonic::Unknown, vec![])),
    }
}

