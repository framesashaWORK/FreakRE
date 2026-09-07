//! Length Disassembler (LDE) for x86/x64.
//! Returns instruction length without full decode. Fast path for CFG building.

use crate::types::{DecodeError, Mode};

const MAX_INSN_LEN: usize = 15;

/// Decode instruction length only. Returns Err on malformed input.
pub fn decode_len(code: &[u8], mode: Mode) -> Result<usize, DecodeError> {
    if code.is_empty() {
        return Err(DecodeError::TooShort);
    }

    let mut pos = 0usize;
    let mut has_66 = false;
    let mut has_67 = false;
    let is_64 = mode == Mode::X64;
    let is_16 = mode == Mode::X16;

    // Skip legacy prefixes
    loop {
        if pos >= code.len() || pos >= MAX_INSN_LEN {
            return Err(if pos >= MAX_INSN_LEN {
                DecodeError::MaxLengthExceeded
            } else {
                DecodeError::TooShort
            });
        }
        match code[pos] {
            0xF0 | 0xF2 | 0xF3 => {
                pos += 1;
            } // LOCK, REPNE, REP
            0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                pos += 1;
            } // CS, SS, DS, ES, FS, GS
            0x66 => {
                has_66 = true;
                pos += 1;
            } // Operand size override
            0x67 => {
                has_67 = true;
                pos += 1;
            } // Address size override
            _ => break,
        }
    }

    // 16-bit effective address/operand widths (0x66/0x67 toggle each way).
    let addr16 = match mode {
        Mode::X16 => !has_67,
        Mode::X86 => has_67,
        Mode::X64 => false,
    };
    let op16 = if is_16 { !has_66 } else { has_66 };
    // Branch displacement width follows the operand width.
    let rel_size: usize = if op16 { 2 } else { 4 };
    // Group-1/imul/mov-imm width (REX.W only widens B8-BF below).
    let grp_imm: usize = if op16 { 2 } else { 4 };

    // REX prefix (64-bit only; in 16/32-bit 0x40-0x4F are inc/dec)
    let has_rex_w = if is_64 && pos < code.len() && (code[pos] & 0xF0) == 0x40 {
        let rex_w = (code[pos] & 0x08) != 0;
        pos += 1;
        rex_w
    } else {
        false
    };

    if pos >= code.len() {
        return Err(DecodeError::TooShort);
    }

    let opcode = code[pos];
    pos += 1;

    // Two-byte opcode escape
    let (opcode, _two_byte) = if opcode == 0x0F {
        if pos >= code.len() {
            return Err(DecodeError::TooShort);
        }
        let op2 = code[pos];
        pos += 1;

        // Three-byte opcode
        if op2 == 0x38 || op2 == 0x3A {
            if pos >= code.len() {
                return Err(DecodeError::TooShort);
            }
            pos += 1; // skip third opcode byte
            if op2 == 0x3A {
                // 3-byte + imm8
                return read_modrm_and_disp(code, pos, addr16).map(|mr| pos + mr + 1);
            }
            return read_modrm_and_disp(code, pos, addr16).map(|mr| pos + mr);
        }

        let len = two_byte_tail_len(code, pos, op2, addr16, rel_size)?;
        if len > code.len() {
            return Err(DecodeError::TooShort);
        }
        return Ok(len);
    } else {
        (opcode, false)
    };

    // VEX/EVEX prefix in 64-bit mode (C4/C5 are not LES/LDS there, 62 is EVEX)
    if is_64 && (opcode == 0xC4 || opcode == 0xC5 || opcode == 0x62) {
        let len = if opcode == 0x62 {
            evex_len(code, pos - 1)?
        } else {
            vex_len(code, pos - 1, opcode)?
        };
        if len > code.len() {
            return Err(DecodeError::TooShort);
        }
        return Ok(len);
    }

    // FPU D8-DF: all have ModR/M, no immediate (except D8-DF with mod==3 may be FPU reg)
    if (0xD8..=0xDF).contains(&opcode) {
        return read_modrm_and_disp(code, pos, addr16).map(|mr| pos + mr);
    }

    // One-byte opcodes
    let has_modrm = matches!(opcode,
        0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B |
        0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B |
        0x62 | 0x63 | 0x69 | 0x6B |
        0x80..=0x8F | 0xC0..=0xC1 | 0xC4..=0xC7 |
        0xD0..=0xD3 | 0xD8..=0xDF |
        0xF6..=0xF7 | 0xFE..=0xFF
    );

    let imm_size: usize = match opcode {
         0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | // AL, imm8
         0x80 | 0x82 | 0x83 | 0xC0 | 0xC1 | 0xC6 | 0xCD | 0xD4 | 0xD5 |
         0x6B | 0xA8 | // imul r,rm,imm8; test al,imm8
         0xEB |
         0x70..=0x7F | // short jumps
         0xE0..=0xE3 | // loop/loope/loopne/jcxz rel8
         0xB0..=0xB7 => 1, // mov reg8, imm8

        // mov al/ax/eax/rax, moffs — sized by *address* size:
        // 16-bit → 2, REX.W in long mode → 8, otherwise 4.
        0xA0..=0xA3 => if addr16 { 2 } else if has_rex_w && is_64 { 8 } else { 4 },

        // Operand-width immediates: 2 bytes when op16, else 4.
        // (0x68 push imm is imm32 even with REX.W in long mode.)
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D |
        0x68 | 0x69 | 0x81 | 0xC7 |
        0xA9 | 0xE8 | 0xE9 => grp_imm,

        0xB8..=0xBF => if has_rex_w && is_64 { 8 } else { grp_imm }, // mov reg, imm

        // Far jmp/call: invalid in long mode, ptr16:16 (5B) / ptr16:32 (7B).
        0xEA | 0x9A => {
            if is_64 {
                return Err(DecodeError::InvalidOpcode);
            }
            return Ok(pos + if is_16 { 4 } else { 6 });
        }

        _ => 0,
    };

    // Fix: some opcodes above overlap, handle special cases
    let imm_size = match opcode {
        0xC2 | 0xCA => 2,
        0xC8 => 3,
        0x6A => 1,
        0x68 => grp_imm,
        0xA0..=0xA3 => {
            if addr16 {
                2
            } else if has_rex_w && is_64 {
                8
            } else {
                4
            }
        }
        0xB8..=0xBF => {
            if has_rex_w && is_64 {
                8
            } else {
                grp_imm
            }
        }
        _ => imm_size,
    };

    let len = if has_modrm {
        // F6/F7 /0 and /1 are TEST r/m, imm forms with a trailing immediate
        let extra_imm = if opcode == 0xF6 || opcode == 0xF7 {
            if pos < code.len() && (code[pos] >> 3) & 7 <= 1 {
                if opcode == 0xF6 {
                    1
                } else {
                    grp_imm
                }
            } else {
                0
            }
        } else {
            0
        };
        pos + read_modrm_and_disp(code, pos, addr16)? + imm_size + extra_imm
    } else {
        pos + imm_size
    };
    if len > code.len() {
        return Err(DecodeError::TooShort);
    }
    Ok(len)
}

/// Two-byte (0F xx / VEX.map1) tail: ModR/M presence + immediate.
/// Returns total bytes consumed from `pos` (which points past the op2 byte).
fn two_byte_tail_len(
    code: &[u8],
    pos: usize,
    op2: u8,
    addr16: bool,
    rel_size: usize,
) -> Result<usize, DecodeError> {
    let has_modrm = matches!(op2,
         0x00..=0x01 | 0x0D | 0x10..=0x19 | 0x1F |
         0x20..=0x23 | 0x28..=0x2F | 0x36..=0x37 | 0x3F |
         0x40..=0x4F | 0x50..=0x76 | 0x78..=0x7F | 0x90..=0x9F | 0xA3..=0xA7 |
         0xAB..=0xB7 | 0xBA..=0xBF |
         0xC0..=0xC7 | 0xD0..=0xFF
    );

    let imm_size = match op2 {
        0x70..=0x73 => 1,        // pshuf* etc
        0x80..=0x8F => rel_size, // jcc rel16/rel32
        0xA4 | 0xAC => 1,        // shld/shrd imm8
        0xBA => 1,               // bt/bts/btr/btc imm8
        0xC2 => 1,               // cmpps imm8
        0xC4..=0xC6 => 1,        // pinsrw/pextrw/shufps imm8
        _ => 0,
    };

    if has_modrm {
        Ok(pos + read_modrm_and_disp(code, pos, addr16)? + imm_size)
    } else {
        Ok(pos + imm_size)
    }
}

/// VEX-encoded instruction length. `vex_pos` points at the C4/C5 byte.
///
/// Layouts:
///   C5 vb1 opcode      [modrm][sib][disp][imm]   — implied map 1 (0F)
///   C4 b1 b2 opcode    [modrm][sib][disp][imm]
///     b1[1:0]: map select — 0: invalid, 1: 0F, 2: 0F38, 3: 0F3A (+imm8)
fn vex_len(code: &[u8], vex_pos: usize, vex_byte: u8) -> Result<usize, DecodeError> {
    const TOO_SHORT: DecodeError = DecodeError::TooShort;
    if vex_byte == 0xC5 {
        let _vb1 = *code.get(vex_pos + 1).ok_or(TOO_SHORT)?;
        let op2 = *code.get(vex_pos + 2).ok_or(TOO_SHORT)?;
        two_byte_tail_len(code, vex_pos + 3, op2, false, 4)
    } else {
        let b1 = *code.get(vex_pos + 1).ok_or(TOO_SHORT)?;
        let _b2 = *code.get(vex_pos + 2).ok_or(TOO_SHORT)?;
        let op3 = *code.get(vex_pos + 3).ok_or(TOO_SHORT)?;
        match b1 & 0x03 {
            0 => Err(DecodeError::InvalidOpcode),
            1 => two_byte_tail_len(code, vex_pos + 4, op3, false, 4),
            2 => {
                // 0F38: all have ModR/M, no immediates in practice
                read_modrm_and_disp(code, vex_pos + 4, false).map(|mr| vex_pos + 4 + mr)
            }
            _ => {
                // 0F3A: all have ModR/M + imm8
                read_modrm_and_disp(code, vex_pos + 4, false).map(|mr| vex_pos + 5 + mr)
            }
        }
    }
}

/// EVEX-encoded instruction length (62 + P0 P1 P2 + opcode).
fn evex_len(code: &[u8], evex_pos: usize) -> Result<usize, DecodeError> {
    const TOO_SHORT: DecodeError = DecodeError::TooShort;
    let _p0 = *code.get(evex_pos + 1).ok_or(TOO_SHORT)?;
    let _p1 = *code.get(evex_pos + 2).ok_or(TOO_SHORT)?;
    let _p2 = *code.get(evex_pos + 3).ok_or(TOO_SHORT)?;
    let op = *code.get(evex_pos + 4).ok_or(TOO_SHORT)?;
    // EVEX map lives in P0[4:3] + P1[1:0], but length only needs
    // opcode + ModR/M + disp + imm. For 0F38/0F3A maps same as VEX,
    // for the 0F map use two_byte_tail.
    // Most EVEX are 0F/0F38/0F3A with ModR/M
    if op == 0x38 || op == 0x3A {
        // Should not happen as EVEX op is after prefix, but handle
        return Ok(evex_pos + 5);
    }
    // Use two_byte_tail for 0F map, else ModR/M
    // For now, assume all EVEX have ModR/M
    let tail = two_byte_tail_len(code, evex_pos + 5, op, false, 4).unwrap_or(evex_pos + 5 + 1);
    // two_byte_tail already includes ModR/M, but we need to ensure we don't double count
    // Fallback to simple ModR/M
    if tail > code.len() {
        read_modrm_and_disp(code, evex_pos + 5, false).map(|mr| evex_pos + 5 + mr)
    } else {
        Ok(tail)
    }
}

/// Read ModR/M + optional SIB + displacement. Returns total bytes consumed.
fn read_modrm_and_disp(code: &[u8], pos: usize, addr16: bool) -> Result<usize, DecodeError> {
    if pos >= code.len() {
        return Err(DecodeError::TooShort);
    }

    let modrm = code[pos];
    let r#mod = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let mut consumed = 1usize;

    // 16-bit addressing: no SIB; disp16 instead of disp32.
    if addr16 {
        let disp_size = match r#mod {
            0 => {
                if rm == 6 {
                    2
                } else {
                    0
                }
            } // disp16-only
            1 => 1, // disp8
            2 => 2, // disp16
            _ => 0, // mod == 3: register direct
        };
        consumed += disp_size;
        if pos + consumed > code.len() {
            return Err(DecodeError::TooShort);
        }
        if pos + consumed > MAX_INSN_LEN {
            return Err(DecodeError::MaxLengthExceeded);
        }
        return Ok(consumed);
    }

    // SIB byte needed when mod != 3 and rm == 4
    if r#mod != 3 && rm == 4 {
        if pos + consumed >= code.len() {
            return Err(DecodeError::TooShort);
        }
        let sib = code[pos + consumed];
        consumed += 1;
        let base = sib & 0x07;
        // If base == 5 and mod == 0, there's a disp32
        if base == 5 && r#mod == 0 {
            consumed += 4;
        }
    }

    // Displacement
    let disp_size = match r#mod {
        0 => {
            if rm == 5 {
                4 // RIP-relative or disp32
            } else {
                0
            }
        }
        1 => 1,
        2 => 4,
        _ => 0, // mod == 3: register direct, no displacement
    };

    consumed += disp_size;

    if pos + consumed > code.len() {
        return Err(DecodeError::TooShort);
    }
    if pos + consumed > MAX_INSN_LEN {
        return Err(DecodeError::MaxLengthExceeded);
    }

    Ok(consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop() {
        assert_eq!(decode_len(&[0x90], Mode::X64).unwrap(), 1);
    }

    #[test]
    fn test_ret() {
        assert_eq!(decode_len(&[0xC3], Mode::X64).unwrap(), 1);
    }

    #[test]
    fn test_mov_reg_imm32() {
        // mov eax, 0x12345678
        assert_eq!(
            decode_len(&[0xB8, 0x78, 0x56, 0x34, 0x12], Mode::X64).unwrap(),
            5
        );
    }

    #[test]
    fn test_rex_mov_r64_imm64() {
        // REX.W mov rax, imm64
        assert_eq!(
            decode_len(&[0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0], Mode::X64).unwrap(),
            10
        );
    }

    #[test]
    fn test_push_rbp() {
        assert_eq!(decode_len(&[0x55], Mode::X64).unwrap(), 1);
    }

    #[test]
    fn test_sub_rsp_imm8() {
        // sub rsp, 0x28 → REX.W 0x83 0xEC 0x28
        assert_eq!(decode_len(&[0x48, 0x83, 0xEC, 0x28], Mode::X64).unwrap(), 4);
    }

    #[test]
    fn test_too_short() {
        assert!(decode_len(&[], Mode::X64).is_err());
        assert!(decode_len(&[0x0F], Mode::X64).is_err());
    }
}
