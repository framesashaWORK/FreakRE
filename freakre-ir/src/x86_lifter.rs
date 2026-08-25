use crate::ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

pub struct X86Lifter {
    is_64bit: bool,
    max_instructions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AluKind {
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
}

fn alu_kind(opcode: u8) -> AluKind {
    match opcode >> 3 {
        0 => AluKind::Add,
        1 => AluKind::Or,
        2 => AluKind::Adc,
        3 => AluKind::Sbb,
        4 => AluKind::And,
        5 => AluKind::Sub,
        6 => AluKind::Xor,
        _ => AluKind::Cmp,
    }
}

/// GRP1 (0x80/0x81/0x83) encodes the ALU operation in the ModRM reg field.
fn grp1_kind(reg_field: u8) -> AluKind {
    match reg_field {
        0 => AluKind::Add,
        1 => AluKind::Or,
        2 => AluKind::Adc,
        3 => AluKind::Sbb,
        4 => AluKind::And,
        5 => AluKind::Sub,
        6 => AluKind::Xor,
        _ => AluKind::Cmp,
    }
}

fn int_ty(bits: u32) -> Ty {
    match bits {
        8 => Ty::i8(),
        16 => Ty::i16(),
        32 => Ty::i32(),
        _ => Ty::i64(),
    }
}

fn reg_name(idx: u8, bits: u32, has_rex: bool) -> String {
    let i = (idx & 0x0F) as usize;
    match bits {
        64 => {
            if i < 8 {
                ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][i].to_string()
            } else {
                format!("r{}", i)
            }
        }
        16 => {
            if i < 8 {
                ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][i].to_string()
            } else {
                format!("r{}w", i)
            }
        }
        8 => {
            if i < 8 {
                if has_rex {
                    ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"][i].to_string()
                } else {
                    ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][i].to_string()
                }
            } else {
                format!("r{}b", i)
            }
        }
        _ => {
            if i < 8 {
                ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][i].to_string()
            } else {
                format!("r{}d", i)
            }
        }
    }
}

fn reg_value(idx: u8, bits: u32, has_rex: bool) -> Value {
    Value::Register {
        name: reg_name(idx, bits, has_rex),
        ty: int_ty(bits),
    }
}

/// Opaque 128-bit XMM register value (SSE register file).
fn xmm_value(idx: u8) -> Value {
    Value::Register {
        name: format!("xmm{}", idx),
        ty: Ty::Unknown,
    }
}

/// How a narrow register write maps onto its widest enclosing parent.
struct SubregWrite {
    /// Parent GPR index (0=rax/eax .. 15=r15).
    parent_idx: u8,
    /// Bit offset of the aliased field inside the parent.
    offset: u32,
    /// Width of the aliased field in bits.
    width: u32,
    /// True when the write clears every bit above the field (32-bit views
    /// in 64-bit mode zero-extend); false when upper bits are preserved.
    zero_high: bool,
}

/// Alias table for nested x86 registers (al/ah/ax/eax/... → widest parent).
///
/// Writes to narrow views are canonicalized through `write_reg` as a
/// read-modify-write of the parent so narrow writes stay visible to wider
/// reads instead of disappearing into an independent variable.
fn subreg_write(name: &str, bits: u32, is_64bit: bool) -> Option<SubregWrite> {
    // Byte/word views share the fixed GPR numbering (ah/ch/dh/bh sit at
    // bits 8..16 of eax/ecx/edx/ebx).
    let byte_word: Option<(u8, u32)> = match name {
        "al" | "ax" => Some((0, 0)),
        "cl" | "cx" => Some((1, 0)),
        "dl" | "dx" => Some((2, 0)),
        "bl" | "bx" => Some((3, 0)),
        "spl" | "sp" => Some((4, 0)),
        "bpl" | "bp" => Some((5, 0)),
        "sil" | "si" => Some((6, 0)),
        "dil" | "di" => Some((7, 0)),
        "ah" => Some((0, 8)),
        "ch" => Some((1, 8)),
        "dh" => Some((2, 8)),
        "bh" => Some((3, 8)),
        _ => None,
    };
    if let Some((idx, off)) = byte_word {
        return Some(SubregWrite { parent_idx: idx, offset: off, width: bits, zero_high: false });
    }
    if !is_64bit {
        // 32-bit mode: the e-names already are the widest view.
        return None;
    }
    const LEGACY32: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    if let Some(idx) = LEGACY32.iter().position(|&n| n == name) {
        return Some(SubregWrite { parent_idx: idx as u8, offset: 0, width: 32, zero_high: true });
    }
    // Extended registers: r8b/r8w/r8d alias r8.
    let rest = name.strip_prefix('r')?;
    let split = rest.find(|c: char| !c.is_ascii_digit())?;
    if split == 0 {
        return None;
    }
    let idx: u8 = rest[..split].parse().ok()?;
    if !(8..=15).contains(&idx) {
        return None;
    }
    match &rest[split..] {
        "b" => Some(SubregWrite { parent_idx: idx, offset: 0, width: 8, zero_high: false }),
        "w" => Some(SubregWrite { parent_idx: idx, offset: 0, width: 16, zero_high: false }),
        "d" => Some(SubregWrite { parent_idx: idx, offset: 0, width: 32, zero_high: true }),
        _ => None,
    }
}

fn decode_modrm(modrm: u8) -> (u8, u8, u8) {
    ((modrm >> 6) & 0x03, (modrm >> 3) & 0x07, modrm & 0x07)
}

fn ext(flag: bool) -> u8 {
    u8::from(flag) * 8
}

fn trunc_err(addr: u64) -> LifterError {
    LifterError::InvalidInstruction(addr, "truncated instruction".into())
}

fn imm_at(code: &[u8], off: usize, n: usize) -> Option<i64> {
    if code.len() < off + n {
        return None;
    }
    let mut v: i64 = 0;
    for k in 0..n {
        v |= (code[off + k] as i64) << (8 * k);
    }
    let sign_bit = 1i64 << (8 * n - 1);
    if v & sign_bit != 0 {
        Some(v - (1i64 << (8 * n)))
    } else {
        Some(v)
    }
}

fn zext_at(code: &[u8], off: usize, n: usize) -> Option<i64> {
    if code.len() < off + n {
        return None;
    }
    let mut v: i64 = 0;
    for k in 0..n {
        v |= (code[off + k] as i64) << (8 * k);
    }
    Some(v)
}

fn read_disp8(code: &[u8], off: usize) -> i64 {
    code.get(off).map(|b| *b as i8 as i64).unwrap_or(0)
}

fn read_i32(code: &[u8], off: usize) -> i64 {
    if code.len() >= off + 4 {
        i32::from_le_bytes([code[off], code[off + 1], code[off + 2], code[off + 3]]) as i64
    } else {
        0
    }
}

fn mem_operand_len(modrm: u8, after: &[u8]) -> usize {
    let (m, _, rm) = decode_modrm(modrm);
    if m == 3 {
        return 1;
    }
    let mut n = 1usize;
    let sib_present = rm == 4;
    let sib_usable = sib_present && !after.is_empty();
    if sib_present {
        n += 1;
    }
    let sib_base5 = sib_usable && (after[0] & 0x07) == 5;
    n += match m {
        1 => 1,
        2 => 4,
        0 if (!sib_present && rm == 5) || sib_base5 => 4,
        _ => 0,
    };
    n
}

fn push_bin(func: &mut IrFunction, block: BlockId, dst: Value, op: OpCode, lhs: Value, rhs: Value) {
    func.push_inst(block, IrInst::Binary { dst, op, lhs, rhs });
}

fn push_un(func: &mut IrFunction, block: BlockId, dst: Value, op: OpCode, src: Value) {
    func.push_inst(block, IrInst::Unary { dst, op, src });
}

struct RmLoc {
    reg: Option<Value>,
    addr: Option<Value>,
    len: usize,
}

impl RmLoc {
    fn load(&self, func: &mut IrFunction, block: BlockId, bits: u32) -> Value {
        if let Some(r) = &self.reg {
            return r.clone();
        }
        let v = func.alloc_var(int_ty(bits));
        let addr = self.addr.clone().unwrap_or(Value::Const(0));
        func.push_inst(block, IrInst::Load {
            dst: v.clone(),
            addr,
            size: bits / 8,
        });
        v
    }

    fn store(&self, lifter: &X86Lifter, func: &mut IrFunction, block: BlockId, val: Value, bits: u32) {
        if let Some(r) = &self.reg {
            lifter.write_reg(func, block, r, OpCode::Copy, val, bits);
        } else {
            let addr = self.addr.clone().unwrap_or(Value::Const(0));
            func.push_inst(block, IrInst::Store { addr, value: val, size: bits / 8 });
        }
    }
}

impl X86Lifter {
    pub fn new(is_64bit: bool) -> Self {
        X86Lifter {
            is_64bit,
            max_instructions: 100_000,
        }
    }

    fn ptr_bits(&self) -> u32 {
        if self.is_64bit { 64 } else { 32 }
    }

    fn stack_bits(&self, o16: bool) -> u32 {
        if o16 {
            16
        } else if self.is_64bit {
            64
        } else {
            32
        }
    }

    fn reg64(&self, name: &str) -> Value {
        Value::Register { name: name.to_string(), ty: Ty::i64() }
    }

    fn flag(&self, name: &str) -> Value {
        Value::Register {
            name: format!("flag_{}", name),
            ty: Ty::Bool,
        }
    }

    fn flag_cmp(&self, func: &mut IrFunction, block: BlockId, op: OpCode, name: &str) -> Value {
        let cond = func.alloc_var(Ty::Bool);
        push_bin(func, block, cond.clone(), op, self.flag(name), Value::Const(1));
        cond
    }

    fn flag_flag_cmp(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        op: OpCode,
        a: &str,
        b: &str,
    ) -> Value {
        let cond = func.alloc_var(Ty::Bool);
        push_bin(func, block, cond.clone(), op, self.flag(a), self.flag(b));
        cond
    }

    fn combine(&self, func: &mut IrFunction, block: BlockId, op: OpCode, a: Value, b: Value) -> Value {
        let dst = func.alloc_var(Ty::Bool);
        push_bin(func, block, dst.clone(), op, a, b);
        dst
    }

    fn jcc_condition(&self, func: &mut IrFunction, block: BlockId, cc: u8) -> Value {
        match cc {
            0x0 => self.flag_cmp(func, block, OpCode::Eq, "of"),
            0x1 => self.flag_cmp(func, block, OpCode::Ne, "of"),
            0x2 => self.flag_cmp(func, block, OpCode::Eq, "cf"),
            0x3 => self.flag_cmp(func, block, OpCode::Ne, "cf"),
            0x4 => self.flag_cmp(func, block, OpCode::Eq, "zf"),
            0x5 => self.flag_cmp(func, block, OpCode::Ne, "zf"),
            0x6 => {
                let cf = self.flag_cmp(func, block, OpCode::Eq, "cf");
                let zf = self.flag_cmp(func, block, OpCode::Eq, "zf");
                self.combine(func, block, OpCode::Or, cf, zf)
            }
            0x7 => {
                let ncf = self.flag_cmp(func, block, OpCode::Ne, "cf");
                let nzf = self.flag_cmp(func, block, OpCode::Ne, "zf");
                self.combine(func, block, OpCode::And, ncf, nzf)
            }
            0x8 => self.flag_cmp(func, block, OpCode::Eq, "sf"),
            0x9 => self.flag_cmp(func, block, OpCode::Ne, "sf"),
            0xA => self.flag_cmp(func, block, OpCode::Eq, "pf"),
            0xB => self.flag_cmp(func, block, OpCode::Ne, "pf"),
            0xC => self.flag_flag_cmp(func, block, OpCode::Ne, "sf", "of"),
            0xD => self.flag_flag_cmp(func, block, OpCode::Eq, "sf", "of"),
            0xE => {
                let zf = self.flag_cmp(func, block, OpCode::Eq, "zf");
                let l = self.flag_flag_cmp(func, block, OpCode::Ne, "sf", "of");
                self.combine(func, block, OpCode::Or, zf, l)
            }
            _ => {
                let nzf = self.flag_cmp(func, block, OpCode::Ne, "zf");
                let ge = self.flag_flag_cmp(func, block, OpCode::Eq, "sf", "of");
                self.combine(func, block, OpCode::And, nzf, ge)
            }
        }
    }

    fn emit_alu(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        kind: AluKind,
        a: Value,
        b: Value,
        bits: u32,
    ) -> Value {
        match kind {
            AluKind::Adc => {
                let t = func.alloc_var(int_ty(bits));
                push_bin(func, block, t.clone(), OpCode::Add, a, b);
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::Add, t, self.flag("cf"));
                r
            }
            AluKind::Sbb => {
                let t = func.alloc_var(int_ty(bits));
                push_bin(func, block, t.clone(), OpCode::Sub, a, b);
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::Sub, t, self.flag("cf"));
                r
            }
            AluKind::Add => {
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::Add, a.clone(), b.clone());
                self.write_add_flags(func, block, &a, &b, &r);
                r
            }
            AluKind::Or => {
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::Or, a, b);
                self.write_logic_flags(func, block, &r);
                r
            }
            AluKind::And => {
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::And, a, b);
                self.write_logic_flags(func, block, &r);
                r
            }
            AluKind::Xor => {
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::Xor, a, b);
                self.write_logic_flags(func, block, &r);
                r
            }
            AluKind::Sub | AluKind::Cmp => {
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::Sub, a.clone(), b.clone());
                self.write_sub_flags(func, block, &a, &b);
                r
            }
        }
    }

    /// Record ZF/CF/SF definitions for a `sub`-style operation so that
    /// later Jcc conditions can be folded into direct comparisons.
    fn write_sub_flags(&self, func: &mut IrFunction, block: BlockId, a: &Value, b: &Value) {
        push_bin(func, block, self.flag("zf"), OpCode::Eq, a.clone(), b.clone());
        push_bin(func, block, self.flag("cf"), OpCode::LtU, a.clone(), b.clone());
        push_bin(func, block, self.flag("sf"), OpCode::LtS, a.clone(), b.clone());
    }

    /// Write `op(src)` into register `dst`, keeping x86 sub-register
    /// aliases coherent.
    ///
    /// Design (stays within the existing IR ops): the narrow-name copy is
    /// emitted unchanged so narrow readers still see the write, and the
    /// value is additionally merged into the widest enclosing parent via a
    /// masked read-modify-write — `parent = (parent & !field) | value_field`
    /// — so later wider reads observe it too. 32-bit writes in 64-bit mode
    /// clear the upper half instead (`parent = zext(value)`), matching the
    /// architectural zero-extension.
    fn write_reg(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        dst: &Value,
        op: OpCode,
        src: Value,
        bits: u32,
    ) {
        push_un(func, block, dst.clone(), op, src.clone());
        let name = match dst {
            Value::Register { name, .. } => name.as_str(),
            _ => return,
        };
        let Some(info) = subreg_write(name, bits, self.is_64bit) else {
            return;
        };
        let pbits = self.ptr_bits();
        let parent = reg_value(info.parent_idx, pbits, false);
        if info.zero_high {
            let widened = func.alloc_var(int_ty(pbits));
            push_un(func, block, widened.clone(), OpCode::Zext, dst.clone());
            push_un(func, block, parent, OpCode::Copy, widened);
            return;
        }
        let field = if info.width >= 64 { u64::MAX } else { (1u64 << info.width) - 1 };
        let keep = (!field << info.offset) as i64;
        let preserved = func.alloc_var(int_ty(pbits));
        push_bin(func, block, preserved.clone(), OpCode::And, parent.clone(), Value::Const(keep));
        let field_val: Value = match src {
            Value::Const(c) => Value::Const((((c as u64) & field) << info.offset) as i64),
            v => {
                let masked = func.alloc_var(int_ty(pbits));
                push_bin(func, block, masked.clone(), OpCode::And, v, Value::Const(field as i64));
                if info.offset > 0 {
                    let shifted = func.alloc_var(int_ty(pbits));
                    push_bin(
                        func,
                        block,
                        shifted.clone(),
                        OpCode::Shl,
                        masked,
                        Value::Const(info.offset as i64),
                    );
                    shifted
                } else {
                    masked
                }
            }
        };
        let merged = func.alloc_var(int_ty(pbits));
        push_bin(func, block, merged.clone(), OpCode::Or, preserved, field_val);
        push_un(func, block, parent, OpCode::Copy, merged);
    }

    /// PF: parity of the result's low byte (set when it holds an even
    /// number of set bits). The IR has no popcount, so fold the byte down
    /// with a xor-tree and test the surviving bit.
    fn write_pf(&self, func: &mut IrFunction, block: BlockId, result: &Value) {
        let pb = self.ptr_bits();
        let mut cur = func.alloc_var(int_ty(pb));
        push_bin(func, block, cur.clone(), OpCode::And, result.clone(), Value::Const(0xFF));
        for sh in [4i64, 2, 1] {
            let hi = func.alloc_var(int_ty(pb));
            push_bin(func, block, hi.clone(), OpCode::Shr, cur.clone(), Value::Const(sh));
            let next = func.alloc_var(int_ty(pb));
            push_bin(func, block, next.clone(), OpCode::Xor, cur, hi);
            cur = next;
        }
        let low = func.alloc_var(int_ty(pb));
        push_bin(func, block, low.clone(), OpCode::And, cur, Value::Const(1));
        push_bin(func, block, self.flag("pf"), OpCode::Eq, low, Value::Const(0));
    }

    /// ADD-family flags: ZF/SF/PF from the result, CF from unsigned wrap,
    /// OF when both operand signs agree but the result sign flips.
    fn write_add_flags(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        a: &Value,
        b: &Value,
        result: &Value,
    ) {
        push_bin(func, block, self.flag("zf"), OpCode::Eq, result.clone(), Value::Const(0));
        push_bin(func, block, self.flag("sf"), OpCode::LtS, result.clone(), Value::Const(0));
        push_bin(func, block, self.flag("cf"), OpCode::LtU, result.clone(), a.clone());
        let neg_a = func.alloc_var(Ty::Bool);
        push_bin(func, block, neg_a.clone(), OpCode::LtS, a.clone(), Value::Const(0));
        let neg_b = func.alloc_var(Ty::Bool);
        push_bin(func, block, neg_b.clone(), OpCode::LtS, b.clone(), Value::Const(0));
        let neg_r = func.alloc_var(Ty::Bool);
        push_bin(func, block, neg_r.clone(), OpCode::LtS, result.clone(), Value::Const(0));
        let same_signs = func.alloc_var(Ty::Bool);
        push_bin(func, block, same_signs.clone(), OpCode::Eq, neg_a.clone(), neg_b);
        let sign_flips = func.alloc_var(Ty::Bool);
        push_bin(func, block, sign_flips.clone(), OpCode::Ne, neg_r, neg_a);
        push_bin(func, block, self.flag("of"), OpCode::And, same_signs, sign_flips);
        self.write_pf(func, block, result);
    }

    /// Logical-group flags (AND/OR/XOR/TEST): CF and OF are cleared,
    /// ZF/SF/PF derive from the result.
    fn write_logic_flags(&self, func: &mut IrFunction, block: BlockId, result: &Value) {
        push_un(func, block, self.flag("cf"), OpCode::Copy, Value::Const(0));
        push_un(func, block, self.flag("of"), OpCode::Copy, Value::Const(0));
        push_bin(func, block, self.flag("zf"), OpCode::Eq, result.clone(), Value::Const(0));
        push_bin(func, block, self.flag("sf"), OpCode::LtS, result.clone(), Value::Const(0));
        self.write_pf(func, block, result);
    }

    /// INC/DEC flags: ZF/SF/OF/PF as usual but CF is deliberately left
    /// untouched — the one way INC/DEC differ from ADD/SUB.
    fn write_incdec_flags(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        a: &Value,
        result: &Value,
        is_inc: bool,
    ) {
        push_bin(func, block, self.flag("zf"), OpCode::Eq, result.clone(), Value::Const(0));
        push_bin(func, block, self.flag("sf"), OpCode::LtS, result.clone(), Value::Const(0));
        let neg_a = func.alloc_var(Ty::Bool);
        push_bin(func, block, neg_a.clone(), OpCode::LtS, a.clone(), Value::Const(0));
        let neg_r = func.alloc_var(Ty::Bool);
        push_bin(func, block, neg_r.clone(), OpCode::LtS, result.clone(), Value::Const(0));
        if is_inc {
            // OF: positive operand wraps to negative (a was MAX).
            let non_neg = func.alloc_var(Ty::Bool);
            push_bin(func, block, non_neg.clone(), OpCode::Eq, neg_a, Value::Const(0));
            push_bin(func, block, self.flag("of"), OpCode::And, non_neg, neg_r);
        } else {
            // OF: negative operand wraps to non-negative (a was MIN).
            let non_neg_r = func.alloc_var(Ty::Bool);
            push_bin(func, block, non_neg_r.clone(), OpCode::Eq, neg_r, Value::Const(0));
            push_bin(func, block, self.flag("of"), OpCode::And, neg_a, non_neg_r);
        }
        self.write_pf(func, block, result);
    }

    fn emit_push(&self, func: &mut IrFunction, block: BlockId, val: Value, bits: u32) {
        let pb = self.ptr_bits();
        let sp = reg_value(4, pb, false);
        let tmp = func.alloc_var(int_ty(pb));
        push_bin(
            func,
            block,
            tmp.clone(),
            OpCode::Sub,
            sp.clone(),
            Value::Const((bits / 8) as i64),
        );
        func.push_inst(block, IrInst::Store {
            addr: tmp.clone(),
            value: val,
            size: bits / 8,
        });
        push_un(func, block, sp, OpCode::Copy, tmp);
    }

    fn emit_pop(&self, func: &mut IrFunction, block: BlockId, dst: Value, bits: u32) {
        let pb = self.ptr_bits();
        let sp = reg_value(4, pb, false);
        let ld = func.alloc_var(int_ty(bits));
        func.push_inst(block, IrInst::Load {
            dst: ld.clone(),
            addr: sp.clone(),
            size: bits / 8,
        });
        let tmp = func.alloc_var(int_ty(pb));
        push_bin(
            func,
            block,
            tmp.clone(),
            OpCode::Add,
            sp.clone(),
            Value::Const((bits / 8) as i64),
        );
        self.write_reg(func, block, &dst, OpCode::Copy, ld, bits);
        push_un(func, block, sp, OpCode::Copy, tmp);
    }

    #[allow(clippy::too_many_arguments)] // mirrors x86 ModRM/SIB decoding inputs
    fn build_address(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        modrm: u8,
        after: &[u8],
        rex_x: bool,
        rex_b: bool,
        rip_next: Option<u64>,
    ) -> (Value, usize) {
        let pbits = self.ptr_bits();
        let pty = int_ty(pbits);
        let (m, _, rm) = decode_modrm(modrm);

        if m == 3 {
            return (reg_value(rm + ext(rex_b), pbits, false), 1);
        }

        if rm == 4 {
            if after.is_empty() {
                return (Value::Const(0), 1);
            }
            let sib = after[0];
            let scale = 1u64 << ((sib >> 6) & 3);
            let idx_field = (sib >> 3) & 7;
            let base_field = sib & 7;
            let mut len = 2usize;
            let mut acc: Option<Value> = None;

            if m != 0 || base_field != 5 {
                acc = Some(reg_value(base_field + ext(rex_b), pbits, false));
            }

            if idx_field != 4 {
                let iv = reg_value(idx_field + ext(rex_x), pbits, false);
                let prod = if scale > 1 {
                    let t = func.alloc_var(pty.clone());
                    push_bin(func, block, t.clone(), OpCode::Mul, iv, Value::Const(scale as i64));
                    t
                } else {
                    iv
                };
                acc = Some(match acc {
                    Some(a) => {
                        let t = func.alloc_var(pty.clone());
                        push_bin(func, block, t.clone(), OpCode::Add, a, prod);
                        t
                    }
                    None => prod,
                });
            }

            let disp: Option<i64> = match m {
                0 if base_field == 5 => {
                    len += 4;
                    Some(read_i32(after, 1))
                }
                1 => {
                    len += 1;
                    Some(read_disp8(after, 1))
                }
                2 => {
                    len += 4;
                    Some(read_i32(after, 1))
                }
                _ => None,
            };

            if let Some(d) = disp {
                let dv = if m == 0 && base_field == 5 {
                    match rip_next {
                        Some(r) => Value::Const(r.wrapping_add(d as u64) as i64),
                        None => Value::Const(d),
                    }
                } else {
                    Value::Const(d)
                };
                acc = Some(match acc {
                    Some(a) => {
                        let t = func.alloc_var(pty.clone());
                        push_bin(func, block, t.clone(), OpCode::Add, a, dv);
                        t
                    }
                    None => dv,
                });
            }

            (acc.unwrap_or(Value::Const(0)), len)
        } else {
            if m == 0 && rm == 5 {
                let d = read_i32(after, 0);
                let v = match rip_next {
                    Some(r) => Value::Const(r.wrapping_add(d as u64) as i64),
                    None => Value::Const(d),
                };
                return (v, 5);
            }
            let base_val = reg_value(rm + ext(rex_b), pbits, false);
            match m {
                0 => (base_val, 1),
                1 => {
                    let d = read_disp8(after, 0);
                    let t = func.alloc_var(pty.clone());
                    push_bin(func, block, t.clone(), OpCode::Add, base_val, Value::Const(d));
                    (t, 2)
                }
                _ => {
                    let d = read_i32(after, 0);
                    let t = func.alloc_var(pty);
                    push_bin(func, block, t.clone(), OpCode::Add, base_val, Value::Const(d));
                    (t, 5)
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn address_of_rm(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        op_pos: usize,
        insn_addr: u64,
        rex_x: bool,
        rex_b: bool,
        trailing_imm: usize,
    ) -> Result<(Value, usize), LifterError> {
        let modrm = *code.get(op_pos + 1).ok_or_else(|| trunc_err(insn_addr))?;
        let after = &code[op_pos + 2..];
        let mlen = mem_operand_len(modrm, after);
        let rip_next = if self.is_64bit && modrm & 0xC0 != 0xC0 {
            Some(insn_addr.wrapping_add((op_pos + 1 + mlen + trailing_imm) as u64))
        } else {
            None
        };
        Ok(self.build_address(func, block, modrm, after, rex_x, rex_b, rip_next))
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_rm(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        op_pos: usize,
        insn_addr: u64,
        bits: u32,
        has_rex: bool,
        rex_x: bool,
        rex_b: bool,
        trailing_imm: usize,
    ) -> Result<RmLoc, LifterError> {
        let modrm = *code.get(op_pos + 1).ok_or_else(|| trunc_err(insn_addr))?;
        if modrm & 0xC0 == 0xC0 {
            let (_, _, rm) = decode_modrm(modrm);
            Ok(RmLoc {
                reg: Some(reg_value(rm + ext(rex_b), bits, has_rex)),
                addr: None,
                len: 1,
            })
        } else {
            let (addr, len) =
                self.address_of_rm(func, block, code, op_pos, insn_addr, rex_x, rex_b, trailing_imm)?;
            Ok(RmLoc { reg: None, addr: Some(addr), len })
        }
    }

    fn try_lift_prologue(&self, func: &mut IrFunction, block: BlockId, code: &[u8]) -> usize {
        if code.len() < 4 {
            return 0;
        }
        if code[0] == 0x55 {
            let rsp = self.reg64("rsp");
            let new_rsp = func.alloc_var(Ty::i64());

            push_bin(func, block, new_rsp.clone(), OpCode::Sub, rsp.clone(), Value::int(8));
            func.push_inst(block, IrInst::Store {
                addr: new_rsp.clone(),
                value: self.reg64("rbp"),
                size: 8,
            });
            push_un(func, block, rsp, OpCode::Copy, new_rsp);

            if code[1] == 0x48 && code[2] == 0x89 && code[3] == 0xE5 {
                push_un(func, block, self.reg64("rbp"), OpCode::Copy, self.reg64("rsp"));
                return 4;
            }

            return 1;
        }
        0
    }

    fn try_lift_epilogue(&self, func: &mut IrFunction, block: BlockId, code: &[u8]) -> usize {
        if code.is_empty() {
            return 0;
        }

        if code[0] == 0xC3 {
            let rsp = self.reg64("rsp");
            let old_rbp = func.alloc_var(Ty::i64());
            let new_rsp = func.alloc_var(Ty::i64());

            func.push_inst(block, IrInst::Load {
                dst: old_rbp.clone(),
                addr: rsp.clone(),
                size: 8,
            });
            push_bin(func, block, new_rsp.clone(), OpCode::Add, rsp, Value::int(8));
            push_un(func, block, self.reg64("rsp"), OpCode::Copy, new_rsp);
            push_un(func, block, self.reg64("rbp"), OpCode::Copy, old_rbp);
            func.push_inst(block, IrInst::Return {
                value: Some(self.reg64("rax")),
            });
            return 1;
        }

        if code[0] == 0xC9 && code.len() >= 2 && code[1] == 0xC3 {
            push_un(func, block, self.reg64("rsp"), OpCode::Copy, self.reg64("rbp"));
            let old_rbp = func.alloc_var(Ty::i64());
            func.push_inst(block, IrInst::Load {
                dst: old_rbp.clone(),
                addr: self.reg64("rsp"),
                size: 8,
            });
            push_un(func, block, self.reg64("rbp"), OpCode::Copy, old_rbp);
            let new_rsp = func.alloc_var(Ty::i64());
            push_bin(
                func,
                block,
                new_rsp.clone(),
                OpCode::Add,
                self.reg64("rsp"),
                Value::int(8),
            );
            push_un(func, block, self.reg64("rsp"), OpCode::Copy, new_rsp);
            func.push_inst(block, IrInst::Return {
                value: Some(self.reg64("rax")),
            });
            return 2;
        }

        0
    }

    fn lift_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> Result<(usize, bool), LifterError> {
        if code.is_empty() {
            return Err(trunc_err(address));
        }

        let mut pos = 0usize;
        let mut o16 = false;
        let mut repz = false;
        let mut repnz = false;

        while pos < code.len() && pos < 15 {
            match code[pos] {
                0xF0 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x67 => pos += 1,
                0xF2 => {
                    repnz = true;
                    pos += 1;
                }
                0xF3 => {
                    repz = true;
                    pos += 1;
                }
                0x66 => {
                    o16 = true;
                    pos += 1;
                }
                _ => break,
            }
        }

        if self.is_64bit && pos < code.len() && matches!(code[pos], 0xC4 | 0xC5) {
            return Err(LifterError::UnsupportedInstruction(format!(
                "VEX-prefixed instruction at 0x{:X}",
                address
            )));
        }

        let mut rex_w = false;
        let mut rex_r = false;
        let mut rex_x = false;
        let mut rex_b = false;
        let mut has_rex = false;

        if self.is_64bit && pos < code.len() && code[pos] & 0xF0 == 0x40 {
            let rex = code[pos];
            rex_w = rex & 0x08 != 0;
            rex_r = rex & 0x04 != 0;
            rex_x = rex & 0x02 != 0;
            rex_b = rex & 0x01 != 0;
            has_rex = true;
            pos += 1;
        }

        if pos >= code.len() {
            return Err(trunc_err(address));
        }

        let opcode = code[pos];
        let obits: u32 = if rex_w {
            64
        } else if o16 {
            16
        } else {
            32
        };
        let sbits = self.stack_bits(o16);

        match opcode {
            0x0F => {
                let &op2 = code.get(pos + 1).ok_or_else(|| trunc_err(address))?;

                if op2 == 0x38 || op2 == 0x3A {
                    let rep_tag = if repz {
                        " repz"
                    } else if repnz {
                        " repnz"
                    } else {
                        ""
                    };
                    return Err(LifterError::UnsupportedInstruction(format!(
                        "three-byte opcode 0F {:02X}{} at 0x{:X}",
                        op2, rep_tag, address
                    )));
                }

                match op2 {
                    0x05 | 0x31 => {
                        func.push_inst(block, IrInst::Nop);
                        Ok((pos + 2, true))
                    }

                    // ── SSE data movement (legacy encoding) ──────────
                    // 10/28/6F: xmm <- mem/reg   11/29/7F: mem/reg <- xmm
                    // Pure data movement regardless of the exact mnemonic
                    // (movups/movaps/movdqa/movdqu/movss/movsd).
                    0x10 | 0x11 | 0x28 | 0x29 | 0x6F | 0x7F => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let vdst = xmm_value(rf + ext(rex_r));
                        let store = matches!(op2, 0x11 | 0x29 | 0x7F);
                        if modrm & 0xC0 == 0xC0 {
                            let vsrc = xmm_value((modrm & 7) + ext(rex_b));
                            if store {
                                push_un(func, block, vsrc, OpCode::Copy, vdst);
                            } else {
                                push_un(func, block, vdst, OpCode::Copy, vsrc);
                            }
                            Ok((p2 + 2, true))
                        } else {
                            let (addr, len) = self.address_of_rm(
                                func, block, code, p2, address, rex_x, rex_b, 0,
                            )?;
                            if store {
                                func.push_inst(block, IrInst::Store {
                                    addr,
                                    value: vdst,
                                    size: 16,
                                });
                            } else {
                                let tmp = func.alloc_var(Ty::Unknown);
                                func.push_inst(block, IrInst::Load {
                                    dst: tmp.clone(),
                                    addr,
                                    size: 16,
                                });
                                push_un(func, block, vdst, OpCode::Copy, tmp);
                            }
                            Ok((p2 + 1 + len, true))
                        }
                    }

                    // pxor/xorps — the canonical `xmm = 0` zeroing idiom when
                    // both operands are the same register.
                    0x57 | 0xEF => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let vdst = xmm_value(rf + ext(rex_r));
                        if modrm & 0xC0 == 0xC0 && (modrm & 7) + ext(rex_b) == rf + ext(rex_r) {
                            push_bin(
                                func,
                                block,
                                vdst.clone(),
                                OpCode::Xor,
                                vdst.clone(),
                                vdst,
                            );
                        } else if modrm & 0xC0 == 0xC0 {
                            let vsrc = xmm_value((modrm & 7) + ext(rex_b));
                            let tmp = func.alloc_var(Ty::Unknown);
                            push_bin(func, block, tmp.clone(), OpCode::Xor, vdst.clone(), vsrc);
                            push_un(func, block, vdst, OpCode::Copy, tmp);
                        } else {
                            let (addr, len) = self.address_of_rm(
                                func, block, code, p2, address, rex_x, rex_b, 0,
                            )?;
                            let tmp = func.alloc_var(Ty::Unknown);
                            func.push_inst(block, IrInst::Load {
                                dst: tmp.clone(),
                                addr,
                                size: 16,
                            });
                            let r = func.alloc_var(Ty::Unknown);
                            push_bin(func, block, r.clone(), OpCode::Xor, vdst.clone(), tmp);
                            push_un(func, block, vdst, OpCode::Copy, r);
                            return Ok((p2 + 1 + len, true));
                        }
                        Ok((p2 + 2, true))
                    }

                    0x1E => match code.get(pos + 2) {
                        Some(0xFA) | Some(0xFB) => {
                            func.push_inst(block, IrInst::Nop);
                            Ok((pos + 3, true))
                        }
                        _ => Err(LifterError::UnsupportedInstruction(format!(
                            "unsupported 0F 1E form at 0x{:X}",
                            address
                        ))),
                    },
                    0x1F => {
                        let modrm = *code.get(pos + 2).ok_or_else(|| trunc_err(address))?;
                        let mlen = mem_operand_len(modrm, &code[pos + 3..]);
                        func.push_inst(block, IrInst::Nop);
                        Ok((pos + 2 + mlen, true))
                    }
                    0x40..=0x4F => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let cond = self.jcc_condition(func, block, op2 - 0x40);
                        let loc = self.resolve_rm(
                            func, block, code, p2, address, obits, has_rex, rex_x, rex_b, 0,
                        )?;
                        let src = loc.load(func, block, obits);
                        let cur = reg_value(rf + ext(rex_r), obits, has_rex);

                        let mask = func.alloc_var(int_ty(obits));
                        push_un(func, block, mask.clone(), OpCode::Sext, cond);
                        let nmask = func.alloc_var(int_ty(obits));
                        push_un(func, block, nmask.clone(), OpCode::Not, mask.clone());
                        let ta = func.alloc_var(int_ty(obits));
                        push_bin(func, block, ta.clone(), OpCode::And, src, mask);
                        let tb = func.alloc_var(int_ty(obits));
                        push_bin(func, block, tb.clone(), OpCode::And, cur.clone(), nmask);
                        let res = func.alloc_var(int_ty(obits));
                        push_bin(func, block, res.clone(), OpCode::Or, ta, tb);
                        self.write_reg(func, block, &cur, OpCode::Copy, res, obits);

                        Ok((p2 + 1 + loc.len, true))
                    }
                    0x63 if self.is_64bit => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let dbits = if o16 { 16 } else { 64 };
                        let loc = self.resolve_rm(
                            func, block, code, p2, address, 32, has_rex, rex_x, rex_b, 0,
                        )?;
                        let src = loc.load(func, block, 32);
                        let dst = reg_value(rf + ext(rex_r), dbits, has_rex);
                        self.write_reg(func, block, &dst, OpCode::Sext, src, dbits);
                        Ok((p2 + 1 + loc.len, true))
                    }
                    0x63 => Err(LifterError::UnsupportedInstruction(format!(
                        "ARPL at 0x{:X}",
                        address
                    ))),
                    0x80..=0x8F => {
                        let rb = if o16 { 2 } else { 4 };
                        let rel = imm_at(code, pos + 2, rb).ok_or_else(|| trunc_err(address))?;
                        let insn_len = pos + 2 + rb;
                        let target_addr = (address as i64 + insn_len as i64 + rel) as u64;
                        let tt = func.add_block(&format!("loc_{:X}", target_addr));
                        let tf = func.add_block(&format!("fall_{:X}", address + insn_len as u64));
                        let cond = self.jcc_condition(func, block, op2 - 0x80);
                        func.push_inst(block, IrInst::CBranch {
                            cond,
                            target_true: tt,
                            target_false: tf,
                        });
                        Ok((insn_len, true))
                    }
                    0x90..=0x9F => {
                        let p2 = pos + 1;
                        let loc = self.resolve_rm(
                            func, block, code, p2, address, 8, has_rex, rex_x, rex_b, 0,
                        )?;
                        let cond = self.jcc_condition(func, block, op2 - 0x90);
                        if let Some(dst) = loc.reg.clone() {
                            self.write_reg(func, block, &dst, OpCode::Copy, cond, 8);
                        } else {
                            let addr = loc.addr.clone().unwrap_or(Value::Const(0));
                            func.push_inst(block, IrInst::Store {
                                addr,
                                value: cond,
                                size: 1,
                            });
                        }
                        Ok((p2 + 1 + loc.len, true))
                    }
                    0xAF => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let loc = self.resolve_rm(
                            func, block, code, p2, address, obits, has_rex, rex_x, rex_b, 0,
                        )?;
                        let src = loc.load(func, block, obits);
                        let dst = reg_value(rf + ext(rex_r), obits, has_rex);
                        let r = func.alloc_var(int_ty(obits));
                        push_bin(func, block, r.clone(), OpCode::Mul, dst.clone(), src);
                        self.write_reg(func, block, &dst, OpCode::Copy, r, obits);
                        Ok((p2 + 1 + loc.len, true))
                    }
                    0xB6 | 0xB7 | 0xBE | 0xBF => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let src_bits = if op2 == 0xB6 || op2 == 0xBE { 8 } else { 16 };
                        let sext = op2 == 0xBE || op2 == 0xBF;
                        let loc = self.resolve_rm(
                            func, block, code, p2, address, src_bits, has_rex, rex_x, rex_b, 0,
                        )?;
                        let src = loc.load(func, block, src_bits);
                        let dst = reg_value(rf + ext(rex_r), obits, has_rex);
                        push_un(
                            func,
                            block,
                            dst,
                            if sext { OpCode::Sext } else { OpCode::Zext },
                            src,
                        );
                        Ok((p2 + 1 + loc.len, true))
                    }
                    other => Err(LifterError::UnsupportedInstruction(format!(
                        "unsupported opcode 0F {:02X} at 0x{:X}",
                        other, address
                    ))),
                }
            }

            o @ (0x00..=0x03
            | 0x08..=0x0B
            | 0x10..=0x13
            | 0x18..=0x1B
            | 0x20..=0x23
            | 0x28..=0x2B
            | 0x30..=0x33
            | 0x38..=0x3B) => {
                let kind = alu_kind(o);
                let bits = if o & 1 == 0 { 8 } else { obits };
                let to_reg = o & 2 != 0;
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0)?;
                let rmv = loc.load(func, block, bits);
                let regv = reg_value(rf + ext(rex_r), bits, has_rex);
                let result = self.emit_alu(func, block, kind, rmv, regv.clone(), bits);
                if kind != AluKind::Cmp {
                    if to_reg {
                        self.write_reg(func, block, &regv, OpCode::Copy, result, bits);
                    } else {
                        loc.store(self, func, block, result, bits);
                    }
                }
                Ok((pos + 1 + loc.len, true))
            }

            o @ (0x04 | 0x05
            | 0x0C | 0x0D
            | 0x14 | 0x15
            | 0x1C | 0x1D
            | 0x24 | 0x25
            | 0x2C | 0x2D
            | 0x34 | 0x35
            | 0x3C | 0x3D) => {
                let kind = alu_kind(o);
                let is_imm8 = o & 1 == 0;
                let ib = if is_imm8 {
                    1
                } else if o16 {
                    2
                } else {
                    4
                };
                let bits = if is_imm8 { 8 } else { obits };
                let imm = imm_at(code, pos + 1, ib).ok_or_else(|| trunc_err(address))?;
                let acc = reg_value(0, bits, false);
                let result = self.emit_alu(func, block, kind, acc.clone(), Value::Const(imm), bits);
                if kind != AluKind::Cmp {
                    self.write_reg(func, block, &acc, OpCode::Copy, result, bits);
                }
                Ok((pos + 1 + ib, true))
            }

            o @ 0x80..=0x83 => {
                let bits = if o == 0x80 || o == 0x82 { 8 } else { obits };
                let ib = if o == 0x81 {
                    if o16 { 2 } else { 4 }
                } else {
                    1
                };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let kind = grp1_kind(rf);
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, ib)?;
                let imm = imm_at(code, pos + 1 + loc.len, ib).ok_or_else(|| trunc_err(address))?;
                let rmv = loc.load(func, block, bits);
                let result = self.emit_alu(func, block, kind, rmv, Value::Const(imm), bits);
                if kind != AluKind::Cmp {
                    loc.store(self, func, block, result, bits);
                }
                Ok((pos + 1 + loc.len + ib, true))
            }

            0x50..=0x57 => {
                let idx = (opcode - 0x50) + u8::from(rex_b) * 8;
                let val = reg_value(idx, sbits, has_rex);
                self.emit_push(func, block, val, sbits);
                Ok((pos + 1, true))
            }

            0x58..=0x5F => {
                let idx = (opcode - 0x58) + u8::from(rex_b) * 8;
                let dst = reg_value(idx, sbits, has_rex);
                self.emit_pop(func, block, dst, sbits);
                Ok((pos + 1, true))
            }

            0x63 if self.is_64bit => {
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let dbits = if o16 { 16 } else { 64 };
                let loc =
                    self.resolve_rm(func, block, code, pos, address, 32, has_rex, rex_x, rex_b, 0)?;
                let src = loc.load(func, block, 32);
                let dst = reg_value(rf + ext(rex_r), dbits, has_rex);
                self.write_reg(func, block, &dst, OpCode::Sext, src, dbits);
                Ok((pos + 1 + loc.len, true))
            }

            0x63 => Err(LifterError::UnsupportedInstruction(format!(
                "ARPL at 0x{:X}",
                address
            ))),

            0x68 => {
                let ib = if o16 { 2 } else { 4 };
                let imm = imm_at(code, pos + 1, ib).ok_or_else(|| trunc_err(address))?;
                self.emit_push(func, block, Value::Const(imm), sbits);
                Ok((pos + 1 + ib, true))
            }

            0x6A => {
                let imm = imm_at(code, pos + 1, 1).ok_or_else(|| trunc_err(address))?;
                self.emit_push(func, block, Value::Const(imm), sbits);
                Ok((pos + 2, true))
            }

            o @ (0x69 | 0x6B) => {
                let ib = if o == 0x69 {
                    if o16 { 2 } else { 4 }
                } else {
                    1
                };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let loc =
                    self.resolve_rm(func, block, code, pos, address, obits, has_rex, rex_x, rex_b, ib)?;
                let src = loc.load(func, block, obits);
                let imm = imm_at(code, pos + 1 + loc.len, ib).ok_or_else(|| trunc_err(address))?;
                let dst = reg_value(rf + ext(rex_r), obits, has_rex);
                let r = func.alloc_var(int_ty(obits));
                push_bin(func, block, r.clone(), OpCode::Mul, src, Value::Const(imm));
                self.write_reg(func, block, &dst, OpCode::Copy, r, obits);
                Ok((pos + 1 + loc.len + ib, true))
            }

            o @ (0x84 | 0x85) => {
                let bits = if o == 0x84 { 8 } else { obits };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0)?;
                let rmv = loc.load(func, block, bits);
                let regv = reg_value(rf + ext(rex_r), bits, has_rex);
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::And, rmv, regv);
                self.write_logic_flags(func, block, &r);
                Ok((pos + 1 + loc.len, true))
            }

            0xA8 | 0xA9 => {
                let is8 = opcode == 0xA8;
                let ib = if is8 {
                    1
                } else if o16 {
                    2
                } else {
                    4
                };
                let bits = if is8 { 8 } else { obits };
                let imm = imm_at(code, pos + 1, ib).ok_or_else(|| trunc_err(address))?;
                let acc = reg_value(0, bits, false);
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), OpCode::And, acc, Value::Const(imm));
                self.write_logic_flags(func, block, &r);
                Ok((pos + 1 + ib, true))
            }

            o @ (0x86 | 0x87) => {
                let bits = if o == 0x86 { 8 } else { obits };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0)?;
                let rmv = loc.load(func, block, bits);
                let regv = reg_value(rf + ext(rex_r), bits, has_rex);
                let tmp = func.alloc_var(int_ty(bits));
                push_un(func, block, tmp.clone(), OpCode::Copy, rmv);
                loc.store(self, func, block, regv.clone(), bits);
                self.write_reg(func, block, &regv, OpCode::Copy, tmp, bits);
                Ok((pos + 1 + loc.len, true))
            }

            o @ (0x88..=0x8B) => {
                let bits = if o == 0x88 || o == 0x8A { 8 } else { obits };
                let to_reg = o == 0x8A || o == 0x8B;
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0)?;
                if to_reg {
                    let src = loc.load(func, block, bits);
                    let dst = reg_value(rf + ext(rex_r), bits, has_rex);
                    self.write_reg(func, block, &dst, OpCode::Copy, src, bits);
                } else {
                    let src = reg_value(rf + ext(rex_r), bits, has_rex);
                    loc.store(self, func, block, src, bits);
                }
                Ok((pos + 1 + loc.len, true))
            }

            0x8D => {
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                if modrm & 0xC0 == 0xC0 {
                    return Err(LifterError::InvalidInstruction(
                        address,
                        "LEA with register operand".into(),
                    ));
                }
                let (_, rf, _) = decode_modrm(modrm);
                let (addr, len) =
                    self.address_of_rm(func, block, code, pos, address, rex_x, rex_b, 0)?;
                let dst = reg_value(rf + ext(rex_r), obits, has_rex);
                self.write_reg(func, block, &dst, OpCode::Copy, addr, obits);
                Ok((pos + 1 + len, true))
            }

            0x90 => {
                func.push_inst(block, IrInst::Nop);
                Ok((pos + 1, true))
            }

            0x98 => {
                let src_bits = if rex_w {
                    32
                } else if o16 {
                    8
                } else {
                    16
                };
                let dst_bits = if rex_w {
                    64
                } else if o16 {
                    16
                } else {
                    32
                };
                let src = reg_value(0, src_bits, false);
                let dst = reg_value(0, dst_bits, false);
                self.write_reg(func, block, &dst, OpCode::Sext, src, dst_bits);
                Ok((pos + 1, true))
            }

            0x99 => {
                let src_bits = if rex_w {
                    32
                } else if o16 {
                    8
                } else {
                    16
                };
                let dst_bits = if rex_w {
                    64
                } else if o16 {
                    16
                } else {
                    32
                };
                let src = reg_value(0, src_bits, false);
                let dst = reg_value(2, dst_bits, false);
                self.write_reg(func, block, &dst, OpCode::Sext, src, dst_bits);
                Ok((pos + 1, true))
            }

            0xB0..=0xB7 => {
                let idx = (opcode - 0xB0) + u8::from(rex_b) * 8;
                let imm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let dst = reg_value(idx, 8, has_rex);
                self.write_reg(func, block, &dst, OpCode::Copy, Value::Const(imm as i8 as i64), 8);
                Ok((pos + 2, true))
            }

            0xB8..=0xBF => {
                let idx = (opcode - 0xB8) + u8::from(rex_b) * 8;
                let (dst, imm, ilen) = if rex_w {
                    (
                        reg_value(idx, 64, has_rex),
                        zext_at(code, pos + 1, 8).ok_or_else(|| trunc_err(address))?,
                        8,
                    )
                } else if o16 {
                    (
                        reg_value(idx, 16, has_rex),
                        zext_at(code, pos + 1, 2).ok_or_else(|| trunc_err(address))?,
                        2,
                    )
                } else {
                    (
                        reg_value(idx, 32, has_rex),
                        zext_at(code, pos + 1, 4).ok_or_else(|| trunc_err(address))?,
                        4,
                    )
                };
                self.write_reg(func, block, &dst, OpCode::Copy, Value::Const(imm), obits);
                Ok((pos + 1 + ilen, true))
            }

            o @ (0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3) => {
                let bits = if o == 0xC0 || o == 0xD0 || o == 0xD2 { 8 } else { obits };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let shift_op = match rf {
                    0 => OpCode::Rol,
                    1 => OpCode::Ror,
                    2 => {
                        return Err(LifterError::UnsupportedInstruction(format!(
                            "RCL at 0x{:X}",
                            address
                        )))
                    }
                    3 => {
                        return Err(LifterError::UnsupportedInstruction(format!(
                            "RCR at 0x{:X}",
                            address
                        )))
                    }
                    4 => OpCode::Shl,
                    5 => OpCode::Shr,
                    6 => {
                        return Err(LifterError::UnsupportedInstruction(format!(
                            "undefined shift /6 at 0x{:X}",
                            address
                        )))
                    }
                    _ => OpCode::Sar,
                };
                let timm = if o == 0xC0 || o == 0xC1 { 1 } else { 0 };
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, timm)?;
                let count = match o {
                    0xD0 | 0xD1 => Value::Const(1),
                    0xD2 | 0xD3 => reg_value(1, 8, false),
                    _ => {
                        let c = zext_at(code, pos + 1 + loc.len, 1)
                            .ok_or_else(|| trunc_err(address))?;
                        Value::Const(c)
                    }
                };
                let v = loc.load(func, block, bits);
                let r = func.alloc_var(int_ty(bits));
                push_bin(func, block, r.clone(), shift_op, v, count);
                loc.store(self, func, block, r, bits);
                Ok((pos + 1 + loc.len + timm, true))
            }

            0xC2 => {
                // RET imm16 pops a zero-extended 16-bit byte count.
                let n = zext_at(code, pos + 1, 2).ok_or_else(|| trunc_err(address))?;
                let pb = self.ptr_bits();
                let sp = reg_value(4, pb, false);
                let tmp = func.alloc_var(int_ty(pb));
                push_bin(func, block, tmp.clone(), OpCode::Add, sp.clone(), Value::Const(n));
                push_un(func, block, sp, OpCode::Copy, tmp);
                func.push_inst(block, IrInst::Return {
                    value: Some(reg_value(0, pb, false)),
                });
                Ok((pos + 3, true))
            }

            0xC3 => {
                func.push_inst(block, IrInst::Return {
                    value: Some(reg_value(0, self.ptr_bits(), false)),
                });
                Ok((pos + 1, true))
            }

            o @ (0xC6 | 0xC7) => {
                let bits = if o == 0xC6 { 8 } else { obits };
                let ib = if o == 0xC6 {
                    1
                } else if o16 {
                    2
                } else {
                    4
                };
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, ib)?;
                let imm = imm_at(code, pos + 1 + loc.len, ib).ok_or_else(|| trunc_err(address))?;
                loc.store(self, func, block, Value::Const(imm), bits);
                Ok((pos + 1 + loc.len + ib, true))
            }

            0xC9 => {
                let pb = self.ptr_bits();
                let sp = reg_value(4, pb, false);
                let bp = reg_value(5, pb, false);
                push_un(func, block, sp.clone(), OpCode::Copy, bp.clone());
                let ld = func.alloc_var(int_ty(pb));
                func.push_inst(block, IrInst::Load {
                    dst: ld.clone(),
                    addr: sp.clone(),
                    size: pb / 8,
                });
                push_un(func, block, bp, OpCode::Copy, ld);
                let tmp = func.alloc_var(int_ty(pb));
                push_bin(
                    func,
                    block,
                    tmp.clone(),
                    OpCode::Add,
                    sp.clone(),
                    Value::Const((sbits / 8) as i64),
                );
                push_un(func, block, sp, OpCode::Copy, tmp);
                Ok((pos + 1, true))
            }

            0xE8 => {
                let rb = if o16 { 2 } else { 4 };
                let rel = imm_at(code, pos + 1, rb).ok_or_else(|| trunc_err(address))?;
                let insn_len = pos + 1 + rb;
                let target_addr = (address as i64 + insn_len as i64 + rel) as u64;
                // CALL pushes the return address; model it so subsequent
                // [rsp±k] memory operands stay aligned.
                let ret_addr = address.wrapping_add(insn_len as u64) as i64;
                self.emit_push(func, block, Value::Const(ret_addr), sbits);
                func.push_inst(block, IrInst::Call {
                    dst: Some(reg_value(0, self.ptr_bits(), false)),
                    target: Value::Symbol(format!("sub_{:X}", target_addr)),
                    args: Vec::new(),
                });
                Ok((insn_len, true))
            }

            0xE9 => {
                let rb = if o16 { 2 } else { 4 };
                let rel = imm_at(code, pos + 1, rb).ok_or_else(|| trunc_err(address))?;
                let insn_len = pos + 1 + rb;
                let target_addr = (address as i64 + insn_len as i64 + rel) as u64;
                let tb = func.add_block(&format!("loc_{:X}", target_addr));
                func.push_inst(block, IrInst::Branch { target: tb });
                Ok((insn_len, true))
            }

            0xEB => {
                let rel = imm_at(code, pos + 1, 1).ok_or_else(|| trunc_err(address))?;
                let target_addr = (address as i64 + 2 + rel) as u64;
                let tb = func.add_block(&format!("loc_{:X}", target_addr));
                func.push_inst(block, IrInst::Branch { target: tb });
                Ok((pos + 2, true))
            }

            // LOOPNZ/LOOPZ/LOOP/JCXZ(JECXZ): conditional branches with a
            // counter side effect on CX/ECX/RCX.
            0xE0..=0xE3 => {
                let rel = imm_at(code, pos + 1, 1).ok_or_else(|| trunc_err(address))?;
                let insn_len = pos + 2;
                let target_addr = (address as i64 + insn_len as i64 + rel) as u64;
                let tt = func.add_block(&format!("loc_{:X}", target_addr));
                let tf = func.add_block(&format!("fall_{:X}", address + insn_len as u64));
                let counter = reg_value(1, sbits, false);
                let cond = if opcode == 0xE3 {
                    let zero = func.alloc_var(Ty::Bool);
                    push_bin(func, block, zero.clone(), OpCode::Eq, counter, Value::Const(0));
                    zero
                } else {
                    let dec = func.alloc_var(int_ty(sbits));
                    push_bin(func, block, dec.clone(), OpCode::Sub, counter.clone(), Value::Const(1));
                    push_un(func, block, counter, OpCode::Copy, dec.clone());
                    let nonzero = func.alloc_var(Ty::Bool);
                    push_bin(func, block, nonzero.clone(), OpCode::Ne, dec, Value::Const(0));
                    match opcode {
                        0xE0 => {
                            let zf_clear = self.flag_cmp(func, block, OpCode::Ne, "zf");
                            self.combine(func, block, OpCode::And, nonzero, zf_clear)
                        }
                        0xE1 => {
                            let zf_set = self.flag_cmp(func, block, OpCode::Eq, "zf");
                            self.combine(func, block, OpCode::And, nonzero, zf_set)
                        }
                        _ => nonzero,
                    }
                };
                func.push_inst(block, IrInst::CBranch {
                    cond,
                    target_true: tt,
                    target_false: tf,
                });
                Ok((insn_len, true))
            }

            0x70..=0x7F => {
                let rel = imm_at(code, pos + 1, 1).ok_or_else(|| trunc_err(address))?;
                let target_addr = (address as i64 + 2 + rel) as u64;
                let tt = func.add_block(&format!("loc_{:X}", target_addr));
                let tf = func.add_block(&format!("fall_{:X}", address + 2));
                let cond = self.jcc_condition(func, block, opcode - 0x70);
                func.push_inst(block, IrInst::CBranch {
                    cond,
                    target_true: tt,
                    target_false: tf,
                });
                Ok((pos + 2, true))
            }

            0xCC => {
                func.push_inst(block, IrInst::Nop);
                Ok((pos + 1, true))
            }

            // INT imm8: opaque OS-level trap, kept as an explicit marker.
            0xCD => {
                func.push_inst(block, IrInst::Nop);
                Ok((pos + 2, true))
            }

            o @ (0xF6 | 0xF7) => {
                let bits = if o == 0xF6 { 8 } else { obits };
                let ib = if o == 0xF6 {
                    1
                } else if o16 {
                    2
                } else {
                    4
                };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                match rf {
                    0 | 1 => {
                        let loc = self.resolve_rm(
                            func, block, code, pos, address, bits, has_rex, rex_x, rex_b, ib,
                        )?;
                        let v = loc.load(func, block, bits);
                        let imm = imm_at(code, pos + 1 + loc.len, ib)
                            .ok_or_else(|| trunc_err(address))?;
                        let r = func.alloc_var(int_ty(bits));
                        push_bin(func, block, r.clone(), OpCode::And, v, Value::Const(imm));
                        self.write_logic_flags(func, block, &r);
                        Ok((pos + 1 + loc.len + ib, true))
                    }
                    2 | 3 => {
                        let loc = self.resolve_rm(
                            func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0,
                        )?;
                        let v = loc.load(func, block, bits);
                        let r = func.alloc_var(int_ty(bits));
                        push_un(
                            func,
                            block,
                            r.clone(),
                            if rf == 2 { OpCode::Not } else { OpCode::Neg },
                            v,
                        );
                        loc.store(self, func, block, r, bits);
                        Ok((pos + 1 + loc.len, true))
                    }
                    4 => Err(LifterError::UnsupportedInstruction(format!(
                        "MUL at 0x{:X}",
                        address
                    ))),
                    5 => Err(LifterError::UnsupportedInstruction(format!(
                        "IMUL at 0x{:X}",
                        address
                    ))),
                    6 => Err(LifterError::UnsupportedInstruction(format!(
                        "DIV at 0x{:X}",
                        address
                    ))),
                    _ => Err(LifterError::UnsupportedInstruction(format!(
                        "IDIV at 0x{:X}",
                        address
                    ))),
                }
            }

            o @ (0xFE | 0xFF) => {
                let bits = if o == 0xFE { 8 } else { obits };
                let loc =
                    self.resolve_rm(func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0)?;
                let (_, rf, _) = decode_modrm(code[pos + 1]);
                match (o, rf) {
                    (_, 0) | (_, 1) => {
                        let v = loc.load(func, block, bits);
                        let r = func.alloc_var(int_ty(bits));
                        // INC/DEC update ZF/SF/OF/PF but *preserve* CF.
                        let is_inc = rf == 0;
                        push_bin(
                            func,
                            block,
                            r.clone(),
                            if is_inc { OpCode::Add } else { OpCode::Sub },
                            v.clone(),
                            Value::Const(1),
                        );
                        self.write_incdec_flags(func, block, &v, &r, is_inc);
                        loc.store(self, func, block, r, bits);
                        Ok((pos + 1 + loc.len, true))
                    }
                    (0xFF, 2) => {
                        let v = loc.load(func, block, bits);
                        func.push_inst(block, IrInst::Call {
                            dst: Some(reg_value(0, self.ptr_bits(), false)),
                            target: v,
                            args: Vec::new(),
                        });
                        Ok((pos + 1 + loc.len, true))
                    }
                    (0xFF, 4) => {
                        let v = loc.load(func, block, bits);
                        func.push_inst(block, IrInst::IndirectBranch { target: v });
                        Ok((pos + 1 + loc.len, true))
                    }
                    (0xFF, 6) => {
                        let v = loc.load(func, block, bits);
                        self.emit_push(func, block, v, sbits);
                        Ok((pos + 1 + loc.len, true))
                    }
                    (0xFF, 3) => Err(LifterError::UnsupportedInstruction(format!(
                        "lcall far at 0x{:X}",
                        address
                    ))),
                    (0xFF, 5) => Err(LifterError::UnsupportedInstruction(format!(
                        "ljmp far at 0x{:X}",
                        address
                    ))),
                    _ => Err(LifterError::UnsupportedInstruction(format!(
                        "{:02X} /{} at 0x{:X}",
                        o, rf, address
                    ))),
                }
            }

            _ => {
                // Decoded but unmodelled opcode: surface it as a Nop so the
                // instruction is accounted for instead of silently vanishing.
                let len = lde_length(code, self.is_64bit)?;
                func.push_inst(block, IrInst::Nop);
                Ok((len.max(1), true))
            }
        }
    }
}

impl Lifter for X86Lifter {
    fn arch_name(&self) -> &str {
        if self.is_64bit { "x86_64" } else { "x86" }
    }

    fn max_instructions(&self) -> usize {
        self.max_instructions
    }

    fn lift_function(
        &self,
        code: &[u8],
        base_address: u64,
        function_name: &str,
    ) -> Result<IrFunction, LifterError> {
        let mut func = IrFunction::new(function_name, base_address);
        let mut current_block = func.entry_block;
        let mut offset = 0usize;
        let mut instruction_count = 0usize;

        if self.is_64bit {
            offset += self.try_lift_prologue(&mut func, current_block, code);
        }

        while offset < code.len() && instruction_count < self.max_instructions {
            let remaining = &code[offset..];
            let address = base_address + offset as u64;

            if self.is_64bit {
                let epilogue_size = self.try_lift_epilogue(&mut func, current_block, remaining);
                if epilogue_size > 0 {
                    offset += epilogue_size;
                    instruction_count += 1;
                    break;
                }
            }

            let (consumed, lifted) = match self.lift_instruction(&mut func, current_block, remaining, address) {
                Ok(ok) => ok,
                // Unsupported opcode: skip the whole instruction using the
                // precise length from the LDE and keep going. Bailing out on
                // the first SSE/AVX op would lose the entire function — real
                // x64 code is full of them.
                Err(LifterError::UnsupportedInstruction(msg)) => {
                    let mode = if self.is_64bit {
                        freakre_x86::types::Mode::X64
                    } else {
                        freakre_x86::types::Mode::X86
                    };
                    let len = freakre_x86::decode_len(remaining, mode)
                        .map_err(|e| LifterError::UnsupportedInstruction(format!("{} ({})", msg, e)))?;
                    if len == 0 || len > remaining.len() {
                        return Err(LifterError::UnsupportedInstruction(format!("{} (bad length {})", msg, len)));
                    }
                    func.push_inst(current_block, IrInst::Nop);
                    (len, false)
                }
                Err(e) => return Err(e),
            };

            if consumed == 0 {
                break;
            }

            offset += consumed;
            instruction_count += 1;

            if lifted {
                if let Some(b) = func.block(current_block) {
                    if b.terminator().is_some() {
                        current_block = func.add_block(&format!("bb_{}", offset));
                    }
                }
            }
        }

        crate::ir::repair_block_graph(&mut func, parse_block_addr);
        func.build_cfg();

        Ok(func)
    }
}

fn parse_block_addr(name: &str, base_address: u64) -> Option<u64> {
    if let Some(rest) = name.strip_prefix("bb_") {
        return rest.parse::<usize>().ok().map(|o| base_address + o as u64);
    }
    if let Some(rest) = name.strip_prefix("loc_") {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = name.strip_prefix("fall_") {
        return u64::from_str_radix(rest, 16).ok();
    }
    None
}

fn lde_bad(off: usize) -> LifterError {
    LifterError::InvalidInstruction(off as u64, "undecodable instruction".into())
}

fn lde_length(code: &[u8], is_64bit: bool) -> Result<usize, LifterError> {
    if code.is_empty() {
        return Err(lde_bad(0));
    }

    let mut pos = 0usize;
    let mut o16 = false;

    while pos < code.len() && pos < 15 {
        match code[pos] {
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x67 => pos += 1,
            0x66 => {
                o16 = true;
                pos += 1;
            }
            _ => break,
        }
    }

    let mut rex_w = false;
    if is_64bit && pos < code.len() && code[pos] & 0xF0 == 0x40 {
        rex_w = code[pos] & 0x08 != 0;
        pos += 1;
    }

    if pos >= code.len() {
        return Err(lde_bad(pos));
    }

    let opcode = code[pos];
    pos += 1;

    let modrm_span = |code: &[u8], p: usize| -> Result<usize, LifterError> {
        let m = *code.get(p).ok_or_else(|| lde_bad(p))?;
        let n = mem_operand_len(m, &code[p + 1..]);
        if p + n > code.len() {
            Err(lde_bad(p))
        } else {
            Ok(n)
        }
    };

    if is_64bit && matches!(opcode, 0xC4 | 0xC5) {
        return Err(LifterError::UnsupportedInstruction(
            "VEX-prefixed instruction".into(),
        ));
    }

    if opcode == 0x0F {
        let op2 = *code.get(pos).ok_or_else(|| lde_bad(pos))?;
        pos += 1;

        if op2 == 0x38 || op2 == 0x3A {
            let _ = *code.get(pos).ok_or_else(|| lde_bad(pos))?;
            pos += 1;
            let n = modrm_span(code, pos)?;
            let total = pos + n + usize::from(op2 == 0x3A);
            if total > code.len() {
                return Err(lde_bad(total));
            }
            return Ok(total);
        }

        let total = match op2 {
            0x05 | 0x31 => pos,
            0x1E => match code.get(pos) {
                Some(0xFA) | Some(0xFB) => pos + 1,
                _ => {
                    return Err(LifterError::UnsupportedInstruction("unsupported 0F 1E form".to_string()))
                }
            },
            0x1F | 0x40..=0x4F | 0x90..=0x9F | 0xAF | 0xB6..=0xB7 | 0xBE..=0xBF => {
                pos + modrm_span(code, pos)?
            }
            0x63 => pos + modrm_span(code, pos)?,
            0x80..=0x8F => pos + if o16 { 2 } else { 4 },
            other => {
                return Err(LifterError::UnsupportedInstruction(format!(
                    "unknown opcode 0F {:02X}",
                    other
                )))
            }
        };
        if total > code.len() {
            return Err(lde_bad(total));
        }
        return Ok(total);
    }


    let total = match opcode {
        0x00..=0x03
        | 0x08..=0x0B
        | 0x10..=0x13
        | 0x18..=0x1B
        | 0x20..=0x23
        | 0x28..=0x2B
        | 0x30..=0x33
        | 0x38..=0x3B => pos + modrm_span(code, pos)?,

        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => pos + 1,

        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => {
            pos + if o16 { 2 } else { 4 }
        }

        0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F | 0x27 | 0x2F | 0x37 | 0x3F => {
            return Err(LifterError::UnsupportedInstruction(format!(
                "unknown opcode {:02X}",
                opcode
            )))
        }

        0x40..=0x4F => pos,

        0x50..=0x5F => pos,

        0x60 | 0x61 => {
            if is_64bit {
                return Err(LifterError::UnsupportedInstruction(
                    "PUSHA/POPA in 64-bit mode".into(),
                ));
            }
            pos
        }

        0x62 if is_64bit => {
            return Err(LifterError::UnsupportedInstruction(
                "EVEX-prefixed instruction".into(),
            ))
        }

        0x63 => pos + modrm_span(code, pos)?,

        0x68 => pos + if o16 { 2 } else { 4 },

        0x69 => {
            let l = modrm_span(code, pos)?;
            pos + l + if o16 { 2 } else { 4 }
        }

        0x6A => pos + 1,

        0x6B => {
            let l = modrm_span(code, pos)?;
            pos + l + 1
        }

        0x6C..=0x6F => pos,

        0x80 | 0x82 => {
            let l = modrm_span(code, pos)?;
            pos + l + 1
        }

        0x81 => {
            let l = modrm_span(code, pos)?;
            pos + l + if o16 { 2 } else { 4 }
        }

        0x83 => {
            let l = modrm_span(code, pos)?;
            pos + l + 1
        }

        0x84..=0x8F => pos + modrm_span(code, pos)?,

        0x90..=0x99 => pos,

        0x9A => {
            return Err(LifterError::UnsupportedInstruction(format!(
                "far call/jmp {:02X}",
                opcode
            )))
        }

        0x9B..=0x9F => pos,

        0xA0..=0xA3 => pos + if o16 { 2 } else if rex_w && is_64bit { 8 } else { 4 },

        0xA4..=0xA7 | 0xAA..=0xAF => pos,

        0xA8 => pos + 1,

        0xA9 => pos + if o16 { 2 } else { 4 },

        0xB0..=0xB7 => pos + 1,

        0xB8..=0xBF => pos + if rex_w && is_64bit { 8 } else if o16 { 2 } else { 4 },

        0xC0 | 0xC1 => {
            let l = modrm_span(code, pos)?;
            pos + l + 1
        }

        0xC2 => pos + 2,

        0xC3 => pos,

        0xC4 | 0xC5 => {
            if is_64bit {
                unreachable!()
            }
            pos + modrm_span(code, pos)?
        }

        0xC6 => {
            let l = modrm_span(code, pos)?;
            pos + l + 1
        }

        0xC7 => {
            let l = modrm_span(code, pos)?;
            pos + l + if o16 { 2 } else { 4 }
        }

        0xC8 => pos + 3,

        0xC9 | 0xCB | 0xCC | 0xCE | 0xCF | 0xF1 | 0xF4 | 0xF5 | 0xF8..=0xFD => pos,

        0xCA => pos + 2,

        0xCD => pos + 1,

        0xD0..=0xD3 => pos + modrm_span(code, pos)?,

        0xE0..=0xE3 | 0xEB => pos + 1,

        0xE4..=0xE7 => pos + 1,

        0xEC..=0xEF => pos,

        0xE8 | 0xE9 => pos + if o16 { 2 } else { 4 },

        0xEA => {
            return Err(LifterError::UnsupportedInstruction(format!(
                "far jmp {:02X}",
                opcode
            )))
        }

        0xFE | 0xFF => pos + modrm_span(code, pos)?,

        o @ (0xF6 | 0xF7) => {
            let l = modrm_span(code, pos)?;
            let digit = (code[pos] >> 3) & 7;
            let ib = if o == 0xF6 {
                1
            } else if o16 {
                2
            } else {
                4
            };
            let extra = if digit <= 1 { ib } else { 0 };
            pos + l + extra
        }

        other => {
            return Err(LifterError::UnsupportedInstruction(format!(
                "unknown opcode {:02X}",
                other
            )))
        }
    };

    if total > code.len() {
        return Err(lde_bad(total));
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(func: &IrFunction) -> String {
        let mut s = String::new();
        for b in &func.blocks {
            for i in &b.insts {
                s.push_str(&format!("{:?}\n", i));
            }
        }
        s
    }

    fn has_reg(s: &str, name: &str) -> bool {
        s.contains(&format!("name: \"{}\"", name))
    }

    fn has_op(s: &str, op: &str) -> bool {
        s.contains(&format!("op: {}", op))
    }

    #[test]
    fn test_lift_ret() {
        let lifter = X86Lifter::new(true);
        let code = [0xC3];
        let func = lifter.lift_function(&code, 0x1000, "test").unwrap();
        assert!(func.total_instructions() > 0);
    }

    #[test]
    fn test_lift_prologue_epilogue() {
        let lifter = X86Lifter::new(true);
        let code = [
            0x55,
            0x48, 0x89, 0xE5,
            0x90,
            0xC9,
            0xC3,
        ];
        let func = lifter.lift_function(&code, 0x401000, "main").unwrap();
        assert!(func.total_instructions() > 3);
    }

    #[test]
    fn test_lift_nop_sequence() {
        let lifter = X86Lifter::new(true);
        let code = [0x90, 0x90, 0x90, 0xC3];
        let func = lifter.lift_function(&code, 0x0, "nops").unwrap();
        assert!(func.total_instructions() >= 3);
    }

    #[test]
    fn test_lift_push_pop() {
        let lifter = X86Lifter::new(true);
        let code = [0x50, 0x5B, 0xC3];
        let func = lifter.lift_function(&code, 0x0, "test").unwrap();
        assert!(func.total_instructions() > 0);
    }

    #[test]
    fn test_registry() {
        use crate::lifter::LifterRegistry;
        let lifter = LifterRegistry::get("x86_64").unwrap();
        assert_eq!(lifter.arch_name(), "x86_64");
    }

    #[test]
    fn test_lde_length() {
        assert_eq!(lde_length(&[0xC3], true).ok(), Some(1));
        assert_eq!(lde_length(&[0x90], true).ok(), Some(1));
        assert_eq!(lde_length(&[0xE8, 0x00, 0x01, 0x00, 0x00], true).ok(), Some(5));
        assert_eq!(lde_length(&[0xEB, 0x10], true).ok(), Some(2));
        assert_eq!(lde_length(&[0x48, 0x83, 0xEC, 0x28], true).ok(), Some(4));
        assert_eq!(
            lde_length(&[0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00], true).ok(),
            Some(8)
        );
        assert!(lde_length(&[0xC5, 0xF8, 0x77], true).is_err());
        assert!(lde_length(&[0x0F, 0xFF], true).is_err());
        assert!(lde_length(&[0x48, 0x83, 0xEC], true).is_err());
    }

    #[test]
    fn test_rex_mov_r15d() {
        let lifter = X86Lifter::new(true);
        let code = [0x41, 0xBF, 0x0A, 0x00, 0x00, 0x00];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "r15d"), "expected r15d in:\n{}", d);
    }

    #[test]
    fn test_rex_mov_r15_imm64() {
        let lifter = X86Lifter::new(true);
        let code = [0x49, 0xBF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "r15"));
        assert!(d.contains("Int(64)"));
    }

    #[test]
    fn test_rex_w_add_rax_r8() {
        let lifter = X86Lifter::new(true);
        let code = [0x4C, 0x01, 0xC0];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Add"), "expected Add in:\n{}", d);
        assert!(has_reg(&d, "r8"), "expected r8 in:\n{}", d);
        assert!(has_reg(&d, "rax"));
    }

    #[test]
    fn test_o16_mov_ax_imm16() {
        let lifter = X86Lifter::new(true);
        let code = [0x66, 0xB8, 0x34, 0x12];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "ax"), "expected ax in:\n{}", d);
        assert!(d.contains("Int(16)"), "expected 16-bit operand:\n{}", d);
    }

    #[test]
    fn test_push_pop_r15() {
        let lifter = X86Lifter::new(true);
        let code = [0x41, 0x57, 0x41, 0x5F, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "r15"), "expected r15 in:\n{}", d);
    }

    #[test]
    fn test_imul_imm8() {
        let lifter = X86Lifter::new(true);
        let code = [0x48, 0x6B, 0xC8, 0x05, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Mul"), "expected Mul in:\n{}", d);
    }

    #[test]
    fn test_imul_imm32() {
        let lifter = X86Lifter::new(true);
        let code = [0x69, 0xDA, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Mul"));
        assert!(d.contains("Const(16)"), "imm32 operand expected:\n{}", d);
    }

    #[test]
    fn test_movzx() {
        let lifter = X86Lifter::new(true);
        let code = [0x0F, 0xB6, 0xC8, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Zext"), "expected Zext in:\n{}", d);
    }

    #[test]
    fn test_movsx_and_movsxd() {
        let lifter = X86Lifter::new(true);
        let code1 = [0x0F, 0xBE, 0xCA];
        let f1 = lifter.lift_function(&code1, 0x1000, "t").unwrap();
        assert!(has_op(&dump(&f1), "Sext"));

        let code2 = [0x48, 0x63, 0xD1];
        let f2 = lifter.lift_function(&code2, 0x1000, "t").unwrap();
        let d2 = dump(&f2);
        assert!(has_op(&d2, "Sext"));
        assert!(has_reg(&d2, "rdx"));
        assert!(has_reg(&d2, "ecx"));
    }

    #[test]
    fn test_setcc() {
        let lifter = X86Lifter::new(true);
        let code = [0x0F, 0x94, 0xC0, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("flag_zf"), "expected zf condition in:\n{}", d);
        assert!(has_reg(&d, "al"));
    }

    #[test]
    fn test_cmovcc() {
        let lifter = X86Lifter::new(true);
        let code = [0x48, 0x0F, 0x44, 0xCA, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("flag_zf"));
        assert!(has_op(&d, "Or"), "expected select lowering Or in:\n{}", d);
        assert!(has_reg(&d, "rcx"));
    }

    #[test]
    fn test_cmovcc_mask_is_full_width() {
        let lifter = X86Lifter::new(true);
        let code = [0x48, 0x0F, 0x44, 0xCA, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Sext"), "mask must come from Sext(cond):\n{}", d);
        assert!(
            !d.contains("Neg"),
            "Neg(Sext(cond)) keeps only the low bit — mask must be Sext(cond) directly:\n{}",
            d
        );
    }

    #[test]
    fn test_grp1_imm8_sub_rsp() {
        let lifter = X86Lifter::new(true);
        // sub rsp, 0x28
        let code = [0x48, 0x83, 0xEC, 0x28, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Sub"), "expected Sub in:\n{}", d);
        assert!(has_reg(&d, "rsp"));
        assert!(d.contains("Const(40)"), "sign-extended imm8 expected:\n{}", d);
    }

    #[test]
    fn test_grp1_imm32_add_ecx() {
        let lifter = X86Lifter::new(true);
        let code = [0x81, 0xC1, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Add"));
        assert!(has_reg(&d, "ecx"));
        assert!(d.contains("Const(16)"));
    }

    #[test]
    fn test_grp1_cmp_writes_flags_without_store() {
        let lifter = X86Lifter::new(true);
        // cmp rcx, 0x10
        let code = [0x48, 0x81, 0xF9, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Sub"), "cmp lowers to Sub + flags:\n{}", d);
        assert!(d.contains("flag_zf"));
    }

    #[test]
    fn test_grp1_imm8_memory_operand() {
        let lifter = X86Lifter::new(true);
        // add qword ptr [rbx], 5
        let code = [0x48, 0x83, 0x03, 0x05, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("Load"), "memory operand must be loaded:\n{}", d);
        assert!(d.contains("Store"), "result must be stored back:\n{}", d);
        assert!(has_op(&d, "Add"));
    }

    #[test]
    fn test_grp1_adc_sbb_consume_cf() {
        let lifter = X86Lifter::new(true);
        let adc = [0x48, 0x83, 0xD1, 0x05, 0xC3]; // adc rcx, 5
        let f = lifter.lift_function(&adc, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("flag_cf"));

        let sbb = [0x48, 0x83, 0xD9, 0x05, 0xC3]; // sbb rcx, 5
        let f = lifter.lift_function(&sbb, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("flag_cf"));
    }

    #[test]
    fn test_loop_decrements_counter_and_branches() {
        let lifter = X86Lifter::new(true);
        let code = [0xE2, 0xFE, 0xC3]; // loop $ (self-loop)
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(
            has_reg(&dump(&func), "rcx"),
            "LOOP must decrement rcx:\n{:?}",
            func.display()
        );
        assert!(matches!(
            func.block(func.entry_block).unwrap().terminator(),
            Some(IrInst::CBranch { .. })
        ));
    }

    #[test]
    fn test_loopnz_loopzd_jcxz_branch() {
        let lifter = X86Lifter::new(true);
        for opc in [0xE0u8, 0xE1, 0xE2, 0xE3] {
            let code = [opc, 0x02, 0xC3];
            let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
            assert!(
                matches!(
                    func.block(func.entry_block).unwrap().terminator(),
                    Some(IrInst::CBranch { .. })
                ),
                "opcode {:02X} must end in CBranch",
                opc
            );
        }
        // JCXZ compares the counter against zero.
        let jcxz = lifter.lift_function(&[0xE3, 0x02, 0xC3], 0x1000, "jcxz").unwrap();
        let d = dump(&jcxz);
        assert!(has_op(&d, "Eq"), "JCXZ must test counter == 0:\n{}", d);
    }

    #[test]
    fn test_int_imm_is_marked_nop() {
        let lifter = X86Lifter::new(true);
        let code = [0xCD, 0x80, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(dump(&func).contains("Nop"), "INT imm8 must leave an explicit marker");
    }

    #[test]
    fn test_decoded_but_unhandled_opcode_emits_nop() {
        // INC EAX (one-byte 0x40 in 32-bit mode) has no lifting model yet;
        // it must surface as Nop rather than silently vanish.
        let lifter = X86Lifter::new(false);
        let code = [0x40, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(dump(&func).contains("Nop"));
    }

    #[test]
    fn test_shl_imm8() {
        let lifter = X86Lifter::new(true);
        let code = [0xC1, 0xE0, 0x05, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Shl"), "expected Shl in:\n{}", d);
    }

    #[test]
    fn test_shift_group_forms() {
        let lifter = X86Lifter::new(true);

        let sar = [0x48, 0xC1, 0xF8, 0x02];
        let f = lifter.lift_function(&sar, 0x1000, "t").unwrap();
        assert!(has_op(&dump(&f), "Sar"));

        let shr_cl = [0xD3, 0xE8];
        let f = lifter.lift_function(&shr_cl, 0x1000, "t").unwrap();
        let d = dump(&f);
        assert!(has_op(&d, "Shr"));
        assert!(has_reg(&d, "cl"));

        let rol = [0xC1, 0xC0, 0x03];
        let f = lifter.lift_function(&rol, 0x1000, "t").unwrap();
        assert!(has_op(&dump(&f), "Rol"));

        let rcl = [0xC1, 0xD0, 0x03];
        // Unsupported shift (/2 = RCL) is skipped gracefully, not fatal.
        let f = lifter.lift_function(&rcl, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"));
    }

    #[test]
    fn test_neg_not() {
        let lifter = X86Lifter::new(true);
        let code = [0xF7, 0xD8, 0x90, 0xF7, 0xD0, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Neg"), "expected Neg in:\n{}", d);
        assert!(has_op(&d, "Not"), "expected Not in:\n{}", d);
    }

    #[test]
    fn test_leave() {
        let lifter = X86Lifter::new(true);
        let code = [0xC9, 0x90, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "rsp") && has_reg(&d, "rbp"));
    }

    #[test]
    fn test_vex_c5_skipped_gracefully() {
        let lifter = X86Lifter::new(true);
        // vzeroupper — unsupported but correctly sized by the LDE
        let code = [0xC5, 0xF8, 0x77, 0xC3];
        let f = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"), "VEX op must be skipped with a Nop");
    }

    #[test]
    fn test_vex_c4_skipped_gracefully() {
        let lifter = X86Lifter::new(true);
        let code = [0xC4, 0xE2, 0x75, 0x00, 0xC0];
        let f = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"));
    }

    #[test]
    fn test_f3_0f38_skipped_gracefully() {
        let lifter = X86Lifter::new(true);
        let code = [0xF3, 0x0F, 0x38, 0xF8, 0xC0];
        let f = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"));
    }

    #[test]
    fn test_endbr_syscall_rdtsc_nop() {
        let lifter = X86Lifter::new(true);

        let endbr = [0xF3, 0x0F, 0x1E, 0xFA, 0xC3];
        let f = lifter.lift_function(&endbr, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"));

        let sc = [0x0F, 0x05, 0xC3];
        let f = lifter.lift_function(&sc, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"));

        let rd = [0x0F, 0x31, 0xC3];
        let f = lifter.lift_function(&rd, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("Nop"));
    }

    #[test]
    fn test_adc_sbb_explicit_semantics() {
        let lifter = X86Lifter::new(true);
        let adc = [0x48, 0x11, 0xD8, 0xC3];
        let f = lifter.lift_function(&adc, 0x1000, "t").unwrap();
        let d = dump(&f);
        assert!(d.contains("flag_cf"), "ADC must consume CF:\n{}", d);

        let sbb = [0x48, 0x19, 0xD8, 0xC3];
        let f = lifter.lift_function(&sbb, 0x1000, "t").unwrap();
        assert!(dump(&f).contains("flag_cf"));
    }

    #[test]
    fn test_mem_operand_sib_index_scale() {
        let lifter = X86Lifter::new(true);
        let code = [0x42, 0x8B, 0x04, 0x9B, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "rbx"), "base expected:\n{}", d);
        assert!(has_reg(&d, "r11"), "REX.X index expected:\n{}", d);
        assert!(d.contains("Mul"), "scaled index expected:\n{}", d);
    }

    #[test]
    fn test_mem_operand_rexb_base() {
        let lifter = X86Lifter::new(true);
        let code = [0x41, 0x8B, 0x46, 0x08, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "r14"), "REX.B base expected:\n{}", d);
        assert!(d.contains("Load"));
    }

    #[test]
    fn test_mem_operand_disp32_no_rexb() {
        let lifter = X86Lifter::new(true);
        let code = [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("Load"), "RIP-relative load expected:\n{}", d);
    }

    #[test]
    fn test_unknown_opcode_errors() {
        let lifter = X86Lifter::new(true);
        let code = [0xD8, 0x05];
        let err = lifter.lift_function(&code, 0x1000, "t").unwrap_err();
        assert!(matches!(err, LifterError::UnsupportedInstruction(_)));
    }

    #[test]
    fn test_lde_matches_lifter_coverage() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x48, 0x89, 0xE5],
            vec![0x48, 0x8B, 0x45, 0x10],
            vec![0x41, 0xB8, 0x01, 0x00, 0x00, 0x00],
            vec![0x49, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x66, 0x89, 0xC1],
            vec![0x68, 0x01, 0x02, 0x03, 0x04],
            vec![0x6A, 0x10],
            vec![0x48, 0x69, 0xC0, 0x05, 0x00, 0x00, 0x00],
            vec![0x84, 0xC0],
            vec![0x86, 0xE1],
            vec![0x8D, 0x44, 0x24, 0x08],
            vec![0x98],
            vec![0x99],
            vec![0xA8, 0x01],
            vec![0xA9, 0x01, 0x02, 0x03, 0x04],
            vec![0xB0, 0x11],
            vec![0x40, 0xB6, 0x11],
            vec![0xC6, 0x45, 0x10, 0x22],
            vec![0xC7, 0x45, 0x10, 0x22, 0x22, 0x22, 0x22],
            vec![0xC9],
            vec![0x0F, 0xAF, 0xC1],
            vec![0x0F, 0xB7, 0xC1],
            vec![0x63, 0xC1],
            vec![0x0F, 0x1E, 0xFA],
            vec![0x0F, 0x05],
            vec![0x0F, 0x31],
            vec![0x0F, 0x93, 0xC0],
            vec![0x48, 0x0F, 0x42, 0xCA],
            vec![0xFF, 0x15, 0x10, 0x00, 0x00, 0x00],
            vec![0xFF, 0x25, 0x10, 0x00, 0x00, 0x00],
            vec![0xFE, 0xC0],
            vec![0xF7, 0x18],
        ];
        for c in &cases {
            let r = lde_length(c, true);
            assert!(r.is_ok(), "lde failed on {:02X?}: {:?}", c, r.err());
            let lifter = X86Lifter::new(true);
            let res = lifter.lift_function(c, 0x1000, "cov");
            match res {
                Ok(_) => {}
                Err(e) => match e {
                    LifterError::UnsupportedInstruction(_) => {}
                    other => panic!("unexpected error for {:02X?}: {}", c, other),
                },
            }
        }
    }

    // ─── Sub-register aliasing ──────────────────────────────────────────

    #[test]
    fn test_al_write_updates_wide_parent() {
        // mov al, 0x11 must stay visible to wider reads of rax/eax.
        let lifter = X86Lifter::new(true);
        let code = [0xB0, 0x11, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_reg(&d, "al"), "narrow view must be written:\n{}", d);
        assert!(
            has_reg(&d, "rax") || has_reg(&d, "eax"),
            "parent register must receive the RMW merge:\n{}",
            d
        );
        assert!(has_op(&d, "Or"), "merge must OR the field into the parent:\n{}", d);
    }

    #[test]
    fn test_ax_write_merge_masks() {
        // 66 B8 34 12: mov ax, 0x1234 -> rax = (rax & ~0xFFFF) | 0x1234.
        let lifter = X86Lifter::new(true);
        let code = [0x66, 0xB8, 0x34, 0x12, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("Const(-65536)"), "keep-mask expected:\n{}", d);
        assert!(d.contains("Const(4660)"), "field value 0x1234 expected:\n{}", d);
        assert!(has_reg(&d, "rax"), "merge target must be rax:\n{}", d);
    }

    #[test]
    fn test_eax_write_zeroes_upper_32() {
        // B8 imm32: writing eax clears rax[63:32] (zero-extension).
        let lifter = X86Lifter::new(true);
        let code = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(has_op(&d, "Zext"), "eax write must zero-extend into rax:\n{}", d);
        assert!(has_reg(&d, "rax"), "widened value must land in rax:\n{}", d);
        assert!(has_reg(&d, "eax"));
    }

    #[test]
    fn test_ah_write_shifts_field() {
        // B7 20: mov bh, 0x20 -> rbx = (rbx & ~0xFF00) | 0x2000.
        let lifter = X86Lifter::new(true);
        let code = [0xB7, 0x20, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("Const(8192)"), "field shifted by 8 expected:\n{}", d);
        assert!(has_reg(&d, "rbx"), "bh merge target must be rbx:\n{}", d);
    }

    // ─── ALU flag modeling ──────────────────────────────────────────────

    #[test]
    fn test_add_writes_all_flags() {
        // add rax, 5 defines ZF/SF/CF/OF/PF.
        let lifter = X86Lifter::new(true);
        let code = [0x48, 0x83, 0xC0, 0x05, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        for f in ["flag_zf", "flag_sf", "flag_cf", "flag_of", "flag_pf"] {
            assert!(d.contains(f), "ADD must define {}:\n{}", f, d);
        }
    }

    #[test]
    fn test_logical_ops_clear_cf_of() {
        // AND/OR/XOR define ZF/SF/PF from the result and clear CF/OF.
        let cases: [[u8; 4]; 3] =
            [[0x48, 0x83, 0xE0, 0x05], [0x48, 0x83, 0xC8, 0x05], [0x48, 0x83, 0xF0, 0x05]];
        for c in &cases {
            let lifter = X86Lifter::new(true);
            let mut code = c.to_vec();
            code.push(0xC3);
            let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
            let d = dump(&func);
            for f in ["flag_zf", "flag_sf", "flag_cf", "flag_of", "flag_pf"] {
                assert!(d.contains(f), "{:02X?} must define {}:\n{}", c, f, d);
            }
        }
    }

    #[test]
    fn test_test_writes_flags_without_result_store() {
        // test al, al computes flags only.
        let lifter = X86Lifter::new(true);
        let code = [0x84, 0xC0, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("flag_zf"), "TEST must define ZF:\n{}", d);
        assert!(d.contains("flag_cf"), "TEST must clear CF:\n{}", d);
    }

    #[test]
    fn test_inc_dec_preserve_cf() {
        // INC/DEC update ZF/SF/OF/PF but never touch CF.
        let lifter = X86Lifter::new(true);

        let inc = lifter.lift_function(&[0xFE, 0xC0, 0xC3], 0x1000, "inc").unwrap();
        let d = dump(&inc);
        assert!(d.contains("flag_zf"), "INC must define ZF:\n{}", d);
        assert!(d.contains("flag_of"), "INC must define OF:\n{}", d);
        assert!(!d.contains("flag_cf"), "INC must preserve CF (no def):\n{}", d);

        let dec = lifter.lift_function(&[0xFE, 0xC8, 0xC3], 0x1000, "dec").unwrap();
        let d = dump(&dec);
        assert!(d.contains("flag_zf"), "DEC must define ZF:\n{}", d);
        assert!(d.contains("flag_of"), "DEC must define OF:\n{}", d);
        assert!(!d.contains("flag_cf"), "DEC must preserve CF (no def):\n{}", d);
    }

    // ─── CALL / RET stack semantics ─────────────────────────────────────

    #[test]
    fn test_call_pushes_return_address() {
        // call rel5 at 0x1000: rsp -= 8 and the return address (0x100A)
        // is stored at [rsp]; the callee symbol resolves to sub_100A.
        let lifter = X86Lifter::new(true);
        let code = [0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("sub_100A"), "callee target expected:\n{}", d);
        assert!(has_op(&d, "Sub"), "push must decrement rsp:\n{}", d);
        assert!(d.contains("Const(8)"), "64-bit push delta expected:\n{}", d);
        assert!(d.contains("Store"), "return address must be stored:\n{}", d);
    }

    #[test]
    fn test_ret_imm16_zero_extension() {
        // ret 0x8000 pops 32768 bytes, not -32768.
        let lifter = X86Lifter::new(true);
        let code = [0xC2, 0x00, 0x80];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("Const(32768)"), "imm16 must zero-extend:\n{}", d);
        assert!(!d.contains("-32768"), "imm16 must not sign-extend:\n{}", d);
    }
}
