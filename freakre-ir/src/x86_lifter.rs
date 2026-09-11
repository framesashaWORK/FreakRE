use crate::ir::{BlockId, IrBlock, IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

pub struct X86Lifter {
    is_64bit: bool,
    max_instructions: usize,
    /// Optional image context for jump-table recovery: (virtual address в†’
    /// bytes). Only used to *read* dispatch tables; lifting never executes
    /// or re-decodes image content outside the recovered targets.
    image: Option<ImageCtx>,
}

/// Read-only view of the binary image for jump-table recovery.
#[derive(Debug, Clone)]
pub struct ImageCtx {
    /// Sections as (vaddr, size) вЂ” vaddrв†’offset resolution via containment.
    sections: Vec<(u64, u64)>,
    /// Image base (VA of the first mapped byte in `bytes[0]` coordinate).
    image_base: u64,
    /// Image base expressed in the LIFTER'S coordinate space (the same
    /// space as `base_address` / rip-relative consts). Defaults to
    /// `image_base`; set to 0 when functions are lifted in RVA space.
    coord_base: u64,
    /// The mapped image bytes, starting at `image_base`.
    bytes: Vec<u8>,
}

impl ImageCtx {
    /// Build from section list + raw image bytes (offset 0 = `image_base`).
    pub fn new(sections: Vec<(u64, u64)>, image_base: u64, bytes: Vec<u8>) -> Self {
        ImageCtx {
            sections,
            coord_base: image_base,
            image_base,
            bytes,
        }
    }

    /// Override the coordinate base for lifters running in a different
    /// address space (e.g. RVA space while the file is at a real base).
    pub fn in_coord_base(mut self, coord_base: u64) -> Self {
        self.coord_base = coord_base;
        self
    }

    /// Resolve a virtual address to a byte slice if it lies inside a mapped
    /// section and the full `len` window is present.
    fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let off = va.checked_sub(self.coord_base)?;
        for &(sva, ssize) in &self.sections {
            if off >= sva && off < sva.checked_add(ssize)? {
                let start = off as usize;
                let end = start.checked_add(len)?;
                return self.bytes.get(start..end);
            }
        }
        None
    }

    /// Read `size` bytes (4 or 8) at a virtual address as a little-endian
    /// unsigned value.
    fn read_ptr(&self, va: u64, size: u64) -> Option<u64> {
        let b = self.read(va, size as usize)?;
        match size {
            4 => Some(u32::from_le_bytes(b.try_into().ok()?) as u64),
            8 => Some(u64::from_le_bytes(b.try_into().ok()?)),
            _ => None,
        }
    }

    /// Read a little-endian pointer-sized value.
    fn read_u64(&self, va: u64) -> Option<u64> {
        let b = self.read(va, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }
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

/// GPR register classes: canonical 64-bit name → every alias that overlaps it.
/// One entry per calling-convention slot (rcx, rdx, r8, r9).
const X64_ARG_SLOTS: [(&str, [&str; 5]); 4] = [
    ("rcx", ["rcx", "ecx", "cx", "cl", "ch"]),
    ("rdx", ["rdx", "edx", "dx", "dl", "dh"]),
    ("r8", ["r8", "r8d", "r8w", "r8b", "r8b"]),
    ("r9", ["r9", "r9d", "r9w", "r9b", "r9b"]),
];

/// GPR alias sets for a slot, where slot 0..1 are the classic regs
/// (ecx/edx for 32-bit code) and 2..3 are r8/r9 (x64 only).
const X86_ARG_SLOTS: [(&str, [&str; 4]); 4] = [
    ("ecx", ["ecx", "cx", "cl", "ch"]),
    ("edx", ["edx", "dx", "dl", "dh"]),
    ("r8", ["r8", "r8d", "r8w", "r8b"]),
    ("r9", ["r9", "r9d", "r9w", "r9b"]),
];

/// Values written by `inst` (dst operands, if any).
fn writes_of(inst: &IrInst) -> impl Iterator<Item = &Value> {
    let v: Vec<&Value> = match inst {
        IrInst::Binary { dst, .. }
        | IrInst::Unary { dst, .. }
        | IrInst::Load { dst, .. } => vec![dst],
        IrInst::Call { dst, .. } => dst.as_ref().into_iter().collect(),
        _ => Vec::new(),
    };
    v.into_iter()
}

/// The argument value a write to `canonical` register contributes:
/// `Copy(dst, src)` contributes `src` (register moves stay inline),
/// anything else contributes the destination variable itself.
/// The caller scans backwards, so the first hit is the live value.
fn arg_value_for_slot(inst: &IrInst, canonical: &str) -> Option<Value> {
    for w in writes_of(inst) {
        if write_reg_names_of(w).any(|n| n == canonical) {
            return match inst {
                IrInst::Unary {
                    op: OpCode::Copy,
                    dst: _,
                    src,
                } => Some(src.clone()),
                _ => Some(w.clone()),
            };
        }
    }
    None
}

/// The instruction in `blk` that defines `v` (last one wins).
fn def_of<'a>(blk: &'a IrBlock, v: &Value) -> Option<&'a IrInst> {
    blk.insts
        .iter()
        .rev()
        .find(|inst| writes_of(inst).any(|d| d == v))
}

/// Canonical register name behind a register `Value` (64-bit spelling).
fn canonical_reg(v: &Value) -> Option<&'static str> {
    match v {
        Value::Register { name, .. } => Some(match name.as_str() {
            "rax" | "eax" | "ax" | "al" | "ah" => "rax",
            "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
            "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
            "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
            "rsp" | "esp" | "sp" | "spl" => "rsp",
            "rbp" | "ebp" | "bp" | "bpl" => "rbp",
            "rsi" | "esi" | "si" | "sil" => "rsi",
            "rdi" | "edi" | "di" | "dil" => "rdi",
            "r8" | "r8d" | "r8w" | "r8b" => "r8",
            "r9" | "r9d" | "r9w" | "r9b" => "r9",
            "r10" | "r10d" | "r10w" | "r10b" => "r10",
            "r11" | "r11d" | "r11w" | "r11b" => "r11",
            "r12" | "r12d" | "r12w" | "r12b" => "r12",
            "r13" | "r13d" | "r13w" | "r13b" => "r13",
            "r14" | "r14d" | "r14w" | "r14b" => "r14",
            "r15" | "r15d" | "r15w" | "r15b" => "r15",
            "rip" | "eip" => "rip",
            _ if name.starts_with("flag_") => "flags",
            _ => "other",
        }),
        _ => None,
    }
}

/// Register names written by a value that is a write destination
/// (canonical 64-bit spellings).
fn write_reg_names_of(v: &Value) -> impl Iterator<Item = &'static str> {
    let names: Vec<&'static str> = canonical_reg(v)
        .map(|n| {
            if n == "other" {
                Vec::new()
            } else {
                vec![n]
            }
        })
        .unwrap_or_default();
    names.into_iter()
}

/// Register names read by `inst` (canonical 64-bit spellings).
fn read_reg_names(inst: &IrInst) -> Vec<&'static str> {
    inst.sources()
        .into_iter()
        .filter_map(canonical_reg)
        .collect()
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

/// Alias table for nested x86 registers (al/ah/ax/eax/... в†’ widest parent).
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
        return Some(SubregWrite {
            parent_idx: idx,
            offset: off,
            width: bits,
            zero_high: false,
        });
    }
    if !is_64bit {
        // 32-bit mode: the e-names already are the widest view.
        return None;
    }
    const LEGACY32: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    if let Some(idx) = LEGACY32.iter().position(|&n| n == name) {
        return Some(SubregWrite {
            parent_idx: idx as u8,
            offset: 0,
            width: 32,
            zero_high: true,
        });
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
        "b" => Some(SubregWrite {
            parent_idx: idx,
            offset: 0,
            width: 8,
            zero_high: false,
        }),
        "w" => Some(SubregWrite {
            parent_idx: idx,
            offset: 0,
            width: 16,
            zero_high: false,
        }),
        "d" => Some(SubregWrite {
            parent_idx: idx,
            offset: 0,
            width: 32,
            zero_high: true,
        }),
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
        func.push_inst(
            block,
            IrInst::Load {
                dst: v.clone(),
                addr,
                size: bits / 8,
            },
        );
        v
    }

    fn store(
        &self,
        lifter: &X86Lifter,
        func: &mut IrFunction,
        block: BlockId,
        val: Value,
        bits: u32,
    ) {
        if let Some(r) = &self.reg {
            lifter.write_reg(func, block, r, OpCode::Copy, val, bits);
        } else {
            let addr = self.addr.clone().unwrap_or(Value::Const(0));
            func.push_inst(
                block,
                IrInst::Store {
                    addr,
                    value: val,
                    size: bits / 8,
                },
            );
        }
    }
}

impl X86Lifter {
    pub fn new(is_64bit: bool) -> Self {
        X86Lifter {
            is_64bit,
            max_instructions: 100_000,
            image: None,
        }
    }

    /// Attach an image context so jump-table recovery can read dispatch
    /// tables out of the binary. Without it, `FF /4` lifts to `IndirectBranch`.
    pub fn with_image(mut self, image: ImageCtx) -> Self {
        self.image = Some(image);
        self
    }

    fn ptr_bits(&self) -> u32 {
        if self.is_64bit {
            64
        } else {
            32
        }
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
        Value::Register {
            name: name.to_string(),
            ty: Ty::i64(),
        }
    }

    fn flag(&self, name: &str) -> Value {
        Value::Register {
            name: format!("flag_{}", name),
            ty: Ty::Bool,
        }
    }

    fn flag_cmp(&self, func: &mut IrFunction, block: BlockId, op: OpCode, name: &str) -> Value {
        let cond = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            cond.clone(),
            op,
            self.flag(name),
            Value::Const(1),
        );
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

    fn combine(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        op: OpCode,
        a: Value,
        b: Value,
    ) -> Value {
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
                let r = func.alloc_var(int_ty(bits));
                func.push_inst(
                    block,
                    IrInst::Adc {
                        dst: r.clone(),
                        a: a.clone(),
                        b: b.clone(),
                        carry: self.flag("cf"),
                    },
                );
                r
            }
            AluKind::Sbb => {
                let r = func.alloc_var(int_ty(bits));
                func.push_inst(
                    block,
                    IrInst::Sbb {
                        dst: r.clone(),
                        a: a.clone(),
                        b: b.clone(),
                        carry: self.flag("cf"),
                    },
                );
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
        push_bin(
            func,
            block,
            self.flag("zf"),
            OpCode::Eq,
            a.clone(),
            b.clone(),
        );
        push_bin(
            func,
            block,
            self.flag("cf"),
            OpCode::LtU,
            a.clone(),
            b.clone(),
        );
        push_bin(
            func,
            block,
            self.flag("sf"),
            OpCode::LtS,
            a.clone(),
            b.clone(),
        );
    }

    /// Write `op(src)` into register `dst`, keeping x86 sub-register
    /// aliases coherent.
    ///
    /// Design (stays within the existing IR ops): the narrow-name copy is
    /// emitted unchanged so narrow readers still see the write, and the
    /// value is additionally merged into the widest enclosing parent via a
    /// masked read-modify-write вЂ” `parent = (parent & !field) | value_field`
    /// вЂ” so later wider reads observe it too. 32-bit writes in 64-bit mode
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
        let field = if info.width >= 64 {
            u64::MAX
        } else {
            (1u64 << info.width) - 1
        };
        let keep = (!field << info.offset) as i64;
        let preserved = func.alloc_var(int_ty(pbits));
        push_bin(
            func,
            block,
            preserved.clone(),
            OpCode::And,
            parent.clone(),
            Value::Const(keep),
        );
        let field_val: Value = match src {
            Value::Const(c) => Value::Const((((c as u64) & field) << info.offset) as i64),
            v => {
                let masked = func.alloc_var(int_ty(pbits));
                push_bin(
                    func,
                    block,
                    masked.clone(),
                    OpCode::And,
                    v,
                    Value::Const(field as i64),
                );
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
        push_bin(
            func,
            block,
            merged.clone(),
            OpCode::Or,
            preserved,
            field_val,
        );
        push_un(func, block, parent, OpCode::Copy, merged);
    }

    /// PF: parity of the result's low byte (set when it holds an even
    /// number of set bits). The IR has no popcount, so fold the byte down
    /// with a xor-tree and test the surviving bit.
    fn write_pf(&self, func: &mut IrFunction, block: BlockId, result: &Value) {
        let pb = self.ptr_bits();
        let mut cur = func.alloc_var(int_ty(pb));
        push_bin(
            func,
            block,
            cur.clone(),
            OpCode::And,
            result.clone(),
            Value::Const(0xFF),
        );
        for sh in [4i64, 2, 1] {
            let hi = func.alloc_var(int_ty(pb));
            push_bin(
                func,
                block,
                hi.clone(),
                OpCode::Shr,
                cur.clone(),
                Value::Const(sh),
            );
            let next = func.alloc_var(int_ty(pb));
            push_bin(func, block, next.clone(), OpCode::Xor, cur, hi);
            cur = next;
        }
        let low = func.alloc_var(int_ty(pb));
        push_bin(func, block, low.clone(), OpCode::And, cur, Value::Const(1));
        push_bin(
            func,
            block,
            self.flag("pf"),
            OpCode::Eq,
            low,
            Value::Const(0),
        );
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
        push_bin(
            func,
            block,
            self.flag("zf"),
            OpCode::Eq,
            result.clone(),
            Value::Const(0),
        );
        push_bin(
            func,
            block,
            self.flag("sf"),
            OpCode::LtS,
            result.clone(),
            Value::Const(0),
        );
        push_bin(
            func,
            block,
            self.flag("cf"),
            OpCode::LtU,
            result.clone(),
            a.clone(),
        );
        let neg_a = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            neg_a.clone(),
            OpCode::LtS,
            a.clone(),
            Value::Const(0),
        );
        let neg_b = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            neg_b.clone(),
            OpCode::LtS,
            b.clone(),
            Value::Const(0),
        );
        let neg_r = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            neg_r.clone(),
            OpCode::LtS,
            result.clone(),
            Value::Const(0),
        );
        let same_signs = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            same_signs.clone(),
            OpCode::Eq,
            neg_a.clone(),
            neg_b,
        );
        let sign_flips = func.alloc_var(Ty::Bool);
        push_bin(func, block, sign_flips.clone(), OpCode::Ne, neg_r, neg_a);
        push_bin(
            func,
            block,
            self.flag("of"),
            OpCode::And,
            same_signs,
            sign_flips,
        );
        self.write_pf(func, block, result);
    }

    /// Logical-group flags (AND/OR/XOR/TEST): CF and OF are cleared,
    /// ZF/SF/PF derive from the result.
    fn write_logic_flags(&self, func: &mut IrFunction, block: BlockId, result: &Value) {
        push_un(func, block, self.flag("cf"), OpCode::Copy, Value::Const(0));
        push_un(func, block, self.flag("of"), OpCode::Copy, Value::Const(0));
        push_bin(
            func,
            block,
            self.flag("zf"),
            OpCode::Eq,
            result.clone(),
            Value::Const(0),
        );
        push_bin(
            func,
            block,
            self.flag("sf"),
            OpCode::LtS,
            result.clone(),
            Value::Const(0),
        );
        self.write_pf(func, block, result);
    }

    /// INC/DEC flags: ZF/SF/OF/PF as usual but CF is deliberately left
    /// untouched вЂ” the one way INC/DEC differ from ADD/SUB.
    fn write_incdec_flags(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        a: &Value,
        result: &Value,
        is_inc: bool,
    ) {
        push_bin(
            func,
            block,
            self.flag("zf"),
            OpCode::Eq,
            result.clone(),
            Value::Const(0),
        );
        push_bin(
            func,
            block,
            self.flag("sf"),
            OpCode::LtS,
            result.clone(),
            Value::Const(0),
        );
        let neg_a = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            neg_a.clone(),
            OpCode::LtS,
            a.clone(),
            Value::Const(0),
        );
        let neg_r = func.alloc_var(Ty::Bool);
        push_bin(
            func,
            block,
            neg_r.clone(),
            OpCode::LtS,
            result.clone(),
            Value::Const(0),
        );
        if is_inc {
            // OF: positive operand wraps to negative (a was MAX).
            let non_neg = func.alloc_var(Ty::Bool);
            push_bin(
                func,
                block,
                non_neg.clone(),
                OpCode::Eq,
                neg_a,
                Value::Const(0),
            );
            push_bin(func, block, self.flag("of"), OpCode::And, non_neg, neg_r);
        } else {
            // OF: negative operand wraps to non-negative (a was MIN).
            let non_neg_r = func.alloc_var(Ty::Bool);
            push_bin(
                func,
                block,
                non_neg_r.clone(),
                OpCode::Eq,
                neg_r,
                Value::Const(0),
            );
            push_bin(func, block, self.flag("of"), OpCode::And, neg_a, non_neg_r);
        }
        self.write_pf(func, block, result);
    }

    /// Calling-convention arguments for a call at the end of `block`.
    ///
    /// x64 (MS ABI): the four register slots rcx/rdx/r8/r9. A slot appears
    /// when its register (or an alias) has a live definition in the block —
    /// either written before the call or read before any write (the value
    /// was prepared outside this block). Holes up to the highest defined
    /// slot are filled with the bare register so argument positions stay
    /// stable; if no slot has evidence the list stays empty.
    ///
    /// x86-32 (cdecl): stack arguments pushed before the call, in push
    /// order reversed (arg0 is the last push). The synthetic return-address
    /// push the lifter models right before the call is excluded.
    fn call_args(&self, func: &IrFunction, block: BlockId) -> Vec<Value> {
        let blk = func.block(block);
        let Some(blk) = blk else {
            return Vec::new();
        };
        if self.is_64bit {
            let names: Vec<&str> = X64_ARG_SLOTS.iter().map(|(c, _)| *c).collect();
            let defs = X86Lifter::arg_defs(func, blk, &names);
            let Some(max_slot) = defs.iter().rposition(|d| d.is_some()) else {
                return Vec::new();
            };
            (0..=max_slot)
                .map(|i| {
                    defs[i].clone().unwrap_or_else(|| {
                        let (canon, _) = X64_ARG_SLOTS[i];
                        Value::Register {
                            name: canon.to_string(),
                            ty: int_ty(64),
                        }
                    })
                })
                .collect()
        } else {
            let pb = self.ptr_bits() as usize;
            // Walk backwards; collect push-shaped stores. Each emit_push is
            // `tmp = rsp - size; [tmp] = val; rsp = tmp`, so the store's
            // address is a temp defined by Sub(sp, const).
            let mut args: Vec<Value> = Vec::new();
            let mut ret_push_skipped = false;
            let mut saw_current_call = false;
            for inst in blk.insts.iter().rev() {
                if let IrInst::Call { .. } = inst {
                    if saw_current_call {
                        break; // a previous call: its pushes are not ours
                    }
                    saw_current_call = true; // the call itself: keep scanning
                    continue;
                }
                if let IrInst::Store { addr, value, size } = inst {
                    if *size as usize != pb / 8 {
                        continue;
                    }
                    let is_push = matches!(
                        def_of(blk, addr),
                        Some(IrInst::Binary {
                            op: OpCode::Sub,
                            ..
                        })
                    );
                    if !is_push {
                        continue;
                    }
                    if !ret_push_skipped {
                        // The nearest store before the call is the modeled
                        // return address, not an argument.
                        ret_push_skipped = true;
                        continue;
                    }
                    args.push(value.clone());
                    if args.len() >= 4 {
                        break;
                    }
                }
            }
            // Reverse scan order already yields arg0 (last push) first.
            args
        }
    }

    /// Last definitions of the calling-convention argument registers,
    /// scanned backwards from the end of `block`.
    ///
    /// A register counts as defined when it was *written* (dst of a write
    /// to any of its aliases) after its last *read* (any use, because
    /// `read_reg_names` covers the full alias set). Scanning backwards and
    /// taking the first "written and not read since" event therefore gives
    /// exactly the value live at the call.
    fn arg_defs(
        func: &IrFunction,
        block: &IrBlock,
        names: &[&str],
    ) -> Vec<Option<Value>> {
        let mut res: Vec<Option<Value>> = vec![None; names.len()];
        let mut defined = vec![false; names.len()];
        for inst in block.insts.iter().rev() {
            let reads = read_reg_names(inst);
            for (slot, canonical) in names.iter().enumerate() {
                if defined[slot] {
                    continue;
                }
                // A write for this slot decides the argument value: a
                // plain copy contributes its source, everything else the
                // computed destination variable. This also covers
                // read-modify-write (`add rax, 1`): the consumed value
                // came from outside, but the *argument* is the result.
                if let Some(argval) = arg_value_for_slot(inst, canonical) {
                    res[slot] = Some(argval);
                    defined[slot] = true;
                    continue;
                }
                if reads.iter().any(|n| n == canonical) {
                    // Read after its last write: value came from outside
                    // the block (pre-call or caller state).
                    defined[slot] = true;
                }
            }
            let _ = func;
        }
        res
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
        func.push_inst(
            block,
            IrInst::Store {
                addr: tmp.clone(),
                value: val,
                size: bits / 8,
            },
        );
        push_un(func, block, sp, OpCode::Copy, tmp);
    }

    fn emit_pop(&self, func: &mut IrFunction, block: BlockId, dst: Value, bits: u32) {
        let pb = self.ptr_bits();
        let sp = reg_value(4, pb, false);
        let ld = func.alloc_var(int_ty(bits));
        func.push_inst(
            block,
            IrInst::Load {
                dst: ld.clone(),
                addr: sp.clone(),
                size: bits / 8,
            },
        );
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
                    push_bin(
                        func,
                        block,
                        t.clone(),
                        OpCode::Mul,
                        iv,
                        Value::Const(scale as i64),
                    );
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
                    push_bin(
                        func,
                        block,
                        t.clone(),
                        OpCode::Add,
                        base_val,
                        Value::Const(d),
                    );
                    (t, 2)
                }
                _ => {
                    let d = read_i32(after, 0);
                    let t = func.alloc_var(pty);
                    push_bin(
                        func,
                        block,
                        t.clone(),
                        OpCode::Add,
                        base_val,
                        Value::Const(d),
                    );
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
            let (addr, len) = self.address_of_rm(
                func,
                block,
                code,
                op_pos,
                insn_addr,
                rex_x,
                rex_b,
                trailing_imm,
            )?;
            Ok(RmLoc {
                reg: None,
                addr: Some(addr),
                len,
            })
        }
    }

    fn try_lift_prologue(&self, func: &mut IrFunction, block: BlockId, code: &[u8]) -> usize {
        if code.len() < 4 {
            return 0;
        }
        if code[0] == 0x55 {
            let rsp = self.reg64("rsp");
            let new_rsp = func.alloc_var(Ty::i64());

            push_bin(
                func,
                block,
                new_rsp.clone(),
                OpCode::Sub,
                rsp.clone(),
                Value::int(8),
            );
            func.push_inst(
                block,
                IrInst::Store {
                    addr: new_rsp.clone(),
                    value: self.reg64("rbp"),
                    size: 8,
                },
            );
            push_un(func, block, rsp, OpCode::Copy, new_rsp);

            if code[1] == 0x48 && code[2] == 0x89 && code[3] == 0xE5 {
                push_un(
                    func,
                    block,
                    self.reg64("rbp"),
                    OpCode::Copy,
                    self.reg64("rsp"),
                );
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

            func.push_inst(
                block,
                IrInst::Load {
                    dst: old_rbp.clone(),
                    addr: rsp.clone(),
                    size: 8,
                },
            );
            push_bin(
                func,
                block,
                new_rsp.clone(),
                OpCode::Add,
                rsp,
                Value::int(8),
            );
            push_un(func, block, self.reg64("rsp"), OpCode::Copy, new_rsp);
            push_un(func, block, self.reg64("rbp"), OpCode::Copy, old_rbp);
            func.push_inst(
                block,
                IrInst::Return {
                    value: Some(self.reg64("rax")),
                },
            );
            return 1;
        }

        if code[0] == 0xC9 && code.len() >= 2 && code[1] == 0xC3 {
            push_un(
                func,
                block,
                self.reg64("rsp"),
                OpCode::Copy,
                self.reg64("rbp"),
            );
            let old_rbp = func.alloc_var(Ty::i64());
            func.push_inst(
                block,
                IrInst::Load {
                    dst: old_rbp.clone(),
                    addr: self.reg64("rsp"),
                    size: 8,
                },
            );
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
            func.push_inst(
                block,
                IrInst::Return {
                    value: Some(self.reg64("rax")),
                },
            );
            return 2;
        }

        0
    }

    /// Recover jump-table switches from `FF /4` (jmp [table + reg*scale])
    /// dispatches.
    ///
    /// Compiler shape:
    /// ```text
    ///     cmp  reg, N
    ///     ja   default            ; or jae (Ne cf) form
    ///     jmp  qword [table + reg*8]   ; table base = disp32 or lea-resolved
    /// ```
    /// For every block ending in `IndirectBranch` the pass:
    /// 1. parses the load address into (table_va, index, scale),
    /// 2. finds the unsigned bounds guard (ja / jae) within two predecessor
    ///    hops and derives the entry count from it,
    /// 3. reads the entries from the attached image and validates every
    ///    target against the function's lifted extent,
    /// 4. reuses existing blocks at exact target addresses or lifts the case
    ///    body into fresh blocks,
    /// 5. rewrites the terminator into `IrInst::Switch` (no default arm вЂ”
    ///    the guard edge already covers out-of-range).
    ///
    /// Any doubt leaves the IndirectBranch untouched: soundness over
    /// coverage.
    fn recover_jump_tables(
        &self,
        func: &mut IrFunction,
        code: &[u8],
        base_address: u64,
    ) -> usize {
        let Some(image) = &self.image else {
            return 0;
        };

        // Reusable blocks keyed by exact start address.
        let mut starts: std::collections::HashMap<u64, BlockId> =
            std::collections::HashMap::new();
        for b in &func.blocks {
            if b.insts.is_empty() {
                continue;
            }
            if let Some(addr) = parse_block_addr(&b.label, base_address) {
                starts.insert(addr, b.id);
            }
        }

        let sites: Vec<BlockId> = func
            .blocks
            .iter()
            .filter(|b| matches!(b.terminator(), Some(IrInst::IndirectBranch { .. })))
            .map(|b| b.id)
            .collect();

        let mut recovered = 0usize;
        for bid in sites {
            if self.try_recover_one(func, image, bid, code, base_address, &mut starts) {
                recovered += 1;
            }
        }
        recovered
    }

    /// Attempt to turn one `IndirectBranch` dispatch into a `Switch`.
    #[allow(clippy::too_many_arguments)]
    fn try_recover_one(
        &self,
        func: &mut IrFunction,
        image: &ImageCtx,
        bid: BlockId,
        code: &[u8],
        base_address: u64,
        starts: &mut std::collections::HashMap<u64, BlockId>,
    ) -> bool {
        // 1. The dispatch block: IBRANCH fed by a Load.
        let (load_addr, load_size) = {
            let blk = match func.block(bid) {
                Some(b) => b,
                None => return false,
            };
            let target = match blk.terminator() {
                Some(IrInst::IndirectBranch { target }) => target.clone(),
                _ => return false,
            };
            let mut found: Option<(Value, u32)> = None;
            for inst in &blk.insts {
                if let IrInst::Load { dst, addr, size } = inst {
                    if *dst == target {
                        found = Some((addr.clone(), *size));
                    }
                }
            }
            match found {
                Some(v) => v,
                None => return false,
            }
        };

        // 2. Address shape: table_va + index*scale.
        let Some((table_va, index_val, scale)) =
            parse_jt_addr(func, bid, &load_addr)
        else {
            return false;
        };
        if !(scale == 4 || scale == 8) || load_size as u64 != scale {
            return false;
        }

        // 3. Bounds guard (ja / jae) в†’ entry count.
        let Some(count) = find_bounds_count(func, bid, &index_val, self.is_64bit) else {
            return false;
        };
        if !(2..=1024).contains(&count) {
            return false;
        }

        // 4. Read + validate entries.
        let mut targets: Vec<u64> = Vec::with_capacity(count as usize);
        for i in 0..count {
            let Some(raw) = image.read_ptr(table_va.wrapping_add(i * scale), scale) else {
                return false;
            };
            // Table contents hold absolute VAs; convert them into the
            // lifter's coordinate space for extent validation.
            let va = if self.is_64bit {
                raw.wrapping_sub(image.image_base)
                    .wrapping_add(image.coord_base)
            } else {
                base_address.wrapping_add(raw)
            };
            // Case targets must fall inside the function's code slice.
            let hi = base_address + code.len() as u64;
            if !(base_address..hi).contains(&va) {
                return false;
            }
            targets.push(va);
        }
        if targets.iter().all(|&t| t == targets[0]) {
            return false; // degenerate single-target table
        }

        // 5. Case bodies: reuse existing blocks at exact targets, lift the
        // rest. Roll back everything newly created on failure.
        let func_hi = base_address + code.len() as u64;
        let mut sorted = targets.clone();
        sorted.sort_unstable();
        sorted.dedup();

        let mut by_va: std::collections::HashMap<u64, BlockId> =
            std::collections::HashMap::new();
        let mut created: Vec<BlockId> = Vec::new();
        for (i, &va) in sorted.iter().enumerate() {
            if let Some(&existing) = starts.get(&va) {
                by_va.insert(va, existing);
                continue;
            }
            let window_end = sorted.get(i + 1).copied().unwrap_or(func_hi);
            match self.lift_case_body(
                func, code, base_address, va, window_end, starts, &mut created,
            ) {
                Ok(b) => {
                    by_va.insert(va, b);
                }
                Err(_) => {
                    func.blocks.retain(|b| !created.contains(&b.id));
                    for &cv in &created {
                        starts.retain(|_, v| *v != cv);
                    }
                    return false;
                }
            }
        }

        // 6. Replace the terminator.
        let cases: Vec<(i64, BlockId)> = targets
            .iter()
            .enumerate()
            .map(|(i, va)| (i as i64, by_va[va]))
            .collect();
        let blk = func.block_mut(bid).expect("site block exists");
        blk.insts.pop(); // IndirectBranch
        blk.insts.push(IrInst::Switch {
            index: index_val,
            cases,
            default: None,
        });
        true
    }

    /// Lift a jump-table case body starting at `va` (code window
    /// `[va, window_end)`), reusing already-lifted blocks and continuing
    /// through internal control flow exactly like the main linear loop.
    /// Returns the block holding the case's first instruction.
    #[allow(clippy::too_many_arguments)]
    fn lift_case_body(
        &self,
        func: &mut IrFunction,
        code: &[u8],
        base: u64,
        va: u64,
        window_end: u64,
        starts: &mut std::collections::HashMap<u64, BlockId>,
        created: &mut Vec<BlockId>,
    ) -> Result<BlockId, LifterError> {
        let start_off = match (va - base) as usize {
            o if o < code.len() => o,
            _ => return Err(trunc_err(va)),
        };
        let end_off = (((window_end - base) as usize).min(code.len())).max(start_off + 1);

        let first = func.add_block(&format!("bb_{}", start_off));
        created.push(first);
        starts.insert(va, first);
        let mut cur = first;
        let mut off = start_off;
        let mut block_start = va;
        let mut budget = 4096usize;

        while off < end_off {
            if budget == 0 {
                func.push_inst(cur, IrInst::Return { value: None });
                break;
            }
            budget -= 1;

            // Continuation hitting a known block start: link and stop.
            if off != start_off {
                if let Some(&existing) = starts.get(&(base + off as u64)) {
                    func.push_inst(cur, IrInst::Branch { target: existing });
                    if let Some(b) = func.block_mut(cur) {
                        b.source_range =
                            Some((block_start, (base + off as u64).max(block_start)));
                    }
                    return Ok(first);
                }
            }

            let address = base + off as u64;
            match self.lift_instruction(func, cur, &code[off..], address) {
                Ok((consumed, _)) => {
                    if consumed == 0 {
                        func.push_inst(cur, IrInst::Return { value: None });
                        break;
                    }
                    off += consumed;
                    let terminated = func
                        .block(cur)
                        .and_then(|b| b.terminator())
                        .is_some();
                    if terminated {
                        let end = base + off as u64;
                        if let Some(b) = func.block_mut(cur) {
                            b.source_range = Some((block_start, end));
                        }
                        if off >= end_off {
                            break;
                        }
                        // Internal control flow: keep lifting linearly into
                        // a fresh continuation block (mirrors the main loop).
                        let nb = func.add_block(&format!("bb_{}", off));
                        created.push(nb);
                        starts.insert(base + off as u64, nb);
                        cur = nb;
                        block_start = end;
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if let Some(b) = func.block_mut(cur) {
            if b.source_range.is_none() {
                b.source_range = Some((block_start, (base + off as u64).max(block_start)));
            }
        }
        if func.block(cur).and_then(|b| b.terminator()).is_none() {
            func.push_inst(cur, IrInst::Return { value: None });
        }
        Ok(first)
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

                    // в”Ђв”Ђ SSE data movement (legacy encoding) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
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
                            let (addr, len) = self
                                .address_of_rm(func, block, code, p2, address, rex_x, rex_b, 0)?;
                            if store {
                                func.push_inst(
                                    block,
                                    IrInst::Store {
                                        addr,
                                        value: vdst,
                                        size: 16,
                                    },
                                );
                            } else {
                                let tmp = func.alloc_var(Ty::Unknown);
                                func.push_inst(
                                    block,
                                    IrInst::Load {
                                        dst: tmp.clone(),
                                        addr,
                                        size: 16,
                                    },
                                );
                                push_un(func, block, vdst, OpCode::Copy, tmp);
                            }
                            Ok((p2 + 1 + len, true))
                        }
                    }

                    // pxor/xorps вЂ” the canonical `xmm = 0` zeroing idiom when
                    // both operands are the same register.
                    0x57 | 0xEF => {
                        let p2 = pos + 1;
                        let modrm = *code.get(p2 + 1).ok_or_else(|| trunc_err(address))?;
                        let (_, rf, _) = decode_modrm(modrm);
                        let vdst = xmm_value(rf + ext(rex_r));
                        if modrm & 0xC0 == 0xC0 && (modrm & 7) + ext(rex_b) == rf + ext(rex_r) {
                            push_bin(func, block, vdst.clone(), OpCode::Xor, vdst.clone(), vdst);
                        } else if modrm & 0xC0 == 0xC0 {
                            let vsrc = xmm_value((modrm & 7) + ext(rex_b));
                            let tmp = func.alloc_var(Ty::Unknown);
                            push_bin(func, block, tmp.clone(), OpCode::Xor, vdst.clone(), vsrc);
                            push_un(func, block, vdst, OpCode::Copy, tmp);
                        } else {
                            let (addr, len) = self
                                .address_of_rm(func, block, code, p2, address, rex_x, rex_b, 0)?;
                            let tmp = func.alloc_var(Ty::Unknown);
                            func.push_inst(
                                block,
                                IrInst::Load {
                                    dst: tmp.clone(),
                                    addr,
                                    size: 16,
                                },
                            );
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
                        func.push_inst(
                            block,
                            IrInst::CBranch {
                                cond,
                                target_true: tt,
                                target_false: tf,
                            },
                        );
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
                            func.push_inst(
                                block,
                                IrInst::Store {
                                    addr,
                                    value: cond,
                                    size: 1,
                                },
                            );
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0,
                )?;
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

            o @ (0x04 | 0x05 | 0x0C | 0x0D | 0x14 | 0x15 | 0x1C | 0x1D | 0x24 | 0x25 | 0x2C
            | 0x2D | 0x34 | 0x35 | 0x3C | 0x3D) => {
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
                    if o16 {
                        2
                    } else {
                        4
                    }
                } else {
                    1
                };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let kind = grp1_kind(rf);
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, ib,
                )?;
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, 32, has_rex, rex_x, rex_b, 0,
                )?;
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
                    if o16 {
                        2
                    } else {
                        4
                    }
                } else {
                    1
                };
                let modrm = *code.get(pos + 1).ok_or_else(|| trunc_err(address))?;
                let (_, rf, _) = decode_modrm(modrm);
                let loc = self.resolve_rm(
                    func, block, code, pos, address, obits, has_rex, rex_x, rex_b, ib,
                )?;
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0,
                )?;
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0,
                )?;
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0,
                )?;
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
                self.write_reg(
                    func,
                    block,
                    &dst,
                    OpCode::Copy,
                    Value::Const(imm as i8 as i64),
                    8,
                );
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
                let bits = if o == 0xC0 || o == 0xD0 || o == 0xD2 {
                    8
                } else {
                    obits
                };
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, timm,
                )?;
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
                push_bin(
                    func,
                    block,
                    tmp.clone(),
                    OpCode::Add,
                    sp.clone(),
                    Value::Const(n),
                );
                push_un(func, block, sp, OpCode::Copy, tmp);
                func.push_inst(
                    block,
                    IrInst::Return {
                        value: Some(reg_value(0, pb, false)),
                    },
                );
                Ok((pos + 3, true))
            }

            0xC3 => {
                func.push_inst(
                    block,
                    IrInst::Return {
                        value: Some(reg_value(0, self.ptr_bits(), false)),
                    },
                );
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, ib,
                )?;
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
                func.push_inst(
                    block,
                    IrInst::Load {
                        dst: ld.clone(),
                        addr: sp.clone(),
                        size: pb / 8,
                    },
                );
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
                // [rspВ±k] memory operands stay aligned.
                let ret_addr = address.wrapping_add(insn_len as u64) as i64;
                self.emit_push(func, block, Value::Const(ret_addr), sbits);
                let args = self.call_args(func, block);
                func.push_inst(
                    block,
                    IrInst::Call {
                        dst: Some(reg_value(0, self.ptr_bits(), false)),
                        target: Value::Symbol(format!("func_{:X}", target_addr)),
                        args,
                    },
                );
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
                    push_bin(
                        func,
                        block,
                        zero.clone(),
                        OpCode::Eq,
                        counter,
                        Value::Const(0),
                    );
                    zero
                } else {
                    let dec = func.alloc_var(int_ty(sbits));
                    push_bin(
                        func,
                        block,
                        dec.clone(),
                        OpCode::Sub,
                        counter.clone(),
                        Value::Const(1),
                    );
                    push_un(func, block, counter, OpCode::Copy, dec.clone());
                    let nonzero = func.alloc_var(Ty::Bool);
                    push_bin(
                        func,
                        block,
                        nonzero.clone(),
                        OpCode::Ne,
                        dec,
                        Value::Const(0),
                    );
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
                func.push_inst(
                    block,
                    IrInst::CBranch {
                        cond,
                        target_true: tt,
                        target_false: tf,
                    },
                );
                Ok((insn_len, true))
            }

            0x70..=0x7F => {
                let rel = imm_at(code, pos + 1, 1).ok_or_else(|| trunc_err(address))?;
                let target_addr = (address as i64 + 2 + rel) as u64;
                let tt = func.add_block(&format!("loc_{:X}", target_addr));
                let tf = func.add_block(&format!("fall_{:X}", address + 2));
                let cond = self.jcc_condition(func, block, opcode - 0x70);
                func.push_inst(
                    block,
                    IrInst::CBranch {
                        cond,
                        target_true: tt,
                        target_false: tf,
                    },
                );
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
                let loc = self.resolve_rm(
                    func, block, code, pos, address, bits, has_rex, rex_x, rex_b, 0,
                )?;
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
                        let args = self.call_args(func, block);
                        func.push_inst(
                            block,
                            IrInst::Call {
                                dst: Some(reg_value(0, self.ptr_bits(), false)),
                                target: v,
                                args,
                            },
                        );
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
        if self.is_64bit {
            "x86_64"
        } else {
            "x86"
        }
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
        // Clamp hostile base addresses (near u64::MAX) once: every
        // `base + offset` / `address + small_const` below then stays in range.
        let base_address = crate::lifter::clamp_base_address(base_address, code.len());
        let mut func = IrFunction::new(function_name, base_address);
        let mut current_block = func.entry_block;
        let mut offset = 0usize;
        let mut instruction_count = 0usize;
        // Start address of the block currently being filled. Recorded into
        // `source_range` so downstream consumers (e.g. the emulator's
        // mid-function entry) can map addresses back to blocks.
        let mut block_start = base_address;

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

            let (consumed, lifted) =
                match self.lift_instruction(&mut func, current_block, remaining, address) {
                    Ok(ok) => ok,
                    // Unsupported opcode: skip the whole instruction using the
                    // precise length from the LDE and keep going. Bailing out on
                    // the first SSE/AVX op would lose the entire function вЂ” real
                    // x64 code is full of them.
                    Err(LifterError::UnsupportedInstruction(msg)) => {
                        let len = freakre_x86::decode_len(
                            remaining,
                            if self.is_64bit {
                                freakre_x86::Mode::X64
                            } else {
                                freakre_x86::Mode::X86
                            },
                        )
                        .map_err(|e| {
                            LifterError::UnsupportedInstruction(format!("{} ({})", msg, e))
                        })?;
                        if len == 0 || len > remaining.len() {
                            return Err(LifterError::UnsupportedInstruction(format!(
                                "{} (bad length {})",
                                msg, len
                            )));
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
                        let end = base_address + offset as u64;
                        if let Some(prev) = func.block_mut(current_block) {
                            prev.source_range = Some((block_start, end));
                        }
                        current_block = func.add_block(&format!("bb_{}", offset));
                        block_start = end;
                    }
                }
            }
        }

        // Close the final block's range (covers the epilogue-break path too).
        {
            let end = base_address + offset as u64;
            if let Some(last) = func.block_mut(current_block) {
                if last.source_range.is_none() {
                    last.source_range = Some((block_start, end.max(block_start)));
                }
            }
        }

        crate::ir::repair_block_graph(&mut func, parse_block_addr);
        func.build_cfg();

        // Jump-table recovery needs the post-repair predecessor graph, so it
        // runs here. Recovered dispatches re-run repair/build_cfg to link the
        // newly lifted case bodies; prune drops the junk blocks the linear
        // decoder produced past the replaced dispatch.
        let mut recovered = 0usize;
        if self.image.is_some() {
            recovered = self.recover_jump_tables(&mut func, code, base_address);
        }
        if recovered > 0 {
            crate::ir::repair_block_graph(&mut func, parse_block_addr);
            func.build_cfg();
        }

        // The lifter materializes the return-address push for every call
        // (`tmp = sp - word; [tmp] = ret; sp = tmp`) so that [rsp±k] operand
        // resolution during lifting stays aligned. That resolution is done by
        // now, so the shadow can go: the `Call` itself implies the adjustment
        // and the triple prints as pure noise in decompiled C.
        let shadows = strip_call_shadows(&mut func, base_address, code.len() as u64);
        let _ = shadows;

        func.prune_unreachable();

        Ok(func)
    }
}

/// Remove call-return-address shadow sequences left by `emit_push` at call
/// sites. The pattern (consecutive, same block):
///   `t = Sub(sp, word)` → `Store{addr: t, value: Const(ret)}` → `sp = Copy(t)`
/// → `Call`. The stored constant must fall inside the function's byte range
/// (a real return address), which keeps genuine `push <code ptr>` argument
/// setups... mostly intact — a `push offset cb; call` false positive is
/// possible but rare. The temp must be referenced exactly twice (store addr +
/// final copy) so no other consumer dangles after removal.
fn strip_call_shadows(func: &mut IrFunction, base: u64, code_len: u64) -> usize {
    use std::collections::HashMap;

    // Use counts for every SSA temp in the function.
    let mut uses: HashMap<u32, usize> = HashMap::new();
    for b in &func.blocks {
        for inst in &b.insts {
            for src in inst.sources() {
                if let Some(id) = src.var_id() {
                    *uses.entry(id).or_insert(0) += 1;
                }
            }
        }
    }

    let sp_names = ["rsp", "esp"];
    let mut removed = 0usize;
    for b in &mut func.blocks {
        let mut len = b.insts.len();
        let mut i = 0usize;
        while i + 3 < len {
            let (sub_tmp, word, sp_name) = match &b.insts[i] {
                IrInst::Binary {
                    dst,
                    op: OpCode::Sub,
                    lhs,
                    rhs: Value::Const(w),
                } => {
                    let sp = match lhs {
                        Value::Register { name, .. } if sp_names.contains(&name.as_str()) => {
                            name.clone()
                        }
                        _ => {
                            i += 1;
                            continue;
                        }
                    };
                    match dst {
                        Value::Var { id, .. } => (*id, *w, sp),
                        _ => {
                            i += 1;
                            continue;
                        }
                    }
                }
                _ => {
                    i += 1;
                    continue;
                }
            };
            if word != 4 && word != 8 {
                i += 1;
                continue;
            }
            let ok_store = matches!(
                &b.insts[i + 1],
                IrInst::Store {
                    addr,
                    value: Value::Const(v),
                    size,
                } if addr.var_id() == Some(sub_tmp)
                    && *size == word as u32
                    && *v >= base as i64
                    && (*v as u64) < base.saturating_add(code_len)
            );
            let ok_copy = matches!(
                &b.insts[i + 2],
                IrInst::Unary {
                    dst: Value::Register { name, .. },
                    op: OpCode::Copy,
                    src,
                } if *name == sp_name && src.var_id() == Some(sub_tmp)
            );
            let ok_call = matches!(&b.insts[i + 3], IrInst::Call { .. });
            if ok_store && ok_copy && ok_call && uses.get(&sub_tmp).copied().unwrap_or(0) == 2 {
                b.insts.drain(i..i + 3);
                removed += 3;
                len -= 3;
                continue; // do not advance: the Call may follow another shadow
            }
            i += 1;
        }
    }
    removed
}

fn parse_block_addr(name: &str, base_address: u64) -> Option<u64> {    if let Some(rest) = name.strip_prefix("bb_") {
        // saturating: `o` comes from a (possibly hostile) label string.
        return rest
            .parse::<usize>()
            .ok()
            .map(|o| base_address.saturating_add(o as u64));
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

/// Decompose a jump-table load address expression into
/// `(table_va, index_value, scale)`.
///
/// Accepted shapes (as emitted by the lifter for `jmp [table + reg*scale]`):
/// - `Add(Const(table), Mul(index, Const(scale)))` вЂ” both defs in the
///   dispatch block,
/// - `Add(<lea-resolved base>, Mul(index, Const(scale)))` вЂ” the base
///   register is resolved backwards through `Copy`/`Add` defs,
/// - anything else в†’ `None` (the pass leaves the dispatch alone).
fn parse_jt_addr(
    func: &IrFunction,
    site: BlockId,
    load_addr: &Value,
) -> Option<(u64, Value, u64)> {
    let blk = func.block(site)?;
    let def = last_def_in_block(blk, load_addr)?;
    match def {
        IrInst::Binary {
            op: OpCode::Add,
            lhs,
            rhs,
            ..
        } => {
            // (base, mul) in either operand order.
            for (bx, mx) in [(lhs, rhs), (rhs, lhs)] {
                if let Some((ix, s)) = jt_mul_def(blk, mx) {
                    if let Some(base) = jt_const_of(func, site, bx) {
                        return Some((base, ix, s));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Resolve `v` to its `Mul(index, Const(scale))` definition inside `blk`.
fn jt_mul_def(blk: &IrBlock, v: &Value) -> Option<(Value, u64)> {
    let def = last_def_in_block(blk, v)?;
    match def {
        IrInst::Binary {
            op: OpCode::Mul,
            lhs,
            rhs,
            ..
        } => {
            if let Value::Const(s) = rhs {
                if *s > 0 && (*s as u64).is_power_of_two() {
                    return Some((lhs.clone(), *s as u64));
                }
            }
            None
        }
        _ => None,
    }
}

/// Constant-fold a table-base operand: literal `Const`, or a chain of
/// `Copy`/`Add(Const, Const)` definitions up to (and including) the dispatch
/// block вЂ” the `lea reg, [rip+table]` shape.
fn jt_const_of(func: &IrFunction, site: BlockId, v: &Value) -> Option<u64> {
    match v {
        Value::Const(c) => Some(*c as u64),
        _ => {
            let mut cur = v.clone();
            for _ in 0..3 {
                match find_def_upto(func, &cur, site) {
                    Some(IrInst::Unary {
                        op: OpCode::Copy,
                        src,
                        ..
                    }) => cur = src.clone(),
                    Some(IrInst::Binary {
                        op: OpCode::Add,
                        lhs: Value::Const(a),
                        rhs: Value::Const(b),
                        ..
                    }) => return Some((*a as u64).wrapping_add(*b as u64)),
                    _ => return None,
                }
            }
            None
        }
    }
}

/// Last definition of `v` scanning blocks in program order, stopping at
/// (and including) `upto` вЂ” register re-definitions after the dispatch must
/// not shadow the value the dispatch actually used.
fn find_def_upto<'a>(func: &'a IrFunction, v: &Value, upto: BlockId) -> Option<&'a IrInst> {
    let mut found = None;
    for b in &func.blocks {
        for i in &b.insts {
            if writes_dst(i, v) {
                found = Some(i);
            }
        }
        if b.id == upto {
            break;
        }
    }
    found
}

/// Whether `inst` writes `v` as its destination.
fn writes_dst(inst: &IrInst, v: &Value) -> bool {
    match inst {
        IrInst::Binary { dst, .. } | IrInst::Unary { dst, .. } | IrInst::Load { dst, .. } => {
            dst == v
        }
        IrInst::Call { dst: Some(d), .. } => d == v,
        _ => false,
    }
}

/// Last definition of `v` within a single block.
fn last_def_in_block<'a>(blk: &'a IrBlock, v: &Value) -> Option<&'a IrInst> {
    blk.insts
        .iter()
        .rev()
        .find(|i| writes_dst(i, v))
}

/// Derive the jump-table entry count from the bounds guard.
///
/// Canonical compiler shapes around a dispatch `jmp [tbl + idx*8]`:
/// - `cmp idx, N` + `ja  default` в†’ valid indices `0..=N` в†’ count `N + 1`
///   (lifter cond: `And(Ne(cf,1), Ne(zf,1))`),
/// - `cmp idx, N` + `jae default` в†’ valid indices `0..=N-1` в†’ count `N`
///   (lifter cond: `Ne(cf,1)`).
///
/// The cmp is lowered to `cf = LtU(idx, N)` on the same index value that
/// feeds the address computation вЂ” matched directly or through subreg
/// (`eax` vs `rax`) / `Sext`/`Copy` chains. Guards in other shapes
/// (`jbe`, swapped operands, runtime bounds) leave the dispatch alone.
fn find_bounds_count(
    func: &IrFunction,
    site: BlockId,
    index: &Value,
    is_64bit: bool,
) -> Option<u64> {
    let mut to_visit: Vec<BlockId> = func
        .block(site)
        .map(|b| b.predecessors.clone())
        .unwrap_or_default();
    let mut hops = 0;
    while hops < 2 {
        hops += 1;
        let mut next: Vec<BlockId> = Vec::new();
        for &pid in &to_visit {
            let Some(b) = func.block(pid) else {
                continue;
            };
            // Determine the guard's jcc form from the branch condition:
            // And-shape в†’ `ja`, Ne(flag_cf, 1) в†’ `jae`. Anything else (jbe,
            // jle, вЂ¦) does not bound a 0-based table from above.
            let count = b.terminator().and_then(|term| match term {
                IrInst::CBranch { cond, .. } => {
                    let shape = find_def_upto(func, cond, pid).and_then(|def| match def {
                        IrInst::Binary { op: OpCode::And, .. } => Some("ja"),
                        IrInst::Binary {
                            op: OpCode::Ne,
                            dst: _,
                            lhs: Value::Register { name, .. },
                            rhs: Value::Const(1),
                        } if name == "flag_cf" => Some("jae"),
                        _ => None,
                    });
                    match shape {
                        Some("ja") => Some(1u64),
                        Some("jae") => Some(0),
                        _ => None,
                    }
                }
                _ => None,
            });
            if let Some(extra) = count {
                for inst in &b.insts {
                    if let IrInst::Binary {
                        op: OpCode::LtU,
                        lhs,
                        rhs,
                        ..
                    } = inst
                    {
                        if jt_index_matches(func, pid, lhs, index, is_64bit) {
                            if let Value::Const(n) = rhs {
                                if *n >= 0 && (*n as u64) < 4096 {
                                    // ja: idx ≤ N → N+1 entries; jae: idx < N → N entries.
                                    return Some(*n as u64 + extra);
                                }
                            }
                        }
                    }
                }
            }
            next.extend(b.predecessors.iter().copied());
        }
        to_visit = next;
    }
    None
}

/// Whether `a` refers to the same runtime value as the table index:
/// identical operands, the same register at different widths (`eax` vs
/// `rax`), or linked through a `Sext`/`Copy` definition (`movsxd`/`cdqe`
/// between the cmp and the address computation).
fn jt_index_matches(
    func: &IrFunction,
    site: BlockId,
    a: &Value,
    index: &Value,
    is_64bit: bool,
) -> bool {
    if a == index {
        return true;
    }
    if let (
        Value::Register { name: an, ty: at },
        Value::Register { name: rn, ty: rt },
    ) = (a, index)
    {
        // Same register at different widths.
        if an == rn {
            return true;
        }
        let bits = |t: &Ty| match t {
            Ty::Int(b) => *b,
            _ => if is_64bit { 64 } else { 32 },
        };
        // eax's parent is rax (and vice versa via the subreg table).
        if let Some(info) = subreg_write(an, bits(at), is_64bit) {
            if reg_value(info.parent_idx, bits(rt), false) == *index {
                return true;
            }
        }
        if let Some(info) = subreg_write(rn, bits(rt), is_64bit) {
            if reg_value(info.parent_idx, bits(at), false) == *a {
                return true;
            }
        }
    }
    // index defined (before the dispatch) as Sext/Copy of a, or the reverse.
    if let Some(IrInst::Unary {
        op: OpCode::Sext | OpCode::Copy,
        src,
        ..
    }) = find_def_upto(func, index, site)
    {
        if src == a {
            return true;
        }
    }
    if let Some(IrInst::Unary {
        op: OpCode::Sext | OpCode::Copy,
        src,
        ..
    }) = find_def_upto(func, a, site)
    {
        if src == index {
            return true;
        }
    }
    false
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
                    return Err(LifterError::UnsupportedInstruction(
                        "unsupported 0F 1E form".to_string(),
                    ))
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

        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => pos + if o16 { 2 } else { 4 },

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

        0xA0..=0xA3 => {
            pos + if o16 {
                2
            } else if rex_w && is_64bit {
                8
            } else {
                4
            }
        }

        0xA4..=0xA7 | 0xAA..=0xAF => pos,

        0xA8 => pos + 1,

        0xA9 => pos + if o16 { 2 } else { 4 },

        0xB0..=0xB7 => pos + 1,

        0xB8..=0xBF => {
            pos + if rex_w && is_64bit {
                8
            } else if o16 {
                2
            } else {
                4
            }
        }

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

    /// Build an ImageCtx over one flat section [0, 0x10000) with base
    /// 0x14000000, placing `code` at 0x14001000 and `table` at 0x14002000.
    fn jt_image(code: &[u8], table: &[u8]) -> ImageCtx {
        let mut bytes = vec![0u8; 0x10000];
        bytes[0x1000..0x1000 + code.len()].copy_from_slice(code);
        bytes[0x2000..0x2000 + table.len()].copy_from_slice(table);
        ImageCtx::new(vec![(0, 0x10000)], 0x14000000, bytes)
    }

    /// Canonical guarded x64 jump table:
    /// ```text
    /// 0x1000  cmp  eax, 1          (N = max valid index)
    /// 0x1003  ja   default         (And-shaped cond в†’ ja в†’ count = N+1)
    /// 0x1005  jmp  qword [tbl + rax*8]   (REX.W: 48 FF 24 C5 <disp32>)
    /// 0x100D  case0: mov eax,1 ; ret
    /// 0x1013  case1: mov eax,2 ; ret
    /// 0x1019  default: mov eax,0 ; ret
    /// ```
    /// Table entries are absolute 64-bit VAs (u64 LE) at 0x14002000.
    fn jt_code(jmp_next: u64, entries: &[u64]) -> (Vec<u8>, Vec<u8>, u64) {
        // 48 FF 24 C5 <disp32>: REX.W + modrm=0x24 (m=0, /4, SIB), SIB=0xC5
        // (scale 8, index rax, no base) + absolute disp32. The lifter
        // resolves the no-base SIB form through rip_next, so the emitted
        // address constant is jmp_next + disp вЂ” hence disp = tbl - jmp_next.
        let table_va: u64 = 0x14002000;
        let disp = (table_va as i64).wrapping_sub(jmp_next as i64) as i32; // disp32
        let mut code = vec![
            0x83, 0xF8, 0x01, // cmp eax, 1
            0x77, 0x14, // ja default
            0x48, 0xFF, 0x24, 0xC5,
        ];
        code.extend_from_slice(&disp.to_le_bytes());
        // case0 @0x100D, case1 @0x1013, default @0x1019
        code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
        code.extend_from_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3]);
        code.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]);
        let mut table = Vec::with_capacity(entries.len() * 8);
        for e in entries {
            table.extend_from_slice(&e.to_le_bytes());
        }
        (code, table, table_va)
    }

    fn jt_switch_block(func: &IrFunction) -> (BlockId, Vec<(i64, BlockId)>) {
        for b in &func.blocks {
            if let Some(IrInst::Switch { index: _, cases, default: _ }) = b.terminator() {
                return (b.id, cases.clone());
            }
        }
        panic!("no Switch terminator found in\n{}", dump(func));
    }

    #[test]
    fn test_call_args_x64_registers() {
        // mov ecx, 1        B9 01 00 00 00
        // mov edx, 2        BA 02 00 00 00
        // call rel32        E8 xx xx xx xx
        // ret               C3
        let mut code = vec![0xB9, 0x01, 0x00, 0x00, 0x00, 0xBA, 0x02, 0x00, 0x00, 0x00];
        code.extend_from_slice(&[0xE8, 0x05, 0x00, 0x00, 0x00]);
        code.push(0xC3);
        let lifter = X86Lifter::new(true);
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let call = func
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .find_map(|i| match i {
                IrInst::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("call not found");
        // `mov ecx, 1` zero-extends into rcx: the lifter models the value
        // as its zext temp. Both args must be distinct value variables.
        assert_eq!(call.len(), 2, "rcx/rdx args, no holes beyond");
        assert!(
            call.iter().all(|a| matches!(a, Value::Var { .. })),
            "args must be computed values, not bare registers: {:?}",
            call
        );
        assert_ne!(call[0], call[1]);
    }

    #[test]
    fn test_call_args_x64_stale_register_dropped() {
        // mov ecx, 1        B9 01 00 00 00   (written)
        // mov ecx, 3        B9 03 00 00 00   (overwritten: last write wins)
        // add ecx, 2        83 C1 02         (read-modify-write: consumes 3)
        // call rel32        E8 xx xx xx xx
        // ret               C3
        let mut code = vec![
            0xB9, 0x01, 0x00, 0x00, 0x00, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x83, 0xC1, 0x02,
        ];
        code.extend_from_slice(&[0xE8, 0x05, 0x00, 0x00, 0x00]);
        code.push(0xC3);
        let lifter = X86Lifter::new(true);
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let call = func
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .find_map(|i| match i {
                IrInst::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("call not found");
        // ecx was RMW'd: the pre-call value is `3 + 2`, carried by the
        // add's dst variable — NOT the const 3 or 1.
        assert_eq!(call.len(), 1);
        let s = format!("{:?}", call[0]);
        assert!(!s.contains("Value::Const"), "RMW value must be a var: {}", s);
    }

    #[test]
    fn test_call_args_x64_no_args() {
        // call rel32 with untouched argument registers.
        let code = [0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3];
        let lifter = X86Lifter::new(true);
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let call = func
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .find_map(|i| match i {
                IrInst::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("call not found");
        assert!(call.is_empty(), "no register evidence -> no args");
    }

    #[test]
    fn test_call_args_x86_stack_pushes() {
        // push 1        6A 01
        // push 2        6A 02
        // call rel32    E8 xx xx xx xx
        // ret           C3
        let mut code = vec![0x6A, 0x01, 0x6A, 0x02];
        code.extend_from_slice(&[0xE8, 0x05, 0x00, 0x00, 0x00]);
        code.push(0xC3);
        let lifter = X86Lifter::new(false);
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let call = func
            .blocks
            .iter()
            .flat_map(|b| &b.insts)
            .find_map(|i| match i {
                IrInst::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("call not found");
        // cdecl: arg0 = last push. The modeled return-address push must be
        // excluded, so exactly the two real pushes remain, in call order.
        assert_eq!(call.len(), 2, "push args: {:?}", call);
        assert!(
            format!("{:?}", call[0]).contains("2") && format!("{:?}", call[1]).contains("1"),
            "arg0 must be the last push: {:?}",
            call
        );
    }

    #[test]
    fn test_jump_table_recovered_reusing_lifted_bodies() {
        let jmp_next = 0x1400100Du64;
        let (code, table, _) = jt_code(jmp_next, &[0x1400100D, 0x14001013]);
        let lifter = X86Lifter::new(true).with_image(jt_image(&code, &table));
        let func = lifter
            .lift_function(&code, 0x14001000, "jt")
            .expect("lift");

        // The dispatch became a Switch with exactly the two table cases.
        let (dispatch, cases) = jt_switch_block(&func);
        assert_eq!(cases.len(), 2, "case count\n{}", dump(&func));
        assert_eq!(cases[0].0, 0, "case values in order\n{}", dump(&func));
        assert_eq!(cases[1].0, 1, "case values in order\n{}", dump(&func));

        // No indirect dispatch survives.
        for b in &func.blocks {
            assert!(
                !matches!(b.terminator(), Some(IrInst::IndirectBranch { .. })),
                "IBranch left behind in bb {}\n{}",
                b.id.0,
                dump(&func)
            );
        }

        // Case blocks hold the real bodies: the first case target must be
        // the block holding `mov eax,1` (Const(1)), the second `mov eax,2`.
        let body = |id: BlockId| -> String {
            let mut f = IrFunction::new("body", 0);
            f.blocks = vec![func.blocks[id.0 as usize].clone()];
            dump(&f)
        };
        assert!(
            body(cases[0].1).contains("Const(1)"),
            "case 0 body:\n{}",
            body(cases[0].1)
        );
        assert!(
            body(cases[1].1).contains("Const(2)"),
            "case 1 body:\n{}",
            body(cases[1].1)
        );
        // The default target is the `mov eax,0` block.
        assert!(dispatch.0 != u32::MAX, "dispatch block must exist");
        let _ = dispatch;
    }

    #[test]
    fn test_jump_table_recovery_falls_back_without_image() {
        let jmp_next = 0x1400100Cu64;
        let (code, table, _) = jt_code(jmp_next, &[0x1400100C, 0x14001012]);
        // No image attached: FF /4 must stay an IndirectBranch.
        let lifter = X86Lifter::new(true);
        let func = lifter.lift_function(&code, 0x14001000, "jt").unwrap();
        assert!(func
            .blocks
            .iter()
            .any(|b| matches!(b.terminator(), Some(IrInst::IndirectBranch { .. }))));
        assert!(func.blocks.iter().all(
            |b| !matches!(b.terminator(), Some(IrInst::Switch { .. }))
        ));
        let _ = table;
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
        let code = [0x55, 0x48, 0x89, 0xE5, 0x90, 0xC9, 0xC3];
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
        assert_eq!(
            lde_length(&[0xE8, 0x00, 0x01, 0x00, 0x00], true).ok(),
            Some(5)
        );
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
            "Neg(Sext(cond)) keeps only the low bit вЂ” mask must be Sext(cond) directly:\n{}",
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
        assert!(
            d.contains("Const(40)"),
            "sign-extended imm8 expected:\n{}",
            d
        );
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
        let jcxz = lifter
            .lift_function(&[0xE3, 0x02, 0xC3], 0x1000, "jcxz")
            .unwrap();
        let d = dump(&jcxz);
        assert!(has_op(&d, "Eq"), "JCXZ must test counter == 0:\n{}", d);
    }

    #[test]
    fn test_int_imm_is_marked_nop() {
        let lifter = X86Lifter::new(true);
        let code = [0xCD, 0x80, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(
            dump(&func).contains("Nop"),
            "INT imm8 must leave an explicit marker"
        );
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
        // vzeroupper вЂ” unsupported but correctly sized by the LDE
        let code = [0xC5, 0xF8, 0x77, 0xC3];
        let f = lifter.lift_function(&code, 0x1000, "t").unwrap();
        assert!(
            dump(&f).contains("Nop"),
            "VEX op must be skipped with a Nop"
        );
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

    // в”Ђв”Ђв”Ђ Sub-register aliasing в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

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
        assert!(
            has_op(&d, "Or"),
            "merge must OR the field into the parent:\n{}",
            d
        );
    }

    #[test]
    fn test_ax_write_merge_masks() {
        // 66 B8 34 12: mov ax, 0x1234 -> rax = (rax & ~0xFFFF) | 0x1234.
        let lifter = X86Lifter::new(true);
        let code = [0x66, 0xB8, 0x34, 0x12, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("Const(-65536)"), "keep-mask expected:\n{}", d);
        assert!(
            d.contains("Const(4660)"),
            "field value 0x1234 expected:\n{}",
            d
        );
        assert!(has_reg(&d, "rax"), "merge target must be rax:\n{}", d);
    }

    #[test]
    fn test_eax_write_zeroes_upper_32() {
        // B8 imm32: writing eax clears rax[63:32] (zero-extension).
        let lifter = X86Lifter::new(true);
        let code = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(
            has_op(&d, "Zext"),
            "eax write must zero-extend into rax:\n{}",
            d
        );
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
        assert!(
            d.contains("Const(8192)"),
            "field shifted by 8 expected:\n{}",
            d
        );
        assert!(has_reg(&d, "rbx"), "bh merge target must be rbx:\n{}", d);
    }

    // в”Ђв”Ђв”Ђ ALU flag modeling в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

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
        let cases: [[u8; 4]; 3] = [
            [0x48, 0x83, 0xE0, 0x05],
            [0x48, 0x83, 0xC8, 0x05],
            [0x48, 0x83, 0xF0, 0x05],
        ];
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

        let inc = lifter
            .lift_function(&[0xFE, 0xC0, 0xC3], 0x1000, "inc")
            .unwrap();
        let d = dump(&inc);
        assert!(d.contains("flag_zf"), "INC must define ZF:\n{}", d);
        assert!(d.contains("flag_of"), "INC must define OF:\n{}", d);
        assert!(
            !d.contains("flag_cf"),
            "INC must preserve CF (no def):\n{}",
            d
        );

        let dec = lifter
            .lift_function(&[0xFE, 0xC8, 0xC3], 0x1000, "dec")
            .unwrap();
        let d = dump(&dec);
        assert!(d.contains("flag_zf"), "DEC must define ZF:\n{}", d);
        assert!(d.contains("flag_of"), "DEC must define OF:\n{}", d);
        assert!(
            !d.contains("flag_cf"),
            "DEC must preserve CF (no def):\n{}",
            d
        );
    }

    // в”Ђв”Ђв”Ђ CALL / RET stack semantics в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    #[test]
    fn test_call_return_address_shadow_stripped() {
        // call rel5 at 0x1000: the lifter models the return-address push for
        // [rsp±k] alignment during lifting, then strips the shadow post-pass:
        // the decompiled IR shows a bare `Call` with callee func_100A and no
        // rsp-decrement/store/copy noise.
        let lifter = X86Lifter::new(true);
        let code = [0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3];
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("func_100A"), "callee target expected:\n{}", d);
        assert!(!has_op(&d, "Sub"), "push shadow must be stripped:\n{}", d);
        assert!(!d.contains("Store"), "no return-address store expected:\n{}", d);
    }

    #[test]
    fn test_push_const_code_addr_survives() {
        // A genuine `push <constant>` before a call is argument machinery,
        // not a return-address shadow: the stored constant (0x1010) lies
        // outside the function's byte range [0x1000, 0x100B), so it must
        // survive stripping while the call's own shadow is removed.
        let lifter = X86Lifter::new(true);
        let mut code = vec![0x68, 0x10, 0x10, 0x00, 0x00]; // push imm32
        code.extend_from_slice(&[0xE8, 0x05, 0x00, 0x00, 0x00]); // call rel5
        code.push(0xC3); // ret
        let func = lifter.lift_function(&code, 0x1000, "t").unwrap();
        let d = dump(&func);
        assert!(d.contains("func_100F"), "callee target expected:\n{}", d);
        assert!(
            d.contains("Store"),
            "argument push must survive (ret==0x100F not pushed here):\n{}",
            d
        );
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
