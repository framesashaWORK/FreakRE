//! Guest machine state: GPR file with x86 sub-register aliasing,
//! flags, and IR SSA variable storage.

use std::collections::{BTreeMap, HashMap};

use freakre_ir::Ty;

/// Canonical 64-bit GPR slot order: rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
/// then r8..r15.
pub const GPR_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

/// Location of an architectural register name inside its parent GPR slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegRef {
    pub slot: u8,
    pub offset: u32,
    pub width: u32,
}

fn legacy(i: u8) -> RegRef {
    RegRef { slot: i, offset: 0, width: 64 }
}

/// Resolve any x86-64 register name (rax/eax/ax/al/ah/r8d/...) to its
/// parent-slot location. Unknown names (xmm0, st0, ...) yield `None`.
pub fn reg_ref(name: &str) -> Option<RegRef> {
    let r = |slot: u8, offset: u32, width: u32| RegRef { slot, offset, width };
    let legacy8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"];
    let high8 = ["ah", "ch", "dh", "bh"];
    let legacy16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"];
    let legacy32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    let legacy64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];

    if let Some(i) = legacy64.iter().position(|&n| n == name) {
        return Some(legacy(i as u8));
    }
    if let Some(i) = legacy32.iter().position(|&n| n == name) {
        return Some(r(i as u8, 0, 32));
    }
    if let Some(i) = legacy16.iter().position(|&n| n == name) {
        return Some(r(i as u8, 0, 16));
    }
    if let Some(i) = legacy8.iter().position(|&n| n == name) {
        return Some(r(i as u8, 0, 8));
    }
    if let Some(i) = high8.iter().position(|&n| n == name) {
        return Some(r(i as u8, 8, 8));
    }

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
        "" => Some(r(idx, 0, 64)),
        "d" => Some(r(idx, 0, 32)),
        "w" => Some(r(idx, 0, 16)),
        "b" => Some(r(idx, 0, 8)),
        _ => None,
    }
}

/// Effective bit width of a value type, clamped to the 64-bit machine word
/// this emulator models. Bool counts as 1 bit (values are 0/1), unknown /
/// pointer / weird types default to 64.
pub fn ty_bits(ty: &Ty) -> u32 {
    match ty.size_bits() {
        Some(n) if (1..=64).contains(&n) => n,
        _ => 64,
    }
}

pub(crate) fn mask(bits: u32) -> u64 {
    debug_assert!(bits <= 64);
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Sign-extend `val` viewed as `bits`-wide to a full i64.
pub fn sext(val: u64, bits: u32) -> i64 {
    let bits = bits.clamp(1, 64);
    let shift = 64 - bits;
    ((val << shift) as i64) >> shift
}

/// Machine state: registers + flags + SSA variable cells.
#[derive(Debug, Clone, Default)]
pub struct Machine {
    /// Parent GPR slots (rax..r15).
    pub regs: [u64; 16],
    /// Flag registers keyed without the `flag_` prefix ("zf", "cf", ...).
    pub flags: BTreeMap<String, bool>,
    /// Non-GPR registers (xmm*, debug, unknown names) accepted defensively
    /// so adversarial IR never panics the emulator.
    pub extra_regs: BTreeMap<String, u64>,
    /// SSA variable storage keyed by `Value::Var{id}`.
    pub vars: HashMap<u32, u64>,
}

impl Machine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a register named by a lifted `Value::Register`.
    ///
    /// Flags read as 0/1; sub-register views are extracted from their
    /// parent slot; unknown names fall back to `extra_regs` (defaulting 0).
    pub fn read_reg(&self, name: &str, ty: &Ty) -> u64 {
        let bits = ty_bits(ty);
        if let Some(flag) = name.strip_prefix("flag_") {
            return u64::from(*self.flags.get(flag).unwrap_or(&false));
        }
        match reg_ref(name) {
            Some(rr) => {
                let field = mask(bits).min(mask(rr.width));
                (self.regs[rr.slot as usize] >> rr.offset) & field
            }
            None => {
                let v = self.extra_regs.get(name).copied().unwrap_or(0);
                v & mask(bits)
            }
        }
    }

    /// Write a register named by a lifted `Value::Register`.
    ///
    /// Sub-register semantics (simplified but faithful where it matters):
    /// - narrow writes merge into the parent slot (RMW of the surrounding bits),
    /// - 32-bit writes zero the upper half of the parent (64-bit mode rule),
    /// - flag writes take bit 0 of `val`.
    pub fn write_reg(&mut self, name: &str, val: u64, bits: u32) {
        let val = val & mask(bits.min(64));
        if let Some(flag) = name.strip_prefix("flag_") {
            self.flags.insert(flag.to_string(), val & 1 != 0);
            return;
        }
        match reg_ref(name) {
            Some(rr) => {
                let w = rr.width.min(bits.clamp(1, 64)).max(1).min(rr.width);
                if rr.offset == 0 && (w == 64 || (w == 32 && rr.width == 32)) {
                    // Full-parent or zero-extending 32-bit write.
                    self.regs[rr.slot as usize] = val & mask(w);
                    return;
                }
                let field = mask(w);
                let shifted = (val & field) << rr.offset;
                let clear = !(field << rr.offset);
                self.regs[rr.slot as usize] =
                    (self.regs[rr.slot as usize] & clear) | shifted;
            }
            None => {
                self.extra_regs.insert(name.to_string(), val);
            }
        }
    }

    /// Snapshot of the canonical 64-bit register file.
    pub fn gpr_snapshot(&self) -> BTreeMap<String, u64> {
        GPR_NAMES
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), self.regs[i]))
            .collect()
    }

    /// Snapshot of defined flags.
    pub fn flag_snapshot(&self) -> BTreeMap<String, bool> {
        self.flags.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_resolution() {
        assert_eq!(reg_ref("rax"), Some(RegRef { slot: 0, offset: 0, width: 64 }));
        assert_eq!(reg_ref("eax"), Some(RegRef { slot: 0, offset: 0, width: 32 }));
        assert_eq!(reg_ref("ax"), Some(RegRef { slot: 0, offset: 0, width: 16 }));
        assert_eq!(reg_ref("al"), Some(RegRef { slot: 0, offset: 0, width: 8 }));
        assert_eq!(reg_ref("ah"), Some(RegRef { slot: 0, offset: 8, width: 8 }));
        assert_eq!(reg_ref("bh"), Some(RegRef { slot: 3, offset: 8, width: 8 }));
        assert_eq!(reg_ref("rdi"), Some(RegRef { slot: 7, offset: 0, width: 64 }));
        assert_eq!(reg_ref("r11d"), Some(RegRef { slot: 11, offset: 0, width: 32 }));
        assert_eq!(reg_ref("r15b"), Some(RegRef { slot: 15, offset: 0, width: 8 }));
        assert_eq!(reg_ref("xmm3"), None);
        assert_eq!(reg_ref("r16"), None);
    }

    #[test]
    fn narrow_write_updates_parent() {
        let mut m = Machine::new();
        m.regs[0] = 0;
        m.write_reg("al", 0x37, 8);
        assert_eq!(m.regs[0], 0x37);
        m.write_reg("ah", 0x42, 8);
        assert_eq!(m.regs[0], 0x4237);
        m.write_reg("cx", 0xABCD, 16);
        assert_eq!(m.regs[1], 0xABCD);
        m.write_reg("ch", 0x11, 8);
        assert_eq!(m.regs[1], 0x11CD);
    }

    #[test]
    fn eax_write_zeroes_upper() {
        let mut m = Machine::new();
        m.regs[0] = 0xDEAD_BEEF_1234_5678;
        m.write_reg("eax", 0xFFFF_FFFF, 32);
        assert_eq!(m.regs[0], 0x0000_0000_FFFF_FFFF);
        // but ah-style writes preserve upper bits
        m.regs[2] = 0xFF00;
        m.write_reg("dh", 0x77, 8);
        assert_eq!(m.regs[2], 0x7700);
    }

    #[test]
    fn flags_roundtrip() {
        let mut m = Machine::new();
        assert_eq!(m.read_reg("flag_zf", &Ty::Bool), 0);
        m.write_reg("flag_zf", 1, 1);
        assert!(m.flags["zf"]);
        assert_eq!(m.read_reg("flag_zf", &Ty::Bool), 1);
    }

    #[test]
    fn unknown_reg_is_defensive() {
        let mut m = Machine::new();
        m.write_reg("xmm0", 0x1234, 64);
        assert_eq!(m.read_reg("xmm0", &Ty::Unknown), 0x1234);
    }

    #[test]
    fn sign_extension() {
        assert_eq!(sext(0xFF, 8), -1i64);
        assert_eq!(sext(0x7F, 8), 127i64);
        assert_eq!(sext(0xFFFF_0000, 32), -65536i64);
        assert_eq!(sext(0x8000_0000, 32), -2147483648i64);
    }
}
