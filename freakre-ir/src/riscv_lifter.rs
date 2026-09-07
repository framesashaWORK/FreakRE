//! RISC-V 32/64 lifter — minimal stub.

use crate::ir::{IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

pub struct RiscvLifter {
    is_64bit: bool,
    max_instructions: usize,
}

impl RiscvLifter {
    pub fn new(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            max_instructions: 100_000,
        }
    }
    fn reg(&self, idx: u8) -> Value {
        let names = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
            "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6",
        ];
        let name = names.get(idx as usize).copied().unwrap_or("x?");
        Value::Register {
            name: name.to_string(),
            ty: if self.is_64bit { Ty::i64() } else { Ty::i32() },
        }
    }
}

impl Lifter for RiscvLifter {
    fn arch_name(&self) -> &str {
        if self.is_64bit {
            "riscv64"
        } else {
            "riscv32"
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
        // See x86_lifter: clamp hostile base addresses once, up front.
        let base_address = crate::lifter::clamp_base_address(base_address, code.len());
        let mut func = IrFunction::new(function_name, base_address);
        let mut current_block = func.entry_block;
        let mut offset = 0usize;
        while offset + 4 <= code.len() {
            let word = u32::from_le_bytes([
                code[offset],
                code[offset + 1],
                code[offset + 2],
                code[offset + 3],
            ]);
            let opcode = word & 0x7F;
            let rd = ((word >> 7) & 0x1F) as u8;
            let funct3 = (word >> 12) & 0x7;
            let rs1 = ((word >> 15) & 0x1F) as u8;
            let rs2 = ((word >> 20) & 0x1F) as u8;
            let funct7 = (word >> 25) & 0x7F;
            let imm_i = ((word as i32) >> 20) as i64;
            let imm_s = (((word >> 7) & 0x1F) as i32 | (((word >> 25) as i32) << 5)) as i64;
            let imm_s = if imm_s & 0x800 != 0 {
                imm_s | !0xFFF
            } else {
                imm_s
            };
            let imm_b = {
                let b12 = ((word >> 31) & 1) as i32;
                let b11 = ((word >> 7) & 1) as i32;
                let b10_5 = ((word >> 25) & 0x3F) as i32;
                let b4_1 = ((word >> 8) & 0xF) as i32;
                let imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
                if imm & 0x1000 != 0 {
                    (imm | !0x1FFF) as i64
                } else {
                    imm as i64
                }
            };
            let imm_u = (word & 0xFFFFF000) as i32 as i64;
            let imm_j = {
                let b20 = ((word >> 31) & 1) as i32;
                let b10_1 = ((word >> 21) & 0x3FF) as i32;
                let b11 = ((word >> 20) & 1) as i32;
                let b19_12 = ((word >> 12) & 0xFF) as i32;
                let imm = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
                if imm & 0x100000 != 0 {
                    (imm | !0x1FFFFF) as i64
                } else {
                    imm as i64
                }
            };
            let address = base_address + offset as u64;
            match opcode {
                0x33 => {
                    // R-type
                    let dst = self.reg(rd);
                    let op = match (funct3, funct7) {
                        (0, 0x00) => OpCode::Add,
                        (0, 0x20) => OpCode::Sub,
                        (4, 0x00) => OpCode::Xor,
                        (6, 0x00) => OpCode::Or,
                        (7, 0x00) => OpCode::And,
                        (1, 0x00) => OpCode::Shl,
                        (5, 0x00) => OpCode::Shr,
                        (5, 0x20) => OpCode::Sar,
                        _ => {
                            func.push_inst(current_block, IrInst::Nop);
                            offset += 4;
                            continue;
                        }
                    };
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst,
                            op,
                            lhs: self.reg(rs1),
                            rhs: self.reg(rs2),
                        },
                    );
                }
                0x13 => {
                    // I-type ALU
                    let dst = self.reg(rd);
                    let op = match funct3 {
                        0 => OpCode::Add,
                        4 => OpCode::Xor,
                        6 => OpCode::Or,
                        7 => OpCode::And,
                        1 => OpCode::Shl,
                        5 => {
                            if (word >> 30) & 1 == 1 {
                                OpCode::Sar
                            } else {
                                OpCode::Shr
                            }
                        }
                        _ => {
                            func.push_inst(current_block, IrInst::Nop);
                            offset += 4;
                            continue;
                        }
                    };
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst,
                            op,
                            lhs: self.reg(rs1),
                            rhs: Value::Const(imm_i),
                        },
                    );
                }
                0x03 => {
                    // Loads
                    let dst = self.reg(rd);
                    let size = match funct3 {
                        0 | 4 => 1,
                        1 | 5 => 2,
                        2 => 4,
                        3 => 8,
                        _ => 4,
                    };
                    let addr = func.alloc_var(if self.is_64bit { Ty::i64() } else { Ty::i32() });
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.reg(rs1),
                            rhs: Value::Const(imm_i),
                        },
                    );
                    func.push_inst(current_block, IrInst::Load { dst, addr, size });
                }
                0x23 => {
                    // Stores
                    let size = match funct3 {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        _ => 4,
                    };
                    let addr = func.alloc_var(if self.is_64bit { Ty::i64() } else { Ty::i32() });
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.reg(rs1),
                            rhs: Value::Const(imm_s),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Store {
                            addr,
                            value: self.reg(rs2),
                            size,
                        },
                    );
                }
                0x63 => {
                    // Branches
                    let target = (address as i64 + imm_b) as u64;
                    let taken = func.add_block(&format!("loc_{:X}", target));
                    let not_taken = func.add_block(&format!("fall_{:X}", address + 4));
                    let cond = func.alloc_var(Ty::Bool);
                    let op = match funct3 {
                        0 => OpCode::Eq,
                        1 => OpCode::Ne,
                        4 => OpCode::LtS,
                        5 => OpCode::GeS,
                        6 => OpCode::LtU,
                        7 => OpCode::GeU,
                        _ => OpCode::Eq,
                    };
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: cond.clone(),
                            op,
                            lhs: self.reg(rs1),
                            rhs: self.reg(rs2),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::CBranch {
                            cond,
                            target_true: taken,
                            target_false: not_taken,
                        },
                    );
                    current_block = not_taken;
                }
                0x6F => {
                    // jal
                    let target = (address as i64 + imm_j) as u64;
                    let target_block = func.add_block(&format!("loc_{:X}", target));
                    if rd == 0 {
                        // JAL x0 is a real unconditional jump, not a call.
                        func.push_inst(
                            current_block,
                            IrInst::Branch {
                                target: target_block,
                            },
                        );
                    } else {
                        func.push_inst(
                            current_block,
                            IrInst::Unary {
                                dst: self.reg(rd),
                                op: OpCode::Copy,
                                src: Value::Const((address + 4) as i64),
                            },
                        );
                        func.push_inst(
                            current_block,
                            IrInst::Call {
                                dst: Some(self.reg(rd)),
                                target: Value::Symbol(format!("func_{:X}", target)),
                                args: vec![],
                            },
                        );
                        let next = func.add_block(&format!("bb_{}", offset + 4));
                        func.push_inst(current_block, IrInst::Branch { target: next });
                        current_block = next;
                    }
                }
                0x67 => {
                    // jalr
                    let dst = self.reg(rd);
                    if rd != 0 {
                        func.push_inst(
                            current_block,
                            IrInst::Unary {
                                dst: dst.clone(),
                                op: OpCode::Copy,
                                src: Value::Const((address + 4) as i64),
                            },
                        );
                    }
                    let target = func.alloc_var(if self.is_64bit { Ty::i64() } else { Ty::i32() });
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: target.clone(),
                            op: OpCode::Add,
                            lhs: self.reg(rs1),
                            rhs: Value::Const(imm_i),
                        },
                    );
                    func.push_inst(current_block, IrInst::IndirectBranch { target });
                }
                0x37 => {
                    // lui
                    let dst = self.reg(rd);
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst,
                            op: OpCode::Copy,
                            src: Value::Const(imm_u),
                        },
                    );
                }
                0x17 => {
                    // auipc
                    let dst = self.reg(rd);
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst,
                            op: OpCode::Copy,
                            src: Value::Const(address as i64 + imm_u),
                        },
                    );
                }
                _ => {
                    func.push_inst(current_block, IrInst::Nop);
                }
            }
            // Handle block terminators
            if let Some(b) = func.block(current_block) {
                if b.terminator().is_some() && offset + 4 < code.len() {
                    // Need new block for fallthrough if not already
                    let next_label = format!("bb_{}", offset + 4);
                    if !func.blocks.iter().any(|b| b.label == next_label) {
                        let nb = func.add_block(&next_label);
                        // Only set current if not already a CBranch fallthrough
                        let term = func
                            .block(current_block)
                            .and_then(|b| b.terminator().cloned());
                        if !matches!(term, Some(IrInst::CBranch { .. })) {
                            current_block = nb;
                        }
                    }
                }
            }
            offset += 4;
        }
        crate::ir::repair_block_graph(&mut func, parse_block_addr);
        func.build_cfg();
        Ok(func)
    }
}

fn parse_block_addr(label: &str, base_address: u64) -> Option<u64> {
    if let Some(rest) = label.strip_prefix("bb_") {
        // saturating: `o` comes from a (possibly hostile) label string.
        return rest
            .parse::<usize>()
            .ok()
            .map(|o| base_address.saturating_add(o as u64));
    }
    for prefix in ["loc_", "fall_"] {
        if let Some(rest) = label.strip_prefix(prefix) {
            return u64::from_str_radix(rest, 16).ok();
        }
    }
    None
}
