//! Value Set Analysis (VSA) — tracks possible values of variables at each program point.
//!
//! Extends the dataflow framework with abstract interpretation over value sets:
//! - Constants: exact known values
//! - Ranges: [min, max] intervals
//! - Strided intervals: {base + k*stride | 0 ≤ k < count}
//! - Top: any value possible
//! - Bottom: unreachable / no value

use freakre_ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use std::collections::HashMap;

// ─── Abstract Value Domain ──────────────────────────────────────────

/// An abstract value representing a set of possible concrete values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbstractValue {
    /// Unreachable / no possible value
    Bottom,
    /// Exactly one known value
    Constant(i64),
    /// Range [lo, hi] inclusive
    Range { lo: i64, hi: i64 },
    /// Strided interval: base + k * stride for k in 0..count
    Strided { base: i64, stride: i64, count: u64 },
    /// Any value possible (top of lattice)
    Top,
}

impl AbstractValue {
    pub fn bottom() -> Self {
        AbstractValue::Bottom
    }
    pub fn top() -> Self {
        AbstractValue::Top
    }
    pub fn constant(v: i64) -> Self {
        AbstractValue::Constant(v)
    }

    pub fn range(lo: i64, hi: i64) -> Self {
        if lo == hi {
            AbstractValue::Constant(lo)
        } else if lo > hi {
            AbstractValue::Bottom
        } else {
            AbstractValue::Range { lo, hi }
        }
    }

    /// Join (union) two abstract values — least upper bound in the lattice.
    pub fn join(&self, other: &AbstractValue) -> AbstractValue {
        match (self, other) {
            (AbstractValue::Bottom, x) | (x, AbstractValue::Bottom) => x.clone(),
            (AbstractValue::Top, _) | (_, AbstractValue::Top) => AbstractValue::Top,
            (AbstractValue::Constant(a), AbstractValue::Constant(b)) => {
                if a == b {
                    AbstractValue::Constant(*a)
                } else {
                    AbstractValue::Range {
                        lo: (*a).min(*b),
                        hi: (*a).max(*b),
                    }
                }
            }
            (AbstractValue::Constant(c), AbstractValue::Range { lo, hi })
            | (AbstractValue::Range { lo, hi }, AbstractValue::Constant(c)) => {
                AbstractValue::Range {
                    lo: (*lo).min(*c),
                    hi: (*hi).max(*c),
                }
            }
            (
                AbstractValue::Range { lo: a_lo, hi: a_hi },
                AbstractValue::Range { lo: b_lo, hi: b_hi },
            ) => AbstractValue::Range {
                lo: (*a_lo).min(*b_lo),
                hi: (*a_hi).max(*b_hi),
            },
            // Strided ∪ Strided with same values → itself; otherwise widen to range
            (
                AbstractValue::Strided {
                    base: a_base,
                    stride: a_stride,
                    count: a_count,
                },
                AbstractValue::Strided {
                    base: b_base,
                    stride: b_stride,
                    count: b_count,
                },
            ) => {
                if self == other {
                    self.clone()
                } else {
                    let (a_lo, a_hi) = strided_extremes(*a_base, *a_stride, *a_count);
                    let (b_lo, b_hi) = strided_extremes(*b_base, *b_stride, *b_count);
                    AbstractValue::Range {
                        lo: a_lo.min(b_lo),
                        hi: a_hi.max(b_hi),
                    }
                }
            }
            // Constant ∪ Strided → range covering both
            (s @ AbstractValue::Strided { .. }, AbstractValue::Constant(c))
            | (AbstractValue::Constant(c), s @ AbstractValue::Strided { .. }) => {
                let (lo, hi) = match s {
                    AbstractValue::Strided {
                        base,
                        stride,
                        count,
                    } => strided_extremes(*base, *stride, *count),
                    _ => unreachable!(),
                };
                AbstractValue::Range {
                    lo: lo.min(*c),
                    hi: hi.max(*c),
                }
            }
            // Range ∪ Strided → range spanning both
            (s @ AbstractValue::Strided { .. }, AbstractValue::Range { lo, hi })
            | (AbstractValue::Range { lo, hi }, s @ AbstractValue::Strided { .. }) => {
                let (s_lo, s_hi) = match s {
                    AbstractValue::Strided {
                        base,
                        stride,
                        count,
                    } => strided_extremes(*base, *stride, *count),
                    _ => unreachable!(),
                };
                AbstractValue::Range {
                    lo: s_lo.min(*lo),
                    hi: s_hi.max(*hi),
                }
            }
        }
    }

    /// Whether this is the bottom element.
    pub fn is_bottom(&self) -> bool {
        matches!(self, AbstractValue::Bottom)
    }

    /// Whether this is a known constant.
    pub fn as_constant(&self) -> Option<i64> {
        match self {
            AbstractValue::Constant(v) => Some(*v),
            _ => None,
        }
    }

    /// Widen: accelerate convergence by jumping to a wider abstraction.
    pub fn widen(&self, other: &AbstractValue) -> AbstractValue {
        let joined = self.join(other);
        match &joined {
            AbstractValue::Range { lo, hi } => {
                // If range is too wide, go to Top
                if hi.wrapping_sub(*lo) > 0xFFFF_FFFF {
                    AbstractValue::Top
                } else {
                    joined
                }
            }
            _ => joined,
        }
    }
}

// ─── VSA Analysis ───────────────────────────────────────────────────

fn strided_extremes(base: i64, stride: i64, count: u64) -> (i64, i64) {
    let max_val = base.wrapping_add(stride.wrapping_mul(count as i64));
    (base.min(max_val), base.max(max_val))
}

/// Value Set Analysis result: maps (block_id, var_id) → abstract value.
#[derive(Debug, Clone)]
pub struct ValueSetAnalysis {
    /// Abstract state at block entry
    pub entry_states: HashMap<BlockId, HashMap<u32, AbstractValue>>,
    /// Abstract state at block exit
    pub exit_states: HashMap<BlockId, HashMap<u32, AbstractValue>>,
}

impl ValueSetAnalysis {
    /// Run VSA on a function.
    pub fn analyze(func: &IrFunction) -> Self {
        let mut vsa = ValueSetAnalysis {
            entry_states: HashMap::new(),
            exit_states: HashMap::new(),
        };

        // Initialize all states to bottom
        for block in &func.blocks {
            vsa.entry_states.insert(block.id, HashMap::new());
            vsa.exit_states.insert(block.id, HashMap::new());
        }

        // Entry block starts with empty state (all vars are Top initially)
        // Worklist algorithm
        let mut worklist: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 200;

        while let Some(block_id) = worklist.pop() {
            if iterations >= MAX_ITERATIONS {
                eprintln!(
                    "warning: value set analysis did not converge after {} iterations; returning partial results",
                    MAX_ITERATIONS
                );
                break;
            }
            iterations += 1;

            // Compute entry state as join of all predecessor exit states
            let block = match func.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            let mut entry_state = HashMap::new();
            if block_id == func.entry_block {
                // Entry: no predecessors, start with empty (Top for accessed vars)
            } else {
                for &pred in &block.predecessors {
                    if let Some(pred_exit) = vsa.exit_states.get(&pred) {
                        for (&var_id, val) in pred_exit {
                            let existing =
                                entry_state.entry(var_id).or_insert(AbstractValue::Bottom);
                            let new_val = if iterations > 50 {
                                existing.widen(val)
                            } else {
                                existing.join(val)
                            };
                            *existing = new_val;
                        }
                    }
                }
            }

            vsa.entry_states.insert(block_id, entry_state.clone());

            // Transfer function: process each instruction.
            // Phi nodes are evaluated against the exit states of their
            // corresponding predecessor blocks, so pass those in.
            let mut state = entry_state;
            for inst in &block.insts {
                transfer_inst(inst, &mut state, &vsa.exit_states);
            }

            // Check if exit state changed
            let old_exit = vsa.exit_states.get(&block_id).cloned().unwrap_or_default();
            if old_exit != state {
                vsa.exit_states.insert(block_id, state);
                // Add successors to worklist
                for &succ in &block.successors {
                    if !worklist.contains(&succ) {
                        worklist.push(succ);
                    }
                }
            }
        }

        vsa
    }

    /// Get the abstract value of a variable at block entry.
    pub fn get_at_entry(&self, block: BlockId, var_id: u32) -> AbstractValue {
        self.entry_states
            .get(&block)
            .and_then(|m| m.get(&var_id))
            .cloned()
            .unwrap_or(AbstractValue::Top)
    }

    /// Get the abstract value of a variable at block exit.
    pub fn get_at_exit(&self, block: BlockId, var_id: u32) -> AbstractValue {
        self.exit_states
            .get(&block)
            .and_then(|m| m.get(&var_id))
            .cloned()
            .unwrap_or(AbstractValue::Top)
    }
}

// ─── Transfer Function ──────────────────────────────────────────────

fn transfer_inst(
    inst: &IrInst,
    state: &mut HashMap<u32, AbstractValue>,
    pred_exit_states: &HashMap<BlockId, HashMap<u32, AbstractValue>>,
) {
    match inst {
        IrInst::Binary { dst, op, lhs, rhs } => {
            let l = eval_abstract(lhs, state);
            let r = eval_abstract(rhs, state);
            let result = abstract_binop(*op, &l, &r);
            if let Some(id) = dst.var_id() {
                state.insert(id, result);
            }
        }
        IrInst::Unary { dst, op, src } => {
            let s = eval_abstract(src, state);
            let result = match (&s, op) {
                (AbstractValue::Constant(c), OpCode::Neg) => {
                    AbstractValue::Constant(c.wrapping_neg())
                }
                (AbstractValue::Constant(c), OpCode::Not) => AbstractValue::Constant(!*c),
                _ => s,
            };
            if let Some(id) = dst.var_id() {
                state.insert(id, result);
            }
        }
        IrInst::Load { dst, .. } => {
            // Loads produce Top (we don't track memory abstractly yet)
            if let Some(id) = dst.var_id() {
                state.insert(id, AbstractValue::Top);
            }
        }
        IrInst::Phi { dst, incoming } => {
            // Sound phi semantics: each incoming value must be evaluated in the
            // EXIT state of the predecessor edge it arrives on — not the current
            // block's (partially-updated) state.
            //
            // Conservative fallback: if a predecessor has no recorded exit
            // state, constants are still evaluated exactly and any variable
            // reference is widened to Top (any value possible).
            let mut result = AbstractValue::Bottom;
            for (pred_id, val) in incoming {
                let v = match pred_exit_states.get(pred_id) {
                    Some(pred_state) => eval_abstract(val, pred_state),
                    None => match val {
                        Value::Const(c) => AbstractValue::Constant(*c),
                        _ => AbstractValue::Top,
                    },
                };
                result = result.join(&v);
            }
            if let Some(id) = dst.var_id() {
                state.insert(id, result);
            }
        }
        IrInst::Call {
            dst: Some(dst_val), ..
        } => {
            // Calls produce Top (unknown return value)
            if let Some(id) = dst_val.var_id() {
                state.insert(id, AbstractValue::Top);
            }
        }
        _ => {} // Branches, stores, returns don't modify variable state
    }
}

fn eval_abstract(value: &Value, state: &HashMap<u32, AbstractValue>) -> AbstractValue {
    match value {
        Value::Const(v) => AbstractValue::Constant(*v),
        Value::Var { id, .. } => state.get(id).cloned().unwrap_or(AbstractValue::Top),
        _ => AbstractValue::Top,
    }
}

fn abstract_binop(op: OpCode, lhs: &AbstractValue, rhs: &AbstractValue) -> AbstractValue {
    match (lhs, rhs) {
        (AbstractValue::Constant(a), AbstractValue::Constant(b)) => {
            let result = match op {
                OpCode::Add => Some(a.wrapping_add(*b)),
                OpCode::Sub => Some(a.wrapping_sub(*b)),
                OpCode::Mul => Some(a.wrapping_mul(*b)),
                OpCode::Div if *b != 0 => Some(a.wrapping_div(*b)),
                OpCode::Mod if *b != 0 => Some(a.wrapping_rem(*b)),
                OpCode::And => Some(a & b),
                OpCode::Or => Some(a | b),
                OpCode::Xor => Some(a ^ b),
                OpCode::Shl if *b >= 0 && *b < 64 => Some(a.wrapping_shl(*b as u32)),
                OpCode::Shr if *b >= 0 && *b < 64 => {
                    Some((*a as u64).wrapping_shr(*b as u32) as i64)
                }
                _ => None,
            };
            result
                .map(AbstractValue::Constant)
                .unwrap_or(AbstractValue::Top)
        }
        // Range arithmetic (simplified)
        (AbstractValue::Range { lo: a_lo, hi: a_hi }, AbstractValue::Constant(b)) => match op {
            OpCode::Add => AbstractValue::Range {
                lo: a_lo.wrapping_add(*b),
                hi: a_hi.wrapping_add(*b),
            },
            OpCode::Sub => AbstractValue::Range {
                lo: a_lo.wrapping_sub(*b),
                hi: a_hi.wrapping_sub(*b),
            },
            OpCode::Mul if *b >= 0 => AbstractValue::Range {
                lo: a_lo.wrapping_mul(*b),
                hi: a_hi.wrapping_mul(*b),
            },
            _ => AbstractValue::Top,
        },
        (AbstractValue::Constant(a), AbstractValue::Range { lo: b_lo, hi: b_hi }) => match op {
            OpCode::Add => AbstractValue::Range {
                lo: a.wrapping_add(*b_lo),
                hi: a.wrapping_add(*b_hi),
            },
            OpCode::Sub => AbstractValue::Range {
                lo: a.wrapping_sub(*b_hi),
                hi: a.wrapping_sub(*b_lo),
            },
            _ => AbstractValue::Top,
        },
        _ => AbstractValue::Top,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_constants() {
        let a = AbstractValue::Constant(5);
        let b = AbstractValue::Constant(10);
        assert_eq!(a.join(&b), AbstractValue::Range { lo: 5, hi: 10 });
    }

    #[test]
    fn test_join_same_constant() {
        let a = AbstractValue::Constant(7);
        let b = AbstractValue::Constant(7);
        assert_eq!(a.join(&b), AbstractValue::Constant(7));
    }

    #[test]
    fn test_join_with_bottom() {
        let a = AbstractValue::Bottom;
        let b = AbstractValue::Constant(42);
        assert_eq!(a.join(&b), AbstractValue::Constant(42));
    }

    #[test]
    fn test_join_with_top() {
        let a = AbstractValue::Constant(42);
        let b = AbstractValue::Top;
        assert_eq!(a.join(&b), AbstractValue::Top);
    }

    #[test]
    fn test_widen_large_range() {
        let a = AbstractValue::Range {
            lo: 0,
            hi: 1_000_000_000,
        };
        let b = AbstractValue::Range {
            lo: 0,
            hi: 10_000_000_000,
        };
        assert_eq!(a.widen(&b), AbstractValue::Top);
    }

    #[test]
    fn test_abstract_add() {
        let a = AbstractValue::Constant(3);
        let b = AbstractValue::Constant(7);
        assert_eq!(
            abstract_binop(OpCode::Add, &a, &b),
            AbstractValue::Constant(10)
        );
    }

    #[test]
    fn test_abstract_range_add() {
        let a = AbstractValue::Range { lo: 0, hi: 10 };
        let b = AbstractValue::Constant(5);
        assert_eq!(
            abstract_binop(OpCode::Add, &a, &b),
            AbstractValue::Range { lo: 5, hi: 15 }
        );
    }
}
