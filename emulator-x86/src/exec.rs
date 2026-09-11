//! IR interpreter: executes a lifted [`IrFunction`] against guest state.
//!
//! Conservative by design: anything the interpreter cannot model surfaces
//! as [`ExitReason::Unsupported`] and the machine stops cleanly instead of
//! guessing. See `lib.rs` for the exact supported-instruction matrix.

use std::collections::{BTreeSet, VecDeque};

use freakre_ir::ir::{BlockId, IrFunction, IrInst, OpCode, Value};

use crate::env::EmuEnv;
use crate::memory::{MemRegion, Memory};
use crate::state::{mask, reg_ref, sext, ty_bits, Machine};

/// Default hard memory budget: 64 MiB of resident guest pages.
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Default number of trace entries kept in the ring buffer.
pub const DEFAULT_TRACE_CAPACITY: usize = 4096;

/// Which budget was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// Interpretation step limit hit.
    Steps,
    /// Guest memory footprint limit hit.
    Memory,
}

impl std::fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetKind::Steps => write!(f, "steps"),
            BudgetKind::Memory => write!(f, "memory"),
        }
    }
}

/// Why emulation stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// A `RETURN` executed — clean exit.
    Return,
    /// Control reached a block with no terminator (ran off the lifted code).
    FellOffEnd,
    /// Hard budget guard tripped.
    BudgetExhausted(BudgetKind),
    /// Hit a user breakpoint: execution stopped *before* the block at `addr`.
    /// Machine and memory state reflect everything up to (not including)
    /// that block, so the caller can inspect and resume.
    Breakpoint { addr: u64 },
    /// Construct the interpreter refuses to model. Always a safe stop.
    Unsupported { addr: u64, what: String },
}

/// Per-step failure inside the interpreter loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepError {
    Unsupported {
        addr: u64,
        what: String,
    },
    BudgetExhausted(BudgetKind),
    /// Terminator targets a block that does not exist in the lifted function.
    BadBlock {
        addr: u64,
        block: u32,
    },
}

impl From<StepError> for ExitReason {
    fn from(e: StepError) -> Self {
        match e {
            StepError::Unsupported { addr, what } => ExitReason::Unsupported { addr, what },
            StepError::BudgetExhausted(k) => ExitReason::BudgetExhausted(k),
            StepError::BadBlock { addr, block } => ExitReason::Unsupported {
                addr,
                what: format!("branch to undefined block bb{block}"),
            },
        }
    }
}

/// One interpreted IR instruction, kept in the tracing ring buffer.
///
/// `addr` is the *approximate* source address: every instruction of a basic
/// block carries the block's start address (derived from lifter labels).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub addr: u64,
    pub text: String,
}

impl std::fmt::Display for TraceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04X}: {}", self.addr, self.text)
    }
}

/// Record of an interpreted `CALL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// Resolved call target, when statically/runtime derivable.
    pub target: Option<u64>,
    /// Raw symbol name when the lifter emitted one (`func_XXXX`,
    /// legacy `sub_XXXX`).
    pub symbol: Option<String>,
    /// Approximate source address of the call site.
    pub at: u64,
}

/// Parse a lifter-emitted code symbol into its address.
///
/// Accepts the current `func_XXXX` scheme and the legacy `sub_XXXX` scheme
/// (the lifter was renamed in-tree; old reports and hand-written IR still
/// use `sub_`). Returns `None` for non-code symbols.
fn parse_code_symbol(s: &str) -> Option<u64> {
    s.strip_prefix("func_")
        .or_else(|| s.strip_prefix("sub_"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

/// Final report of a completed emulation run.
#[derive(Debug, Clone)]
pub struct EmuResult {
    /// Number of interpreted IR instructions (including the one that
    /// tripped a budget guard).
    pub steps: u64,
    pub exit_reason: ExitReason,
    /// Merged summary of every guest-written memory region.
    pub written_regions: Vec<MemRegion>,
    /// Canonical 64-bit register file snapshot.
    pub registers: std::collections::BTreeMap<String, u64>,
    /// Defined flags snapshot ("zf", "cf", ...).
    pub flags: std::collections::BTreeMap<String, bool>,
    /// Approximate source address of the last executed block.
    pub final_address: u64,
    /// Every executed call (direct and indirect), in execution order.
    /// Indirect targets are resolved from the machine state at the call site.
    pub calls: Vec<CallRecord>,
}

/// Control-flow outcome of interpreting one IR instruction.
enum Flow {
    Next,
    Jump(BlockId),
    Halt(ExitReason),
}

/// The mini-emulator: machine state + sparse memory + environment hooks +
/// trace ring buffer. Feed it a lifted [`IrFunction`] via [`Emulator::run`].
pub struct Emulator<E: EmuEnv> {
    pub machine: Machine,
    mem: Memory,
    env: E,
    trace: VecDeque<TraceEntry>,
    trace_cap: usize,
    calls: Vec<CallRecord>,
    last_addr: u64,
    breakpoints: BTreeSet<u64>,
}

/// Distinct block addresses visited by a trace, ascending.
///
/// Cheap dynamic-coverage signal: run a stub, collect [`Emulator::trace`],
/// and every covered address maps back to decoded bytes for highlighting
/// (or reveals dead branches for deobfuscation triage).
pub fn block_coverage(trace: &[TraceEntry]) -> Vec<u64> {
    let mut set = BTreeSet::new();
    for t in trace {
        set.insert(t.addr);
    }
    set.into_iter().collect()
}

/// Address encoded in a lifter block label (`entry`, `bb_<off>`,
/// `loc_<hex>`, `fall_<hex>`), relative to the function base.
pub fn block_address(label: &str, base: u64) -> Option<u64> {
    if let Some(rest) = label.strip_prefix("bb_") {
        return rest
            .parse::<usize>()
            .ok()
            .map(|o| base.wrapping_add(o as u64));
    }
    if let Some(rest) = label.strip_prefix("loc_") {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = label.strip_prefix("fall_") {
        return u64::from_str_radix(rest, 16).ok();
    }
    if label == "entry" {
        return Some(base);
    }
    None
}

/// Pick the block to start execution at for `base + entry_offset`.
/// Falls back to the entry block for offset 0.
fn find_entry_block(func: &IrFunction, base: u64, entry_offset: u64) -> Option<BlockId> {
    if entry_offset == 0 {
        return Some(func.entry_block);
    }
    let want = base.wrapping_add(entry_offset);
    let mut empty_match = None;
    for b in &func.blocks {
        if block_address(&b.label, base) == Some(want) {
            if !b.insts.is_empty() {
                return Some(b.id);
            }
            empty_match = empty_match.or(Some(b.id));
        }
    }
    if let Some(id) = empty_match {
        return Some(id);
    }
    // Fallback: find block whose source_range contains `want`
    for b in &func.blocks {
        if let Some((start, end)) = b.source_range {
            if want >= start && want < end {
                return Some(b.id);
            }
        }
    }
    // Second fallback: want is inside a block's byte range (for mid-block entry like XOR_LOOP+4)
    // Use block_address ordering: find the block with greatest address <= want.
    // Empty label blocks (e.g. a bare `loc_XXXX` jump target) must not shadow
    // a non-empty block: starting in an empty block falls off immediately.
    let mut best: Option<(u64, BlockId)> = None;
    let mut best_nonempty: Option<(u64, BlockId)> = None;
    for b in &func.blocks {
        if let Some(addr) = block_address(&b.label, base) {
            if addr <= want && want.wrapping_sub(addr) < 15 {
                match best {
                    Some((best_addr, _)) if best_addr > addr => {}
                    _ => best = Some((addr, b.id)),
                }
                if !b.insts.is_empty() {
                    match best_nonempty {
                        Some((best_addr, _)) if best_addr > addr => {}
                        _ => best_nonempty = Some((addr, b.id)),
                    }
                }
            }
        }
    }
    if let Some((best_addr, id)) = best_nonempty.or(best) {
        // Verify that want is before the next block's address (if any)
        let mut next_addr: Option<u64> = None;
        for b in &func.blocks {
            if let Some(addr) = block_address(&b.label, base) {
                if addr > want {
                    next_addr = Some(match next_addr {
                        Some(n) if n < addr => n,
                        Some(n) => n.min(addr),
                        None => addr,
                    });
                }
            }
        }
        // If want is inside the best block's extent (up to next block or end), return it
        if next_addr.map(|n| want < n).unwrap_or(true) {
            // Also ensure want is not too far from best_addr (max insn len)
            if want.wrapping_sub(best_addr) < 15 {
                return Some(id);
            }
        }
    }
    None
}

fn unsup(addr: u64, what: impl Into<String>) -> StepError {
    StepError::Unsupported {
        addr,
        what: what.into(),
    }
}

/// Find the instruction index within a block whose source address matches `want`.
///
/// Uses `source_range` when available; falls back to matching the block's own
/// label address (for single-instruction blocks or blocks without per-inst
/// address metadata). Returns `(BlockId, inst_index)` if found.
fn find_instruction_at(func: &IrFunction, base: u64, want: u64) -> Option<(BlockId, usize)> {
    for b in &func.blocks {
        // Check source_range first (most precise)
        if let Some((start, end)) = b.source_range {
            if want >= start && want < end {
                // Try to pinpoint the exact instruction by proportional offset
                if !b.insts.is_empty() {
                    let span = end.saturating_sub(start).max(1);
                    let off = want.saturating_sub(start);
                    let idx = ((off as f64 / span as f64) * b.insts.len() as f64) as usize;
                    return Some((b.id, idx.min(b.insts.len().saturating_sub(1))));
                }
                return Some((b.id, 0));
            }
        }
        // Fallback: block label address matches exactly
        if let Some(addr) = block_address(&b.label, base) {
            if addr == want && !b.insts.is_empty() {
                return Some((b.id, 0));
            }
        }
    }
    None
}

/// Split a basic block at instruction index `split_idx`, creating a new
/// continuation block. All terminators pointing at the original block are
/// left unchanged — the caller is responsible for re-targeting if needed.
///
/// The new block inherits the original block's successors and gets a fresh
/// `BlockId`. The original block keeps instructions `[0..split_idx]` and
/// gains a `Branch` terminator to the new block.
fn split_block_at(func: &mut IrFunction, block_id: BlockId, split_idx: usize) {
    // Phase 1: extract data from the original block (no overlapping borrows)
    let (tail_insts, succs, source_tail, orig_label) = {
        let Some(block) = func.block_mut(block_id) else {
            return;
        };
        if split_idx == 0 || split_idx >= block.insts.len() {
            return;
        }
        let tail: Vec<IrInst> = block.insts.drain(split_idx..).collect();
        let s = std::mem::take(&mut block.successors);
        let sr = block.source_range.map(|(_, end)| (end, end));
        let lbl = block.label.clone();
        (tail, s, sr, lbl)
    };

    // Phase 2: create and populate the new continuation block
    let new_label = format!("{}_split", orig_label);
    let new_id = func.add_block(&new_label);
    if let Some(nb) = func.block_mut(new_id) {
        nb.insts = tail_insts;
        nb.successors = succs;
        nb.source_range = source_tail;
    }

    // Phase 3: update the original block with branch to continuation
    if let Some(block) = func.block_mut(block_id) {
        block.successors.push(new_id);
        block.insts.push(IrInst::Branch { target: new_id });
    }
}

impl<E: EmuEnv> Emulator<E> {
    /// Fresh emulator with the default 64 MiB memory budget and 4096-entry
    /// trace ring.
    pub fn new(env: E) -> Self {
        Self::with_limits(env, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_TRACE_CAPACITY)
    }

    /// Fresh emulator with explicit budgets.
    pub fn with_limits(env: E, max_memory_bytes: u64, trace_capacity: usize) -> Self {
        Emulator {
            machine: Machine::new(),
            mem: Memory::new(max_memory_bytes),
            env,
            trace: VecDeque::with_capacity(trace_capacity.min(4096)),
            trace_cap: trace_capacity,
            calls: Vec::new(),
            last_addr: 0,
            breakpoints: BTreeSet::new(),
        }
    }

    // ─── Setup helpers ───────────────────────────────────────────────

    /// Seed guest memory before a run (caller-provided image/data pages;
    /// bypasses the runtime page budget).
    pub fn init_mem(&mut self, addr: u64, data: &[u8]) {
        self.mem.load_image(addr, data);
    }

    /// Set a register by any alias name (rax/eax/al/r8d/...).
    pub fn set_reg(&mut self, name: &str, val: u64) {
        self.machine.write_reg(name, val, 64);
    }

    /// Read the full 64-bit parent slot of a register by alias name.
    pub fn reg(&self, name: &str) -> Option<u64> {
        reg_ref(name).map(|rr| self.machine.regs[rr.slot as usize])
    }

    /// Guest memory (inspection after a run).
    pub fn memory(&self) -> &Memory {
        &self.mem
    }

    /// Environment hooks (syscall log etc.).
    pub fn env(&self) -> &E {
        &self.env
    }

    pub fn env_mut(&mut self) -> &mut E {
        &mut self.env
    }

    /// Ordered trace snapshot (oldest first).
    pub fn trace(&self) -> Vec<TraceEntry> {
        self.trace.iter().cloned().collect()
    }

    /// Calls recorded during interpretation.
    pub fn calls(&self) -> &[CallRecord] {
        &self.calls
    }

    // ─── Breakpoints ───────────────────────────────────────────────────

    /// Stop before the block at `addr` on the next run. Addresses are guest
    /// VAs, compared against per-block addresses from lifter labels.
    pub fn add_breakpoint(&mut self, addr: u64) {
        self.breakpoints.insert(addr);
    }

    /// Remove a breakpoint. Returns `true` when one existed.
    pub fn remove_breakpoint(&mut self, addr: u64) -> bool {
        self.breakpoints.remove(&addr)
    }

    /// Drop all breakpoints.
    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
    }

    /// Currently armed breakpoint addresses, ascending.
    pub fn breakpoints(&self) -> Vec<u64> {
        self.breakpoints.iter().copied().collect()
    }

    /// Map `data` into guest memory at `base` (code, tables, globals).
    pub fn load_image(&mut self, base: u64, data: &[u8]) {
        self.mem.load_image(base, data);
    }

    /// Run until the block at `target` (one-shot breakpoint), `Return`, or
    /// any other stop. The temporary breakpoint is always removed, even when
    /// the run stops elsewhere.
    pub fn run_to(
        &mut self,
        func: &IrFunction,
        base: u64,
        entry_offset: u64,
        target: u64,
        max_steps: u64,
    ) -> EmuResult {
        let had = self.breakpoints.contains(&target);
        self.breakpoints.insert(target);
        let res = self.run(func, base, entry_offset, max_steps);
        if !had {
            self.breakpoints.remove(&target);
        }
        res
    }

    // ─── Run loop ────────────────────────────────────────────────────

    /// Interpret `func` starting at `base + entry_offset`.
    ///
    /// Never panics on adversarial IR: every failure mode collapses into
    /// the returned [`ExitReason`].
    pub fn run(
        &mut self,
        func: &IrFunction,
        base: u64,
        entry_offset: u64,
        max_steps: u64,
    ) -> EmuResult {
        // Each run reports only its own calls.
        self.calls.clear();
        // For mid-block entry (e.g., XOR_LOOP+4 where 0x04 is inside the entry block),
        // split the containing block at `want` so execution starts at the correct instruction.
        let func_owned: Option<IrFunction>;
        let func_ref: &IrFunction = if entry_offset != 0 {
            let want = base.wrapping_add(entry_offset);
            if let Some((block_id, inst_idx)) = find_instruction_at(func, base, want) {
                if inst_idx > 0 {
                    let mut cloned = func.clone();
                    split_block_at(&mut cloned, block_id, inst_idx);
                    func_owned = Some(cloned);
                    func_owned.as_ref().unwrap()
                } else {
                    func
                }
            } else {
                func
            }
        } else {
            func
        };
        let (steps, exit_reason) = match find_entry_block(func_ref, base, entry_offset) {
            None => (
                0,
                ExitReason::Unsupported {
                    addr: base.wrapping_add(entry_offset),
                    what: "no lifted block at entry offset".into(),
                },
            ),
            Some(start) => self.exec(func_ref, start, base, max_steps),
        };
        EmuResult {
            steps,
            exit_reason,
            written_regions: self.mem.written_regions(),
            registers: self.machine.gpr_snapshot(),
            flags: self.machine.flag_snapshot(),
            final_address: self.last_addr,
            calls: self.calls.clone(),
        }
    }

    fn exec(
        &mut self,
        func: &IrFunction,
        start: BlockId,
        base: u64,
        max_steps: u64,
    ) -> (u64, ExitReason) {
        let mut steps: u64 = 0;
        let mut cur = start;
        loop {
            let Some(block) = func.block(cur) else {
                let addr = self.last_addr;
                return (steps, StepError::BadBlock { addr, block: cur.0 }.into());
            };
            let baddr = block_address(&block.label, base).unwrap_or(self.last_addr);
            self.last_addr = baddr;

            // Breakpoints fire before the block executes, so state reflects
            // everything strictly prior to `baddr`.
            if self.breakpoints.contains(&baddr) {
                return (steps, ExitReason::Breakpoint { addr: baddr });
            }

            let mut jump: Option<BlockId> = None;
            for inst in &block.insts {
                steps += 1;
                if steps > max_steps {
                    return (steps, ExitReason::BudgetExhausted(BudgetKind::Steps));
                }
                self.push_trace(TraceEntry {
                    addr: baddr,
                    text: inst.display(),
                });
                match self.execute(inst, baddr) {
                    Ok(Flow::Next) => {}
                    Ok(Flow::Jump(target)) => {
                        jump = Some(target);
                        break;
                    }
                    Ok(Flow::Halt(reason)) => return (steps, reason),
                    Err(e) => return (steps, e.into()),
                }
            }

            match jump {
                Some(next) => cur = next,
                // Ran off the end of a block without executing a terminator.
                None => return (steps, ExitReason::FellOffEnd),
            }
        }
    }

    fn push_trace(&mut self, entry: TraceEntry) {
        if self.trace_cap == 0 {
            return;
        }
        if self.trace.len() >= self.trace_cap {
            self.trace.pop_front();
        }
        self.trace.push_back(entry);
    }

    // ─── Instruction interpretation ──────────────────────────────────

    fn execute(&mut self, inst: &IrInst, addr: u64) -> Result<Flow, StepError> {
        match inst {
            IrInst::Nop => Ok(Flow::Next),

            IrInst::Binary { dst, op, lhs, rhs } => self.exec_binary(dst, *op, lhs, rhs, addr),

            IrInst::Unary { dst, op, src } => self.exec_unary(dst, *op, src, addr),

            IrInst::Adc { dst, a, b, carry } => {
                let av = self.eval(a, addr)?;
                let bv = self.eval(b, addr)?;
                let cv = self.eval(carry, addr)? & 1;
                let bits = ty_bits(&dst.ty());
                let r = av.wrapping_add(bv).wrapping_add(cv) & mask(bits);
                self.write_dst(dst, r);
                Ok(Flow::Next)
            }

            IrInst::Sbb { dst, a, b, carry } => {
                let av = self.eval(a, addr)?;
                let bv = self.eval(b, addr)?;
                let cv = self.eval(carry, addr)? & 1;
                let bits = ty_bits(&dst.ty());
                let r = av.wrapping_sub(bv).wrapping_sub(cv) & mask(bits);
                self.write_dst(dst, r);
                Ok(Flow::Next)
            }

            IrInst::Load { dst, addr: a, size } => {
                if *size == 0 || *size > 8 {
                    return Err(unsup(addr, format!("{size}-byte LOAD unsupported")));
                }
                let va = self.eval(a, addr)?;
                let n = *size as usize;
                let mut buf = [0u8; 8];
                match self.env.mem_read(va, *size) {
                    Some(data) => {
                        let m = data.len().min(n);
                        buf[..m].copy_from_slice(&data[..m]);
                    }
                    None => self.mem.read_bytes(va, &mut buf[..n]),
                }
                let val = u64::from_le_bytes(buf) & mask(*size * 8);
                self.write_dst(dst, val);
                Ok(Flow::Next)
            }

            IrInst::Store {
                addr: a,
                value,
                size,
            } => {
                if *size == 0 || *size > 8 {
                    return Err(unsup(addr, format!("{size}-byte STORE unsupported")));
                }
                let va = self.eval(a, addr)?;
                let vv = self.eval(value, addr)? & mask(*size * 8);
                let bytes = vv.to_le_bytes()[..*size as usize].to_vec();
                self.env.mem_write(va, &bytes);
                let status = self.mem.write_bytes(va, &bytes);
                if let Some(kind) = status.budget_kind() {
                    return Err(StepError::BudgetExhausted(kind));
                }
                Ok(Flow::Next)
            }

            IrInst::Branch { target } => Ok(Flow::Jump(*target)),

            IrInst::CBranch {
                cond,
                target_true,
                target_false,
            } => {
                let c = self.eval(cond, addr)?;
                Ok(Flow::Jump(if c != 0 {
                    *target_true
                } else {
                    *target_false
                }))
            }

            IrInst::Call { dst, target, args } => {
                let tval: Option<u64> = match target {
                    Value::Symbol(s) => parse_code_symbol(s),
                    v => Some(self.eval(v, addr)?),
                };
                let mut argv = Vec::with_capacity(args.len());
                for a in args {
                    argv.push(self.eval(a, addr)?);
                }
                self.calls.push(CallRecord {
                    target: tval,
                    symbol: match target {
                        Value::Symbol(s) => Some(s.clone()),
                        _ => None,
                    },
                    at: addr,
                });
                // Stub callee: RAX = 0, keep executing the fall-through.
                if let Some(d) = dst {
                    self.write_dst(d, 0);
                }
                Ok(Flow::Next)
            }

            IrInst::Return { value } => {
                if let Some(v) = value {
                    let r = self.eval(v, addr)?;
                    self.machine.write_reg("rax", r, 64);
                }
                Ok(Flow::Halt(ExitReason::Return))
            }

            IrInst::Syscall { number, args } => {
                let num = match number {
                    Some(v) => Some(self.eval(v, addr)? as i64),
                    None => None,
                };
                let mut argv = Vec::with_capacity(args.len());
                for a in args {
                    argv.push(self.eval(a, addr)?);
                }
                let ret = self.env.syscall(num, &argv);
                self.machine.write_reg("rax", ret as u64, 64);
                Ok(Flow::Next)
            }

            IrInst::IndirectBranch { .. } => {
                Err(unsup(addr, "IndirectBranch (computed jmp) unsupported"))
            }

            IrInst::Switch { index, cases, default } => {
                let v = self.eval(index, addr)?;
                // First case whose value matches wins; cases are expected to
                // be unique, so scan order is irrelevant. Fall back to the
                // default (or fail when the dispatch is exhaustive-only and
                // the value matches nothing — same as an OOB jump table read).
                let target = cases
                    .iter()
                    .find(|(cv, _)| *cv == v as i64)
                    .map(|(_, b)| *b)
                    .or(*default);
                match target {
                    Some(b) => Ok(Flow::Jump(b)),
                    None => Err(unsup(addr, format!("SWITCH: no case for {v} and no default"))),
                }
            }

            IrInst::Phi { .. } => Err(unsup(addr, "Phi unsupported")),
        }
    }

    fn exec_binary(
        &mut self,
        dst: &Value,
        op: OpCode,
        lhs: &Value,
        rhs: &Value,
        addr: u64,
    ) -> Result<Flow, StepError> {
        let a = self.eval(lhs, addr)?;
        let b = self.eval(rhs, addr)?;
        let lw = ty_bits(&lhs.ty());
        let rw = ty_bits(&rhs.ty());

        let val: u64 = match op {
            OpCode::Add => a.wrapping_add(b),
            OpCode::Sub => a.wrapping_sub(b),
            OpCode::Mul => a.wrapping_mul(b),
            OpCode::Div => {
                if b == 0 {
                    return Err(unsup(addr, "integer division by zero"));
                }
                a / b
            }
            OpCode::Mod => {
                if b == 0 {
                    return Err(unsup(addr, "integer modulo by zero"));
                }
                a % b
            }
            OpCode::And => a & b,
            OpCode::Or => a | b,
            OpCode::Xor => a ^ b,
            OpCode::Shl => a.wrapping_shl((b & 63) as u32),
            OpCode::Shr => a.wrapping_shr((b & 63) as u32),
            OpCode::Sar => sext(a, lw).wrapping_shr((b & 63) as u32) as u64,
            OpCode::Rol => rotate(a, lw, b, true),
            OpCode::Ror => rotate(a, lw, b, false),
            OpCode::Eq => (a == b) as u64,
            OpCode::Ne => (a != b) as u64,
            OpCode::LtU => (a < b) as u64,
            OpCode::LeU => (a <= b) as u64,
            OpCode::GtU => (a > b) as u64,
            OpCode::GeU => (a >= b) as u64,
            OpCode::LtS => (sext(a, lw) < sext(b, rw)) as u64,
            OpCode::LeS => (sext(a, lw) <= sext(b, rw)) as u64,
            OpCode::GtS => (sext(a, lw) > sext(b, rw)) as u64,
            OpCode::GeS => (sext(a, lw) >= sext(b, rw)) as u64,
            OpCode::Copy => a,
            other => {
                return Err(unsup(addr, format!("unsupported binary op {other}")));
            }
        };
        self.write_dst(dst, val);
        Ok(Flow::Next)
    }

    fn exec_unary(
        &mut self,
        dst: &Value,
        op: OpCode,
        src: &Value,
        addr: u64,
    ) -> Result<Flow, StepError> {
        let v = self.eval(src, addr)?;
        let sw = ty_bits(&src.ty());
        let dw = ty_bits(&dst.ty());

        let val: u64 = match op {
            OpCode::Copy => v & mask(dw),
            OpCode::Zext => v & mask(dw),
            OpCode::Trunc => v & mask(dw),
            OpCode::Sext => (sext(v, sw) as u64) & mask(dw),
            OpCode::Not => !v,
            OpCode::Neg => v.wrapping_neg(),
            OpCode::FloatToFloat
            | OpCode::IntToFloat
            | OpCode::FloatToInt
            | OpCode::FloatNeg
            | OpCode::FloatAbs
            | OpCode::FloatSqrt => {
                return Err(unsup(addr, format!("float op {op} unsupported")));
            }
            other => {
                return Err(unsup(addr, format!("unsupported unary op {other}")));
            }
        };
        self.write_dst(dst, val);
        Ok(Flow::Next)
    }

    // ─── Value plumbing ──────────────────────────────────────────────

    /// Evaluate an IR value to a machine word. Total: never panics.
    fn eval(&self, v: &Value, addr: u64) -> Result<u64, StepError> {
        match v {
            Value::Const(c) => Ok(*c as u64),
            Value::WideConst(bytes) => {
                let mut buf = [0u8; 8];
                let n = bytes.len().min(8);
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(u64::from_le_bytes(buf))
            }
            Value::Var { id, ty } => {
                Ok(self.machine.vars.get(id).copied().unwrap_or(0) & mask(ty_bits(ty)))
            }
            Value::Register { name, ty } => Ok(self.machine.read_reg(name, ty)),
            Value::Symbol(s) => match parse_code_symbol(s) {
                Some(v) => Ok(v),
                None if s.starts_with("sub_") || s.starts_with("func_") => {
                    Err(unsup(addr, format!("malformed symbol @{s}")))
                }
                None => Err(unsup(addr, format!("symbolic value @{s} in data position"))),
            },
            Value::StringRef(_) => Err(unsup(addr, "StringRef in data position")),
        }
    }

    /// Assign a computed value to an IR destination. Non-storable
    /// destinations (constants, symbols) are silently dropped — the
    /// lifter never produces them and adversarial IR must not panic us.
    fn write_dst(&mut self, dst: &Value, val: u64) {
        match dst {
            Value::Var { id, ty } => {
                self.machine.vars.insert(*id, val & mask(ty_bits(ty)));
            }
            Value::Register { name, ty } => {
                self.machine.write_reg(name, val, ty_bits(ty));
            }
            _ => {}
        }
    }
}

/// Width-aware rotate: `count` is reduced modulo `bits`, result masked
/// back into the operand width (x86 rotate semantics).
fn rotate(val: u64, bits: u32, count: u64, left: bool) -> u64 {
    let bits = bits.clamp(1, 64);
    let m = mask(bits);
    let v = val & m;
    let cnt = (count % bits as u64) as u32;
    if cnt == 0 {
        return v;
    }
    if left {
        ((v << cnt) | (v >> (bits - cnt))) & m
    } else {
        ((v >> cnt) | (v << (bits - cnt))) & m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::DefaultEnv;

    #[test]
    fn rotate_width_semantics() {
        assert_eq!(rotate(0x8000_0000_0000_0001, 64, 1, true), 3); // bits {63,0} -> {0,1}
        assert_eq!(
            rotate(0x0000_0000_0000_0001, 64, 63, true),
            0x8000_0000_0000_0000
        );
        assert_eq!(rotate(0xABCD, 16, 4, true), 0xBCDA);
        assert_eq!(rotate(0xABCD, 16, 4, false), 0xDABC);
        assert_eq!(rotate(0xFF, 8, 8, true), 0xFF);
    }

    #[test]
    fn trace_ring_respects_capacity() {
        let mut emu: Emulator<DefaultEnv> = Emulator::with_limits(DefaultEnv::new(), 1 << 20, 3);
        for i in 0..10u64 {
            emu.push_trace(TraceEntry {
                addr: i,
                text: "NOP".into(),
            });
        }
        let t = emu.trace();
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].addr, 7);
        assert_eq!(t[2].addr, 9);
    }
}
