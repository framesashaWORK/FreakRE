//! Control flow structuring: convert unstructured CFG to structured AST.
//!
//! Recovers high-level control flow constructs from the control flow graph:
//! - if/else
//! - while loops (pre-condition)
//! - do-while loops (post-condition)
//! - for loops (init + condition + increment)
//! - switch/case (jump tables and comparison chains)
//! - break / continue
//! - try-catch (exception handler regions)
//! - Nested structures at arbitrary depth

use crate::ast::*;
use crate::ir_to_ast::IrToAstConverter;
use freakre_ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

// в”Ђв”Ђв”Ђ Public API в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Structure the control flow of a function into AST statements.
pub fn structure_control_flow(func: &IrFunction, converter: &mut IrToAstConverter) -> Vec<Stmt> {
    let s = ControlFlowStructurer::new(func);
    s.structure(converter)
}

// в”Ђв”Ђв”Ђ Loop classification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoopKind {
    /// Condition checked before body: `while (cond) { ... }`
    While,
    /// Condition checked after body: `do { ... } while (cond);`
    DoWhile,
    /// Init + condition + update: `for (init; cond; update) { ... }`
    For,
}

#[derive(Debug, Clone)]
struct LoopInfo {
    header: BlockId,
    back_edge_from: BlockId,
    kind: LoopKind,
    /// Blocks that belong to this loop body (excluding header for do-while).
    body_blocks: HashSet<BlockId>,
    /// The latch block (the one with the back edge).
    latch: BlockId,
    /// For `for` loops: the pre-header block containing init code.
    pre_header: Option<BlockId>,
}

// в”Ђв”Ђв”Ђ Switch / jump-table info в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[derive(Debug, Clone)]
struct SwitchInfo {
    /// Block that performs the indirect branch or comparison chain.
    dispatch_block: BlockId,
    /// The expression being switched on.
    expr: Value,
    /// case value в†’ target block
    cases: BTreeMap<i64, BlockId>,
    /// Optional default target.
    default: Option<BlockId>,
}

// в”Ђв”Ђв”Ђ Try-catch region в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[derive(Debug, Clone)]
struct TryCatchRegion {
    try_blocks: HashSet<BlockId>,
    catch_handler: BlockId,
}

// в”Ђв”Ђв”Ђ Structurer в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

struct ControlFlowStructurer<'a> {
    func: &'a IrFunction,
    loops: Vec<LoopInfo>,
    switches: Vec<SwitchInfo>,
    try_catches: Vec<TryCatchRegion>,
    /// Map from block → loop whose header is that block.
    loop_by_header: HashMap<BlockId, usize>,
    /// Immediate dominator map: block → its idom (Cooper-Harvey-Kennedy).
    idom: HashMap<BlockId, BlockId>,
    /// Every block id in the function (used to build out-of-loop boundary sets).
    all_blocks: HashSet<BlockId>,
    /// Blocks targeted by a `goto` (discovered during the first structuring
    /// pass). The second pass prepends a `Stmt::Label` at each such block's
    /// emission site so the generated `goto bbN;` resolves to valid C.
    goto_targets: std::cell::RefCell<HashSet<BlockId>>,
}

impl<'a> ControlFlowStructurer<'a> {
    fn new(func: &'a IrFunction) -> Self {
        let idom = freakre_ir::ssa::compute_dominators(func);
        let loops = detect_and_classify_loops(func, &idom);
        let loop_by_header: HashMap<BlockId, usize> = loops
            .iter()
            .enumerate()
            .map(|(i, l)| (l.header, i))
            .collect();
        let switches = detect_switches(func);
        let try_catches = detect_try_catch_regions(func);
        let all_blocks: HashSet<BlockId> = func.blocks.iter().map(|b| b.id).collect();

        ControlFlowStructurer {
            func,
            loops,
            switches,
            try_catches,
            loop_by_header,
            idom,
            all_blocks,
            goto_targets: std::cell::RefCell::new(HashSet::new()),
        }
    }

    // в”Ђв”Ђ entry point в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /// Emit a `goto` to `target` (an already-emitted block) and record the
    /// target so the second structuring pass prepends a matching label at the
    /// block's emission site.
    fn emit_goto(&self, stmts: &mut Vec<Stmt>, target: BlockId) {
        self.goto_targets.borrow_mut().insert(target);
        stmts.push(Stmt::Goto {
            label: format!("bb{}", target.0),
        });
    }

    /// If `block_id` was discovered as a `goto` target during the first pass,
    /// emit its `bbN:` label before its instructions so the jump resolves to a
    /// valid, position-correct C label.
    fn maybe_emit_label(&self, stmts: &mut Vec<Stmt>, block_id: BlockId) {
        if self.goto_targets.borrow().contains(&block_id) {
            stmts.push(Stmt::Label {
                name: format!("bb{}", block_id.0),
            });
        }
    }

    fn structure(&self, converter: &mut IrToAstConverter) -> Vec<Stmt> {
        // Pass 1: discover every backward/visited jump target. A `goto` to a
        // block is only recognised after that block has already been emitted,
        // so we cannot prepend its label during a single forward pass. Running
        // the structuring once (discarding output) records all targets; the
        // second pass then emits the labels at the correct, earlier positions.
        {
            let mut ctx = StructContext::default();
            let empty: HashSet<BlockId> = HashSet::new();
            let mut probe = IrToAstConverter::new(self.func);
            let _ = self.process_region(
                self.func.entry_block,
                None,
                &mut probe,
                &mut ctx,
                0,
                &empty,
            );
        }

        // Pass 2: emit the structured AST, now with labels for goto targets.
        let mut ctx = StructContext::default();
        let empty: HashSet<BlockId> = HashSet::new();
        self.process_region(
            self.func.entry_block,
            None, // no enclosing loop
            converter,
            &mut ctx,
            0,
            &empty,
        )
    }

    // в”Ђв”Ђ region processor в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /// Process a region of the CFG starting at `start`.
    /// `enclosing_loop_idx` is the index into `self.loops` if we are inside a loop.
    /// `boundaries` contains blocks at which this region must stop without
    /// consuming them (e.g., the merge point of the if/else that spawned it),
    /// so each block is emitted exactly once and merge points are processed
    /// by their continuation instead of being duplicated with gotos.
    fn process_region(
        &self,
        start: BlockId,
        enclosing_loop_idx: Option<usize>,
        converter: &mut IrToAstConverter,
        ctx: &mut StructContext,
        depth: usize,
        boundaries: &HashSet<BlockId>,
    ) -> Vec<Stmt> {
        const MAX_DEPTH: usize = 512;
        if depth > MAX_DEPTH {
            return vec![Stmt::Comment("structuring depth limit reached".into())];
        }

        let mut stmts = Vec::new();
        let mut current = Some(start);

        while let Some(block_id) = current {
            // Region boundary (merge point): leave for the continuation.
            if boundaries.contains(&block_id) {
                break;
            }

            // Already visited in this region? в†’ break/continue/goto
            if ctx.visited.contains(&block_id) {
                let header_continue = enclosing_loop_idx
                    .map(|loop_idx| {
                        let li = &self.loops[loop_idx];
                        // `continue` is only valid when jumping to the
                        // condition re-check of a while/for loop.
                        li.header == block_id
                            && matches!(li.kind, LoopKind::While | LoopKind::For)
                    })
                    .unwrap_or(false);
                if header_continue {
                    stmts.push(Stmt::Continue);
                } else {
                    // Backward jump to an already-emitted block: emit a `goto`
                    // whose target label is prepended when that block was
                    // emitted (see `maybe_emit_label`), keeping the C valid.
                    self.emit_goto(&mut stmts, block_id);
                }
                break;
            }

            // в”Ђв”Ђ Check if this block is a loop header в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
            if let Some(&loop_idx) = self.loop_by_header.get(&block_id) {
                let loop_stmts = self.structure_loop(loop_idx, enclosing_loop_idx, converter, ctx, depth);
                stmts.extend(loop_stmts);
                // After the loop, follow the successor that is NOT part of the loop
                // (unless a break arm already consumed it).
                current = self
                    .loop_exit_block(loop_idx)
                    .filter(|e| !ctx.visited.contains(e));
                continue;
            }

            // в”Ђв”Ђ Check if this block is a switch dispatch в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
            if let Some(sw_idx) = self.switch_at(block_id) {
                let (sw_stmts, cont) = self.structure_switch(
                    sw_idx,
                    enclosing_loop_idx,
                    converter,
                    ctx,
                    depth,
                    boundaries,
                );
                stmts.extend(sw_stmts);
                current = cont.or_else(|| self.switch_continuation(sw_idx, ctx));
                continue;
            }

            // в”Ђв”Ђ Check if this block starts a try-catch region в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
            if let Some(tc_idx) = self.try_catch_at(block_id) {
                let tc_stmts = self.structure_try_catch(tc_idx, enclosing_loop_idx, converter, ctx, depth);
                stmts.extend(tc_stmts);
                current = self.try_catch_exit(tc_idx);
                continue;
            }

            // в”Ђв”Ђ Normal block в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
            ctx.visited.insert(block_id);

            // A block that is the target of a backward `goto` needs a label so
            // the generated jump resolves (otherwise the C would be dangling).
            self.maybe_emit_label(&mut stmts, block_id);

            let block = match self.func.block(block_id) {
                Some(b) => b,
                None => break,
            };

            // Convert non-terminator instructions (unless a break arm
            // already emitted them and only left the terminator pending).
            if !ctx.insts_emitted.remove(&block_id) {
                for inst in &block.insts {
                    if !inst.is_terminator() {
                        stmts.extend(converter.convert_inst(inst));
                    }
                }
            }

            // Handle terminator
            match block.terminator() {
                Some(IrInst::Branch { target }) => {
                    // If target is in a different structural context, handle accordingly
                    if self.is_back_edge(block_id, *target) {
                        // Back edge: `continue` when it returns to the
                        // condition re-check of the enclosing while/for
                        // loop; anything else (no enclosing loop, outer
                        // header, do-while body top) cannot be expressed
                        // as `continue` and falls back to goto.
                        let is_loop_continue = enclosing_loop_idx
                            .map(|loop_idx| {
                                let li = &self.loops[loop_idx];
                                li.header == *target
                                    && matches!(li.kind, LoopKind::While | LoopKind::For)
                            })
                            .unwrap_or(false);
                        if is_loop_continue {
                            stmts.push(Stmt::Continue);
                        } else {
                            self.emit_goto(&mut stmts, *target);
                        }
                        break;
                    }
                    if boundaries.contains(target) {
                        // Merge point of an enclosing if/else: stop here.
                        break;
                    }
                    current = Some(*target);
                }

                Some(IrInst::CBranch { cond, target_true, target_false }) => {
                    let cond_expr = converter.convert_value_to_expr(cond);

                    // Detect do-while: if the false branch goes back to a loop header
                    // that encloses us, this might be the do-while condition at the bottom.
                    if let Some(loop_idx) = enclosing_loop_idx {
                        let li = &self.loops[loop_idx];
                        if li.kind == LoopKind::DoWhile && li.latch == block_id {
                            // This is the do-while exit condition вЂ” already handled by structure_loop
                            break;
                        }
                    }

                    // Break recognition: inside a loop, a conditional whose
                    // arm leaves the natural loop body is an early exit and
                    // must become `break` instead of recursing into post-loop
                    // code (which would swallow it and strand the continuation).
                    if let Some(loop_idx) = enclosing_loop_idx {
                        let body = self.loops[loop_idx].body_blocks.clone();
                        let tt_out = !body.contains(target_true);
                        let tf_out = !body.contains(target_false);
                        if tt_out || tf_out {
                            let exit_b = self.loop_exit_block(loop_idx);
                            if tt_out && tf_out {
                                let then_arm = self.build_break_arm(
                                    *target_true,
                                    loop_idx,
                                    exit_b,
                                    enclosing_loop_idx,
                                    converter,
                                    ctx,
                                    depth,
                                    boundaries,
                                );
                                let else_arm = self.build_break_arm(
                                    *target_false,
                                    loop_idx,
                                    exit_b,
                                    enclosing_loop_idx,
                                    converter,
                                    ctx,
                                    depth,
                                    boundaries,
                                );
                                if matches!(then_arm.as_slice(), [Stmt::Break])
                                    && matches!(else_arm.as_slice(), [Stmt::Break])
                                {
                                    stmts.push(Stmt::Break);
                                    current = None;
                                    continue;
                                }
                                stmts.push(Stmt::If {
                                    cond: cond_expr,
                                    then_body: then_arm,
                                    else_body: Some(else_arm),
                                });
                                current = None;
                                continue;
                            }
                            let (out_target, in_target, negate) = if tt_out {
                                (*target_true, *target_false, false)
                            } else {
                                (*target_false, *target_true, true)
                            };
                            let break_arm = self.build_break_arm(
                                out_target,
                                loop_idx,
                                exit_b,
                                enclosing_loop_idx,
                                converter,
                                ctx,
                                depth,
                                boundaries,
                            );
                            let break_cond = if negate {
                                Expr::Unary {
                                    op: UnOp::LogNot,
                                    operand: Box::new(cond_expr),
                                }
                            } else {
                                cond_expr
                            };
                            stmts.push(Stmt::If {
                                cond: break_cond,
                                then_body: break_arm,
                                else_body: None,
                            });
                            // The surviving in-loop path continues linearly.
                            current = Some(in_target);
                            continue;
                        }
                    }

                    // Find the merge point FIRST and pass it as a boundary to
                    // both arms, so neither arm consumes blocks past the join.
                    // Inside a loop the search is confined to the loop body:
                    // a join outside the loop would make this region swallow
                    // the loop exit, which the continuation then re-visits
                    // as a spurious backward goto.
                    let loop_scope = enclosing_loop_idx.map(|idx| &self.loops[idx].body_blocks);
                    let merge = self.find_merge_point(*target_true, *target_false, loop_scope);
                    let mut arm_boundaries = boundaries.clone();
                    if let Some(m) = merge {
                        arm_boundaries.insert(m);
                    }

                    let then_body = self.process_region(
                        *target_true,
                        enclosing_loop_idx,
                        converter,
                        ctx,
                        depth + 1,
                        &arm_boundaries,
                    );
                    let else_body = self.process_region(
                        *target_false,
                        enclosing_loop_idx,
                        converter,
                        ctx,
                        depth + 1,
                        &arm_boundaries,
                    );

                    let else_body = if else_body.is_empty() {
                        None
                    } else {
                        Some(else_body)
                    };

                    // `if (c) { continue; } else { continue; }` is just
                    // `continue;` — collapse the degenerate form.
                    if matches!(then_body.as_slice(), [Stmt::Continue])
                        && matches!(else_body.as_deref(), Some([Stmt::Continue]))
                    {
                        stmts.push(Stmt::Continue);
                        current = None;
                        continue;
                    }

                    stmts.push(Stmt::If {
                        cond: cond_expr,
                        then_body,
                        else_body,
                    });

                    // Continue at the merge point (now guaranteed unvisited).
                    // A visited merge means the branch rejoins already-emitted
                    // code (loop-shaped join): both arms above turned their
                    // edges into continue/goto, so re-entering the merge here
                    // would only produce a spurious backward goto.
                    current = merge.filter(|m| *m != block_id && !ctx.visited.contains(m));
                }

                Some(IrInst::Return { value }) => {
                    let ret_value = value.as_ref().map(|v| converter.convert_value_to_expr(v));
                    stmts.push(Stmt::Return { value: ret_value });
                    break;
                }

                Some(IrInst::IndirectBranch { target }) => {
                    let target_expr = converter.convert_value_to_expr(target);
                    stmts.push(Stmt::Expr(Expr::Call {
                        func: "goto".to_string(),
                        args: vec![target_expr],
                    }));
                    break;
                }

                _ => {
                    break;
                }
            }
        }

        stmts
    }

    // в”Ђв”Ђ Loop structuring в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    fn structure_loop(
        &self,
        loop_idx: usize,
        _enclosing_loop_idx: Option<usize>,
        converter: &mut IrToAstConverter,
        ctx: &mut StructContext,
        depth: usize,
    ) -> Vec<Stmt> {
        let li = &self.loops[loop_idx];

        match li.kind {
            LoopKind::While => {
                // while (header_cond) { body }
                let header = self.func.block(li.header).unwrap();
                let cond_expr = match header.terminator() {
                    Some(IrInst::CBranch { cond, target_true, target_false }) => {
                        let e = converter.convert_value_to_expr(cond);
                        if li.body_blocks.contains(target_false) && !li.body_blocks.contains(target_true) {
                            Expr::Unary {
                                op: UnOp::LogNot,
                                operand: Box::new(e),
                            }
                        } else {
                            e
                        }
                    }
                    _ => Expr::BoolLit(true),
                };

                let mut header_stmts = Vec::new();
                for inst in &header.insts {
                    if !inst.is_terminator() {
                        header_stmts.extend(converter.convert_inst(inst));
                    }
                }

                // Mark header as visited so inner processing knows it's a loop boundary
                ctx.visited.insert(li.header);

                // Process body blocks (skip header itself)
                let mut full_body = header_stmts;
                full_body.extend(self.process_loop_body(loop_idx, Some(loop_idx), converter, ctx, depth));
                trim_trailing_continue(&mut full_body);

                vec![Stmt::While { cond: cond_expr, body: full_body }]
            }

            LoopKind::DoWhile => {
                // do { body } while (latch_cond);
                ctx.visited.insert(li.header);

                let mut body = Vec::new();
                if let Some(header) = self.func.block(li.header) {
                    for inst in &header.insts {
                        if !inst.is_terminator() {
                            body.extend(converter.convert_inst(inst));
                        }
                    }
                }
                body.extend(self.process_loop_body(loop_idx, Some(loop_idx), converter, ctx, depth));
                trim_trailing_continue(&mut body);

                // Get condition from latch block
                let latch = self.func.block(li.latch).unwrap();
                let cond_expr = match latch.terminator() {
                    Some(IrInst::CBranch { cond, target_true, target_false }) => {
                        let e = converter.convert_value_to_expr(cond);
                        if *target_true != li.header && *target_false == li.header {
                            Expr::Unary {
                                op: UnOp::LogNot,
                                operand: Box::new(e),
                            }
                        } else {
                            e
                        }
                    }
                    _ => Expr::BoolLit(true),
                };

                vec![Stmt::DoWhile { body, cond: cond_expr }]
            }

            LoopKind::For => {
                // for (init; cond; update) { body }
                ctx.visited.insert(li.header);

                // Init: from pre-header if available
                let init = if let Some(pre_hdr) = li.pre_header {
                    if ctx.visited.contains(&pre_hdr) {
                        None
                    } else {
                        ctx.visited.insert(pre_hdr);
                        let pre_block = self.func.block(pre_hdr).unwrap();
                        let mut init_stmts = Vec::new();
                        for inst in &pre_block.insts {
                            if !inst.is_terminator() {
                                init_stmts.extend(converter.convert_inst(inst));
                            }
                        }
                        if init_stmts.is_empty() {
                            None
                        } else {
                            Some(Box::new(if init_stmts.len() == 1 {
                                init_stmts.into_iter().next().unwrap()
                            } else {
                                Stmt::Block(init_stmts)
                            }))
                        }
                    }
                } else {
                    None
                };

                // Condition from header
                let header = self.func.block(li.header).unwrap();
                let cond = match header.terminator() {
                    Some(IrInst::CBranch { cond, target_true, target_false }) => {
                        let e = converter.convert_value_to_expr(cond);
                        let inverted =
                            li.body_blocks.contains(target_false) && !li.body_blocks.contains(target_true);
                        Some(if inverted {
                            Expr::Unary {
                                op: UnOp::LogNot,
                                operand: Box::new(e),
                            }
                        } else {
                            e
                        })
                    }
                    _ => None,
                };

                let mut header_stmts = Vec::new();
                for inst in &header.insts {
                    if !inst.is_terminator() {
                        header_stmts.extend(converter.convert_inst(inst));
                    }
                }

                // Update: last non-terminator instruction(s) in latch
                let latch = self.func.block(li.latch).unwrap();
                let update = {
                    let mut update_stmts = Vec::new();
                    for inst in &latch.insts {
                        if !inst.is_terminator() {
                            update_stmts.extend(converter.convert_inst(inst));
                        }
                    }
                    if update_stmts.is_empty() {
                        None
                    } else {
                        Some(Box::new(if update_stmts.len() == 1 {
                            update_stmts.into_iter().next().unwrap()
                        } else {
                            Stmt::Block(update_stmts)
                        }))
                    }
                };

                // Body: everything between header and latch
                let mut body = header_stmts;
                body.extend(self.process_loop_body(loop_idx, Some(loop_idx), converter, ctx, depth));
                trim_trailing_continue(&mut body);

                vec![Stmt::For { init, cond, update, body }]
            }
        }
    }

    /// Process all body blocks of a loop (excluding header for while/for,
    /// excluding latch terminator for do-while).
    fn process_loop_body(
        &self,
        loop_idx: usize,
        enclosing_loop_idx: Option<usize>,
        converter: &mut IrToAstConverter,
        ctx: &mut StructContext,
        depth: usize,
    ) -> Vec<Stmt> {
        let li = &self.loops[loop_idx];
        let mut body = Vec::new();

        // Collect body blocks in topological-ish order
        let ordered: Vec<BlockId> = self.topo_sort_within(&li.body_blocks, li.header);

        for bid in ordered {
            if ctx.visited.contains(&bid) {
                continue;
            }
            // Skip header for while/for (condition is emitted separately)
            if bid == li.header && li.kind != LoopKind::DoWhile {
                continue;
            }
            // For do-while, skip latch terminator (condition emitted separately)
            if bid == li.latch && li.kind == LoopKind::DoWhile {
                // Emit non-terminator instructions of latch
                if let Some(block) = self.func.block(bid) {
                    ctx.visited.insert(bid);
                    for inst in &block.insts {
                        if !inst.is_terminator() {
                            body.extend(converter.convert_inst(inst));
                        }
                    }
                }
                continue;
            }

            let empty: HashSet<BlockId> = HashSet::new();
            let region = self.process_region(bid, enclosing_loop_idx, converter, ctx, depth + 1, &empty);
            body.extend(region);
        }

        trim_trailing_continue(&mut body);
        body
    }

    /// Build the then-arm for a mid-loop early exit: convert the break
    /// path's own block(s) without spilling past the loop boundary, then
    /// terminate with `break`.
    #[allow(clippy::too_many_arguments)]
    fn build_break_arm(
        &self,
        target: BlockId,
        loop_idx: usize,
        exit_block: Option<BlockId>,
        enclosing_loop_idx: Option<usize>,
        converter: &mut IrToAstConverter,
        ctx: &mut StructContext,
        depth: usize,
        boundaries: &HashSet<BlockId>,
    ) -> Vec<Stmt> {
        // The break edge lands directly on the shared post-loop block (or a
        // block that was already emitted): plain `break` and leave the code
        // to the continuation after the loop.
        if exit_block == Some(target) || ctx.visited.contains(&target) {
            return vec![Stmt::Break];
        }

        // Confine the arm to blocks outside the loop body: everything not in
        // the loop becomes a stop point so the arm cannot swallow post-loop
        // or outer-loop code.
        let body = &self.loops[loop_idx].body_blocks;
        let mut arm_bounds = boundaries.clone();
        for &b in &self.all_blocks {
            if !body.contains(&b) && b != target {
                arm_bounds.insert(b);
            }
        }

        let mut arm =
            self.process_region(target, enclosing_loop_idx, converter, ctx, depth + 1, &arm_bounds);
        if ends_with_jump(&arm) {
            return arm;
        }

        // The arm stopped just short of the shared loop-exit block: hoist
        // its non-terminator instructions into the arm (they only execute on
        // this path before breaking out) and defer the terminator to the
        // continuation via `insts_emitted`.
        if let Some(exit_b) = exit_block {
            if !ctx.insts_emitted.contains(&exit_b) {
                let mut scope = body.clone();
                scope.insert(exit_b);
                scope.insert(target);
                if is_reachable_in(self.func, target, exit_b, Some(&scope)) {
                    if let Some(exit_blk) = self.func.block(exit_b) {
                        for inst in &exit_blk.insts {
                            if !inst.is_terminator() {
                                arm.extend(converter.convert_inst(inst));
                            }
                        }
                        ctx.insts_emitted.insert(exit_b);
                    }
                }
            }
        }

        arm.push(Stmt::Break);
        arm
    }

    /// Find the exit block of a loop: the first successor outside the loop
    /// body, checking the header and latch first, then mid-body blocks
    /// (early-exit shapes have no header/latch edge leaving the loop).
    fn loop_exit_block(&self, loop_idx: usize) -> Option<BlockId> {
        let li = &self.loops[loop_idx];
        let mut ordered: Vec<BlockId> = vec![li.header, li.latch];
        let mut rest: Vec<BlockId> = li.body_blocks.iter().copied().collect();
        rest.sort_by_key(|b| b.0);
        ordered.extend(rest);
        for bid in ordered {
            if let Some(block) = self.func.block(bid) {
                for succ in &block.successors {
                    if !li.body_blocks.contains(succ) && *succ != li.header {
                        return Some(*succ);
                    }
                }
            }
        }
        None
    }

    // в”Ђв”Ђ Switch structuring в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    fn structure_switch(
        &self,
        sw_idx: usize,
        enclosing_loop_idx: Option<usize>,
        converter: &mut IrToAstConverter,
        ctx: &mut StructContext,
        depth: usize,
        boundaries: &HashSet<BlockId>,
    ) -> (Vec<Stmt>, Option<BlockId>) {
        let sw = &self.switches[sw_idx];
        ctx.visited.insert(sw.dispatch_block);

        let expr = converter.convert_value_to_expr(&sw.expr);

        // Every case-entry block plus the default target acts as a boundary:
        // a case body must never swallow the next case, the default or the
        // post-switch join (previously the first case consumed everything).
        let mut all_targets: HashSet<BlockId> = sw.cases.values().copied().collect();
        if let Some(d) = sw.default {
            all_targets.insert(d);
        }
        let join = self.find_switch_join(sw, &all_targets);

        let mut arm_boundaries = boundaries.clone();
        for t in &all_targets {
            arm_boundaries.insert(*t);
        }
        if let Some(j) = join {
            arm_boundaries.insert(j);
        }

        let mut cases = Vec::new();
        let mut emitted_targets: HashSet<BlockId> = HashSet::new();
        for (&val, &target) in &sw.cases {
            if !emitted_targets.insert(target) {
                // Shared case target: control falls into the already
                // emitted body of the first case with this target.
                cases.push(SwitchCase {
                    value: Expr::IntLit(val),
                    body: Vec::new(),
                    fallthrough: true,
                });
                continue;
            }
            let case_body =
                self.process_region(target, enclosing_loop_idx, converter, ctx, depth + 1, &arm_boundaries);
            let fallthrough = !ends_with_jump(&case_body);
            cases.push(SwitchCase {
                value: Expr::IntLit(val),
                body: case_body,
                fallthrough,
            });
        }

        let default = sw.default.map(|d| {
            if !emitted_targets.insert(d) {
                Vec::new()
            } else {
                self.process_region(d, enclosing_loop_idx, converter, ctx, depth + 1, &arm_boundaries)
            }
        });

        let cont = join.filter(|j| !ctx.visited.contains(j));
        (vec![Stmt::Switch { expr, cases, default }], cont)
    }

    /// Find the post-switch join block: a block reachable from every case
    /// target (and default) that is not itself a dispatch/case block.
    fn find_switch_join(&self, sw: &SwitchInfo, targets: &HashSet<BlockId>) -> Option<BlockId> {
        if targets.is_empty() {
            return None;
        }
        let mut inter: Option<HashSet<BlockId>> = None;
        for &t in targets {
            let reach = self.reach_closure(t);
            inter = Some(match inter {
                None => reach,
                Some(i) => i.intersection(&reach).copied().collect(),
            });
        }
        let inter = inter?;
        let mut best: Option<BlockId> = None;
        for &c in &inter {
            if c == sw.dispatch_block || targets.contains(&c) {
                continue;
            }
            best = Some(match best {
                None => c,
                Some(b) if c.0 < b.0 => c,
                Some(b) => b,
            });
        }
        best
    }

    /// Successor closure of a block, bounded to keep large functions fast.
    fn reach_closure(&self, from: BlockId) -> HashSet<BlockId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(from);
        visited.insert(from);
        let budget = self.func.blocks.len() * 4 + 64;
        let mut steps = 0usize;
        while let Some(cur) = queue.pop_front() {
            if steps >= budget {
                break;
            }
            steps += 1;
            if let Some(block) = self.func.block(cur) {
                for succ in &block.successors {
                    if visited.insert(*succ) {
                        queue.push_back(*succ);
                    }
                }
            }
        }
        visited
    }

    fn switch_at(&self, block_id: BlockId) -> Option<usize> {
        self.switches.iter().position(|s| s.dispatch_block == block_id)
    }

    fn switch_continuation(&self, sw_idx: usize, ctx: &StructContext) -> Option<BlockId> {
        let sw = &self.switches[sw_idx];
        if let Some(d) = sw.default {
            if !ctx.visited.contains(&d) {
                return Some(d);
            }
        }
        if let Some(db) = self.func.block(sw.dispatch_block) {
            for succ in &db.successors {
                if !sw.cases.values().any(|t| t == succ)
                    && sw.default != Some(*succ)
                    && !ctx.visited.contains(succ)
                {
                    return Some(*succ);
                }
            }
        }
        None
    }

    // в”Ђв”Ђ Try-catch structuring в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    fn structure_try_catch(
        &self,
        tc_idx: usize,
        enclosing_loop_idx: Option<usize>,
        converter: &mut IrToAstConverter,
        ctx: &mut StructContext,
        depth: usize,
    ) -> Vec<Stmt> {
        let tc = &self.try_catches[tc_idx];

        // Process try body
        let mut try_body = Vec::new();
        let mut ordered: Vec<BlockId> = tc.try_blocks.iter().copied().collect();
        ordered.sort_by_key(|b| b.0);
        for bid in ordered {
            if !ctx.visited.contains(&bid) {
                let empty: HashSet<BlockId> = HashSet::new();
            let region = self.process_region(bid, enclosing_loop_idx, converter, ctx, depth + 1, &empty);
                try_body.extend(region);
            }
        }

        // Process catch body
        let empty: HashSet<BlockId> = HashSet::new();
        let catch_body = self.process_region(
            tc.catch_handler,
            enclosing_loop_idx,
            converter,
            ctx,
            depth + 1,
            &empty,
        );

        vec![Stmt::TryCatch {
            try_body,
            catch_var: Some("__exception".into()),
            catch_body,
        }]
    }

    fn try_catch_at(&self, block_id: BlockId) -> Option<usize> {
        self.try_catches
            .iter()
            .position(|tc| tc.try_blocks.contains(&block_id))
    }

    fn try_catch_exit(&self, tc_idx: usize) -> Option<BlockId> {
        let tc = &self.try_catches[tc_idx];
        if let Some(cb) = self.func.block(tc.catch_handler) {
            for succ in &cb.successors {
                if !tc.try_blocks.contains(succ) && *succ != tc.catch_handler {
                    return Some(*succ);
                }
            }
        }
        let mut ordered: Vec<BlockId> = tc.try_blocks.iter().copied().collect();
        ordered.sort_by_key(|b| b.0);
        for tb in ordered {
            if let Some(b) = self.func.block(tb) {
                for succ in &b.successors {
                    if !tc.try_blocks.contains(succ) && *succ != tc.catch_handler {
                        return Some(*succ);
                    }
                }
            }
        }
        None
    }

    // в”Ђв”Ђ Helpers в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    fn is_back_edge(&self, from: BlockId, to: BlockId) -> bool {
        dominates_with_idom(to, from, &self.idom) && from != to
    }

    /// Find the immediate post-dominator (merge point) of two branches.
    /// FIXED: Dynamic BFS bound based on function size instead of hardcoded 256.
    /// `scope` (the enclosing loop body, if any) confines the search: a merge
    /// must not lie outside the loop, otherwise this region would consume the
    /// loop exit and force the continuation into a goto fallback.
    fn find_merge_point(
        &self,
        a: BlockId,
        b: BlockId,
        scope: Option<&HashSet<BlockId>>,
    ) -> Option<BlockId> {
        // Trivial case: both edges land on the same block.
        if a == b {
            return Some(a);
        }

        // Half-diamond: when exactly one arm flows into the other's target,
        // that target IS the merge point (`if (c) { A }` whose body falls
        // through into the false target). The generic BFS below excludes
        // `a` and `b` as candidates; without this shortcut the then-arm
        // would swallow the join block and the else-arm would degrade to
        // a goto fallback with an "unstructured backward jump" warning.
        //
        // Scope guard: reachability from one arm to the other can route
        // THROUGH a loop back edge (arm -> latch -> header -> ... -> exit),
        // which makes an out-of-loop exit block look like a half-diamond
        // join. A merge outside the enclosing loop body is never a real
        // join for this region - it is the loop exit and must be handled
        // as break by the caller instead.
        let a_reaches_b = is_reachable_in(self.func, a, b, scope);
        let b_reaches_a = is_reachable_in(self.func, b, a, scope);
        if a_reaches_b && !b_reaches_a {
            return if in_scope(scope, &b) { Some(b) } else { None };
        }
        if b_reaches_a && !a_reaches_b {
            return if in_scope(scope, &a) { Some(a) } else { None };
        }
        // Both reachable (cycle / loop-shaped join) or neither: fall back
        // to the generic search below.

        // BFS from both targets; first common block is the merge point
        let mut visited_a = HashSet::new();
        let mut queue_a = VecDeque::new();
        queue_a.push_back(a);
        visited_a.insert(a);

        let mut visited_b = HashSet::new();
        let mut queue_b = VecDeque::new();
        queue_b.push_back(b);
        visited_b.insert(b);

        // FIXED: Scale BFS limit to function size. Large functions (>256 blocks)
        // need more steps to find merge points. Cap at 4x block count + 64.
        let max_steps = self.func.blocks.len() * 4 + 64;
        for _ in 0..max_steps {
            // Expand A one step
            if let Some(cur) = queue_a.pop_front() {
                if visited_b.contains(&cur) && cur != a && cur != b && in_scope(scope, &cur) {
                    return Some(cur);
                }
                if in_scope(scope, &cur) {
                    if let Some(block) = self.func.block(cur) {
                        for succ in &block.successors {
                            if visited_a.insert(*succ) {
                                queue_a.push_back(*succ);
                            }
                        }
                    }
                }
            }
            // Expand B one step
            if let Some(cur) = queue_b.pop_front() {
                if visited_a.contains(&cur) && cur != a && cur != b {
                    return Some(cur);
                }
                if in_scope(scope, &cur) {
                    if let Some(block) = self.func.block(cur) {
                        for succ in &block.successors {
                            if visited_b.insert(*succ) {
                                queue_b.push_back(*succ);
                            }
                        }
                    }
                }
            }
            if queue_a.is_empty() && queue_b.is_empty() {
                break;
            }
        }
        None
    }

    /// Topological sort of blocks within a set, starting from `start`.
    fn topo_sort_within(&self, blocks: &HashSet<BlockId>, start: BlockId) -> Vec<BlockId> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);

        while let Some(bid) = queue.pop_front() {
            if !blocks.contains(&bid) || !visited.insert(bid) {
                continue;
            }
            result.push(bid);
            if let Some(block) = self.func.block(bid) {
                for succ in &block.successors {
                    if blocks.contains(succ) {
                        queue.push_back(*succ);
                    }
                }
            }
        }

        // Add any remaining blocks not reachable from start
        let mut rest: Vec<BlockId> = blocks.iter().copied().collect();
        rest.sort_by_key(|b| b.0);
        for &bid in &rest {
            if visited.insert(bid) {
                result.push(bid);
            }
        }

        result
    }
}

// в”Ђв”Ђв”Ђ Context for tracking visited blocks during structuring в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[derive(Default)]
struct StructContext {
    visited: HashSet<BlockId>,
    /// Blocks whose non-terminator instructions were already emitted while
    /// structuring a break arm; the continuation must emit only the
    /// terminator (e.g. the shared loop-exit block's `return`).
    insts_emitted: HashSet<BlockId>,
}

/// Whether `block` may be expanded during a scoped search (`None` = unscoped).
fn in_scope(scope: Option<&HashSet<BlockId>>, block: &BlockId) -> bool {
    scope.is_none_or(|s| s.contains(block))
}

/// Whether the last statement transfers control (return/break/continue/goto),
/// meaning no implicit fallthrough follows.
fn ends_with_jump(stmts: &[Stmt]) -> bool {
    matches!(
        stmts.last(),
        Some(Stmt::Return { .. } | Stmt::Break | Stmt::Continue | Stmt::Goto { .. })
    )
}

/// A bare `continue` as the very last statement of a loop body is a no-op
/// (control reaches the loop's repeat point anyway); drop it.
fn trim_trailing_continue(stmts: &mut Vec<Stmt>) {
    while matches!(stmts.last(), Some(Stmt::Continue)) {
        stmts.pop();
    }
}

/// Check if block `to` is reachable from block `from` via any successor path,
/// optionally confined to a scope (e.g. the enclosing loop body).
fn is_reachable_in(
    func: &IrFunction,
    from: BlockId,
    to: BlockId,
    scope: Option<&HashSet<BlockId>>,
) -> bool {
    if from == to {
        return true;
    }
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(from);
    visited.insert(from);

    while let Some(current) = queue.pop_front() {
        if in_scope(scope, &current) {
            if let Some(block) = func.block(current) {
                for succ in &block.successors {
                    if *succ == to {
                        return true;
                    }
                    if visited.insert(*succ) {
                        queue.push_back(*succ);
                    }
                }
            }
        }
    }
    false
}

/// Check if block `a` dominates block `b`.
///
/// Uses the immediate dominator map for O(depth) lookup when available,
/// falls back to BFS from entry otherwise.
pub(crate) fn dominates(func: &IrFunction, a: BlockId, b: BlockId) -> bool {
    dominates_with_idom(a, b, &freakre_ir::ssa::compute_dominators(func))
}

/// Check if block `a` dominates block `b` using a precomputed idom map.
pub(crate) fn dominates_with_idom(
    a: BlockId,
    b: BlockId,
    idom: &HashMap<BlockId, BlockId>,
) -> bool {
    if a == b {
        return true;
    }
    // Walk b's dominator chain up to the entry
    let mut cur = b;
    while cur != a {
        match idom.get(&cur) {
            Some(&parent) if parent != cur => cur = parent,
            _ => return false,
        }
    }
    true
}

// в”Ђв”Ђв”Ђ Loop detection and classification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn detect_and_classify_loops(func: &IrFunction, idom: &HashMap<BlockId, BlockId>) -> Vec<LoopInfo> {
    let mut loops: Vec<LoopInfo> = Vec::new();

    // Find all back edges
    for block in &func.blocks {
        for succ in &block.successors {
            if dominates_with_idom(*succ, block.id, idom) {
                // Back edge: block в†’ succ (succ is loop header)
                let header = *succ;
                let latch = block.id;

                // Compute loop body via reverse DFS from latch avoiding header
                let body_blocks = compute_natural_loop(func, header, latch);

                // Classify loop
                let kind = classify_loop(func, header, latch, &body_blocks);

                // Detect pre-header for `for` loops
                let pre_header = if kind == LoopKind::For {
                    find_pre_header(func, header, &body_blocks)
                } else {
                    None
                };

                if let Some(existing) = loops.iter_mut().find(|l| l.header == header) {
                    existing.body_blocks.extend(body_blocks);
                    continue;
                }

                loops.push(LoopInfo {
                    header,
                    back_edge_from: latch,
                    kind,
                    body_blocks,
                    latch,
                    pre_header,
                });
            }
        }
    }

    loops
}

/// Compute the natural loop body: all blocks that can reach `latch` without going through `header`.
fn compute_natural_loop(func: &IrFunction, header: BlockId, latch: BlockId) -> HashSet<BlockId> {
    let mut body = HashSet::new();
    body.insert(header);
    body.insert(latch);

    if header == latch {
        return body;
    }

    // Reverse DFS from latch, not expanding through the header
    let mut stack = vec![latch];
    while let Some(bid) = stack.pop() {
        if bid == header {
            continue;
        }
        if let Some(block) = func.block(bid) {
            for pred in &block.predecessors {
                if body.insert(*pred) {
                    stack.push(*pred);
                }
            }
        }
    }

    body
}

/// Classify a loop as while, do-while, or for.
fn classify_loop(func: &IrFunction, header: BlockId, latch: BlockId, _body: &HashSet<BlockId>) -> LoopKind {
    let header_block = match func.block(header) {
        Some(b) => b,
        None => return LoopKind::While,
    };

    let latch_block = match func.block(latch) {
        Some(b) => b,
        None => return LoopKind::While,
    };

    // Do-while: header has no conditional branch (unconditional entry),
    // and latch has the conditional branch back to header.
    let header_is_unconditional = matches!(header_block.terminator(), Some(IrInst::Branch { .. }));
    let latch_has_cond = matches!(latch_block.terminator(), Some(IrInst::CBranch { .. }));

    if header_is_unconditional && latch_has_cond {
        return LoopKind::DoWhile;
    }

    // For-loop heuristic: header has a conditional branch AND there exists
    // a pre-header with an assignment, AND the latch contains an increment-like pattern.
    if latch_has_cond && find_pre_header(func, header, _body).is_some()
        && latch_has_increment_pattern(latch_block) {
            return LoopKind::For;
        }

    // Default: while loop (condition at header)
    LoopKind::While
}

/// Find a pre-header block: a predecessor of the header outside the loop with init-like code.
fn find_pre_header(func: &IrFunction, header: BlockId, body: &HashSet<BlockId>) -> Option<BlockId> {
    let header_block = func.block(header)?;
    let preds = &header_block.predecessors;

    for &pred in preds {
        if pred == header || body.contains(&pred) {
            continue;
        }
        if let Some(pb) = func.block(pred) {
            // Check if this block has an assignment-like instruction
            let has_init = pb.insts.iter().any(|inst| {
                matches!(inst, IrInst::Binary { op: OpCode::Copy | OpCode::Add | OpCode::Sub, .. }
                    | IrInst::Unary { op: OpCode::Copy, .. })
            });
            if has_init {
                return Some(pred);
            }
        }
    }
    None
}

/// Check if a latch block contains an increment/decrement pattern typical of for-loops.
fn latch_has_increment_pattern(block: &freakre_ir::IrBlock) -> bool {
    for inst in &block.insts {
        if let IrInst::Binary { op: OpCode::Add | OpCode::Sub, .. } = inst {
            return true;
        }
    }
    false
}

// в”Ђв”Ђв”Ђ Switch detection в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn detect_switches(func: &IrFunction) -> Vec<SwitchInfo> {
    let mut switches = Vec::new();
    // Build the comparison index once: cond var id -> (compared var, const, eq-on-true)
    let cmp_index = build_cmp_index(func);

    for block in &func.blocks {
        // Pattern 1: IndirectBranch preceded by bounds check в†’ jump table
        if let Some(IrInst::IndirectBranch { target }) = block.terminator() {
            // Look for comparison chain or table load in preceding instructions
            if let Some(sw) = detect_jump_table_switch(func, block, target, &cmp_index) {
                switches.push(sw);
                continue;
            }
        }

        // Pattern 2: Comparison chain (series of CBranch with same variable compared to constants)
        if let Some(sw) = detect_comparison_chain_switch(func, block, &cmp_index) {
            switches.push(sw);
        }
    }

    switches
}

/// Precomputed map from condition variable to its defining equality comparison.
/// Avoids re-scanning the whole function per chain step (was O(n^2)).
struct CmpIndex(HashMap<u32, (u32, i64, bool)>);

fn build_cmp_index(func: &IrFunction) -> CmpIndex {
    let mut map: HashMap<u32, (u32, i64, bool)> = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            // Handle Eq/Ne as well as range checks LtU/LeU/GtU/GeU for switch bounds
            let (op, is_eq) = match inst {
                IrInst::Binary { dst: _, op: OpCode::Eq, .. } => (OpCode::Eq, true),
                IrInst::Binary { dst: _, op: OpCode::Ne, .. } => (OpCode::Ne, false),
                IrInst::Binary { dst: _, op: OpCode::LtU, .. } => (OpCode::LtU, false),
                IrInst::Binary { dst: _, op: OpCode::LeU, .. } => (OpCode::LeU, false),
                IrInst::Binary { dst: _, op: OpCode::GtU, .. } => (OpCode::GtU, false),
                IrInst::Binary { dst: _, op: OpCode::GeU, .. } => (OpCode::GeU, false),
                _ => continue,
            };
            if let IrInst::Binary { dst, lhs, rhs, .. } = inst {
                let cond_id = match dst.var_id() {
                    Some(id) => id,
                    None => continue,
                };
                let eq_on_true = is_eq;
                // For range ops, treat as not eq, but still record
                let info = if let (Some(vid), Some(cval)) = (lhs.var_id(), rhs.as_const()) {
                    Some((vid, cval, eq_on_true))
                } else if let (Some(cval), Some(vid)) = (lhs.as_const(), rhs.var_id()) {
                    Some((vid, cval, eq_on_true))
                } else {
                    None
                };
                if let Some(info) = info {
                    map.entry(cond_id).or_insert(info);
                }
                let _ = op;
            }
        }
    }
    CmpIndex(map)
}

impl CmpIndex {
    fn lookup(&self, cond: &Value) -> Option<(u32, i64, bool)> {
        self.0.get(&cond.var_id()?).copied()
    }
}

/// Detect a jump-table based switch: load from base + index*stride, bounded by cmp.
fn detect_jump_table_switch(func: &IrFunction, block: &freakre_ir::IrBlock, _target: &Value, cmp_index: &CmpIndex) -> Option<SwitchInfo> {
    // Look for a Load instruction whose address involves an index variable
    let mut switch_var = None;
    let mut cases = BTreeMap::new();

    for inst in &block.insts {
        if let IrInst::Load { addr, .. } = inst {
            // Check if addr = base + index * stride
            if let Value::Var { id, .. } = addr {
                switch_var = Some(Value::var(*id, addr.ty()));
            }
        }
    }

    let switch_var = switch_var?;

    // Try to resolve jump table entries from predecessors' constant comparisons
    for pred_id in &block.predecessors {
        if let Some(pred) = func.block(*pred_id) {
            if let Some(IrInst::CBranch { cond, target_true, target_false }) = pred.terminator() {
                // Check if cond compares a variable to a constant
                if let Some((var_id, const_val, eq_on_true)) = cmp_index.lookup(cond) {
                    if let Value::Var { id, .. } = &switch_var {
                        if var_id == *id {
                            // The equality-matching branch goes to a case target
                            let case_target = if eq_on_true { *target_true } else { *target_false };
                            cases.insert(const_val, case_target);
                            // The false branch might be default or next comparison
                            if !cases.values().any(|v| *v == *target_false) {
                                // Could be default
                            }
                        }
                    }
                }
            }
        }
    }

    if cases.is_empty() {
        return None;
    }

    Some(SwitchInfo {
        dispatch_block: block.id,
        expr: switch_var,
        cases,
        default: None,
    })
}

/// Detect a comparison-chain switch: multiple CBranch on same variable vs constants.
fn detect_comparison_chain_switch(func: &IrFunction, block: &freakre_ir::IrBlock, cmp_index: &CmpIndex) -> Option<SwitchInfo> {
    let terminator = block.terminator()?;
    let (cond, target_true, target_false) = match terminator {
        IrInst::CBranch { cond, target_true, target_false } => (cond, target_true, target_false),
        _ => return None,
    };

    // Extract variable and constant from this comparison
    let (var_id, const_val, eq_on_true) = cmp_index.lookup(cond)?;
    let switch_var = Value::var(var_id, cond.ty());

    let mut cases = BTreeMap::new();
    let case_target = if eq_on_true { *target_true } else { *target_false };
    cases.insert(const_val, case_target);

    // Follow the not-equal branch to see if it leads to another comparison on the same variable
    let mut current = if eq_on_true { *target_false } else { *target_true };
    let mut max_chain = 32; // prevent infinite loops

    while max_chain > 0 {
        max_chain -= 1;
        let next_block = func.block(current)?;

        // Must have exactly one predecessor (the previous chain block)
        if next_block.predecessors.len() != 1 {
            // This is likely the default case
            break;
        }

        match next_block.terminator() {
            Some(IrInst::CBranch { cond: c, target_true: t_true, target_false: t_false }) => {
                if let Some((vid, cv, eq_taken)) = cmp_index.lookup(c) {
                    if vid == var_id {
                        cases.insert(cv, if eq_taken { *t_true } else { *t_false });
                        current = if eq_taken { *t_false } else { *t_true };
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            _ => {
                // End of chain вЂ” this block is the default
                break;
            }
        }
    }

    // Need at least 3 cases to qualify as a switch (otherwise it's just if/else)
    if cases.len() < 3 {
        return None;
    }

    let default = if max_chain > 0 {
        Some(current)
    } else {
        None
    };

    Some(SwitchInfo {
        dispatch_block: block.id,
        expr: switch_var,
        cases,
        default,
    })
}

/// Extract (variable_id, constant_value) from an equality comparison expression.
fn extract_cmp_const(cmp_index: &CmpIndex, cond: &Value) -> Option<(u32, i64)> {
    cmp_index.lookup(cond).map(|(v, c, _)| (v, c))
}

// в”Ђв”Ђв”Ђ Try-catch detection в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn detect_try_catch_regions(func: &IrFunction) -> Vec<TryCatchRegion> {
    let mut regions = Vec::new();

    // Heuristic: look for blocks that call exception-handling runtime functions
    // (e.g., __CxxFrameHandler3, _except_handler3, __gcc_personality_v0)
    // and blocks whose successors include an exception handler landing pad.
    //
    // In IR, exception handlers are typically represented as:
    // 1. A Call to a function that may throw
    // 2. An IndirectBranch or special marker to a handler block
    //
    // We detect this by finding blocks with calls followed by a branch to
    // a block that has no normal predecessors (only reachable via exception).

    let exception_handlers: HashSet<&str> = [
        "__CxxFrameHandler3",
        "_except_handler3",
        "_except_handler4",
        "__gcc_personality_v0",
        "__gxx_personality_v0",
        "_C_specific_handler",
        "__clang_call_terminate",
    ]
    .iter()
    .copied()
    .collect();

    // Find potential handler blocks: blocks referenced by IndirectBranch
    // or blocks that are successors of blocks containing exception-related calls
    for block in &func.blocks {
        let mut has_throwing_call = false;
        let mut handler_target = None;

        for inst in &block.insts {
            if let IrInst::Call { target: Value::Symbol(sym), .. } = inst {
                if exception_handlers.contains(sym.as_str()) {
                    has_throwing_call = true;
                }
            }
        }

        if has_throwing_call {
            // Look for an IndirectBranch or special successor as handler
            if let Some(IrInst::IndirectBranch { target }) = block.terminator() {
                if let Some(tid) = target.var_id().or_else(|| {
                    // If target is a constant address, find the block at that address
                    target.as_const().and_then(|addr| {
                        func.blocks.iter()
                            .find(|b| b.source_range.is_some_and(|(s, _)| s == addr as u64))
                            .map(|b| b.id.0)
                    })
                }) {
                    handler_target = Some(BlockId(tid));
                }
            }

            if let Some(handler) = handler_target {
                // All blocks between the throwing call and the handler form the try region
                let mut try_blocks = HashSet::new();
                try_blocks.insert(block.id);

                // Also include successors up to the handler
                if let Some(b) = func.block(block.id) {
                    for succ in &b.successors {
                        if *succ != handler {
                            try_blocks.insert(*succ);
                        }
                    }
                }

                regions.push(TryCatchRegion {
                    try_blocks,
                    catch_handler: handler,
                });
            }
        }
    }

    regions
}

// в”Ђв”Ђв”Ђ Legacy public API (kept for compatibility) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

/// Detect loops in the CFG (public API for external consumers).
pub fn detect_loops(func: &IrFunction) -> Vec<super::LoopInfo> {
    let idom = freakre_ir::ssa::compute_dominators(func);
    let loops = detect_and_classify_loops(func, &idom);
    loops
        .into_iter()
        .map(|l| super::LoopInfo {
            header: l.header,
            back_edge_from: l.back_edge_from,
        })
        .collect()
}

/// Detect if-else patterns (public API).
pub fn detect_if_else(func: &IrFunction, block_id: BlockId) -> Option<super::IfElsePattern> {
    let block = func.block(block_id)?;
    let terminator = block.terminator()?;
    if let IrInst::CBranch { cond: _, target_true, target_false } = terminator {
        Some(super::IfElsePattern {
            cond_block: block_id,
            then_block: *target_true,
            else_block: *target_false,
        })
    } else {
        None
    }
}

// в”Ђв”Ђв”Ђ Tests в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{OpCode, Ty, Value};

    #[test]
    fn test_simple_structuring() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());

        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v0.clone()),
        });

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Stmt::Return { .. }));
    }

    #[test]
    fn test_if_else_detection() {
        let mut func = IrFunction::new("test", 0x1000);
        let cond = Value::var(0, Ty::Bool);
        let then_block = func.add_block("then");
        let else_block = func.add_block("else");

        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: cond.clone(),
            target_true: then_block,
            target_false: else_block,
        });

        let pattern = detect_if_else(&func, func.entry_block);
        assert!(pattern.is_some());

        let pattern = pattern.unwrap();
        assert_eq!(pattern.cond_block, func.entry_block);
        assert_eq!(pattern.then_block, then_block);
        assert_eq!(pattern.else_block, else_block);
    }

    #[test]
    fn test_while_loop_detection() {
        let mut func = IrFunction::new("while_test", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let body_block = func.add_block("body");
        let exit_block = func.add_block("exit");

        // Entry: cbranch cond в†’ body | exit
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: cond.clone(),
            target_true: body_block,
            target_false: exit_block,
        });

        // Body: branch в†’ entry (back edge)
        func.push_inst(body_block, IrInst::Branch { target: func.entry_block });

        // Exit: return
        func.push_inst(exit_block, IrInst::Return { value: None });

        func.build_cfg();

        let idom = freakre_ir::ssa::compute_dominators(&func);
        let loops = detect_and_classify_loops(&func, &idom);

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].kind, LoopKind::While);
        assert_eq!(loops[0].header, func.entry_block);
    }

    #[test]
    fn test_do_while_loop_detection() {
        let mut func = IrFunction::new("do_while_test", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let latch = func.add_block("latch");

        // Entry: unconditional branch в†’ latch (body)
        func.push_inst(func.entry_block, IrInst::Branch { target: latch });

        // Latch: cbranch cond в†’ entry | exit
        let exit_block = func.add_block("exit");
        func.push_inst(latch, IrInst::CBranch {
            cond: cond.clone(),
            target_true: func.entry_block,
            target_false: exit_block,
        });

        func.push_inst(exit_block, IrInst::Return { value: None });

        func.build_cfg();

        let idom = freakre_ir::ssa::compute_dominators(&func);
        let loops = detect_and_classify_loops(&func, &idom);

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].kind, LoopKind::DoWhile);
    }

    #[test]
    fn test_comparison_chain_switch() {
        let mut func = IrFunction::new("switch_test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());

        // Create comparison: v1 = v0 == 1
        let v1 = func.alloc_var(Ty::Bool);
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v1.clone(),
            op: OpCode::Eq,
            lhs: v0.clone(),
            rhs: Value::Const(1),
        });

        let case1 = func.add_block("case1");
        let chain2 = func.add_block("chain2");
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: v1,
            target_true: case1,
            target_false: chain2,
        });

        // Chain2: v2 = v0 == 2
        let v2 = func.alloc_var(Ty::Bool);
        func.push_inst(chain2, IrInst::Binary {
            dst: v2.clone(),
            op: OpCode::Eq,
            lhs: v0.clone(),
            rhs: Value::Const(2),
        });

        let case2 = func.add_block("case2");
        let chain3 = func.add_block("chain3");
        func.push_inst(chain2, IrInst::CBranch {
            cond: v2,
            target_true: case2,
            target_false: chain3,
        });

        // Chain3: v3 = v0 == 3
        let v3 = func.alloc_var(Ty::Bool);
        func.push_inst(chain3, IrInst::Binary {
            dst: v3.clone(),
            op: OpCode::Eq,
            lhs: v0.clone(),
            rhs: Value::Const(3),
        });

        let case3 = func.add_block("case3");
        let default = func.add_block("default");
        func.push_inst(chain3, IrInst::CBranch {
            cond: v3,
            target_true: case3,
            target_false: default,
        });

        func.build_cfg();

        let switches = detect_switches(&func);
        assert!(!switches.is_empty(), "Should detect comparison chain switch");
        assert_eq!(switches[0].cases.len(), 3);
    }

    fn contains_return(stmts: &[Stmt]) -> bool {
        stmts.iter().any(|s| match s {
            Stmt::Return { .. } => true,
            Stmt::If { then_body, else_body, .. } => {
                contains_return(then_body)
                    || else_body.as_ref().map(|e| contains_return(e)).unwrap_or(false)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                contains_return(body)
            }
            Stmt::Block(b) => contains_return(b),
            Stmt::Switch { cases, default, .. } => {
                cases.iter().any(|c| contains_return(&c.body))
                    || default.as_ref().map(|d| contains_return(d)).unwrap_or(false)
            }
            Stmt::TryCatch { try_body, catch_body, .. } => {
                contains_return(try_body) || contains_return(catch_body)
            }
            _ => false,
        })
    }

    fn build_chain_switch_func(name: &str, op: OpCode) -> IrFunction {
        let mut func = IrFunction::new(name, 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let mut prev_false = func.entry_block;
        for (i, val) in [1i64, 2, 3].iter().enumerate() {
            let vi = func.alloc_var(Ty::Bool);
            func.push_inst(prev_false, IrInst::Binary {
                dst: vi.clone(),
                op,
                lhs: v0.clone(),
                rhs: Value::Const(*val),
            });
            let case_i = func.add_block(&format!("case{}", i));
            let next = if i == 2 {
                func.add_block("default")
            } else {
                func.add_block(&format!("chain{}", i + 1))
            };
            func.push_inst(prev_false, IrInst::CBranch {
                cond: vi,
                target_true: case_i,
                target_false: next,
            });
            prev_false = next;
            if i == 2 {
                return func;
            }
        }
        unreachable!()
    }

    #[test]
    fn test_switch_tail_not_dropped() {
        let mut func = build_chain_switch_func("switch_tail", OpCode::Eq);
        let join = func.add_block("join");
        let blocks: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        for bid in blocks {
            let is_case = matches!(func.block(bid).and_then(|b| b.terminator()), Some(IrInst::Branch { target }) if *target == join);
            let has_cbranch = matches!(func.block(bid).and_then(|b| b.terminator()), Some(IrInst::CBranch { .. }));
            if !has_cbranch && !is_case && bid != join {
                func.push_inst(bid, IrInst::Branch { target: join });
            }
        }
        func.push_inst(join, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);
        assert!(contains_return(&stmts), "code after switch must not be dropped");
    }

    #[test]
    fn test_lt_chain_is_not_switch() {
        let func = build_chain_switch_func("lt_chain", OpCode::LtS);
        let switches = detect_switches(&func);
        assert!(switches.is_empty(), "range checks must not become switch cases");
    }

    #[test]
    fn test_while_condition_inverted_when_body_on_false_edge() {
        let mut func = IrFunction::new("polarity", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let body_block = func.add_block("body");
        let exit_block = func.add_block("exit");

        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: cond.clone(),
            target_true: exit_block,
            target_false: body_block,
        });
        func.push_inst(body_block, IrInst::Branch { target: func.entry_block });
        func.push_inst(exit_block, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);
        match &stmts[0] {
            Stmt::While { cond, .. } => {
                assert!(
                    matches!(cond, Expr::Unary { op: UnOp::LogNot, .. }),
                    "condition must be inverted when body is behind the false edge"
                );
            }
            other => panic!("expected while loop, got {:?}", other),
        }
    }

    #[test]
    fn test_pre_header_excludes_loop_blocks() {
        let mut func = IrFunction::new("preheader", 0x1000);
        let pre = func.entry_block;
        let header = func.add_block("header");
        let latch = func.add_block("latch");
        let exit_block = func.add_block("exit");

        let init_dst = func.alloc_var(Ty::i32());
        func.push_inst(pre, IrInst::Unary {
            dst: init_dst,
            op: OpCode::Copy,
            src: Value::Const(0),
        });
        func.push_inst(pre, IrInst::Branch { target: header });
        func.push_inst(header, IrInst::Branch { target: latch });
        let v = func.alloc_var(Ty::Bool);
        func.push_inst(latch, IrInst::CBranch {
            cond: v,
            target_true: header,
            target_false: exit_block,
        });
        func.push_inst(exit_block, IrInst::Return { value: None });
        func.build_cfg();

        let body = compute_natural_loop(&func, header, latch);
        assert!(body.contains(&header) && body.contains(&latch));
        assert!(!body.contains(&pre), "pre-header must not leak into the loop body");
        let ph = find_pre_header(&func, header, &body);
        assert_eq!(ph, Some(pre));
    }

    #[test]
    fn test_multiple_back_edges_merge_into_one_loop() {
        let mut func = IrFunction::new("multiback", 0x1000);
        let header = func.entry_block;
        let b1 = func.add_block("b1");
        let b2 = func.add_block("b2");
        let exit_block = func.add_block("exit");

        let c = func.alloc_var(Ty::Bool);
        func.push_inst(header, IrInst::CBranch {
            cond: c,
            target_true: b1,
            target_false: b2,
        });
        func.push_inst(b1, IrInst::Branch { target: header });
        func.push_inst(b2, IrInst::Branch { target: header });
        func.push_inst(exit_block, IrInst::Return { value: None });
        let _ = exit_block;
        func.build_cfg();

        let idom = freakre_ir::ssa::compute_dominators(&func);
        let loops = detect_and_classify_loops(&func, &idom);
        assert_eq!(loops.len(), 1, "two latches to one header merge into one loop");
        assert!(loops[0].body_blocks.contains(&b1));
        assert!(loops[0].body_blocks.contains(&b2));
    }

    // в”Ђв”Ђв”Ђ Helpers for checking structured output в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /// Collect goto labels and warning comments that indicate structuring
    /// fell back to unstructured output.
    fn collect_fallbacks(stmts: &[Stmt], out: &mut Vec<String>) {
        for s in stmts {
            match s {
                Stmt::Goto { label } => out.push(format!("goto {}", label)),
                Stmt::Comment(c) if c.contains("WARNING") => out.push(c.clone()),
                Stmt::If { then_body, else_body, .. } => {
                    collect_fallbacks(then_body, out);
                    if let Some(e) = else_body {
                        collect_fallbacks(e, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                    collect_fallbacks(body, out)
                }
                Stmt::Block(b) => collect_fallbacks(b, out),
                Stmt::Switch { cases, default, .. } => {
                    for c in cases {
                        collect_fallbacks(&c.body, out);
                    }
                    if let Some(d) = default {
                        collect_fallbacks(d, out);
                    }
                }
                Stmt::TryCatch { try_body, catch_body, .. } => {
                    collect_fallbacks(try_body, out);
                    collect_fallbacks(catch_body, out);
                }
                _ => {}
            }
        }
    }

    fn has_while(stmts: &[Stmt]) -> bool {
        stmts.iter().any(|s| match s {
            Stmt::While { .. } => true,
            Stmt::If { then_body, else_body, .. } => {
                has_while(then_body)
                    || else_body.as_ref().map(|e| has_while(e)).unwrap_or(false)
            }
            Stmt::Block(b) => has_while(b),
            _ => false,
        })
    }

    // в”Ђв”Ђв”Ђ Reproducers: shapes that must not fall back to goto в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    /// Half-diamond: `if (c) { body }` where the body flows into the false
    /// target itself (the join IS one of the branch targets). This is the
    /// shape seen in real output as `else { goto bbN; }` plus
    /// "WARNING: unstructured backward jump".
    #[test]
    fn test_half_diamond_join_on_branch_target() {
        let mut func = IrFunction::new("half_diamond", 0x1000);
        let body = func.add_block("body");
        let join = func.add_block("join");
        let next = func.add_block("next");

        // entry: cbranch c ? body : join
        let c = func.alloc_var(Ty::Bool);
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: c,
            target_true: body,
            target_false: join,
        });
        let tmp = func.alloc_var(Ty::i32());
        func.push_inst(body, IrInst::Unary {
            dst: tmp,
            op: OpCode::Copy,
            src: Value::Const(1),
        });
        // body falls through into the join (false target)
        func.push_inst(body, IrInst::Branch { target: join });
        func.push_inst(join, IrInst::Branch { target: next });
        func.push_inst(next, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        let mut fallbacks = Vec::new();
        collect_fallbacks(&stmts, &mut fallbacks);
        assert!(
            fallbacks.is_empty(),
            "half-diamond must structure without goto/warning, got {:?} in {:?}",
            fallbacks,
            stmts
        );
    }

    /// While loop whose body contains a conditional branch back to the
    /// header (continue-style edge taken from the middle of the body):
    /// while (c) { if (z) goto header; more(); goto header; }
    #[test]
    fn test_conditional_back_edge_inside_while_body() {
        let mut func = IrFunction::new("cond_back_edge", 0x1000);
        let header = func.entry_block;
        let body = func.add_block("body");
        let mid = func.add_block("mid");
        let exit_block = func.add_block("exit");

        let c = func.alloc_var(Ty::Bool);
        func.push_inst(header, IrInst::CBranch {
            cond: c,
            target_true: body,
            target_false: exit_block,
        });

        // Body: conditional back edge to the header (true side)
        let z = func.alloc_var(Ty::Bool);
        func.push_inst(body, IrInst::CBranch {
            cond: z,
            target_true: header,
            target_false: mid,
        });

        // Mid: latch with unconditional back edge
        func.push_inst(mid, IrInst::Branch { target: header });
        func.push_inst(exit_block, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        assert!(has_while(&stmts), "expected a While loop, got {:?}", stmts);
        let mut fallbacks = Vec::new();
        collect_fallbacks(&stmts, &mut fallbacks);
        assert!(
            fallbacks.is_empty(),
            "continue-style edge inside a while must not produce goto/warning, got {:?} in {:?}",
            fallbacks,
            stmts
        );
    }

    /// A backward jump with no detectable natural loop (irreducible):
    /// the goto fallback must stay. Two mutually-reachable blocks with no
    /// dominating header form a cycle that cannot be expressed as a loop.
    #[test]
    fn test_irreducible_backward_jump_keeps_goto() {
        let mut func = IrFunction::new("irreducible", 0x1000);
        let a = func.add_block("a");
        let b = func.add_block("b");

        // entry branches to both sides; neither a nor b dominates the
        // other, so no natural loop exists even though control flow cycles.
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: Value::Const(1),
            target_true: a,
            target_false: b,
        });
        let v = func.alloc_var(Ty::Bool);
        let ret_block = func.add_block("ret");
        func.push_inst(a, IrInst::CBranch {
            cond: v,
            target_true: b,
            target_false: ret_block,
        });
        func.push_inst(b, IrInst::Branch { target: a });
        func.push_inst(ret_block, IrInst::Return { value: None });
        func.build_cfg();

        let idom = freakre_ir::ssa::compute_dominators(&func);
        assert!(
            detect_and_classify_loops(&func, &idom).is_empty(),
            "mutually reachable blocks without a dominating header must not be classified as a natural loop"
        );

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);
        let mut fallbacks = Vec::new();
        collect_fallbacks(&stmts, &mut fallbacks);
        assert!(
            fallbacks.iter().any(|f| f.starts_with("goto")),
            "irreducible cycle must keep the goto fallback, got {:?}",
            stmts
        );
    }

    // в”ЂвЂЂвЂЂ Degenerate while(true)+continue reproducers вЂЂвЂЂвЂЂвЂЂвЂЂвЂЂвЂЂвЂЂвЂЂвЂЂвЂЂвЂЂ

    /// Count occurrences of IntLit(val) anywhere in the statement trees
    /// (including conditions). Used to verify code is emitted exactly once.
    fn expr_int_lit_count(e: &Expr, val: i64) -> usize {
        let own = matches!(e, Expr::IntLit(v) if *v == val) as usize;
        own + match e {
            Expr::Binary { lhs, rhs, .. } => {
                expr_int_lit_count(lhs, val) + expr_int_lit_count(rhs, val)
            }
            Expr::Unary { operand, .. } => expr_int_lit_count(operand, val),
            Expr::Call { args, .. } => args.iter().map(|a| expr_int_lit_count(a, val)).sum(),
            Expr::Index { base, index } => {
                expr_int_lit_count(base, val) + expr_int_lit_count(index, val)
            }
            Expr::Deref(x) | Expr::AddrOf(x) => expr_int_lit_count(x, val),
            Expr::Cast { expr, .. } => expr_int_lit_count(expr, val),
            Expr::Ternary { cond, then_expr, else_expr } => {
                expr_int_lit_count(cond, val)
                    + expr_int_lit_count(then_expr, val)
                    + expr_int_lit_count(else_expr, val)
            }
            _ => 0,
        }
    }

    fn stmt_int_lit_count(stmts: &[Stmt], val: i64) -> usize {
        let mut n = 0;
        for s in stmts {
            n += match s {
                Stmt::Assign { target, value } => {
                    expr_int_lit_count(target, val) + expr_int_lit_count(value, val)
                }
                Stmt::If { cond, then_body, else_body } => {
                    expr_int_lit_count(cond, val)
                        + stmt_int_lit_count(then_body, val)
                        + else_body.as_ref().map(|e| stmt_int_lit_count(e, val)).unwrap_or(0)
                }
                Stmt::While { cond, body } => {
                    expr_int_lit_count(cond, val) + stmt_int_lit_count(body, val)
                }
                Stmt::For { init, cond, update, body } => {
                    init.as_ref().map(|s| stmt_int_lit_count(std::slice::from_ref(s), val)).unwrap_or(0)
                        + cond.as_ref().map(|e| expr_int_lit_count(e, val)).unwrap_or(0)
                        + update.as_ref().map(|s| stmt_int_lit_count(std::slice::from_ref(s), val)).unwrap_or(0)
                        + stmt_int_lit_count(body, val)
                }
                Stmt::DoWhile { body, cond } => {
                    stmt_int_lit_count(body, val) + expr_int_lit_count(cond, val)
                }
                Stmt::Return { value } => {
                    value.as_ref().map(|e| expr_int_lit_count(e, val)).unwrap_or(0)
                }
                Stmt::Expr(e) => expr_int_lit_count(e, val),
                Stmt::Block(b) => stmt_int_lit_count(b, val),
                Stmt::Switch { expr, cases, default } => {
                    expr_int_lit_count(expr, val)
                        + cases.iter().map(|c| {
                            expr_int_lit_count(&c.value, val) + stmt_int_lit_count(&c.body, val)
                        }).sum::<usize>()
                        + default.as_ref().map(|d| stmt_int_lit_count(d, val)).unwrap_or(0)
                }
                Stmt::Decl { init, .. } => {
                    init.as_ref().map(|e| expr_int_lit_count(e, val)).unwrap_or(0)
                }
                _ => 0,
            };
        }
        n
    }

    /// True if any loop body (at any depth) ends in a bare top-level Continue.
    fn has_bare_trailing_continue(stmts: &[Stmt]) -> bool {
        stmts.iter().any(|s| match s {
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                matches!(body.last(), Some(Stmt::Continue))
                    || has_bare_trailing_continue(body)
            }
            Stmt::If { then_body, else_body, .. } => {
                has_bare_trailing_continue(then_body)
                    || else_body.as_ref().map(|e| has_bare_trailing_continue(e)).unwrap_or(false)
            }
            Stmt::Block(b) => has_bare_trailing_continue(b),
            _ => false,
        })
    }

    fn contains_break(stmts: &[Stmt]) -> bool {
        stmts.iter().any(|s| match s {
            Stmt::Break => true,
            Stmt::If { then_body, else_body, .. } => {
                contains_break(then_body)
                    || else_body.as_ref().map(|e| contains_break(e)).unwrap_or(false)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                contains_break(body)
            }
            Stmt::Block(b) => contains_break(b),
            Stmt::Switch { cases, default, .. } => {
                cases.iter().any(|c| contains_break(&c.body))
                    || default.as_ref().map(|d| contains_break(d)).unwrap_or(false)
            }
            _ => false,
        })
    }

    fn assert_no_fallbacks(stmts: &[Stmt]) {
        let mut fallbacks = Vec::new();
        collect_fallbacks(stmts, &mut fallbacks);
        assert!(
            fallbacks.is_empty(),
            "must structure without goto/warning, got {:?} in {:#?}",
            fallbacks,
            stmts
        );
    }

    /// Marker instruction helper: `dst = const` so the test can verify the
    /// block's code was emitted exactly once at the right place.
    fn push_marker(func: &mut IrFunction, block: BlockId, val: i64) {
        let dst = func.alloc_var(Ty::i32());
        func.push_inst(block, IrInst::Unary {
            dst,
            op: OpCode::Copy,
            src: Value::Const(val),
        });
    }

    /// Repro of the frozen-binary shape at 0xBE00: loop header with NO
    /// conditional branch (unconditional entry into the body) and the real
    /// exit test sitting mid-body; the exit edge leaves the natural loop.
    /// Must structure as While(true) whose body contains `if (c) { break; }`,
    /// with the exit block processed AFTER the loop - never as a body that
    /// swallows the exit code and/or ends in a bare `continue`.
    #[test]
    fn test_mid_body_exit_true_side() {
        let mut func = IrFunction::new("mid_exit_true", 0x1000);
        let header = func.add_block("header");
        let t1 = func.add_block("t1");
        let t2 = func.add_block("t2");
        let exit_block = func.add_block("exit");

        func.push_inst(func.entry_block, IrInst::Branch { target: header });
        func.push_inst(header, IrInst::Branch { target: t1 });
        let c = func.alloc_var(Ty::Bool);
        func.push_inst(t1, IrInst::CBranch {
            cond: c,
            target_true: exit_block,
            target_false: t2,
        });
        func.push_inst(t2, IrInst::Branch { target: header });
        func.push_inst(exit_block, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        assert_no_fallbacks(&stmts);
        assert_eq!(stmts.len(), 2, "expected [While, Return], got {:#?}", stmts);
        let (cond, body) = match &stmts[0] {
            Stmt::While { cond, body } => (cond, body),
            other => panic!("expected top-level While, got {:?}", other),
        };
        assert!(
            matches!(cond, Expr::BoolLit(true)),
            "header does not test anything, cond should be true, got {:?}",
            cond
        );
        assert!(contains_break(body), "mid-body exit must become break, got {:#?}", body);
        assert!(!contains_return(body), "exit block must not be swallowed into the body");
        assert!(!has_bare_trailing_continue(&stmts), "body must not end in a bare continue");
    }

    /// Same shape, but the FALSE edge of the mid-body test leaves the loop.
    /// The break condition must be negated.
    #[test]
    fn test_mid_body_exit_false_side() {
        let mut func = IrFunction::new("mid_exit_false", 0x1000);
        let header = func.add_block("header");
        let t1 = func.add_block("t1");
        let t2 = func.add_block("t2");
        let exit_block = func.add_block("exit");

        func.push_inst(func.entry_block, IrInst::Branch { target: header });
        func.push_inst(header, IrInst::Branch { target: t1 });
        let c = func.alloc_var(Ty::Bool);
        func.push_inst(t1, IrInst::CBranch {
            cond: c,
            target_true: t2,
            target_false: exit_block,
        });
        func.push_inst(t2, IrInst::Branch { target: header });
        func.push_inst(exit_block, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        assert_no_fallbacks(&stmts);
        assert_eq!(stmts.len(), 2, "expected [While, Return], got {:#?}", stmts);
        let body = match &stmts[0] {
            Stmt::While { body, .. } => body,
            other => panic!("expected top-level While, got {:?}", other),
        };
        let break_if = body.iter().find_map(|s| match s {
            Stmt::If { cond, then_body, .. } => Some((cond, then_body)),
            _ => None,
        });
        let (cond, then_body) = break_if.expect("expected an if guarding the break");
        assert!(
            matches!(cond, Expr::Unary { op: UnOp::LogNot, .. }),
            "false-side exit must negate the condition, got {:?}",
            cond
        );
        assert!(
            matches!(then_body.as_slice(), [Stmt::Break]),
            "break must be the whole then-arm, got {:#?}",
            then_body
        );
        assert!(!contains_return(body), "exit block must not be swallowed into the body");
        assert!(!has_bare_trailing_continue(&stmts));
    }

    /// Nested loops where the INNER loop has a mid-body exit whose target
    /// rejoins the OUTER loop body. The exit must become a break of the
    /// inner loop only, with the rejoined code executed exactly once.
    #[test]
    fn test_nested_loop_mid_body_exit() {
        let mut func = IrFunction::new("nested_mid_exit", 0x1000);
        let h1 = func.add_block("h1");
        let h2 = func.add_block("h2");
        let i1 = func.add_block("i1");
        let i2 = func.add_block("i2");
        let mid_exit = func.add_block("mid_exit");
        let l1 = func.add_block("l1");
        let done = func.add_block("done");

        func.push_inst(func.entry_block, IrInst::Branch { target: h1 });
        func.push_inst(h1, IrInst::Branch { target: h2 });

        let o = func.alloc_var(Ty::Bool);
        func.push_inst(h2, IrInst::CBranch {
            cond: o,
            target_true: i1,
            target_false: done,
        });
        let i = func.alloc_var(Ty::Bool);
        func.push_inst(i1, IrInst::CBranch {
            cond: i,
            target_true: i2,
            target_false: mid_exit,
        });
        func.push_inst(i2, IrInst::Branch { target: h2 });
        push_marker(&mut func, mid_exit, 7);
        func.push_inst(mid_exit, IrInst::Branch { target: l1 });
        func.push_inst(l1, IrInst::Branch { target: h1 });
        push_marker(&mut func, done, 9);
        func.push_inst(done, IrInst::Branch { target: l1 });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        assert_no_fallbacks(&stmts);
        assert!(!has_bare_trailing_continue(&stmts));

        // Outer loop must exist and contain the inner loop.
        let outer = match stmts.first() {
            Some(Stmt::While { body, .. }) => body,
            other => panic!("expected outer While, got {:?}", other),
        };
        assert!(
            outer.iter().any(|s| matches!(s, Stmt::While { .. })),
            "inner loop must be nested inside the outer one, got {:#?}",
            outer
        );
        // Inner-loop exit path marker (7) and post-inner-loop marker (9):
        // each emitted exactly once.
        assert_eq!(stmt_int_lit_count(&stmts, 7), 1, "mid-exit code duplicated/dropped: {:#?}", stmts);
        assert_eq!(stmt_int_lit_count(&stmts, 9), 1, "post-exit code duplicated/dropped: {:#?}", stmts);
    }

    /// Loop exit target shared with the surrounding continuation: both the
    /// loop header (condition false) and a mid-body break jump to the same
    /// block after the loop. The shared block must be emitted exactly once,
    /// after the loop.
    #[test]
    fn test_loop_exit_shared_with_outer_continuation() {
        let mut func = IrFunction::new("shared_exit", 0x1000);
        let h = func.add_block("h");
        let b1 = func.add_block("b1");
        let tail = func.add_block("tail");
        let exit_block = func.add_block("exit");

        func.push_inst(func.entry_block, IrInst::Branch { target: h });
        let c = func.alloc_var(Ty::Bool);
        func.push_inst(h, IrInst::CBranch {
            cond: c,
            target_true: b1,
            target_false: exit_block,
        });
        let d = func.alloc_var(Ty::Bool);
        func.push_inst(b1, IrInst::CBranch {
            cond: d,
            target_true: h,
            target_false: tail,
        });
        push_marker(&mut func, tail, 5);
        func.push_inst(tail, IrInst::Branch { target: exit_block });
        push_marker(&mut func, exit_block, 8);
        func.push_inst(exit_block, IrInst::Return { value: None });
        func.build_cfg();

        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);

        assert_no_fallbacks(&stmts);
        assert!(!has_bare_trailing_continue(&stmts));

        let (cond, body) = match stmts.first() {
            Some(Stmt::While { cond, body }) => (cond, body),
            other => panic!("expected top-level While, got {:?}", other),
        };
        assert!(
            matches!(cond, Expr::Var(_)),
            "header tests c, so the while must have a real condition, got {:?}",
            cond
        );
        assert!(contains_break(body), "mid-body exit must become break");
        assert_eq!(stmt_int_lit_count(&stmts, 5), 1, "tail code duplicated/dropped: {:#?}", stmts);
        assert_eq!(stmt_int_lit_count(&stmts, 8), 1, "shared exit code duplicated/dropped: {:#?}", stmts);
        assert!(
            matches!(stmts.last(), Some(Stmt::Return { .. })),
            "shared exit block must run after the loop, got {:#?}",
            stmts
        );
        assert_eq!(stmts.len(), 2, "nothing else expected at top level, got {:#?}", stmts);
    }

    #[test]
    fn test_structuring_is_deterministic() {
        let mut func = build_chain_switch_func("determinism", OpCode::Eq);
        func.build_cfg();
        let out1 = {
            let mut converter = IrToAstConverter::new(&func);
            format!("{:?}", structure_control_flow(&func, &mut converter))
        };
        let out2 = {
            let mut converter = IrToAstConverter::new(&func);
            format!("{:?}", structure_control_flow(&func, &mut converter))
        };
        assert_eq!(out1, out2);
    }
}
