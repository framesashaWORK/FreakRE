use eframe::egui;
use freakre_scanner::{scanner::Scanner, report::FileReport};
use plugins::PluginManager;
use capstone_ffi::{Disassembler, Arch};
use cfg_builder::{build_cfg, CfgConfig, ControlFlowGraph};
use xrefs::{XrefDatabase, build_import_xrefs};
use freakre_ir::x86_lifter::X86Lifter;
use freakre_ir::Lifter;
use decompiler::decompile_function;
use dataflow::DataFlowAnalysis;
use func_sigs::{scan_signatures, SigScanConfig, SignatureScanResult};
use ml_detection::{extract_features, EnsembleClassifier, BinaryInfo};
use diffing::DiffResult;
use freakre_symbols::SymbolDb;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::collections::HashMap;
use std::time::Instant;

use crate::theme::{self, AppSettings, ThemeColors, ToastManager, ToastKind};
use crate::views;

// ─── Top-level UI modes (mode strip above the classic views) ────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Classic IDA-style layout with the central tab bar (default).
    Standard,
    /// Split pseudocode + assembly for the same function.
    Multi,
    /// Scanner/ML verdict dashboard.
    MalwareDetector,
    /// Backdoor findings filtered by profile (Applications / Malware / Multi).
    BackdoorAnalyzer,
}

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Standard        => "Standard",
            Mode::Multi           => "Multi",
            Mode::MalwareDetector => "Malware Detector",
            Mode::BackdoorAnalyzer=> "Backdoor Analyzer",
        }
    }

    pub fn all() -> &'static [Mode] {
        &[Mode::Standard, Mode::Multi, Mode::MalwareDetector, Mode::BackdoorAnalyzer]
    }
}

// ─── Central Tabs (IDA-style: always visible in center panel) ───────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Disassembly,
    Decompiler,
    HexView,
    GraphView,
    Strings,
    Imports,
    Xrefs,
    Entropy,
    Report,
    Findings,
    Structures,
    Settings,
    Scripting,
    Plugins,
    Diffing,
    DataFlow,
    MlClassify,
    FuncSigs,
    FullSource,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Disassembly  => "IDA View-A",
            Tab::Decompiler   => "Pseudocode-A",
            Tab::HexView      => "Hex View-1",
            Tab::GraphView    => "Graph",
            Tab::Strings      => "Strings",
            Tab::Imports      => "Imports",
            Tab::Xrefs        => "Xrefs",
            Tab::Entropy      => "Entropy",
            Tab::Report       => "Report",
            Tab::Findings     => "Findings",
            Tab::Structures   => "Structures",
            Tab::Settings     => "Settings",
            Tab::Scripting    => "Script REPL",
            Tab::Plugins      => "Plugins",
            Tab::Diffing      => "Diffing",
            Tab::DataFlow     => "DataFlow",
            Tab::MlClassify   => "ML Classify",
            Tab::FuncSigs     => "Func Sigs",
            Tab::FullSource   => "Full Source",
        }
    }

    /// Tabs shown in the central tab bar
    pub fn main_tabs() -> &'static [Tab] {
        &[
            Tab::Disassembly,
            Tab::Decompiler,
            Tab::HexView,
            Tab::GraphView,
            Tab::Strings,
            Tab::Imports,
            Tab::Xrefs,
            Tab::Entropy,
            Tab::Report,
            Tab::Findings,
            Tab::Structures,
            Tab::Scripting,
            Tab::Plugins,
            Tab::Diffing,
            Tab::DataFlow,
            Tab::MlClassify,
            Tab::FuncSigs,
            Tab::FullSource,
            Tab::Settings,
        ]
    }
}

/// Incremental "Full Source" decompilation of every function in the file.
/// Processed N functions per frame so the UI never freezes.
#[derive(Default)]
pub struct FullSourceState {
    /// (start_offset, name, end_offset_exclusive)
    pub funcs: Vec<(u64, String, u64)>,
    pub next: usize,
    pub done: usize,
    pub failed: usize,
    pub running: bool,
    pub started_at: Option<Instant>,
    /// Accumulated output: (function name, decompiled text)
    pub chunks: Vec<(String, String)>,
    pub truncated_note: Option<String>,
}


#[allow(clippy::large_enum_variant)]
pub enum ScanMessage {
    /// Raw file bytes plus read error (empty data + Err when the read failed).
    Report(FileReport, std::io::Result<Vec<u8>>),
    Done,
}

pub enum Job {
    XrefBuild { data: Arc<Vec<u8>>, import_names: Vec<String> },
    FuncSigs { data: Arc<Vec<u8>> },
    MlClassify { data: Arc<Vec<u8>> },
    Decompile { addr: u64, code: Vec<u8>, func_name: String, is_64bit: bool },
    BuildCfg { addr: u64, code: Vec<u8>, base_va: u64, is_64bit: bool },
    XrefViewScan { report_idx: usize, target: u64, data_len: usize, data: Arc<Vec<u8>>, is_64bit: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKey {
    XrefBuild,
    FuncSigs,
    MlClassify,
    Decompile(u64),
    BuildCfg(u64),
    XrefViewScan(usize, u64, usize),
}

#[allow(clippy::large_enum_variant)]
enum JobResult {
    XrefBuild(XrefDatabase),
    FuncSigs(Box<SignatureScanResult>),
    MlClassify(ml_detection::ClassificationResult),
    Decompile { addr: u64, text: String, dataflow: Option<DataFlowAnalysis>, note: Option<String> },
    BuildCfg { addr: u64, cfg: ControlFlowGraph },
    XrefViewScan { key: (usize, u64, usize), hits: Vec<(u64, String)> },
}

/// Commands sent to the blocking project-DB worker thread so sled I/O
/// never runs on the UI thread.
pub enum DbCommand {
    Create { project_path: PathBuf, binary_path: PathBuf, hash: String },
    AddBookmark(project_db::Bookmark),
    SetLabel(u64, String),
    SetComment(u64, String),
    RemoveComment(u64),
}

/// Scripting REPL state
pub struct ReplState {
    pub input: String,
    pub history: Vec<String>,
    pub history_pos: usize,
    pub output: Vec<(String, String)>,  // (input, output)
}

impl ReplState {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            history: Vec::new(),
            history_pos: 0,
            output: Vec::new(),
        }
    }
}

pub struct FreakREApp {
    pub scanner: Scanner,
    pub plugin_manager: PluginManager,
    pub reports: Vec<FileReport>,
    pub report_data: Vec<Arc<Vec<u8>>>,
    pub selected_report: Option<usize>,
    pub active_tab: Tab,
    pub is_scanning: bool,
    pub scan_total: usize,
    pub scan_done: usize,
    pub drag_hovered: bool,
    pub scan_rx: Option<mpsc::Receiver<ScanMessage>>,
    job_tx: mpsc::Sender<Job>,
    job_rx: mpsc::Receiver<JobResult>,
    /// In-flight jobs keyed by JobKey → report generation they belong to.
    /// Stale results (older generation) are discarded on completion.
    pub pending_jobs: HashMap<JobKey, u64>,
    /// Bumped whenever a new file report is added; used to invalidate
    /// per-file analysis caches and queued background jobs.
    report_generation: u64,
    pub xref_view_cache: HashMap<(usize, u64, usize), Vec<(u64, String)>>,
    pub yara_rules_path: Option<PathBuf>,

    // Hex view state
    pub hex_offset: usize,
    pub hex_search: String,

    /// Set when the raw bytes for the current report could not be read,
    /// so Hex/Disasm views can surface it instead of showing "empty".
    pub data_read_error: Option<String>,

    // Disassembly state
    pub disasm_offset: u64,
    pub disasm_is_64bit: bool,

    // Functions panel filter
    pub functions_filter: String,

    /// Function that last auto-scrolled in the Functions panel (avoids
    /// issuing scroll_to_me every frame, which forced continuous repaints).
    pub last_cursor_func: Option<u64>,

    // Output / log panel
    pub output_lines: Vec<String>,

    // Plugin output log
    pub plugin_output: Vec<String>,

    // Settings & theme
    pub settings: AppSettings,
    pub colors: ThemeColors,
    pub toasts: ToastManager,

    // Search
    pub global_search: String,
    pub show_search: bool,

    // ── IDA-like Navigation ──────────────────────────────────────
    /// Navigation history (back/forward like browser)
    pub nav_history: Vec<u64>,
    pub nav_history_pos: usize,

    /// Bookmarks (Alt+1..9 to set, Ctrl+1..9 to jump)
    pub bookmarks: [Option<u64>; 10],

    /// Go-to-address dialog state
    pub show_goto: bool,
    pub goto_input: String,

    /// Rename dialog state
    pub show_rename: bool,
    pub rename_input: String,
    pub rename_target_addr: Option<u64>,

    /// Xref query address
    pub xref_query_addr: u64,

    /// Decompiled pseudocode cache (address → decompiled text)
    pub decompile_cache: HashMap<u64, String>,

    /// Comments map (address → comment string)
    pub comments: HashMap<u64, String>,

    /// Show comment edit dialog
    pub show_comment_edit: bool,
    pub comment_input: String,
    pub comment_target_addr: Option<u64>,

    /// Custom function names (address → user-defined name)
    pub custom_names: HashMap<u64, String>,

    // ─── NEW: Advanced Analysis State ─────────────────────────────

    /// Capstone disassembler (multi-arch)
    pub disasm: Option<Disassembler>,

    /// CFG cache per function (entry address → CFG)
    pub cfg_cache: HashMap<u64, ControlFlowGraph>,

    /// Xref database (built from scan results)
    pub xref_db: XrefDatabase,

    /// Project database persistence moved off the UI thread: commands are
    /// sent to a worker that owns the blocking sled database.
    pub db_tx: mpsc::Sender<DbCommand>,
    db_status_rx: mpsc::Receiver<String>,

    /// Function signatures scan result
    pub func_sigs_result: Option<SignatureScanResult>,

    /// ML classification result
    pub ml_result: Option<ml_detection::ClassificationResult>,

    /// Scripting REPL
    pub repl: ReplState,

    /// Diffing state
    pub diffing_other_path: Option<PathBuf>,
    pub diffing_result: Option<DiffResult>,

    /// DataFlow analysis for current function
    pub dataflow_result: Option<DataFlowAnalysis>,

    /// Current file path (for project persistence)
    pub current_file_path: Option<PathBuf>,

    /// Debug symbols loaded from PDB or DWARF for the current binary.
    pub symbol_db: Option<SymbolDb>,

    // ─── UI overhaul state ────────────────────────────────────────
    /// Active top-level mode (Standard / Multi / Malware Detector / Backdoor).
    pub active_mode: Mode,

    /// Multi mode: selected instruction address + selected pseudocode line.
    pub multi_cursor_addr: u64,
    pub multi_selected_line: usize,

    /// Backdoor Analyzer sub-tab index (0=Applications, 1=Malware, 2=Multi).
    pub backdoor_subtab: usize,

    /// When the current scan started (for the centered progress overlay).
    pub scan_started_at: Option<Instant>,

    /// Incremental full-source decompilation job.
    pub full_source: FullSourceState,

    /// One-shot focus latch for modal dialogs: request focus only on the
    /// frame a dialog OPENS, not every frame (repeated request_focus steals
    /// focus from other widgets and makes buttons feel dead).
    pub dialog_focus_latch: bool,
}

impl FreakREApp {
    pub fn new() -> Self {
        let mut plugin_manager = PluginManager::new();
        freakre_sys_plugins::register_system_plugins(&mut plugin_manager);

        let settings = AppSettings::load();
        let colors = ThemeColors::ida_dark();

        let (job_tx, job_rx_in) = mpsc::channel::<Job>();
        let (res_tx, job_rx_out) = mpsc::channel::<JobResult>();

        std::thread::spawn(move || {
            while let Ok(job) = job_rx_in.recv() {
                if res_tx.send(run_job(job)).is_err() {
                    break;
                }
            }
        });

        // Blocking project-DB (sled) worker: owns the database so writes
        // never stall the UI thread. Status lines come back for the log.
        let (db_tx, db_rx) = mpsc::channel::<DbCommand>();
        let (db_status_tx, db_status_rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut db: Option<project_db::ProjectDatabase> = None;
            while let Ok(cmd) = db_rx.recv() {
                match cmd {
                    DbCommand::Create { project_path, binary_path, hash } => {
                        match project_db::ProjectDatabase::create(
                            &project_path,
                            binary_path,
                            hash,
                            "x86_64".to_string(),
                            "PE".to_string(),
                        ) {
                            Ok(opened) => {
                                db = Some(opened);
                                let _ = db_status_tx.send(format!("Project DB opened: {:?}", project_path));
                            }
                            Err(e) => {
                                db = None;
                                let _ = db_status_tx.send(format!("Failed to open project DB: {}", e));
                            }
                        }
                    }
                    DbCommand::AddBookmark(bm) => {
                        if let Some(ref mut d) = db { let _ = d.add_bookmark(bm); }
                    }
                    DbCommand::SetLabel(addr, label) => {
                        if let Some(ref mut d) = db { let _ = d.set_label(addr, label); }
                    }
                    DbCommand::SetComment(addr, comment) => {
                        if let Some(ref mut d) = db { let _ = d.set_comment(addr, comment); }
                    }
                    DbCommand::RemoveComment(addr) => {
                        if let Some(ref mut d) = db { let _ = d.remove_comment(addr); }
                    }
                }
            }
        });

        Self {
            scanner: Scanner::new(),
            plugin_manager,
            reports: Vec::new(),
            report_data: Vec::new(),
            selected_report: None,
            active_tab: Tab::Disassembly,
            is_scanning: false,
            scan_total: 0,
            scan_done: 0,
            drag_hovered: false,
            scan_rx: None,
            job_tx,
            job_rx: job_rx_out,
            pending_jobs: HashMap::new(),
            report_generation: 0,
            xref_view_cache: HashMap::new(),
            yara_rules_path: None,
            hex_offset: 0,
            hex_search: String::new(),
            data_read_error: None,
            disasm_offset: 0,
            disasm_is_64bit: true,
            functions_filter: String::new(),
            last_cursor_func: None,
            output_lines: vec!["FreakRE v0.2 ready.".to_string()],
            plugin_output: Vec::new(),
            settings,
            colors,
            toasts: ToastManager::new(),
            global_search: String::new(),
            show_search: false,
            nav_history: Vec::new(),
            nav_history_pos: 0,
            bookmarks: [None; 10],
            show_goto: false,
            goto_input: String::new(),
            show_rename: false,
            rename_input: String::new(),
            rename_target_addr: None,
            xref_query_addr: 0,
            decompile_cache: HashMap::new(),
            comments: HashMap::new(),
            show_comment_edit: false,
            comment_input: String::new(),
            comment_target_addr: None,
            custom_names: HashMap::new(),
            disasm: None,
            cfg_cache: HashMap::new(),
            xref_db: XrefDatabase::new(),
            db_tx,
            db_status_rx,
            func_sigs_result: None,
            ml_result: None,
            repl: ReplState::new(),
            diffing_other_path: None,
            diffing_result: None,
            dataflow_result: None,
            current_file_path: None,
            symbol_db: None,
            active_mode: Mode::Standard,
            multi_cursor_addr: 0,
            multi_selected_line: 0,
            backdoor_subtab: 0,
            scan_started_at: None,
            full_source: FullSourceState::default(),
            dialog_focus_latch: false,
        }
    }

    pub fn apply_theme(&mut self, ctx: &egui::Context) {
        self.colors = ThemeColors::ida_dark();
        theme::apply_theme(ctx, &self.colors);
        self.settings.save();
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        self.output_lines.push(msg.into());
        if self.output_lines.len() > 500 {
            self.output_lines.drain(0..self.output_lines.len() - 500);
        }
    }

    /// Initialize disassembler for current architecture
    pub fn ensure_disasm(&mut self) {
        if self.disasm.is_none() {
            let mode = if self.disasm_is_64bit {
                capstone_ffi::Mode::Mode64
            } else {
                capstone_ffi::Mode::Mode32
            };
            match Disassembler::new(Arch::X86, mode) {
                Ok(d) => {
                    self.disasm = Some(d);
                    self.log(format!("Disassembler initialized ({})", if self.disasm_is_64bit { "x86_64" } else { "x86" }));
                }
                Err(e) => {
                    self.log(format!("Failed to create disassembler: {}", e));
                }
            }
        }
    }

    /// Queue background xref database build from current report
    fn request_xref_build(&mut self) {
        let idx = match self.selected_report.or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) }) {
            Some(i) => i,
            None => return,
        };
        let data = match self.report_data.get(idx) {
            Some(d) => d.clone(),
            None => return,
        };
        let report = match self.reports.get(idx) {
            Some(r) => r,
            None => return,
        };

        let import_names: Vec<String> = report.findings.iter()
            .filter(|f| f.module == "imports" || f.module == "import_analyzer")
            .map(|f| f.description.clone())
            .collect();

        self.enqueue_job(JobKey::XrefBuild, Job::XrefBuild { data, import_names });
    }

    /// Queue background function signature scan
    pub fn request_func_sigs(&mut self) {
        let idx = match self.selected_report.or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) }) {
            Some(i) => i,
            None => return,
        };
        let data = match self.report_data.get(idx) {
            Some(d) => d.clone(),
            None => return,
        };

        self.enqueue_job(JobKey::FuncSigs, Job::FuncSigs { data });
    }

    /// Queue background ML classification
    pub fn request_ml_classify(&mut self) {
        let idx = match self.selected_report.or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) }) {
            Some(i) => i,
            None => return,
        };
        let data = match self.report_data.get(idx) {
            Some(d) => d.clone(),
            None => return,
        };

        self.enqueue_job(JobKey::MlClassify, Job::MlClassify { data });
    }

    fn enqueue_job(&mut self, key: JobKey, job: Job) {
        if self.pending_jobs.contains_key(&key) {
            return;
        }
        if self.job_tx.send(job).is_ok() {
            self.pending_jobs.insert(key, self.report_generation);
        }
    }

    /// Queue a background scan of the binary for direct references to target
    pub fn enqueue_xref_view_scan(&mut self, key: (usize, u64, usize), data: Arc<Vec<u8>>, is_64bit: bool) {
        self.enqueue_job(
            JobKey::XrefViewScan(key.0, key.1, key.2),
            Job::XrefViewScan { report_idx: key.0, target: key.1, data_len: key.2, data, is_64bit },
        );
    }

    /// Remove a completed job and report whether its result still belongs to
    /// the currently loaded file (generation matches). Results queued for an
    /// older binary are discarded instead of being applied to the new one.
    fn finish_job(&mut self, key: JobKey) -> bool {
        matches!(self.pending_jobs.remove(&key), Some(gen) if gen == self.report_generation)
    }

    /// Drain finished background jobs and apply their results
    fn drain_job_results(&mut self, ctx: &egui::Context) {
        while let Ok(result) = self.job_rx.try_recv() {
            match result {
                JobResult::XrefBuild(db) => {
                    if !self.finish_job(JobKey::XrefBuild) { continue; }
                    let count = db.len();
                    self.xref_db = db;
                    self.log(format!("Xref database built: {} xrefs", count));
                }
                JobResult::FuncSigs(res) => {
                    if !self.finish_job(JobKey::FuncSigs) { continue; }
                    self.log(format!("Func sigs: {} matches, compiler: {:?}",
                        res.matches.len(),
                        res.compiler_info.as_ref().map(|c| c.compiler.as_str()).unwrap_or("unknown")));
                    self.func_sigs_result = Some(*res);
                }
                JobResult::MlClassify(res) => {
                    if !self.finish_job(JobKey::MlClassify) { continue; }
                    self.log(format!("ML classify: {} ({:.0}% confidence)", res.class, res.confidence * 100.0));
                    self.ml_result = Some(res);
                }
                JobResult::Decompile { addr, text, dataflow, note } => {
                    if !self.finish_job(JobKey::Decompile(addr)) { continue; }
                    // Bound the cache: evict entries furthest from current
                    // cursor instead of nuking everything (the old .clear()
                    // caused re-decompilation storms on large binaries).
                    if self.decompile_cache.len() > 256 {
                        evict_cache_by_distance(&mut self.decompile_cache, self.disasm_offset, 128);
                    }
                    self.decompile_cache.insert(addr, text);
                    if let Some(df) = dataflow {
                        self.dataflow_result = Some(df);
                    }
                    if let Some(note) = note {
                        self.log(note);
                    }
                }
                JobResult::BuildCfg { addr, cfg } => {
                    if !self.finish_job(JobKey::BuildCfg(addr)) { continue; }
                    self.log(format!("CFG built: {} blocks, {} edges", cfg.blocks.len(), cfg.num_edges()));
                    // CFGs for large functions are heavy — evict by distance.
                    if self.cfg_cache.len() > 64 {
                        evict_cache_by_distance(&mut self.cfg_cache, self.disasm_offset, 32);
                    }
                    self.cfg_cache.insert(addr, cfg);
                }
                JobResult::XrefViewScan { key, hits } => {
                    if !self.finish_job(JobKey::XrefViewScan(key.0, key.1, key.2)) { continue; }
                    // Xref view cache: drop oldest half when over limit.
                    if self.xref_view_cache.len() > 256 {
                        let target = 128;
                        let keys: Vec<_> = self.xref_view_cache.keys().cloned().collect();
                        let to_remove = keys.len().saturating_sub(target);
                        for k in keys.into_iter().take(to_remove) {
                            self.xref_view_cache.remove(&k);
                        }
                    }
                    self.xref_view_cache.insert(key, hits);
                }
            }
        }

        if !self.pending_jobs.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(33));
        }
    }

    /// Drain status lines produced by the project-DB worker.
    fn drain_db_status(&mut self) {
        while let Ok(line) = self.db_status_rx.try_recv() {
            self.log(line);
        }
    }

    pub fn handle_drag_and_drop(&mut self, ctx: &egui::Context) {
        let (hovered, dropped) = ctx.input(|i| {
            let dropped: Vec<PathBuf> = i
                .raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect();
            (!i.raw.hovered_files.is_empty(), dropped)
        });

        if hovered {
            egui::Area::new(egui::Id::new("drop_overlay"))
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .interactable(false)
                .show(ctx, |ui| {
                    let size = egui::vec2(480.0_f32, 180.0_f32);
                    let (response, painter) = ui.allocate_painter(size, egui::Sense::hover());
                    let rect = response.rect;
                    let stroke = egui::Stroke::new(3.0_f32, self.colors.info);
                    painter.rect_stroke(rect, 16.0_f32, stroke, egui::StrokeKind::Inside);
                    painter.rect_filled(
                        rect,
                        16.0_f32,
                        self.colors.info.gamma_multiply(0.08_f32),
                    );
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "Drop files to open and scan",
                        egui::FontId::proportional(24.0_f32),
                        self.colors.info,
                    );
                });
        }

        if dropped.is_empty() {
            return;
        }

        let existing: Vec<PathBuf> = dropped.into_iter().filter(|p| p.is_file()).collect();
        if existing.is_empty() {
            self.log("Dropped items are not readable files");
            return;
        }

        if self.is_scanning {
            self.log("Scan already in progress, dropped files ignored");
            return;
        }

        self.log(format!("Received {} dropped file(s)", existing.len()));
        self.scan_files(existing);
    }

    pub fn scan_files(&mut self, paths: Vec<PathBuf>) {
        if self.is_scanning {
            return;
        }
        self.is_scanning = true;
        self.scan_total = paths.len();
        self.scan_done = 0;
        // Drives the centered progress modal (spinner + elapsed clock).
        self.scan_started_at = Some(Instant::now());

        for p in &paths {
            if let Some(s) = p.to_str() {
                self.settings.add_recent_file(s);
            }
        }
        self.settings.save();

        if let Some(first) = paths.first() {
            self.current_file_path = Some(first.clone());
        }

        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);

        let yara_path = self.yara_rules_path.clone();

        std::thread::spawn(move || {
            let worker = if let Some(ref rules_path) = yara_path {
                match Scanner::new().with_yara_rules(rules_path) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Failed to load YARA rules: {}", e);
                        Scanner::new()
                    }
                }
            } else {
                Scanner::new()
            };

            for path in &paths {
                let data = std::fs::read(path);
                let report = worker.scan_file(path);
                let _ = tx.send(ScanMessage::Report(report, data));
            }
            let _ = tx.send(ScanMessage::Done);
        });
    }

    pub fn load_yara_rules(&mut self, path: PathBuf) {
        match Scanner::new().with_yara_rules(&path) {
            Ok(_) => {
                self.yara_rules_path = Some(path);
                self.log("YARA rules loaded successfully");
                self.toasts.add("YARA rules loaded", ToastKind::Success);
            }
            Err(e) => {
                self.log(format!("Failed to load YARA rules: {}", e));
                self.toasts.add(format!("YARA error: {}", e), ToastKind::Error);
            }
        }
    }

    /// Clear every per-file analysis cache. Must run whenever a NEW report
    /// is added — not only when evicting the oldest one — otherwise F5/CFG/
    /// xref views keep showing the PREVIOUS binary's data.
    fn reset_per_file_analysis_state(&mut self) {
        self.decompile_cache.clear();
        self.cfg_cache.clear();
        self.xref_view_cache.clear();
        self.comments.clear();
        self.custom_names.clear();
        self.func_sigs_result = None;
        self.ml_result = None;
        self.dataflow_result = None;
        self.data_read_error = None;
        self.disasm = None;
        self.last_cursor_func = None;
        self.symbol_db = None;
        // Full Source output belongs to the previous binary — drop it.
        self.full_source = FullSourceState::default();
        // Jobs queued for the previous binary would return stale results;
        // drop them and bump the generation so in-flight ones are discarded.
        self.pending_jobs.clear();
        self.report_generation = self.report_generation.wrapping_add(1);
    }

    fn poll_scan_results(&mut self) {
        // Collect messages first to avoid borrow conflict on self
        let mut messages: Vec<ScanMessage> = Vec::new();
        let mut disconnected = false;
        if let Some(ref rx) = self.scan_rx {
            loop {
                match rx.try_recv() {
                    Ok(msg) => messages.push(msg),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // Sender dropped (worker finished or panicked without
                        // sending Done). Treat as completion so is_scanning
                        // cannot get stuck true forever.
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        let mut finished = disconnected;
        for msg in messages {
            match msg {
                ScanMessage::Report(report, data_res) => {
                    let fname = report.path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".into());
                    self.log(format!("Scanned: {} ({})", fname, report.file_type));

                    // Cap retained files: each entry holds the FULL raw file
                    // bytes (report_data) — a 190 MB binary scanned a handful
                    // of times used to accumulate gigabytes of RSS.
                    const MAX_REPORTS: usize = 4;
                    if self.reports.len() >= MAX_REPORTS {
                        let remove = 0usize; // oldest
                        self.reports.remove(remove);
                        self.report_data.remove(remove);
                        self.selected_report = None;
                    }

                    // Address-keyed caches are per-file → reset on EVERY new
                    // report, not just on eviction.
                    self.reset_per_file_analysis_state();

                    match data_res {
                        Ok(data) => {
                            self.reports.push(report);
                            self.report_data.push(Arc::new(data));
                        }
                        Err(e) => {
                            // Keep the report (findings are still valid) but
                            // surface the missing bytes to Hex/Disasm views.
                            let err = format!("Failed to read {}: {} — Hex/Disasm views unavailable", fname, e);
                            self.log(err.clone());
                            self.toasts.add(format!("Read error: {}", fname), ToastKind::Error);
                            self.data_read_error = Some(err);
                            self.reports.push(report);
                            self.report_data.push(Arc::new(Vec::new()));
                        }
                    }
                    self.scan_done += 1;
                }
                ScanMessage::Done => {
                    finished = true;
                }
            }
        }

        if finished {
            self.is_scanning = false;
            self.scan_rx = None;
            self.scan_started_at = None;
            self.log("Scan completed.");
            self.toasts.add("Scan completed", ToastKind::Success);

            // Auto-load debug symbols (PDB alongside PE, or DWARF from ELF bytes)
            self.try_load_symbols();

            // Auto-build analysis (queued to background worker)
            self.ensure_disasm();
            self.request_xref_build();
            self.request_func_sigs();
            self.request_ml_classify();

            // Open project database on the blocking-DB worker thread
            // (sled I/O must not run on the UI thread).
            if let Some(ref path) = self.current_file_path {
                let project_path = path.with_extension("bdb");
                let hash = self.reports.last()
                    .map(|r| r.sha256.clone())
                    .unwrap_or_default();
                let _ = self.db_tx.send(DbCommand::Create {
                    project_path,
                    binary_path: path.clone(),
                    hash,
                });
            }
        }
    }

    /// Push current disasm address onto navigation history
    pub fn nav_push(&mut self, addr: u64) {
        // Don't push duplicate of current position
        if let Some(&last) = self.nav_history.get(self.nav_history_pos) {
            if last == addr { return; }
        }
        // Truncate forward history when navigating to new location
        self.nav_history.truncate(self.nav_history_pos + 1);
        self.nav_history.push(addr);
        self.nav_history_pos = self.nav_history.len() - 1;
        // Cap history size
        if self.nav_history.len() > 256 {
            self.nav_history.drain(0..self.nav_history.len() - 256);
            self.nav_history_pos = self.nav_history.len() - 1;
        }
    }

    pub fn nav_back(&mut self) {
        if self.nav_history_pos > 0 {
            self.nav_history_pos -= 1;
            if let Some(&addr) = self.nav_history.get(self.nav_history_pos) {
                self.disasm_offset = addr;
                self.active_tab = Tab::Disassembly;
            }
        }
    }

    pub fn nav_forward(&mut self) {
        if self.nav_history_pos + 1 < self.nav_history.len() {
            self.nav_history_pos += 1;
            if let Some(&addr) = self.nav_history.get(self.nav_history_pos) {
                self.disasm_offset = addr;
                self.active_tab = Tab::Disassembly;
            }
        }
    }

    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        // While scanning, all interaction is blocked by the progress overlay.
        if self.is_scanning {
            return;
        }
        // Must be read BEFORE ctx.input(): nesting another Context accessor
        // inside the input() closure deadlocks (it holds the context write
        // lock), and RawInput no longer carries this flag in egui 0.31.
        let typing = ctx.wants_keyboard_input();
        ctx.input(|i| {
            // Plain-letter shortcuts must NOT fire while a text field has
            // keyboard focus, otherwise typing "g"/"n"/"x"/space in the
            // filter/search boxes opens dialogs or switches views — this made
            // controls feel unresponsive.

            // ── F5: Decompile (IDA signature shortcut) ────────────────
            if i.key_pressed(egui::Key::F5) {
                self.active_tab = Tab::Decompiler;
                // Trigger decompilation for current address
                let addr = self.disasm_offset;
                if !self.decompile_cache.contains_key(&addr) {
                    self.decompile_at(addr);
                }
            }

            // ── G: Go to address ──────────────────────────────────────
            if !typing && !i.modifiers.any() && i.key_pressed(egui::Key::G) {
                self.open_goto();
            }

            // ── N: Rename function/symbol at cursor ───────────────────
            if !typing && !i.modifiers.any() && i.key_pressed(egui::Key::N) {
                self.open_rename_at(self.disasm_offset);
            }

            // ── X: Show cross-references ──────────────────────────────
            if !typing && !i.modifiers.any() && i.key_pressed(egui::Key::X) {
                self.xref_query_addr = self.disasm_offset;
                self.goto_tab(Tab::Xrefs);
            }

            // ── Space: Toggle Disassembly ↔ Graph ────────────────────
            if !typing && !i.modifiers.any() && i.key_pressed(egui::Key::Space) {
                self.active_tab = match self.active_tab {
                    Tab::Disassembly => Tab::GraphView,
                    Tab::GraphView => Tab::Disassembly,
                    other => other,
                };
                // Build CFG when switching to graph
                if self.active_tab == Tab::GraphView {
                    self.build_cfg_at(self.disasm_offset);
                }
            }

            // ── Esc: Navigation back / close dialogs ──────────────────
            if i.key_pressed(egui::Key::Escape) {
                if self.show_search { self.show_search = false; }
                else if self.show_goto { self.show_goto = false; }
                else if self.show_rename { self.show_rename = false; }
                else if self.show_comment_edit { self.show_comment_edit = false; }
                else { self.nav_back(); }
            }

            // ── Ctrl+F: Search ────────────────────────────────────────
            if i.modifiers.ctrl && i.key_pressed(egui::Key::F) {
                self.show_search = !self.show_search;
            }

            // ── Ctrl+Tab / Ctrl+Shift+Tab: cycle tabs ─────────────────
            if i.modifiers.ctrl && i.key_pressed(egui::Key::Tab) {
                let tabs = Tab::main_tabs();
                let cur = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
                let next = if i.modifiers.shift {
                    (cur + tabs.len() - 1) % tabs.len()
                } else {
                    (cur + 1) % tabs.len()
                };
                self.active_tab = tabs[next];
            }

            // ── Alt+Left / Alt+Right: Nav back/forward ────────────────
            if i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft) {
                self.nav_back();
            }
            if i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight) {
                self.nav_forward();
            }

            // ── Bookmarks: Alt+0..9 set, Ctrl+0..9 jump ──────────────
            for key_idx in 0..=9u8 {
                let key = match key_idx {
                    0 => egui::Key::Num0,
                    1 => egui::Key::Num1,
                    2 => egui::Key::Num2,
                    3 => egui::Key::Num3,
                    4 => egui::Key::Num4,
                    5 => egui::Key::Num5,
                    6 => egui::Key::Num6,
                    7 => egui::Key::Num7,
                    8 => egui::Key::Num8,
                    9 => egui::Key::Num9,
                    _ => continue,
                };
                // Alt+N: set bookmark
                if i.modifiers.alt && i.key_pressed(key) {
                    self.bookmarks[key_idx as usize] = Some(self.disasm_offset);
                    // Persist to project-db (blocking sled write runs on the
                    // DB worker thread).
                    let _ = self.db_tx.send(DbCommand::AddBookmark(project_db::Bookmark {
                        address: self.disasm_offset,
                        name: format!("Bookmark {}", key_idx),
                        comment: None,
                        created_at: chrono::Utc::now(),
                    }));
                    self.toasts.add(
                        format!("Bookmark {} set: {:08X}", key_idx, self.disasm_offset),
                        ToastKind::Info,
                    );
                }
                // Ctrl+N: jump to bookmark
                if i.modifiers.ctrl && i.key_pressed(key) {
                    if let Some(addr) = self.bookmarks[key_idx as usize] {
                        self.nav_push(addr);
                        self.disasm_offset = addr;
                        self.active_tab = Tab::Disassembly;
                        self.toasts.add(
                            format!("Jumped to bookmark {}: {:08X}", key_idx, addr),
                            ToastKind::Info,
                        );
                    }
                }
            }

            // ── ; or : : Add/edit comment at cursor ──────────────────
            if !typing && !i.modifiers.any() && (i.key_pressed(egui::Key::Semicolon) || i.key_pressed(egui::Key::Colon)) {
                self.open_comment_at(self.disasm_offset);
            }

            // ── Y: Set type (stub) ────────────────────────────────────
            if !typing && !i.modifiers.any() && i.key_pressed(egui::Key::Y) {
                self.toasts.add("Set type: not yet implemented", ToastKind::Info);
            }
        });
    }

    /// Queue CFG build for a function at given address
    pub fn build_cfg_at(&mut self, addr: u64) {
        if self.cfg_cache.contains_key(&addr) || self.pending_jobs.contains_key(&JobKey::BuildCfg(addr)) {
            return;
        }

        let idx = match self.selected_report.or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) }) {
            Some(i) => i,
            None => return,
        };
        let data = match self.report_data.get(idx) {
            Some(d) => d.clone(),
            None => return,
        };

        let start = addr as usize;
        if start >= data.len() {
            return;
        }

        // Find function boundaries (simple: scan forward until RET or max size)
        let mut end = start;
        let max_size = 0x2000.min(data.len() - start);
        while end < start + max_size {
            if data[end] == 0xC3 || data[end] == 0xCB { // RET
                end += 1;
                break;
            }
            end += 1;
        }

        let code = data[start..end].to_vec();
        self.enqueue_job(JobKey::BuildCfg(addr), Job::BuildCfg {
            addr,
            code,
            base_va: addr,
            is_64bit: self.disasm_is_64bit,
        });
    }

    /// Queue background decompilation using IR pipeline
    pub fn decompile_at(&mut self, addr: u64) {
        if self.pending_jobs.contains_key(&JobKey::Decompile(addr)) {
            self.decompile_cache.entry(addr)
                .or_insert_with(|| format!("// Decompiling @ {:08X}…", addr));
            return;
        }
        if self.decompile_cache.contains_key(&addr) {
            return;
        }

        let idx = self.selected_report
            .or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) });
        let data = match idx.and_then(|i| self.report_data.get(i)) {
            Some(d) => d.clone(),
            None => {
                self.decompile_cache.insert(addr, "// No file loaded".to_string());
                return;
            }
        };

        let start = addr as usize;
        if start >= data.len() {
            self.decompile_cache.insert(addr, "// Address out of bounds".to_string());
            return;
        }

        // Find function end
        let mut end = start;
        let max_size = 0x1000.min(data.len() - start);
        while end < start + max_size {
            if data[end] == 0xC3 || data[end] == 0xCB {
                end += 1;
                break;
            }
            end += 1;
        }

        let code = data[start..end].to_vec();
        let func_name = self.current_function_name_at(addr)
            .unwrap_or_else(|| format!("sub_{:X}", addr));

        if self.decompile_cache.len() > 256 {
            evict_cache_by_distance(&mut self.decompile_cache, addr, 128);
        }
        self.decompile_cache.insert(addr, format!("// Decompiling {} @ {:08X}…", func_name, addr));
        self.enqueue_job(JobKey::Decompile(addr), Job::Decompile {
            addr,
            code,
            func_name,
            is_64bit: self.disasm_is_64bit,
        });
    }

    // ─── UI-overhaul action helpers ──────────────────────────────
    //
    // Every menu entry / toolbar button / shortcut routes through these
    // so dialogs reset the focus latch exactly once when they OPEN.
    // (Calling request_focus() every frame steals keyboard focus from
    // other widgets for as long as the dialog is open, which made
    // buttons feel dead.)

    /// Switch central tab; lazily kicks off Full Source generation.
    pub fn goto_tab(&mut self, tab: Tab) {
        self.active_tab = tab;
        if tab == Tab::FullSource {
            self.start_full_source();
        }
    }

    pub fn open_goto(&mut self) {
        self.show_goto = true;
        self.goto_input.clear();
        self.dialog_focus_latch = false;
    }

    pub fn open_rename_at(&mut self, addr: u64) {
        self.show_rename = true;
        self.rename_target_addr = Some(addr);
        self.rename_input = self.custom_names.get(&addr)
            .cloned()
            .unwrap_or_else(|| self.current_function_name_at(addr).unwrap_or_default());
        self.dialog_focus_latch = false;
    }

    pub fn open_comment_at(&mut self, addr: u64) {
        self.show_comment_edit = true;
        self.comment_target_addr = Some(addr);
        self.comment_input = self.comments.get(&addr).cloned().unwrap_or_default();
        self.dialog_focus_latch = false;
    }

    /// Quick-action "Scan": re-scan the current file, or open the picker
    /// when nothing is loaded yet.
    pub fn rescan_current_file(&mut self) {
        if let Some(path) = self.current_file_path.clone() {
            let path2 = path.clone();
            self.scan_files(vec![path2]);
        } else if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.scan_files(vec![path]);
        }
    }

    /// Kick off incremental whole-file decompilation ("Full Source").
    /// No-ops when already running/finished for the current file.
    pub fn start_full_source(&mut self) {
        if self.full_source.running {
            return;
        }
        if !self.full_source.chunks.is_empty() && self.full_source.next >= self.full_source.funcs.len() {
            return; // already complete for this file
        }
        let Some(idx) = self.selected_report
            .or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) })
        else {
            return;
        };
        let funcs: Vec<(u64, String, u64)> = match self.reports.get(idx) {
            Some(report) => {
                let mut list: Vec<(u64, String, u64)> = report.functions.iter()
                    .filter(|f| f.size > 0)
                    .map(|f| (f.address, f.name.clone(), f.address + f.size as u64))
                    .collect();
                list.sort_by_key(|(a, _, _)| *a);
                list.dedup_by_key(|(a, _, _)| *a);
                list
            }
            None => Vec::new(),
        };

        const MAX_FULL_SOURCE_FUNCS: usize = 4096;
        let truncated_note = if funcs.len() > MAX_FULL_SOURCE_FUNCS {
            Some(format!(
                "// File contains {} functions — processing first {}.",
                funcs.len(), MAX_FULL_SOURCE_FUNCS
            ))
        } else {
            None
        };

        self.full_source = FullSourceState {
            funcs: funcs.into_iter().take(MAX_FULL_SOURCE_FUNCS).collect(),
            next: 0,
            done: 0,
            failed: 0,
            running: true,
            started_at: Some(Instant::now()),
            chunks: Vec::new(),
            truncated_note,
        };
        self.log(format!("Full Source: decompiling {} functions…", self.full_source.funcs.len()));
    }

    /// Per-frame incremental worker for "Full Source": decompiles a small,
    /// time-budgeted batch of functions so the UI never freezes.
    pub fn pump_full_source(&mut self, ctx: &egui::Context) {
        if !self.full_source.running {
            return;
        }
        let idx = match self.selected_report
            .or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) })
        {
            Some(i) => i,
            None => {
                self.full_source.running = false;
                return;
            }
        };
        let Some(data) = self.report_data.get(idx).cloned() else {
            self.full_source.running = false;
            return;
        };
        let is_64bit = self.disasm_is_64bit;

        let deadline = Instant::now() + std::time::Duration::from_millis(8);
        let mut processed = 0usize;
        while self.full_source.next < self.full_source.funcs.len()
            && processed < 8
            && Instant::now() < deadline
        {
            let (start, name, end) = &self.full_source.funcs[self.full_source.next];
            let text = decompile_range_sync(*start, name.as_str(), *end, &data, is_64bit);
            if text.starts_with("// [FAILED]") {
                self.full_source.failed += 1;
            } else {
                self.full_source.done += 1;
            }
            self.full_source.chunks.push((name.clone(), text));
            self.full_source.next += 1;
            processed += 1;
        }

        if self.full_source.next >= self.full_source.funcs.len() {
            self.full_source.running = false;
            let total = self.full_source.done + self.full_source.failed;
            self.log(format!(
                "Full Source finished: {} ok, {} failed, {} total",
                self.full_source.done, self.full_source.failed, total
            ));
            self.toasts.add("Full Source ready", ToastKind::Success);
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        }
    }
}

/// Evict entries from a u64-keyed cache down to `target_len`, removing
/// entries whose keys are furthest from `reference_addr` first.
/// This keeps recently-viewed / nearby functions cached while discarding
/// distant ones, avoiding the pathological full-clear behaviour that
/// caused re-decompilation storms on large binaries.
fn evict_cache_by_distance<V>(cache: &mut HashMap<u64, V>, reference_addr: u64, target_len: usize) {
    if cache.len() <= target_len {
        return;
    }
    let mut entries: Vec<(u64, u64)> = cache
        .keys()
        .map(|&k| (k, k.abs_diff(reference_addr)))
        .collect();
    // Sort by distance descending so we remove the FURTHEST entries first.
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    let to_remove = cache.len() - target_len;
    for (key, _) in entries.into_iter().take(to_remove) {
        cache.remove(&key);
    }
}

/// Find the end offset of the function starting at `start` (file offset):
/// scan forward to the first near RET (0xC3/0xCB), capped at `max` bytes.
fn code_bounds(data: &[u8], start: usize, max: usize) -> usize {
    if start >= data.len() {
        return start;
    }
    let mut end = start;
    let limit = start.saturating_add(max).min(data.len());
    while end < limit {
        if data[end] == 0xC3 || data[end] == 0xCB {
            return end + 1;
        }
        end += 1;
    }
    end
}

/// Decompile `[start, end)` synchronously on the calling thread.
/// Used by the background job runner AND by the incremental Full Source
/// pump. Failures become placeholder comment blocks, never panics.
fn decompile_range_sync(
    start: u64,
    name: &str,
    end_hint: u64,
    data: &[u8],
    is_64bit: bool,
) -> String {
    let start_us = start as usize;
    if start_us >= data.len() {
        return format!("// [FAILED] {} @ {:08X}: address out of bounds\n", name, start);
    }
    let hinted = (end_hint.max(start + 16) as usize).min(data.len());
    let end = code_bounds(data, start_us, hinted.saturating_sub(start_us).clamp(16, 0x2000));
    let code = &data[start_us..end];

    let lifter = X86Lifter::new(is_64bit);
    match lifter.lift_function(code, start, name) {
        Ok(ir_func) => match decompile_function(&ir_func) {
            Ok(c_code) => {
                let mut out = format!(
                    "// Decompiled by FreakRE @ {:08X} — {} IR instructions, {} blocks\n",
                    start, ir_func.total_instructions(), ir_func.blocks.len()
                );
                out.push_str(&c_code);
                out
            }
            Err(e) => format!(
                "// [FAILED] {} @ {:08X}: decompiler error: {}\n// Falling back to raw pseudocode is disabled in Full Source mode.\n",
                name, start, e
            ),
        },
        Err(e) => format!(
            "// [FAILED] {} @ {:08X}: lifting failed ({})\n",
            name, start, e
        ),
    }
}

/// Fallback pseudocode generation when IR pipeline fails
fn fallback_pseudocode(addr: u64, data: &[u8], func_name: &str, is_64bit: bool) -> String {
    let end = 0x200.min(data.len());
    let code_region = &data[..end];

    let mut pseudocode = String::new();
    pseudocode.push_str(&format!("// Decompiled by FreakRE @ {:08X} (fallback mode)\n\n", addr));
    pseudocode.push_str(&format!("void {}() {{\n", func_name));

    let mut offset = 0usize;
    let mut inst_count = 0;
    let mut has_ret = false;
    while offset < code_region.len() && inst_count < 100 {
        match freakre_x86::decode(&code_region[offset..], is_64bit) {
            Ok(inst) => {
                let mnemonic = inst.mnemonic.as_str();
                let operands = freakre_x86::format_instruction(&inst);

                match mnemonic {
                    "push" => pseudocode.push_str(&format!("    // save {}\n", operands)),
                    "pop" => pseudocode.push_str(&format!("    // restore {}\n", operands)),
                    "mov" => {
                        let parts: Vec<&str> = operands.splitn(2, ',').collect();
                        if parts.len() == 2 {
                            pseudocode.push_str(&format!("    {} = {};\n",
                                parts[0].trim(), parts[1].trim()));
                        } else {
                            pseudocode.push_str(&format!("    mov({});\n", operands));
                        }
                    }
                    "call" => pseudocode.push_str(&format!("    {}({});\n", operands, "")),
                    "ret" | "retn" => {
                        pseudocode.push_str("    return;\n");
                        has_ret = true;
                        break;
                    }
                    "nop" => {}
                    "test" | "cmp" => pseudocode.push_str(&format!("    // {} {}\n", mnemonic, operands)),
                    "je" | "jz" => pseudocode.push_str(&format!("    if (zero) goto {};\n", operands)),
                    "jne" | "jnz" => pseudocode.push_str(&format!("    if (!zero) goto {};\n", operands)),
                    "jmp" => pseudocode.push_str(&format!("    goto {};\n", operands)),
                    "xor" => {
                        let parts: Vec<&str> = operands.splitn(2, ',').collect();
                        if parts.len() == 2 && parts[0].trim() == parts[1].trim() {
                            pseudocode.push_str(&format!("    {} = 0;\n", parts[0].trim()));
                        } else {
                            pseudocode.push_str(&format!("    {} ^= {};\n",
                                parts[0].trim(),
                                parts.get(1).map(|s| s.trim()).unwrap_or("?")));
                        }
                    }
                    "add" => {
                        let parts: Vec<&str> = operands.splitn(2, ',').collect();
                        if parts.len() == 2 {
                            pseudocode.push_str(&format!("    {} += {};\n",
                                parts[0].trim(), parts[1].trim()));
                        }
                    }
                    "sub" => {
                        let parts: Vec<&str> = operands.splitn(2, ',').collect();
                        if parts.len() == 2 {
                            pseudocode.push_str(&format!("    {} -= {};\n",
                                parts[0].trim(), parts[1].trim()));
                        }
                    }
                    _ => pseudocode.push_str(&format!("    // {} {}\n", mnemonic, operands)),
                }
                offset += inst.length;
                inst_count += 1;
            }
            Err(_) => { offset += 1; }
        }
    }

    if !has_ret {
        pseudocode.push_str("    // ... (truncated)\n");
    }
    pseudocode.push_str("}\n");

    pseudocode
}

fn run_job(job: Job) -> JobResult {
    match job {
        Job::XrefBuild { data, import_names } => {
            let mut db = XrefDatabase::new();
            if !import_names.is_empty() {
                db.add_all(build_import_xrefs(&data, &import_names));
            }
            JobResult::XrefBuild(db)
        }
        Job::FuncSigs { data } => {
            let config = SigScanConfig::default();
            JobResult::FuncSigs(Box::new(scan_signatures(&data, 0, &config)))
        }
        Job::MlClassify { data } => {
            let info = BinaryInfo::default();
            let features = extract_features(&data, &info);
            let classifier = EnsembleClassifier::new();
            JobResult::MlClassify(classifier.classify(&features))
        }
        Job::Decompile { addr, code, func_name, is_64bit } => {
            let lifter = X86Lifter::new(is_64bit);
            match lifter.lift_function(&code, addr, &func_name) {
                Ok(ir_func) => {
                    let df = DataFlowAnalysis::analyze(&ir_func);
                    match decompile_function(&ir_func) {
                        Ok(c_code) => {
                            let mut output = format!("// Decompiled by FreakRE @ {:08X}\n", addr);
                            output.push_str(&format!("// IR instructions: {}\n", ir_func.total_instructions()));
                            output.push_str(&format!("// Blocks: {}\n\n", ir_func.blocks.len()));
                            output.push_str(&c_code);
                            let note = format!("Decompiled {} ({} IR insts)", func_name, ir_func.total_instructions());
                            JobResult::Decompile { addr, text: output, dataflow: Some(df), note: Some(note) }
                        }
                        Err(e) => {
                            let note = format!("Decompile failed: {}, falling back to pseudocode", e);
                            let text = fallback_pseudocode(addr, &code, &func_name, is_64bit);
                            JobResult::Decompile { addr, text, dataflow: Some(df), note: Some(note) }
                        }
                    }
                }
                Err(e) => {
                    let note = format!("Lift failed: {}, falling back", e);
                    let text = fallback_pseudocode(addr, &code, &func_name, is_64bit);
                    JobResult::Decompile { addr, text, dataflow: None, note: Some(note) }
                }
            }
        }
        Job::BuildCfg { addr, code, base_va, is_64bit } => {
            let config = CfgConfig {
                is_64bit,
                base_va,
                max_instructions: 10_000,
                ..CfgConfig::default()
            };
            let cfg = build_cfg(&code, addr as usize, &config);
            JobResult::BuildCfg { addr, cfg }
        }
        Job::XrefViewScan { report_idx, target, data_len, data, is_64bit } => {
            let key = (report_idx, target, data_len);
            let mut hits: Vec<(u64, String)> = Vec::new();

            // A 64-bit address cannot be encoded in one imm32; match either
            // LE u32 half so >32-bit targets still find their references.
            let lo = (target & 0xFFFF_FFFF) as u32;
            let hi = (target >> 32) as u32;

            let mut scan_offset = 0usize;
            while scan_offset + 4 <= data.len() && hits.len() < 200 {
                let candidate = u32::from_le_bytes([
                    data[scan_offset], data[scan_offset+1],
                    data[scan_offset+2], data[scan_offset+3],
                ]);
                if (candidate == lo || (hi != 0 && candidate == hi)) && scan_offset > 0 {
                    let inst_start = scan_offset.saturating_sub(8);
                    if let Ok(inst) = freakre_x86::decode(&data[inst_start..], is_64bit) {
                        let operands = freakre_x86::format_instruction(&inst);
                        hits.push((inst_start as u64, format!("{} {}", inst.mnemonic.as_str(), operands)));
                    }
                }
                scan_offset += 1;
            }

            JobResult::XrefViewScan { key, hits }
        }
    }
}

impl FreakREApp {
    /// Get function name at address (custom name > symbol DB > report function name > generated)
    fn current_function_name_at(&self, addr: u64) -> Option<String> {
        if let Some(name) = self.custom_names.get(&addr) {
            return Some(name.clone());
        }
        // Try debug symbols (PDB/DWARF) before falling back to scanner heuristics.
        if let Some(ref db) = self.symbol_db {
            if let Some(sym) = db.find_by_address(addr) {
                if !sym.name.is_empty() {
                    return Some(sym.name.clone());
                }
            }
        }
        let idx = self.selected_report
            .or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) })?;
        let report = self.reports.get(idx)?;
        report.functions.iter()
            .find(|f| addr >= f.address && addr < f.address + f.size as u64)
            .map(|f| f.name.clone())
    }

    /// Attempt to load debug symbols for the currently loaded binary.
    /// Tries PDB file alongside the binary first, then DWARF from ELF bytes.
    fn try_load_symbols(&mut self) {
        let path = match self.current_file_path.as_ref() {
            Some(p) => p.clone(),
            None => return,
        };

        // 1. Try PDB alongside the binary (same directory, .pdb extension)
        let pdb_path = path.with_extension("pdb");
        if pdb_path.exists() {
            match SymbolDb::load_pdb(&pdb_path) {
                Ok(db) => {
                    let count = db.functions().len();
                    self.symbol_db = Some(db);
                    self.log(format!("Loaded {} symbols from {:?}", count, pdb_path));
                    self.toasts.add(
                        format!("Symbols: {} functions from PDB", count),
                        ToastKind::Success,
                    );
                    return;
                }
                Err(e) => {
                    self.log(format!("PDB load failed: {}", e));
                }
            }
        }

        // 2. Try DWARF from ELF binary bytes
        let idx = self.selected_report
            .or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) });
        if let Some(i) = idx {
            if let Some(data) = self.report_data.get(i) {
                if !data.is_empty() {
                    match SymbolDb::load_dwarf_elf(data) {
                        Ok(db) => {
                            let count = db.functions().len();
                            self.symbol_db = Some(db);
                            self.log(format!("Loaded {} symbols from DWARF debug info", count));
                            self.toasts.add(
                                format!("Symbols: {} functions from DWARF", count),
                                ToastKind::Success,
                            );
                            return;
                        }
                        Err(freakre_symbols::SymbolError::NoDebugInfo) => {
                            // Not an error — just no debug info in this binary.
                        }
                        Err(e) => {
                            self.log(format!("DWARF load failed: {}", e));
                        }
                    }
                }
            }
        }
    }

    /// Execute script in REPL
    pub fn execute_repl_script(&mut self) {
        let source = self.repl.input.clone();
        if source.trim().is_empty() {
            return;
        }

        self.repl.history.push(source.clone());
        self.repl.history_pos = self.repl.history.len();

        let config = freakre_script::SandboxConfig::default();
        let caps = freakre_script::Capabilities::default();

        let result = freakre_script::run(&source, &config, &caps);
        let output = match result {
            Ok(val) => format!("=> {}", val),
            Err(e) => format!("ERROR: {}", e),
        };

        self.repl.output.push((source, output));
        self.repl.input.clear();
    }
}

// ═══════════════════════════════════════════════════════════════════
// IDA Pro Layout:
//   ┌─────────────────────────────────────────────────┐
//   │ Menu Bar                                        │
//   ├──────────┬──────────────────────────────────────┤
//   │Functions │  Central Tabs                        │
//   │ Panel    │  ┌────┬────┬────┬────┬────┐         │
//   │          │  │DA  │Hex │Grph│Str │Imp │         │
//   │          │  ├────┴────┴────┴────┴────┤         │
//   │          │  │                        │         │
//   │          │  │  Active View Content   │         │
//   │          │  │                        │         │
//   │          │  ├────────────────────────┤         │
//   │          │  │ Output Window          │         │
//   ├──────────┴──────────────────────────────────────┤
//   │ Status Bar                                      │
//   в””в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”
// ═══════════════════════════════════════════════════════════════════

// ─── Tab categories & accents ─────────────────────────────────────────

fn tab_category(tab: &Tab) -> &'static str {
    match tab {
        Tab::Disassembly | Tab::Decompiler | Tab::GraphView | Tab::FullSource => "analysis",
        Tab::HexView | Tab::Strings | Tab::Imports | Tab::Xrefs | Tab::Structures => "data",
        Tab::Report | Tab::Findings | Tab::Entropy | Tab::MlClassify
        | Tab::FuncSigs | Tab::Diffing | Tab::DataFlow => "report",
        Tab::Scripting | Tab::Plugins | Tab::Settings => "tools",
    }
}

fn tab_accent(category: &str) -> egui::Color32 {
    match category {
        "analysis" => egui::Color32::from_rgb(0x56, 0x9C, 0xD6), // blue
        "data"     => egui::Color32::from_rgb(0x4E, 0xC1, 0x74), // green
        "report"   => egui::Color32::from_rgb(0xE2, 0xA4, 0x3C), // amber
        _          => egui::Color32::from_rgb(0x8A, 0x8A, 0x8A),
    }
}

/// Central IDA-style tab bar.
///
/// CLICK FIX: egui's `Frame::show` returns a response that only senses
/// HOVER (`Frame::allocate_space` uses `Sense::hover()`), because its inner
/// widgets here are plain labels which never sense clicks. Calling
/// `.clicked()` on such a response ALWAYS returns false — the old code made
/// every central tab (including "View"-adjacent ones) unclickable, forcing
/// users through the menu repeatedly. `Response::interact(Sense::CLICK)`
/// re-registers the exact same rect as click-sensitive, so one click on any
/// part of the tab activates it.
fn render_central_tab_strip(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let mut prev_category = "";
        for tab in Tab::main_tabs() {
            let is_active = app.active_tab == *tab;
            let bg = if is_active { c.bg_tab_active } else { c.bg_tab_inactive };
            let fg = if is_active { c.text_white } else { c.text_secondary };
            let cat = tab_category(tab);

            // Thin separator between tab categories
            if !prev_category.is_empty() && prev_category != cat {
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(2.0);
            }
            prev_category = cat;

            let frame = egui::Frame::new()
                .fill(bg)
                .stroke(egui::Stroke::new(1.0_f32, c.border))
                .inner_margin(egui::Margin::symmetric(10, 4));

            let resp = frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(1.0);
                    ui.label(egui::RichText::new("●").size(8.0).color(tab_accent(cat)));
                    ui.label(egui::RichText::new(tab.label()).size(11.0).color(fg));
                });
            }).response.interact(egui::Sense::CLICK);

            // Accent underline under the active tab
            if is_active {
                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        resp.rect.left_bottom() + egui::vec2(1.0, -2.0),
                        egui::vec2(resp.rect.width() - 2.0, 2.0),
                    ),
                    0.0,
                    tab_accent(cat),
                );
            }

            if resp.clicked() {
                app.goto_tab(*tab);
            } else if resp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
        }
    });
}

/// Verdict chip color for the status bar.
fn verdict_color(score: f64) -> egui::Color32 {
    if score < 0.15 {
        egui::Color32::from_rgb(0x4E, 0xC1, 0x74)
    } else if score < 0.35 {
        egui::Color32::from_rgb(0xE2, 0xA4, 0x3C)
    } else {
        egui::Color32::from_rgb(0xE5, 0x5B, 0x5B)
    }
}

/// True when the current report carries at least one finding produced by
/// the scanner's backdoor analyzer.
fn current_report_has_backdoor_findings(app: &FreakREApp) -> bool {
    let idx = app.selected_report
        .or_else(|| if app.reports.is_empty() { None } else { Some(app.reports.len() - 1) });
    match idx.and_then(|i| app.reports.get(i)) {
        Some(report) => report.findings.iter().any(|f| f.module == "backdoor-analyzer"),
        None => false,
    }
}

impl FreakREApp {
    /// Centered welcome screen shown when no file is loaded.
    fn welcome_ui(&mut self, ui: &mut egui::Ui) {
        let c = self.colors.clone();
        ui.vertical_centered_justified(|ui| {
            ui.add_space(ui.available_height() * 0.16);
            ui.label(
                egui::RichText::new("FreakRE")
                    .size(42.0)
                    .strong()
                    .color(c.text_white),
            );
            ui.label(
                egui::RichText::new("reverse engineering framework")
                    .size(13.0)
                    .color(c.text_secondary),
            );
            ui.add_space(28.0);

            // Drop zone frame
            let (rect, resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width().min(520.0), 120.0),
                egui::Sense::hover(),
            );
            let hovered = self.drag_hovered;
            ui.painter().rect_stroke(
                rect,
                6.0,
                egui::Stroke::new(if hovered { 2.0_f32 } else { 1.0_f32 },
                    if hovered { c.func_color } else { c.border }),
                egui::StrokeKind::Inside,
            );
            ui.painter().text(
                rect.center() - egui::vec2(0.0, 12.0),
                egui::Align2::CENTER_CENTER,
                "⬇",
                egui::FontId::proportional(26.0),
                c.text_secondary,
            );
            ui.painter().text(
                rect.center() + egui::vec2(0.0, 14.0),
                egui::Align2::CENTER_CENTER,
                "drag & drop a binary here",
                egui::FontId::proportional(13.0),
                c.text_secondary,
            );
            let _ = resp;

            ui.add_space(18.0);
            let open = egui::Button::new(
                egui::RichText::new("Open File…").size(15.0),
            ).min_size(egui::vec2(160.0, 34.0));
            if ui.add(open).clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.scan_files(vec![path]);
                }
            }

            ui.add_space(30.0);
            ui.separator();
            ui.add_space(10.0);
            ui.label(egui::RichText::new("shortcuts").color(c.text_secondary).size(11.0));
            egui::Grid::new("shortcut_help")
                .num_columns(2)
                .spacing([24.0, 3.0])
                .min_col_width(0.0)
                .show(ui, |ui| {
                    for (k, d) in [
                        ("F5", "decompile function"),
                        ("Space", "graph ⇄ disassembly"),
                        ("G", "go to address"),
                        ("N / ;", "rename / comment"),
                        ("X", "cross-references"),
                        ("Ctrl+F", "search"),
                        ("Alt+← →", "navigation history"),
                    ] {
                        ui.label(egui::RichText::new(k).monospace()
                            .color(c.func_color).size(11.0));
                        ui.label(egui::RichText::new(d).color(c.text_primary).size(11.0));
                        ui.end_row();
                    }
                });
        });
    }
}

fn verdict_label(score: f64) -> &'static str {
    if score < 0.15 { "CLEAN" } else if score < 0.35 { "SUSPICIOUS" } else { "MALICIOUS" }
}

impl eframe::App for FreakREApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Guard: if the OS theme flips to light mid-session, re-assert dark.
        if ctx.theme() != egui::Theme::Dark {
            ctx.set_theme(egui::Theme::Dark);
            theme::apply_theme(ctx, &self.colors);
        }

        self.poll_scan_results();
        self.drain_job_results(ctx);
        self.drain_db_status();
        self.handle_keyboard_shortcuts(ctx);
        self.handle_drag_and_drop(ctx);

        let c = self.colors.clone();

        // ─── Menu Bar ───────────────────────────────────────────────
        egui::TopBottomPanel::top("menu_bar")
            .exact_height(24.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    egui::menu::bar(ui, |ui| {
                        ui.menu_button("File", |ui| {
                            if ui.button("Open…").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.scan_files(vec![path]);
                                }
                                ui.close_menu();
                            }
                            if ui.button("Load YARA Rules…").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("YARA", &["yar", "yara"])
                                    .pick_file()
                                {
                                    self.load_yara_rules(path);
                                }
                                ui.close_menu();
                            }
                            if ui.button("Open for Diffing…").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.diffing_other_path = Some(path);
                                }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Recent Files").clicked() {
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Exit").clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("Edit", |ui| {
                            if ui.button("Search (Ctrl+F)").clicked() {
                                self.show_search = !self.show_search;
                                ui.close_menu();
                            }
                            if ui.button("Go to Address (G)").clicked() {
                                self.open_goto();
                                ui.close_menu();
                            }
                            if ui.button("Rename (N)").clicked() {
                                self.open_rename_at(self.disasm_offset);
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Add Comment (;)").clicked() {
                                self.open_comment_at(self.disasm_offset);
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("Analysis", |ui| {
                            if ui.button("Build CFG (Space)").clicked() {
                                self.build_cfg_at(self.disasm_offset);
                                self.active_tab = Tab::GraphView;
                                ui.close_menu();
                            }
                            if ui.button("Decompile (F5)").clicked() {
                                self.decompile_at(self.disasm_offset);
                                self.active_tab = Tab::Decompiler;
                                ui.close_menu();
                            }
                            if ui.button("Scan Func Sigs").clicked() {
                                self.request_func_sigs();
                                self.active_tab = Tab::FuncSigs;
                                ui.close_menu();
                            }
                            if ui.button("ML Classify").clicked() {
                                self.request_ml_classify();
                                self.active_tab = Tab::MlClassify;
                                ui.close_menu();
                            }
                            if ui.button("Build Xrefs").clicked() {
                                self.request_xref_build();
                                ui.close_menu();
                            }
                            if ui.button("Run Binary Diff").clicked() {
                                self.active_tab = Tab::Diffing;
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("View", |ui| {
                            for mode in Mode::all() {
                                if ui.selectable_label(self.active_mode == *mode, format!("Mode: {}", mode.label())).clicked() {
                                    self.active_mode = *mode;
                                    ui.close_menu();
                                }
                            }
                            ui.separator();
                            for tab in Tab::main_tabs() {
                                if ui.selectable_label(self.active_tab == *tab, tab.label()).clicked() {
                                    self.goto_tab(*tab);
                                    ui.close_menu();
                                }
                            }
                            ui.separator();
                            ui.menu_button("Bookmarks", |ui| {
                                for i in 0..=9u8 {
                                    let label = if let Some(addr) = self.bookmarks[i as usize] {
                                        format!("{}: {:08X}", i, addr)
                                    } else {
                                        format!("{}: (empty)", i)
                                    };
                                    if ui.add_enabled(self.bookmarks[i as usize].is_some(), egui::Button::new(&label)).clicked() {
                                        if let Some(addr) = self.bookmarks[i as usize] {
                                            self.nav_push(self.disasm_offset);
                                            self.disasm_offset = addr;
                                            self.goto_tab(Tab::Disassembly);
                                        }
                                        ui.close_menu();
                                    }
                                }
                            });
                            ui.menu_button("Recent Files", |ui| {
                                if self.settings.recent_files.is_empty() {
                                    ui.label(egui::RichText::new("(none yet)").color(c.text_secondary).size(11.0));
                                }
                                let mut picked: Option<PathBuf> = None;
                                for path in &self.settings.recent_files {
                                    let name = std::path::Path::new(path)
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| path.clone());
                                    if ui.button(name).clicked() {
                                        picked = Some(PathBuf::from(path));
                                    }
                                }
                                if let Some(p) = picked {
                                    // Act AFTER the menu closes: opening a
                                    // modal file scan while the popup still
                                    // owns focus can swallow the click.
                                    ui.close_menu();
                                    self.scan_files(vec![p]);
                                }
                            });
                        });

                        ui.menu_button("Help", |ui| {
                            ui.label(egui::RichText::new("FreakRE v0.2").monospace().size(11.0));
                            ui.separator();
                            ui.label(egui::RichText::new("Modes: Standard / Multi / Malware Detector / Backdoor Analyzer").color(c.text_secondary).size(10.0));
                            if ui.button("About").clicked() {
                                self.toasts.add(
                                    "FreakRE v0.2 — reverse engineering framework",
                                    ToastKind::Info,
                                );
                                ui.close_menu();
                            }
                        });
                    });
                });
            });

        // ─── Mode Strip (top-level modes ABOVE all other views) ─────
        egui::TopBottomPanel::top("mode_strip")
            .exact_height(26.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("MODE").size(9.0).color(c.text_secondary).monospace().strong());
                    for mode in Mode::all() {
                        let active = self.active_mode == *mode;
                        let text = egui::RichText::new(mode.label()).size(11.5);
                        let resp = ui.add(
                            egui::Button::new(if active { text.strong().color(c.text_white) } else { text.color(c.text_secondary) })
                                .selected(active)
                                .fill(if active { c.bg_selection } else { egui::Color32::TRANSPARENT })
                                .min_size(egui::vec2(0.0, 20.0)),
                        );
                        if resp.clicked() {
                            self.active_mode = *mode;
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let hint = match self.active_mode {
                            Mode::Standard => "classic IDA-style workspace",
                            Mode::Multi => "pseudocode ⇄ assembly, synchronized cursor",
                            Mode::MalwareDetector => "scanner & ML verdict dashboard",
                            Mode::BackdoorAnalyzer => "backdoor findings by profile",
                        };
                        ui.label(egui::RichText::new(hint).size(10.0).color(c.text_secondary).monospace());
                    });
                });
            });

        // ─── Toolbar (quick actions, always visible) ─────────────────
        egui::TopBottomPanel::top("toolbar")
            .exact_height(30.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add_space(6.0);

                    // Persistent quick actions (single-click guaranteed:
                    // plain egui buttons own their full hit area).
                    let scan_btn = if !self.is_scanning {
                        egui::Button::new(egui::RichText::new("▶ Scan"))
                    } else {
                        egui::Button::new(egui::RichText::new("… Scanning")).fill(c.bg_hover)
                    };
                    if ui.add_enabled(!self.is_scanning, scan_btn)
                        .on_disabled_hover_text("Scan already in progress")
                        .clicked()
                    {
                        self.rescan_current_file();
                    }
                    if ui.button("⚡ Decompile  F5").clicked() {
                        self.goto_tab(Tab::Decompiler);
                        self.decompile_at(self.disasm_offset);
                    }
                    if ui.button(" CFG  Space").clicked() {
                        self.build_cfg_at(self.disasm_offset);
                        self.goto_tab(Tab::GraphView);
                    }
                    if ui.button(" Xrefs  X").clicked() {
                        self.xref_query_addr = self.disasm_offset;
                        self.goto_tab(Tab::Xrefs);
                    }
                    if ui.button(" Strings").clicked() {
                        self.goto_tab(Tab::Strings);
                    }
                    if ui.button(" Backdoor Scan").clicked() {
                        // Findings are produced by the scanner's backdoor
                        // analyzer; surface them on the dedicated mode.
                        self.active_mode = Mode::BackdoorAnalyzer;
                        let has_bd = current_report_has_backdoor_findings(self);
                        self.log(if has_bd {
                            "Backdoor scan: findings available (Backdoor Analyzer)".to_string()
                        } else {
                            "Backdoor scan: no backdoor indicators found".to_string()
                        });
                    }
                    if ui.button(" Full Source").clicked() {
                        self.active_mode = Mode::Standard;
                        self.goto_tab(Tab::FullSource);
                    }

                    ui.separator();

                    // Navigation aids
                    let can_back = self.nav_history_pos > 0;
                    let can_fwd = self.nav_history_pos + 1 < self.nav_history.len();
                    let back = ui.add_enabled(can_back, egui::Button::new("◀"));
                    if back.clicked() { self.nav_back(); }
                    let fwd = ui.add_enabled(can_fwd, egui::Button::new("▶"));
                    if fwd.clicked() { self.nav_forward(); }
                    back.on_disabled_hover_text("No navigation history (Alt+←)");
                    fwd.on_disabled_hover_text("Nothing forward (Alt+→)");
                    if ui.button("Goto (G)").clicked() {
                        self.open_goto();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.is_scanning {
                            ui.add(egui::Spinner::new().size(16.0));
                            if self.scan_total > 0 {
                                ui.label(
                                    egui::RichText::new(format!("{}/{}", self.scan_done, self.scan_total))
                                        .monospace().size(11.0).color(c.text_secondary),
                                );
                            } else {
                                ui.label(egui::RichText::new("scanning…")
                                    .monospace().size(11.0).color(c.text_secondary));
                            }
                        }
                        if ui.button("🔍").on_hover_text("Search (Ctrl+F)").clicked() {
                            self.show_search = !self.show_search;
                        }
                    });
                });
            });

        // ─── Functions Panel (left, always visible like IDA) ────────
        egui::SidePanel::left("functions_panel")
            .default_width(self.settings.functions_panel_width)
            .resizable(true)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    // Panel header with function count
                    let func_count = self.reports.get(self.selected_report.unwrap_or(usize::MAX))
                        .map(|r| r.functions.len())
                        .unwrap_or(0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Functions")
                            .color(c.text_secondary).size(11.0).strong());
                        if func_count > 0 {
                            ui.label(egui::RichText::new(format!("({})", func_count))
                                .color(c.func_color).size(11.0).monospace());
                        }
                    });
                    ui.separator();

                    // Filter
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            egui::vec2(ui.available_width(), 20.0),
                            egui::TextEdit::singleline(&mut self.functions_filter)
                                .hint_text("Filter…")
                                .font(egui::FontId::monospace(11.0)),
                        );
                    });
                    ui.separator();

                    // Function list.
                    // NOTE: no per-frame allocations here — iterating
                    // self.reports directly. Click/auto-scroll actions are
                    // collected into locals and applied AFTER the loop, so
                    // the immutable `report` borrow never overlaps a &mut
                    // self call (nav_push/decompile_at). The previous
                    // clone-the-whole-list-every-frame version ballooned RSS.
                    let mut clicked: Option<(u8, u64)> = None; // (0=nav, 1=decompile)
                    let mut scrolled_to: Option<u64> = None;
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        let report = if let Some(i) = self.selected_report {
                            self.reports.get(i)
                        } else if self.reports.is_empty() {
                            None
                        } else {
                            let n = self.reports.len();
                            self.reports.get(n - 1)
                        };
                        let Some(report) = report else {
                            ui.label(egui::RichText::new("No file loaded")
                                .color(c.text_secondary).size(11.0));
                            return;
                        };

                        let filter_lower = self.functions_filter.to_lowercase();
                        let cursor = self.disasm_offset;
                        let last_scrolled = self.last_cursor_func;
                        for func in &report.functions {
                            let name = &func.name;
                            if !filter_lower.is_empty()
                                && !name.to_lowercase().contains(&filter_lower)
                            {
                                continue;
                            }
                            // Highlight the function containing the cursor
                            let contains_cursor =
                                cursor >= func.address
                                && cursor < func.address + func.size as u64;
                            let row = ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(format!("{:08X}", func.address))
                                    .monospace().size(self.settings.font_size_code - 1.0)
                                    .color(if contains_cursor { c.text_white } else { c.text_secondary }));
                                ui.label(egui::RichText::new(name)
                                    .monospace().size(self.settings.font_size_code)
                                    .color(if contains_cursor { c.text_white } else { c.func_color })
                                    .strong());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(egui::RichText::new(format!("{}h", func.size))
                                            .monospace()
                                            .size(self.settings.font_size_code - 2.0)
                                            .color(c.comment_color));
                                    },
                                );
                            });
                            let resp = row.response.interact(egui::Sense::click());
                            // Auto-scroll only when the cursor function CHANGES,
                            // not on every frame (a per-frame scroll_to_me kept
                            // egui repainting + relayouting forever).
                            if contains_cursor && last_scrolled != Some(func.address) {
                                resp.scroll_to_me(Some(egui::Align::Center));
                                scrolled_to = Some(func.address);
                            }
                            if resp.clicked() {
                                clicked = Some((0, func.address));
                            }
                            if resp.double_clicked() {
                                clicked = Some((1, func.address));
                            }
                            if self.settings.show_tooltips {
                                resp.on_hover_text(format!(
                                    "Size: {} bytes\nType: {:?}\n\nClick: navigate\nDouble-click: decompile",
                                    func.size, func.func_type
                                ));
                            }
                        }
                    });
                    if let Some(addr) = scrolled_to {
                        self.last_cursor_func = Some(addr);
                    }
                    match clicked {
                        Some((0, addr)) => {
                            self.nav_push(self.disasm_offset);
                            self.disasm_offset = addr;
                            self.active_tab = Tab::Disassembly;
                        }
                        Some((1, addr)) => {
                            self.nav_push(self.disasm_offset);
                            self.disasm_offset = addr;
                            self.decompile_at(addr);
                            self.active_tab = Tab::Decompiler;
                        }
                        Some((_, _)) => {}
                        None => {}
                    }
                });
            });

        // ─── Output Panel (bottom, resizable like IDA) ──────────────
        egui::TopBottomPanel::bottom("output_panel")
            .resizable(true)
            .default_height(self.settings.output_panel_height)
            .min_height(60.0)
            .max_height(400.0)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Output window")
                            .color(c.text_secondary).size(11.0).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Clear").clicked() {
                                self.output_lines.clear();
                            }
                        });
                    });
                    ui.separator();

                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.output_lines {
                                ui.label(egui::RichText::new(line)
                                    .monospace()
                                    .size(11.0)
                                    .color(c.text_primary));
                            }
                        });
                });
            });

        // ─── Status Bar (very bottom, IDA blue) ─────────────────────
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(22.0)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(c.bg_statusbar)
                    .inner_margin(egui::Margin::symmetric(8, 2))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // File info
                            if let Some(idx) = self.selected_report.or_else(|| {
                                if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) }
                            }) {
                                if let Some(report) = self.reports.get(idx) {
                                    let fname = report.path.file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "unknown".into());
                                    ui.label(egui::RichText::new(&fname).color(egui::Color32::WHITE).size(11.0).monospace());
                                    ui.label(egui::RichText::new("|").color(egui::Color32::from_gray(180)).size(11.0));
                                    ui.label(egui::RichText::new(&report.file_type).color(egui::Color32::WHITE).size(11.0).monospace());
                                    ui.label(egui::RichText::new("|").color(egui::Color32::from_gray(180)).size(11.0));
                                    // Verdict chip
                                    let score = report.suspicion_score;
                                    let vc = verdict_color(score);
                                    let chip = egui::Frame::new()
                                        .fill(vc.gamma_multiply(0.25))
                                        .stroke(egui::Stroke::new(1.0_f32, vc))
                                        .inner_margin(egui::Margin::symmetric(6, 1));
                                    chip.show(ui, |ui| {
                                        ui.label(egui::RichText::new(format!(
                                            "{} {:.0}%",
                                            verdict_label(score),
                                            score * 100.0
                                        )).color(vc).size(10.5).monospace().strong());
                                    });
                                }
                            } else {
                                ui.label(egui::RichText::new("No file loaded").color(egui::Color32::from_gray(200)).size(11.0).monospace());
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if self.is_scanning {
                                    let scanning_label = |ui: &mut egui::Ui, text: String| {
                                        ui.label(egui::RichText::new(text).color(egui::Color32::YELLOW).size(11.0).monospace());
                                    };
                                    if self.scan_total > 1 {
                                        let frac = if self.scan_total == 0 {
                                            0.0_f32
                                        } else {
                                            self.scan_done as f32 / self.scan_total as f32
                                        };
                                        scanning_label(ui, format!("{}/{} files", self.scan_done.min(self.scan_total), self.scan_total));
                                        let bar = egui::ProgressBar::new(frac)
                                            .desired_width(160.0)
                                            .show_percentage();
                                        ui.add(bar);
                                    } else {
                                        ui.add(egui::Spinner::new().size(14.0));
                                        let name = self.current_file_path.as_ref()
                                            .and_then(|p| p.file_name())
                                            .map(|n| n.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "file".into());
                                        scanning_label(ui, format!("Scanning {}...", name));
                                    }
                                } else {
                                    ui.label(egui::RichText::new(
                                        if self.disasm_is_64bit { "x86_64" } else { "x86" }
                                    ).color(egui::Color32::WHITE).size(11.0).monospace());
                                }
                            });
                        });
                    });
            });

        // ─── Search Bar (conditional, below menu) ───────────────────
        if self.show_search {
            egui::TopBottomPanel::top("search_panel")
                .exact_height(28.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Search:").color(c.text_secondary).size(11.0).monospace());
                        let resp = ui.add_sized(
                            egui::vec2(ui.available_width() - 60.0, 20.0),
                            egui::TextEdit::singleline(&mut self.global_search)
                                .hint_text("Enter search term…")
                                .font(egui::FontId::monospace(11.0)),
                        );
                        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            let term = self.global_search.clone();
                            if !term.is_empty() {
                                let data_idx = self.selected_report.or_else(|| {
                                    self.reports.is_empty().then_some(usize::MAX)
                                });
                                let data = data_idx.and_then(|i| self.report_data.get(i)).cloned();
                                if let Some(data) = data {
                                    let needle = term.as_bytes();
                                    match data.windows(needle.len())
                                        .position(|w| w == needle)
                                    {
                                        Some(off) => {
                                            self.hex_offset = off;
                                            self.active_tab = Tab::HexView;
                                            self.log(format!(
                                                "Found \"{}\" at file offset 0x{:X}",
                                                term, off
                                            ));
                                            self.toasts.add(
                                                format!("Found at 0x{:X}", off),
                                                ToastKind::Success,
                                            );
                                        }
                                        None => {
                                            self.log(format!("Not found: {}", term));
                                            self.toasts.add("Not found", ToastKind::Warning);
                                        }
                                    }
                                }
                            }
                        }
                        if ui.small_button("X").clicked() {
                            self.show_search = false;
                        }
                    });
                });
        }

        // ─── Central Panel ──────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            let has_file = !self.reports.is_empty() || self.is_scanning;

            if !has_file {
                self.welcome_ui(ui);
                return;
            }

            let mode = self.active_mode;
            if mode == Mode::Standard {
                // Scan progress bar (thin strip above tabs)
                if self.is_scanning && self.scan_total > 0 {
                    let frac = self.scan_done as f32 / self.scan_total.max(1) as f32;
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_height(3.0)
                            .show_percentage(),
                    );
                }

                render_central_tab_strip(ui, self);

                ui.separator();

                // Active view content
                match self.active_tab {
                    Tab::Disassembly  => views::disassembly_view(ui, self),
                    Tab::Decompiler   => views::decompiler_view(ui, self),
                    Tab::HexView      => views::hex_view(ui, self),
                    Tab::GraphView    => views::graph_view(ui, self),
                    Tab::Strings      => views::strings_view(ui, self),
                    Tab::Imports      => views::imports_view(ui, self),
                    Tab::Xrefs        => views::xrefs_view(ui, self),
                    Tab::Entropy      => views::entropy_view(ui, self),
                    Tab::Report       => views::report_view(ui, self),
                    Tab::Findings     => views::findings_view(ui, self),
                    Tab::Structures   => views::structures_view(ui, self),
                    Tab::Settings     => views::settings_view(ui, self),
                    Tab::Scripting    => views::scripting_view(ui, self),
                    Tab::Plugins      => views::plugins_view(ui, self),
                    Tab::Diffing      => views::diffing_view(ui, self),
                    Tab::DataFlow     => views::dataflow_view(ui, self),
                    Tab::MlClassify   => views::ml_classify_view(ui, self),
                    Tab::FuncSigs     => views::func_sigs_view(ui, self),
                    Tab::FullSource   => views::full_source_view(ui, self),
                }
            } else {
                match mode {
                    Mode::Multi             => views::multi_view(ui, self),
                    Mode::MalwareDetector   => views::malware_detector_view(ui, self),
                    Mode::BackdoorAnalyzer  => views::backdoor_analyzer_view(ui, self),
                    Mode::Standard          => unreachable!("handled above"),
                }
            }
        });

        // ─── Modal Dialogs (IDA-style) ──────────────────────────────
        views::goto_dialog(ctx, self);
        views::rename_dialog(ctx, self);
        views::comment_dialog(ctx, self);

        // ─── Toast Notifications ────────────────────────────────────
        self.toasts.show(ctx, &self.colors);

        // ─── Incremental Full Source worker (no UI freeze) ─────────
        self.pump_full_source(ctx);

        // ─── Centered modal progress overlay while scanning ────────
        // Drawn LAST so it sits on top; the full-screen blocker area is
        // click-sensitive and therefore consumes all pointer input while
        // a scan runs (keyboard shortcuts are gated separately).
        if self.is_scanning {
            let started = self.scan_started_at;
            let total = self.scan_total;
            let done = self.scan_done.min(self.scan_total.max(1));
            let file_name = self.current_file_path.as_ref()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());

            // Dimmer + input blocker covering the whole window.
            egui::Area::new(egui::Id::new("scan_modal_blocker"))
                .order(egui::Order::Foreground)
                .interactable(true)
                .show(ctx, |ui| {
                    let screen = ctx.screen_rect();
                    let _resp = ui.allocate_rect(screen, egui::Sense::CLICK);
                    ui.painter().rect_filled(
                        screen,
                        0.0,
                        egui::Color32::from_black_alpha(150),
                    );
                });

            // Centered card: spinner + progress text + elapsed time.
            egui::Area::new(egui::Id::new("scan_modal_card"))
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .interactable(false)
                .show(ctx, |ui| {
                    let elapsed = started
                        .map(|t| t.elapsed().as_secs_f64())
                        .unwrap_or(0.0);
                    let mins = (elapsed / 60.0) as u64;
                    let secs = elapsed % 60.0;

                    egui::Frame::new()
                        .fill(c.bg_panel)
                        .stroke(egui::Stroke::new(1.0_f32, c.info))
                        .corner_radius(egui::CornerRadius::same(4))
                        .inner_margin(egui::Margin::same(24))
                        .show(ui, |ui| {
                            ui.set_min_width(360.0);
                            ui.vertical_centered(|ui| {
                                ui.add_space(4.0);
                                ui.add(egui::Spinner::new().size(34.0));
                                ui.add_space(12.0);
                                ui.label(
                                    egui::RichText::new("Scanning")
                                        .size(16.0).strong().color(c.text_white),
                                );
                                ui.add_space(2.0);
                                ui.label(
                                    egui::RichText::new(&file_name)
                                        .size(12.0).monospace().color(c.func_color),
                                );
                                ui.add_space(10.0);
                                if total > 1 {
                                    let frac = done as f32 / total.max(1) as f32;
                                    ui.add(
                                        egui::ProgressBar::new(frac)
                                            .desired_width(320.0)
                                            .desired_height(14.0)
                                            .show_percentage(),
                                    );
                                    ui.label(
                                        egui::RichText::new(format!("file {} of {}", done, total))
                                            .size(11.0).monospace().color(c.text_secondary),
                                    );
                                } else {
                                    ui.label(
                                        egui::RichText::new("analyzing binary…")
                                            .size(11.0).monospace().color(c.text_secondary),
                                    );
                                }
                                ui.add_space(6.0);
                                ui.label(
                                    egui::RichText::new(format!("elapsed  {:02}:{:05.2}", mins, secs))
                                        .size(11.0).monospace().color(c.text_secondary),
                                );
                                ui.add_space(2.0);
                                ui.label(
                                    egui::RichText::new("input is blocked until the scan finishes")
                                        .size(9.5).color(c.text_secondary.gamma_multiply(0.7)),
                                );
                                ui.add_space(4.0);
                            });
                        });
                });

            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
}
