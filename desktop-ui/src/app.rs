use eframe::egui;
use freakre_scanner::{scanner::Scanner, report::FileReport};
use plugins::PluginManager;
use freakre_sys_plugins;
use std::path::PathBuf;
use std::sync::mpsc;

use crate::theme::{self, AppSettings, ThemeColors, ToastManager, ToastKind};
use crate::views;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Dashboard,
    Report,
    Findings,
    Entropy,
    HexView,
    Disassembly,
    GraphView,
    Plugins,
    Settings,
}

impl Tab {
    pub fn icon(&self) -> &'static str {
        match self {
            Tab::Dashboard => "📊",
            Tab::Report => "📋",
            Tab::Findings => "🔍",
            Tab::Entropy => "📈",
            Tab::HexView => "🔢",
            Tab::Disassembly => "⚙️",
            Tab::GraphView => "🕸",
            Tab::Plugins => "🧩",
            Tab::Settings => "⚙️",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Report => "Report",
            Tab::Findings => "Findings",
            Tab::Entropy => "Entropy",
            Tab::HexView => "Hex View",
            Tab::Disassembly => "Disasm",
            Tab::GraphView => "CFG Graph",
            Tab::Plugins => "Plugins",
            Tab::Settings => "Settings",
        }
    }

    pub fn all() -> &'static [Tab] {
        &[
            Tab::Dashboard,
            Tab::Report,
            Tab::Findings,
            Tab::Entropy,
            Tab::HexView,
            Tab::Disassembly,
            Tab::GraphView,
            Tab::Plugins,
            Tab::Settings,
        ]
    }
}

pub enum ScanMessage {
    Report(FileReport, Vec<u8>),
    Done,
}

pub struct FreakREApp {
    pub scanner: Scanner,
    pub plugin_manager: PluginManager,
    pub reports: Vec<FileReport>,
    pub report_data: Vec<Vec<u8>>,
    pub selected_report: Option<usize>,
    pub active_tab: Tab,
    pub is_scanning: bool,
    pub drag_hovered: bool,
    pub scan_rx: Option<mpsc::Receiver<ScanMessage>>,
    pub yara_rules_path: Option<PathBuf>,
    // Hex view state
    pub hex_offset: usize,
    pub hex_search: String,
    // Disassembly state
    pub disasm_offset: u64,
    pub disasm_is_64bit: bool,
    // Plugin output log
    pub plugin_output: Vec<String>,
    // Settings & theme
    pub settings: AppSettings,
    pub colors: ThemeColors,
    pub toasts: ToastManager,
    // Search
    pub global_search: String,
    pub show_search: bool,
}

impl FreakREApp {
    pub fn new() -> Self {
        let mut plugin_manager = PluginManager::new();
        freakre_sys_plugins::register_system_plugins(&mut plugin_manager);

        let settings = AppSettings::load();
        let colors = ThemeColors::from_id(settings.theme, settings.accent_color);

        Self {
            scanner: Scanner::new(),
            plugin_manager,
            reports: Vec::new(),
            report_data: Vec::new(),
            selected_report: None,
            active_tab: Tab::Dashboard,
            is_scanning: false,
            drag_hovered: false,
            scan_rx: None,
            yara_rules_path: None,
            hex_offset: 0,
            hex_search: String::new(),
            disasm_offset: 0,
            disasm_is_64bit: true,
            plugin_output: Vec::new(),
            settings,
            colors,
            toasts: ToastManager::new(),
            global_search: String::new(),
            show_search: false,
        }
    }

    pub fn apply_current_theme(&mut self, ctx: &egui::Context) {
        self.colors = ThemeColors::from_id(self.settings.theme, self.settings.accent_color);
        theme::apply_theme(ctx, &self.colors);
        self.settings.save();
    }

    pub fn scan_files(&mut self, paths: Vec<PathBuf>) {
        if self.is_scanning {
            return;
        }
        self.is_scanning = true;

        // Add to recent files
        for p in &paths {
            if let Some(s) = p.to_str() {
                self.settings.add_recent_file(s);
            }
        }
        self.settings.save();

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
                let data = std::fs::read(path).unwrap_or_default();
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
                self.toasts.add("YARA rules loaded successfully", ToastKind::Success);
            }
            Err(e) => {
                eprintln!("Invalid YARA rules: {}", e);
                self.toasts.add(format!("Failed to load YARA rules: {}", e), ToastKind::Error);
            }
        }
    }

    fn poll_scan_results(&mut self) {
        if let Some(ref rx) = self.scan_rx {
            loop {
                match rx.try_recv() {
                    Ok(ScanMessage::Report(report, data)) => {
                        self.reports.push(report);
                        self.report_data.push(data);
                    }
                    Ok(ScanMessage::Done) => {
                        self.is_scanning = false;
                        self.scan_rx = None;
                        self.toasts.add("Scan completed", ToastKind::Success);
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.is_scanning = false;
                        self.scan_rx = None;
                        break;
                    }
                }
            }
        }
    }

    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        ctx.input(|i| {
            // Ctrl+F — toggle search
            if i.modifiers.ctrl && i.key_pressed(egui::Key::F) {
                self.show_search = !self.show_search;
            }
            // Escape — close search / go back
            if i.key_pressed(egui::Key::Escape) {
                if self.show_search {
                    self.show_search = false;
                }
            }
        });
    }
}

impl eframe::App for FreakREApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan_results();
        self.handle_keyboard_shortcuts(ctx);

        // ─── Sidebar ────────────────────────────────────────────────
        let sidebar_width = if self.settings.sidebar_collapsed { 52.0 } else { 180.0 };

        egui::SidePanel::left("sidebar")
            .exact_width(sidebar_width)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(12.0);

                // Logo area
                ui.horizontal(|ui| {
                    ui.add_space(if self.settings.sidebar_collapsed { 8.0 } else { 14.0 });
                    ui.label(
                        egui::RichText::new("🔥")
                            .size(if self.settings.sidebar_collapsed { 20.0 } else { 18.0 })
                            .color(self.colors.accent),
                    );
                    if !self.settings.sidebar_collapsed {
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new("FreakRE")
                                .color(self.colors.text_primary)
                                .size(16.0)
                                .strong(),
                        );
                    }
                });

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                // Navigation items
                for tab in Tab::all() {
                    let is_active = self.active_tab == *tab;
                    let btn_height = 36.0;

                    let response = if self.settings.sidebar_collapsed {
                        // Collapsed: icon only
                        let mut frame = egui::Frame::new()
                            .fill(if is_active { self.colors.sidebar_active } else { egui::Color32::TRANSPARENT })
                            .inner_margin(egui::Margin::symmetric(0, 6));
                        frame.corner_radius = egui::CornerRadius::same(8);

                        frame.show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.allocate_ui_with_layout(
                                    egui::vec2(sidebar_width - 8.0, btn_height),
                                    egui::Layout::centered_and_justified(egui::Direction::TopDown),
                                    |ui| {
                                        let text_color = if is_active { self.colors.accent } else { self.colors.text_secondary };
                                        ui.label(egui::RichText::new(tab.icon()).size(18.0).color(text_color));
                                    },
                                );
                            });
                        }).response
                    } else {
                        // Expanded: icon + label
                        let mut frame = egui::Frame::new()
                            .fill(if is_active { self.colors.sidebar_active } else { egui::Color32::TRANSPARENT })
                            .inner_margin(egui::Margin::symmetric(12, 6));
                        frame.corner_radius = egui::CornerRadius::same(8);

                        frame.show(ui, |ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(sidebar_width - 24.0, btn_height),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    let text_color = if is_active { self.colors.accent } else { self.colors.text_secondary };
                                    ui.label(egui::RichText::new(tab.icon()).size(16.0).color(text_color));
                                    ui.add_space(10.0);
                                    ui.label(
                                        egui::RichText::new(tab.label())
                                            .size(self.settings.font_size_ui)
                                            .color(if is_active { self.colors.text_primary } else { self.colors.text_secondary }),
                                    );
                                },
                            );
                        }).response
                    };

                    if response.clicked() {
                        self.active_tab = *tab;
                    }

                    // Tooltip (only if enabled in settings)
                    if self.settings.show_tooltips && self.settings.sidebar_collapsed {
                        response.on_hover_text(tab.label());
                    }

                    ui.add_space(2.0);
                }

                // Bottom: collapse toggle
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);

                    let toggle_label = if self.settings.sidebar_collapsed { "▶" } else { "◀ Collapse" };
                    let toggle_resp = ui.selectable_label(false, toggle_label);
                    if toggle_resp.clicked() {
                        self.settings.sidebar_collapsed = !self.settings.sidebar_collapsed;
                        self.settings.save();
                    }
                });
            });

        // ─── Status Bar ─────────────────────────────────────────────
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(28.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);

                    // Current file info
                    if let Some(idx) = self.selected_report.or_else(|| if self.reports.is_empty() { None } else { Some(self.reports.len() - 1) }) {
                        if let Some(report) = self.reports.get(idx) {
                            let fname = report.path.file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "unknown".into());
                            ui.label(egui::RichText::new(&fname).color(self.colors.text_primary).size(11.0));
                            ui.separator();
                            ui.label(egui::RichText::new(&report.file_type).color(self.colors.text_secondary).size(11.0));
                            ui.separator();
                            ui.label(egui::RichText::new(format!("{:.1}%", report.suspicion_score * 100.0)).color(theme::verdict_color(&report.verdict)).size(11.0));
                        }
                    } else {
                        ui.label(egui::RichText::new("No file loaded").color(self.colors.text_secondary).size(11.0));
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(12.0);

                        // Scan status
                        if self.is_scanning {
                            ui.label(egui::RichText::new("⟳ Scanning…").color(self.colors.warn).size(11.0));
                        } else {
                            ui.label(egui::RichText::new(format!("{} files", self.reports.len())).color(self.colors.text_secondary).size(11.0));
                        }

                        ui.separator();

                        // Architecture
                        ui.label(egui::RichText::new(if self.disasm_is_64bit { "x86_64" } else { "x86" }).color(self.colors.text_secondary).size(11.0));

                        // Keyboard shortcut hint
                        ui.separator();
                        ui.label(egui::RichText::new("Ctrl+F Search").color(self.colors.text_secondary.gamma_multiply(0.6)).size(10.0));
                    });
                });
            });

        // ─── Top Search Bar (conditional) ───────────────────────────
        if self.show_search {
            egui::TopBottomPanel::top("search_panel")
                .exact_height(40.0)
                .show(ctx, |ui| {
                    ui.horizontal_centered(|ui| {
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new("🔍").size(14.0).color(self.colors.accent));
                        ui.add_space(6.0);
                        let resp = ui.add_sized(
                            egui::vec2(ui.available_width() - 100.0, 28.0),
                            egui::TextEdit::singleline(&mut self.global_search)
                                .hint_text("Search findings, strings, symbols…"),
                        );
                        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            // TODO: implement global search
                            self.toasts.add("Search not yet implemented", ToastKind::Info);
                        }
                    });
                });
        }

        // ─── Central Panel ──────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Dashboard => views::dashboard_view(ui, self),
                Tab::Report => views::report_view(ui, self),
                Tab::Findings => views::findings_view(ui, self),
                Tab::Entropy => views::entropy_view(ui, self),
                Tab::HexView => views::hex_view(ui, self),
                Tab::Disassembly => views::disassembly_view(ui, self),
                Tab::GraphView => views::graph_view(ui, self),
                Tab::Plugins => views::plugins_view(ui, self),
                Tab::Settings => views::settings_view(ui, self),
            }
        });

        // ─── Toast Notifications ────────────────────────────────────
        self.toasts.show(ctx);

        // Request repaint if scanning
        if self.is_scanning {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
}

