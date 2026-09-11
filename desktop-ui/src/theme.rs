use eframe::egui;
use freakre_scanner::report::{Severity, Verdict};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Settings ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub show_tooltips: bool,
    pub font_size_code: f32,
    pub hex_bytes_per_row: usize,
    pub disasm_max_instructions: usize,
    pub functions_panel_width: f32,
    pub output_panel_height: f32,
    pub recent_files: Vec<String>,
    pub max_recent_files: usize,
    #[serde(default)]
    pub suppressed_rules: Vec<String>,
    #[serde(default)]
    pub baseline_hashes: Vec<String>,
    /// FLIRT signature-base tier: 0 = low (~1.2M), 1 = basic (~2.7M),
    /// 2 = freak (all ~2.9M). Persisted across runs.
    #[serde(default)]
    pub sigs_tier: u8,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            show_tooltips: false,
            font_size_code: 13.0,
            hex_bytes_per_row: 16,
            disasm_max_instructions: 200,
            functions_panel_width: 220.0,
            output_panel_height: 150.0,
            recent_files: Vec::new(),
            max_recent_files: 20,
            suppressed_rules: Vec::new(),
            baseline_hashes: Vec::new(),
            sigs_tier: 1,
        }
    }
}

impl AppSettings {
    /// Tier name for the currently selected signature tier.
    pub fn sigs_tier_name(&self) -> &'static str {
        match self.sigs_tier {
            0 => "low",
            2 => "freak",
            _ => "basic",
        }
    }
}

impl AppSettings {
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("freakre").join("settings.toml"))
    }

    pub fn load() -> Self {
        if let Some(path) = Self::config_path() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(settings) = toml::from_str(&content) {
                    return settings;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        if let Some(path) = Self::config_path() {
            if let Ok(content) = toml::to_string_pretty(self) {
                // File I/O off the UI thread: serialize here, write in the
                // background. Best-effort; last writer wins.
                std::thread::spawn(move || {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&path, content);
                });
            }
        }
    }

    pub fn add_recent_file(&mut self, path: &str) {
        self.recent_files.retain(|p| p != path);
        self.recent_files.insert(0, path.to_string());
        self.recent_files.truncate(self.max_recent_files);
    }
}

// ─── IDA Pro Color Palette ──────────────────────────────────────────

/// All colors follow IDA Pro / VS Code Dark+ conventions.
/// No shadows, no gradients, no glassmorphism. Flat panels, thin borders.
#[derive(Debug, Clone)]
pub struct ThemeColors {
    // Backgrounds
    pub bg_main: egui::Color32,         // #1e1e1e — editor/disasm area
    pub bg_panel: egui::Color32,        // #252526 — side panels, toolbars
    pub bg_frame: egui::Color32,        // #2d2d2d — input fields, frames
    pub bg_hover: egui::Color32,        // #3e3e40 — hover state
    pub bg_selection: egui::Color32,    // #264f78 — selection highlight
    pub bg_statusbar: egui::Color32,    // #007acc — status bar (IDA blue)
    pub bg_tab_active: egui::Color32,   // #1e1e1e — active tab matches editor
    pub bg_tab_inactive: egui::Color32, // #2d2d2d — inactive tab

    // Text
    pub text_primary: egui::Color32,   // #cccccc — general UI text
    pub text_secondary: egui::Color32, // #858585 — dimmed/secondary
    pub text_white: egui::Color32,     // #ffffff — emphasis

    // Disassembly token colors (IDA-style)
    pub addr_color: egui::Color32, // #dcdcaa — addresses (yellow-ish)
    pub mnemonic_color: egui::Color32, // #569cd6 — instructions (blue)
    pub operand_color: egui::Color32, // #9cdcfe — registers/operands (light blue)
    pub string_color: egui::Color32, // #ce9178 — string literals (orange)
    pub comment_color: egui::Color32, // #6a9955 — comments (green)
    pub type_color: egui::Color32, // #c586c0 — types/keywords (purple)
    pub func_color: egui::Color32, // #4ec9b0 — function names (teal)
    pub number_color: egui::Color32, // #b5cea8 — numeric constants (light green)
    pub label_color: egui::Color32, // #d7ba7d — labels (gold)

    // Severity / verdict
    pub danger: egui::Color32, // #f44747
    pub warn: egui::Color32,   // #cca700
    pub safe: egui::Color32,   // #4caf50
    pub info: egui::Color32,   // #3794ff

    // Borders & misc
    pub border: egui::Color32,       // #3e3e40 — thin panel borders
    pub border_light: egui::Color32, // #4e4e50 — lighter separator
    pub scrollbar_bg: egui::Color32, // #1e1e1e
    pub scrollbar_fg: egui::Color32, // #424242
}

impl ThemeColors {
    /// Single IDA Pro dark theme. No variants.
    pub fn ida_dark() -> Self {
        Self {
            bg_main: egui::Color32::from_rgb(30, 30, 30),
            bg_panel: egui::Color32::from_rgb(37, 37, 38),
            bg_frame: egui::Color32::from_rgb(45, 45, 45),
            bg_hover: egui::Color32::from_rgb(62, 62, 64),
            bg_selection: egui::Color32::from_rgb(38, 79, 120),
            bg_statusbar: egui::Color32::from_rgb(0, 122, 204),
            bg_tab_active: egui::Color32::from_rgb(30, 30, 30),
            bg_tab_inactive: egui::Color32::from_rgb(45, 45, 45),

            text_primary: egui::Color32::from_rgb(204, 204, 204),
            text_secondary: egui::Color32::from_rgb(133, 133, 133),
            text_white: egui::Color32::WHITE,

            addr_color: egui::Color32::from_rgb(220, 220, 170),
            mnemonic_color: egui::Color32::from_rgb(86, 156, 214),
            operand_color: egui::Color32::from_rgb(156, 220, 254),
            string_color: egui::Color32::from_rgb(206, 145, 120),
            comment_color: egui::Color32::from_rgb(106, 153, 85),
            type_color: egui::Color32::from_rgb(197, 134, 192),
            func_color: egui::Color32::from_rgb(78, 201, 176),
            number_color: egui::Color32::from_rgb(181, 206, 168),
            label_color: egui::Color32::from_rgb(215, 186, 125),

            danger: egui::Color32::from_rgb(244, 71, 71),
            warn: egui::Color32::from_rgb(204, 167, 0),
            safe: egui::Color32::from_rgb(76, 175, 80),
            info: egui::Color32::from_rgb(55, 148, 255),

            border: egui::Color32::from_rgb(62, 62, 64),
            border_light: egui::Color32::from_rgb(78, 78, 80),
            scrollbar_bg: egui::Color32::from_rgb(30, 30, 30),
            scrollbar_fg: egui::Color32::from_rgb(66, 66, 66),
        }
    }
}

// ─── Apply IDA visuals to egui ──────────────────────────────────────

pub fn apply_theme(ctx: &egui::Context, colors: &ThemeColors) {
    let mut visuals = egui::Visuals::dark();

    visuals.override_text_color = Some(colors.text_primary);
    visuals.window_fill = colors.bg_main;
    visuals.panel_fill = colors.bg_panel;

    // Widgets — flat, minimal rounding, thin borders
    let stroke = egui::Stroke::new(1.0_f32, colors.border);
    let fg_stroke = egui::Stroke::new(1.0_f32, colors.text_primary);

    visuals.widgets.noninteractive.bg_fill = colors.bg_frame;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, colors.text_secondary);
    visuals.widgets.noninteractive.bg_stroke = stroke;
    visuals.widgets.inactive.bg_fill = colors.bg_frame;
    visuals.widgets.inactive.fg_stroke = fg_stroke;
    visuals.widgets.inactive.bg_stroke = stroke;
    visuals.widgets.hovered.bg_fill = colors.bg_hover;
    visuals.widgets.hovered.fg_stroke = fg_stroke;
    visuals.widgets.hovered.bg_stroke = stroke;
    visuals.widgets.active.bg_fill = colors.bg_selection;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, colors.text_white);
    visuals.widgets.active.bg_stroke = stroke;

    visuals.selection.bg_fill = colors.bg_selection;
    visuals.hyperlink_color = colors.info;

    // NO shadows anywhere — IDA is flat
    visuals.popup_shadow = egui::Shadow::NONE;
    visuals.window_shadow = egui::Shadow::NONE;

    // Minimal rounding (0-2px like IDA)
    let rounding = egui::CornerRadius::same(2);
    visuals.widgets.noninteractive.corner_radius = rounding;
    visuals.widgets.inactive.corner_radius = rounding;
    visuals.widgets.hovered.corner_radius = rounding;
    visuals.widgets.active.corner_radius = rounding;
    visuals.window_corner_radius = egui::CornerRadius::same(0);
    visuals.menu_corner_radius = egui::CornerRadius::same(2);

    // Scrollbar styling is handled via egui::ScrollArea in each view.
    // egui 0.31+ removed Visuals::scroll_bar_width; using default.

    ctx.set_visuals(visuals);
}

/// Load Consolas / monospace font for code views.
/// Falls back to system monospace if Consolas not available.
pub fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Try to load Consolas from Windows system path
    let consolas_paths = [
        "C:\\Windows\\Fonts\\consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ];

    for path in &consolas_paths {
        if let Ok(font_data) = std::fs::read(path) {
            fonts.font_data.insert(
                "code_font".to_owned(),
                egui::FontData::from_owned(font_data).into(),
            );
            // Prepend to monospace family
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "code_font".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

// ─── Backward-compatible color constants (now IDA palette) ─────────

pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(55, 148, 255);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(244, 71, 71);
pub const WARN: egui::Color32 = egui::Color32::from_rgb(204, 167, 0);
pub const SAFE: egui::Color32 = egui::Color32::from_rgb(76, 175, 80);
pub const INFO_COLOR: egui::Color32 = egui::Color32::from_rgb(133, 133, 133);
pub const BG_DARK: egui::Color32 = egui::Color32::from_rgb(30, 30, 30);
pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(37, 37, 38);
pub const BG_FRAME: egui::Color32 = egui::Color32::from_rgb(45, 45, 45);
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(62, 62, 64);
pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(204, 204, 204);
pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(133, 133, 133);

pub fn severity_color(sev: &Severity) -> egui::Color32 {
    match sev {
        Severity::Critical => DANGER,
        Severity::High => egui::Color32::from_rgb(255, 123, 79),
        Severity::Medium => WARN,
        Severity::Low => ACCENT,
        Severity::Info => INFO_COLOR,
    }
}

pub fn verdict_color(verdict: &Verdict) -> egui::Color32 {
    match verdict {
        Verdict::Malicious => DANGER,
        Verdict::Suspicious => WARN,
        Verdict::Clean => SAFE,
        Verdict::Error => INFO_COLOR,
    }
}

// ─── Toast Notification System (IDA-style: compact, bottom-right) ───

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    pub created_at: f64,
    pub duration: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

impl Toast {
    pub fn color(&self) -> egui::Color32 {
        match self.kind {
            ToastKind::Info => INFO_COLOR,
            ToastKind::Success => SAFE,
            ToastKind::Warning => WARN,
            ToastKind::Error => DANGER,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self.kind {
            ToastKind::Info => "i",
            ToastKind::Success => "+",
            ToastKind::Warning => "!",
            ToastKind::Error => "x",
        }
    }
}

pub struct ToastManager {
    pub toasts: Vec<Toast>,
}

impl ToastManager {
    pub fn new() -> Self {
        Self { toasts: Vec::new() }
    }

    pub fn add(&mut self, message: impl Into<String>, kind: ToastKind) {
        self.toasts.push(Toast {
            message: message.into(),
            kind,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            duration: 4.0,
        });
    }

    pub fn cleanup(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.toasts.retain(|t| now - t.created_at < t.duration);
    }

    pub fn show(&mut self, ctx: &egui::Context, colors: &ThemeColors) {
        self.cleanup();
        if self.toasts.is_empty() {
            return;
        }

        let viewport = ctx.screen_rect();
        let toast_area = egui::Area::new(egui::Id::new("toast_area"))
            .fixed_pos(egui::pos2(
                viewport.right() - 300.0,
                viewport.bottom() - 50.0,
            ))
            .order(egui::Order::Foreground)
            .interactable(false);

        toast_area.show(ctx, |ui| {
            ui.vertical(|ui| {
                for toast in self.toasts.iter().rev().take(3) {
                    // IDA-style: flat frame, thin border, no shadow
                    let frame = egui::Frame::new()
                        .fill(colors.bg_panel)
                        .stroke(egui::Stroke::new(1.0_f32, toast.color()))
                        .corner_radius(egui::CornerRadius::same(2))
                        .inner_margin(egui::Margin::symmetric(10, 5));

                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(toast.icon())
                                    .color(toast.color())
                                    .size(12.0)
                                    .strong()
                                    .monospace(),
                            );
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(&toast.message)
                                    .color(colors.text_primary)
                                    .size(12.0)
                                    .monospace(),
                            );
                        });
                    });
                    ui.add_space(4.0);
                }
            });
        });
    }
}
