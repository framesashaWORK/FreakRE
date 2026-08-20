use eframe::egui;
use bibleteks_scanner::report::{Severity, Verdict};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Settings ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: ThemeId,
    pub show_tooltips: bool,
    pub font_size_ui: f32,
    pub font_size_code: f32,
    pub accent_color: [u8; 3],
    pub hex_bytes_per_row: usize,
    pub disasm_max_instructions: usize,
    pub sidebar_collapsed: bool,
    pub recent_files: Vec<String>,
    pub max_recent_files: usize,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: ThemeId::DarkProfessional,
            show_tooltips: false,
            font_size_ui: 13.0,
            font_size_code: 11.0,
            accent_color: [88, 166, 255],
            hex_bytes_per_row: 16,
            disasm_max_instructions: 100,
            sidebar_collapsed: false,
            recent_files: Vec::new(),
            max_recent_files: 20,
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
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(content) = toml::to_string_pretty(self) {
                let _ = std::fs::write(&path, content);
            }
        }
    }

    pub fn add_recent_file(&mut self, path: &str) {
        self.recent_files.retain(|p| p != path);
        self.recent_files.insert(0, path.to_string());
        self.recent_files.truncate(self.max_recent_files);
    }
}

// ─── Theme System ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeId {
    DarkProfessional,
    LightClean,
    MidnightBlue,
    OledBlack,
}

impl ThemeId {
    pub fn label(&self) -> &'static str {
        match self {
            ThemeId::DarkProfessional => "Dark Professional",
            ThemeId::LightClean => "Light Clean",
            ThemeId::MidnightBlue => "Midnight Blue",
            ThemeId::OledBlack => "OLED Black",
        }
    }

    pub fn all() -> &'static [ThemeId] {
        &[
            ThemeId::DarkProfessional,
            ThemeId::LightClean,
            ThemeId::MidnightBlue,
            ThemeId::OledBlack,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct ThemeColors {
    pub bg_dark: egui::Color32,
    pub bg_panel: egui::Color32,
    pub bg_frame: egui::Color32,
    pub bg_hover: egui::Color32,
    pub accent: egui::Color32,
    pub danger: egui::Color32,
    pub warn: egui::Color32,
    pub safe: egui::Color32,
    pub text_primary: egui::Color32,
    pub text_secondary: egui::Color32,
    pub border: egui::Color32,
    pub sidebar_bg: egui::Color32,
    pub sidebar_active: egui::Color32,
    pub status_bar_bg: egui::Color32,
    pub shadow: egui::Shadow,
}

impl ThemeColors {
    pub fn from_id(id: ThemeId, custom_accent: [u8; 3]) -> Self {
        let accent = egui::Color32::from_rgb(custom_accent[0], custom_accent[1], custom_accent[2]);
        match id {
            ThemeId::DarkProfessional => Self {
                bg_dark: egui::Color32::from_rgb(13, 17, 23),
                bg_panel: egui::Color32::from_rgb(22, 27, 34),
                bg_frame: egui::Color32::from_rgb(33, 38, 45),
                bg_hover: egui::Color32::from_rgb(48, 54, 61),
                accent,
                danger: egui::Color32::from_rgb(248, 81, 73),
                warn: egui::Color32::from_rgb(210, 153, 34),
                safe: egui::Color32::from_rgb(63, 185, 80),
                text_primary: egui::Color32::from_rgb(230, 237, 243),
                text_secondary: egui::Color32::from_rgb(139, 148, 158),
                border: egui::Color32::from_rgb(48, 54, 61),
                sidebar_bg: egui::Color32::from_rgb(18, 22, 28),
                sidebar_active: egui::Color32::from_rgb(33, 38, 45),
                status_bar_bg: egui::Color32::from_rgb(18, 22, 28),
                shadow: egui::Shadow { offset: [0i8, 2i8], blur: 8, spread: 0, color: egui::Color32::from_black_alpha(80) },
            },
            ThemeId::LightClean => Self {
                bg_dark: egui::Color32::from_rgb(255, 255, 255),
                bg_panel: egui::Color32::from_rgb(248, 249, 251),
                bg_frame: egui::Color32::from_rgb(240, 242, 245),
                bg_hover: egui::Color32::from_rgb(230, 233, 238),
                accent,
                danger: egui::Color32::from_rgb(220, 53, 69),
                warn: egui::Color32::from_rgb(200, 150, 20),
                safe: egui::Color32::from_rgb(40, 167, 69),
                text_primary: egui::Color32::from_rgb(33, 37, 41),
                text_secondary: egui::Color32::from_rgb(108, 117, 125),
                border: egui::Color32::from_rgb(222, 226, 230),
                sidebar_bg: egui::Color32::from_rgb(243, 245, 248),
                sidebar_active: egui::Color32::from_rgb(230, 233, 238),
                status_bar_bg: egui::Color32::from_rgb(243, 245, 248),
                shadow: egui::Shadow { offset: [0i8, 2i8], blur: 10, spread: 0, color: egui::Color32::from_black_alpha(40) },
            },
            ThemeId::MidnightBlue => Self {
                bg_dark: egui::Color32::from_rgb(10, 12, 20),
                bg_panel: egui::Color32::from_rgb(16, 20, 35),
                bg_frame: egui::Color32::from_rgb(24, 30, 50),
                bg_hover: egui::Color32::from_rgb(35, 42, 65),
                accent,
                danger: egui::Color32::from_rgb(255, 99, 99),
                warn: egui::Color32::from_rgb(255, 193, 7),
                safe: egui::Color32::from_rgb(72, 199, 142),
                text_primary: egui::Color32::from_rgb(220, 225, 240),
                text_secondary: egui::Color32::from_rgb(130, 140, 170),
                border: egui::Color32::from_rgb(40, 50, 75),
                sidebar_bg: egui::Color32::from_rgb(12, 15, 26),
                sidebar_active: egui::Color32::from_rgb(24, 30, 50),
                status_bar_bg: egui::Color32::from_rgb(12, 15, 26),
                shadow: egui::Shadow { offset: [0i8, 3i8], blur: 12, spread: 0, color: egui::Color32::from_black_alpha(100) },
            },
            ThemeId::OledBlack => Self {
                bg_dark: egui::Color32::BLACK,
                bg_panel: egui::Color32::from_rgb(10, 10, 10),
                bg_frame: egui::Color32::from_rgb(20, 20, 20),
                bg_hover: egui::Color32::from_rgb(35, 35, 35),
                accent,
                danger: egui::Color32::from_rgb(255, 82, 82),
                warn: egui::Color32::from_rgb(255, 193, 7),
                safe: egui::Color32::from_rgb(76, 175, 80),
                text_primary: egui::Color32::from_rgb(230, 230, 230),
                text_secondary: egui::Color32::from_rgb(120, 120, 120),
                border: egui::Color32::from_rgb(40, 40, 40),
                sidebar_bg: egui::Color32::from_rgb(5, 5, 5),
                sidebar_active: egui::Color32::from_rgb(20, 20, 20),
                status_bar_bg: egui::Color32::from_rgb(5, 5, 5),
                shadow: egui::Shadow { offset: [0i8, 2i8], blur: 6, spread: 0, color: egui::Color32::from_black_alpha(120) },
            },
        }
    }
}

/// Apply theme visuals to egui context
pub fn apply_theme(ctx: &egui::Context, colors: &ThemeColors) {
    let mut visuals = egui::Visuals::dark();

    // For light theme, start from light base
    if colors.bg_dark.r() > 128 {
        visuals = egui::Visuals::light();
    }

    visuals.override_text_color = Some(colors.text_primary);
    visuals.window_fill = colors.bg_dark;
    visuals.panel_fill = colors.bg_panel;
    visuals.widgets.noninteractive.bg_fill = colors.bg_frame;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, colors.text_secondary);
    visuals.widgets.inactive.bg_fill = colors.bg_frame;
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, colors.text_primary);
    visuals.widgets.hovered.bg_fill = colors.bg_hover;
    visuals.widgets.active.bg_fill = colors.accent;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::WHITE);
    visuals.selection.bg_fill = colors.accent.linear_multiply(0.25);
    visuals.hyperlink_color = colors.accent;
    visuals.popup_shadow = colors.shadow;

    let rounding = egui::CornerRadius::same(6);
    visuals.widgets.noninteractive.corner_radius = rounding;
    visuals.widgets.inactive.corner_radius = rounding;
    visuals.widgets.hovered.corner_radius = rounding;
    visuals.widgets.active.corner_radius = rounding;
    visuals.window_corner_radius = egui::CornerRadius::same(10);
    visuals.menu_corner_radius = rounding;

    ctx.set_visuals(visuals);
}

pub fn setup_fonts(ctx: &egui::Context) {
    let _ = ctx;
}

// ─── Color helpers (backward compat + dynamic) ───────────────────────

pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(88, 166, 255);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(248, 81, 73);
pub const WARN: egui::Color32 = egui::Color32::from_rgb(210, 153, 34);
pub const SAFE: egui::Color32 = egui::Color32::from_rgb(63, 185, 80);
pub const INFO_COLOR: egui::Color32 = egui::Color32::from_rgb(139, 148, 158);
pub const BG_DARK: egui::Color32 = egui::Color32::from_rgb(13, 17, 23);
pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(22, 27, 34);
pub const BG_FRAME: egui::Color32 = egui::Color32::from_rgb(33, 38, 45);
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(48, 54, 61);
pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(230, 237, 243);
pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(139, 148, 158);

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

// ─── Toast Notification System ───────────────────────────────────────

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
            ToastKind::Info => "ℹ",
            ToastKind::Success => "✓",
            ToastKind::Warning => "⚠",
            ToastKind::Error => "✕",
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

    pub fn show(&mut self, ctx: &egui::Context) {
        self.cleanup();
        if self.toasts.is_empty() {
            return;
        }

        let viewport = ctx.screen_rect();
        let toast_area = egui::Area::new(egui::Id::new("toast_area"))
            .fixed_pos(egui::pos2(viewport.right() - 320.0, viewport.bottom() - 60.0))
            .order(egui::Order::Foreground)
            .interactable(false);

        toast_area.show(ctx, |ui| {
            ui.vertical(|ui| {
                for toast in self.toasts.iter().rev().take(3) {
                    let frame = egui::Frame::new()
                        .fill(toast.color().linear_multiply(0.15))
                        .stroke(egui::Stroke::new(1.0_f32, toast.color().linear_multiply(0.4)))
                        .corner_radius(egui::CornerRadius::same(8))
                        .inner_margin(egui::Margin::symmetric(14, 8))
                        .shadow(egui::Shadow { offset: [0i8, 4i8], blur: 12, spread: 0, color: egui::Color32::from_black_alpha(60) });

                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(toast.icon()).color(toast.color()).size(14.0).strong());
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(&toast.message).color(egui::Color32::WHITE).size(12.0));
                        });
                    });
                    ui.add_space(6.0);
                }
            });
        });
    }
}



