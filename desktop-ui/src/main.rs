#![allow(dead_code, unused_assignments)]
use eframe::egui;

mod app;
mod theme;
mod views;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([1000.0, 700.0])
            .with_title("FreakRE — Reverse Engineering Framework"),
        ..Default::default()
    };

    eframe::run_native(
        "FreakRE",
        options,
        Box::new(|cc| {
            theme::setup_fonts(&cc.egui_ctx);
            // Apply saved theme on startup
            let settings = theme::AppSettings::load();
            let colors = theme::ThemeColors::from_id(settings.theme, settings.accent_color);
            theme::apply_theme(&cc.egui_ctx, &colors);
            Ok(Box::new(app::FreakREApp::new()))
        }),
    )
}


