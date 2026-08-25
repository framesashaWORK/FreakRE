#![allow(dead_code, unused_assignments)]
use eframe::egui;

mod app;
mod theme;
mod views;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([1024.0, 700.0])
            .with_title("FreakRE"),
        ..Default::default()
    };

    eframe::run_native(
        "FreakRE",
        options,
        Box::new(|cc| {
            // Load monospace font (Consolas / system fallback)
            theme::setup_fonts(&cc.egui_ctx);
            // Apply IDA Pro dark theme
            let colors = theme::ThemeColors::ida_dark();
            theme::apply_theme(&cc.egui_ctx, &colors);
            Ok(Box::new(app::FreakREApp::new()))
        }),
    )
}
