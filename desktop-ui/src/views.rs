use eframe::egui;
use freakre_scanner::report::FileReport;
use cfg_builder::EdgeType;
use std::sync::Arc;

use crate::app::{DbCommand, FreakREApp, JobKey, Tab};
use crate::theme::{self, ToastKind};

// ═══════════════════════════════════════════════════════════════════
// All views follow IDA Pro conventions:
// - Monospace font for code/data
// - Flat panels, thin 1px borders, no shadows
// - Minimal padding, compact layout
// - Token-level coloring in disassembly
// ═══════════════════════════════════════════════════════════════════

// ─── Disassembly View (IDA-style) ──────────────────────────────────

pub fn disassembly_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();
    let fs = app.settings.font_size_code;

    // Toolbar row
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Address:").color(c.text_secondary).size(11.0).monospace());
        let mut offset_str = format!("{:08X}", app.disasm_offset);
        let resp = ui.add_sized(
            egui::vec2(80.0, 18.0),
            egui::TextEdit::singleline(&mut offset_str)
                .font(egui::FontId::monospace(11.0)),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Ok(val) = u64::from_str_radix(&offset_str, 16) {
                app.nav_push(app.disasm_offset);
                app.disasm_offset = val;
            }
        }

        ui.separator();
        ui.checkbox(&mut app.disasm_is_64bit,
            egui::RichText::new("x86_64").monospace().size(11.0).color(c.text_primary));

    });

    ui.separator();

    let data = match get_current_data(app) {
        Some(d) => d,
        None => {
            ui.label(egui::RichText::new("No file loaded.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    if data.is_empty() {
        if let Some(ref err) = app.data_read_error {
            ui.label(egui::RichText::new(err)
                .color(c.danger).size(11.0).monospace());
        } else {
            ui.label(egui::RichText::new("File is empty.")
                .color(c.text_secondary).size(11.0).monospace());
        }
        return;
    }

    // Use capstone-ffi for real disassembly
    app.ensure_disasm();

    let start = app.disasm_offset as usize;
    if start >= data.len() {
        ui.label(egui::RichText::new("invalid address")
            .color(c.text_secondary).size(11.0).monospace());
        return;
    }
    let end = (start + 0x400).min(data.len());
    let code_region = &data[start..end];

    // Disassemble using capstone (or fallback LDE)
    let instructions = if let Some(ref disasm) = app.disasm {
        disasm.disassemble_n(code_region, start as u64, app.settings.disasm_max_instructions)
    } else {
        Vec::new()
    };

    // Toolbar: nav buttons + hotkey hints
    ui.horizontal(|ui| {
        if ui.small_button("◄ Back").clicked() { app.nav_back(); }
        if ui.small_button("Fwd ►").clicked() { app.nav_forward(); }
        ui.separator();
        if ui.small_button("EP").clicked() {
            if let Some(report) = current_report(app) {
                if let Some(ep_str) = entry_point_str(report) {
                    if !ep_str.is_empty() {
                        if let Ok(ep_rva) = u64::from_str_radix(ep_str.trim_start_matches("0x"), 16) {
                            // PE entry points are RVAs — translate to a file
                            // offset before using it as a disasm byte offset.
                            let ep = pe_rva_to_file_offset(app, ep_rva);
                            app.nav_push(app.disasm_offset);
                            app.disasm_offset = ep;
                        }
                    }
                }
            }
        }
        ui.separator();
        if ui.small_button("CFG").clicked() {
            app.build_cfg_at(app.disasm_offset);
            app.active_tab = Tab::GraphView;
        }
        if ui.small_button("F5").clicked() {
            app.decompile_at(app.disasm_offset);
            app.active_tab = Tab::Decompiler;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new("G:goto  N:rename  X:xrefs  ;:comment  F5:decompile  Space:graph")
                .color(c.text_secondary.gamma_multiply(0.5)).size(9.0).monospace());
        });
    });

    ui.separator();

    // Column header
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Address ").color(c.text_secondary).size(fs).monospace());
        ui.label(egui::RichText::new("Bytes              ").color(c.text_secondary).size(fs).monospace());
        ui.label(egui::RichText::new("Mnemonic   ").color(c.text_secondary).size(fs).monospace());
        ui.label(egui::RichText::new("Operands").color(c.text_secondary).size(fs).monospace());
        ui.label(egui::RichText::new("Comment").color(c.text_secondary).size(fs).monospace());
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        if instructions.is_empty() {
            ui.label(egui::RichText::new("; No valid instructions at this offset (capstone fallback)")
                .color(c.comment_color).size(fs).monospace());
            return;
        }

        for inst in &instructions {
            ui.horizontal(|ui| {
                // Address (yellow-ish like IDA)
                ui.label(egui::RichText::new(format!("{:08X} ", inst.address))
                    .color(c.addr_color).size(fs).monospace());

                // Bytes from original data (dimmed)
                let inst_start = inst.address as usize;
                let inst_end = (inst_start + inst.size).min(data.len());
                let inst_bytes = &data[inst_start..inst_end];
                let bytes_str: String = inst_bytes.iter()
                    .take(8)
                    .map(|b| format!("{:02X} ", b))
                    .collect();
                ui.label(egui::RichText::new(format!("{:<24}", bytes_str))
                    .color(c.text_secondary).size(fs).monospace());

                // Mnemonic (blue like IDA keywords)
                ui.label(egui::RichText::new(format!("{:<10}", inst.mnemonic))
                    .color(c.mnemonic_color).size(fs).monospace());

                // Operands (light blue like IDA registers)
                ui.label(egui::RichText::new(&inst.operands)
                    .color(c.operand_color).size(fs).monospace());

                // Inline comment (if any)
                if let Some(comment) = app.comments.get(&inst.address) {
                    ui.label(egui::RichText::new(format!("; {}", comment))
                        .color(c.comment_color).size(fs).monospace());
                }

                // Bookmark indicator
                for (bi, bm) in app.bookmarks.iter().enumerate() {
                    if *bm == Some(inst.address) {
                        ui.label(egui::RichText::new(format!(" [{}]", bi))
                            .color(c.label_color).size(fs).monospace());
                        break;
                    }
                }
            });

            // Click on instruction to navigate
            if ui.interact(ui.min_rect().expand(2.0), ui.id().with(("inst_nav", inst.address)), egui::Sense::CLICK).clicked() {
                app.nav_push(app.disasm_offset);
                app.disasm_offset = inst.address;
            }
        }
    });
}

// ─── Hex View (IDA classic style) ──────────────────────────────────

pub fn hex_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();
    let fs = app.settings.font_size_code;

    // Toolbar
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Offset:").color(c.text_secondary).size(11.0).monospace());
        let mut offset_str = format!("{:08X}", app.hex_offset);
        let resp = ui.add_sized(
            egui::vec2(80.0, 18.0),
            egui::TextEdit::singleline(&mut offset_str)
                .font(egui::FontId::monospace(11.0)),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Ok(val) = u64::from_str_radix(&offset_str, 16) {
                app.hex_offset = val as usize;
            }
        }

        ui.separator();
        ui.label(egui::RichText::new("Find:").color(c.text_secondary).size(11.0).monospace());
        ui.add_sized(
            egui::vec2(120.0, 18.0),
            egui::TextEdit::singleline(&mut app.hex_search)
                .font(egui::FontId::monospace(11.0))
                .hint_text("ASCII/hex"),
        );
        if ui.small_button("Find").clicked() && !app.hex_search.is_empty() {
            if let Some(data) = get_current_data(app) {
                let search_bytes = app.hex_search.as_bytes();
                let start = app.hex_offset.saturating_add(1);
                if start < data.len() {
                    if let Some(pos) = data[start..].windows(search_bytes.len()).position(|w| w == search_bytes) {
                        app.hex_offset = start + pos;
                    }
                }
            }
        }

        ui.separator();
        if ui.small_button("|<<").clicked() { app.hex_offset = 0; }
        if ui.small_button("<").clicked() { app.hex_offset = app.hex_offset.saturating_sub(0x100); }
        if ui.small_button(">").clicked() {
            if let Some(data) = get_current_data(app) {
                app.hex_offset = app.hex_offset.saturating_add(0x100).min(data.len().saturating_sub(16));
            }
        }
    });

    ui.separator();

    let data = match get_current_data(app) {
        Some(d) => d,
        None => {
            ui.label(egui::RichText::new("No file loaded.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    if data.is_empty() {
        if let Some(ref err) = app.data_read_error {
            ui.label(egui::RichText::new(err)
                .color(c.danger).size(11.0).monospace());
        } else {
            ui.label(egui::RichText::new("File is empty.")
                .color(c.text_secondary).size(11.0).monospace());
        }
        return;
    }

    let bpr = app.settings.hex_bytes_per_row.max(1);
    let start = app.hex_offset & !(bpr - 1);
    let end = (start + 0x400).min(data.len());

    // Header line
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Offset   ").color(c.text_secondary).size(fs).monospace());
        for i in 0..bpr {
            ui.label(egui::RichText::new(format!("{:02X} ", i)).color(c.text_secondary).size(fs).monospace());
            if i == 7 { ui.add_space(4.0); }
        }
        ui.add_space(4.0);
        ui.label(egui::RichText::new("ASCII").color(c.text_secondary).size(fs).monospace());
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        let mut offset = start;
        while offset < end {
            ui.horizontal(|ui| {
                // Offset column
                ui.label(egui::RichText::new(format!("{:08X} ", offset))
                    .color(c.addr_color).size(fs).monospace());

                let mut ascii = String::with_capacity(bpr);
                for col in 0..bpr {
                    let byte_off = offset + col;
                    if byte_off < data.len() {
                        let byte = data[byte_off];
                        let hex_color = if byte == 0 {
                            c.text_secondary.gamma_multiply(0.5)
                        } else if byte.is_ascii_graphic() || byte == b' ' {
                            c.number_color
                        } else {
                            c.text_primary
                        };
                        ui.label(egui::RichText::new(format!("{:02X} ", byte))
                            .color(hex_color).size(fs).monospace());

                        ascii.push(if byte.is_ascii_graphic() || byte == b' ' {
                            byte as char
                        } else {
                            '.'
                        });
                    } else {
                        ui.label(egui::RichText::new("   ").size(fs).monospace());
                        ascii.push(' ');
                    }
                    if col == 7 { ui.add_space(4.0); }
                }

                ui.add_space(4.0);
                ui.label(egui::RichText::new(&ascii)
                    .color(c.string_color).size(fs).monospace());
            });
            offset += bpr;
        }
    });
}

// ─── Strings View ──────────────────────────────────────────────────

pub fn strings_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    let report = match current_report(app) {
        Some(r) => r,
        None => {
            ui.label(egui::RichText::new("No file loaded.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    // Header
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Offset     ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("Len   ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("String").color(c.text_secondary).size(11.0).monospace().strong());
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        if report.strings_found == 0 {
            ui.label(egui::RichText::new("No strings found.")
                .color(c.text_secondary).size(11.0).monospace());
        } else {
            for finding in &report.findings {
                if finding.module == "strings" || finding.rule_id.contains("string") {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("-------- ")
                            .color(c.text_secondary).size(11.0).monospace());
                        ui.label(egui::RichText::new("---- ")
                            .color(c.text_secondary).size(11.0).monospace());
                        ui.label(egui::RichText::new(&finding.description)
                            .color(c.string_color).size(11.0).monospace());
                    });
                }
            }

            let has_string_findings = report.findings.iter()
                .any(|f| f.module == "strings" || f.rule_id.contains("string"));

            if !has_string_findings {
                ui.label(egui::RichText::new(format!(
                    "{} strings detected (details in Report view)",
                    report.strings_found
                )).color(c.text_primary).size(11.0).monospace());
            }
        }
    });
}

// ─── Imports View ──────────────────────────────────────────────────

pub fn imports_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    let report = match current_report(app) {
        Some(r) => r,
        None => {
            ui.label(egui::RichText::new("No file loaded.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    let imports: Vec<(String, String)> = if report.pe_info.is_some() {
        report.findings.iter()
            .filter(|f| f.module == "imports" || f.module == "import_analyzer")
            .map(|f| ("PE Import".to_string(), f.description.clone()))
            .collect()
    } else if let Some(ref macho) = report.macho_info {
        macho.imported_dylibs.iter()
            .map(|lib| ("dylib".to_string(), lib.clone()))
            .collect()
    } else {
        Vec::new()
    };

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Type       ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("Name").color(c.text_secondary).size(11.0).monospace().strong());
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        if imports.is_empty() {
            ui.label(egui::RichText::new("No import data available for this file type.")
                .color(c.text_secondary).size(11.0).monospace());
        } else {
            for (typ, name) in &imports {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("{:<12}", typ))
                        .color(c.type_color).size(11.0).monospace());
                    ui.label(egui::RichText::new(name)
                        .color(c.func_color).size(11.0).monospace());
                });
            }
        }
    });
}

// ─── Graph View (Real CFG) ─────────────────────────────────────────

pub fn graph_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Function:").color(c.text_secondary).size(11.0).monospace());
        ui.label(egui::RichText::new(format!("{:08X}", app.disasm_offset))
            .color(c.addr_color).size(11.0).monospace());
        ui.separator();
        if ui.small_button("Rebuild CFG").clicked() {
            app.cfg_cache.remove(&app.disasm_offset);
            app.build_cfg_at(app.disasm_offset);
        }
    });

    ui.separator();

    let cfg = match app.cfg_cache.get(&app.disasm_offset) {
        Some(cfg) => cfg,
        None => {
            if app.pending_jobs.contains_key(&JobKey::BuildCfg(app.disasm_offset)) {
                ui.label(egui::RichText::new("Building CFG…")
                    .color(c.text_secondary).size(11.0).monospace());
                return;
            }
            ui.label(egui::RichText::new("No CFG. Press Space or click Rebuild to build one.")
                .color(c.text_secondary).size(11.0).monospace());
            if ui.button("Build CFG now").clicked() {
                app.build_cfg_at(app.disasm_offset);
            }
            return;
        }
    };

    // Stats
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("Blocks: {}", cfg.blocks.len()))
            .color(c.text_primary).size(11.0).monospace());
        ui.separator();
        ui.label(egui::RichText::new(format!("Edges: {}", cfg.num_edges()))
            .color(c.text_primary).size(11.0).monospace());
        ui.separator();
        ui.label(egui::RichText::new(format!("Instructions: {}", cfg.total_instructions))
            .color(c.text_primary).size(11.0).monospace());
        ui.separator();
        let anomalies = cfg.anomalies.len();
        ui.label(egui::RichText::new(format!("Anomalies: {}", anomalies))
            .color(if anomalies > 0 { c.danger } else { c.safe })
            .size(11.0).monospace());
    });

    let cyclomatic = if !cfg.blocks.is_empty() {
        cfg.num_edges() as i64 - cfg.blocks.len() as i64 + 2
    } else { 0 };

    ui.label(egui::RichText::new(format!("Cyclomatic complexity: {}", cyclomatic))
        .color(c.text_secondary).size(11.0).monospace());

    ui.separator();

    // Visual graph
    let (rect, _response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().min(800.0), 400.0),
        egui::Sense::hover(),
    );

    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, egui::CornerRadius::same(0), c.bg_frame);
    painter.rect_stroke(rect, egui::CornerRadius::same(0),
        egui::Stroke::new(1.0_f32, c.border), egui::StrokeKind::Inside);

    if cfg.blocks.is_empty() {
        return;
    }

    // Layout: simple grid
    let cols = (cfg.blocks.len() as f64).sqrt().ceil() as usize;
    let rows = cfg.blocks.len().div_ceil(cols);
    let cell_w = rect.width() / (cols as f32 + 1.0);
    let cell_h = rect.height() / (rows as f32 + 1.0);

    let mut node_centers = Vec::new();
    let mut node_rects = Vec::new();

    for (i, block) in cfg.blocks.iter().enumerate() {
        let col = i % cols;
        let row = i / cols;
        let cx = rect.left() + (col as f32 + 1.0) * cell_w;
        let cy = rect.top() + (row as f32 + 1.0) * cell_h;
        let center = egui::pos2(cx, cy);
        node_centers.push(center);

        let node_rect = egui::Rect::from_center_size(center, egui::vec2(50.0, 24.0));
        node_rects.push(node_rect);

        let is_anomalous = cfg.anomalies.iter().any(|a| a.offsets.contains(&block.start_offset));
        let fill = if is_anomalous { c.danger.gamma_multiply(0.5) } else { c.bg_selection };
        let stroke_color = if is_anomalous { c.danger } else { c.border_light };

        painter.rect_filled(node_rect, egui::CornerRadius::same(0), fill);
        painter.rect_stroke(node_rect, egui::CornerRadius::same(0),
            egui::Stroke::new(1.0_f32, stroke_color), egui::StrokeKind::Inside);

        // Block info
        let label = format!("BB{}\n{} insts", i, block.num_instructions);
        painter.text(center, egui::Align2::CENTER_CENTER,
            label, egui::FontId::monospace(8.0), c.text_primary);
    }

    // Draw edges
    for (i, block) in cfg.blocks.iter().enumerate() {
        for (j, &succ_id) in block.successors.iter().enumerate() {
            if succ_id < node_centers.len() && i != succ_id {
                let from = node_centers[i];
                let to = node_centers[succ_id];

                let color = match block.edge_types.get(j) {
                    Some(EdgeType::ConditionalBranch) => egui::Color32::from_rgb(100, 200, 100),
                    Some(EdgeType::UnconditionalJump) => egui::Color32::from_rgb(200, 100, 100),
                    Some(EdgeType::Fallthrough) => egui::Color32::from_gray(150),
                    Some(EdgeType::Call) => egui::Color32::from_rgb(100, 150, 255),
                    Some(EdgeType::Return) => egui::Color32::from_rgb(255, 200, 100),
                    None => c.border_light,
                };

                painter.line_segment([from, to], egui::Stroke::new(1.0_f32, color));

                // Arrow head
                let dir = (to - from).normalized();
                let arrow_size = 6.0;
                let arrow_base = to - dir * arrow_size;
                let perp = egui::vec2(-dir.y, dir.x);
                painter.line_segment(
                    [arrow_base + perp * arrow_size * 0.5, to],
                    egui::Stroke::new(1.5_f32, color),
                );
                painter.line_segment(
                    [arrow_base - perp * arrow_size * 0.5, to],
                    egui::Stroke::new(1.5_f32, color),
                );
            }
        }
    }

    // Anomalies list
    if !cfg.anomalies.is_empty() {
        ui.separator();
        ui.label(egui::RichText::new("Anomalies:")
            .color(c.danger).size(11.0).monospace().strong());
        egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
            for anomaly in &cfg.anomalies {
                ui.label(egui::RichText::new(format!("  ! [{}] {}", anomaly.severity, anomaly.description))
                    .color(c.text_primary).size(11.0).monospace());
            }
        });
    }
}

// ─── Entropy View ──────────────────────────────────────────────────

pub fn entropy_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    let report = match current_report(app) {
        Some(r) => r,
        None => {
            ui.label(egui::RichText::new("No file loaded.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    if report.sections_entropy.is_empty() {
        ui.label(egui::RichText::new("No section entropy data.")
            .color(c.text_secondary).size(11.0).monospace());
        return;
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Section        ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("Entropy  ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("Bar").color(c.text_secondary).size(11.0).monospace().strong());
    });
    ui.separator();

    let bar_max_width = ui.available_width().min(500.0) - 200.0;

    for section in &report.sections_entropy {
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(100.0, 18.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.label(egui::RichText::new(&section.name)
                        .color(c.text_primary).size(11.0).monospace());
                },
            );

            let bar_color = if section.entropy > 7.0 {
                c.danger
            } else if section.entropy > 6.0 {
                c.warn
            } else {
                c.safe
            };

            ui.label(egui::RichText::new(format!("{:.2}  ", section.entropy))
                .color(bar_color).size(11.0).monospace());

            let fraction = (section.entropy / 8.0).min(1.0);
            let bar_width = (fraction * bar_max_width as f64) as f32;
            let bar_rect = egui::Rect::from_min_size(
                ui.cursor().min,
                egui::vec2(bar_width.max(2.0), 14.0),
            );
            ui.painter().rect_filled(bar_rect, egui::CornerRadius::same(0), bar_color);
            ui.advance_cursor_after_rect(bar_rect);
        });
    }
}

// ─── Report View ───────────────────────────────────────────────────

pub fn report_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let report = app.selected_report
        .and_then(|i| app.reports.get(i))
        .or(app.reports.last());

    match report {
        Some(report) => show_report_detail(ui, report, &app.colors),
        None => {
            ui.label(egui::RichText::new("No reports. Scan a file first.")
                .color(app.colors.text_secondary).size(11.0).monospace());
        }
    }
}

// ─── Findings View ─────────────────────────────────────────────────

pub fn findings_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    let report = match current_report(app) {
        Some(r) => r,
        None => {
            ui.label(egui::RichText::new("No reports available.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    if report.findings.is_empty() {
        ui.label(egui::RichText::new("No findings - file appears clean.")
            .color(c.safe).size(11.0).monospace());
        return;
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Severity   ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("Module           ").color(c.text_secondary).size(11.0).monospace().strong());
        ui.label(egui::RichText::new("Description").color(c.text_secondary).size(11.0).monospace().strong());
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        for finding in &report.findings {
            let sev_color = theme::severity_color(&finding.severity);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("{:<12}", format!("{}", finding.severity)))
                    .color(sev_color).size(11.0).monospace());
                ui.label(egui::RichText::new(format!("{:<18}", finding.module))
                    .color(c.text_secondary).size(11.0).monospace());
                ui.label(egui::RichText::new(&finding.description)
                    .color(c.text_primary).size(11.0).monospace());
            });

            if let Some(ref details) = finding.details {
                ui.label(egui::RichText::new(format!("             {}", details))
                    .color(c.text_secondary.gamma_multiply(0.7)).size(10.0).monospace());
            }
        }
    });
}

// ─── Settings View ─────────────────────────────────────────────────

pub fn settings_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("Settings")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.label(egui::RichText::new("Interface").color(c.info).size(12.0).monospace().strong());
        ui.add_space(4.0);
        ui.checkbox(&mut app.settings.show_tooltips,
            egui::RichText::new("Show tooltips").monospace().size(11.0).color(c.text_primary));
        ui.add_space(8.0);

        ui.label(egui::RichText::new("Hex View").color(c.info).size(12.0).monospace().strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Bytes per row:").monospace().size(11.0).color(c.text_primary));
            egui::ComboBox::from_label("")
                .selected_text(app.settings.hex_bytes_per_row.to_string())
                .width(60.0)
                .show_ui(ui, |ui| {
                    for val in [8, 16, 32] {
                        ui.selectable_value(&mut app.settings.hex_bytes_per_row, val, val.to_string());
                    }
                });
        });
        ui.add_space(8.0);

        ui.label(egui::RichText::new("Disassembly").color(c.info).size(12.0).monospace().strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Max instructions:").monospace().size(11.0).color(c.text_primary));
            ui.add(egui::Slider::new(&mut app.settings.disasm_max_instructions, 50..=500));
        });
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Code font size:").monospace().size(11.0).color(c.text_primary));
            ui.add(egui::Slider::new(&mut app.settings.font_size_code, 9.0..=18.0).suffix("px"));
        });
        ui.add_space(8.0);

        ui.label(egui::RichText::new("Data").color(c.info).size(12.0).monospace().strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Max recent files:").monospace().size(11.0).color(c.text_primary));
            ui.add(egui::Slider::new(&mut app.settings.max_recent_files, 5..=50));
        });
        ui.add_space(4.0);
        if ui.button(egui::RichText::new("Clear Recent Files").monospace().size(11.0)).clicked() {
            app.settings.recent_files.clear();
            app.toasts.add("Recent files cleared", ToastKind::Info);
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button(egui::RichText::new("Save Settings").monospace().size(11.0)).clicked() {
                app.settings.save();
                app.toasts.add("Settings saved", ToastKind::Success);
            }
            if ui.button(egui::RichText::new("Reset Defaults").monospace().size(11.0)).clicked() {
                app.settings = crate::theme::AppSettings::default();
                app.settings.save();
                app.toasts.add("Settings reset", ToastKind::Info);
            }
        });

        ui.add_space(4.0);
        ui.label(egui::RichText::new("Config: ~/.config/freakre/settings.toml")
            .color(c.text_secondary.gamma_multiply(0.5)).size(10.0).monospace());
    });
}

// ─── Decompiler / Pseudocode View (F5) ──────────────────────────────

pub fn decompiler_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();
    let fs = app.settings.font_size_code;

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Address:").color(c.text_secondary).size(11.0).monospace());
        let mut addr_str = format!("{:08X}", app.disasm_offset);
        let resp = ui.add_sized(
            egui::vec2(80.0, 18.0),
            egui::TextEdit::singleline(&mut addr_str)
                .font(egui::FontId::monospace(11.0)),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Ok(val) = u64::from_str_radix(&addr_str, 16) {
                app.nav_push(app.disasm_offset);
                app.disasm_offset = val;
                app.decompile_cache.remove(&val);
            }
        }

        ui.separator();
        if ui.small_button("Re-decompile").clicked() {
            app.decompile_cache.remove(&app.disasm_offset);
            app.decompile_at(app.disasm_offset);
        }
        if ui.small_button("Copy").clicked() {
            if let Some(code) = app.decompile_cache.get(&app.disasm_offset) {
                ui.ctx().copy_text(code.clone());
                app.toasts.add("Pseudocode copied", ToastKind::Success);
            }
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new("F5")
                .color(c.text_secondary).size(10.0).monospace());
        });
    });

    ui.separator();

    let addr = app.disasm_offset;
    if !app.decompile_cache.contains_key(&addr) {
        app.decompile_at(addr);
    }

    let pseudocode = app.decompile_cache.get(&addr).cloned()
        .unwrap_or_else(|| "// Nothing to decompile".to_string());

    egui::ScrollArea::vertical()
        .id_salt("pseudocode_scroll")
        .show(ui, |ui| {
            for (i, line) in pseudocode.lines().enumerate() {
                ui.horizontal(|ui| {
                    // Line-number gutter
                    let num = format!("{:4}", i + 1);
                    ui.label(
                        egui::RichText::new(num)
                            .monospace()
                            .size(fs - 1.0)
                            .color(c.comment_color.gamma_multiply(0.8)),
                    );
                    // Syntax-highlighted code line (LayoutJob = fast + correct)
                    let job = highlight_c_line(line, &c, fs);
                    ui.label(job);
                });
            }
        });
}

/// Token-level C syntax highlighting via a LayoutJob.
fn highlight_c_line(line: &str, c: &crate::theme::ThemeColors, fs: f32) -> egui::WidgetText {
    use egui::text::{LayoutJob, TextFormat};

    let mut job = LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;

    let kw_color = c.type_color;         // keywords
    let ty_color = c.type_color;         // types share the keyword color family
    let num_color = egui::Color32::from_rgb(0xB5, 0xCE, 0xA8); // VS Code green numbers
    let str_color = egui::Color32::from_rgb(0xCE, 0x91, 0x78); // VS Code orange strings
    let fn_color = c.func_color;
    let txt_color = c.text_primary;

    let push = |job: &mut LayoutJob, text: &str, color: egui::Color32, bold: bool| {
        job.append(
            text,
            0.0,
            TextFormat::simple(egui::FontId::monospace(fs), color),
        );
        let _ = bold;
    };

    let trimmed_start = line.len() - line.trim_start().len();
    if trimmed_start > 0 {
        push(&mut job, &line[..trimmed_start], txt_color, false);
    }
    let rest = &line[trimmed_start..];

    if rest.starts_with("//") || rest.starts_with('*') && rest.contains("//") {
        push(&mut job, rest, c.comment_color, false);
        return job.into();
    }

    let keywords = [
        "void", "return", "if", "else", "while", "for", "do", "goto", "break",
        "continue", "switch", "case", "default", "struct", "typedef", "unsigned",
        "sizeof", "try", "catch", "const",
    ];
    let types = [
        "bool", "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "float", "double", "char", "int",
    ];

    let bytes = rest.as_bytes();
    let mut i = 0usize;
    let n = rest.len();

    while i < n {
        let b = bytes[i];
        let start = i;

        // String / char literal
        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            while i < n {
                if bytes[i] == b'\\' { i += 2; continue; }
                if bytes[i] == quote { i += 1; break; }
                i += 1;
            }
            push(&mut job, &rest[start..i.min(n)], str_color, false);
            continue;
        }

        // Line comment
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            push(&mut job, &rest[start..], c.comment_color, false);
            break;
        }

        // Number (hex or decimal)
        if b.is_ascii_digit()
            || (b == b'-' && i + 1 < n && bytes[i + 1].is_ascii_digit())
            || (b == b'0' && i + 1 < n && (bytes[i + 1] | 32) == b'x')
        {
            i += 1;
            while i < n
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            push(&mut job, &rest[start..i], num_color, false);
            continue;
        }

        // Identifier / keyword / type / function call
        if b.is_ascii_alphabetic() || b == b'_' {
            i += 1;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let word = &rest[start..i];
            let color = if keywords.contains(&word) {
                kw_color
            } else if types.contains(&word) {
                ty_color
            } else if rest[i..].starts_with('(') {
                fn_color
            } else if word.starts_with("xmm") || word.starts_with('v') && word[1..].chars().all(|ch| ch.is_ascii_digit()) {
                egui::Color32::from_rgb(0x9C, 0xDC, 0xFE) // light blue vars
            } else {
                txt_color
            };
            push(&mut job, word, color, false);
            continue;
        }

        // Everything else (operators, punctuation)
        i += 1;
        push(&mut job, &rest[start..i], c.operand_color, false);
    }

    job.into()
}

// ─── Xrefs View ────────────────────────────────────────────────────

pub fn xrefs_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Xrefs to:").color(c.text_secondary).size(11.0).monospace());
        let mut addr_str = format!("{:08X}", app.xref_query_addr);
        let resp = ui.add_sized(
            egui::vec2(80.0, 18.0),
            egui::TextEdit::singleline(&mut addr_str)
                .font(egui::FontId::monospace(11.0)),
        );
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Ok(val) = u64::from_str_radix(&addr_str, 16) {
                app.xref_query_addr = val;
            }
        }
    });

    ui.separator();

    let summary = app.xref_db.summary();
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("Total xrefs: {}", summary.total_xrefs))
            .color(c.text_primary).size(11.0).monospace());
        ui.separator();
        ui.label(egui::RichText::new(format!("Unique targets: {}", summary.unique_targets))
            .color(c.text_primary).size(11.0).monospace());
        ui.separator();
        ui.label(egui::RichText::new(format!("String xrefs: {}", summary.string_xrefs))
            .color(c.string_color).size(11.0).monospace());
        ui.separator();
        ui.label(egui::RichText::new(format!("Import xrefs: {}", summary.import_xrefs))
            .color(c.func_color).size(11.0).monospace());
    });

    ui.separator();

    ui.label(egui::RichText::new(format!("References to {:08X}:", app.xref_query_addr))
        .color(c.info).size(12.0).monospace().strong());
    if app.xref_query_addr > u32::MAX as u64 {
        ui.label(egui::RichText::new("  (>32-bit address: matching both LE u32 halves)")
            .color(c.warn).size(10.0).monospace());
    }
    ui.add_space(4.0);

    let idx = app.selected_report
        .or_else(|| if app.reports.is_empty() { None } else { Some(app.reports.len() - 1) });
    let data = match get_current_data(app) {
        Some(d) => d,
        None => {
            ui.label(egui::RichText::new("No binary data available.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    let target = app.xref_query_addr;
    let cache_key = (idx.unwrap_or(usize::MAX), target, data.len());

    let found_xrefs = match app.xref_view_cache.get(&cache_key).cloned() {
        Some(hits) => hits,
        None => {
            if idx.is_some() {
                app.enqueue_xref_view_scan(cache_key, data, app.disasm_is_64bit);
            }
            ui.label(egui::RichText::new("  Scanning binary for direct references…")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        if found_xrefs.is_empty() {
            ui.label(egui::RichText::new("  No direct references found in binary.")
                .color(c.text_secondary).size(11.0).monospace());
            ui.label(egui::RichText::new("  (Full xref analysis available after deep scan)")
                .color(c.text_secondary.gamma_multiply(0.6)).size(10.0).monospace());
        } else {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Address    ").color(c.text_secondary).size(11.0).monospace().strong());
                ui.label(egui::RichText::new("Instruction").color(c.text_secondary).size(11.0).monospace().strong());
            });
            ui.separator();

            for (addr, inst_text) in &found_xrefs {
                ui.horizontal(|ui| {
                    let resp = ui.label(egui::RichText::new(format!("{:08X}   ", addr))
                        .color(c.addr_color).size(11.0).monospace());
                    if resp.clicked() {
                        app.nav_push(app.disasm_offset);
                        app.disasm_offset = *addr;
                        app.active_tab = Tab::Disassembly;
                    }
                    if resp.hovered() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }

                    ui.label(egui::RichText::new(inst_text)
                        .color(c.text_primary).size(11.0).monospace());
                });
            }
        }
    });
}

// ─── Structures View ───────────────────────────────────────────────

pub fn structures_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("Structures")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.separator();

    let report = match current_report(app) {
        Some(r) => r,
        None => {
            ui.label(egui::RichText::new("No file loaded.")
                .color(c.text_secondary).size(11.0).monospace());
            return;
        }
    };

    if let Some(ref pe) = report.pe_info {
        ui.label(egui::RichText::new("PE Structures").color(c.info).size(12.0).monospace().strong());
        ui.add_space(4.0);

        egui::CollapsingHeader::new(egui::RichText::new("IMAGE_DOS_HEADER").monospace().size(11.0).color(c.type_color))
            .default_open(false)
            .show(ui, |ui| {
                info_row(ui, "e_magic", "MZ (0x5A4D)", &c);
                info_row(ui, "e_lfanew", &format!("{:#X}", 0), &c);
            });

        egui::CollapsingHeader::new(egui::RichText::new("IMAGE_FILE_HEADER").monospace().size(11.0).color(c.type_color))
            .default_open(false)
            .show(ui, |ui| {
                info_row(ui, "Machine", &pe.machine, &c);
                info_row(ui, "NumberOfSections", &pe.num_sections.to_string(), &c);
                info_row(ui, "TimeDateStamp", &pe.timestamp.to_string(), &c);
            });

        ui.add_space(8.0);
    }

    if let Some(ref elf) = report.elf_info {
        ui.label(egui::RichText::new("ELF Structures").color(c.info).size(12.0).monospace().strong());
        ui.add_space(4.0);

        egui::CollapsingHeader::new(egui::RichText::new("Elf_Header").monospace().size(11.0).color(c.type_color))
            .default_open(false)
            .show(ui, |ui| {
                info_row(ui, "Class", &elf.class, &c);
                info_row(ui, "Endian", &elf.endian, &c);
                info_row(ui, "Machine", &elf.machine, &c);
                info_row(ui, "Type", &elf.elf_type, &c);
                info_row(ui, "Entry Point", &elf.entry_point, &c);
            });

        ui.add_space(8.0);
    }

    ui.separator();
    ui.label(egui::RichText::new("Tip: Press Y on a variable to set its type.")
        .color(c.text_secondary.gamma_multiply(0.6)).size(10.0).monospace());
}

// ─── Scripting REPL View ───────────────────────────────────────────

pub fn scripting_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("Script REPL (Lua-like sandboxed DSL)")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.label(egui::RichText::new("Capabilities: print, type, math. No IO, no network, no time.")
        .color(c.text_secondary).size(10.0).monospace());
    ui.separator();

    // History output
    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
        for (input, output) in &app.repl.output {
            ui.label(egui::RichText::new(format!(">>> {}", input))
                .color(c.text_secondary).size(11.0).monospace());
            ui.label(egui::RichText::new(output)
                .color(c.text_primary).size(11.0).monospace());
            ui.separator();
        }
    });

    ui.separator();

    // Input area
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(">>>").color(c.addr_color).size(12.0).monospace());
        let resp = ui.add_sized(
            egui::vec2(ui.available_width() - 80.0, 22.0),
            egui::TextEdit::singleline(&mut app.repl.input)
                .hint_text("Enter script code...")
                .font(egui::FontId::monospace(11.0)),
        );

        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            app.execute_repl_script();
        }

        if ui.button("Run").clicked() {
            app.execute_repl_script();
        }
        if ui.button("Clear").clicked() {
            app.repl.output.clear();
        }
    });

    ui.add_space(4.0);
    ui.label(egui::RichText::new("Example: local x = 2 + 3; return x * 2")
        .color(c.text_secondary.gamma_multiply(0.6)).size(10.0).monospace());
}

// ─── Plugins View ───────────────────────────────────────────────────

pub fn plugins_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("Plugins Manager")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.separator();

    let plugins = app.plugin_manager.list_plugins();

    if plugins.is_empty() {
        ui.label(egui::RichText::new("No plugins loaded.")
            .color(c.text_secondary).size(11.0).monospace());
    } else {
        egui::ScrollArea::vertical().show(ui, |ui| {
            for meta in &plugins {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&meta.name)
                        .color(c.func_color).size(12.0).monospace().strong());
                    ui.label(egui::RichText::new(format!("v{}", meta.version))
                        .color(c.text_secondary).size(11.0).monospace());
                });
                ui.label(egui::RichText::new(&meta.description)
                    .color(c.text_primary).size(11.0).monospace());
                if let Some(ref author) = meta.author {
                    ui.label(egui::RichText::new(format!("Author: {}", author))
                        .color(c.text_secondary.gamma_multiply(0.7)).size(10.0).monospace());
                }
                ui.separator();
            }
        });
    }

    ui.add_space(8.0);
    ui.label(egui::RichText::new("Plugin dirs:")
        .color(c.text_secondary).size(11.0).monospace().strong());
    ui.label(egui::RichText::new("  ./plugins/")
        .color(c.text_primary).size(10.0).monospace());
    if let Some(d) = dirs::data_dir() {
        ui.label(egui::RichText::new(format!("  {}/freakre/plugins/", d.display()))
            .color(c.text_primary).size(10.0).monospace());
    }
}

// ─── Diffing View ──────────────────────────────────────────────────

pub fn diffing_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("Binary Diffing (Diaphora-style)")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.separator();

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Current binary:").color(c.text_secondary).size(11.0).monospace());
        if let Some(ref p) = app.current_file_path {
            ui.label(egui::RichText::new(p.display().to_string())
                .color(c.text_primary).size(11.0).monospace());
        } else {
            ui.label(egui::RichText::new("(none)").color(c.text_secondary).size(11.0).monospace());
        }
    });

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Other binary:").color(c.text_secondary).size(11.0).monospace());
        if let Some(ref p) = app.diffing_other_path {
            ui.label(egui::RichText::new(p.display().to_string())
                .color(c.text_primary).size(11.0).monospace());
        } else {
            ui.label(egui::RichText::new("(none - use File > Open for Diffing)").color(c.text_secondary).size(11.0).monospace());
        }
        if ui.button("Pick...").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                app.diffing_other_path = Some(path);
            }
        }
    });

    ui.separator();

    if let Some(ref result) = app.diffing_result {
        // Stats
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("Matched: {} / {}", result.stats.matched_count, result.stats.total_functions_a))
                .color(c.safe).size(11.0).monospace());
            ui.separator();
            ui.label(egui::RichText::new(format!("Avg similarity: {:.1}%", result.stats.average_similarity * 100.0))
                .color(c.info).size(11.0).monospace());
            ui.separator();
            ui.label(egui::RichText::new(format!("Perfect: {}", result.stats.perfect_matches))
                .color(c.func_color).size(11.0).monospace());
        });

        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.label(egui::RichText::new("Matched Functions")
                .color(c.info).size(12.0).monospace().strong());
            for m in &result.matches {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("{:08X} {} <-> ", m.address_a, m.name_a))
                        .color(c.addr_color).size(11.0).monospace());
                    ui.label(egui::RichText::new(format!("{:08X} {}", m.address_b, m.name_b))
                        .color(c.func_color).size(11.0).monospace());
                    ui.label(egui::RichText::new(format!("[{:.0}%]", m.similarity * 100.0))
                        .color(c.info).size(11.0).monospace());
                });
            }
        });
    } else {
        ui.label(egui::RichText::new("No diffing result yet.")
            .color(c.text_secondary).size(11.0).monospace());
        ui.label(egui::RichText::new("Diffing requires project-db for both binaries. This feature requires two loaded projects.")
            .color(c.text_secondary.gamma_multiply(0.6)).size(10.0).monospace());
    }
}

// ─── DataFlow View ─────────────────────────────────────────────────

pub fn dataflow_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("DataFlow Analysis")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.label(egui::RichText::new("Reaching definitions, live variables, use-def chains.")
        .color(c.text_secondary).size(10.0).monospace());
    ui.separator();

    if let Some(ref df) = app.dataflow_result {
        let patterns = df.suspicious_patterns();
        ui.label(egui::RichText::new(format!("Suspicious patterns: {}", patterns.len()))
            .color(if patterns.is_empty() { c.safe } else { c.warn }).size(11.0).monospace());

        if !patterns.is_empty() {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for p in &patterns {
                    ui.label(egui::RichText::new(format!("  ! {}", p))
                        .color(c.warn).size(11.0).monospace());
                }
            });
        }

        ui.add_space(8.0);
        ui.label(egui::RichText::new("DataFlow computed for current function (F5 to trigger)")
            .color(c.text_secondary).size(10.0).monospace());
    } else {
        ui.label(egui::RichText::new("No dataflow analysis yet. Press F5 to decompile and compute.")
            .color(c.text_secondary).size(11.0).monospace());
    }
}

// ─── ML Classify View ──────────────────────────────────────────────

pub fn ml_classify_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("ML Malware Classification")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.label(egui::RichText::new("Ensemble of 8 decision trees on 96 features.")
        .color(c.text_secondary).size(10.0).monospace());
    ui.separator();

    if let Some(ref result) = app.ml_result {
        let verdict_color = match format!("{:?}", result.class).to_lowercase().as_str() {
            s if s.contains("malicious") => c.danger,
            s if s.contains("suspicious") => c.warn,
            s if s.contains("packed") => c.info,
            _ => c.safe,
        };

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Class:").color(c.text_secondary).size(12.0).monospace());
            ui.label(egui::RichText::new(format!("{:?}", result.class))
                .color(verdict_color).size(14.0).monospace().strong());
        });

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Confidence:").color(c.text_secondary).size(12.0).monospace());
            ui.label(egui::RichText::new(format!("{:.1}%", result.confidence * 100.0))
                .color(verdict_color).size(14.0).monospace().strong());
        });

        ui.separator();

        ui.label(egui::RichText::new("Explanation:")
            .color(c.info).size(12.0).monospace().strong());
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.label(egui::RichText::new(&result.explanation)
                .color(c.text_primary).size(11.0).monospace());
        });
    } else {
        ui.label(egui::RichText::new("No classification yet. Auto-runs on file load.")
            .color(c.text_secondary).size(11.0).monospace());
        if ui.button("Run ML Classification").clicked() {
            // Can't call &mut self method from &self view, need app to do it
            // This will be handled via menu
        }
    }
}

// ─── Function Signatures View ──────────────────────────────────────

pub fn func_sigs_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let c = app.colors.clone();

    ui.label(egui::RichText::new("Function Signatures (FLIRT-like)")
        .color(c.text_primary).size(14.0).monospace().strong());
    ui.separator();

    if let Some(ref result) = app.func_sigs_result {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("Matches: {}", result.matches.len()))
                .color(c.text_primary).size(11.0).monospace());
            ui.separator();
            ui.label(egui::RichText::new(format!("Libraries: {}", result.libraries_found.len()))
                .color(c.func_color).size(11.0).monospace());
        });

        if let Some(ref compiler) = result.compiler_info {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Compiler:").color(c.text_secondary).size(11.0).monospace());
                ui.label(egui::RichText::new(&compiler.compiler)
                    .color(c.info).size(11.0).monospace().strong());
            });
        }

        ui.separator();

        if !result.libraries_found.is_empty() {
            ui.label(egui::RichText::new("Libraries found:")
                .color(c.info).size(12.0).monospace().strong());
            for lib in &result.libraries_found {
                ui.label(egui::RichText::new(format!("  • {}", lib))
                    .color(c.func_color).size(11.0).monospace());
            }
            ui.add_space(8.0);
        }

        ui.label(egui::RichText::new("Matched functions:")
            .color(c.info).size(12.0).monospace().strong());

        egui::ScrollArea::vertical().show(ui, |ui| {
            for m in &result.matches {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("{:08X} ", m.offset))
                        .color(c.addr_color).size(11.0).monospace());
                    ui.label(egui::RichText::new(format!("{}::{}", m.signature.library, m.signature.function_name))
                        .color(c.func_color).size(11.0).monospace());
                    ui.label(egui::RichText::new(format!(" [{:.0}%]", m.confidence * 100.0))
                        .color(c.text_secondary).size(11.0).monospace());
                });
            }
        });
    } else {
        ui.label(egui::RichText::new("No signature scan yet. Auto-runs on file load.")
            .color(c.text_secondary).size(11.0).monospace());
    }
}

// ─── Modal Dialogs ─────────────────────────────────────────────────

pub fn goto_dialog(ctx: &egui::Context, app: &mut FreakREApp) {
    if !app.show_goto { return; }

    let mut open = app.show_goto;
    egui::Window::new("Go to Address")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(320.0, 100.0))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Address:").monospace().size(12.0));
                let resp = ui.add_sized(
                    egui::vec2(200.0, 24.0),
                    egui::TextEdit::singleline(&mut app.goto_input)
                        .hint_text("hex address or symbol name")
                        .font(egui::FontId::monospace(12.0)),
                );
                resp.request_focus();

                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || ui.button("Go").clicked()
                {
                    let input = app.goto_input.trim();
                    let parsed = input.strip_prefix("0x")
                        .or_else(|| input.strip_prefix("0X"))
                        .unwrap_or(input);
                    if let Ok(addr) = u64::from_str_radix(parsed, 16) {
                        app.nav_push(app.disasm_offset);
                        app.disasm_offset = addr;
                        app.active_tab = Tab::Disassembly;
                        app.show_goto = false;
                    } else {
                        let lower = input.to_lowercase();
                        let idx = app.selected_report
                            .or_else(|| if app.reports.is_empty() { None } else { Some(app.reports.len() - 1) });
                        if let Some(idx) = idx {
                            if let Some(report) = app.reports.get(idx) {
                                let found_addr = report.functions.iter()
                                    .find(|f| f.name.to_lowercase() == lower)
                                    .map(|f| f.address);
                                if let Some(addr) = found_addr {
                                    app.nav_push(app.disasm_offset);
                                    app.disasm_offset = addr;
                                    app.active_tab = Tab::Disassembly;
                                    app.show_goto = false;
                                }
                            }
                        }
                    }
                }
            });
        });
    app.show_goto = open;
}

pub fn rename_dialog(ctx: &egui::Context, app: &mut FreakREApp) {
    if !app.show_rename { return; }

    let mut open = app.show_rename;
    egui::Window::new("Rename")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(360.0, 100.0))
        .show(ctx, |ui| {
            let addr = app.rename_target_addr.unwrap_or(0);
            ui.label(egui::RichText::new(format!("Rename at {:08X}:", addr))
                .monospace().size(11.0).color(app.colors.text_secondary));
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                let resp = ui.add_sized(
                    egui::vec2(240.0, 24.0),
                    egui::TextEdit::singleline(&mut app.rename_input)
                        .hint_text("new_name")
                        .font(egui::FontId::monospace(12.0)),
                );
                resp.request_focus();

                let do_rename = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || ui.button("OK").clicked();

                if do_rename && !app.rename_input.is_empty() {
                    if let Some(addr) = app.rename_target_addr {
                        app.custom_names.insert(addr, app.rename_input.clone());
                        app.log(format!("Renamed {:08X} → {}", addr, app.rename_input));
                        app.toasts.add(format!("Renamed to {}", app.rename_input), ToastKind::Success);

                        // Persist to project-db (blocking write on worker thread)
                        let _ = app.db_tx.send(DbCommand::SetLabel(addr, app.rename_input.clone()));
                    }
                    app.show_rename = false;
                }
            });
        });
    app.show_rename = open;
}

pub fn comment_dialog(ctx: &egui::Context, app: &mut FreakREApp) {
    if !app.show_comment_edit { return; }

    let mut open = app.show_comment_edit;
    egui::Window::new("Edit Comment")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .fixed_size(egui::vec2(400.0, 120.0))
        .show(ctx, |ui| {
            let addr = app.comment_target_addr.unwrap_or(0);
            ui.label(egui::RichText::new(format!("Comment at {:08X}:", addr))
                .monospace().size(11.0).color(app.colors.text_secondary));
            ui.add_space(4.0);

            let resp = ui.add_sized(
                egui::vec2(ui.available_width(), 40.0),
                egui::TextEdit::multiline(&mut app.comment_input)
                    .hint_text("Enter comment...")
                    .font(egui::FontId::monospace(11.0)),
            );
            resp.request_focus();

            ui.horizontal(|ui| {
                if ui.button("OK").clicked() {
                    if let Some(addr) = app.comment_target_addr {
                        if app.comment_input.is_empty() {
                            app.comments.remove(&addr);
                            // Persist (blocking sled write on worker thread)
                            let _ = app.db_tx.send(DbCommand::RemoveComment(addr));
                        } else {
                            let comment = app.comment_input.clone();
                            app.comments.insert(addr, comment.clone());
                            let _ = app.db_tx.send(DbCommand::SetComment(addr, comment));
                        }
                    }
                    app.show_comment_edit = false;
                }
                if ui.button("Cancel").clicked() {
                    app.show_comment_edit = false;
                }
                if ui.button("Clear").clicked() {
                    app.comment_input.clear();
                }
            });
        });
    app.show_comment_edit = open;
}

// ─── Helpers ───────────────────────────────────────────────────────

fn current_report(app: &FreakREApp) -> Option<&FileReport> {
    app.selected_report
        .and_then(|i| app.reports.get(i))
        .or(app.reports.last())
}

fn get_current_data(app: &FreakREApp) -> Option<Arc<Vec<u8>>> {
    let idx = app.selected_report
        .or_else(|| if app.reports.is_empty() { None } else { Some(app.reports.len() - 1) })?;
    app.report_data.get(idx).cloned()
}

fn entry_point_str(report: &FileReport) -> Option<&str> {
    report.pe_info.as_ref().and_then(|p| p.entry_point.as_deref())
        .or(report.macho_info.as_ref().and_then(|m| m.entry_point.as_deref()))
        .or(report.elf_info.as_ref().map(|e| e.entry_point.as_str()))
}

/// Map a PE RVA to a raw file offset via pe-parser. Non-PE inputs and
/// untranslatable RVAs are returned unchanged (legacy behavior).
fn pe_rva_to_file_offset(app: &FreakREApp, rva: u64) -> u64 {
    if rva > u32::MAX as u64 {
        return rva;
    }
    let is_pe = current_report(app).is_some_and(|r| r.pe_info.is_some());
    if !is_pe {
        return rva;
    }
    get_current_data(app)
        .and_then(|data| {
            pe_parser::PeFile::parse(&data)
                .ok()
                .and_then(|pe| pe.rva_to_offset(rva as u32))
        })
        .map(|off| off as u64)
        .unwrap_or(rva)
}

fn info_row(ui: &mut egui::Ui, label: &str, value: &str, colors: &crate::theme::ThemeColors) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(160.0, 16.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(egui::RichText::new(label)
                    .color(colors.text_secondary).size(11.0).monospace());
            },
        );
        ui.label(egui::RichText::new(value)
            .color(colors.text_primary).size(11.0).monospace());
    });
}

fn section_header(ui: &mut egui::Ui, title: &str, colors: &crate::theme::ThemeColors) {
    ui.separator();
    ui.add_space(4.0);
    ui.label(egui::RichText::new(title)
        .color(colors.info).size(12.0).monospace().strong());
    ui.add_space(4.0);
}

fn mitre_tag(ui: &mut egui::Ui, technique: &str, colors: &crate::theme::ThemeColors) {
    ui.label(egui::RichText::new(format!("[{}]", technique))
        .color(colors.info).size(10.0).monospace());
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn show_report_detail(ui: &mut egui::Ui, report: &FileReport, colors: &crate::theme::ThemeColors) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        let file_name = report.path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());

        ui.label(egui::RichText::new(&file_name)
            .color(colors.text_primary).size(14.0).monospace().strong());

        let verdict_color = theme::verdict_color(&report.verdict);
        ui.label(egui::RichText::new(format!("Verdict: {} ({:.1}%)", report.verdict, report.suspicion_score * 100.0))
            .color(verdict_color).size(12.0).monospace());

        ui.separator();

        info_row(ui, "SHA-256", &report.sha256, colors);
        info_row(ui, "MD5", &report.md5, colors);
        info_row(ui, "Size", &format_bytes(report.size), colors);
        info_row(ui, "Type", &report.file_type, colors);
        info_row(ui, "Scan Time", &format!("{} ms", report.scan_duration_ms), colors);
        info_row(ui, "Strings", &report.strings_found.to_string(), colors);

        if let Some(ref pe) = report.pe_info {
            section_header(ui, "PE Header", colors);
            info_row(ui, "Machine", &pe.machine, colors);
            info_row(ui, "Sections", &pe.num_sections.to_string(), colors);
            info_row(ui, "Timestamp", &pe.timestamp.to_string(), colors);
            for w in &pe.warnings {
                ui.label(egui::RichText::new(format!("  ! {}", w))
                    .color(colors.warn).size(11.0).monospace());
            }
        }

        if let Some(ref elf) = report.elf_info {
            section_header(ui, "ELF Header", colors);
            info_row(ui, "Class", &elf.class, colors);
            info_row(ui, "Endian", &elf.endian, colors);
            info_row(ui, "Machine", &elf.machine, colors);
            info_row(ui, "Type", &elf.elf_type, colors);
            info_row(ui, "Entry Point", &elf.entry_point, colors);
            info_row(ui, "Static", &elf.is_statically_linked.to_string(), colors);
            info_row(ui, "Stripped", &elf.is_stripped.to_string(), colors);
        }

        if let Some(ref macho) = report.macho_info {
            section_header(ui, "Mach-O Header", colors);
            info_row(ui, "CPU Type", &macho.cpu_type, colors);
            info_row(ui, "File Type", &macho.file_type, colors);
            info_row(ui, "64-bit", &macho.is_64bit.to_string(), colors);
            info_row(ui, "PIE", &macho.is_pie.to_string(), colors);
            info_row(ui, "Encrypted", &macho.is_encrypted.to_string(), colors);
            info_row(ui, "Segments", &macho.num_segments.to_string(), colors);
            info_row(ui, "Sections", &macho.num_sections.to_string(), colors);
            if let Some(ep) = macho.entry_point.as_deref() {
                info_row(ui, "Entry Point", ep, colors);
            }
            for lib in &macho.imported_dylibs {
                ui.label(egui::RichText::new(format!("  dylib: {}", lib))
                    .color(colors.func_color).size(11.0).monospace());
            }
            for seg in &macho.rwx_segments {
                ui.label(egui::RichText::new(format!("  ! RWX: {}", seg))
                    .color(colors.danger).size(11.0).monospace());
            }
            for w in &macho.warnings {
                ui.label(egui::RichText::new(format!("  ! {}", w))
                    .color(colors.warn).size(11.0).monospace());
            }
        }

        if let Some(ref bd) = report.backdoor_report {
            section_header(ui, "Backdoor Analysis", colors);
            info_row(ui, "Risk Score", &format!("{:.1}%", bd.risk_score * 100.0), colors);
            info_row(ui, "Verdict", &bd.verdict, colors);
            info_row(ui, "Findings", &bd.num_findings.to_string(), colors);
            for t in &bd.mitre_techniques {
                mitre_tag(ui, t, colors);
            }
        }

        if let Some(ref sc) = report.shellcode_report {
            section_header(ui, "Shellcode Analysis", colors);
            info_row(ui, "Verdict", &sc.verdict, colors);
            info_row(ui, "Findings", &sc.num_findings.to_string(), colors);
            for h in &sc.api_hashes_resolved {
                ui.label(egui::RichText::new(format!("  hash: {}", h))
                    .color(colors.func_color).size(11.0).monospace());
            }
        }

        if let Some(ref cfg) = report.cfg_summary {
            section_header(ui, "Control Flow Graph", colors);
            info_row(ui, "Blocks", &cfg.num_blocks.to_string(), colors);
            info_row(ui, "Edges", &cfg.num_edges.to_string(), colors);
            info_row(ui, "Instructions", &cfg.total_instructions.to_string(), colors);
            info_row(ui, "Anomalies", &cfg.num_anomalies.to_string(), colors);
            for a in &cfg.anomalies {
                ui.label(egui::RichText::new(format!("  ! {}", a))
                    .color(colors.warn).size(11.0).monospace());
            }
        }

        if let Some(ref sig) = report.signature_summary {
            section_header(ui, "Function Signatures", colors);
            info_row(ui, "Matches", &sig.num_matches.to_string(), colors);
            if let Some(compiler) = sig.compiler.as_deref() {
                info_row(ui, "Compiler", compiler, colors);
            }
            for lib in &sig.libraries_found {
                ui.label(egui::RichText::new(format!("  lib: {}", lib))
                    .color(colors.func_color).size(11.0).monospace());
            }
        }

        if let Some(ref xref) = report.xref_summary {
            section_header(ui, "Cross-References", colors);
            info_row(ui, "Total Xrefs", &xref.total_xrefs.to_string(), colors);
            info_row(ui, "Unique Targets", &xref.unique_targets.to_string(), colors);
            info_row(ui, "String Xrefs", &xref.string_xrefs.to_string(), colors);
            info_row(ui, "Import Xrefs", &xref.import_xrefs.to_string(), colors);
        }
    });
}
