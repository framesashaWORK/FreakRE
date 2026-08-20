use eframe::egui;
use bibleteks_scanner::report::{FileReport, Verdict};

use crate::app::FreakREApp;
use crate::theme::{self, ThemeId, ToastKind};

// ─── Dashboard View ──────────────────────────────────────────────

pub fn dashboard_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    ui.add_space(20.0);

    // Title
    ui.vertical_centered(|ui| {
        ui.heading(
            egui::RichText::new("FreakRE — Reverse Engineering Framework")
                .color(app.colors.text_primary)
                .size(28.0),
        );
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new("Drag & drop files or click to browse")
                .color(app.colors.text_secondary)
                .size(14.0),
        );
    });

    ui.add_space(30.0);

    // Drop zone
    let drop_zone = egui::Frame::new()
        .fill(app.colors.bg_frame)
        .stroke(egui::Stroke::new(
            2.0_f32,
            if app.drag_hovered {
                app.colors.accent
            } else {
                app.colors.border
            },
        ))
        .corner_radius(egui::CornerRadius::same(12))
        .inner_margin(egui::Margin::symmetric(40, 60))
        .shadow(app.colors.shadow);

    let response = drop_zone.show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new("📁")
                    .size(48.0)
                    .color(app.colors.accent),
            );
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new("Drop files here")
                    .size(18.0)
                    .color(app.colors.text_primary),
            );
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("PE32, PE32+, ELF, Mach-O supported")
                    .size(12.0)
                    .color(app.colors.text_secondary),
            );
        });
    }).response;

    // Handle drag & drop
    if response.hovered() {
        app.drag_hovered = true;
    } else {
        app.drag_hovered = false;
    }

    if let Some(dropped) = ui.ctx().input(|i| i.raw.dropped_files.first().cloned()) {
        if let Some(path) = dropped.path {
            app.scan_files(vec![path]);
        }
    }

    ui.add_space(20.0);

    // Browse button
    ui.vertical_centered(|ui| {
        let btn = ui.button(
            egui::RichText::new("Browse Files")
                .color(egui::Color32::WHITE)
                .size(14.0),
        );
        if btn.clicked() {
            if let Some(paths) = rfd::FileDialog::new()
                .set_title("Select files to analyze")
                .pick_files()
            {
                app.scan_files(paths);
            }
        }
    });

    ui.add_space(30.0);

    // Stats cards
    if !app.reports.is_empty() {
        ui.horizontal(|ui| {
            let total = app.reports.len();
            let malicious = app.reports.iter().filter(|r| r.verdict == Verdict::Malicious).count();
            let suspicious = app.reports.iter().filter(|r| r.verdict == Verdict::Suspicious).count();
            let clean = app.reports.iter().filter(|r| r.verdict == Verdict::Clean).count();

            stat_card(ui, "Total", &total.to_string(), app.colors.accent, &app.colors);
            stat_card(ui, "Malicious", &malicious.to_string(), app.colors.danger, &app.colors);
            stat_card(ui, "Suspicious", &suspicious.to_string(), app.colors.warn, &app.colors);
            stat_card(ui, "Clean", &clean.to_string(), app.colors.safe, &app.colors);
        });

        ui.add_space(20.0);

        // Recent scans table
        ui.heading(egui::RichText::new("Recent Scans").color(app.colors.text_primary).size(16.0));
        ui.add_space(8.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("recent_scans")
                .num_columns(5)
                .spacing([12.0, 8.0])
                .striped(true)
                .show(ui, |ui| {
                    for header in ["File", "Type", "Verdict", "Score", "Time"] {
                        ui.label(
                            egui::RichText::new(header)
                                .strong()
                                .color(app.colors.text_secondary)
                                .size(11.0),
                        );
                    }
                    ui.end_row();

                    for (_idx, report) in app.reports.iter().enumerate().rev() {
                        let file_name = report.path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown".into());

                        ui.label(egui::RichText::new(&file_name).color(app.colors.text_primary).size(13.0));
                        ui.label(egui::RichText::new(&report.file_type).color(app.colors.text_secondary).size(12.0));

                        let verdict_color = theme::verdict_color(&report.verdict);
                        ui.label(egui::RichText::new(format!("{}", report.verdict)).color(verdict_color).size(12.0));

                        let score_pct = format!("{:.0}%", report.suspicion_score * 100.0);
                        ui.label(egui::RichText::new(score_pct).color(app.colors.text_primary).size(12.0));

                        let time_ms = format!("{}ms", report.scan_duration_ms);
                        ui.label(egui::RichText::new(time_ms).color(app.colors.text_secondary).size(12.0));

                        ui.end_row();
                    }
                });
        });
    }

    // Recent files section
    if !app.settings.recent_files.is_empty() {
        ui.add_space(24.0);
        ui.heading(egui::RichText::new("Recent Files").color(app.colors.text_primary).size(16.0));
        ui.add_space(8.0);

        let recent_files: Vec<String> = app.settings.recent_files.iter().take(10).cloned().collect();
        for path_str in &recent_files {
            let fname = std::path::Path::new(path_str)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path_str.clone());

            let frame = egui::Frame::new()
                .fill(app.colors.bg_frame)
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(12, 6))
                .stroke(egui::Stroke::new(1.0_f32, app.colors.border));

            let resp = frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("📄").size(12.0).color(app.colors.text_secondary));
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(&fname).color(app.colors.text_primary).size(12.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(path_str).color(app.colors.text_secondary.gamma_multiply(0.5)).size(10.0));
                    });
                });
            }).response;

            if resp.clicked() {
                let path = std::path::PathBuf::from(path_str);
                if path.exists() {
                    app.scan_files(vec![path]);
                } else {
                    app.toasts.add("File no longer exists", ToastKind::Warning);
                }
            }
            ui.add_space(3.0);
        }
    }
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32, colors: &crate::theme::ThemeColors) {
    let frame = egui::Frame::new()
        .fill(colors.bg_frame)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(20, 16))
        .stroke(egui::Stroke::new(1.0_f32, colors.border))
        .shadow(colors.shadow);

    frame.show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new(value).color(color).size(28.0).strong());
            ui.add_space(4.0);
            ui.label(egui::RichText::new(label).color(colors.text_secondary).size(12.0));
        });
    });
}

// ─── Report View ─────────────────────────────────────────────────

pub fn report_view(ui: &mut egui::Ui, app: &FreakREApp) {
    if let Some(idx) = app.selected_report {
        if let Some(report) = app.reports.get(idx) {
            show_report_detail(ui, report, &app.colors);
        }
    } else if let Some(report) = app.reports.last() {
        show_report_detail(ui, report, &app.colors);
    } else {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(100.0);
            ui.label(
                egui::RichText::new("No reports yet. Scan some files first.")
                    .color(app.colors.text_secondary)
                    .size(16.0),
            );
        });
    }
}

// ─── Plugins View ────────────────────────────────────────────────

pub fn plugins_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    ui.add_space(12.0);
    ui.heading(egui::RichText::new("🧩 System Plugins").color(app.colors.text_primary).size(22.0));
    ui.add_space(8.0);

    let plugin_names = freakre_sys_plugins::system_plugin_names();
    ui.label(egui::RichText::new(format!("{} system plugins loaded", plugin_names.len())).color(app.colors.safe).size(13.0));
    ui.add_space(8.0);

    for name in &plugin_names {
        let frame = egui::Frame::new()
            .fill(app.colors.bg_frame)
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(16, 10))
            .stroke(egui::Stroke::new(1.0_f32, app.colors.border));
        frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("✅").size(14.0));
                ui.add_space(8.0);
                ui.label(egui::RichText::new(*name).color(app.colors.text_primary).size(13.0).strong());
            });
        });
        ui.add_space(4.0);
    }

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);

    ui.heading(egui::RichText::new("Plugin Output").color(app.colors.text_primary).size(16.0));
    ui.add_space(4.0);

    if app.plugin_output.is_empty() {
        ui.label(egui::RichText::new("No plugin output yet.").color(app.colors.text_secondary).size(12.0));
    } else {
        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            for line in app.plugin_output.iter().rev() {
                ui.label(egui::RichText::new(line).color(app.colors.text_primary).size(11.0).monospace());
            }
        });
    }
}

fn show_report_detail(ui: &mut egui::Ui, report: &FileReport, colors: &crate::theme::ThemeColors) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.add_space(12.0);

        let file_name = report.path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());

        ui.horizontal(|ui| {
            ui.heading(egui::RichText::new(&file_name).color(colors.text_primary).size(22.0));
            ui.add_space(12.0);

            let verdict_color = theme::verdict_color(&report.verdict);
            let verdict_frame = egui::Frame::new()
                .fill(verdict_color.gamma_multiply(0.15))
                .corner_radius(egui::CornerRadius::same(4))
                .inner_margin(egui::Margin::symmetric(10, 4));
            verdict_frame.show(ui, |ui| {
                ui.label(egui::RichText::new(format!("{}", report.verdict)).color(verdict_color).size(13.0).strong());
            });
        });

        ui.add_space(16.0);

        info_row(ui, "SHA-256", &report.sha256, colors);
        info_row(ui, "MD5", &report.md5, colors);
        info_row(ui, "Size", &format_bytes(report.size), colors);
        info_row(ui, "Type", &report.file_type, colors);
        info_row(ui, "Score", &format!("{:.1}%", report.suspicion_score * 100.0), colors);
        info_row(ui, "Scan Time", &format!("{} ms", report.scan_duration_ms), colors);
        info_row(ui, "Strings Found", &report.strings_found.to_string(), colors);

        ui.add_space(16.0);

        if let Some(ref pe) = report.pe_info {
            section_header(ui, "PE Header", colors);
            info_row(ui, "Machine", &pe.machine, colors);
            info_row(ui, "Sections", &pe.num_sections.to_string(), colors);
            info_row(ui, "Timestamp", &pe.timestamp.to_string(), colors);
            if !pe.warnings.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Warnings:").color(colors.warn).size(12.0));
                for w in &pe.warnings {
                    ui.label(egui::RichText::new(format!("  ⚠ {}", w)).color(colors.text_secondary).size(11.0));
                }
            }
            ui.add_space(12.0);
        }

        if let Some(ref elf) = report.elf_info {
            section_header(ui, "ELF Header", colors);
            info_row(ui, "Class", &elf.class, colors);
            info_row(ui, "Endian", &elf.endian, colors);
            info_row(ui, "Machine", &elf.machine, colors);
            info_row(ui, "Type", &elf.elf_type, colors);
            info_row(ui, "Entry Point", &elf.entry_point, colors);
            info_row(ui, "Statically Linked", &elf.is_statically_linked.to_string(), colors);
            info_row(ui, "Stripped", &elf.is_stripped.to_string(), colors);
            ui.add_space(12.0);
        }

        if let Some(ref macho) = report.macho_info {
            section_header(ui, "Mach-O Header", colors);
            info_row(ui, "CPU Type", &macho.cpu_type, colors);
            info_row(ui, "CPU Subtype", &format!("0x{:08X}", macho.cpu_subtype), colors);
            info_row(ui, "File Type", &macho.file_type, colors);
            info_row(ui, "64-bit", &macho.is_64bit.to_string(), colors);
            info_row(ui, "Flags", &format!("0x{:08X}", macho.flags), colors);
            info_row(ui, "PIE", &macho.is_pie.to_string(), colors);
            info_row(ui, "Restricted", &macho.is_restricted.to_string(), colors);
            info_row(ui, "Encrypted", &macho.is_encrypted.to_string(), colors);
            info_row(ui, "Code Signature", &macho.has_code_signature.to_string(), colors);
            info_row(ui, "Segments", &macho.num_segments.to_string(), colors);
            info_row(ui, "Sections", &macho.num_sections.to_string(), colors);
            if let Some(ref ep) = macho.entry_point {
                info_row(ui, "Entry Point", ep, colors);
            }
            if !macho.imported_dylibs.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Imported Dylibs:").color(colors.accent).size(12.0));
                for lib in &macho.imported_dylibs {
                    ui.label(egui::RichText::new(format!("  • {}", lib)).color(colors.text_secondary).size(11.0));
                }
            }
            if !macho.rwx_segments.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("RWX Segments:").color(colors.danger).size(12.0));
                for seg in &macho.rwx_segments {
                    ui.label(egui::RichText::new(format!("  ⚠ {}", seg)).color(colors.danger).size(11.0));
                }
            }
            if !macho.warnings.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Warnings:").color(colors.warn).size(12.0));
                for w in &macho.warnings {
                    ui.label(egui::RichText::new(format!("  ⚠ {}", w)).color(colors.text_secondary).size(11.0));
                }
            }
            ui.add_space(12.0);
        }

        if let Some(ref bd) = report.backdoor_report {
            section_header(ui, "Backdoor Analysis", colors);
            info_row(ui, "Risk Score", &format!("{:.1}%", bd.risk_score * 100.0), colors);
            info_row(ui, "Verdict", &bd.verdict, colors);
            info_row(ui, "Findings", &bd.num_findings.to_string(), colors);
            if !bd.mitre_techniques.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("MITRE ATT&CK:").color(colors.accent).size(12.0));
                for t in &bd.mitre_techniques {
                    mitre_tag(ui, t, colors);
                }
            }
            ui.add_space(12.0);
        }

        if let Some(ref sc) = report.shellcode_report {
            section_header(ui, "Shellcode Analysis", colors);
            info_row(ui, "Verdict", &sc.verdict, colors);
            info_row(ui, "Findings", &sc.num_findings.to_string(), colors);
            if !sc.api_hashes_resolved.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Resolved API Hashes:").color(colors.accent).size(12.0));
                for h in &sc.api_hashes_resolved {
                    ui.label(egui::RichText::new(format!("  • {}", h)).color(colors.text_secondary).size(11.0));
                }
            }
            ui.add_space(12.0);
        }

        if let Some(ref cfg) = report.cfg_summary {
            section_header(ui, "Control Flow Graph", colors);
            info_row(ui, "Basic Blocks", &cfg.num_blocks.to_string(), colors);
            info_row(ui, "Edges", &cfg.num_edges.to_string(), colors);
            info_row(ui, "Instructions", &cfg.total_instructions.to_string(), colors);
            info_row(ui, "Anomalies", &cfg.num_anomalies.to_string(), colors);
            if !cfg.anomalies.is_empty() {
                ui.add_space(4.0);
                for a in &cfg.anomalies {
                    ui.label(egui::RichText::new(format!("  ⚠ {}", a)).color(colors.warn).size(11.0));
                }
            }
            ui.add_space(12.0);
        }

        if let Some(ref sig) = report.signature_summary {
            section_header(ui, "Function Signatures", colors);
            info_row(ui, "Matches", &sig.num_matches.to_string(), colors);
            if let Some(ref compiler) = sig.compiler {
                info_row(ui, "Compiler", compiler, colors);
            }
            if !sig.libraries_found.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Libraries:").color(colors.accent).size(12.0));
                for lib in &sig.libraries_found {
                    ui.label(egui::RichText::new(format!("  • {}", lib)).color(colors.text_secondary).size(11.0));
                }
            }
            ui.add_space(12.0);
        }

        if let Some(ref xref) = report.xref_summary {
            section_header(ui, "Cross-References", colors);
            info_row(ui, "Total Xrefs", &xref.total_xrefs.to_string(), colors);
            info_row(ui, "Unique Targets", &xref.unique_targets.to_string(), colors);
            info_row(ui, "String Xrefs", &xref.string_xrefs.to_string(), colors);
            info_row(ui, "Import Xrefs", &xref.import_xrefs.to_string(), colors);
            info_row(ui, "Correlated Pairs", &xref.correlated_pairs.to_string(), colors);
            ui.add_space(12.0);
        }

        ui.add_space(20.0);
    });
}

// ─── Findings View ───────────────────────────────────────────────

pub fn findings_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let report = app.selected_report
        .and_then(|i| app.reports.get(i))
        .or(app.reports.last());

    if let Some(report) = report {
        ui.add_space(12.0);
        ui.heading(egui::RichText::new("Findings").color(app.colors.text_primary).size(20.0));
        ui.add_space(8.0);

        if report.findings.is_empty() {
            ui.label(egui::RichText::new("No findings — file appears clean.").color(app.colors.safe).size(14.0));
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for finding in &report.findings {
                let sev_color = theme::severity_color(&finding.severity);

                let frame = egui::Frame::new()
                    .fill(app.colors.bg_frame)
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::same(12))
                    .stroke(egui::Stroke::new(1.0_f32, sev_color.gamma_multiply(0.3)));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let badge_frame = egui::Frame::new()
                            .fill(sev_color.gamma_multiply(0.2))
                            .corner_radius(egui::CornerRadius::same(3))
                            .inner_margin(egui::Margin::symmetric(8, 2));
                        badge_frame.show(ui, |ui| {
                            ui.label(egui::RichText::new(format!("{}", finding.severity)).color(sev_color).size(11.0).strong());
                        });

                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&finding.module).color(app.colors.text_secondary).size(11.0));
                        ui.label(egui::RichText::new("•").color(app.colors.border).size(11.0));
                        ui.label(egui::RichText::new(&finding.rule_id).color(app.colors.accent).size(11.0));
                    });

                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(&finding.description).color(app.colors.text_primary).size(13.0));

                    if let Some(ref details) = finding.details {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(details).color(app.colors.text_secondary).size(11.0));
                    }
                });

                ui.add_space(6.0);
            }
        });
    } else {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(100.0);
            ui.label(egui::RichText::new("No reports available.").color(app.colors.text_secondary).size(16.0));
        });
    }
}

// ─── Entropy View ────────────────────────────────────────────────

pub fn entropy_view(ui: &mut egui::Ui, app: &FreakREApp) {
    let report = app.selected_report
        .and_then(|i| app.reports.get(i))
        .or(app.reports.last());

    if let Some(report) = report {
        ui.add_space(12.0);
        ui.heading(egui::RichText::new("Section Entropy").color(app.colors.text_primary).size(20.0));
        ui.add_space(16.0);

        if report.sections_entropy.is_empty() {
            ui.label(egui::RichText::new("No section data available.").color(app.colors.text_secondary).size(14.0));
            return;
        }

        let max_entropy = 8.0;
        let bar_height = 28.0;
        let chart_width = ui.available_width().min(700.0);

        for section in &report.sections_entropy {
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(120.0, bar_height),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.label(egui::RichText::new(&section.name).color(app.colors.text_primary).size(12.0));
                    },
                );

                let fraction = (section.entropy / max_entropy).min(1.0);
                let bar_color = if section.entropy > 7.0 {
                    app.colors.danger
                } else if section.entropy > 6.0 {
                    app.colors.warn
                } else {
                    app.colors.safe
                };

                let bar_width = (fraction * (chart_width as f64 - 200.0)) as f32;
                let bar_rect = egui::Rect::from_min_size(
                    ui.cursor().min,
                    egui::vec2(bar_width.max(2.0), bar_height - 4.0),
                );
                ui.painter().rect_filled(bar_rect, egui::CornerRadius::same(4), bar_color);

                ui.advance_cursor_after_rect(bar_rect);
                ui.add_space(8.0);

                ui.label(
                    egui::RichText::new(format!("{:.2}", section.entropy))
                        .color(bar_color)
                        .size(12.0)
                        .strong(),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(&section.classification)
                        .color(app.colors.text_secondary)
                        .size(11.0),
                );
            });

            ui.add_space(4.0);
        }
    } else {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(100.0);
            ui.label(egui::RichText::new("No reports available.").color(app.colors.text_secondary).size(16.0));
        });
    }
}

// ─── Settings View ───────────────────────────────────────────────

pub fn settings_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    ui.add_space(12.0);
    ui.heading(egui::RichText::new("⚙️ Settings").color(app.colors.text_primary).size(22.0));
    ui.add_space(16.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // ─── Theme Selection ─────────────────────────────────────
        settings_section(ui, "Appearance", &app.colors, |ui| {
            ui.label(egui::RichText::new("Theme").color(app.colors.text_primary).size(13.0));
            ui.add_space(4.0);

            egui::ComboBox::from_label("")
                .selected_text(app.settings.theme.label())
                .width(250.0)
                .show_ui(ui, |ui| {
                    for theme_id in ThemeId::all() {
                        ui.selectable_value(&mut app.settings.theme, *theme_id, theme_id.label());
                    }
                });

            ui.add_space(8.0);

            // Accent color
            ui.label(egui::RichText::new("Accent Color").color(app.colors.text_primary).size(13.0));
            ui.add_space(4.0);
            let mut accent = [
                app.settings.accent_color[0] as f32 / 255.0,
                app.settings.accent_color[1] as f32 / 255.0,
                app.settings.accent_color[2] as f32 / 255.0,
            ];
            if ui.color_edit_button_rgb(&mut accent).changed() {
                app.settings.accent_color = [
                    (accent[0] * 255.0) as u8,
                    (accent[1] * 255.0) as u8,
                    (accent[2] * 255.0) as u8,
                ];
            }

            ui.add_space(8.0);

            // Font sizes
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("UI Font Size:").color(app.colors.text_primary).size(13.0));
                ui.add(egui::Slider::new(&mut app.settings.font_size_ui, 10.0..=20.0).suffix("px"));
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Code Font Size:").color(app.colors.text_primary).size(13.0));
                ui.add(egui::Slider::new(&mut app.settings.font_size_code, 9.0..=16.0).suffix("px"));
            });
        });

        ui.add_space(12.0);

        // ─── Interface ───────────────────────────────────────────
        settings_section(ui, "Interface", &app.colors, |ui| {
            ui.checkbox(&mut app.settings.show_tooltips, 
                egui::RichText::new("Show tooltips").color(app.colors.text_primary).size(13.0));
            ui.add_space(4.0);
            ui.checkbox(&mut app.settings.sidebar_collapsed,
                egui::RichText::new("Collapse sidebar by default").color(app.colors.text_primary).size(13.0));
        });

        ui.add_space(12.0);

        // ─── Hex View ────────────────────────────────────────────
        settings_section(ui, "Hex View", &app.colors, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Bytes per row:").color(app.colors.text_primary).size(13.0));
                egui::ComboBox::from_label("")
                    .selected_text(app.settings.hex_bytes_per_row.to_string())
                    .width(80.0)
                    .show_ui(ui, |ui| {
                        for val in [8, 16, 32] {
                            ui.selectable_value(&mut app.settings.hex_bytes_per_row, val, val.to_string());
                        }
                    });
            });
        });

        ui.add_space(12.0);

        // ─── Disassembly ─────────────────────────────────────────
        settings_section(ui, "Disassembly", &app.colors, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Max instructions:").color(app.colors.text_primary).size(13.0));
                ui.add(egui::Slider::new(&mut app.settings.disasm_max_instructions, 50..=500));
            });
        });

        ui.add_space(12.0);

        // ─── Data Management ─────────────────────────────────────
        settings_section(ui, "Data", &app.colors, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Max recent files:").color(app.colors.text_primary).size(13.0));
                ui.add(egui::Slider::new(&mut app.settings.max_recent_files, 5..=50));
            });
            ui.add_space(8.0);
            if ui.button(egui::RichText::new("Clear Recent Files").size(13.0)).clicked() {
                app.settings.recent_files.clear();
                app.toasts.add("Recent files cleared", ToastKind::Info);
            }
        });

        ui.add_space(20.0);

        // Apply button
        ui.horizontal(|ui| {
            if ui.button(egui::RichText::new("💾 Apply & Save").color(egui::Color32::WHITE).size(14.0)).clicked() {
                app.apply_current_theme(ui.ctx());
                app.toasts.add("Settings saved", ToastKind::Success);
            }
            if ui.button(egui::RichText::new("↺ Reset to Defaults").size(14.0)).clicked() {
                app.settings = crate::theme::AppSettings::default();
                app.apply_current_theme(ui.ctx());
                app.toasts.add("Settings reset to defaults", ToastKind::Info);
            }
        });

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Settings are saved automatically to ~/.config/freakre/settings.toml")
                .color(app.colors.text_secondary.gamma_multiply(0.6))
                .size(10.0),
        );
    });
}

fn settings_section(ui: &mut egui::Ui, title: &str, colors: &crate::theme::ThemeColors, content: impl FnOnce(&mut egui::Ui)) {
    let frame = egui::Frame::new()
        .fill(colors.bg_frame)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::same(16))
        .stroke(egui::Stroke::new(1.0_f32, colors.border));

    frame.show(ui, |ui| {
        ui.heading(egui::RichText::new(title).color(colors.accent).size(15.0));
        ui.add_space(10.0);
        content(ui);
    });
}

// ─── YARA Rules Panel (used from Settings or Plugins) ──────────

#[allow(dead_code)]
pub fn yara_panel(ui: &mut egui::Ui, app: &mut FreakREApp) {
    ui.add_space(12.0);
    ui.heading(egui::RichText::new("Advanced Analysis").color(app.colors.text_primary).size(22.0));
    ui.add_space(12.0);

    let yara_frame = egui::Frame::new()
        .fill(app.colors.bg_frame)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::same(16))
        .stroke(egui::Stroke::new(1.0_f32, app.colors.border));

    yara_frame.show(ui, |ui| {
        ui.heading(egui::RichText::new("🛡 YARA Rules").color(app.colors.accent).size(16.0));
        ui.add_space(8.0);

        let current_status = if let Some(ref path) = app.yara_rules_path {
            format!("✅ Loaded: {}", path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "unknown".into()))
        } else {
            "⚠ No YARA rules loaded".to_string()
        };
        ui.label(egui::RichText::new(&current_status).color(app.colors.text_secondary).size(12.0));
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button(egui::RichText::new("📂 Load YARA Rules (.yar)").size(13.0)).clicked() {
                if let Some(file) = rfd::FileDialog::new()
                    .add_filter("YARA Rules", &["yar", "yara"])
                    .set_title("Select YARA rules file")
                    .pick_file()
                {
                    app.load_yara_rules(file);
                }
            }
            if app.yara_rules_path.is_some() {
                if ui.button(egui::RichText::new("❌ Clear").size(13.0)).clicked() {
                    app.yara_rules_path = None;
                }
            }
        });
    });

    ui.add_space(16.0);

    ui.heading(egui::RichText::new("Upcoming Features").color(app.colors.text_primary).size(16.0));
    ui.add_space(8.0);

    let features = [
        ("🔗 Cross-Reference Explorer", "Interactive xref graph with filtering"),
        ("📊 CFG Visualization", "Control flow graph with anomaly highlighting"),
        ("🔍 Hex Dump Viewer", "Byte-level view with entropy overlay"),
        ("⚙️ Disassembly View", "Integrated disassembler around points of interest"),
        ("📝 FLIRT Signature Editor", "Create and manage function signatures"),
    ];

    for (icon, desc) in features {
        let frame = egui::Frame::new()
            .fill(app.colors.bg_frame)
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(16, 10))
            .stroke(egui::Stroke::new(1.0_f32, app.colors.border));

        frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(icon).size(16.0));
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(icon.split(' ').skip(1).collect::<Vec<_>>().join(" ")).color(app.colors.text_primary).size(13.0).strong());
                    ui.label(egui::RichText::new(desc).color(app.colors.text_secondary).size(11.0));
                });
            });
        });
        ui.add_space(6.0);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

fn info_row(ui: &mut egui::Ui, label: &str, value: &str, colors: &crate::theme::ThemeColors) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(140.0, 20.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(egui::RichText::new(label).color(colors.text_secondary).size(12.0));
            },
        );
        ui.label(egui::RichText::new(value).color(colors.text_primary).size(12.0));
    });
    ui.add_space(2.0);
}

fn section_header(ui: &mut egui::Ui, title: &str, colors: &crate::theme::ThemeColors) {
    ui.separator();
    ui.add_space(8.0);
    ui.heading(egui::RichText::new(title).color(colors.accent).size(15.0));
    ui.add_space(6.0);
}

fn mitre_tag(ui: &mut egui::Ui, technique: &str, colors: &crate::theme::ThemeColors) {
    let frame = egui::Frame::new()
        .fill(colors.accent.gamma_multiply(0.15))
        .corner_radius(egui::CornerRadius::same(3))
        .inner_margin(egui::Margin::symmetric(6, 2));
    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(technique).color(colors.accent).size(10.0));
    });
    ui.add_space(4.0);
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

// ─── Hex View ──────────────────────────────────────────────────────

pub fn hex_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    ui.add_space(12.0);
    ui.heading(egui::RichText::new("Hex Dump").color(app.colors.text_primary).size(20.0));
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Offset:").color(app.colors.text_secondary).size(12.0));
        let mut offset_str = format!("0x{:08X}", app.hex_offset);
        let resp = ui.text_edit_singleline(&mut offset_str);
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Ok(val) = u64::from_str_radix(offset_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                app.hex_offset = val as usize;
            }
        }

        ui.add_space(12.0);

        ui.label(egui::RichText::new("Search:").color(app.colors.text_secondary).size(12.0));
        ui.text_edit_singleline(&mut app.hex_search);

        if ui.button("Find").clicked() && !app.hex_search.is_empty() {
            if let Some(data) = get_current_data(app) {
                let search_bytes = app.hex_search.as_bytes();
                let start = app.hex_offset + 1;
                if let Some(pos) = data[start..].windows(search_bytes.len()).position(|w| w == search_bytes) {
                    app.hex_offset = start + pos;
                }
            }
        }

        ui.add_space(12.0);
        if ui.button("⏪ 0x0").clicked() { app.hex_offset = 0; }
        if ui.button("◀ -0x100").clicked() { app.hex_offset = app.hex_offset.saturating_sub(0x100); }
        if ui.button("▶ +0x100").clicked() {
            if let Some(data) = get_current_data(app) {
                app.hex_offset = (app.hex_offset + 0x100).min(data.len().saturating_sub(16));
            }
        }
    });

    ui.add_space(8.0);

    let data = match get_current_data(app) {
        Some(d) => d,
        None => {
            ui.label(egui::RichText::new("No file loaded. Scan a file first.").color(app.colors.text_secondary).size(14.0));
            return;
        }
    };

    if data.is_empty() {
        ui.label(egui::RichText::new("File is empty.").color(app.colors.text_secondary).size(14.0));
        return;
    }

    ui.label(egui::RichText::new(format!("File size: {} (0x{:X} bytes)", format_bytes(data.len() as u64), data.len())).color(app.colors.text_secondary).size(11.0));
    ui.add_space(4.0);

    let bytes_per_row = app.settings.hex_bytes_per_row;
    let start = app.hex_offset & !(bytes_per_row - 1);
    let end = (start + 0x400).min(data.len());

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Offset  ").color(app.colors.accent).size(app.settings.font_size_code).monospace());
            for i in 0..bytes_per_row {
                ui.label(egui::RichText::new(format!("{:02X} ", i)).color(app.colors.text_secondary).size(app.settings.font_size_code).monospace());
            }
            ui.label(egui::RichText::new(" ASCII").color(app.colors.text_secondary).size(app.settings.font_size_code).monospace());
        });
        ui.separator();

        let mut offset = start;
        while offset < end {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("{:08X}  ", offset)).color(app.colors.accent).size(app.settings.font_size_code).monospace());

                let mut ascii = String::new();
                for col in 0..bytes_per_row {
                    let byte_offset = offset + col;
                    if byte_offset < data.len() {
                        let byte = data[byte_offset];
                        let color = if byte == 0 {
                            app.colors.text_secondary
                        } else if byte.is_ascii_graphic() || byte == b' ' {
                            app.colors.text_primary
                        } else if byte.is_ascii() {
                            app.colors.warn
                        } else {
                            app.colors.accent
                        };
                        ui.label(egui::RichText::new(format!("{:02X} ", byte)).color(color).size(app.settings.font_size_code).monospace());

                        if byte.is_ascii_graphic() || byte == b' ' {
                            ascii.push(byte as char);
                        } else {
                            ascii.push('.');
                        }
                    } else {
                        ui.label(egui::RichText::new("   ").color(app.colors.text_secondary).size(app.settings.font_size_code).monospace());
                        ascii.push(' ');
                    }

                    if col == 7 {
                        ui.label(egui::RichText::new(" ").size(app.settings.font_size_code));
                    }
                }

                ui.add_space(4.0);
                ui.label(egui::RichText::new(&ascii).color(app.colors.safe).size(app.settings.font_size_code).monospace());
            });

            offset += bytes_per_row;
        }
    });
}

fn get_current_data<'a>(app: &'a FreakREApp) -> Option<&'a [u8]> {
    let idx = app.selected_report
        .or_else(|| if app.reports.is_empty() { None } else { Some(app.reports.len() - 1) })?;
    app.report_data.get(idx).map(|v| v.as_slice())
}

// ─── Disassembly View ────────────────────────────────────────────────

pub fn disassembly_view(ui: &mut egui::Ui, app: &mut FreakREApp) {
    ui.add_space(12.0);
    ui.heading(egui::RichText::new("Disassembly").color(app.colors.text_primary).size(20.0));
    ui.add_space(8.0);

    let data: Vec<u8> = match get_current_data(app) {
        Some(d) => d.to_vec(),
        None => {
            ui.label(egui::RichText::new("No file loaded. Scan a file first.").color(app.colors.text_secondary).size(14.0));
            return;
        }
    };

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Offset:").color(app.colors.text_secondary).size(12.0));
        let mut offset_str = format!("0x{:08X}", app.disasm_offset);
        let resp = ui.text_edit_singleline(&mut offset_str);
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Ok(val) = u64::from_str_radix(offset_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                app.disasm_offset = val;
            }
        }

        ui.add_space(12.0);
        ui.label(egui::RichText::new("Arch:").color(app.colors.text_secondary).size(12.0));
        ui.checkbox(&mut app.disasm_is_64bit, "x86_64");

        ui.add_space(12.0);
        if let Some(report) = app.selected_report.and_then(|i| app.reports.get(i)).or(app.reports.last()) {
            if let Some(ep_str) = report.pe_info.as_ref().and_then(|p| p.entry_point.as_deref()).or(report.macho_info.as_ref().and_then(|m| m.entry_point.as_deref())).or(report.elf_info.as_ref().map(|e| e.entry_point.as_str())) {
                if !ep_str.is_empty() {
                    if ui.button("Go to Entry Point").clicked() {
                        if let Ok(ep) = u64::from_str_radix(ep_str.trim_start_matches("0x"), 16) {
                            app.disasm_offset = ep;
                        }
                    }
                }
            }
        }
    });

    ui.add_space(8.0);

    if data.is_empty() {
        ui.label(egui::RichText::new("File is empty.").color(app.colors.text_secondary).size(14.0));
        return;
    }

    use capstone_ffi::{Disassembler, Arch, Mode};

    let arch = if app.disasm_is_64bit { Mode::Mode64 } else { Mode::Mode32 };
    let disasm = match Disassembler::new(Arch::X86, arch) {
        Ok(d) => d,
        Err(e) => {
            ui.label(egui::RichText::new(format!("Disassembler error: {}", e)).color(app.colors.danger).size(12.0));
            return;
        }
    };

    let start = app.disasm_offset as usize;
    let end = (start + 0x200).min(data.len());

    let code_region = &data[start..end];
    let instructions = disasm.disassemble(code_region, start as u64);

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Address   ").color(app.colors.accent).size(app.settings.font_size_code).monospace());
            ui.label(egui::RichText::new("Bytes            ").color(app.colors.text_secondary).size(app.settings.font_size_code).monospace());
            ui.label(egui::RichText::new("Instruction").color(app.colors.text_secondary).size(app.settings.font_size_code).monospace());
        });
        ui.separator();

        for inst in instructions.iter().take(app.settings.disasm_max_instructions) {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("{:08X}  ", inst.address)).color(app.colors.accent).size(app.settings.font_size_code).monospace());

                let bytes_str: String = inst.bytes.iter()
                    .take(inst.bytes.len().min(8))
                    .map(|b| format!("{:02X} ", b))
                    .collect();
                ui.label(egui::RichText::new(format!("{:24}", bytes_str)).color(app.colors.text_secondary).size(app.settings.font_size_code).monospace());

                let instr_text = format!("{} {}", inst.mnemonic, inst.operands);
                ui.label(egui::RichText::new(&instr_text).color(app.colors.text_primary).size(app.settings.font_size_code).monospace());
            });
        }

        if instructions.len() > app.settings.disasm_max_instructions {
            ui.label(egui::RichText::new(format!("... and {} more instructions", instructions.len() - app.settings.disasm_max_instructions)).color(app.colors.text_secondary).size(11.0));
        }
    });
}

// ─── Graph View (CFG) ────────────────────────────────────────────────

pub fn graph_view(ui: &mut egui::Ui, app: &FreakREApp) {
    ui.add_space(12.0);
    ui.heading(egui::RichText::new("Control Flow Graph").color(app.colors.text_primary).size(20.0));
    ui.add_space(8.0);

    let report = app.selected_report
        .and_then(|i| app.reports.get(i))
        .or(app.reports.last());

    if let Some(report) = report {
        if let Some(ref cfg) = report.cfg_summary {
            ui.horizontal(|ui| {
                stat_card(ui, "Blocks", &cfg.num_blocks.to_string(), app.colors.accent, &app.colors);
                stat_card(ui, "Edges", &cfg.num_edges.to_string(), app.colors.accent, &app.colors);
                stat_card(ui, "Instructions", &cfg.total_instructions.to_string(), app.colors.safe, &app.colors);
                stat_card(ui, "Anomalies", &cfg.num_anomalies.to_string(), app.colors.danger, &app.colors);
            });

            ui.add_space(16.0);

            ui.heading(egui::RichText::new("Graph Metrics").color(app.colors.text_primary).size(16.0));
            ui.add_space(8.0);

            let avg_degree = if cfg.num_blocks > 0 {
                cfg.num_edges as f64 / cfg.num_blocks as f64
            } else { 0.0 };
            let cyclomatic = if cfg.num_blocks > 0 {
                cfg.num_edges as i64 - cfg.num_blocks as i64 + 2
            } else { 0 };

            info_row(ui, "Average out-degree", &format!("{:.2}", avg_degree), &app.colors);
            info_row(ui, "Cyclomatic complexity", &format!("{}", cyclomatic), &app.colors);

            let complexity_class = if cyclomatic <= 10 {
                ("Low (simple)", app.colors.safe)
            } else if cyclomatic <= 20 {
                ("Medium", app.colors.warn)
            } else if cyclomatic <= 50 {
                ("High (complex)", egui::Color32::from_rgb(255, 123, 79))
            } else {
                ("Very High (obfuscated?)", app.colors.danger)
            };

            info_row(ui, "Complexity", complexity_class.0, &app.colors);

            ui.add_space(16.0);

            ui.heading(egui::RichText::new("Visual Layout").color(app.colors.text_primary).size(16.0));
            ui.add_space(8.0);

            let (rect, _response) = ui.allocate_exact_size(
                egui::vec2(ui.available_width().min(700.0), 400.0),
                egui::Sense::hover(),
            );

            let painter = ui.painter_at(rect);
            painter.rect_filled(rect, egui::CornerRadius::same(6), app.colors.bg_frame);
            painter.rect_stroke(rect, egui::CornerRadius::same(6), egui::Stroke::new(1.0_f32, app.colors.border), egui::StrokeKind::Inside);

            if cfg.num_blocks > 0 {
                let cols = (cfg.num_blocks as f64).sqrt().ceil() as usize;
                let rows = (cfg.num_blocks + cols - 1) / cols;
                let cell_w = rect.width() / (cols as f32 + 1.0);
                let cell_h = rect.height() / (rows as f32 + 1.0);

                let mut node_centers = Vec::new();
                for i in 0..cfg.num_blocks.min(100) {
                    let col = i % cols;
                    let row = i / cols;
                    let cx = rect.left() + (col as f32 + 1.0) * cell_w;
                    let cy = rect.top() + (row as f32 + 1.0) * cell_h;
                    let center = egui::pos2(cx, cy);
                    node_centers.push(center);

                    let node_rect = egui::Rect::from_center_size(center, egui::vec2(20.0, 14.0));
                    let color = if cfg.anomalies.iter().any(|a| a.contains(&format!("block {}", i))) {
                        app.colors.danger
                    } else {
                        app.colors.accent.gamma_multiply(0.7)
                    };
                    painter.rect_filled(node_rect, egui::CornerRadius::same(3), color);
                    painter.text(
                        center,
                        egui::Align2::CENTER_CENTER,
                        format!("{}", i),
                        egui::FontId::proportional(8.0),
                        egui::Color32::WHITE,
                    );
                }

                let max_edges = cfg.edges.len().min(500);
                for &(from_id, to_id) in cfg.edges.iter().take(max_edges) {
                    if (from_id as usize) < node_centers.len() && (to_id as usize) < node_centers.len() {
                        let from_pt = node_centers[from_id as usize];
                        let to_pt = node_centers[to_id as usize];
                        if from_id != to_id {
                            painter.line_segment(
                                [from_pt, to_pt],
                                egui::Stroke::new(0.8_f32, app.colors.accent.gamma_multiply(0.4)),
                            );
                        }
                    }
                }
            }

            ui.add_space(16.0);

            if !cfg.anomalies.is_empty() {
                ui.heading(egui::RichText::new("CFG Anomalies").color(app.colors.danger).size(16.0));
                ui.add_space(8.0);

                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    for anomaly in &cfg.anomalies {
                        let frame = egui::Frame::new()
                            .fill(app.colors.bg_frame)
                            .corner_radius(egui::CornerRadius::same(4))
                            .inner_margin(egui::Margin::same(8))
                            .stroke(egui::Stroke::new(1.0_f32, app.colors.danger.gamma_multiply(0.3)));

                        frame.show(ui, |ui| {
                            ui.label(egui::RichText::new(format!("⚠ {}", anomaly)).color(app.colors.text_primary).size(12.0));
                        });
                        ui.add_space(4.0);
                    }
                });
            }
        } else {
            ui.vertical_centered_justified(|ui| {
                ui.add_space(100.0);
                ui.label(
                    egui::RichText::new("No CFG data available.\nMake sure the file has executable code sections.")
                        .color(app.colors.text_secondary)
                        .size(16.0),
                );
            });
        }
    } else {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(100.0);
            ui.label(
                egui::RichText::new("No reports available. Scan a file first.")
                    .color(app.colors.text_secondary)
                    .size(16.0),
            );
        });
    }
}



