#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
use std::collections::VecDeque;
use eframe::egui;
use rfd::FileDialog;

// bring injector trait into scope so methods like `eject()` work
use injector_core::injector::Injector;
use injector_core::inject_helper;
use injector_core::process::Process;
use injector_core::injector::InjectionMethod;

mod injector_core {
    pub mod elevate;
    pub mod error;
    pub mod inject_helper;
    pub mod injector;
    pub mod process;
    pub mod utils;
    pub mod winapi;
}

mod config;

/// main egui application
struct MyApp {
    // ---- Process selection stuff
    process_search: String,
    process_list: Vec<Process>,
    selected_process: Option<usize>,

    // ---- DLL list
    dll_list: Vec<String>,
    selected_dll: Option<usize>,

    // ---- Injection method
    injection_method: InjectionMethod,

    // ---- Logging
    logs: VecDeque<String>,

    // Show advanced? (toggle)
    show_advanced: bool,

    // ---- Config
    config: config::Config,
}

impl Default for MyApp {
    fn default() -> Self {
        let config = config::Config::load();
        let dll_list = config.dll_paths.clone();

        Self {
            process_search: String::new(),
            process_list: Vec::new(),
            selected_process: None,
            dll_list,
            selected_dll: None,
            injection_method: InjectionMethod::LoadLibrary,
            logs: VecDeque::new(),
            show_advanced: false,
            config,
        }
    }
}

impl MyApp {
    fn log(&mut self, msg: &str) {
        // limit logs to 300 lines or so
        if self.logs.len() >= 300 {
            self.logs.pop_front();
        }
        self.logs.push_back(msg.to_string());
        eprintln!("{}", msg); // prints to console if you run with a console
    }

    fn refresh_process_list(&mut self) {
        self.log("Refreshing process list...");
        // save the search text now to avoid borrow conflicts
        let search_lower = self.process_search.to_lowercase();

        match injector_core::process::find_process_by_name("") {
            Ok(all_processes) => {
                // filter them
                let filtered: Vec<Process> = all_processes
                    .into_iter()
                    .filter(|proc| proc.name.to_lowercase().contains(&search_lower))
                    .collect();
                self.log(&format!("Found {} process(es).", filtered.len()));
                self.process_list = filtered;
            }
            Err(e) => self.log(&format!("Error enumerating processes: {}", e)),
        }
    }

    /// inject the entire DLL list into the selected process
    fn inject_selected(&mut self) {
        let process_idx = match self.selected_process {
            Some(idx) => idx,
            None => {
                self.log("No process selected to inject into.");
                return;
            }
        };

        if self.dll_list.is_empty() {
            self.log("No DLL(s) in list to inject.");
            return;
        }

        // copy needed data from `self` to avoid overlapping borrows:
        let proc_obj = self.process_list[process_idx].clone();
        let method = self.injection_method;
        let dll_list = self.dll_list.clone();

        self.log(&format!(
            "Injecting into process '{}' (PID: {}) using {:?}",
            proc_obj.name, proc_obj.pid, method
        ));

        // each DLL is attempted in turn
        for dll_path in dll_list {
            // Validate
            if !inject_helper::validate_dll_path(&dll_path) {
                self.log(&format!("Skipping invalid DLL path: {}", dll_path));
                continue;
            }

            // or now, let's just call the existing .inject() from the trait (LoadLibrary).
            match proc_obj.inject_with_method(&dll_path, method) {
                Ok(_) => self.log(&format!("Successfully injected: {}", dll_path)),
                Err(e) => self.log(&format!("Error injecting {}: {}", dll_path, e)),
            }
        }
    }

    fn eject_selected(&mut self) {
        let process_idx = match self.selected_process {
            Some(idx) => idx,
            None => {
                self.log("No process selected to eject from.");
                return;
            }
        };
        let dll_idx = match self.selected_dll {
            Some(idx) => idx,
            None => {
                self.log("No DLL selected to eject.");
                return;
            }
        };

        // Copy local data
        let proc_obj = self.process_list[process_idx].clone();
        let dll_path = self.dll_list[dll_idx].clone();

        self.log(&format!(
            "Attempting to eject '{}' from process '{}' (PID: {})",
            dll_path, proc_obj.name, proc_obj.pid
        ));

        // The trait has .eject(dll) (todo!).
        match proc_obj.eject(&dll_path) {
            Ok(_) => self.log("DLL ejected successfully."),
            Err(e) => self.log(&format!("DLL ejection failed: {}", e)),
        }
    }

    fn setup_custom_style(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        
        // Modern color scheme - dark theme with accent colors
        let bg_primary = egui::Color32::from_rgb(24, 25, 28);        // Dark background
        let bg_secondary = egui::Color32::from_rgb(32, 34, 37);      // Slightly lighter panels
        let bg_tertiary = egui::Color32::from_rgb(45, 47, 51);       // Input fields, buttons
        let accent_blue = egui::Color32::from_rgb(68, 138, 255);     // Primary accent
        let accent_green = egui::Color32::from_rgb(52, 199, 89);     // Success/inject
        let accent_red = egui::Color32::from_rgb(255, 69, 58);       // Danger/eject
        let text_primary = egui::Color32::from_rgb(255, 255, 255);   // Main text
        let text_secondary = egui::Color32::from_rgb(152, 152, 157); // Secondary text
        let border_color = egui::Color32::from_rgb(60, 62, 68);      // Subtle borders

        // Update visuals
        style.visuals.dark_mode = true;
        style.visuals.panel_fill = bg_secondary;
        style.visuals.window_fill = bg_primary;
        style.visuals.extreme_bg_color = bg_primary;
        style.visuals.faint_bg_color = bg_tertiary;
        style.visuals.code_bg_color = bg_tertiary;
        
        // Text colors
        style.visuals.override_text_color = Some(text_primary);
        style.visuals.warn_fg_color = text_secondary;
        
        // Interactive elements
        style.visuals.widgets.noninteractive.bg_fill = bg_tertiary;
        style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, border_color);
        style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, text_primary);
        
        style.visuals.widgets.inactive.bg_fill = bg_tertiary;
        style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, border_color);
        style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, text_secondary);
        
        style.visuals.widgets.hovered.bg_fill = accent_blue.gamma_multiply(0.3);
        style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, accent_blue);
        style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, text_primary);
        
        style.visuals.widgets.active.bg_fill = accent_blue.gamma_multiply(0.5);
        style.visuals.widgets.active.bg_stroke = egui::Stroke::new(2.0, accent_blue);
        style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, text_primary);
        
        // Selection colors
        style.visuals.selection.bg_fill = accent_blue.gamma_multiply(0.4);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, accent_blue);
        
        // Spacing and sizing for better proportions
        style.spacing.indent = 16.0;
        style.spacing.item_spacing = egui::Vec2::new(8.0, 6.0);
        style.spacing.button_padding = egui::Vec2::new(12.0, 8.0);
        style.spacing.menu_margin = egui::Margin::same(8.0);
        
        // Window styling
        style.visuals.window_rounding = egui::Rounding::same(8.0);
        style.visuals.window_shadow = egui::epaint::Shadow::NONE;
        style.visuals.popup_shadow = egui::epaint::Shadow::NONE;
        
        // Widget rounding for modern look
        style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(6.0);
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
        style.visuals.widgets.active.rounding = egui::Rounding::same(6.0);
        
        ctx.set_style(style);
    }

    fn styled_button(&self, ui: &mut egui::Ui, text: &str, color: egui::Color32) -> egui::Response {
        let button = egui::Button::new(egui::RichText::new(text).color(egui::Color32::WHITE))
            .fill(color)
            .rounding(egui::Rounding::same(6.0));
        ui.add_sized([80.0, 32.0], button)
    }

    fn styled_section_header(&self, ui: &mut egui::Ui, text: &str) {
        ui.add_space(8.0);
        ui.label(egui::RichText::new(text)
            .size(16.0)
            .strong()
            .color(egui::Color32::from_rgb(255, 255, 255)));
        ui.add_space(4.0);
        
        // Modern subtle separator
        let rect = ui.available_rect_before_wrap();
        let line_rect = egui::Rect::from_min_size(
            rect.min,
            egui::Vec2::new(rect.width(), 1.0)
        );
        ui.painter().rect_filled(
            line_rect,
            egui::Rounding::ZERO, 
            egui::Color32::from_rgb(68, 138, 255).gamma_multiply(0.3)
        );
        ui.add_space(8.0);
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply custom styling
        Self::setup_custom_style(ctx);

        // === Top Panel: Search and Refresh ===
        egui::TopBottomPanel::top("top_panel")
            .exact_height(60.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    
                    // App title with icon-like styling
                    ui.label(egui::RichText::new("DLL Injector")
                        .size(18.0)
                        .strong()
                        .color(egui::Color32::from_rgb(68, 138, 255)));
                    
                    ui.add_space(32.0);
                    
                    // Search section
                    ui.label(egui::RichText::new("Process Filter:")
                        .color(egui::Color32::from_rgb(152, 152, 157)));
                    
                    let search_response = ui.add_sized(
                        [200.0, 28.0],
                        egui::TextEdit::singleline(&mut self.process_search)
                            .hint_text("Search processes...")
                    );
                    
                    if search_response.changed() {
                        self.refresh_process_list();
                    }
                    
                    ui.add_space(8.0);
                    
                    if self.styled_button(ui, "Refresh", egui::Color32::from_rgb(68, 138, 255)).clicked() {
                        self.refresh_process_list();
                    }
                });
                ui.add_space(8.0);
            });

        // === Side Panel: Process List ===
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(280.0)
            .width_range(250.0..=400.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                self.styled_section_header(ui, "Process List");

                // Process count info
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("{} processes", self.process_list.len()))
                        .size(12.0)
                        .color(egui::Color32::from_rgb(152, 152, 157)));
                });
                ui.add_space(8.0);

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for (i, proc_obj) in self.process_list.iter().enumerate() {
                            let is_selected = Some(i) == self.selected_process;
                            
                            // Custom styled process entry
                            let (rect, response) = ui.allocate_exact_size(
                                egui::Vec2::new(ui.available_width(), 40.0),
                                egui::Sense::click()
                            );
                            
                            if response.clicked() {
                                self.selected_process = Some(i);
                            }
                            
                            // Background with hover effect
                            let bg_color = if is_selected {
                                egui::Color32::from_rgb(68, 138, 255).gamma_multiply(0.3)
                            } else if response.hovered() {
                                egui::Color32::from_rgb(45, 47, 51)
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            
                            ui.painter().rect_filled(rect, egui::Rounding::same(6.0), bg_color);
                            
                            // Border for selected item
                            if is_selected {
                                ui.painter().rect_stroke(
                                    rect, 
                                    egui::Rounding::same(6.0), 
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(68, 138, 255))
                                );
                            }
                            
                            // Process name and PID
                            let text_rect = rect.shrink(8.0);
                            let mut child_ui = ui.new_child(egui::UiBuilder::new().max_rect(text_rect));
                            child_ui.vertical(|ui| {
                                ui.label(egui::RichText::new(&proc_obj.name)
                                    .size(13.0)
                                    .strong()
                                    .color(egui::Color32::WHITE));
                                ui.label(egui::RichText::new(format!("PID: {}", proc_obj.pid))
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(152, 152, 157)));
                            });
                            
                            ui.add_space(2.0);
                        }
                    });
            });

        // === Central Panel: DLL list, injection method, etc. ===
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            self.styled_section_header(ui, "DLL Management");

            // DLL list with modern styling
            ui.group(|ui| {
                ui.set_min_height(180.0);
                
                if self.dll_list.is_empty() {
                    // Empty state
                    let rect = ui.available_rect_before_wrap();
                    let mut child_ui = ui.new_child(egui::UiBuilder::new().max_rect(rect));
                    child_ui.centered_and_justified(|ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("📁")
                                .size(32.0)
                                .color(egui::Color32::from_rgb(152, 152, 157)));
                            ui.label(egui::RichText::new("No DLLs added")
                                .color(egui::Color32::from_rgb(152, 152, 157)));
                            ui.label(egui::RichText::new("Click 'Add DLL' to get started")
                                .size(11.0)
                                .color(egui::Color32::from_rgb(152, 152, 157)));
                        });
                    });
                } else {
                    egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                        for (i, dll) in self.dll_list.iter().enumerate() {
                            let is_selected = Some(i) == self.selected_dll;
                            
                            // Extract filename for cleaner display
                            let filename = std::path::Path::new(dll)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(dll);
                            
                            let (rect, response) = ui.allocate_exact_size(
                                egui::Vec2::new(ui.available_width(), 32.0),
                                egui::Sense::click()
                            );
                            
                            if response.clicked() {
                                self.selected_dll = Some(i);
                            }
                            
                            let bg_color = if is_selected {
                                egui::Color32::from_rgb(52, 199, 89).gamma_multiply(0.3)
                            } else if response.hovered() {
                                egui::Color32::from_rgb(45, 47, 51)
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            
                            ui.painter().rect_filled(rect, egui::Rounding::same(4.0), bg_color);
                            
                            if is_selected {
                                ui.painter().rect_stroke(
                                    rect, 
                                    egui::Rounding::same(4.0), 
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 199, 89))
                                );
                            }
                            
                            let text_rect = rect.shrink(8.0);
                            let mut child_ui = ui.new_child(egui::UiBuilder::new().max_rect(text_rect));
                            child_ui.horizontal(|ui| {
                                ui.label("");
                                ui.label(egui::RichText::new(filename)
                                    .color(egui::Color32::WHITE));
                            });
                        }
                    });
                }
            });

            ui.add_space(12.0);

            // DLL management buttons
            ui.horizontal(|ui| {
                if self.styled_button(ui, "Add DLL", egui::Color32::from_rgb(52, 199, 89)).clicked() {
                    if let Some(path) = FileDialog::new().add_filter("DLL", &["dll"]).pick_file() {
                        let path_str = path.to_string_lossy().to_string();
                        self.log(&format!("Added DLL: {}", path_str));
                        self.dll_list.push(path_str.clone());
                        self.config.add_dll(path_str);
                    }
                }
                
                ui.add_space(8.0);
                
                if self.styled_button(ui, "Remove", egui::Color32::from_rgb(255, 69, 58)).clicked() {
                    if let Some(idx) = self.selected_dll {
                        let removed = self.dll_list.remove(idx);
                        self.log(&format!("Removed DLL: {}", removed));
                        self.config.remove_dll(&removed);
                        self.selected_dll = None;
                    }
                }
                
                ui.add_space(8.0);
                
                if self.styled_button(ui, "Clear All", egui::Color32::from_rgb(152, 152, 157)).clicked() {
                    if !self.dll_list.is_empty() {
                        self.dll_list.clear();
                        self.selected_dll = None;
                        self.config.clear_dlls();
                        self.log("Cleared all DLL entries.");
                    }
                }
            });

            ui.add_space(16.0);
            self.styled_section_header(ui, "Injection Configuration");

            // Injection method selection with modern combo box
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Method:")
                    .color(egui::Color32::from_rgb(152, 152, 157)));
                
                egui::ComboBox::from_id_salt("inj_method_combo")
                    .selected_text(format!("{:?}", self.injection_method))
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::LoadLibrary, "LoadLibrary");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::NtCreateThreadEx, "NtCreateThreadEx");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::ManualMap, "ManualMap");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::ThreadHijack, "ThreadHijack");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::AtomBombing, "AtomBombing");
                    });
            });

            ui.add_space(8.0);

            // Advanced options toggle
            let advanced_btn_color = if self.show_advanced {
                egui::Color32::from_rgb(68, 138, 255)
            } else {
                egui::Color32::from_rgb(100, 100, 100)
            };
            
            if self.styled_button(ui, "Advanced", advanced_btn_color).clicked() {
                self.show_advanced = !self.show_advanced;
            }
            
            if self.show_advanced {
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Advanced Options")
                            .strong()
                            .color(egui::Color32::from_rgb(68, 138, 255)));
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("• Additional injection parameters")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(152, 152, 157)));
                        ui.label(egui::RichText::new("• Process integrity checks")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(152, 152, 157)));
                        ui.label(egui::RichText::new("• Custom timing options")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(152, 152, 157)));
                    });
                });
            }

            ui.add_space(24.0);

            // Main action buttons with prominent styling
            ui.horizontal(|ui| {
                let inject_btn = egui::Button::new(
                    egui::RichText::new("INJECT")
                        .size(14.0)
                        .strong()
                        .color(egui::Color32::WHITE)
                )
                .fill(egui::Color32::from_rgb(52, 199, 89))
                .rounding(egui::Rounding::same(8.0));
                
                if ui.add_sized([120.0, 40.0], inject_btn).clicked() {
                    self.inject_selected();
                }
                
                ui.add_space(16.0);
                
                let eject_btn = egui::Button::new(
                    egui::RichText::new("EJECT")
                        .size(14.0)
                        .strong()
                        .color(egui::Color32::WHITE)
                )
                .fill(egui::Color32::from_rgb(255, 69, 58))
                .rounding(egui::Rounding::same(8.0));
                
                if ui.add_sized([120.0, 40.0], eject_btn).clicked() {
                    self.eject_selected();
                }
            });
        });

        // === Bottom Panel: Logs ===
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .default_height(120.0)
            .height_range(80.0..=300.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                self.styled_section_header(ui, "Activity Log");
                
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for (i, line) in self.logs.iter().enumerate() {
                            let color = if line.contains("Successfully") || line.contains("ejected successfully") {
                                egui::Color32::from_rgb(52, 199, 89)
                            } else if line.contains("Error") || line.contains("failed") {
                                egui::Color32::from_rgb(255, 69, 58)
                            } else if line.contains("Found") || line.contains("Refreshing") {
                                egui::Color32::from_rgb(68, 138, 255)
                            } else {
                                egui::Color32::from_rgb(200, 200, 200)
                            };
                            
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(format!("{:03}", i + 1))
                                    .size(10.0)
                                    .monospace()
                                    .color(egui::Color32::from_rgb(100, 100, 100)));
                                ui.label(egui::RichText::new(line)
                                    .size(12.0)
                                    .monospace()
                                    .color(color));
                            });
                        }
                    });
            });
    }
}

/// The main entry point
fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("DLL Injector")
            .with_icon(
                // You can add an icon here if you have one
                eframe::icon_data::from_png_bytes(&[]).unwrap_or_default()
            ),
        ..Default::default()
    };

    eframe::run_native(
        "DLL Injector",
        options,
        Box::new(|_cc| -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Box::new(MyApp::default()))
        }),
    )?;

    Ok(())
}