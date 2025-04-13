#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::collections::VecDeque;
use eframe::egui;
use rfd::FileDialog;

// bring  injector trait into scope so methods like `eject()` work:
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
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            process_search: String::new(),
            process_list: Vec::new(),
            selected_process: None,
            dll_list: Vec::new(),
            selected_dll: None,
            injection_method: InjectionMethod::LoadLibrary,
            logs: VecDeque::new(),
            show_advanced: false,
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

            // or now, let’s just call the existing .inject() from the trait (LoadLibrary).
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

        // The trait has .eject(dll). This might be unimplemented (todo!).
        match proc_obj.eject(&dll_path) {
            Ok(_) => self.log("DLL ejected successfully."),
            Err(e) => self.log(&format!("DLL ejection failed: {}", e)),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {

        // === Top Panel: Search and Refresh ===
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Process Filter:");
                if ui.text_edit_singleline(&mut self.process_search).changed() {
                    // Optionally do live refresh here, or wait for user to click refresh
                }
                if ui.button("Refresh").clicked() {
                    self.refresh_process_list();
                }
            });
        });

        // === Side Panel: Process List ===
        egui::SidePanel::left("left_panel").show(ctx, |ui| {
            ui.heading("Processes");
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, proc_obj) in self.process_list.iter().enumerate() {
                    let is_selected = Some(i) == self.selected_process;
                    let label = format!("{} (PID: {})", proc_obj.name, proc_obj.pid);
                    if ui.selectable_label(is_selected, label).clicked() {
                        self.selected_process = Some(i);
                    }
                }
            });
        });

        // === Central Panel: DLL list, injection method, etc. ===
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DLL Management");
            ui.separator();

            // DLL list
            egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                for (i, dll) in self.dll_list.iter().enumerate() {
                    let is_selected = Some(i) == self.selected_dll;
                    if ui.selectable_label(is_selected, dll).clicked() {
                        self.selected_dll = Some(i);
                    }
                }
            });

            // Buttons for DLL list
            ui.horizontal(|ui| {
                if ui.button("Add DLL").clicked() {
                    if let Some(path) = FileDialog::new().add_filter("DLL", &["dll"]).pick_file() {
                        let path_str = path.to_string_lossy().to_string();
                        self.log(&format!("Added DLL: {}", path_str));
                        self.dll_list.push(path_str);
                    }
                }
                if ui.button("Remove Selected").clicked() {
                    if let Some(idx) = self.selected_dll {
                        let removed = self.dll_list.remove(idx);
                        self.log(&format!("Removed DLL: {}", removed));
                        self.selected_dll = None;
                    }
                }
                if ui.button("Clear").clicked() {
                    self.dll_list.clear();
                    self.selected_dll = None;
                    self.log("Cleared all DLL entries.");
                }
            });

            ui.separator();

            // Injection method combo
            ui.horizontal(|ui| {
                ui.label("Injection Method:");
                egui::ComboBox::from_id_salt("inj_method_combo") // replaced from_id_source => from_id_salt
                    .selected_text(format!("{:?}", self.injection_method))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::LoadLibrary, "LoadLibrary");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::NtCreateThreadEx, "NtCreateThreadEx");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::ManualMap, "ManualMap");
                        ui.selectable_value(&mut self.injection_method, InjectionMethod::ThreadHijack, "ThreadHijack");
                    });
            });

            // Toggle advanced
            if ui.button("Advanced Options").clicked() {
                self.show_advanced = !self.show_advanced;
            }
            if self.show_advanced {
                ui.group(|ui| {
                    ui.label("Extra advanced settings placeholder...");
                });
            }

            ui.separator();

            // Injection / Ejection actions
            ui.horizontal(|ui| {
                if ui.button("Inject").clicked() {
                    self.inject_selected();
                }
                if ui.button("Eject Selected").clicked() {
                    self.eject_selected();
                }
            });
        });

        // === Bottom Panel: Logs ===
        egui::TopBottomPanel::bottom("log_panel").resizable(true).show(ctx, |ui| {
            ui.heading("Logs");
            ui.separator();
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                for line in &self.logs {
                    ui.label(line);
                }
            });
        });
    }
}

/// The main entry point
fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "Injector",
        options,
        Box::new(|_cc| -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
            // Return `Ok(...)` with your App inside a Box:
            Ok(Box::new(MyApp::default()))
        }),
    )?;

    Ok(())
}

