// fn main() {
//     let term = Term::stdout();
//     term.set_title("Rust DLL Injector");

//     println!("Enter the name of the process to inject (e.g., target.exe):");
//     let mut process_name = String::new();
//     std::io::stdin().read_line(&mut process_name).unwrap();
//     let process_name = process_name.trim().to_string(); 

//     println!("Enter the full path of the DLL to inject:");
//     let mut dll_path = String::new();
//     std::io::stdin().read_line(&mut dll_path).unwrap();
//     let dll_path = dll_path.trim().to_string(); 

//     if !inject_helper::validate_dll_path(&dll_path) {
//         return;
//     }

//     let retry_interval = Duration::from_secs(2);
//     let process = inject_helper::wait_for_process(&process_name, retry_interval);

//     if let Some(proc) = process {
//         if let Err(err) = inject_helper::inject_dll(&proc, &dll_path) {
//             println!("{}", err);
//         } else {
//             println!("DLL successfully injected. Monitoring process...");
//         }

//         loop {
//             thread::sleep(Duration::from_secs(1));
//             if Process::find_first_by_name(&process_name).is_none() {
//                 println!(
//                     "Process '{}' has exited. Injector will now terminate.",
//                     process_name
//                 );
//                 break;
//             }
//         }
//     }

//     println!("Press ENTER to exit.");
//     std::io::stdin().read_line(&mut String::new()).unwrap();
// }
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // Hide console window on Windows in release
use std::thread;
use std::time::Duration;
use injector_core::inject_helper;
use injector_core::injector;
use injector_core::process::Process;
use eframe::egui;
use rfd::FileDialog;
mod injector_core {
    pub mod elevate;
    pub mod error;
    pub mod injector;
    pub mod process;
    pub mod utils;
    pub mod winapi;
    pub mod inject_helper;
}

fn main() -> eframe::Result<()> {
    // Configure the app's options
    let options = eframe::NativeOptions {
        ..Default::default()
    };

    // Run the app
    eframe::run_native(
        "Injector",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::default()))),
    )
}

struct MyApp {
    process_name: String,
    dll_list: Vec<String>,
    selected_dll: Option<usize>,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            process_name: String::new(),
            dll_list: vec![],
            selected_dll: None,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Process Name Section
            ui.horizontal(|ui| {
                ui.label("Process Name:");
                ui.text_edit_singleline(&mut self.process_name);
                if ui.button("Select").clicked() {
                    // Logic for selecting process
                }
            });

            ui.separator();

            // Inject List Section
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.label("Inject List:");

                    // DLL List
                    egui::Grid::new("dll_list").show(ui, |ui| {
                        for (index, dll) in self.dll_list.iter().enumerate() {
                            let mut selected = false; // Declare `selected` as mutable
                            if ui.checkbox(&mut selected, dll).clicked() {
                                self.selected_dll = if selected { None } else { Some(index) };
                            }
                            ui.end_row();
                        }
                    });

                    // Buttons
                    ui.horizontal(|ui| {
                        if ui.button("Add DLL").clicked() {
                            if let Some(path) = FileDialog::new().add_filter("DLL files", &["dll"]).pick_file() {
                                // let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                                // self.dll_list.push(file_name.into());
                                self.dll_list.push(path.to_string_lossy().into());
                            }
                        }
                        if ui.button("Enable/Disable").clicked() {
                            if let Some(selected) = self.selected_dll {
                                // Logic to enable/disable DLL
                                println!("Toggled DLL: {}", self.dll_list[selected]);
                            }
                        }
                        if ui.button("Remove").clicked() {
                            if let Some(selected) = self.selected_dll {
                                self.dll_list.remove(selected);
                                self.selected_dll = None;
                            }
                        }
                        if ui.button("Clear").clicked() {
                            self.dll_list.clear();
                            self.selected_dll = None;
                        }
                    });
                });
            });

            ui.separator();

            // Footer Buttons
            ui.horizontal(|ui| {
                if ui.button("About").clicked() {
                    // About logic
                }
                if ui.button("Settings").clicked() {
                    // Settings logic
                }
                if ui.button("Inject").clicked() {
                    // Inject logic
                    if !self.process_name.is_empty() && !self.dll_list.is_empty() {
                        let retry_interval = Duration::from_secs(2);
                        let process = inject_helper::wait_for_process(&self.process_name, retry_interval);

                        if let Some(proc) = process {
                            for dll in &self.dll_list {
                                if let Err(err) = inject_helper::inject_dll(&proc, dll) {
                                    println!("{}", err);
                                } else {
                                    println!("DLL successfully injected. Monitoring process...");
                                }
                            }
                        }
                    }
                }
                // ui.add_enabled(false, egui::Button::new("Inject")); // Disabled Inject button
            });
        });
    }
}
