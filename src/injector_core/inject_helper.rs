use std::io::{stdout, Write};
use std::thread;
use std::time::Duration;

use super::injector::*;
use super::process::Process;

#[allow(dead_code)]
pub fn validate_dll_path(dll_path: &str) -> bool {
    if std::path::Path::new(dll_path).exists() {
        true
    } else {
        println!(
            "Error: DLL not found at {}. Ensure the file exists.",
            dll_path
        );
        false
    }
}

pub fn wait_for_process(process_name: &str, retry_interval: Duration) -> Option<Process> {
    let animation = ["-", "/", "|", "\\"];
    let mut anim_index = 0;

    loop {
        match Process::find_first_by_name(process_name) {
            Some(proc) => {
                println!("\nProcess '{}' found with PID: {}", process_name, proc.pid);
                return Some(proc);
            }
            None => {
                print!(
                    "\rWaiting for process '{}'... {}",
                    process_name, animation[anim_index]
                );
                stdout().flush().unwrap();
                anim_index = (anim_index + 1) % animation.len();
                thread::sleep(retry_interval);
            }
        }
    }
}

pub fn inject_dll(process: &Process, dll_path: &str) -> Result<(), String> {
    println!("Attempting to inject DLL...");
    match process.inject(dll_path) {
        Ok(_) => {
            println!("Successfully injected DLL into process with PID: {}", process.pid);
            Ok(())
        }
        Err(e) => Err(format!("DLL injection failed: {}", e)),
    }
}