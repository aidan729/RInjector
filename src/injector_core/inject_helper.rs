use super::injector::{Injector, InjectionMethod};
use super::process::Process;
use std::time::Duration;
use std::thread;
use std::io::{stdout, Write};

#[allow(dead_code)]
pub fn validate_dll_path(dll_path: &str) -> bool {
    if std::path::Path::new(dll_path).exists() {
        true
    } else {
        println!("DLL not found: {}", dll_path);
        false
    }
}

pub fn wait_for_process(process_name: &str, retry_interval: Duration) -> Option<Process> {
    let animation = ["-", "/", "|", "\\"];
    let mut anim_index = 0;

    loop {
        let proc_found = Process::find_first_by_name(process_name);
        match proc_found {
            Some(proc) => {
                println!("\nProcess '{}' found (PID: {})", process_name, proc.pid);
                return Some(proc);
            }
            None => {
                print!("\rWaiting for process '{}'... {}", process_name, animation[anim_index]);
                stdout().flush().unwrap();
                anim_index = (anim_index + 1) % animation.len();
                thread::sleep(retry_interval);
            }
        }
    }
}

/// By default uses LoadLibrary injection, but you could pass method as an argument
pub fn inject_dll(process: &Process, dll_path: &str) -> Result<(), String> {
    match process.inject_with_method(dll_path, InjectionMethod::LoadLibrary) {
        Ok(_) => {
            println!("DLL injected into PID: {}", process.pid);
            Ok(())
        }
        Err(e) => Err(format!("DLL injection failed: {}", e)),
    }
}
