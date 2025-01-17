use injrs::inject_windows::*;
use injrs::process_windows::*;
use console::Term;
use std::io::{stdout, Write};
use std::thread;
use std::time::Duration;

fn validate_dll_path(dll_path: &str) -> bool {
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

fn wait_for_process(process_name: &str, retry_interval: Duration) -> Option<Process> {
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

fn inject_dll(process: &Process, dll_path: &str) -> Result<(), String> {
    println!("Attempting to inject DLL...");
    match process.inject(dll_path) {
        Ok(_) => {
            println!("Successfully injected DLL into process with PID: {}", process.pid);
            Ok(())
        }
        Err(e) => Err(format!("DLL injection failed: {}", e)),
    }
}

fn main() {
    let term = Term::stdout();
    term.set_title("Rust DLL Injector");

    println!("Enter the name of the process to inject (e.g., target.exe):");
    let mut process_name = String::new();
    std::io::stdin().read_line(&mut process_name).unwrap();
    let process_name = process_name.trim().to_string(); 

    println!("Enter the full path of the DLL to inject:");
    let mut dll_path = String::new();
    std::io::stdin().read_line(&mut dll_path).unwrap();
    let dll_path = dll_path.trim().to_string(); 

    if !validate_dll_path(&dll_path) {
        return;
    }

    let retry_interval = Duration::from_secs(2);
    let process = wait_for_process(&process_name, retry_interval);

    if let Some(proc) = process {
        if let Err(err) = inject_dll(&proc, &dll_path) {
            println!("{}", err);
        } else {
            println!("DLL successfully injected. Monitoring process...");
        }

        loop {
            thread::sleep(Duration::from_secs(1));
            if Process::find_first_by_name(&process_name).is_none() {
                println!(
                    "Process '{}' has exited. Injector will now terminate.",
                    process_name
                );
                break;
            }
        }
    }

    println!("Press ENTER to exit.");
    std::io::stdin().read_line(&mut String::new()).unwrap();
}
