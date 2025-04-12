use super::injector::{Injector, InjectionMethod};
use super::process::Process;
use super::winapi::*;
use std::mem::{self};
use std::time::Duration;
use std::thread;
use std::io::{stdout, Write};

/// Minimal PE structures we need
#[repr(C)]
pub struct DosHeader {
    pub e_magic: u16,    // Must be 0x5A4D ('MZ')
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32, // Offset to NT Headers
}

// Typically you'd define IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, etc. For brevity:
#[repr(C)]
pub struct NtHeaders64 {
    pub signature: u32,   // Must be 0x00004550 ('PE\0\0')
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16, // 0x20b => PE32+ (64-bit)
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // data directories follow...
}

// We'll define a minimal `ImageSectionHeader`
#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

pub type NtCreateThreadEx = unsafe extern "system" fn(
    h_thread: *mut HANDLE,
    desired_access: DWORD,
    object_attributes: *const OBJECT_ATTRIBUTES,
    process_handle: HANDLE,
    start_address: LPTHREAD_START_ROUTINE,
    parameter: LPVOID,
    create_flags: DWORD,
    stack_size: SIZE_T,
    thread_id: *mut DWORD,
) -> NTSTATUS;

#[allow(dead_code)]
pub fn validate_dll_path(dll_path: &str) -> bool {
    if std::path::Path::new(dll_path).exists() {
        true
    } else {
        println!("DLL not found: {}", dll_path);
        false
    }
}

#[allow(dead_code)]
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

/// by default uses LoadLibrary injection, but could pass method as an argument
#[allow(dead_code)]
pub fn inject_dll(process: &Process, dll_path: &str) -> Result<(), String> {
    match process.inject_with_method(dll_path, InjectionMethod::LoadLibrary) {
        Ok(_) => {
            println!("DLL injected into PID: {}", process.pid);
            Ok(())
        }
        Err(e) => Err(format!("DLL injection failed: {}", e)),
    }
}

// function heper for thread hijacking
pub fn find_any_thread_in_process(pid: u32) -> Option<u32> {
    unsafe {
        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if h_snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut te = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..mem::zeroed()
        };

        if Thread32First(h_snapshot, &mut te) == FALSE {
            CloseHandle(h_snapshot);
            return None;
        }

        while Thread32Next(h_snapshot, &mut te) != FALSE {
            if te.th32OwnerProcessID == pid {
                // Found a thread from our target process
                CloseHandle(h_snapshot);
                return Some(te.th32ThreadID);
            }
        }

        CloseHandle(h_snapshot);
    }
    None
}