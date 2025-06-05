#[allow(unused_imports)]

use super::winapi::*;
use super::utils::*;
use crate::inject_helper::NtHeaders64;
use crate::inject_helper::ImageSectionHeader;

use std::io;
use std::mem::{self, MaybeUninit};

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;


pub type ProcessHandle = HANDLE;

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub handle: ProcessHandle,
}

impl Process {

    pub fn new(handle: ProcessHandle, pid: u32, name: &str) -> Self {
        Self {
            pid: pid,
            name: name.into(),
            handle,
        }
    }

    pub fn from_pid(pid: u32) -> Option<Self> {

        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        if handle.is_null() {
            return None;
        }

        let name = get_process_name(handle);

        Some(Self::new(handle, pid, name.as_str()))
    }

    pub fn from_pid_and_name(pid: u32, name: &str) -> Option<Self> {
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        if handle.is_null() {
            return None;
        }
        
        Some(Self::new(handle, pid, name))
    }

    pub fn find_first_by_name(name: &str) -> Option<Self> {
        match find_process_by_name(name).unwrap_or_default().first() {
            // TODO: ugly, shoudl implement copy trait for process
            Some(v) => Process::from_pid(v.pid),
            None => None
        }
    }

    #[allow(dead_code)]
    pub fn find_all_by_name(name: &str) -> Vec<Self> {
        match find_process_by_name(name) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn from_handle(handle: ProcessHandle) -> Self {

        let pid = unsafe { GetProcessId(handle) as u32 };

        let name = get_process_name(handle);

        Self {pid, name, handle}
    }

}

impl Process {
    pub fn close(&self) -> io::Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        let result = unsafe{ CloseHandle(self.handle) };
        if result != 0 {
            return Ok(());
        }
        Err(get_last_error())
    }

    #[allow(dead_code)]
    pub fn find_module_by_name(_dllname: &str) -> Option<MODULEENTRY32> {
        todo!()
    }

    #[allow(dead_code)]
    pub fn is_wow64(&self) -> Result<bool, io::Error> {
        let mut is_wow64 = MaybeUninit::uninit();
        let r = unsafe{IsWow64Process(self.handle, is_wow64.as_mut_ptr())};
        if r == FALSE {
            return Err(get_last_error());
        }
        Ok(unsafe{is_wow64.assume_init()} == TRUE)
    }

    // Convert RVA (Relative Virtual Address) to file offset
    pub fn rva_to_offset(&self, nt_headers: &NtHeaders64, rva: u32) -> Option<usize> {
        // Get section headers - they come right after the NT headers
        let section_headers = unsafe {
            std::slice::from_raw_parts(
                (nt_headers as *const _ as *const u8).add(std::mem::size_of::<NtHeaders64>()) 
                    as *const ImageSectionHeader,
                nt_headers.file_header.number_of_sections as usize,
            )
        };

        // Find which section contains this RVA
        for section in section_headers {
            if rva >= section.virtual_address && 
               rva < section.virtual_address + section.virtual_size 
            {
                // Calculate offset within the section
                let offset_in_section = rva - section.virtual_address;
                // Return file offset = section's file position + offset within section
                return Some((section.pointer_to_raw_data + offset_in_section) as usize);
            }
        }
        None // RVA not found in any section
    }

    // Apply a single relocation entry
    pub fn apply_relocation(&self, reloc_addr: LPVOID, delta: u64, reloc_type: u16) -> Result<(), io::Error> {
        let mut old_value = 0u64;
        let mut bytes_read = 0;

        // Determine how many bytes to read based on relocation type
        let bytes_to_read = match reloc_type {
            IMAGE_REL_BASED_HIGHLOW => 4, // 32-bit relocation
            IMAGE_REL_BASED_DIR64 => 8,   // 64-bit relocation
            _ => return Ok(()), // Skip unknown types
        };

        // Read the current value at the relocation address
        let read_result = unsafe {
            ReadProcessMemory(
                self.handle,
                reloc_addr,
                &mut old_value as *mut _ as *mut c_void,
                bytes_to_read,
                &mut bytes_read,
            )
        };

        if read_result == FALSE || bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other, 
                format!("Failed to read relocation address: {}", unsafe { GetLastError() })
            ));
        }

        // Calculate the new value after applying the delta
        let new_value = match reloc_type {
            IMAGE_REL_BASED_HIGHLOW => {
                // 32-bit relocation: add delta to lower 32 bits
                (old_value as u32).wrapping_add(delta as u32) as u64
            },
            IMAGE_REL_BASED_DIR64 => {
                // 64-bit relocation: add delta to full 64 bits
                old_value.wrapping_add(delta)
            },
            _ => old_value, // Should not reach here due to earlier check
        };

        // Write the new value back
        let write_result = unsafe {
            WriteProcessMemory(
                self.handle,
                reloc_addr,
                &new_value as *const _ as *const c_void,
                bytes_to_read,
                std::ptr::null_mut(),
            )
        };

        if write_result == FALSE {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to write relocation: {}", unsafe { GetLastError() })
            ));
        }

        Ok(())
    }

}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn get_process_name(handle: ProcessHandle) -> String {
    let mut buf = [0u16; MAX_PATH + 1];
    unsafe {
        GetModuleBaseNameW(handle, 0 as _, buf.as_mut_ptr(),  MAX_PATH as DWORD + 1);
        return wchar_to_string(&buf)
    };
}

#[allow(dead_code)]
pub fn get_process_path(handle: ProcessHandle) -> String {
    let mut buf = [0u16; MAX_PATH + 1];
    unsafe {
        GetModuleFileNameExW(handle, 0 as _, buf.as_mut_ptr(), MAX_PATH as DWORD + 1);
        return wchar_to_string(&buf);
    }
}

// TODO: accept callback function
pub fn find_process_by_name(name: &str) -> Result<Vec<Process>, io::Error> {
    let handle = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 as _)
    };

    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(get_last_error());
    }

    let mut result: Vec<Process> = Vec::new();

    let mut _name: String;

    let mut entry: PROCESSENTRY32 = unsafe { ::std::mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    while 0 != unsafe { Process32Next(handle, &mut entry) } {
        _name = char_to_string(&entry.szExeFile);
        entry.szExeFile = unsafe { ::std::mem::zeroed() };

        if name.len() > 0 && !_name.contains(name) {
            continue;
        }
        // parse process and push to result vec
        // TODO: improve reuse the name and other information
        match Process::from_pid_and_name(entry.th32ProcessID, _name.as_str()) {
            Some(v) => result.push(v),
            None => {},
        }

    }

    Ok(result)
}

fn char_to_string(chars  : &[i8]) -> String {
    chars.into_iter().map(|c| { *c as u8 as char }).collect()
}

pub fn wchar_to_string(slice: &[u16]) -> String {
    match slice.iter().position(|&x| x == 0) {
        Some(pos) => OsString::from_wide(&slice[..pos])
            .to_string_lossy()
            .into_owned(),
        None => OsString::from_wide(slice).to_string_lossy().into_owned(),
    }
}