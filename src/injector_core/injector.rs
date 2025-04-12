use std::io;
use std::mem::{self};
use std::path::Path;
use std::ptr::null_mut;

use super::utils::*;
use super::winapi::*;
use super::process::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMethod {
    LoadLibrary,
    NtCreateThreadEx,
    ManualMap,
    // Reflective,
    // QueueUserAPC,
}

/// The Injector trait
pub trait Injector {
    fn inject_with_method(&self, dll_path: &str, method: InjectionMethod) -> Result<(), io::Error>;
    fn eject(&self, dll_path: &str) -> Result<(), io::Error>;
}

// Implementation for our Process
impl Injector for Process {

    fn inject_with_method(&self, dll_path: &str, method: InjectionMethod) -> Result<(), io::Error> {
        match method {
            InjectionMethod::LoadLibrary => self.inject_via_loadlibrary(dll_path),
            InjectionMethod::NtCreateThreadEx => self.inject_via_ntcreate(dll_path),
            InjectionMethod::ManualMap => self.inject_via_manualmap(dll_path),
        }
    }

    fn eject(&self, dll_path: &str) -> Result<(), io::Error> {
        // Only works for standard LoadLibrary-based injection, because we need the HMODULE from that.
        // For manual map or reflective injection, you must manually free memory sections, call DllMain, etc.
        // So here we do the standard FreeLibrary approach:

        // 1) Find the module handle in the remote process (by enumerating modules).
        // 2) Call FreeLibrary in remote process via CreateRemoteThread or NtCreateThreadEx.
        // This is just a stub:
        Err(io::Error::new(io::ErrorKind::Other, "Ejection not yet implemented."))
    }
}

impl Process {
    fn inject_via_loadlibrary(&self, dll: &str) -> Result<(), io::Error> {
        let fullpath = Path::new(dll).canonicalize()?;
        let dll = fullpath.to_str().unwrap();
        let path_wstr = to_wide_string(dll);
        let path_len = path_wstr.len() * 2;

        let r_path_addr = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                path_len,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if r_path_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
        }

        let wpm_ok = unsafe {
            WriteProcessMemory(
                self.handle,
                r_path_addr,
                path_wstr.as_ptr() as _,
                path_len,
                null_mut(),
            )
        };
        if wpm_ok == FALSE {
            return Err(io::Error::new(io::ErrorKind::Other, "WriteProcessMemory failed"));
        }

        let loadlib_w_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr() as _),
                "LoadLibraryW\0".as_ptr() as _,
            )
        };
        if loadlib_w_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Could not get LoadLibraryW address"));
        }

        let thread_handle = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                Some(mem::transmute(loadlib_w_addr)),
                r_path_addr,
                0,
                null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(get_last_error());
        }

        // Wait up to 5s for the thread to complete
        let wait_code = unsafe { WaitForSingleObject(thread_handle, 5000) };
        if wait_code == WAIT_FAILED {
            // Not fatal, but suspicious
        }

        unsafe {
            CloseHandle(thread_handle);
            VirtualFreeEx(self.handle, r_path_addr, 0, MEM_RELEASE);
        }

        Ok(())
    }

    fn inject_via_ntcreate(&self, _dll: &str) -> Result<(), io::Error> {
        // Using NtCreateThreadEx is similar to CreateRemoteThread, but you have to dynamically
        // fetch NtCreateThreadEx from ntdll and call it.
        // This is left as an exercise / placeholder:
        Err(io::Error::new(
            io::ErrorKind::Other,
            "NtCreateThreadEx method not implemented.",
        ))
    }

    fn inject_via_manualmap(&self, _dll: &str) -> Result<(), io::Error> {
        // Manual map requires parsing the PE file, allocating remote memory for each
        // section, doing relocations, building the import table, calling DllMain, etc.
        // Potentially use an existing crate like 'manualmap' or 'pelite'.
        // This is left as an exercise / placeholder:
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Manual Map method not implemented.",
        ))
    }
}
