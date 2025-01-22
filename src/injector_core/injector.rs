use std::io;
use std::mem::{self};
use std::ptr::null_mut;
use std::path::Path;

use super::utils::*;
use super::winapi::*;
use super::process::*;


#[allow(dead_code)]
pub trait Injector {
    fn is_injected(&self, dll: &str) -> Result<bool, io::Error>;
    fn inject(&self, dll: &str) -> Result<(), io::Error>;
    fn eject(&self, dll: &str) -> Result<(), io::Error>;
}

impl Injector for Process {

    // check if the dll is injected (TODO)
    fn is_injected(&self, _dll: &str) -> Result<bool, io::Error> {
        todo!()
    }

    fn inject(&self, dll: &str) -> Result<(), io::Error> {
        let fullpath = Path::new(dll).canonicalize();
        if fullpath.is_err() {
            return Err(fullpath.unwrap_err());
        }
        let fullpath = fullpath.unwrap();
        let dll = fullpath.to_str().unwrap();

        let path_wstr = to_wide_string(dll);

        let path_len = path_wstr.len() * 2 + 1;

        let r_path_addr = unsafe{VirtualAllocEx(self.handle, null_mut(), path_len,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};

        if r_path_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "alloc memorry failed"));
        }

        let r = unsafe{WriteProcessMemory(self.handle, r_path_addr,
            path_wstr.as_ptr() as _, path_len, null_mut())};

        if r == FALSE {
            return Err(io::Error::new(io::ErrorKind::Other, "write data to memorry failed"));
        }

        let r_func_addr = unsafe{GetProcAddress(
            GetModuleHandleA("kernel32.dll\0".as_ptr() as _),
            "LoadLibraryW\0".as_ptr() as _,
        )};

        if r_func_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "get load func memorry failed"));
        }

        let t_handle = unsafe{CreateRemoteThread(
            self.handle,
            null_mut(),
            0,
            Some(mem::transmute(r_func_addr)),
            r_path_addr,
            0,
            null_mut()
        )};
        if t_handle.is_null() {
            println!("create remote thread failed");
            return Err(get_last_error());
        }

        let r = unsafe{WaitForSingleObject(t_handle, 100)}; 
        if r == WAIT_FAILED {
            return Err(get_last_error());
        }

        unsafe{VirtualFreeEx(self.handle, r_path_addr, 1, MEM_DECOMMIT)};

        unsafe{CloseHandle(t_handle)};

        Ok(())
    }

    // eject the dll from the process (TODO)
    fn eject(&self, _dll: &str) -> Result<(), io::Error> {
        todo!()
    }
}