use std::io;
use std::mem::{self};
use std::path::Path;
use std::ptr::null_mut;
use std::slice;

use super::utils::*;
use super::winapi::*;
use super::process::*;
use super::inject_helper::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMethod {
    LoadLibrary,
    NtCreateThreadEx,
    ManualMap,
    ThreadHijack,
    // Reflective,
    // QueueUserAPC,
}

/// The Injector trait
pub trait Injector {
    fn inject_with_method(&self, dll_path: &str, method: InjectionMethod) -> Result<(), io::Error>;
    fn eject(&self, dll_path: &str) -> Result<(), io::Error>;
}

impl Injector for Process {

    fn inject_with_method(&self, dll_path: &str, method: InjectionMethod) -> Result<(), io::Error> {
        match method {
            InjectionMethod::LoadLibrary => self.inject_via_loadlibrary(dll_path),
            InjectionMethod::NtCreateThreadEx => self.inject_via_ntcreate(dll_path),
            InjectionMethod::ManualMap => self.inject_via_manualmap(dll_path),
            InjectionMethod::ThreadHijack => self.inject_via_thread_hijack(dll_path),
        }
    }

    fn eject(&self, _dll_path: &str) -> Result<(), io::Error> {
        // Only works for standard LoadLibrary based injection, because we need the HMODULE from that.
        // For manual map or reflective injection, we have to manually free memory sections, call DllMain, etc.
        // hijacking a thread is also tricky because we need to restore the original context.
        // Reflective DLLs are even more complex, as they may not have a standard entry point.
        // So here we do the standard FreeLibrary approach, I might implement the others later.:

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

        // wait up to 5s for the thread to complete
        let wait_code = unsafe { WaitForSingleObject(thread_handle, 5000) };
        if wait_code == WAIT_FAILED {
            // not fatal, but suspicious
        }

        unsafe {
            CloseHandle(thread_handle);
            VirtualFreeEx(self.handle, r_path_addr, 0, MEM_RELEASE);
        }

        Ok(())
    }

    fn inject_via_ntcreate(&self, dll_path: &str) -> Result<(), io::Error> {
        let process_handle = self.handle;
    
        let load_library_w = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"LoadLibraryW\0".as_ptr() as _,
            )
        };
        if load_library_w.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Could not get LoadLibraryW address"));
        }
    
        // get NtCreateThreadEx pointer
        let ntdll_module = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _) };
        if ntdll_module.is_null() {
            // handle error
        }

        let nt_create_thread_ex_addr = unsafe {
            GetProcAddress(ntdll_module, b"NtCreateThreadEx\0".as_ptr() as _)
        };
        if nt_create_thread_ex_addr.is_null() {
            // handle error
        }
    
        // convert the raw pointer to Option<fn(...)>
        // let start_routine: Option<unsafe extern "system" fn(*mut c_void) -> u32> = Some( unsafe { std::mem::transmute(load_library_w) });
    
        let filepath = Path::new(dll_path).canonicalize()?;
        let wide_path = to_wide_string(filepath.to_str().unwrap());
        let path_len_in_bytes = wide_path.len() * 2;
    
        let remote_mem = unsafe {
            VirtualAllocEx(
                process_handle,
                std::ptr::null_mut(),
                path_len_in_bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if remote_mem.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
        }
    
        let wpm_ok = unsafe {
            WriteProcessMemory(
                process_handle,
                remote_mem,
                wide_path.as_ptr() as _,
                path_len_in_bytes,
                std::ptr::null_mut(),
            )
        };
        if wpm_ok == FALSE {
            unsafe { VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE) };
            return Err(io::Error::new(io::ErrorKind::Other, "WriteProcessMemory failed"));
        }
    
        let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _) };
        if ntdll.is_null() {
            unsafe {
                VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            }
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get ntdll module handle"));
        }
    
        let nt_create_thread_ex_addr = unsafe {
            GetProcAddress(ntdll, b"NtCreateThreadEx\0".as_ptr() as _)
        };
        if nt_create_thread_ex_addr.is_null() {
            unsafe {
                VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            }
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get NtCreateThreadEx address"));
        }
    
        let nt_create_thread_ex_fn: NtCreateThreadEx = unsafe {
            std::mem::transmute(nt_create_thread_ex_addr)
        };
    
        let mut thread_handle: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            nt_create_thread_ex_fn(
                &mut thread_handle,
                0x1FFFFF,           // THREAD_ALL_ACCESS
                null_mut(),         // OBJECT_ATTRIBUTES
                process_handle,
                load_library_w as PVOID,
                remote_mem as PVOID,
                0,                  // CreateFlags (0 for immediate execution)
                0,                  // ZeroBits
                0,                  // StackSize (default)
                0,                  // MaximumStackSize
                null_mut(),         // AttributeList
            )
        };
    
        // check status
        if status != 0 {
            unsafe {
                VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("NtCreateThreadEx failed, NTSTATUS={:#x}", status),
            ));
        }
    
        // optionally wait on the new thread, then close
        unsafe {
            WaitForSingleObject(thread_handle, 1000);
            CloseHandle(thread_handle);
    
            // If you like, free the memory. Sometimes you keep it if the DLL needs it.
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }
    
        Ok(())
    }
    

    pub fn inject_via_manualmap(&self, dll_path: &str) -> Result<(), io::Error> {
        let file_data = std::fs::read(dll_path)?;

        // Parse DOS header
        let dos_header = unsafe {
            // SAFETY: Check bounds before dereferencing
            if mem::size_of::<DosHeader>() > file_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "File too small for DOS header"));
            }
            &*(file_data.as_ptr() as *const DosHeader)
        };
        if dos_header.e_magic != 0x5A4D {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid DOS header"));
        }

        // Parse NtHeaders64
        let nt_headers_offset = dos_header.e_lfanew as usize;
        let nt_headers = unsafe {
            // SAFETY: Check that we can read NtHeaders64 at nt_headers_offset
            if nt_headers_offset + mem::size_of::<NtHeaders64>() > file_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "File too small for NT headers"));
            }
            &*(file_data.as_ptr().add(nt_headers_offset) as *const NtHeaders64)
        };
        if nt_headers.signature != 0x4550 {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid PE header"));
        }

        // Number of section headers
        let section_count = nt_headers.file_header.number_of_sections as usize;

        // Compute the offset where the section headers begin
        let section_headers_offset = nt_headers_offset + mem::size_of::<NtHeaders64>();
        let total_section_headers_size = section_count * mem::size_of::<ImageSectionHeader>();

        // Make sure the section headers fit in the file
        if section_headers_offset + total_section_headers_size > file_data.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "File too small for section headers"));
        }

        // Create a slice of the section headers
        let section_headers = unsafe {
            slice::from_raw_parts(
                file_data.as_ptr().add(section_headers_offset) as *const ImageSectionHeader,
                section_count,
            )
        };

        // --- Now do your VirtualAlloc, WriteProcessMemory, shellcode, etc. ---

        // For example:
        let image_size = nt_headers.optional_header.size_of_image as usize;
        let base_address = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if base_address.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
        }

        // Write PE headers
        let headers_size = nt_headers.optional_header.size_of_headers as usize;
        unsafe {
            WriteProcessMemory(
                self.handle,
                base_address,
                file_data.as_ptr() as _,
                headers_size,
                null_mut(),
            );
        }

        // Write sections
        for section in section_headers {
            if section.size_of_raw_data == 0 {
                continue;
            }

            let section_data = &file_data
                [section.pointer_to_raw_data as usize
                    ..(section.pointer_to_raw_data as usize + section.size_of_raw_data as usize)];
            let dest_addr = unsafe { base_address.add(section.virtual_address as usize) };

            unsafe {
                WriteProcessMemory(
                    self.handle,
                    dest_addr,
                    section_data.as_ptr() as _,
                    section.size_of_raw_data as usize,
                    null_mut(),
                );
            }
        }

        for section in section_headers {
            if section.size_of_raw_data == 0 {
                continue;
            }

            let section_data = &file_data[section.pointer_to_raw_data as usize..][..section.size_of_raw_data as usize];
            let dest_addr = unsafe { base_address.add(section.virtual_address as usize) };

            unsafe {
                WriteProcessMemory(
                    self.handle,
                    dest_addr,
                    section_data.as_ptr() as _,
                    section.size_of_raw_data as usize,
                    null_mut(),
                );
            }
        }

        // Call DllMain via shellcode (to ensure correct calling convention)
        let entry_rva = (*nt_headers).optional_header.address_of_entry_point;
        let entry_point = unsafe { base_address.add(entry_rva as usize) };

        // Shellcode: Call DllMain(base_address, DLL_PROCESS_ATTACH, 0)
        let shellcode = [
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28 (shadow space)
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, base_address
            0xBA, 0x01, 0x00, 0x00, 0x00,       // mov edx, DLL_PROCESS_ATTACH (1)
            0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov r8d, 0 (reserved)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entry_point
            0xFF, 0xD0,                         // call rax
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
            0xC3,                                // ret
        ];

        // Patch shellcode with actual addresses
        let mut patched_shellcode = shellcode.to_vec();
        patched_shellcode[6..14].copy_from_slice(&(base_address as u64).to_ne_bytes());
        patched_shellcode[24..32].copy_from_slice(&(entry_point as u64).to_ne_bytes());

        // Allocate executable memory for shellcode
        let shellcode_addr = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                patched_shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if shellcode_addr.is_null() {
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to allocate shellcode"));
        }

        // Write shellcode
        unsafe {
            WriteProcessMemory(
                self.handle,
                shellcode_addr,
                patched_shellcode.as_ptr() as _,
                patched_shellcode.len(),
                null_mut(),
            );
        }

        // Execute shellcode
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                Some(mem::transmute(shellcode_addr)),
                null_mut(),
                0,
                null_mut(),
            )
        };
        if thread_handle.is_null() {
            unsafe { VirtualFreeEx(self.handle, shellcode_addr, 0, MEM_RELEASE) };
            return Err(io::Error::new(io::ErrorKind::Other, "CreateRemoteThread failed"));
        }

        // Wait for completion
        unsafe {
            WaitForSingleObject(thread_handle, INFINITE);
            CloseHandle(thread_handle);
            VirtualFreeEx(self.handle, shellcode_addr, 0, MEM_RELEASE);
        }

        Ok(())
    }

    pub fn inject_via_thread_hijack(&self, dll_path: &str) -> Result<(), io::Error> {
        let full_path = std::fs::canonicalize(dll_path)?;
        let wide_path = to_wide_string(full_path.to_str().unwrap());
        let path_len_bytes = wide_path.len() * 2;

        // Find a thread in the target process
        let thread_id = find_any_thread_in_process(self.pid)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No threads found"))?;

        // Open the thread
        let h_thread = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE,
                thread_id,
            )
        };
        if h_thread.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "OpenThread failed"));
        }

        // Suspend the thread
        if unsafe { SuspendThread(h_thread) } == u32::MAX {
            unsafe { CloseHandle(h_thread) };
            return Err(io::Error::new(io::ErrorKind::Other, "SuspendThread failed"));
        }

        // Get thread context
        let mut ctx: CONTEXT = unsafe { mem::zeroed() };
        ctx.ContextFlags = CONTEXT_FULL;
        if unsafe { GetThreadContext(h_thread, &mut ctx) } == FALSE {
            unsafe { ResumeThread(h_thread); CloseHandle(h_thread); }
            return Err(io::Error::new(io::ErrorKind::Other, "GetThreadContext failed"));
        }

        // Allocate memory for DLL path
        let remote_mem = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                path_len_bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_mem.is_null() {
            unsafe { ResumeThread(h_thread); CloseHandle(h_thread); }
            return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
        }

        // Write DLL path
        if unsafe {
            WriteProcessMemory(
                self.handle,
                remote_mem,
                wide_path.as_ptr() as _,
                path_len_bytes,
                null_mut(),
            )
        } == FALSE {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE); }
            unsafe { ResumeThread(h_thread); CloseHandle(h_thread); }
            return Err(io::Error::new(io::ErrorKind::Other, "WriteProcessMemory failed"));
        }

        // Get LoadLibraryW address
        let loadlib_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"LoadLibraryW\0".as_ptr() as _,
            )
        };
        if loadlib_addr.is_null() {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE); }
            unsafe { ResumeThread(h_thread); CloseHandle(h_thread); }
            return Err(io::Error::new(io::ErrorKind::Other, "LoadLibraryW not found"));
        }

        // Save original RIP (for restoration)
        let old_rip = ctx.Rip;

        // Modify context to call LoadLibraryW(remote_mem)
        ctx.Rip = loadlib_addr as u64;   // New instruction pointer
        ctx.Rcx = remote_mem as u64;     // First argument (DLL path)

        // Set new context
        if unsafe { SetThreadContext(h_thread, &ctx) } == FALSE {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE); }
            unsafe { ResumeThread(h_thread); CloseHandle(h_thread); }
            return Err(io::Error::new(io::ErrorKind::Other, "SetThreadContext failed"));
        }

        // Resume thread (executes LoadLibraryW)
        if unsafe { ResumeThread(h_thread) } == u32::MAX {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE); }
            unsafe { CloseHandle(h_thread); }
            return Err(io::Error::new(io::ErrorKind::Other, "ResumeThread failed"));
        }

        // Wait for LoadLibrary to complete (optional)
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Restore original thread context (optional, but recommended)
        unsafe {
            SuspendThread(h_thread);
            ctx.Rip = old_rip;
            SetThreadContext(h_thread, &ctx);
            ResumeThread(h_thread);
            CloseHandle(h_thread);
        }

        Ok(())
    }
}