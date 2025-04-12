use std::io;
use std::mem::{self};
use std::path::Path;
use std::ptr::null_mut;
use std::fs::File;
use std::io::Read;

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

    fn eject(&self, dll_path: &str) -> Result<(), io::Error> {
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
            // Not fatal, but suspicious
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
    
        // Convert the raw pointer to Option<fn(...)>
        let start_routine: Option<unsafe extern "system" fn(*mut c_void) -> u32>
            = Some( unsafe { std::mem::transmute(load_library_w) });
    
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
                std::ptr::null(),   // OBJECT_ATTRIBUTES => usually NULL
                process_handle,
                start_routine,      // calls LoadLibraryW
                remote_mem,         // pointer to the wide DLL path
                0,                  // create_flags
                0,                  // stack_size => default
                std::ptr::null_mut(), // out ThreadId => optional
            )
        };
    
        // 8) Check status
        if status != 0 {
            unsafe {
                VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("NtCreateThreadEx failed, NTSTATUS={:#x}", status),
            ));
        }
    
        // 9) Optionally wait on the new thread, then close
        unsafe {
            WaitForSingleObject(thread_handle, 1000);
            CloseHandle(thread_handle);
    
            // If you like, free the memory. Sometimes you keep it if the DLL needs it.
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }
    
        Ok(())
    }
    

    pub fn inject_via_manualmap(&self, dll_path: &str) -> Result<(), io::Error> {
        // read the entire DLL file into a buffer
        let fullpath = Path::new(dll_path).canonicalize()?;
        let mut file = File::open(&fullpath)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;

        // check DOS header => MZ
        if file_data.len() < mem::size_of::<DosHeader>() {
            return Err(io::Error::new(io::ErrorKind::Other, "File too small, not a valid PE?"));
        }
        let dos = unsafe { &*(file_data.as_ptr() as *const DosHeader) };
        if dos.e_magic != 0x5A4D {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid DOS header magic"));
        }

        // get NT headers => check 'PE\0\0' => 0x00004550
        let nt_offset = dos.e_lfanew as usize;
        if file_data.len() < nt_offset + mem::size_of::<NtHeaders64>() {
            return Err(io::Error::new(io::ErrorKind::Other, "Missing or invalid NT headers"));
        }
        let nth = unsafe { &*(file_data.as_ptr().add(nt_offset) as *const NtHeaders64) };
        if nth.signature != 0x4550 {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid PE signature"));
        }
        if nth.optional_header.magic != 0x20B {
            return Err(io::Error::new(io::ErrorKind::Other, "Not a 64-bit PE (Magic != 0x20B)"));
        }

        // allocate memory in target process => size_of_image from OptionalHeader
        let image_size = nth.optional_header.size_of_image as usize;
        let base_address = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                image_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if base_address.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
        }

        // copy PE headers => size_of_headers
        let size_of_headers = nth.optional_header.size_of_headers as usize;
        if size_of_headers > file_data.len() {
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE); }
            return Err(io::Error::new(io::ErrorKind::Other, "Headers size bigger than file?"));
        }
        let write_ok = unsafe {
            WriteProcessMemory(
                self.handle,
                base_address,
                file_data.as_ptr() as LPCVOID,
                size_of_headers,
                null_mut(),
            )
        };
        if write_ok == FALSE {
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE); }
            return Err(io::Error::new(io::ErrorKind::Other, "WriteProcessMemory (headers) failed"));
        }

        // copy each section into the target
        let section_count = nth.file_header.number_of_sections as usize;
        let sec_hdr_ptr = unsafe {
            file_data.as_ptr().offset(nt_offset as isize + mem::size_of::<NtHeaders64>() as isize)
                as *const ImageSectionHeader
        };
        
        for i in 0..section_count {
            // pointer arithmetic with .offset
            let sec_ptr = unsafe { sec_hdr_ptr.offset(i as isize) };
            let sec = unsafe { &*sec_ptr };

            // if sec.size_of_raw_data == 0 { continue; } // some sections can be empty

            let section_va = sec.virtual_address as usize; // offset from image base
            let dest_ptr = unsafe { base_address.add(section_va) };

            if sec.pointer_to_raw_data as usize + sec.size_of_raw_data as usize > file_data.len() {
                continue; // or error out
            }

            let src_data = unsafe { file_data.as_ptr().add(sec.pointer_to_raw_data as usize) };
            let bytes_to_write = sec.size_of_raw_data as usize;

            let ok = unsafe {
                WriteProcessMemory(
                    self.handle,
                    dest_ptr,
                    src_data as LPCVOID,
                    bytes_to_write,
                    null_mut(),
                )
            };
            if ok == FALSE {
                unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE); }
                return Err(io::Error::new(io::ErrorKind::Other, "WriteProcessMemory (section) failed"));
            }
        }

        // [Relocations, Import resolution, etc] - NOT IMPLEMENTED here
        // Typically you'd parse the DataDirectory for IMAGE_DIRECTORY_ENTRY_BASERELOC,
        // iterate over reloc blocks, fix each relocation, parse imports, etc
        // for brevity we skip it

        // call DllMain in the remote process
        // the entry point is optional_header.address_of_entry_point (RVA)
        let entry_rva = nth.optional_header.address_of_entry_point;
        let entry_point = unsafe { base_address.add(entry_rva as usize) };
        if entry_rva == 0 {
            // some DLLs might not have a typical entry point
            // we can skip or do something else
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE); }
            return Err(io::Error::new(io::ErrorKind::Other, "No entry point found"));
        }

        // were going to have to create a remote thread at DllMain(HMODULE, DLL_PROCESS_ATTACH, 0)
        // But we need to pass the module handle (base_address) in RCX (for 64-bit),
        // so we do the same approach as with CreateRemoteThread plus param:
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                Some(mem::transmute(entry_point)),
                base_address, // pass base_address as lpParameter => (HMODULE)
                0,
                null_mut(),
            )
        };
        if thread_handle.is_null() {
            unsafe {
                VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE);
            }
            return Err(get_last_error());
        }
        // Wait a bit
        unsafe {
            WaitForSingleObject(thread_handle, 2000);
            CloseHandle(thread_handle);
        }

        // *** At this point, the library is "manual-mapped" but we have NOT done relocations or imports.
        //     A real manual map must do them. This is the minimal skeleton.

        Ok(())
    }

    pub fn inject_via_thread_hijack(&self, dll_path: &str) -> Result<(), io::Error> {
        // verify DLL path
        let fullpath = Path::new(dll_path).canonicalize()?;
        let wide_path = to_wide_string(fullpath.to_str().unwrap());
        let path_len_bytes = wide_path.len() * 2;

        // find a thread belonging to our process
        let thread_id = find_any_thread_in_process(self.pid)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No threads found for target PID"))?;

        // open that thread with enough privileges
        // we need SUSPEND_RESUME, GET_CONTEXT, SET_CONTEXT at a minimum
        let desired_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
        let h_thread = unsafe { OpenThread(desired_access, FALSE, thread_id) };
        if h_thread.is_null() {
            return Err(get_last_error());
        }

        unsafe {
            // suspend the thread
            if SuspendThread(h_thread) == u32::MAX {
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "SuspendThread failed"));
            }

            // prepare to read/modify thread CONTEXT
            // for 64-bit, we use winapi::um::winnt::CONTEXT structure
            // we need to set ContextFlags before calling GetThreadContext
            let mut ctx: CONTEXT = mem::zeroed();
            // this constant means we want all regs
            ctx.ContextFlags = CONTEXT_FULL;

            // get the threads context
            if GetThreadContext(h_thread, &mut ctx as *mut CONTEXT) == FALSE {
                ResumeThread(h_thread); // resume so we don’t lock it
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "GetThreadContext failed"));
            }

            // allocate memory in remote process for our DLL path
            let remote_mem = VirtualAllocEx(
                self.handle,
                null_mut(),
                path_len_bytes,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            );
            if remote_mem.is_null() {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
            }

            // write the DLL path to the remote memory
            let wpm_ok = WriteProcessMemory(
                self.handle,
                remote_mem,
                wide_path.as_ptr() as _,
                path_len_bytes,
                null_mut(),
            );
            if wpm_ok == FALSE {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "WriteProcessMemory failed"));
            }

            // get the address of LoadLibraryW in local process
            let loadlib_addr = GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr() as _),
                "LoadLibraryW\0".as_ptr() as _,
            );
            if loadlib_addr.is_null() {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "Could not get LoadLibraryW address"));
            }

            // so on x64 Windows, the first parameter to a function is in RCX
            // we want to set RCX to point to the remote DLL string
            // and set RIP to the address of LoadLibraryW in the target process
            // this is a bit of a hack, but it works because we are hijacking the thread
            // so that when the thread resumes, it calls LoadLibraryW(remoteString)

            // save old RIP if you want to restore it after
            let _old_rip = ctx.Rip;

            // modify context
            ctx.Rcx = remote_mem as u64;   // param: pointer to wide DLL path
            ctx.Rip = loadlib_addr as u64; // instruction pointer => LoadLibraryW

            // set the new context with our changes
            if SetThreadContext(h_thread, &ctx as *const CONTEXT) == FALSE {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                ResumeThread(h_thread);
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "SetThreadContext failed"));
            }

            // resume the thread so it executes LoadLibraryW(dll_path)
            if ResumeThread(h_thread) == u32::MAX {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                CloseHandle(h_thread);
                return Err(io::Error::new(io::ErrorKind::Other, "ResumeThread failed"));
            }

            // optionally wait a bit for the load to finish
            // (Though we have no direct WaitForSingleObject on a hijacked threads completion)
            // in a real scenario, i might do more robust waiting or code injection
            // for example we could use a named event or semaphore to signal completion
            // or we could use a custom APC (Asynchronous Procedure Call) to signal completion
            // this is a bit more advanced, but it would be more robust
            // for now we just wait a bit to let the thread finish loading the DLL

            // if we wanted to restore the old RIP so the thread continues normally:
            //   SuspendThread again
            //   GetThreadContext, set ctx.Rip = old_rip
            //   SetThreadContext, ResumeThread
            // That is more advanced and not needed for now
            
            CloseHandle(h_thread);
        }
        Ok(())
    }
}