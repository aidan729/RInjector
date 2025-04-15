use std::io;
use std::mem::{self};
use std::path::Path;
use std::ptr::null_mut;
use std::slice;

use super::utils::*;
use super::winapi::*;
use super::process::*;
use super::inject_helper::*;

// Constants needed for relocation
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

#[repr(C)]
struct ImageBaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

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

        // 1 - Find the module handle in the remote process (by enumerating modules).
        // 2 - Call FreeLibrary in remote process via CreateRemoteThread or NtCreateThreadEx.
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
    
            // free the memory (Sometimes keep it if the DLL needs it.)
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }
    
        Ok(())
    }

    // --- manual map injection ---
    fn inject_via_manualmap(&self, dll_path: &str) -> Result<(), io::Error> {
        let file_data = std::fs::read(dll_path)?;
    
        // parse DOS header
        let dos_header = unsafe {
            if mem::size_of::<DosHeader>() > file_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "File too small for DOS header"));
            }
            &*(file_data.as_ptr() as *const DosHeader)
        };
        if dos_header.e_magic != 0x5A4D {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid DOS header"));
        }
    
        // parse NT headers
        let nt_headers_offset = dos_header.e_lfanew as usize;
        let nt_headers = unsafe {
            if nt_headers_offset + mem::size_of::<NtHeaders64>() > file_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "File too small for NT headers"));
            }
            &*(file_data.as_ptr().add(nt_headers_offset) as *const NtHeaders64)
        };
        if nt_headers.signature != 0x4550 {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid PE header"));
        }
    
        // validate basic PE structure
        if nt_headers.optional_header.magic != 0x20B { // PE32+
            return Err(io::Error::new(io::ErrorKind::Other, "Not a valid PE32+ file"));
        }
    
        // get section headers
        let section_count = nt_headers.file_header.number_of_sections as usize;
        let section_headers_offset = nt_headers_offset + mem::size_of::<NtHeaders64>();
        let total_section_headers_size = section_count * mem::size_of::<ImageSectionHeader>();
    
        if section_headers_offset + total_section_headers_size > file_data.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "File too small for section headers"));
        }
    
        let section_headers = unsafe {
            slice::from_raw_parts(
                file_data.as_ptr().add(section_headers_offset) as *const ImageSectionHeader,
                section_count,
            )
        };
    
        // validate sections
        for section in section_headers {
            // check for invalid section sizes
            if section.virtual_address as u64 + section.virtual_size as u64 > nt_headers.optional_header.size_of_image as u64 {
                return Err(io::Error::new(io::ErrorKind::Other, "Section exceeds image bounds"));
            }
    
            // check for suspicious section names (allow null terminated ASCII)
            let mut section_name = Vec::with_capacity(8);
            for &b in &section.name {
                if b == 0 { break; } // Stop at null terminator
                if !b.is_ascii() || b.is_ascii_control() {
                    return Err(io::Error::new(io::ErrorKind::Other,
                        format!("Invalid character in section name: {:?}", section.name)));
                }
                section_name.push(b);
            }

            // allow standard PE sections even if they have padding nulls
            let section_name = String::from_utf8_lossy(&section_name);
            if section_name.is_empty() {
                return Err(io::Error::new(io::ErrorKind::Other,
                    format!("Empty section name: {:?}", section.name)));
            }
        }
    
        // allocate memory for the DLL
        let image_size = nt_headers.optional_header.size_of_image as usize;
        let base_address = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(), // dont try to use preferred base address
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if base_address.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "VirtualAllocEx failed"));
        }
    
        // write PE headers
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
    
        // write sections with strict validation
        for section in section_headers {
            if section.size_of_raw_data == 0 {
                continue;
            }
    
            let section_start = section.pointer_to_raw_data as usize;
            let section_end = section_start + section.size_of_raw_data as usize;
            
            // skip sections that are completely outside the file
            if section_start >= file_data.len() {
                continue;
            }
    
            // calculate safe copy size
            let copy_size = if section_end > file_data.len() {
                file_data.len() - section_start
            } else {
                section.size_of_raw_data as usize
            };
    
            if copy_size == 0 {
                continue;
            }
    
            let section_data = &file_data[section_start..section_start + copy_size];
            let dest_addr = unsafe { base_address.add(section.virtual_address as usize) };
    
            unsafe {
                WriteProcessMemory(
                    self.handle,
                    dest_addr,
                    section_data.as_ptr() as _,
                    copy_size,
                    null_mut(),
                );
            }
        }
    
        // perform base relocation if needed
        if base_address as usize != nt_headers.optional_header.image_base as usize {
            if let Err(e) = self.perform_relocations(&file_data, base_address, nt_headers) {
                unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE) };
                return Err(e);
            }
        }
    
        // fix memory protections
        if let Err(e) = self.set_proper_protections(base_address, nt_headers, section_headers) {
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE) };
            return Err(e);
        }
    
        // call entry point
        let entry_rva = nt_headers.optional_header.address_of_entry_point;
        let entry_point = unsafe { base_address.add(entry_rva as usize) };
    
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                Some(mem::transmute(entry_point)),
                base_address as _,
                DLL_PROCESS_ATTACH,
                null_mut(),
            )
        };
        if thread_handle.is_null() {
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE) };
            return Err(io::Error::new(io::ErrorKind::Other, "CreateRemoteThread failed"));
        }
    
        unsafe {
            WaitForSingleObject(thread_handle, INFINITE);
            CloseHandle(thread_handle);
        }
    
        Ok(())
    }
    
    fn set_proper_protections(&self, base: LPVOID, _nt_headers: &NtHeaders64, sections: &[ImageSectionHeader]) -> Result<(), io::Error> {
        // set proper memory protections for each section
        for section in sections {
            let protect = match section.characteristics {
                x if x & IMAGE_SCN_MEM_EXECUTE != 0 => PAGE_EXECUTE_READ,
                x if x & IMAGE_SCN_MEM_READ != 0 && x & IMAGE_SCN_MEM_WRITE != 0 => PAGE_READWRITE,
                x if x & IMAGE_SCN_MEM_READ != 0 => PAGE_READONLY,
                _ => PAGE_NOACCESS,
            };
    
            let size = section.virtual_size as usize;
            if size == 0 {
                continue;
            }
    
            let mut old_protect = 0;
            let result = unsafe {
                VirtualProtectEx(
                    self.handle,
                    base.add(section.virtual_address as usize),
                    size,
                    protect,
                    &mut old_protect,
                )
            };
            if result == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "VirtualProtectEx failed"));
            }
        }
        Ok(())
    }
    
    fn rva_to_offset(&self, nt_headers: &NtHeaders64, rva: u32) -> Option<usize> {
        let section_headers = unsafe {
            slice::from_raw_parts(
                (nt_headers as *const _ as *const u8).add(mem::size_of::<NtHeaders64>()) 
                    as *const ImageSectionHeader,
                nt_headers.file_header.number_of_sections as usize,
            )
        };

        for section in section_headers {
            if rva >= section.virtual_address && 
               rva < section.virtual_address + section.virtual_size 
            {
                let offset = rva - section.virtual_address;
                return Some((section.pointer_to_raw_data + offset) as usize);
            }
        }
        None
    }

    fn perform_relocations(&self, file_data: &[u8], new_base: LPVOID, nt_headers: &NtHeaders64) -> Result<(), io::Error> {
        let delta = (new_base as u64).wrapping_sub(nt_headers.optional_header.image_base);
        if delta == 0 {
            return Ok(()); // no relocation needed
        }

        // get the relocation directory
        let reloc_dir = nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            return Ok(()); // No relocation table present
        }

        // calculate relocation table offset
        let reloc_offset = self.rva_to_offset(nt_headers, reloc_dir.virtual_address)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid relocation table RVA"))?;

        if reloc_offset + reloc_dir.size as usize > file_data.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Relocation table exceeds file bounds"));
        }

        let reloc_data = &file_data[reloc_offset..reloc_offset + reloc_dir.size as usize];
        let mut current_offset = 0;

        // process each relocation block
        while current_offset + mem::size_of::<ImageBaseRelocation>() <= reloc_data.len() {
            let block = unsafe {
                &*(reloc_data.as_ptr().add(current_offset) as *const ImageBaseRelocation)
            };

            current_offset += mem::size_of::<ImageBaseRelocation>();
            let block_end = current_offset + block.size_of_block as usize - mem::size_of::<ImageBaseRelocation>();

            if block_end > reloc_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid relocation block size"));
            }

            // calculate page base address
            let page_base = unsafe { new_base.add(block.virtual_address as usize) };

            // process each relocation entry in the block
            let entry_count = (block.size_of_block as usize - mem::size_of::<ImageBaseRelocation>()) / 2;
            for _ in 0..entry_count {
                if current_offset + 2 > reloc_data.len() {
                    break;
                }

                let entry_data = unsafe {
                    *reloc_data.as_ptr().add(current_offset).cast::<u16>()
                };
                current_offset += 2;

                // skip padding entries
                if entry_data == 0 {
                    continue;
                }

                // extract relocation type and offset
                let reloc_type = entry_data >> 12;
                let offset = entry_data & 0xFFF;

                // only handle valid relocation types
                match reloc_type {
                    IMAGE_REL_BASED_HIGHLOW | IMAGE_REL_BASED_DIR64 => {
                        let reloc_addr = unsafe { page_base.add(offset as usize) };
                        self.apply_relocation(reloc_addr, delta, reloc_type)?;
                    }
                    IMAGE_REL_BASED_ABSOLUTE => {} // skip absolute relocations
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("Unsupported relocation type: {}", reloc_type),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_relocation(&self, reloc_addr: LPVOID, delta: u64, reloc_type: u16) -> Result<(), io::Error> {
        let mut old_value = 0u64;
        let mut bytes_read = 0;

        // read the current value at the relocation address
        unsafe {
            ReadProcessMemory(
                self.handle,
                reloc_addr,
                &mut old_value as *mut _ as _,
                match reloc_type {
                    IMAGE_REL_BASED_HIGHLOW => 4,
                    IMAGE_REL_BASED_DIR64 => 8,
                    _ => 0,
                },
                &mut bytes_read,
            );
        }

        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to read relocation address"));
        }

        // calculate new value
        let new_value = match reloc_type {
            IMAGE_REL_BASED_HIGHLOW => (old_value as u32).wrapping_add(delta as u32) as u64,
            IMAGE_REL_BASED_DIR64 => old_value.wrapping_add(delta),
            _ => old_value,
        };

        // write the new value
        unsafe {
            WriteProcessMemory(
                self.handle,
                reloc_addr,
                &new_value as *const _ as _,
                match reloc_type {
                    IMAGE_REL_BASED_HIGHLOW => 4,
                    IMAGE_REL_BASED_DIR64 => 8,
                    _ => 0,
                },
                null_mut(),
            );
        }

        Ok(())
    }
    // --- manual map injection end ---
    
    pub fn inject_via_thread_hijack(&self, dll_path: &str) -> Result<(), io::Error> {
        // enable debug privilege first
        enable_debug_privilege()?;
    
        let full_path = std::fs::canonicalize(dll_path)?;
        let wide_path: Vec<u16> = full_path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(std::iter::once(0)) // null terminate
            .collect();
        let path_len_bytes = wide_path.len() * 2;
    
        // find a thread in the target process
        let thread_id = find_any_thread_in_process(self.pid)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No threads found"))?;
    
        // open the thread
        let h_thread = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE,
                thread_id,
            )
        };
        if h_thread.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("OpenThread failed: {}", last_error_string()),
            ));
        }
    
        // suspend the thread
        let suspend_count = unsafe { SuspendThread(h_thread) };
        if suspend_count == u32::MAX {
            unsafe { CloseHandle(h_thread) };
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SuspendThread failed: {}", last_error_string()),
            ));
        }
    
        // get thread context
        let mut ctx: CONTEXT = unsafe { mem::zeroed() };
        ctx.ContextFlags = CONTEXT_FULL;
        if unsafe { GetThreadContext(h_thread, &mut ctx) } == FALSE {
            let err_str = format!("GetThreadContext failed: {}", last_error_string());
            unsafe {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
            }
            return Err(io::Error::new(io::ErrorKind::Other, err_str));
        }
    
        // allocate memory for DLL path
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
            let err_str = format!("VirtualAllocEx failed: {}", last_error_string());
            unsafe {
                ResumeThread(h_thread);
                CloseHandle(h_thread);
            }
            return Err(io::Error::new(io::ErrorKind::Other, err_str));
        }
    
        // write DLL path
        let wpm_ok = unsafe {
            WriteProcessMemory(
                self.handle,
                remote_mem,
                wide_path.as_ptr() as *const c_void,
                path_len_bytes,
                null_mut(),
            )
        };
        if wpm_ok == FALSE {
            let err_str = format!("WriteProcessMemory failed: {}", last_error_string());
            unsafe {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                ResumeThread(h_thread);
                CloseHandle(h_thread);
            }
            return Err(io::Error::new(io::ErrorKind::Other, err_str));
        }
    
        // get LoadLibraryW address
        let loadlib_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"LoadLibraryW\0".as_ptr() as _,
            )
        };
        if loadlib_addr.is_null() {
            let err_str = format!("LoadLibraryW not found: {}", last_error_string());
            unsafe {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                ResumeThread(h_thread);
                CloseHandle(h_thread);
            }
            return Err(io::Error::new(io::ErrorKind::Other, err_str));
        }
    
        // save original RIP
        let old_rip = ctx.Rip;
    
        // modify context to call LoadLibraryW(remote_mem)
        ctx.Rip = loadlib_addr as u64;  // new instruction pointer
        ctx.Rcx = remote_mem as u64;    // first argument (DLL path)
    
        if unsafe { SetThreadContext(h_thread, &ctx) } == FALSE {
            let err_str = format!("SetThreadContext failed: {}", last_error_string());
            unsafe {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                ResumeThread(h_thread);
                CloseHandle(h_thread);
            }
            return Err(io::Error::new(io::ErrorKind::Other, err_str));
        }
    
        // resume thread to execute LoadLibraryW
        if unsafe { ResumeThread(h_thread) } == u32::MAX {
            let err_str = format!("ResumeThread (LoadLibrary call) failed: {}", last_error_string());
            unsafe {
                VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE);
                CloseHandle(h_thread);
            }
            return Err(io::Error::new(io::ErrorKind::Other, err_str));
        }
    
        // wait briefly for LoadLibrary to complete
        std::thread::sleep(std::time::Duration::from_millis(500));
    
        // restore original thread context
        unsafe {
            if SuspendThread(h_thread) == u32::MAX {
                eprintln!("SuspendThread (restore) failed: {}", last_error_string());
            }
            ctx.Rip = old_rip;
            if SetThreadContext(h_thread, &ctx) == FALSE {
                eprintln!("SetThreadContext (restore) failed: {}", last_error_string());
            }
            if ResumeThread(h_thread) == u32::MAX {
                eprintln!("ResumeThread (restore) failed: {}", last_error_string());
            }
            CloseHandle(h_thread);
        }
    
        Ok(())
    }
}