use std::io;
use std::mem::{self};
use std::path::Path;
use std::ptr::null_mut;
use std::slice;
use crate::injector_core::winapi::c_void;

use super::utils::*;
use super::winapi::*;
use super::process::*;
use super::inject_helper::*;

// Constants needed for relocation
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

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

    fn eject(&self, dll_path: &str) -> Result<(), io::Error> {
        // resolve the absolute (canonical) path of the DLL so that
        // we can compare with the path enumerated from the remote process
        let fullpath = Path::new(dll_path).canonicalize()?;
        let fullpath_str = fullpath.to_string_lossy().to_lowercase();

        // create a snapshot of the modules in the remote process.
        // we need the process ID which we can get via GetProcessId(self.handle)
        let process_id: DWORD = unsafe { GetProcessId(self.handle) };
        let snapshot_handle = unsafe {
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                process_id,
            )
        };

        if snapshot_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create module snapshot"));
        }

        // set up the MODULEENTRY32W structure for iteration
        let mut module_entry: MODULEENTRY32W = unsafe { mem::zeroed() };
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        let mut target_module: Option<*mut std::ffi::c_void> = None;
        let mut found = false;
        if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) } != FALSE {
            loop {
                // convert the modules full path (szExePath) to a Rust String
                let module_path = wide_str_to_string(&module_entry.szExePath);
                if module_path.to_lowercase() == fullpath_str {
                    // found our module. record its module handle
                    target_module = Some(module_entry.hModule as *mut _);
                    found = true;
                    break;
                }
                // if no more modules, break out
                if unsafe { Module32NextW(snapshot_handle, &mut module_entry) } == FALSE {
                    break;
                }
            }
        }

        // clean up the snapshot handle
        unsafe { CloseHandle(snapshot_handle) };

        if !found {
            return Err(io::Error::new(io::ErrorKind::Other, "Module not found in remote process"));
        }

        // get the address of FreeLibrary in the local process, its safe because kernel32.dll is shared
        let free_library_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"FreeLibrary\0".as_ptr() as _,
            )
        };
        if free_library_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Could not get FreeLibrary address"));
        }

        // use CreateRemoteThread to call FreeLibrary in the remote process
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                Some(mem::transmute(free_library_addr)),
                target_module.unwrap() as LPVOID,
                0,
                null_mut(),
            )
        };

        if thread_handle.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("CreateRemoteThread failed with error code: {}", unsafe { GetLastError() })));
        }

        // wait for the remote thread to finish executing
        let wait_result = unsafe { WaitForSingleObject(thread_handle, 5000) };
        if wait_result == WAIT_FAILED {
            // log a warning; not every failure here is fatal...
            eprintln!("Warning: WaitForSingleObject failed for the remote thread.");
        }

        // clean up the thread handle.
        unsafe { CloseHandle(thread_handle) };

        Ok(())
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

        // Support both PE32 and PE32+
        let is_pe32_plus = nt_headers.optional_header.magic == 0x20B;
        let is_pe32 = nt_headers.optional_header.magic == 0x10B;
        
        if !is_pe32_plus && !is_pe32 {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid PE format"));
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

        // allocate memory for the DLL
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
            return Err(io::Error::new(
                io::ErrorKind::Other, 
                format!("VirtualAllocEx failed: {}", unsafe { GetLastError() })
            ));
        }

        // write PE headers
        let headers_size = nt_headers.optional_header.size_of_headers as usize;
        let write_result = unsafe {
            WriteProcessMemory(
                self.handle,
                base_address,
                file_data.as_ptr() as *const c_void,
                headers_size,
                null_mut(),
            )
        };
        if write_result == FALSE {
            unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE) };
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WriteProcessMemory (headers) failed: {}", unsafe { GetLastError() })
            ));
        }

        // write sections
        for section in section_headers {
            if section.size_of_raw_data == 0 || section.pointer_to_raw_data == 0 {
                continue;
            }

            let section_start = section.pointer_to_raw_data as usize;
            let section_end = section_start + section.size_of_raw_data as usize;
            
            if section_start >= file_data.len() {
                continue;
            }

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

            let write_result = unsafe {
                WriteProcessMemory(
                    self.handle,
                    dest_addr,
                    section_data.as_ptr() as *const c_void,
                    copy_size,
                    null_mut(),
                )
            };
            if write_result == FALSE {
                eprintln!("Warning: Failed to write section at RVA {:#x}", section.virtual_address);
            }
        }

        // perform base relocation if needed
        if base_address as usize != nt_headers.optional_header.image_base as usize {
            if let Err(e) = self.perform_relocations(&file_data, base_address, nt_headers) {
                eprintln!("Warning: Relocation failed: {}", e);
            }
        }

        // **SIMPLIFIED**: Just call the entry point directly for now
        let entry_rva = nt_headers.optional_header.address_of_entry_point;
        if entry_rva != 0 {
            let entry_point = unsafe { base_address.add(entry_rva as usize) };

            let thread_handle = unsafe {
                CreateRemoteThread(
                    self.handle,
                    null_mut(),
                    0,
                    Some(mem::transmute(entry_point)),
                    base_address as LPVOID,
                    0,
                    null_mut(),
                )
            };
            
            if thread_handle.is_null() {
                unsafe { VirtualFreeEx(self.handle, base_address, 0, MEM_RELEASE) };
                return Err(io::Error::new(
                    io::ErrorKind::Other, 
                    format!("CreateRemoteThread failed: {}", unsafe { GetLastError() })
                ));
            }

            unsafe {
                WaitForSingleObject(thread_handle, 5000);
                CloseHandle(thread_handle);
            }
        }

        println!("Manual map injection completed successfully");
        Ok(())
    }

    // Add this missing method:
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
                        // Don't fail on unknown relocation types, just skip them
                        eprintln!("Warning: Unsupported relocation type: {}", reloc_type);
                    }
                }
            }
        }

        Ok(())
    }

    // Replace your inject_via_thread_hijack method with this simplified version:
    pub fn inject_via_thread_hijack(&self, dll_path: &str) -> Result<(), io::Error> {
        // Enable debug privilege first
        if let Err(e) = enable_debug_privilege() {
            eprintln!("Warning: Could not enable debug privilege: {}", e);
        }

        let full_path = std::fs::canonicalize(dll_path)?;
        let wide_path: Vec<u16> = full_path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_len_bytes = wide_path.len() * 2;

        // Find a suitable thread
        let thread_id = self.find_suitable_thread()?;

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
                format!("OpenThread failed: {}", unsafe { GetLastError() }),
            ));
        }

        // Suspend thread
        let suspend_count = unsafe { SuspendThread(h_thread) };
        if suspend_count == u32::MAX {
            unsafe { CloseHandle(h_thread) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to suspend thread"));
        }

        // Get thread context
        let mut ctx: CONTEXT = unsafe { mem::zeroed() };
        ctx.ContextFlags = CONTEXT_FULL;
        if unsafe { GetThreadContext(h_thread, &mut ctx) } == FALSE {
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("GetThreadContext failed: {}", unsafe { GetLastError() })
            ));
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
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("VirtualAllocEx failed: {}", unsafe { GetLastError() })
            ));
        }

        // Write DLL path
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
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE) };
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WriteProcessMemory failed: {}", unsafe { GetLastError() })
            ));
        }

        // Get LoadLibraryW address
        let loadlib_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"LoadLibraryW\0".as_ptr() as _,
            )
        };
        if loadlib_addr.is_null() {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE) };
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(io::ErrorKind::Other, "LoadLibraryW not found"));
        }

        // Create shellcode
        let shellcode = self.create_hijack_shellcode(loadlib_addr as PVOID, remote_mem, ctx.Rip)?;

        // Set the thread to execute our shellcode
        ctx.Rip = shellcode as u64;

        if unsafe { SetThreadContext(h_thread, &ctx) } == FALSE {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE) };
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SetThreadContext failed: {}", unsafe { GetLastError() })
            ));
        }

        // Resume thread
        if unsafe { ResumeThread(h_thread) } == u32::MAX {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE) };
            unsafe { CloseHandle(h_thread) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to resume thread"));
        }

        // Wait and cleanup
        std::thread::sleep(std::time::Duration::from_millis(1000));
        unsafe { CloseHandle(h_thread) };
        
        println!("Thread hijack injection completed");
        Ok(())
    }

    // Add these helper methods:
    fn find_suitable_thread(&self) -> Result<u32, io::Error> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        };
        
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create thread snapshot"));
        }

        let mut thread_entry: THREADENTRY32 = unsafe { mem::zeroed() };
        thread_entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        let mut suitable_thread = None;

        if unsafe { Thread32First(snapshot, &mut thread_entry) } != FALSE {
            loop {
                if thread_entry.th32OwnerProcessID == self.pid {
                    suitable_thread = Some(thread_entry.th32ThreadID);
                    break;
                }
                if unsafe { Thread32Next(snapshot, &mut thread_entry) } == FALSE {
                    break;
                }
            }
        }

        unsafe { CloseHandle(snapshot) };
        suitable_thread.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No suitable thread found"))
    }

    fn create_hijack_shellcode(
        &self, 
        loadlib_addr: PVOID, 
        dll_path: LPVOID, 
        original_rip: u64
    ) -> Result<LPVOID, io::Error> {
        #[cfg(target_arch = "x86_64")]
        let shellcode_template: &[u8] = &[
            0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 40 (shadow space)
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, dll_path (placeholder)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, loadlib_addr (placeholder)
            0xFF, 0xD0,                                                 // call rax
            0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 40
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, original_rip (placeholder)
            0xFF, 0xE0,                                                 // jmp rax
        ];

        let mut shellcode = shellcode_template.to_vec();
        
        // Patch in the actual addresses
        let dll_path_bytes = (dll_path as u64).to_le_bytes();
        shellcode[6..14].copy_from_slice(&dll_path_bytes);
        
        let loadlib_bytes = (loadlib_addr as u64).to_le_bytes();
        shellcode[16..24].copy_from_slice(&loadlib_bytes);
        
        let original_rip_bytes = original_rip.to_le_bytes();
        shellcode[32..40].copy_from_slice(&original_rip_bytes);

        // Allocate and write the shellcode
        let shellcode_mem = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        
        if shellcode_mem.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to allocate shellcode memory"));
        }

        let write_result = unsafe {
            WriteProcessMemory(
                self.handle,
                shellcode_mem,
                shellcode.as_ptr() as *const c_void,
                shellcode.len(),
                null_mut(),
            )
        };
        
        if write_result == FALSE {
            unsafe { VirtualFreeEx(self.handle, shellcode_mem, 0, MEM_RELEASE) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to write shellcode"));
        }

        Ok(shellcode_mem)
    }

    fn cleanup_thread_hijack(&self, h_thread: HANDLE, suspend_count: u32) {
        unsafe {
            for _ in 0..suspend_count {
                ResumeThread(h_thread);
            }
            CloseHandle(h_thread);
        }
    }
}