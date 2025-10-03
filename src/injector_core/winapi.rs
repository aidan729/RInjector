
pub use winapi::shared::basetsd::SIZE_T;
pub use winapi::ctypes::c_void;


pub use winapi::um::tlhelp32::{
    TH32CS_SNAPMODULE, 
    TH32CS_SNAPMODULE32,
    MODULEENTRY32W,
    Module32FirstW,
    Module32NextW
};

pub use winapi::shared::ntdef::{
    HANDLE,
    NTSTATUS,
    ULONG
};

pub use winapi::shared::minwindef::{
    FALSE,
    TRUE,
    MAX_PATH,
    DWORD,
    LPVOID,
};

pub use winapi::um::processthreadsapi::{
    GetProcessId,
    GetCurrentProcess,
    OpenProcess,
    OpenProcessToken,
    CreateRemoteThread,
    GetExitCodeProcess
};

pub use winapi::um::handleapi::{
    CloseHandle,
    INVALID_HANDLE_VALUE
};

pub use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot,
    Process32Next,
    TH32CS_SNAPPROCESS,
    PROCESSENTRY32, MODULEENTRY32,
};

pub use winapi::um::psapi::{
    GetModuleBaseNameW,
    GetModuleFileNameExW
};

pub use winapi::um::winnt::{
    PROCESS_ALL_ACCESS,
    MEM_COMMIT,
    MEM_RELEASE,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
    TOKEN_PRIVILEGES,
    TOKEN_ADJUST_PRIVILEGES,
    TOKEN_QUERY,
    SE_PRIVILEGE_ENABLED,
    SE_DEBUG_NAME,
    LUID_AND_ATTRIBUTES,
    ACCESS_MASK,
    PVOID,
    DLL_PROCESS_ATTACH,
    IMAGE_SCN_MEM_EXECUTE,
    PAGE_EXECUTE_READ,
    IMAGE_SCN_MEM_WRITE,
    IMAGE_SCN_MEM_READ,
    PAGE_READONLY,
    PAGE_NOACCESS,
    LUID
};

pub use winapi::um::memoryapi::{
    WriteProcessMemory,
    VirtualAllocEx,
    VirtualFreeEx,
    VirtualProtectEx,
    ReadProcessMemory
};

pub use winapi::um::libloaderapi::{
    GetModuleHandleA,
    GetProcAddress
};

pub use winapi::um::synchapi::WaitForSingleObject;

pub use winapi::um::wow64apiset::IsWow64Process;

pub use winapi::um::winbase::{
    WAIT_FAILED,
    LookupPrivilegeValueA,
    INFINITE
};

pub use winapi::um::errhandlingapi::GetLastError;

pub use winapi::um::securitybaseapi::AdjustTokenPrivileges;

pub use winapi::um::tlhelp32::{
    THREADENTRY32, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
};

pub use winapi::um::processthreadsapi::{
    OpenThread, SuspendThread, ResumeThread,
    GetThreadContext, SetThreadContext,
};

pub use winapi::um::winnt::{
    CONTEXT, CONTEXT_FULL, /* flags for 64-bit context */
    THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};

// AtomBombing specific APIs
pub use winapi::um::winbase::{
    GlobalAddAtomA, GlobalAddAtomW, GlobalGetAtomNameA, GlobalGetAtomNameW,
    GlobalDeleteAtom,
};

pub use winapi::shared::minwindef::{
    ATOM,
};

pub use winapi::um::processthreadsapi::{
    QueueUserAPC, GetCurrentThread,
};

pub use winapi::shared::basetsd::{
    ULONG_PTR,
};

pub use winapi::um::memoryapi::{
    VirtualAlloc,
};

// Additional APIs needed for full AtomBombing
pub use winapi::um::synchapi::{
    CreateEventA, SetEvent, WaitForMultipleObjects,
};

pub use winapi::um::handleapi::{
    DuplicateHandle,
};

pub use winapi::um::winbase::{
    WAIT_OBJECT_0,
};

// Define constants that may not be available
pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
pub const WAIT_TIMEOUT: u32 = 258;

pub use winapi::um::winnt::{
    CONTEXT_CONTROL,
};

// NtDll function types for AtomBombing
pub type NtQueueApcThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: PVOID,
    NormalContext: PVOID,
    SystemArgument1: PVOID,
    SystemArgument2: PVOID,
) -> NTSTATUS;

pub type NtSetContextThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ThreadContext: *const CONTEXT,
) -> NTSTATUS;

// Function pointer structure for shellcode
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FunctionPointers {
    pub pfn_load_library_a: *mut c_void,
    pub pfn_get_proc_address: *mut c_void,
}

