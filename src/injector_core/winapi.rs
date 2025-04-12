// For NtCreateThreadEx you also need:
pub use winapi::shared::ntdef::OBJECT_ATTRIBUTES;

// For specifying stack sizes and other pointer-sized fields (64-bit)
pub use winapi::shared::basetsd::SIZE_T;

// For remote-thread function pointer
pub use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;

pub use winapi::ctypes::c_void;

pub use winapi::shared::ntdef::{
    HANDLE,
    NULL,
    NTSTATUS,
};

pub use winapi::shared::minwindef::{
    FALSE,
    TRUE,
    MAX_PATH,
    DWORD,
    HMODULE,
    LPVOID,
    LPCVOID,
};

pub use winapi::um::processthreadsapi::{
    GetProcessId,
    GetCurrentProcess,
    OpenProcess,
    OpenProcessToken,
    CreateRemoteThread,
    GetExitCodeThread
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
    MEM_DECOMMIT,
    MEM_RELEASE,
    MEM_RESERVE,
    PAGE_READWRITE,
    PAGE_EXECUTE_READWRITE,
    TOKEN_PRIVILEGES,
    TOKEN_ADJUST_PRIVILEGES,
    TOKEN_QUERY,
    SE_PRIVILEGE_ENABLED,
    SE_DEBUG_NAME,
    LUID_AND_ATTRIBUTES
};

pub use winapi::um::memoryapi::{
    ReadProcessMemory,
    WriteProcessMemory,
    VirtualAllocEx,
    VirtualFreeEx,
};

pub use winapi::um::libloaderapi::{
    GetModuleHandleA,
    GetProcAddress
};

pub use winapi::um::synchapi::{
    WaitForSingleObject
};

pub use winapi::um::wow64apiset::{
    IsWow64Process
};

pub use winapi::um::winbase::{
    INFINITE,
    WAIT_FAILED,
    LookupPrivilegeValueA,
    CREATE_SUSPENDED,
    CREATE_NEW_CONSOLE
};

pub use winapi::um::securitybaseapi::{
    AdjustTokenPrivileges
};

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
