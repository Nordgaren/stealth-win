#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

#[cfg(test)]
mod tests;

use crate::consts::*;
use crate::crypto_util::*;
use crate::svec::{SVec, ToSVec};
use crate::util::{
    case_insensitive_compare_strs_as_bytes, compare_str_and_w_str_bytes,
    compare_xor_str_and_str_bytes, compare_xor_str_and_w_str_bytes, copy_buffer, find_char,
    get_resource_bytes, strlen, strlen_with_null,
};
use crate::windows::ntdll::*;
use core::ffi::{c_char, CStr};
use core::ptr::addr_of;
use core::{mem, slice};
use slice::from_raw_parts;
use crate::resource::XORString;

pub type FnAllocConsole = unsafe extern "system" fn() -> u32;
pub type FnCloseHandle = unsafe extern "system" fn(hObject: usize) -> bool;
pub type FnCreateFileA = unsafe extern "system" fn(
    lpFileName: *const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) -> usize;
pub type FnCreateFileW = unsafe extern "system" fn(
    lpFileName: *const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) -> usize;
pub type FnCreateProcessA = unsafe extern "system" fn(
    lpApplicationName: *const u8,
    lpCommandLine: *const u8,
    lpProcessAttributes: *const SECURITY_ATTRIBUTES,
    lpThreadAttributes: *const SECURITY_ATTRIBUTES,
    bInheritHandles: u32,
    dwCreationFlags: u32,
    lpEnvironment: usize,
    lpCurrentDirectory: *const u8,
    lpStartupInfo: *const STARTUPINFOA,
    lpProcessInformation: *const PROCESS_INFORMATION,
) -> u32;
pub type FnCreateProcessW = unsafe extern "system" fn(
    lpApplicationName: *const u16,
    lpCommandLine: *const u8,
    lpProcessAttributes: *const SECURITY_ATTRIBUTES,
    lpThreadAttributes: *const SECURITY_ATTRIBUTES,
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
pub type FnGetFileSize = unsafe extern "system" fn(hFile: usize, lpFileSizeHigh: *const u32) -> u32;
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
pub type FnGetProcessHeap = unsafe extern "system" fn() -> usize;
pub type FnGetSystemDirectoryA = unsafe extern "system" fn(lpBuffer: *mut u8, uSize: u32) -> u32;
pub type FnGetSystemDirectoryW = unsafe extern "system" fn(lpBuffer: *mut u16, uSize: u32) -> u32;
pub type FnHeapAlloc =
    unsafe extern "system" fn(hHeap: usize, dwFlags: u32, dwBytes: usize) -> usize;
pub type FnHeapFree = unsafe extern "system" fn(hHeap: usize, dwFlags: u32, lpMem: usize) -> u32;
pub type FnHeapReAlloc =
    unsafe extern "system" fn(hHeap: usize, dwFlags: u32, lpMem: usize, dwBytes: usize) -> usize;
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
pub type FnOVERLAPPED_COMPLETION_ROUTINE = unsafe extern "system" fn(
    dwErrorCode: u32,
    dwNumberOfBytesTransfered: u32,
    lpOverlapped: *mut OVERLAPPED,
);
pub type FnProcess32First =
    unsafe extern "system" fn(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32;
pub type FnProcess32Next =
    unsafe extern "system" fn(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32;
pub type FnReadFile = unsafe extern "system" fn(
    hFile: usize,
    lpBuffer: *mut u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: *mut u32,
    lpOverlapped: *mut OVERLAPPED,
) -> u32;
pub type FnReadFileEx = unsafe extern "system" fn(
    hFile: usize,
    lpBuffer: *mut u8,
    nNumberOfBytesToRead: u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: FnOVERLAPPED_COMPLETION_ROUTINE,
) -> u32;
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

pub const FILE_FLAG_WRITE_THROUGH: u32 = 0x80000000;
pub const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
pub const FILE_FLAG_NO_BUFFERING: u32 = 0x20000000;
pub const FILE_FLAG_RANDOM_ACCESS: u32 = 0x10000000;
pub const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x08000000;
pub const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x04000000;
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
pub const FILE_FLAG_POSIX_SEMANTICS: u32 = 0x01000000;
pub const FILE_FLAG_SESSION_AWARE: u32 = 0x00800000;
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
pub const FILE_FLAG_OPEN_NO_RECALL: u32 = 0x00100000;
pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;

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
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Offset: u32,
    pub OffsetHigh: u32,
    pub hEvent: usize,
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

// These two implementations of GetModuleHandle were inspired by reenz0h of Sektor7!
// credits: reenz0h - @SEKTOR7net, zerosum0x0, and speedi13
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
        let name = slice::from_raw_parts(
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

pub unsafe fn GetModuleHandleX(xor_string: &XORString) -> usize {
    let peb = get_peb();

    if xor_string.resource.is_empty() {
        return peb.ImageBaseAddress;
    }

    let ldr = peb.Ldr;
    let module_list = &ldr.InMemoryOrderModuleList;

    let mut list_entry = module_list.Flink;
    while addr_of!(*list_entry) as usize != addr_of!(*module_list) as usize {
        let entry: &'static TRUNC_LDR_DATA_TABLE_ENTRY = mem::transmute(list_entry);

        let name = slice::from_raw_parts(
            entry.BaseDllName.Buffer,
            entry.BaseDllName.Length as usize / 2,
        );
        if xor_string == name {
            return entry.DllBase;
        }
        list_entry = list_entry.Flink;
    }

    0
}

// These two implementations of GetProcAddress were inspired by reenz0h.
// credits: reenz0h - @SEKTOR7net, zerosum0x0, and speedi13
pub unsafe fn GetProcAddressInternal(base_address: usize, proc_name: &[u8]) -> usize {
    let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_headers: &'static IMAGE_NT_HEADERS =
        mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_headers.OptionalHeader;
    let export_data_directory =
        &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
        mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

    let export_address_table_rva = base_address + export_directory.AddressOfFunctions as usize;
    let export_address_table_array = slice::from_raw_parts(
        export_address_table_rva as *const u32,
        export_directory.NumberOfFunctions as usize,
    );

    let mut proc_address = 0;
    let ordinal_test = (proc_name.as_ptr() as *const u32);
    if proc_name.len() >= 4 && *ordinal_test >> 16 == 0 {
        let ordinal = *ordinal_test;
        let base = export_directory.Base;

        if (ordinal < base) || (ordinal >= base + export_directory.NumberOfFunctions) {
            return 0;
        }

        proc_address =
            base_address + export_address_table_array[(ordinal - base) as usize] as usize;
    } else {
        let name_table_address = base_address + export_directory.AddressOfNames as usize;
        let name_table = slice::from_raw_parts(
            name_table_address as *const u32,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let string_address = base_address + name_table[i] as usize;
            let name = slice::from_raw_parts(
                string_address as *const u8,
                strlen(string_address as *const u8),
            );

            if case_insensitive_compare_strs_as_bytes(proc_name, name) {
                let hints_table_address =
                    base_address + export_directory.AddressOfNameOrdinals as usize;
                let hints_table = slice::from_raw_parts(
                    hints_table_address as *const u16,
                    export_directory.NumberOfNames as usize,
                );

                proc_address =
                    base_address + export_address_table_array[hints_table[i] as usize] as usize;
            }
        }
    }

    if proc_address >= addr_of!(*export_directory) as usize
        && proc_address < addr_of!(*export_directory) as usize + export_data_directory.Size as usize
    {
        proc_address = get_fwd_addr(proc_address);
    }

    proc_address
}

pub unsafe fn GetProcAddressX(base_address: usize, xor_string: &XORString) -> usize {
    let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_headers: &'static IMAGE_NT_HEADERS =
        mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_headers.OptionalHeader;
    let export_data_directory =
        &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
        mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

    let export_address_table_rva = base_address + export_directory.AddressOfFunctions as usize;
    let export_address_table_array = slice::from_raw_parts(
        export_address_table_rva as *const u32,
        export_directory.NumberOfFunctions as usize,
    );
    // We are only loading by name for this function, so remove the ordinal code.
    // checking for ordinal can cause issues, here.
    let mut proc_address = 0;
    let name_table_address = base_address + export_directory.AddressOfNames as usize;
    let name_table = slice::from_raw_parts(
        name_table_address as *const u32,
        export_directory.NumberOfNames as usize,
    );

    for i in 0..name_table.len() {
        let string_address = (base_address + name_table[i] as usize) as *const u8;
        let name = slice::from_raw_parts(string_address, strlen(string_address));

        if xor_string == name {
            let hints_table_address =
                base_address + export_directory.AddressOfNameOrdinals as usize;
            let hints_table = slice::from_raw_parts(
                hints_table_address as *const u16,
                export_directory.NumberOfNames as usize,
            );

            proc_address =
                base_address + export_address_table_array[hints_table[i] as usize] as usize;
        }
    }

    if proc_address >= addr_of!(*export_directory) as usize
        && proc_address < addr_of!(*export_directory) as usize + export_data_directory.Size as usize
    {
        proc_address = get_fwd_addr(proc_address);
    }

    proc_address
}

unsafe fn get_fwd_addr(proc_address: usize) -> usize {
    let len = strlen(proc_address as *const u8);

    #[cfg(feature = "no_std")]
    let mut forward_dll = [0; MAX_PATH + 1];
    #[cfg(feature = "no_std")]
    copy_buffer(proc_address as *const u8, forward_dll.as_mut_ptr(), len);

    #[cfg(not(feature = "no_std"))]
    let mut forward_dll = slice::from_raw_parts(proc_address as *const u8, len).to_svec();

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

    GetProcAddressInternal(forward_handle, &forward_dll[split_pos + 1..len])
}

pub unsafe fn AllocConsole() -> u32 {
    let allocConsole: FnAllocConsole = core::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "AllocConsole".as_bytes(),
    ));

    allocConsole()
}

pub unsafe fn CloseHandle(hObject: usize) -> bool {
    let closeHandle: FnCloseHandle = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(CLOSEHANDLE_POS, CLOSEHANDLE_KEY, CLOSEHANDLE_LEN)
    ));

    closeHandle(hObject)
}

pub unsafe fn CreateFileA(
    lpFileName: *const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) -> usize {
    let createFileA: FnCreateFileA = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(CREATEFILEA_POS, CREATEFILEA_KEY, CREATEFILEA_LEN)
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

pub unsafe fn CreateFileW(
    lpFileName: *const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: *const SECURITY_ATTRIBUTES,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: usize,
) -> usize {
    let createFileW: FnCreateFileW = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(CREATEFILEW_POS, CREATEFILEW_KEY, CREATEFILEW_LEN)
    ));

    createFileW(
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
    lpProcessAttributes: *const SECURITY_ATTRIBUTES,
    lpThreadAttributes: *const SECURITY_ATTRIBUTES,
    bInheritHandles: u32,
    dwCreationFlags: u32,
    lpEnvironment: usize,
    lpCurrentDirectory: *const u8,
    lpStartupInfo: *const STARTUPINFOA,
    lpProcessInformation: *const PROCESS_INFORMATION,
) -> u32 {
    let createProcessA: FnCreateProcessA = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(CREATEPROCESSA_POS, CREATEPROCESSA_KEY, CREATEPROCESSA_LEN)
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

pub unsafe fn CreateProcessW(
    lpApplicationName: *const u16,
    lpCommandLine: *const u8,
    lpProcessAttributes: *const SECURITY_ATTRIBUTES,
    lpThreadAttributes: *const SECURITY_ATTRIBUTES,
    bInheritHandles: u32,
    dwCreationFlags: u32,
    lpEnvironment: usize,
    lpCurrentDirectory: *const u8,
    lpStartupInfo: *const STARTUPINFOA,
    lpProcessInformation: *const PROCESS_INFORMATION,
) -> u32 {
    let createProcessW: FnCreateProcessW = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(CREATEPROCESSW_POS, CREATEPROCESSW_KEY, CREATEPROCESSW_LEN)
    ));

    createProcessW(
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
    let createRemoteThread: FnCreateRemoteThread = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(CREATEREMOTETHREAD_POS, CREATEREMOTETHREAD_KEY, CREATEREMOTETHREAD_LEN)
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
        core::mem::transmute(GetProcAddressX(
            GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
            &XORString::from_offsets(CREATETOOLHELP32SNAPSHOT_POS, CREATETOOLHELP32SNAPSHOT_KEY, CREATETOOLHELP32SNAPSHOT_LEN)
        ));

    createToolhelp32Snapshot(dwFlags, th32ProcessID)
}

pub unsafe fn FreeConsole() -> u32 {
    let freeConsole: FnFreeConsole = core::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "FreeConsole".as_bytes(),
    ));

    freeConsole()
}

//FindResourceA

pub unsafe fn GetCurrentProcess() -> usize {
    let getCurrentProcess: FnGetCurrentProcess = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETCURRENTPROCESS_POS, GETCURRENTPROCESS_KEY, GETCURRENTPROCESS_LEN)
    ));

    getCurrentProcess()
}

pub unsafe fn GetFileSize(hFile: usize, lpFileSizeHigh: *const u32) -> u32 {
    let getFileSize: FnGetFileSize = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETFILESIZE_POS, GETFILESIZE_KEY, GETFILESIZE_LEN)
    ));

    getFileSize(hFile, lpFileSizeHigh)
}

pub unsafe fn GetFinalPathNameByHandleA(
    hFile: usize,
    lpszFilePath: *const u8,
    cchFilePath: u32,
    dwFlags: u32,
) -> u32 {
    let getFinalPathNameByHandleA: FnGetFinalPathNameByHandleA =
        core::mem::transmute(GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            "GetFinalPathNameByHandleA".as_bytes(),
        ));

    getFinalPathNameByHandleA(hFile, lpszFilePath, cchFilePath, dwFlags)
}

pub unsafe fn GetLastError() -> u32 {
    let getLastError: FnGetLastError = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETLASTERROR_POS, GETLASTERROR_KEY, GETLASTERROR_LEN)
    ));

    getLastError()
}

pub unsafe fn GetModuleHandleA(lpModuleName: *const u8) -> usize {
    let getModuleHandleA: FnGetModuleHandleA = core::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "GetModuleHandleA".as_bytes(),
    ));

    getModuleHandleA(lpModuleName)
}

pub unsafe fn GetModuleHandleW(lpModuleName: *const u16) -> usize {
    let getModuleHandleW: FnGetModuleHandleW = core::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "GetModuleHandleW".as_bytes(),
    ));

    getModuleHandleW(lpModuleName)
}

pub unsafe fn GetProcAddress(hModule: usize, lpProcName: *const u8) -> usize {
    let getProcAddress: FnGetProcAddress = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETPROCADDRESS_POS, GETPROCADDRESS_KEY, GETPROCADDRESS_LEN)
    ));

    getProcAddress(hModule, lpProcName)
}

pub unsafe fn GetProcessHeap() -> usize {
    let getProcessHeap: FnGetProcessHeap = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETPROCESSHEAP_POS, GETPROCESSHEAP_KEY, GETPROCESSHEAP_LEN)
    ));

    getProcessHeap()
}

pub unsafe fn GetSystemDirectoryA(lpBuffer: *mut u8, uSize: u32) -> u32 {
    let getSystemDirectoryA: FnGetSystemDirectoryA = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETSYSTEMDIRECTORYA_POS, GETSYSTEMDIRECTORYA_KEY, GETSYSTEMDIRECTORYA_LEN),
    ));

    getSystemDirectoryA(lpBuffer, uSize)
}

pub unsafe fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32 {
    let getSystemDirectoryW: FnGetSystemDirectoryW = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(GETSYSTEMDIRECTORYW_POS, GETSYSTEMDIRECTORYW_KEY, GETSYSTEMDIRECTORYW_LEN),
    ));

    getSystemDirectoryW(lpBuffer, uSize)
}

pub unsafe fn HeapAlloc(hHeap: usize, dwFlags: u32, dwBytes: usize) -> usize {
    let heapAlloc: FnHeapAlloc = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(HEAPALLOC_POS, HEAPALLOC_KEY, HEAPALLOC_LEN)
    ));

    heapAlloc(hHeap, dwFlags, dwBytes)
}

pub unsafe fn HeapFree(hHeap: usize, dwFlags: u32, lpMem: usize) -> u32 {
    let heapFree: FnHeapFree = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(HEAPFREE_POS, HEAPFREE_KEY, HEAPFREE_LEN)
    ));

    heapFree(hHeap, dwFlags, lpMem)
}

pub unsafe fn HeapReAlloc(hHeap: usize, dwFlags: u32, lpMem: usize, dwBytes: usize) -> usize {
    let heapAlloc: FnHeapReAlloc = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(HEAPREALLOC_POS, HEAPREALLOC_KEY, HEAPREALLOC_LEN)
    ));

    heapAlloc(hHeap, dwFlags, lpMem, dwBytes)
}

pub unsafe fn IsProcessorFeaturePresent(ProcessorFeature: u32) -> u32 {
    let isProcessorFeaturePresent: FnIsProcessorFeaturePresent =
        core::mem::transmute(GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            "IsProcessorFeaturePresent".as_bytes(),
        ));

    isProcessorFeaturePresent(ProcessorFeature)
}

pub unsafe fn LoadLibraryA(lpLibFileName: *const u8) -> usize {
    let loadLibraryA: FnLoadLibraryA = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(LOADLIBRARYA_POS, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN)
    ));

    loadLibraryA(lpLibFileName)
}

// LoadResource

// LockResource

pub unsafe fn OpenFile(lpFileName: *const u8, lpReOpenBuff: *const OFSTRUCT, uStyle: u32) -> i32 {
    let openFile: FnOpenFile = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(OPENFILE_POS, OPENFILE_KEY, OPENFILE_LEN)
    ));

    openFile(lpFileName, lpReOpenBuff, uStyle)
}

pub unsafe fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: u32, dwProcessId: u32) -> usize {
    let openProcess: FnOpenProcess = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(OPENPROCESS_POS, OPENPROCESS_KEY, OPENPROCESS_LEN)
    ));

    openProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
}

pub unsafe fn Process32First(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32 {
    let process32First: FnProcess32First = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(PROCESS32FIRST_POS, PROCESS32FIRST_KEY, PROCESS32FIRST_LEN)
    ));

    process32First(hSnapshot, lppe)
}

pub unsafe fn Process32Next(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> u32 {
    let process32Next: FnProcess32Next = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(PROCESS32NEXT_POS, PROCESS32NEXT_KEY, PROCESS32NEXT_LEN)
    ));

    process32Next(hSnapshot, lppe)
}

pub unsafe fn ReadFile(
    hFile: usize,
    lpBuffer: *mut u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: *mut u32,
    lpOverlapped: *mut OVERLAPPED,
) -> u32 {
    let readFile: FnReadFile = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(READFILE_POS, READFILE_KEY, READFILE_LEN)
    ));

    readFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped,
    )
}

pub unsafe fn ReadFileEx(
    hFile: usize,
    lpBuffer: *mut u8,
    nNumberOfBytesToRead: u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: FnOVERLAPPED_COMPLETION_ROUTINE,
) -> u32 {
    let readFileEx: FnReadFileEx = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(READFILEEX_POS, READFILEEX_KEY, READFILEEX_LEN)
    ));

    readFileEx(
        hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpOverlapped,
        lpCompletionRoutine,
    )
}

pub unsafe fn ReadProcessMemory(
    hProcess: usize,
    lpBaseAddress: usize,
    lpBuffer: *mut u8,
    nSize: usize,
    lpNumberOfBytesRead: *mut usize,
) -> u32 {
    let readProcessMemory: FnReadProcessMemory = core::mem::transmute(GetProcAddressInternal(
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
    let resumeThread: FnResumeThread = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(RESUMETHREAD_POS, RESUMETHREAD_KEY, RESUMETHREAD_LEN)
    ));

    resumeThread(hThread)
}

pub unsafe fn SetStdHandle(nStdHandle: u32, hHandle: usize) -> u32 {
    let setStdHandle: FnSetStdHandle = core::mem::transmute(GetProcAddressInternal(
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
    let virtualAlloc: FnVirtualAlloc = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(VIRTUALALLOC_POS, VIRTUALALLOC_KEY, VIRTUALALLOC_LEN)
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
    let virtualAllocEx: FnVirtualAllocEx = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(VIRTUALALLOCEX_POS, VIRTUALALLOCEX_KEY, VIRTUALALLOCEX_LEN)
    ));

    virtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
}

pub unsafe fn VirtualFree(lpAddress: usize, dwSize: usize, dwFreeType: u32) -> usize {
    let virtualFree: FnVirtualFree = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(VIRTUALFREE_POS, VIRTUALFREE_KEY, VIRTUALFREE_LEN)
    ));

    virtualFree(lpAddress, dwSize, dwFreeType)
}

pub unsafe fn VirtualFreeEx(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    dwFreeType: u32,
) -> usize {
    let virtualFreeEx: FnVirtualFreeEx = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(VIRTUALFREEEX_POS, VIRTUALFREEEX_KEY, VIRTUALFREEEX_LEN)
    ));

    virtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)
}

pub unsafe fn VirtualProtect(
    lpAddress: usize,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> u32 {
    let virtualProtect: FnVirtualProtect = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(VIRTUALPROTECT_POS, VIRTUALPROTECT_KEY, VIRTUALPROTECT_LEN)
    ));

    virtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
}

pub unsafe fn VirtualQuery(
    lpAddress: usize,
    lpBuffer: &mut MEMORY_BASIC_INFORMATION,
    dwLength: usize,
) -> usize {
    let virtualQuery: FnVirtualQuery = core::mem::transmute(GetProcAddressInternal(
        GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
        "VirtualQuery".as_bytes(),
    ));

    virtualQuery(lpAddress, lpBuffer, dwLength)
}

pub unsafe fn WaitForSingleObject(hProcess: usize, dwMilliseconds: u32) -> u32 {
    let waitForSingleObject: FnWaitForSingleObject = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(WAITFORSINGLEOBJECT_POS, WAITFORSINGLEOBJECT_KEY, WAITFORSINGLEOBJECT_LEN),
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
    let writeFile: FnWriteFile = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(WRITEFILE_POS, WRITEFILE_KEY, WRITEFILE_LEN)
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
    let writeProcessMemory: FnWriteProcessMemory = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
        &XORString::from_offsets(WRITEPROCESSMEMORY_POS, WRITEPROCESSMEMORY_KEY, WRITEPROCESSMEMORY_LEN)
    ));

    writeProcessMemory(hProcess, lpAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
}
