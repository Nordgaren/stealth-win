#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

pub type DllMain =
    extern "stdcall" fn(hinstDLL: usize, dwReason: u32, lpReserved: *mut usize) -> i32;

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

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const INVALID_HANDLE_VALUE: usize = usize::MAX;
pub const MAX_PATH: usize = 260;

//user32.dll
pub type MessageBoxA = unsafe extern "system" fn(
    hWnd: usize,
    lpText: *const u8,
    lpCaption: *const u8,
    uType: u32,
) -> u32;

pub const MB_OK: u32 = 0x00000000;
pub const MB_OKCANCEL: u32 = 0x00000001;
pub const MB_ABORTRETRYIGNORE: u32 = 0x00000002;
pub const MB_YESNOCANCEL: u32 = 0x00000003;
pub const MB_YESNO: u32 = 0x00000004;
pub const MB_RETRYCANCEL: u32 = 0x00000005;
pub const MB_CANCELTRYCONTINUE: u32 = 0x00000006;
pub const MB_ICONHAND: u32 = 0x00000010;
pub const MB_ICONQUESTION: u32 = 0x00000020;
pub const MB_ICONEXCLAMATION: u32 = 0x00000030;
pub const MB_ICONASTERISK: u32 = 0x00000040;
pub const MB_USERICON: u32 = 0x00000080;
pub const MB_ICONWARNING: u32 = MB_ICONEXCLAMATION;
pub const MB_ICONERROR: u32 = MB_ICONHAND;
pub const MB_ICONINFORMATION: u32 = MB_ICONASTERISK;
pub const MB_ICONSTOP: u32 = MB_ICONHAND;
pub const MB_DEFBUTTON1: u32 = 0x00000000;
pub const MB_DEFBUTTON2: u32 = 0x00000100;
pub const MB_DEFBUTTON3: u32 = 0x00000200;
pub const MB_DEFBUTTON4: u32 = 0x00000300;
pub const MB_APPLMODAL: u32 = 0x00000000;
pub const MB_SYSTEMMODAL: u32 = 0x00001000;
pub const MB_TASKMODAL: u32 = 0x00002000;
pub const MB_HELP: u32 = 0x00004000;
// Help Button
pub const MB_NOFOCUS: u32 = 0x00008000;
pub const MB_SETFOREGROUND: u32 = 0x00010000;
pub const MB_DEFAULT_DESKTOP_ONLY: u32 = 0x00020000;
pub const MB_TOPMOST: u32 = 0x00040000;
pub const MB_RIGHT: u32 = 0x00080000;
pub const MB_RTLREADING: u32 = 0x00100000;

//advapi32.dll
pub type CryptAcquireContextW = unsafe extern "system" fn(
    phProv: *mut usize,
    szContainer: usize,
    szProvider: *const u16,
    dwProvType: u32,
    dwFlags: u32,
) -> bool;
pub type CryptCreateHash = unsafe extern "system" fn(
    phProv: usize,
    ALG_ID: u32,
    hKey: usize,
    dwFlags: u32,
    phHash: *mut usize,
) -> bool;
pub type CryptHashData = unsafe extern "system" fn(
    hHash: usize,
    pbData: *const u8,
    dwDataLen: u32,
    dwFlags: u32,
) -> bool;
pub type CryptSetKeyParam =
    unsafe extern "system" fn(hKey: usize, dwParam: u32, pbData: *const u8, dwFlags: u32) -> bool;
pub type CryptGetKeyParam = unsafe extern "system" fn(
    hKey: usize,
    dwParam: u32,
    pbData: *mut u8,
    pbDataLen: *mut u32,
    dwFlags: u32,
) -> bool;
pub type CryptDeriveKey = unsafe extern "system" fn(
    hHash: usize,
    Algid: u32,
    hBaseData: usize,
    dwFlags: u32,
    phKey: *mut usize,
) -> bool;
pub type CryptDecrypt = unsafe extern "system" fn(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> bool;
pub type CryptEncrypt = unsafe extern "system" fn(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    dwBufLen: u32,
) -> bool;

pub type CryptReleaseContext = unsafe extern "system" fn(hProv: usize, dwFlags: u32) -> bool;
pub type CryptDestroyKey = unsafe extern "system" fn(hKey: usize) -> bool;
pub type CryptDestroyHash = unsafe extern "system" fn(hHash: usize) -> bool;

pub const ALG_CLASS_HASH: u32 = 4 << 13;
pub const ALG_TYPE_ANY: u32 = 0;
pub const ALG_SID_SHA_256: u32 = 12;
pub const CALG_SHA_256: u32 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256;

pub const ALG_CLASS_DATA_ENCRYPT: u32 = 3 << 13;
pub const ALG_TYPE_BLOCK: u32 = 3 << 9;
pub const ALG_SID_AES_256: u32 = 16;
pub const CALG_AES_256: u32 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256;

pub const KP_IV: u32 = 1;
pub const KP_BLOCKLEN: u32 = 8u32;
pub const KP_KEYLEN: u32 = 9u32;

pub const PROV_RSA_AES: u32 = 24;
pub const CRYPT_VERIFYCONTEXT: u32 = 0xF0000000;

pub type IMAGE_SUBSYSTEM = u16;
pub type IMAGE_DLL_CHARACTERISTICS = u16;
pub type IMAGE_FILE_CHARACTERISTICS = u16;
pub type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
pub type IMAGE_FILE_MACHINE = u16;
pub type IMAGE_SECTION_CHARACTERISTICS = u32;
pub type IMAGE_DIRECTORY_ENTRY = u32;

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
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: usize,
    pub ImageBaseAddress: usize,
    pub Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: usize,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: usize,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: usize,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: usize,
    pub EntryPoint: usize,
    pub SizeOfImage: usize,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
pub struct TRUNC_LDR_DATA_TABLE_ENTRY {
    //pub InLoadOrderLinks: LIST_ENTRY, // removed to start from InMemoryOrderLinks without recalculating offset.
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: usize,
    pub EntryPoint: usize,
    pub SizeOfImage: usize,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x4550;

#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    #[cfg(target_arch = "x86")]
    pub BaseOfData: u32,
    pub ImageBase: usize,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: usize,
    pub SizeOfStackCommit: usize,
    pub SizeOfHeapReserve: usize,
    pub SizeOfHeapCommit: usize,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: IMAGE_SECTION_CHARACTERISTICS,
}

#[repr(C)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub OriginalFirstThunk: u32,
    // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)
    pub TimeDateStamp: u32,
    // -1 if no forwarders
    pub ForwarderChain: u32,
    pub Name: u32,
    // RVA to IAT (if bound this IAT has actual addresses)
    pub FirstThunk: u32,
}

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
    //  WORD    TypeOffset[1];
}

#[repr(C)]
pub struct IMAGE_RELOC {
    pub bitfield: u16,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    // RVA from base of image
    pub AddressOfNames: u32,
    // RVA from base of image
    pub AddressOfNameOrdinals: u32, // RVA from base of image
}

#[repr(C)]
pub struct RESOURCE_DIRECTORY_TABLE {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub NumberOfNameEntries: u16,
    pub NumberOfIDEntries: u16,
}

#[repr(C)]
pub struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    pub Name: u32,
    pub OffsetToData: u32,
}

#[repr(C)]
pub struct RESOURCE_DATA_ENTRY {
    pub DataRVA: u32,
    pub DataSize: u32,
    pub CodePage: u32,
    pub Reserved: u32,
}

pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

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

pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;
pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_QUERY_HMODULE: u32 = 6;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
pub const IMAGE_REL_BASED_MACHINE_SPECIFIC_5: u16 = 5;
pub const IMAGE_REL_BASED_RESERVED: u16 = 6;
pub const IMAGE_REL_BASED_MACHINE_SPECIFIC_7: u16 = 7;
pub const IMAGE_REL_BASED_MACHINE_SPECIFIC_8: u16 = 8;
pub const IMAGE_REL_BASED_MACHINE_SPECIFIC_9: u16 = 9;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

#[cfg(all(target_pointer_width = "64"))]
pub const IMAGE_ORDINAL_FLAG: usize = 0x8000000000000000;
#[cfg(all(target_pointer_width = "32"))]
pub const IMAGE_ORDINAL_FLAG: usize = 0x80000000;

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: u16,
    pub Name: u8,
}
