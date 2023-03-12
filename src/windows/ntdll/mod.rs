#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

pub type DllMain =
extern "stdcall" fn(hinstDLL: usize, dwReason: u32, lpReserved: *mut usize) -> i32;

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: u16,
    pub Name: u8,
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

pub type IMAGE_SUBSYSTEM = u16;
pub type IMAGE_DLL_CHARACTERISTICS = u16;
pub type IMAGE_FILE_CHARACTERISTICS = u16;
pub type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
pub type IMAGE_FILE_MACHINE = u16;
pub type IMAGE_SECTION_CHARACTERISTICS = u32;
pub type IMAGE_DIRECTORY_ENTRY = u32;

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: usize,
    pub ImageBaseAddress: usize,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: u32,
    pub SubSystemData: usize,
    pub ProcessHeap: usize,
    pub FastPebLock: usize,
    pub AtlThunkSListPtr: usize,
    pub IFEOKey: usize,
    pub CrossProcessFlags: u32,
    pub KernelCallbackTable: usize,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: usize,
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