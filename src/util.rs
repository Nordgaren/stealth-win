#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use std::arch::global_asm;
//use std::fs;
use std::mem::size_of;
use crate::windows::ntdll::{IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, RESOURCE_DATA_ENTRY, RESOURCE_DIRECTORY_TABLE};

pub unsafe fn str_len(ptr: *const u8, max: usize) -> usize {
    let mut pos = ptr as usize;
    let mut len = 0;
    while *(pos as *const u8) != 0 && len < max {
        len += 1;
        pos += 1;
    }

    len
}

pub fn get_resource_bytes(resource_id: u32, offset: usize, len: usize) -> Vec<u8> {
    let resource = unsafe { get_resource(resource_id) };
    let end = offset + len;

    resource[offset..end].to_vec()
}

pub fn get_unmapped_resource_bytes(resource_id: u32, offset: usize, len: usize) -> Vec<u8> {
    let resource = unsafe { get_unmapped_resource(resource_id) };
    let end = offset + len;

    resource[offset..end].to_vec()
}

unsafe fn get_resource(resource_id: u32) -> &'static [u8] {
    let pBaseAddr = get_dll_base();

    let pDosHdr = pBaseAddr as *const IMAGE_DOS_HEADER;
    let pNTHdr = (pBaseAddr + (*pDosHdr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let pOptionalHdr = &(*pNTHdr).OptionalHeader;
    let pResourceDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    let pResourceDirAddr =
        (pBaseAddr + pResourceDataDir.VirtualAddress as usize) as *const RESOURCE_DIRECTORY_TABLE;

    let pResourceDataEntry = get_resource_data_entry(pResourceDirAddr, resource_id);
    let pData = pBaseAddr + (*pResourceDataEntry).DataRVA as usize;
    std::slice::from_raw_parts(pData as *const u8, (*pResourceDataEntry).DataSize as usize)
}

unsafe fn get_unmapped_resource(resource_id: u32) -> &'static [u8] {
    let pBaseAddr = get_dll_base();
    // let pBaseAddr = fs::read(
    //     r"C:\Users\Nord\source\Hacking\Sektor7\RTO-MDI\03.Assignment\reflective-dll\target\debug\dyload.dll",
    // ).unwrap();
    // let pBaseAddr = pBaseAddr.as_ptr() as usize;
    let pDosHdr = pBaseAddr as *const IMAGE_DOS_HEADER;
    let pNTHdrs = (pBaseAddr + (*pDosHdr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let pOptionalHdr = &(*pNTHdrs).OptionalHeader;
    let pResourceDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    let pResourceDirAddrFOA = rva_to_foa(pNTHdrs, pResourceDataDir.VirtualAddress);
    let pResourceDirAddr =
        (pBaseAddr + pResourceDirAddrFOA as usize) as *const RESOURCE_DIRECTORY_TABLE;

    let pResourceDataEntry = get_resource_data_entry(pResourceDirAddr, resource_id);
    let pDataFOA = rva_to_foa(pNTHdrs, (*pResourceDataEntry).DataRVA);
    let pData = pBaseAddr + pDataFOA as usize;
    std::slice::from_raw_parts(pData as *const u8, (*pResourceDataEntry).DataSize as usize)
}

unsafe fn get_resource_data_entry(
    pResourceDirAddr: *const RESOURCE_DIRECTORY_TABLE,
    resource_id: u32,
) -> *const RESOURCE_DATA_ENTRY {
    //level 1: Resource type directory
    let mut offset = get_entry_offset_by_id(pResourceDirAddr, RT_RCDATA as u32);
    offset &= 0x7FFFFFFF;

    //level 2: Resource Name/ID subdirectory
    let pDataResourceDirAddr =
        (pResourceDirAddr as usize + offset as usize) as *const RESOURCE_DIRECTORY_TABLE;
    let mut offset = get_entry_offset_by_id(pDataResourceDirAddr, resource_id);
    offset &= 0x7FFFFFFF;

    //level 3: language subdirectory - just use the first entry.
    let pLangResourceDirAddr =
        (pResourceDirAddr as usize + offset as usize) as *const RESOURCE_DIRECTORY_TABLE;
    let pLangResourceEntries =
        pLangResourceDirAddr as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let pLangResourceEntry = pLangResourceEntries as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
    let offset = (*pLangResourceEntry).OffsetToData;

    (pResourceDirAddr as usize + offset as usize) as *const RESOURCE_DATA_ENTRY
}

unsafe fn get_entry_offset_by_id(
    pResourceDirAddr: *const RESOURCE_DIRECTORY_TABLE,
    id: u32,
) -> u32 {
    let pResourceEntries = pResourceDirAddr as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let sResourceDirectoryEntries: &[IMAGE_RESOURCE_DIRECTORY_ENTRY] = std::slice::from_raw_parts(
        pResourceEntries as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        ((*pResourceDirAddr).NumberOfNameEntries + (*pResourceDirAddr).NumberOfIDEntries) as usize,
    );

    for i in (*pResourceDirAddr).NumberOfNameEntries as usize..sResourceDirectoryEntries.len() {
        if sResourceDirectoryEntries[i].Name == id {
            return sResourceDirectoryEntries[i].OffsetToData;
        }
    }

    0
}

unsafe fn get_entry_offset_by_name(
    pResourceDirAddr: *const RESOURCE_DIRECTORY_TABLE,
    id: u32,
) -> u32 {
    let pResourceEntries = pResourceDirAddr as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let sResourceDirectoryEntries: &[IMAGE_RESOURCE_DIRECTORY_ENTRY] = std::slice::from_raw_parts(
        pResourceEntries as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        ((*pResourceDirAddr).NumberOfNameEntries + (*pResourceDirAddr).NumberOfIDEntries) as usize,
    );

    for i in 0..(*pResourceDirAddr).NumberOfNameEntries as usize {
        if sResourceDirectoryEntries[i].Name == id {
            return sResourceDirectoryEntries[i].OffsetToData;
        }
    }

    0
}

const ALIGN_16: usize = usize::MAX - 0xF;

pub unsafe fn get_dll_base() -> usize {
    // functions always end on 16 byte aligned address, relative to the beginning of the file.
    let mut pLibraryAddress = get_return() & ALIGN_16;

    loop {
        // for some reason, 16 byte alignment is unstable for this function, in x86, so use sizeof::<usize>() * 2
        pLibraryAddress -= size_of::<usize>() * 2;

        let pos = pLibraryAddress as *const u16;
        if IMAGE_DOS_SIGNATURE == *pos {
            let pDosHeader = pos as *const IMAGE_DOS_HEADER;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if (*pDosHeader).e_lfanew < 0x400 {
                // break if we have found a valid MZ/PE header
                let pNtHeaders =
                    (pLibraryAddress + (*pDosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
                if (*pNtHeaders).Signature == IMAGE_NT_SIGNATURE {
                    return pLibraryAddress;
                }
            }
        }
    }
}

extern "C" {
    pub fn get_return() -> usize;
}

#[cfg(all(windows, target_arch = "x86_64"))]
global_asm!(
    r"
.global get_return
get_return:
    mov rax, [rsp]
    ret",
);

#[cfg(all(windows, target_arch = "x86"))]
global_asm!(
    r"
.global _get_return
_get_return:
    mov eax, [esp]
    ret",
);

unsafe fn rva_to_foa(pNtHeaders: *const IMAGE_NT_HEADERS, dwRVA: u32) -> u32 {
    let pSectionHeaders =
        (pNtHeaders as usize + size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
    let sectionHeaders = std::slice::from_raw_parts(
        pSectionHeaders,
        (*pNtHeaders).FileHeader.NumberOfSections as usize,
    );

    if dwRVA < sectionHeaders[0].PointerToRawData {
        return dwRVA;
    }

    for i in 0..(*pNtHeaders).FileHeader.NumberOfSections as usize {
        if (dwRVA >= sectionHeaders[i].VirtualAddress)
            && (dwRVA <= sectionHeaders[i].VirtualAddress + sectionHeaders[i].SizeOfRawData)
        {
            return sectionHeaders[i].PointerToRawData + (dwRVA - sectionHeaders[i].VirtualAddress);
        }
    }

    return 0;
}

#[inline(always)]
pub(crate) fn low_word(n: usize) -> u16 {
    (n & 0xFFFF) as u16
}

#[inline(always)]
pub(crate) fn hi_word(n: usize) -> u16 {
    ((n >> 16) & 0xFFFF) as u16
}

#[inline(always)]
pub(crate) fn low_byte(n: usize) -> u8 {
    (n & 0xFF) as u8
}

#[inline(always)]
pub(crate) fn hi_byte(n: usize) -> u8 {
    ((n >> 8) & 0xFF) as u8
}
