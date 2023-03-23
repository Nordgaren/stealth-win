#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use std::arch::global_asm;
use std::mem;
//use std::fs;
use crate::windows::ntdll::{
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS,
    IMAGE_NT_SIGNATURE, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, RESOURCE_DATA_ENTRY,
    RESOURCE_DIRECTORY_TABLE,
};
use std::mem::size_of;
use std::ptr::{addr_of, addr_of_mut};

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

    let pDosHdr: &IMAGE_DOS_HEADER = mem::transmute(pBaseAddr);
    let pNTHdr: &IMAGE_NT_HEADERS = mem::transmute(pBaseAddr + pDosHdr.e_lfanew as usize);
    let pOptionalHdr = &pNTHdr.OptionalHeader;
    let pResourceDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    let pResourceDirAddr: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(pBaseAddr + pResourceDataDir.VirtualAddress as usize);

    let pResourceDataEntry = get_resource_data_entry(pResourceDirAddr, resource_id);
    let pData = pBaseAddr + pResourceDataEntry.DataRVA as usize;
    std::slice::from_raw_parts(pData as *const u8, pResourceDataEntry.DataSize as usize)
}

unsafe fn get_unmapped_resource(resource_id: u32) -> &'static [u8] {
    let pBaseAddr = get_dll_base();

    let pDosHdr: &IMAGE_DOS_HEADER = mem::transmute(pBaseAddr);
    let pNTHdr: &IMAGE_NT_HEADERS = mem::transmute(pBaseAddr + pDosHdr.e_lfanew as usize);
    let pOptionalHdr = &pNTHdr.OptionalHeader;
    let pResourceDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    let pResourceDirAddrFOA = rva_to_foa(pNTHdr, pResourceDataDir.VirtualAddress);
    let pResourceDirAddr: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(pBaseAddr + pResourceDirAddrFOA as usize);

    let pResourceDataEntry = get_resource_data_entry(pResourceDirAddr, resource_id);
    let pDataFOA = rva_to_foa(pNTHdr, pResourceDataEntry.DataRVA);
    let pData = pBaseAddr + pDataFOA as usize;
    std::slice::from_raw_parts(pData as *const u8, pResourceDataEntry.DataSize as usize)
}

unsafe fn get_resource_data_entry(
    pResourceDirAddr: &RESOURCE_DIRECTORY_TABLE,
    resource_id: u32,
) -> &'static RESOURCE_DATA_ENTRY {
    //level 1: Resource type directory
    let mut offset = get_entry_offset_by_id(pResourceDirAddr, RT_RCDATA as u32);
    offset &= 0x7FFFFFFF;

    //level 2: Resource Name/ID subdirectory
    let pDataResourceDirAddr: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(addr_of!(*pResourceDirAddr) as usize + offset as usize);
    let mut offset = get_entry_offset_by_id(pDataResourceDirAddr, resource_id);
    offset &= 0x7FFFFFFF;

    //level 3: language subdirectory - just use the first entry.
    let pLangResourceDirAddr: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(addr_of!(*pResourceDirAddr) as usize + offset as usize);
    let pLangResourceEntries =
        addr_of!(*pLangResourceDirAddr) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let pLangResourceEntry: &IMAGE_RESOURCE_DIRECTORY_ENTRY = mem::transmute(pLangResourceEntries);
    let offset = pLangResourceEntry.OffsetToData;

    mem::transmute(addr_of!(*pResourceDirAddr) as usize + offset as usize)
}

unsafe fn get_entry_offset_by_id(pResourceDirAddr: &RESOURCE_DIRECTORY_TABLE, id: u32) -> u32 {
    let pResourceEntries =
        addr_of!(*pResourceDirAddr) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let sResourceDirectoryEntries = std::slice::from_raw_parts(
        pResourceEntries as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        (pResourceDirAddr.NumberOfNameEntries + pResourceDirAddr.NumberOfIDEntries) as usize,
    );

    for i in pResourceDirAddr.NumberOfNameEntries as usize..sResourceDirectoryEntries.len() {
        if sResourceDirectoryEntries[i].Name == id {
            return sResourceDirectoryEntries[i].OffsetToData;
        }
    }

    0
}

unsafe fn get_entry_offset_by_name(pResourceDirAddr: &RESOURCE_DIRECTORY_TABLE, id: u32) -> u32 {
    let pResourceEntries =
        addr_of!(*pResourceDirAddr) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let sResourceDirectoryEntries = std::slice::from_raw_parts(
        pResourceEntries as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        (pResourceDirAddr.NumberOfNameEntries + pResourceDirAddr.NumberOfIDEntries) as usize,
    );

    for i in 0..pResourceDirAddr.NumberOfNameEntries as usize {
        if sResourceDirectoryEntries[i].Name == id {
            return sResourceDirectoryEntries[i].OffsetToData;
        }
    }

    0
}

const ALIGN_16: usize = usize::MAX - 0xF;

pub unsafe fn get_dll_base() -> usize {
    // functions always end on 16 byte aligned address, relative to the beginning of the file.
    let mut pLibraryAddress = get_return_address() & ALIGN_16;

    loop {
        // for some reason, 16 byte alignment is unstable for this function, in x86, so use sizeof::<usize>() * 2
        pLibraryAddress -= size_of::<usize>() * 2;

        let pos = pLibraryAddress as *const u16;
        if *pos == IMAGE_DOS_SIGNATURE {
            let pDosHeader: &IMAGE_DOS_HEADER = mem::transmute(pos);
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if pDosHeader.e_lfanew < 0x400 {
                // break if we have found a valid MZ/PE header
                let pNtHeaders: &IMAGE_NT_HEADERS = mem::transmute(pLibraryAddress + pDosHeader.e_lfanew as usize);
                if pNtHeaders.Signature == IMAGE_NT_SIGNATURE {
                    return pLibraryAddress;
                }
            }
        }
    }
}

extern "C" {
    pub fn get_return_address() -> usize;
}

#[cfg(all(windows, target_arch = "x86_64"))]
global_asm!(
    r"
.global get_return_address
get_return_address:
    mov rax, [rsp]
    ret",
);

#[cfg(all(windows, target_arch = "x86"))]
global_asm!(
    r"
.global _get_return_address
_get_return_address:
    mov eax, [esp]
    ret",
);

unsafe fn rva_to_foa(pNtHeaders: &IMAGE_NT_HEADERS, dwRVA: u32) -> u32 {
    let pSectionHeaders = addr_of!(*pNtHeaders) as usize + size_of::<IMAGE_NT_HEADERS>();
    let sectionHeaders = std::slice::from_raw_parts(
        pSectionHeaders as *const IMAGE_SECTION_HEADER,
        pNtHeaders.FileHeader.NumberOfSections as usize,
    );

    if dwRVA < sectionHeaders[0].PointerToRawData {
        return dwRVA;
    }

    for i in 0..pNtHeaders.FileHeader.NumberOfSections as usize {
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

#[cfg(test)]
pub(crate) unsafe fn print_buffer_as_string(string_ptr: *const u8, len: usize) {
    let buff = std::slice::from_raw_parts(string_ptr, len);
    let str = String::from_utf8(buff.to_vec()).unwrap();
    println!("{}", str);
}

#[cfg(test)]
pub(crate) unsafe fn print_buffer_as_string_utf16(string_ptr: *const u16, len: usize) {
    let buff = std::slice::from_raw_parts(string_ptr, len);
    let str = String::from_utf16(buff).unwrap();
    println!("{}", str);
}
