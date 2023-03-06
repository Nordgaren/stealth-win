#![allow(non_snake_case)]

use std::fs;
use crate::consts::*;
use crate::winapi::*;
use crate::winternals::*;
use std::mem::size_of;

pub unsafe fn str_len(ptr: *const u8, max: usize) -> usize {
    let mut pos = ptr as usize;
    let mut len = 0;
    while *(pos as *const u8) != 0 && len < max {
        len += 1;
        pos += 1;
    }

    len
}

pub fn get_resource_bytes(resource_id: u32 ,offset: usize, len: usize) -> Vec<u8> {
    let mut resource = unsafe { get_resource(resource_id) };
    let end = offset + len;

    resource[offset..end].to_vec()
}

pub fn get_unmapped_resource_bytes(resource_id: u32 ,offset: usize, len: usize) -> Vec<u8> {
    let mut resource = unsafe { get_unmapped_resource(resource_id) };
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

unsafe fn get_unmapped_resource(resource_id: u32) ->&'static [u8]  {
    let pBaseAddr = get_dll_base();
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
    resource_id: u32
) -> *const RESOURCE_DATA_ENTRY {
    //level 1: Resource type directory
    let pResourceEntries = pResourceDirAddr as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let mut offset = get_id_entry_offset(pResourceDirAddr, pResourceEntries, RT_RCDATA as u32);
    offset &= 0x7FFFFFFF;

    //level 2: Resource Name/ID subdirectory
    let pDataResourceDirAddr =
        (pResourceDirAddr as usize + offset as usize) as *const RESOURCE_DIRECTORY_TABLE;
    let pDataResourceEntries =
        pDataResourceDirAddr as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let mut offset = get_id_entry_offset(
        pDataResourceDirAddr,
        pDataResourceEntries,
        resource_id,
    );
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

unsafe fn get_id_entry_offset(
    pResourceDirAddr: *const RESOURCE_DIRECTORY_TABLE,
    pResourceEntries: usize,
    id: u32,
) -> u32 {
    for i in (*pResourceDirAddr).NumberOfNameEntries
        ..(*pResourceDirAddr).NumberOfNameEntries + (*pResourceDirAddr).NumberOfIDEntries
    {
        let pResourceEntry = (pResourceEntries
            + i as usize * size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>())
            as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
        if (*pResourceEntry).Name == id {
            return (*pResourceEntry).OffsetToData;
        }
    }

    0
}

pub unsafe fn get_dll_base() -> usize {
    let mut uiLibraryAddress = get_dll_base as usize;
    loop {
        uiLibraryAddress -= 0x10; //functions always end on 16 byte aligned address, relative to the beginning fo the file.

        let pos = uiLibraryAddress as *const u16;
        if IMAGE_DOS_SIGNATURE == *pos {
            let header = pos as *const IMAGE_DOS_HEADER;
            if (*header).e_lfanew < 0x400 {
                return uiLibraryAddress;
            }
        }
    }
}

unsafe fn rva_to_foa(pNtHeaders: *const IMAGE_NT_HEADERS, dwRVA: u32) -> u32 {
    let pSectionHeaders = (pNtHeaders as usize + size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
    let sectionHeaders = std::slice::from_raw_parts(pSectionHeaders, (*pNtHeaders).FileHeader.NumberOfSections as usize);

    for i in 0..(*pNtHeaders).FileHeader.NumberOfSections as usize {
        if (dwRVA >= sectionHeaders[i].VirtualAddress) && (dwRVA <= sectionHeaders[i].VirtualAddress + sectionHeaders[i].SizeOfRawData)
        {
            return sectionHeaders[i].PointerToRawData + (dwRVA - sectionHeaders[i].VirtualAddress);
        }
    }

    return 0;
}
