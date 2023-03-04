#![allow(non_snake_case)]

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

pub fn get_resource_bytes(offset: usize, len: usize) -> Vec<u8> {
    let mut resource = unsafe { get_resource() };
    let end = offset + len;

    resource[offset..end].to_vec()
}

unsafe fn get_resource() -> Vec<u8> {
    let pBaseAddr = get_dll_module_handle();

    let pOptionalHdr = get_image_nt_headers(pBaseAddr);
    let pResourceDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    //level 1: Resource directory
    let pResourceDirAddr =
        (pBaseAddr + pResourceDataDir.VirtualAddress as usize) as *const RESOURCE_DIRECTORY_TABLE;

    let pResourceDataEntry = get_resource_data_entry(pResourceDirAddr);
    let pData = pBaseAddr + (*pResourceDataEntry).DataRVA as usize;
    std::slice::from_raw_parts(pData as *const u8, (*pResourceDataEntry).DataSize as usize).to_vec()
}

unsafe fn get_unmapped_resource() -> Vec<u8> {
    let pBaseAddr = get_dll_module_handle();

    let pOptionalHdr = get_image_nt_headers(pBaseAddr);
    let pResourceDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    //level 1: Resource directory
    let pResourceDirAddr =
        (pBaseAddr + pResourceDataDir.VirtualAddress as usize) as *const RESOURCE_DIRECTORY_TABLE;

    let pResourceDataEntry = get_resource_data_entry(pResourceDirAddr);
    let pData = pBaseAddr + (*pResourceDataEntry).DataRVA as usize;
    std::slice::from_raw_parts(pData as *const u8, (*pResourceDataEntry).DataSize as usize).to_vec()
}

unsafe fn get_image_nt_headers(pBaseAddr: usize) -> &'static IMAGE_OPTIONAL_HEADER {
    let pDosHdr = pBaseAddr as *const IMAGE_DOS_HEADER;
    let pNTHdr = (pBaseAddr + (*pDosHdr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    &(*pNTHdr).OptionalHeader
}

unsafe fn get_resource_data_entry(pResourceDirAddr: *const RESOURCE_DIRECTORY_TABLE) -> *const RESOURCE_DATA_ENTRY {
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
        RESOURCE_ID as u32,
    );
    offset &= 0x7FFFFFFF;

    //level 3: language subdirectory - just use the first entry.
    let pLangResourceDirAddr =
        (pResourceDirAddr as usize + offset as usize) as *const RESOURCE_DIRECTORY_TABLE;
    let pLangResourceEntries =
        pLangResourceDirAddr as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let pLangResourceEntry = pLangResourceEntries as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
    let offset = (*pLangResourceEntry).OffsetToData;

    //resource data entry
    (pResourceDirAddr as usize + offset as usize) as *const RESOURCE_DATA_ENTRY
}

unsafe fn get_id_entry_offset(
    pResourceDirAddr: *const RESOURCE_DIRECTORY_TABLE,
    pResourceEntries: usize,
    target_dir: u32,
) -> u32 {
    for i in (*pResourceDirAddr).NumberOfNameEntries
        ..(*pResourceDirAddr).NumberOfNameEntries + (*pResourceDirAddr).NumberOfIDEntries
    {
        let pResourceEntry = (pResourceEntries
            + i as usize * size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>())
            as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
        if (*pResourceEntry).Name == target_dir {
            return (*pResourceEntry).OffsetToData;
        }
    }

    0
}

pub unsafe fn get_dll_module_handle() -> usize {
    let mut uiLibraryAddress = get_dll_module_handle as usize;
    loop {
        uiLibraryAddress -= 8;

        let pos = uiLibraryAddress as *const u16;
        if IMAGE_DOS_SIGNATURE == *pos {
            let header = pos as *const IMAGE_DOS_HEADER;
            if (*header).e_lfanew < 0x400 {
                return uiLibraryAddress;
            }
        }
    }
}
