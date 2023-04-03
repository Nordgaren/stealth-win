#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use std::arch::global_asm;
use std::ffi::CStr;
use std::mem;
use crate::windows::kernel32::MAX_PATH;
use crate::windows::ntdll::{
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS,
    IMAGE_NT_SIGNATURE, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, RESOURCE_DATA_ENTRY,
    RESOURCE_DIRECTORY_TABLE,
};
use std::mem::size_of;
use std::ptr::{addr_of, addr_of_mut};

pub fn get_resource_bytes(resource_id: u32, offset: usize, len: usize) -> &'static [u8] {
    let resource = unsafe {
        let base_address = get_dll_base();
        if check_mapped(base_address) {
            get_resource_mapped(base_address, resource_id)
        } else {
            get_resource_unmapped(base_address, resource_id)
        }
    };

    let end = offset + len;
    &resource[offset..end]
}

unsafe fn check_mapped(base_address: usize) -> bool {
    let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address);
    let first_section: &IMAGE_SECTION_HEADER =
        mem::transmute(base_address + dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS>());
    let section_on_disk = base_address + first_section.PointerToRawData as usize;
    let ptr_to_zero = section_on_disk as *const u64;

    *ptr_to_zero == 0
}

unsafe fn get_resource_mapped(base_address: usize, resource_id: u32) -> &'static [u8] {
    let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_header: &IMAGE_NT_HEADERS = mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_header.OptionalHeader;
    let resource_data_dir = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];

    let resource_directory_table: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(base_address + resource_data_dir.VirtualAddress as usize);

    let resource_data_entry = get_resource_data_entry(resource_directory_table, resource_id);
    let data = base_address + resource_data_entry.DataRVA as usize;
    std::slice::from_raw_parts(data as *const u8, resource_data_entry.DataSize as usize)
}

unsafe fn get_resource_unmapped(base_address: usize, resource_id: u32) -> &'static [u8] {
    let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_header: &IMAGE_NT_HEADERS = mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_header.OptionalHeader;
    let resource_data_dir = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];

    let resource_directory_table_foa = rva_to_foa(nt_header, resource_data_dir.VirtualAddress);
    let resource_directory_table: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(base_address + resource_directory_table_foa as usize);

    let resource_data_entry = get_resource_data_entry(resource_directory_table, resource_id);
    let data_foa = rva_to_foa(nt_header, resource_data_entry.DataRVA);
    let data = base_address + data_foa as usize;
    std::slice::from_raw_parts(data as *const u8, resource_data_entry.DataSize as usize)
}

unsafe fn get_resource_data_entry(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    resource_id: u32,
) -> &'static RESOURCE_DATA_ENTRY {
    let resource_directory_table_addr = addr_of!(*resource_directory_table) as usize;

    //level 1: Resource type directory
    let mut offset = get_entry_offset_by_id(resource_directory_table, RT_RCDATA as u32);
    offset &= 0x7FFFFFFF;

    //level 2: Resource Name/ID subdirectory
    let resource_directory_table_name_id: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(resource_directory_table_addr + offset as usize);
    let mut offset = get_entry_offset_by_id(resource_directory_table_name_id, resource_id);
    offset &= 0x7FFFFFFF;

    //level 3: language subdirectory - just use the first entry.
    let resource_directory_table_lang: &RESOURCE_DIRECTORY_TABLE =
        mem::transmute(resource_directory_table_addr as usize + offset as usize);
    let resource_directory_table_lang_entries =
        addr_of!(*resource_directory_table_lang) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let resource_directory_table_lang_entry: &IMAGE_RESOURCE_DIRECTORY_ENTRY =
        mem::transmute(resource_directory_table_lang_entries);
    let offset = resource_directory_table_lang_entry.OffsetToData;

    mem::transmute(resource_directory_table_addr as usize + offset as usize)
}

unsafe fn get_entry_offset_by_id(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    id: u32,
) -> u32 {
    // We have to skip the Name entries, here, to iterate over the entires by Id.
    let resource_entries_address = addr_of!(*resource_directory_table) as usize
        + size_of::<RESOURCE_DIRECTORY_TABLE>()
        + (size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>()
            * resource_directory_table.NumberOfNameEntries as usize);
    let resource_directory_entries = std::slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfIDEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        if resource_directory_entry.Id == id {
            return resource_directory_entry.OffsetToData;
        }
    }

    0
}

unsafe fn get_entry_offset_by_name(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    name: &[u8],
) -> u32 {
    let resource_entries_address =
        addr_of!(*resource_directory_table) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let resource_directory_entries = std::slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfNameEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        let name_ptr =
            addr_of!(*resource_directory_table) as usize + resource_directory_entry.Id as usize;
        let resource_name =
            std::slice::from_raw_parts(name_ptr as *const u8, strlen(name_ptr as *const u8));
        if resource_name == name {
            return resource_directory_entry.OffsetToData;
        }
    }

    0
}

const PAGE_BOUNDRY: usize = 0x1000;

pub unsafe fn get_dll_base() -> usize {
    // file will be mapped to the start of a page boundary.
    let mut module_address = get_return_address() & !(PAGE_BOUNDRY - 1);

    loop {
        let magic = module_address as *const u16;
        if *magic == IMAGE_DOS_SIGNATURE {
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(magic);
            // Some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if dos_header.e_lfanew < 0x400 {
                // break if we have found a valid MZ/PE header
                let nt_headers: &IMAGE_NT_HEADERS =
                    mem::transmute(module_address + dos_header.e_lfanew as usize);
                if nt_headers.Signature == IMAGE_NT_SIGNATURE {
                    return module_address;
                }
            }
        }

        // Just search on the page boundaries.
        module_address -= PAGE_BOUNDRY;
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

unsafe fn rva_to_foa(nt_headers: &IMAGE_NT_HEADERS, rva: u32) -> u32 {
    let section_headers_pointer = addr_of!(*nt_headers) as usize + size_of::<IMAGE_NT_HEADERS>();
    let section_headers = std::slice::from_raw_parts(
        section_headers_pointer as *const IMAGE_SECTION_HEADER,
        nt_headers.FileHeader.NumberOfSections as usize,
    );

    if rva < section_headers[0].PointerToRawData {
        return rva;
    }

    for section_header in section_headers {
        if (rva >= section_header.VirtualAddress)
            && (rva <= section_header.VirtualAddress + section_header.SizeOfRawData)
        {
            return section_header.PointerToRawData + (rva - section_header.VirtualAddress);
        }
    }

    return 0;
}

#[inline(always)]
pub fn lo_word(n: usize) -> u16 {
    (n & 0xFFFF) as u16
}

#[inline(always)]
pub fn hi_word(n: usize) -> u16 {
    ((n >> 16) & 0xFFFF) as u16
}

#[inline(always)]
pub fn lo_byte(n: usize) -> u8 {
    (n & 0xFF) as u8
}

#[inline(always)]
pub fn hi_byte(n: usize) -> u8 {
    ((n >> 8) & 0xFF) as u8
}

pub fn find_pos(string: &[u8], char: u8) -> usize {
    for (i, s) in string.iter().enumerate() {
        if *s == char {
            return i;
        }
    }

    usize::MAX
}

// Need internal function for this in unmapped PE state.
pub fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 && len <= MAX_PATH {
        len += 1;
    }

    len
}
#[inline(always)]
pub fn strlen_with_null(s: *const u8) -> usize {
    strlen(s) + 1
}

// These two xor comparison methods were inspired by Jonas @jonasLyk. Thanks for the idea to just use the xor'd strings. :)
const CASE_BIT: u8 = 0x20;

// &[u8] is the second easiest way to deal with C-style strings in Rust. Here we will take in the xor'd string
// as bytes, a CString from the place in memory we are searching, and the key. Do the same as the
// wide string version, without the casts. This way we can compare the strings without allocating and
// xoring memory. You will want to use this with case_insensitive with any string embedded in the resource,
// as they are all lowercase.
pub fn compare_xor_str_and_str_bytes(
    xor_string_bytes: &[u8],
    string_bytes: &[u8],
    key: &[u8],
) -> bool {
    if xor_string_bytes.len() != string_bytes.len() && string_bytes.len() != key.len() {
        return false;
    }

    for i in 0..xor_string_bytes.len() {
        let mut val = string_bytes[i];
        if val >= 0x41 && val <= 0x5A {
            val ^= CASE_BIT
        }

        val ^= key[i];
        if val != xor_string_bytes[i] {
            return false;
        }
    }

    true
}

// This function assumes that the wide string version of each character in the string is just the u16
// version of the ASCII character. The DLL names are all stored in Windows memory as wide strings, and this is
// the best solution I have without allocating on the heap for wide string encoding.
// You will want to use this with case_insensitive with any string embedded in the resource, as they are all lowercase.
pub fn compare_xor_str_and_w_str_bytes(
    xor_string_bytes: &[u8],
    w_string_bytes: &[u16],
    key: &[u8],
) -> bool {
    if xor_string_bytes.len() != w_string_bytes.len() && w_string_bytes.len() != key.len() {
        return false;
    }

    for i in 0..xor_string_bytes.len() {
        let mut w_val = w_string_bytes[i];
        if w_val >= 0x41 && w_val <= 0x5A {
            w_val ^= CASE_BIT as u16;
        }
        w_val ^= key[i] as u16;
        if w_val != xor_string_bytes[i] as u16 {
            return false;
        }
    }

    true
}

// &[u8] is the second easiest way to deal with C-style strings in Rust. Here we will take in the two
// strings as &[u8] and &[u16], and will compare them u16 by u16 after casting the u8 to u16.
// You will want to use this with case_insensitive with any string embedded in the resource, as they are all lowercase.
pub fn compare_str_and_w_str_bytes(
    string_bytes: &[u8],
    w_string_bytes: &[u16],
    case_insensitive: bool,
) -> bool {
    if string_bytes.len() != w_string_bytes.len() {
        return false;
    }

    for i in 0..string_bytes.len() {
        let mut val = string_bytes[i] as u16;
        let mut val2 = w_string_bytes[i];

        if case_insensitive {
            if val >= 0x41 && val <= 0x5A {
                val ^= CASE_BIT as u16
            }
            if val2 >= 0x41 && val2 <= 0x5A {
                val2 ^= CASE_BIT as u16
            }
        }

        if val != val2 {
            return false;
        }
    }

    true
}

// &[u8] is the second easiest way to deal with C-style strings in Rust. Here we will take in the two
// strings as &[u8], and will compare them byte by byte. You will want to use this with case_insensitive with
// any string embedded in the resource, as they are all lowercase.
pub fn compare_strs_as_bytes(
    string_bytes: &[u8],
    othr_string_bytes: &[u8],
    case_insensitive: bool,
) -> bool {
    if string_bytes.len() != othr_string_bytes.len() {
        return false;
    }

    for i in 0..string_bytes.len() {
        let mut val = string_bytes[i];
        let mut val2 = othr_string_bytes[i];

        if case_insensitive {
            if val >= 0x41 && val <= 0x5A {
                val ^= CASE_BIT
            }
            if val2 >= 0x41 && val2 <= 0x5A {
                val2 ^= CASE_BIT
            }
        }

        if val != val2 {
            return false;
        }
    }

    true
}

// Because you can't use the normal rust copy function in an unmapped PE, for some reason.
pub unsafe fn copy_buffer<T>(src: *const T, dst: *mut T, len: usize) {
    let total_size = size_of::<T>() * len;
    let src_slice = std::slice::from_raw_parts(src as *const u8, total_size);
    let dst_slice = std::slice::from_raw_parts_mut(dst as *mut u8, total_size);

    for i in 0..total_size {
        dst_slice[i] = src_slice[i];
    }
}
