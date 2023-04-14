#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::windows::kernel32::{GetSystemDirectoryA, GetSystemDirectoryW, MAX_PATH, PAGE_SIZE};
use crate::windows::ntdll::{
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS,
    IMAGE_NT_SIGNATURE, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, RESOURCE_DATA_ENTRY,
    RESOURCE_DIRECTORY_TABLE,
};
use crate::windows::pe::PE;
use alloc::string::String;
use core::arch::global_asm;
use core::mem;
use core::mem::size_of;

pub fn get_resource_bytes(resource_id: u32, offset: usize, len: usize) -> &'static [u8] {
    let resource = unsafe {
        PE::from_address_unchecked(get_dll_base())
            .get_pe_resource(resource_id)
            .unwrap()
    };

    let end = offset + len;
    &resource[offset..end]
}

pub unsafe fn get_dll_base() -> usize {
    // file will be mapped to the start of a page boundary.
    let mut module_address = get_return_address() & !(PAGE_SIZE - 1);

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
        module_address -= PAGE_SIZE;
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

// These are macros in the windows headers. Didn't feel like they would be good rust macros.
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

pub fn find_char(string: &[u8], char: u8) -> Option<usize> {
    string.into_iter().position(|c| *c == char)
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

// Need internal function for this in unmapped PE state.
pub fn strlenw(s: *const u16) -> usize {
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 && len <= MAX_PATH {
        len += 1;
    }

    len
}

#[inline(always)]
pub fn strlenw_with_null(s: *const u16) -> usize {
    strlenw(s) + 1
}

// These two xor comparison methods were inspired by Jonas @jonasLyk. Thanks for the idea to just
// use the xor'd strings. as they are :)
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

// &[u8] is the second easiest way to deal with C-style strings in Rust. Here we will take in the two
// strings as &[u8], and will compare them byte by byte.
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

// This function assumes that the wide string version of each character in the string is just the u16
// version of the ASCII character. Here we will take in the two strings as &[u8] and &[u16], and will
// compare them u16 by u16 after casting the u8 to u16. You will want to use this with case_insensitive
// with any string embedded in the resource, as they are all lowercase.
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
// strings as &[u8], and will compare them byte by byte. You will want to use this with case_insensitive
// with any string embedded in the resource, as they are all lowercase.This function is case insensitive.
// If you want case sensitive comparison, you can just compare the u8 slices to each other, directly.
pub fn case_insensitive_compare_strs_as_bytes(
    string_bytes: &[u8],
    other_string_bytes: &[u8],
) -> bool {
    if string_bytes.len() != other_string_bytes.len() {
        return false;
    }

    for i in 0..string_bytes.len() {
        let mut val = string_bytes[i];
        let mut val2 = other_string_bytes[i];

        if val >= 0x41 && val <= 0x5A {
            val ^= CASE_BIT
        }
        if val2 >= 0x41 && val2 <= 0x5A {
            val2 ^= CASE_BIT
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
    let src_slice = core::slice::from_raw_parts(src as *const u8, total_size);
    let dst_slice = core::slice::from_raw_parts_mut(dst as *mut u8, total_size);

    for i in 0..total_size {
        dst_slice[i] = src_slice[i];
    }
}

pub unsafe fn zero_memory<T>(buffer: *mut T, len: usize) {
    let total_size = size_of::<T>() * len;
    let dst_slice = core::slice::from_raw_parts_mut(buffer as *mut u8, total_size);

    for i in 0..total_size {
        dst_slice[i] = 0;
    }
}

pub fn get_system_dir() -> String {
    unsafe {
        let mut buffer = [0; MAX_PATH + 1];
        GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
        String::from_utf8(buffer[..strlen(buffer.as_ptr())].to_vec()).unwrap()
    }
}

pub fn get_system_dir_w() -> String {
    unsafe {
        let mut buffer = [0; MAX_PATH + 1];
        GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
        let len = strlenw(buffer.as_ptr());
        String::from_utf16(&buffer[..len]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::*;
    use crate::windows::kernel32::GetModuleHandleA;

    #[test]
    fn get_return_addr() {
        unsafe {
            let return_addr = get_return_address();
            let base_addr = GetModuleHandleA(0 as *const u8);
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_addr);
            let nt_header: &IMAGE_NT_HEADERS =
                mem::transmute(base_addr + dos_header.e_lfanew as usize);
            let end_addr = base_addr + nt_header.OptionalHeader.SizeOfImage as usize;

            assert!((base_addr..end_addr).contains(&return_addr));
        }
    }

    #[test]
    fn get_resource() {
        unsafe {
            let resource = get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN);
            assert_eq!(resource.len(), "kernel32.dll".len())
        }
    }

    #[test]
    fn get_dll_base_test() {
        unsafe {
            let dll_base = get_dll_base();
            let handle = GetModuleHandleA(0 as *const u8);
            assert_eq!(dll_base, handle)
        }
    }
}
