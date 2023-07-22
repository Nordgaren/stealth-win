extern crate alloc;
use super::*;
use crate::std::fs;
use crate::util::strlenw;
use crate::windows::pe::PE;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp;
use core::cmp::max;
use core::mem::size_of;

#[test]
fn geb_peb() {
    unsafe {
        let peb = get_peb();
        let peb_addr: usize = mem::transmute(peb);
        assert_ne!(peb_addr, 0);
    }
}

#[test]
fn get_module_handle() {
    unsafe {
        let kernel32 = GetModuleHandleInternal("kernel32.dll".as_bytes());
        assert_ne!(kernel32, 0)
    }
}

#[test]
fn get_proc_address() {
    unsafe {
        let load_library_a_addr = GetProcAddressInternal(
            GetModuleHandleInternal("kernel32.dll".as_bytes()),
            "LoadLibraryA".as_bytes(),
        );
        assert_ne!(load_library_a_addr, 0)
    }
}

fn get_function_ordinal(dll_name: &[u8], function_name: &[u8]) -> u16 {
    unsafe {
        let base_addr = GetModuleHandleA(dll_name.as_ptr());
        let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_addr);
        let nt_headers: &IMAGE_NT_HEADERS =
            mem::transmute(base_addr + dos_header.e_lfanew as usize);
        let export_dir =
            &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        let image_export_directory: &IMAGE_EXPORT_DIRECTORY =
            mem::transmute(base_addr + export_dir.VirtualAddress as usize);

        let name_dir = slice::from_raw_parts(
            (base_addr + image_export_directory.AddressOfNames as usize) as *const u32,
            image_export_directory.NumberOfNames as usize,
        );
        let ordinal_dir = slice::from_raw_parts(
            (base_addr + image_export_directory.AddressOfNameOrdinals as usize) as *const u16,
            image_export_directory.NumberOfNames as usize,
        );

        for i in 0..name_dir.len() {
            let name = slice::from_raw_parts(
                (base_addr + name_dir[i] as usize) as *const u8,
                strlen((base_addr + name_dir[i] as usize) as *const u8),
            );

            if name == function_name {
                return ordinal_dir[i] + image_export_directory.Base as u16;
            }
        }
    }

    0u16
}

#[test]
fn get_proc_address_by_ordinal() {
    unsafe {
        let ordinal =
            get_function_ordinal("KERNEL32.DLL\0".as_bytes(), "LoadLibraryA".as_bytes()) as u32;
        let load_library_a_address_ordinal = GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            ordinal.to_le_bytes().as_slice(),
        );
        let load_library_a_address = GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            "LoadLibraryA".as_bytes(),
        );
        let load_library: FnLoadLibraryA = mem::transmute(load_library_a_address_ordinal);

        assert_eq!(load_library_a_address_ordinal, load_library_a_address);
    }
}

#[test]
fn get_fwd_proc_address() {
    unsafe {
        let acquire_srw_lock_exclusive = GetProcAddressInternal(
            GetModuleHandleInternal("KERNEL32.DLL".as_bytes()),
            "AcquireSRWLockExclusive".as_bytes(),
        );
        let real_acquire_srw_lock_exclusive = GetProcAddress(GetModuleHandleA("kernel32.dll\0".as_ptr()), "AcquireSRWLockExclusive\0".as_ptr());

        assert_eq!(acquire_srw_lock_exclusive, real_acquire_srw_lock_exclusive)
    }
}

#[test]
fn get_module_handle_x_test() {
    unsafe {
        let kernel32 = GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN));
        let kernel32_normal = GetModuleHandleA("KERNEL32.DLL\0".as_ptr());
        assert_eq!(kernel32, kernel32_normal);
    }
}

#[test]
fn get_proc_address_x_test() {
    unsafe {
        let load_library_a_handle_x = GetProcAddressX(
            GetModuleHandleX(&XORString::from_offsets(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN)),
            &XORString::from_offsets(LOADLIBRARYA_POS, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN),
        );
        let load_library_a_handle = GetProcAddress(
            GetModuleHandleA("KERNEL32.DLL\0".as_ptr()),
            "LoadLibraryA\0".as_ptr(),
        );
        assert_eq!(load_library_a_handle_x, load_library_a_handle);
    }
}

#[test]
fn get_system_directory_a() {
    unsafe {
        let mut buffer = [0; MAX_PATH + 1];
        let out = GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
        let path = String::from_utf8(buffer[..out as usize].to_vec()).unwrap();
        assert!(path.ends_with(r"\Windows\system32"))
    }
}

#[test]
fn get_system_directory_w() {
    unsafe {
        let mut buffer = [0; MAX_PATH + 1];
        let out = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
        let path = String::from_utf16(&buffer[..out as usize]).unwrap();
        assert!(path.ends_with(r"\Windows\system32"))
    }
}
