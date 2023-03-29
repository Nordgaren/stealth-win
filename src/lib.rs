#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused)]

pub mod consts;
pub mod crypto_util;
pub mod util;
pub mod windows;

use crate::consts::*;
use crate::crypto_util::{get_aes_encrypted_resource_bytes, get_xor_encrypted_bytes};
use crate::windows::kernel32::LoadLibraryA;
use crate::windows::user32::*;

#[cfg(test)]
mod tests {
    use crate::consts::{
        KERNEL32_DLL_KEY, KERNEL32_DLL_LEN, KERNEL32_DLL_POS, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN,
        LOADLIBRARYA_POS, RESOURCE_ID, USER32_DLL_LEN, USER32_DLL_POS,
    };
    use crate::crypto_util::{get_aes_encrypted_resource_bytes, get_xor_encrypted_bytes};
    use crate::util::{get_dll_base, get_resource_bytes, get_return_address};
    use crate::windows::kernel32::{
        get_peb, GetModuleHandleA, GetModuleHandleInternal, GetModuleHandleX, GetProcAddress,
        GetProcAddressInternal, GetProcAddressX, LoadLibraryA,
    };
    use crate::windows::ntdll::PEB;
    use std::mem;
    use std::ptr::addr_of;

    #[test]
    fn get_module_handle() {
        unsafe {
            let kernel32 = GetModuleHandleInternal("KERNEL32.DLL".as_bytes().to_vec());
            assert_ne!(kernel32, 0)
        }
    }

    #[test]
    fn get_proc_address() {
        unsafe {
            let load_library_a_addr = GetProcAddressInternal(
                GetModuleHandleInternal("KERNEL32.DLL".as_bytes().to_vec()),
                "LoadLibraryA".as_bytes(),
            );
            assert_ne!(load_library_a_addr, 0)
        }
    }

    //#[test]
    // you will need to get the ordinal from your particular kernel32.dll build on your system, to
    // enable this test.
    // fn get_proc_address_by_ordinal() {
    //     unsafe {
    //         let load_library_a_address_ordinal = GetProcAddressInternal(
    //             GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec()),
    //             &[0xC9, 0x03, 0x00, 0x00],
    //         );
    //         let load_library_a_address = GetProcAddressInternal(
    //             GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec()),
    //             "LoadLibraryA".as_bytes(),
    //         );
    //         let load_library: LoadLibraryA = mem::transmute(load_library_a_address_ordinal);
    //         let library_handle = LoadLibraryA("USER32.dll".as_ptr());
    //         let library_handle_ordinal = load_library("USER32.dll".as_ptr());
    //         assert_eq!(load_library_a_address_ordinal, load_library_a_address);
    //         assert_eq!(library_handle, library_handle_ordinal)
    //     }
    // }

    #[test]
    fn get_fwd_proc_address() {
        unsafe {
            let pWideCharToMultiByte = GetProcAddressInternal(
                GetModuleHandleInternal("KERNEL32.DLL".as_bytes().to_vec()),
                "AcquireSRWLockExclusive".as_bytes(),
            );
            assert_ne!(pWideCharToMultiByte, 0)
        }
    }

    #[test]
    fn geb_peb() {
        unsafe {
            let peb = get_peb();
            let peb_addr: usize = mem::transmute(peb);
            assert_ne!(peb_addr, 0);
        }
    }

    #[test]
    fn get_return_addr() {
        unsafe {
            let get_return = get_return_address();
            assert_ne!(get_return, 0)
        }
    }

    #[test]
    fn get_resource() {
        unsafe {
            let resource = get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN);
            assert_ne!(resource.len(), 0)
        }
    }

    #[test]
    fn get_xor_encrypted_string_test() {
        unsafe {
            let kernel32 =
                get_xor_encrypted_bytes(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN);
            assert_eq!(&kernel32[..], "kernel32.dll".as_bytes())
        }
    }

    #[test]
    fn get_module_handle_x_test() {
        unsafe {
            let kernel32 = GetModuleHandleX(
                get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
                get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
            );
            let kernel32_normal = GetModuleHandleA("KERNEL32.DLL\0".as_ptr());
            assert_eq!(kernel32, kernel32_normal);
        }
    }

    #[test]
    fn get_proc_address_x_test() {
        unsafe {
            let load_library_a_handle_x = GetProcAddressX(
                GetModuleHandleX(
                    get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_POS, KERNEL32_DLL_LEN),
                    get_resource_bytes(RESOURCE_ID, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN),
                ),
                get_resource_bytes(RESOURCE_ID, LOADLIBRARYA_POS, LOADLIBRARYA_LEN),
                get_resource_bytes(RESOURCE_ID, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN),
            );
            let load_library_a_handle = GetProcAddress(
                GetModuleHandleA("KERNEL32.DLL\0".as_ptr()),
                "LoadLibraryA\0".as_ptr(),
            );
            assert_eq!(load_library_a_handle_x, load_library_a_handle);
        }
    }
}
