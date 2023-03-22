#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused)]

mod consts;
mod crypto_util;
mod hash;
mod loader;
mod util;
mod windows;

use crate::consts::*;
use crate::crypto_util::{get_aes_encrypted_resource_bytes, get_xor_encrypted_string};
use crate::windows::kernel32::LoadLibraryA;
use crate::windows::user32::*;

static mut hAppInstance: usize = 0;

#[no_mangle] // call it "DllMain" in the compiled DLL
#[allow(unused)]
pub extern "stdcall" fn DllMain(hinstDLL: usize, dwReason: u32, lpReserved: *mut usize) -> i32 {
    match dwReason {
        // match for what reason it's calling us
        DLL_PROCESS_ATTACH => {
            unsafe {
                hAppInstance = hinstDLL;
                load_libraries();
                MessageBoxA(
                    0,
                    "Hello from DllMain!\0".as_ptr(),
                    "Reflective Dll Injection\0".as_ptr(),
                    MB_OK,
                );
            }
            return true as i32;
        }
        DLL_QUERY_HMODULE => {
            unsafe {
                if lpReserved as usize != 0 {
                    *lpReserved = hAppInstance;
                }
            }
            return true as i32;
        }
        _ => true as i32,
    }
}

fn load_libraries() {
    unsafe {
        let mut advapi =
            get_xor_encrypted_string(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN);
        advapi.push(0);
        LoadLibraryA(advapi.as_ptr());

        let mut user32 = get_aes_encrypted_resource_bytes(USER32_DLL_POS, USER32_DLL_LEN);
        user32.push(0);
        LoadLibraryA(user32.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::{
        KERNEL32_DLL_KEY, KERNEL32_DLL_LEN, KERNEL32_DLL_POS, RESOURCE_ID, USER32_DLL_LEN,
        USER32_DLL_POS,
    };
    use crate::crypto_util::{get_aes_encrypted_resource_bytes, get_xor_encrypted_string};
    use crate::hash::hash_case_insensitive;
    use crate::loader::ReflectiveLoader;
    use crate::util::{get_dll_base, get_resource_bytes, get_return};
    use crate::windows::kernel32::{get_peb, GetModuleHandle, GetProcAddress};
    use crate::windows::ntdll::PEB;
    use std::mem;
    use std::ptr::addr_of;

    #[test]
    fn get_module_handle() {
        unsafe {
            let kernel32 = GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec());
            assert_ne!(kernel32, 0)
        }
    }

    #[test]
    fn get_proc_address() {
        unsafe {
            let loadLibarayA = GetProcAddress(
                GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec()),
                "LoadLibraryA".as_bytes(),
            );
            assert_ne!(loadLibarayA, 0)
        }
    }

    #[test]
    fn get_fwd_proc_address() {
        unsafe {
            let pWideCharToMultiByte = GetProcAddress(
                GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec()),
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
            let get_return = get_return();
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
                get_xor_encrypted_string(KERNEL32_DLL_POS, KERNEL32_DLL_KEY, KERNEL32_DLL_LEN);
            assert_eq!(&kernel32[..], "KERNEL32.DLL".as_bytes())
        }
    }

    #[test]
    fn get_aes_encrypted_resource_bytes_test() {
        unsafe {
            let user32 = get_aes_encrypted_resource_bytes(USER32_DLL_POS, USER32_DLL_LEN);
            assert_eq!(&user32[..], "USER32.dll".as_bytes())
        }
    }

    #[test]
    fn playground() {
        unsafe {
            let mut sFwdDll = match std::fs::read("Bingus") {
                Ok(s) => s,
                Err(_) => return,
            };

            println!("Failed to return early");
            // let floppa = API_SET_NAMESPACE_V6{
            //     Version: 0,
            //     Size: 0,
            //     Flags: 0,
            //     Count: 0,
            //     EntryOffset: 69,
            //     HashOffset: 0,
            //     HashFactor: 0,
            // };
            // let k32 = "KERNEL32.DLL".encode_utf16().collect::<Vec<u16>>();
            // ApiSetpSearchForApiSetV6(addr_of!(floppa), k32.as_ptr(), k32.len() as u16);
        }
    }
}
