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
    use crate::hash::hash_case_insensitive;
    use crate::loader::ReflectiveLoader;
    use crate::util::{get_dll_base, get_return};
    use crate::windows::kernel32::{GetModuleHandle, GetProcAddress};

    #[test]
    fn it_works() {
        unsafe {
            let pVirtualAlloc = GetProcAddress(
                GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec()),
                "VirtualAlloc".as_bytes(),
            );
            println!("Virtual Alloc: {:X}", pVirtualAlloc);
            println!("{:X} {:X}", get_return(), get_dll_base());
        }
    }
}
