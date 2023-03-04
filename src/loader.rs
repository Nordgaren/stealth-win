#![allow(non_snake_case)]

use std::arch::asm;
use std::ffi::c_uint;
use std::ptr::addr_of;
use crate::consts::*;
use crate::crypto_util::get_aes_encrypted_resource_bytes;
use crate::winternals::IMAGE_DOS_SIGNATURE;
use crate::util::get_dll_module_handle;
use crate::winapi::get_peb;

#[no_mangle]
pub unsafe extern "C" fn reflective_load() {
    let uiLibraryAddress = get_dll_module_handle();

    let peb = get_peb();

    let str = String::from_utf8(get_aes_encrypted_resource_bytes(PROCESS32FIRST_POS, PROCESS32FIRST_LEN)).unwrap();
    println!("{}", str);
}


