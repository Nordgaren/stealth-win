#![allow(non_snake_case)]

use std::fmt::format;
use std::fs;
use crate::consts::*;
use crate::util::get_resource_bytes;
use crate::winapi::*;
use crate::winternals::*;
use std::ptr::addr_of_mut;

pub fn get_aes_encrypted_resource_bytes(offset: usize, len: usize) -> Vec<u8> {
    unsafe {
        let mut hProv = 0;
        if !CryptAcquireContextW(
            addr_of_mut!(hProv),
            0,
            0 as *const u16,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) {
            panic!();
        }

        let mut hHash = 0;
        if !CryptCreateHash(hProv, CALG_SHA_256, 0, 0, addr_of_mut!(hHash)) {
            panic!();
        }

        let key = get_resource_bytes(AES_KEY_POS, AES_KEY_LEN);
        if !CryptHashData(hHash, key.as_ptr(), key.len() as u32, 0) {
            panic!();
        }

        let mut hKey = 0;
        if !CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, addr_of_mut!(hKey)) {
            panic!();
        }

        let iv = get_resource_bytes(AES_IV_POS, AES_IV_LEN);
        if !CryptSetKeyParam(hKey, KP_IV, iv.as_ptr(), 0) {
            panic!();
        }

        let mut resource = get_resource_bytes(offset, len);
        let mut len = resource.len() as u32;
        if !CryptDecrypt(hKey, 0, 0, 0, resource.as_mut_ptr(), addr_of_mut!(len)) {
            panic!();
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);

        let pad = get_padding(&resource[..]);
        if pad > 0 {
            resource.truncate(resource.len() - pad);
        }
        resource
    }
}

pub fn get_xor_encrypted_string(offset: usize, key_offset: usize, len: usize) -> Vec<u8> {
    let key = get_resource_bytes(key_offset, len);
    let mut buff = get_resource_bytes(offset, len);

    for i in 0..len {
        buff[i] ^= key[i];
    }

    buff
}

fn get_padding(slice: &[u8]) -> usize {
    if slice.is_empty() {
        return 0;
    }

    let pad = slice[slice.len() - 1];
    for b in slice.iter().rev().take(pad as usize) {
        if b != &pad {
            return 0;
        }
    }

    pad as usize
}
