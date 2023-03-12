#![allow(non_snake_case)]
#![allow(unused)]

use crate::consts::*;
use crate::util::{get_resource_bytes, get_unmapped_resource_bytes};
use std::ptr::addr_of_mut;
use crate::windows::advapi::*;

fn aes_encrypt_bytes(bytes: &[u8], aes_key: &[u8], aes_iv: &[u8]) -> Vec<u8> {
    unsafe {
        let mut hProv = 0;
        if CryptAcquireContextW(
            addr_of_mut!(hProv),
            0,
            0 as *const u16,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) {
            panic!();
        }

        let mut hHash = 0;
        if CryptCreateHash(
            hProv,
            ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
            0,
            0,
            addr_of_mut!(hHash),
        ) {
            panic!();
        }

        if CryptHashData(hHash, aes_key.as_ptr(), aes_key.len() as u32, 0) {
            panic!();
        }

        let mut hKey = 0;
        if CryptDeriveKey(
            hProv,
            ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
            hHash,
            0,
            addr_of_mut!(hKey),
        ) {
            panic!();
        }

        if CryptSetKeyParam(hKey, KP_IV, aes_iv.as_ptr(), 0) {
            panic!();
        }

        let mut block_len = 0u32;
        let mut len = 4u32;
        if CryptGetKeyParam(
            hKey,
            KP_BLOCKLEN,
            addr_of_mut!(block_len) as *mut u8,
            addr_of_mut!(len),
            0,
        ) {
            panic!();
        }

        block_len = block_len >> 3;
        let mut out = bytes.to_vec();

        let pad = block_len - (out.len() % block_len as usize) as u32;
        out.resize(out.len() + pad as usize, pad as u8);
        let mut len = out.len() as u32;
        if CryptEncrypt(hKey, 0, 0, 0, out.as_mut_ptr(), addr_of_mut!(len), len) {
            panic!();
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);

        out
    }
}

pub fn aes_decrypt_bytes(bytes: &mut Vec<u8>, key: &[u8], iv: &[u8]) {
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

        if !CryptHashData(hHash, key.as_ptr(), key.len() as u32, 0) {
            panic!();
        }

        let mut hKey = 0;
        if !CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, addr_of_mut!(hKey)) {
            panic!();
        }

        if !CryptSetKeyParam(hKey, KP_IV, iv.as_ptr(), 0) {
            panic!();
        }

        let mut len = bytes.len() as u32;
        if !CryptDecrypt(hKey, 0, 0, 0, bytes.as_mut_ptr(), addr_of_mut!(len)) {
            panic!();
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);

        let pad = get_padding(&bytes[..]);
        if pad > 0 {
            bytes.truncate(bytes.len() - pad);
        }
    }
}

pub fn get_aes_encrypted_resource_bytes(offset: usize, len: usize) -> Vec<u8> {
    let mut resource = get_resource_bytes(RESOURCE_ID, offset, len);
    let key = get_resource_bytes(RESOURCE_ID, AES_KEY_POS, AES_KEY_LEN);
    let iv = get_resource_bytes(RESOURCE_ID, AES_IV_POS, AES_IV_LEN);
    aes_decrypt_bytes(&mut resource, key.as_slice(), iv.as_slice());

    resource
}

pub fn get_aes_encrypted_resource_bytes_unmapped(offset: usize, len: usize) -> Vec<u8> {
    let mut resource = get_unmapped_resource_bytes(RESOURCE_ID, offset, len);
    let key = get_unmapped_resource_bytes(RESOURCE_ID, AES_KEY_POS, AES_KEY_LEN);
    let iv = get_unmapped_resource_bytes(RESOURCE_ID, AES_IV_POS, AES_IV_LEN);
    aes_decrypt_bytes(&mut resource, key.as_slice(), iv.as_slice());

    resource
}

pub fn get_xor_encrypted_string(offset: usize, key_offset: usize, len: usize) -> Vec<u8> {
    let key = get_resource_bytes(RESOURCE_ID, key_offset, len);
    let mut buff = get_resource_bytes(RESOURCE_ID, offset, len);

    for i in 0..len {
        buff[i] ^= key[i];
    }

    buff
}

pub fn get_xor_encrypted_string_unmapped(offset: usize, key_offset: usize, len: usize) -> Vec<u8> {
    let key = get_unmapped_resource_bytes(RESOURCE_ID, key_offset, len);
    let mut buffer = get_unmapped_resource_bytes(RESOURCE_ID, offset, len);

    for i in 0..len {
        buffer[i] ^= key[i];
    }

    buffer
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
