use std::ptr::addr_of_mut;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::{ALG_CLASS_DATA_ENCRYPT, ALG_CLASS_HASH, ALG_SID_AES_256, ALG_SID_SHA_256, ALG_TYPE_ANY, ALG_TYPE_BLOCK, CRYPT_VERIFYCONTEXT, CryptAcquireContextW, CryptCreateHash, CryptDecrypt, CryptDeriveKey, CryptDestroyHash, CryptDestroyKey, CryptEncrypt, CryptGenKey, CryptGetKeyParam, CryptHashData, CryptReleaseContext, CryptSetKeyParam, KP_BLOCKLEN, KP_IV, KP_KEYLEN, PROV_RSA_AES};

#[allow(non_snake_case)]
fn get_key_len() -> usize {
    unsafe {
        let mut hProv = 0;
        if CryptAcquireContextW(
            addr_of_mut!(hProv),
            0 as PCWSTR,
            0 as *const u16,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            panic!();
        }

        let mut hHash = 0;
        if CryptCreateHash(
            hProv,
            ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
            0,
            0,
            addr_of_mut!(hHash),
        ) == 0
        {
            panic!();
        }

        if CryptHashData(hHash, 0 as *const u8, 0, 0) == 0 {
            panic!();
        }

        let mut hKey = 0;
        if CryptGenKey(
            hProv,
            ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
            0,
            addr_of_mut!(hKey),
        ) == 0
        {
            panic!();
        }

        let mut key_len = 0u32;
        let mut len = 4u32;
        if CryptGetKeyParam(
            hKey,
            KP_KEYLEN,
            addr_of_mut!(key_len) as *mut u8,
            addr_of_mut!(len),
            0,
        ) == 0
        {
            panic!();
        }

        (key_len / 8) as usize
    }
}

#[allow(non_snake_case)]
fn get_iv_len() -> usize {
    unsafe {
        let mut hProv = 0;
        if CryptAcquireContextW(
            addr_of_mut!(hProv),
            0 as PCWSTR,
            0 as *const u16,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            panic!();
        }

        let mut hHash = 0;
        if CryptCreateHash(
            hProv,
            ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
            0,
            0,
            addr_of_mut!(hHash),
        ) == 0
        {
            panic!();
        }

        if CryptHashData(hHash, 0 as *const u8, 0, 0) == 0 {
            panic!();
        }

        let mut hKey = 0;
        if CryptGenKey(
            hProv,
            ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
            0,
            addr_of_mut!(hKey),
        ) == 0
        {
            panic!();
        }

        let mut iv: Vec<u8> = vec![0; 420];
        let mut len = iv.len() as u32;
        if CryptGetKeyParam(hKey, KP_IV, iv.as_mut_ptr(), addr_of_mut!(len), 0) == 0 {
            panic!("GLE: {:X}", GetLastError());
        }

        len as usize
    }
}

#[allow(non_snake_case)]
fn aes_encrypt_bytes(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    unsafe {
        let mut hProv = 0;
        if CryptAcquireContextW(
            addr_of_mut!(hProv),
            0 as PCWSTR,
            0 as *const u16,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            panic!();
        }

        let mut hHash = 0;
        if CryptCreateHash(
            hProv,
            ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
            0,
            0,
            addr_of_mut!(hHash),
        ) == 0
        {
            panic!();
        }

        if CryptHashData(hHash, key.as_ptr(), key.len() as u32, 0) == 0 {
            panic!();
        }

        let mut hKey = 0;
        if CryptDeriveKey(
            hProv,
            ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
            hHash,
            0,
            addr_of_mut!(hKey),
        ) == 0
        {
            panic!();
        }

        if CryptSetKeyParam(hKey, KP_IV, iv.as_ptr(), 0) == 0 {
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
        ) == 0
        {
            panic!();
        }

        block_len = block_len >> 3;
        let mut out = bytes.to_vec();

        let pad = block_len - (out.len() % block_len as usize) as u32;
        out.resize(out.len() + pad as usize, pad as u8);
        let mut len = out.len() as u32;
        if CryptEncrypt(hKey, 0, 0, 0, out.as_mut_ptr(), addr_of_mut!(len), len) == 0 {
            panic!();
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);

        out
    }
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

#[allow(non_snake_case)]
pub fn aes_decrypt_bytes(bytes: Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    unsafe {
        let mut hProv = 0;
        if CryptAcquireContextW(
            addr_of_mut!(hProv),
            0 as PCWSTR,
            0 as *const u16,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            panic!();
        }

        let mut hHash = 0;
        if !CryptCreateHash(
            hProv,
            ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
            0,
            0,
            addr_of_mut!(hHash),
        ) == 0
        {
            panic!();
        }

        if !CryptHashData(hHash, key.as_ptr(), key.len() as u32, 0) == 0 {
            panic!();
        }

        let mut hKey = 0;
        if !CryptDeriveKey(
            hProv,
            ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
            hHash,
            0,
            addr_of_mut!(hKey),
        ) == 0
        {
            panic!();
        }

        if !CryptSetKeyParam(hKey, KP_IV, iv.as_ptr(), 0) == 0 {
            panic!();
        }

        let mut len = bytes.len() as u32;
        let mut payload = bytes.to_vec();
        if !CryptDecrypt(hKey, 0, 0, 0, payload.as_mut_ptr(), addr_of_mut!(len)) == 0 {
            panic!();
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);

        let pad = get_padding(&payload[..]);
        if pad > 0 {
            payload.truncate(bytes.len() - pad);
        }

        payload
    }
}

fn xor_encrypt_bytes(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    if bytes.len() != key.len() {
        panic!("Key and source len differ.")
    }

    let mut out = bytes.to_vec();

    for i in 0..bytes.len() {
        out[i] ^= key[i];
    }

    out
}

fn generate_random_bytes(i: usize) -> Vec<u8> {
    (0..i).map(|_| rand::thread_rng().gen()).collect()
}

fn generate_random_bytes_in_range(i: usize, r: Range<u8>) -> Vec<u8> {
    (0..i)
        .map(|_| rand::thread_rng().gen_range(r.start..r.end))
        .collect()
}
