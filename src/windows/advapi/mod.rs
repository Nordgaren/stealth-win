#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use crate::resource::XORString;
use crate::util::get_resource_bytes;
use crate::windows::kernel32::{GetModuleHandleX, GetProcAddress, GetProcAddressX};

pub type FnCryptAcquireContextW = unsafe extern "system" fn(
    phProv: *mut usize,
    szContainer: usize,
    szProvider: *const u16,
    dwProvType: u32,
    dwFlags: u32,
) -> bool;
pub type FnCryptCreateHash = unsafe extern "system" fn(
    phProv: usize,
    ALG_ID: u32,
    hKey: usize,
    dwFlags: u32,
    phHash: *mut usize,
) -> bool;
pub type FnCryptDecrypt = unsafe extern "system" fn(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> bool;
pub type FnCryptDeriveKey = unsafe extern "system" fn(
    hHash: usize,
    Algid: u32,
    hBaseData: usize,
    dwFlags: u32,
    phKey: *mut usize,
) -> bool;
pub type FnCryptDestroyKey = unsafe extern "system" fn(hKey: usize) -> bool;
pub type FnCryptDestroyHash = unsafe extern "system" fn(hHash: usize) -> bool;
pub type FnCryptEncrypt = unsafe extern "system" fn(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    dwBufLen: u32,
) -> bool;
pub type FnCryptGetKeyParam = unsafe extern "system" fn(
    hKey: usize,
    dwParam: u32,
    pbData: *mut u8,
    pbDataLen: *mut u32,
    dwFlags: u32,
) -> bool;
pub type FnCryptHashData = unsafe extern "system" fn(
    hHash: usize,
    pbData: *const u8,
    dwDataLen: u32,
    dwFlags: u32,
) -> bool;
pub type FnCryptSetKeyParam =
    unsafe extern "system" fn(hKey: usize, dwParam: u32, pbData: *const u8, dwFlags: u32) -> bool;
pub type FnCryptReleaseContext = unsafe extern "system" fn(hProv: usize, dwFlags: u32) -> bool;

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
    let cryptAcquireContextW: FnCryptAcquireContextW = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX( &XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)
        ),
        &XORString::from_offsets(CRYPTACQUIRECONTEXTW_POS, CRYPTACQUIRECONTEXTW_KEY, CRYPTACQUIRECONTEXTW_LEN),
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
    let cryptCreateHash: FnCryptCreateHash = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX( &XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTCREATEHASH_POS, CRYPTCREATEHASH_KEY, CRYPTCREATEHASH_LEN)
    ));

    cryptCreateHash(phProv, ALG_ID, hKey, dwFlags, phHash)
}
pub unsafe fn CryptDecrypt(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> bool {
    let cryptDecrypt: FnCryptDecrypt = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTDECRYPT_POS, CRYPTDECRYPT_KEY, CRYPTDECRYPT_LEN)
    ));

    cryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
}
pub unsafe fn CryptDeriveKey(
    hHash: usize,
    Algid: u32,
    hBaseData: usize,
    dwFlags: u32,
    phKey: *mut usize,
) -> bool {
    let cryptDeriveKey: FnCryptDeriveKey = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTDERIVEKEY_POS, CRYPTDERIVEKEY_KEY, CRYPTDERIVEKEY_LEN)
    ));

    cryptDeriveKey(hHash, Algid, hBaseData, dwFlags, phKey)
}
pub unsafe fn CryptDestroyKey(hKey: usize) -> bool {
    let cryptDestroyKey: FnCryptDestroyKey = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTDESTROYKEY_POS, CRYPTDESTROYKEY_KEY, CRYPTDESTROYKEY_LEN)
    ));

    cryptDestroyKey(hKey)
}
pub unsafe fn CryptDestroyHash(hHash: usize) -> bool {
    let cryptDestroyHash: FnCryptDestroyHash = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTDESTROYHASH_POS, CRYPTDESTROYHASH_KEY, CRYPTDESTROYHASH_LEN)
    ));

    cryptDestroyHash(hHash)
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
    let cryptEncrypt: FnCryptEncrypt = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTDECRYPT_POS, CRYPTDECRYPT_KEY, CRYPTDECRYPT_LEN)
    ));

    cryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
}
pub unsafe fn CryptGetKeyParam(
    hKey: usize,
    dwParam: u32,
    pbData: *mut u8,
    pbDataLen: *mut u32,
    dwFlags: u32,
) -> bool {
    let cryptGetKeyParam: FnCryptGetKeyParam = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTGETKEYPARAM_POS, CRYPTGETKEYPARAM_KEY, CRYPTGETKEYPARAM_LEN)
    ));

    cryptGetKeyParam(hKey, dwParam, pbData, pbDataLen, dwFlags)
}
pub unsafe fn CryptHashData(hHash: usize, pbData: *const u8, dwDataLen: u32, dwFlags: u32) -> bool {
    let cryptHashData: FnCryptHashData = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTHASHDATA_POS, CRYPTHASHDATA_KEY, CRYPTHASHDATA_LEN)
    ));

    cryptHashData(hHash, pbData, dwDataLen, dwFlags)
}
pub unsafe fn CryptReleaseContext(hProv: usize, dwFlags: u32) -> bool {
    let cryptReleaseContext: FnCryptReleaseContext = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTRELEASECONTEXT_POS, CRYPTRELEASECONTEXT_KEY, CRYPTRELEASECONTEXT_LEN),
    ));

    cryptReleaseContext(hProv, dwFlags)
}
pub unsafe fn CryptSetKeyParam(hKey: usize, dwParam: u32, pbData: *const u8, dwFlags: u32) -> bool {
    let cryptSetKeyParam: FnCryptSetKeyParam = core::mem::transmute(GetProcAddressX(
        GetModuleHandleX(&XORString::from_offsets(ADVAPI32_DLL_POS, ADVAPI32_DLL_KEY, ADVAPI32_DLL_LEN)),
        &XORString::from_offsets(CRYPTSETKEYPARAM_POS, CRYPTSETKEYPARAM_KEY, CRYPTSETKEYPARAM_LEN)
    ));

    cryptSetKeyParam(hKey, dwParam, pbData, dwFlags)
}
