#![allow(non_snake_case)]

use crate::consts::HASH_KEY;

#[inline(always)]
pub fn hash(str_ptr: usize) -> u32 {
    unsafe {
        let mut pBuffer = str_ptr as *const u8;
        let mut dwModuleHash = 0u32;

        while *pBuffer != 0 {
            dwModuleHash = dwModuleHash.rotate_right(HASH_KEY);
            dwModuleHash += *pBuffer as u32;
            pBuffer = (pBuffer as usize + 1) as *const u8;
        }
        dwModuleHash
    }
}

#[inline(always)]
pub fn hash_case_insensitive(str_ptr: usize, len: usize) -> u32 {
    unsafe {
        let pBuffer = str_ptr as *const u8;
        let sString = std::slice::from_raw_parts(pBuffer, len);
        let mut dwModuleHash = 0u32;

        for i in 0..sString.len() {
            dwModuleHash = dwModuleHash.rotate_right(HASH_KEY);

            if sString[i] >= 0x61 {
                dwModuleHash += (sString[i] - 0x20) as u32;
            } else {
                dwModuleHash += sString[i] as u32;
            }
        }
        dwModuleHash
    }
}
