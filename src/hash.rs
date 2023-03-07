#![allow(non_snake_case)]

const HASH_KEY: u32 = 13;

#[inline(always)]
pub fn hash(str_ptr: usize) -> u32 {
    unsafe  {
        let mut pBuffer = str_ptr as *const u8;
        let mut dwModuleHash = 0;
        while *pBuffer != 0 {
            dwModuleHash = u32::rotate_right(dwModuleHash, HASH_KEY);
            dwModuleHash += *pBuffer as u32;
            pBuffer = (pBuffer as usize + 1) as *const u8;
        }

        dwModuleHash
    }
}

#[inline(always)]
pub fn hash_case_insensitive(str_ptr: usize, len: usize) -> u32 {
    unsafe {
        let mut pBuffer = str_ptr as *const u8;
        let mut len = len;
        let mut dwModuleHash = 0u32;
        while len != 0 {
            dwModuleHash = dwModuleHash.rotate_right(HASH_KEY);

            if *pBuffer >= 0x61 {
                dwModuleHash += (*pBuffer - 0x20) as u32;
            } else {
                dwModuleHash += *pBuffer as u32;
            }

            pBuffer = (pBuffer as usize + 1) as *const u8;
            len -= 1;
        }
        dwModuleHash
    }
}