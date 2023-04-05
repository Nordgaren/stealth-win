use crate::util::check_mapped;
use crate::windows::ntdll::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
    IMAGE_SECTION_HEADER,
};
use std::mem::size_of;
use std::ptr::addr_of;
use std::{mem, slice};

struct PE {
    base_address: usize,
    dos_header: &'static IMAGE_DOS_HEADER,
    nt_headers: &'static IMAGE_NT_HEADERS,
    is_64bit: bool,
    is_mapped: bool,
}

impl PE {
    pub fn from_addr(base_address: usize) -> Self {
        unsafe {
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute(base_address + dos_header.e_lfanew as usize);

            if dos_header.e_magic != IMAGE_DOS_SIGNATURE
                && nt_headers.Signature != IMAGE_NT_SIGNATURE
            {
                panic!()
            }

            PE {
                base_address,
                dos_header,
                nt_headers,
                is_64bit: nt_headers.FileHeader.Machine == 0x8664,
                is_mapped: check_mapped(base_address),
            }
        }
    }
    #[inline(always)]
    pub fn from_ptr(ptr: *const u8) -> Self {
        Self::from_addr(ptr as usize)
    }
    #[inline(always)]
    pub fn base_address(&self) -> usize {
        self.base_address
    }
    #[inline(always)]
    pub fn dos_header(&self) -> &'static IMAGE_DOS_HEADER {
        self.dos_header
    }
    #[inline(always)]
    pub fn nt_headers(&self) -> &'static IMAGE_NT_HEADERS {
        self.nt_headers
    }
    #[inline(always)]
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }
    #[inline(always)]
    pub fn is_mapped(&self) -> bool {
        self.is_mapped
    }
}
