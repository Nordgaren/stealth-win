use core::ops::Range;
use crate::consts::RESOURCE_ID;
use crate::util::get_resource_bytes;

pub struct XORString {
    pub resource: &'static [u8],
    pub key: &'static [u8],
}

impl XORString {
    pub fn new() -> Self {
        XORString {
            resource: &[],
            key: &[],
        }
    }
    pub fn from_offsets(resource_offset: usize, key_offset: usize, len: usize) -> Self {
        XORString {
            resource: get_resource_bytes(RESOURCE_ID, resource_offset, len),
            key: get_resource_bytes(RESOURCE_ID, key_offset, len),
        }
    }
    pub fn from_resource(resource: u32, resource_offset: usize, key_offset: usize, len: usize) -> Self {
        XORString {
            resource: get_resource_bytes(resource, resource_offset, len),
            key: get_resource_bytes(resource, key_offset, len),
        }
    }
}

const CASE_BIT: u8 = 0x20;
const CASE_RANGE: Range<u8> = 0x41..0x5A;
impl PartialEq<[u8]> for XORString {
    fn eq(&self, other: &[u8]) -> bool {
        if self.resource.len() != other.len() {
            return false;
        }

        for i in 0..self.resource.len() {
            let mut val = other[i];

            if CASE_RANGE.contains(&val){
                val ^= CASE_BIT;
            }
            val ^= self.key[i];
            if val != self.resource[i] {
                return false;
            }
        }

        true
    }
}


impl PartialEq<[u16]> for XORString {
    fn eq(&self, other: &[u16]) -> bool {
        if self.resource.len() != other.len() {
            return false;
        }

        for i in 0..self.resource.len() {
            let mut val = other[i] as u8;

            if CASE_RANGE.contains(&val) {
                val ^= CASE_BIT;
            }
            val ^= self.key[i];
            if val != self.resource[i] {
                return false;
            }
        }

        true
    }
}
