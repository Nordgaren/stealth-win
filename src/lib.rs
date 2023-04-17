#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused)]
#![no_std]

extern crate alloc;

use crate::std::alloc::NoImportAllocator;

pub mod consts;
pub mod crypto_util;
pub mod std;
pub mod svec;
pub mod util;
pub mod windows;
#[cfg(feature = "no_std")]
pub mod no_std;
