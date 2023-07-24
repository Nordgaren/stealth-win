#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused)]
#![no_std]

extern crate alloc;

pub mod consts;
pub mod crypto_util;
#[cfg(feature = "no_std")]
pub mod no_std;
pub mod ptr;
pub mod resource;
pub mod std;
pub mod svec;
pub mod util;
pub mod windows;
