use lazy_static::lazy_static;
use std::ops::RangeInclusive;

pub const RESOURCE_ID: u32 = 100;
pub const RESOURCE_NAME: &'static str = "resource.bin";

// Optional parameters
pub const TARGET_PROCESS: &'static str = "";
pub const SHELLCODE_PATH: &'static str = "";
pub const DLL_PATH: &'static str = r"";

// Range for random byte generation. Will generate random amount of junk data between resource entries.
pub const RANGE_START: usize = 0;
pub const RANGE_END: usize = 0x100;
pub const PAD_RANGE: RangeInclusive<usize> = RANGE_START..=RANGE_END;

// Any strings placed in here will be embedded in the PE resource, with a constant named after the string
// I.E. TEST_STRING
lazy_static! {
    pub static ref USER_STRINGS: Vec<&'static str> = vec![];
}

// Will try to automate the configs stuff, later. At the moment, doesn't work with 'cargo build'
// Even with switching to windows-rs for build encryption methods, it still doesn't play nice with
// the cfg defines (but only in the build script. Works fine in `src/`)
// #[cfg(all(windows, target_pointer_width = "64"))]
// const TARGET_PROCESS: &'static str = "notepad.exe";
// #[cfg(all(windows, target_pointer_width = "32"))]x32d
// const TARGET_PROCESS: &'static str = "x32dbg.exe";

// #[cfg(all(windows, target_pointer_width = "64"))]
// const SHELLCODE_PATH: &'static str = "build_src/shellcode64.bin";
// #[cfg(all(windows, target_pointer_width = "32"))]
// const SHELLCODE_PATH: &'static str = "build_src/shellcode32.bin";
