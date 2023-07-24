use alloc::string::ToString;
use crate::consts::{NTDLL_DLL_KEY, NTDLL_DLL_LEN, NTDLL_DLL_POS};
use crate::resource::strings::XORString;

#[test]
fn get_string() {
    unsafe {
        let str = XORString::from_offsets(NTDLL_DLL_POS, NTDLL_DLL_KEY, NTDLL_DLL_LEN);
        assert_eq!(str.to_string(), "ntdll.dll");
    }
}