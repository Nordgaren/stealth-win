#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::consts::*;
use crate::crypto_util::{get_aes_encrypted_resource_bytes, get_xor_encrypted_bytes};
use crate::util::get_resource_bytes;
use crate::windows::kernel32::{GetModuleHandleX, GetProcAddress, GetProcAddressX};

//user32.dll
pub type FnMessageBoxA = unsafe extern "system" fn(
    hWnd: usize,
    lpText: *const u8,
    lpCaption: *const u8,
    uType: u32,
) -> u32;

pub const MB_OK: u32 = 0x00000000;
pub const MB_OKCANCEL: u32 = 0x00000001;
pub const MB_ABORTRETRYIGNORE: u32 = 0x00000002;
pub const MB_YESNOCANCEL: u32 = 0x00000003;
pub const MB_YESNO: u32 = 0x00000004;
pub const MB_RETRYCANCEL: u32 = 0x00000005;
pub const MB_CANCELTRYCONTINUE: u32 = 0x00000006;
pub const MB_ICONHAND: u32 = 0x00000010;
pub const MB_ICONQUESTION: u32 = 0x00000020;
pub const MB_ICONEXCLAMATION: u32 = 0x00000030;
pub const MB_ICONASTERISK: u32 = 0x00000040;
pub const MB_USERICON: u32 = 0x00000080;
pub const MB_ICONWARNING: u32 = MB_ICONEXCLAMATION;
pub const MB_ICONERROR: u32 = MB_ICONHAND;
pub const MB_ICONINFORMATION: u32 = MB_ICONASTERISK;
pub const MB_ICONSTOP: u32 = MB_ICONHAND;
pub const MB_DEFBUTTON1: u32 = 0x00000000;
pub const MB_DEFBUTTON2: u32 = 0x00000100;
pub const MB_DEFBUTTON3: u32 = 0x00000200;
pub const MB_DEFBUTTON4: u32 = 0x00000300;
pub const MB_APPLMODAL: u32 = 0x00000000;
pub const MB_SYSTEMMODAL: u32 = 0x00001000;
pub const MB_TASKMODAL: u32 = 0x00002000;
pub const MB_HELP: u32 = 0x00004000;
// Help Button
pub const MB_NOFOCUS: u32 = 0x00008000;
pub const MB_SETFOREGROUND: u32 = 0x00010000;
pub const MB_DEFAULT_DESKTOP_ONLY: u32 = 0x00020000;
pub const MB_TOPMOST: u32 = 0x00040000;
pub const MB_RIGHT: u32 = 0x00080000;
pub const MB_RTLREADING: u32 = 0x00100000;

pub unsafe fn MessageBoxA(hWnd: usize, lpText: *const u8, lpCaption: *const u8, uType: u32) -> u32 {
    let messageBoxA: FnMessageBoxA = std::mem::transmute(GetProcAddressX(
        GetModuleHandleX(
            get_resource_bytes(RESOURCE_ID, USER32_DLL_KEY, USER32_DLL_LEN),
            get_resource_bytes(RESOURCE_ID, USER32_DLL_POS, USER32_DLL_LEN),
        ),
        get_resource_bytes(RESOURCE_ID, MESSAGEBOXA_POS, MESSAGEBOXA_LEN),
        get_resource_bytes(RESOURCE_ID, MESSAGEBOXA_KEY, MESSAGEBOXA_LEN),
    ));

    messageBoxA(hWnd, lpText, lpCaption, uType)
}
