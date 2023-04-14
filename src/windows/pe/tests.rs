use crate::std::fs;
use crate::util::get_system_dir;
use crate::windows::kernel32::{GetModuleHandleA, GetProcAddress};
use crate::windows::pe::PE;
use alloc::format;

#[test]
fn pe_from_memory_address() {
    unsafe {
        let addr = GetModuleHandleA(0 as *const u8);
        let pe = PE::from_address(addr).unwrap();
        #[cfg(any(target_arch = "x86_64"))]
        assert_eq!(pe.nt_headers().file_header().Machine, 0x8664);
        #[cfg(any(target_arch = "x86"))]
        assert_eq!(pe.nt_headers().file_header().Machine, 0x014C);
    }
}

#[test]
fn pe_from_file_32() {
    unsafe {
        let path = get_system_dir();
        let file = fs::read(format!("{path}\\..\\SysWOW64\\notepad.exe").as_bytes()).unwrap();
        let pe = PE::from_slice(file.as_slice()).unwrap();
        assert_eq!(pe.nt_headers().file_header().Machine, 0x014C)
    }
}

#[test]
fn pe_from_file_64() {
    unsafe {
        let path = get_system_dir();
        #[cfg(any(target_arch = "x86_64"))]
        let file = fs::read(format!("{path}\\notepad.exe").as_bytes()).unwrap();
        #[cfg(any(target_arch = "x86"))]
        let file = fs::read(format!("{path}\\..\\Sysnative\\notepad.exe").as_bytes()).unwrap();
        let pe = PE::from_slice(file.as_slice()).unwrap();
        assert_eq!(pe.nt_headers().file_header().Machine, 0x8664)
    }
}

#[test]
fn get_rva_by_ordinal() {
    unsafe {
        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let pe = PE::from_address(kernel_32_addr).unwrap();

        let ordinal = pe.get_function_ordinal("LoadLibraryA".as_bytes()) as u32;

        let load_library_a_address_ordinal_offset =
            pe.get_export_rva(ordinal.to_le_bytes().as_slice()).unwrap();

        let load_library_a_address = GetProcAddress(kernel_32_addr, "LoadLibraryA\0".as_ptr());
        assert_eq!(
            load_library_a_address_ordinal_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}

#[test]
fn get_rva() {
    unsafe {
        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let load_library_a_address_offset = PE::from_address(kernel_32_addr)
            .unwrap()
            .get_export_rva("LoadLibraryA".as_bytes())
            .unwrap();

        let load_library_a_address = GetProcAddress(kernel_32_addr, "LoadLibraryA\0".as_ptr());
        assert_eq!(
            load_library_a_address_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}

#[test]
fn get_rva_by_ordinal_on_disk() {
    unsafe {
        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let pe = PE::from_address(kernel_32_addr).unwrap();

        let ordinal = pe.get_function_ordinal("LoadLibraryA".as_bytes()) as u32;

        let path = get_system_dir();
        let kernel32_file = fs::read(format!("{path}/kernel32.dll").as_bytes()).unwrap();
        let load_library_a_address_ordinal_offset =
            pe.get_export_rva(ordinal.to_le_bytes().as_slice()).unwrap();

        let load_library_a_address = GetProcAddress(kernel_32_addr, "LoadLibraryA\0".as_ptr());
        assert_eq!(
            load_library_a_address_ordinal_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}

#[test]
fn get_rva_on_disk() {
    unsafe {
        let path = get_system_dir();
        let kernel32_file = fs::read(format!("{path}/kernel32.dll").as_bytes()).unwrap();
        let load_library_a_address_offset = PE::from_slice(kernel32_file.as_slice())
            .unwrap()
            .get_export_rva("LoadLibraryA".as_bytes())
            .unwrap();

        let kernel_32_addr = GetModuleHandleA("KERNEL32.DLL\0".as_ptr());
        let load_library_a_address = GetProcAddress(kernel_32_addr, "LoadLibraryA\0".as_ptr());
        assert_eq!(
            load_library_a_address_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}

// This test should not compile.
//     |
// 135 |                 pe = PE::from_slice(file.as_slice()).unwrap();
//     |                                     ^^^^^^^^^^^^^^^ borrowed value does not live long enough
// 136 |             }
//     |             - `file` dropped here while still borrowed
// 137 |             assert_ne!(pe.nt_headers().file_header().Machine, 0x8664)
//     |                        --------------- borrow later used here
// #[test]
// fn pe_from_file_lifetime_fail() {
//     unsafe {
//         let mut buffer = [0; MAX_PATH + 1];
//         GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
//         let pe;
//         let path = String::from_utf8(buffer[..strlen(buffer.as_ptr())].to_vec()).unwrap();
//         {
//             let file = fs::read(format!("{path}\\notepad.exe").as_bytes()).unwrap();
//             pe = PE::from_slice(file.as_slice()).unwrap();
//         }
//         assert_ne!(pe.nt_headers().file_header().Machine, 0x8664)
//     }
// }
