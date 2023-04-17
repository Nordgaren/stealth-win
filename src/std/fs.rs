use crate::svec::{SVec, ToSVec};
use crate::util::copy_buffer;
use crate::windows::kernel32::{
    CloseHandle, CreateFileA, CreateFileW, GetFileSize, GetLastError, ReadFile,
    WaitForSingleObject, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
    GENERIC_READ, INFINITE, INVALID_HANDLE_VALUE, MAX_PATH, OPEN_EXISTING, OVERLAPPED,
    SECURITY_ATTRIBUTES,
};
use crate::windows::ntdll::{
    NtReadFile, IO_STATUS_BLOCK, LARGE_INTEGER, STATUS_END_OF_FILE, STATUS_PENDING,
};
use alloc::borrow::Cow::Borrowed;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::addr_of_mut;
use core::{cmp, ptr, slice};

pub fn read(path: &[u8]) -> Result<Vec<u8>, u32> {
    unsafe {
        #[cfg(feature = "no_std")]
            let mut file_path = [0; MAX_PATH + 1];
        #[cfg(feature = "no_std")]
        copy_buffer(path.as_ptr(), file_path.as_mut_ptr(), path.len());

        #[cfg(not(feature = "no_std"))]
            let mut file_path = path.to_svec();
        #[cfg(not(feature = "no_std"))]
        file_path.push(0);

        let file_handle = CreateFileA(
            file_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            0 as *const SECURITY_ATTRIBUTES,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            0,
        );
        if file_handle == INVALID_HANDLE_VALUE {
            return Err(GetLastError());
        }

        read_file_from_handle(file_handle)
    }
}

pub fn read_w(path: &[u16]) -> Result<Vec<u8>, u32> {
    unsafe {
        #[cfg(feature = "no_std")]
            let mut file_path = [0; MAX_PATH + 1];
        #[cfg(feature = "no_std")]
        copy_buffer(path.as_ptr(), file_path.as_mut_ptr(), path.len());

        #[cfg(not(feature = "no_std"))]
            let mut file_path = path.to_svec();
        #[cfg(not(feature = "no_std"))]
        file_path.push(0);

        let file_handle = CreateFileW(
            file_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            0 as *const SECURITY_ATTRIBUTES,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if file_handle == INVALID_HANDLE_VALUE {
            return Err(GetLastError());
        }

        read_file_from_handle(file_handle)
    }
}

pub fn sread(path: &[u8]) -> Result<SVec<u8>, u32> {
    unsafe {
        #[cfg(feature = "no_std")]
        let mut file_path = [0; MAX_PATH + 1];
        #[cfg(feature = "no_std")]
        copy_buffer(path.as_ptr(), file_path.as_mut_ptr(), path.len());

        #[cfg(not(feature = "no_std"))]
        let mut file_path = path.to_svec();
        #[cfg(not(feature = "no_std"))]
        file_path.push(0);

        let file_handle = CreateFileA(
            file_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            0 as *const SECURITY_ATTRIBUTES,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if file_handle == INVALID_HANDLE_VALUE {
            return Err(GetLastError());
        }

        sread_file_from_handle(file_handle)
    }
}

pub fn sread_w(path: &[u16]) -> Result<SVec<u8>, u32> {
    unsafe {
        #[cfg(feature = "no_std")]
            let mut file_path = [0; MAX_PATH + 1];
        #[cfg(feature = "no_std")]
        copy_buffer(path.as_ptr(), file_path.as_mut_ptr(), path.len());

        #[cfg(not(feature = "no_std"))]
            let mut file_path = path.to_svec();
        #[cfg(not(feature = "no_std"))]
        file_path.push(0);

        let file_handle = CreateFileW(
            file_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            0 as *const SECURITY_ATTRIBUTES,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if file_handle == INVALID_HANDLE_VALUE {
            return Err(GetLastError());
        }

        sread_file_from_handle(file_handle)
    }
}

unsafe fn read_file_from_handle(file_handle: usize) -> Result<Vec<u8>, u32> {
    let mut file_size_high = 0;
    let file_size_low = GetFileSize(file_handle, addr_of_mut!(file_size_high)) as u64;
    let file_size = ((file_size_high as u64) << 32) | file_size_low;

    let mut file = Vec::with_capacity(file_size as usize);
    file.set_len(file_size as usize);

    let result = read_file_to_end(file_handle, &mut file[..]);
    if result != 0 {
        return Err(result as u32);
    }

    Ok(file)
}

unsafe fn sread_file_from_handle(file_handle: usize) -> Result<SVec<u8>, u32> {
    let mut file_size_high = 0;
    let file_size_low = GetFileSize(file_handle, addr_of_mut!(file_size_high)) as u64;
    let file_size = ((file_size_high as u64) << 32) | file_size_low;

    let mut file = SVec::with_capacity(file_size as usize);
    file.set_len(file_size as usize);

    let result = read_file_to_end(file_handle, &mut file[..]);
    if result != 0 {
        return Err(result as u32);
    }

    Ok(file)
}

unsafe fn read_file_to_end(file_handle: usize, buffer: &mut [u8]) -> i32 {
    let file_size = buffer.len();
    let mut len = cmp::min(buffer.len(), u32::MAX as usize) as u32;
    let mut read = 0;

    loop {
        let result = read_to_buffer(file_handle, buffer.as_mut_ptr().add(read), len, read);

        read += len as usize;
        len = cmp::min(buffer.len() - read, u32::MAX as usize) as u32;

        if len == 0 {
            break;
        }
    }

    0
}

unsafe fn read_to_buffer(file_handle: usize, buffer: *mut u8, len: u32, offset: usize) -> i32 {
    let mut io_status = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    let large_integer = LARGE_INTEGER(offset as u64);
    let status = NtReadFile(
        file_handle,
        0,
        0,
        0,
        &mut io_status,
        buffer,
        len,
        &large_integer,
        0 as *const u32,
    );

    let status = if status == STATUS_PENDING {
        WaitForSingleObject(file_handle, INFINITE);
        io_status.Status
    } else {
        status
    };
    match status {
        // If the operation has not completed then abort the process.
        // Doing otherwise means that the buffer and stack may be written to
        // after this function returns.
        STATUS_PENDING => panic!(),

        // Return `Ok(0)` when there's nothing more to read.
        STATUS_END_OF_FILE => 0,

        // Success!
        status if status >= 0 => io_status.Information as i32,

        status => panic!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::std::alloc::NoImportAllocator;
    use crate::std::fs;
    use crate::util::get_system_dir;
    use alloc::format;
    use core::ffi::CStr;

    #[test]
    fn read_file() {
        let path = get_system_dir();
        let file = fs::read(format!("{path}\\..\\SysWOW64\\notepad.exe").as_bytes()).unwrap();

        assert_eq!(file[..2], [0x4D, 0x5A]);
    }

    #[test]
    fn sread_file() {
        let path = get_system_dir();
        let file = fs::sread(format!("{path}\\..\\SysWOW64\\notepad.exe").as_bytes()).unwrap();

        assert_eq!(file[..2], [0x4D, 0x5A]);
    }

    #[test]
    // Read a 10GB file. Test takes a long ass time, so keep it as ignore, for now.
    // tests multiple pass NtReadFile
    // Cannot be done in 32 bit.
    #[cfg(target_arch = "x86_64")]
    #[ignore]
    fn read_large_file() {
        let file = fs::read(format!("C:\\Users\\malware\\Downloads\\10GB.bin").as_bytes()).unwrap();

        assert_eq!(file[..2], [0x71, 0x4B]);
        assert_eq!(
            file[file.len() - 0x10..],
            [
                0xE2, 0x50, 0x3E, 0x3A, 0x24, 0x02, 0x13, 0x0B, 0xF6, 0xB3, 0x85, 0xB9, 0xAD, 0x2D,
                0x4C, 0x51
            ]
        );
    }
}
