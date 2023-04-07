use crate::consts::RT_RCDATA;
use crate::util::strlen;
use crate::windows::ntdll::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_FILE_HEADER, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, IMAGE_OPTIONAL_HEADER,
    IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, RESOURCE_DATA_ENTRY,
    RESOURCE_DIRECTORY_TABLE,
};
use crate::windows::pe::definitions::{
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
};
use std::marker::PhantomData;
use std::mem::size_of;
use std::ptr::addr_of;
use std::{mem, slice};

mod definitions;

pub struct PE<T> {
    base_address: u64,
    dos_header: &'static IMAGE_DOS_HEADER,
    nt_headers: u64,
    image_optional_header: u64,
    is_64bit: bool,
    is_mapped: bool,
    phantom_data: PhantomData<T>,
}
pub struct Base;
pub struct NtHeaders;
pub struct ImageOptionalHeader;

impl<T> PE<T> {
    #[inline(always)]
    pub fn base_address(&self) -> u64 {
        self.base_address
    }
}

impl PE<Base> {
    #[inline(always)]
    pub fn from_ptr(ptr: *const u8) -> Result<Self, ()> {
        Self::from_addr(ptr as u64)
    }
    #[inline(always)]
    pub fn from_ptr_unchecked(ptr: *const u8) -> Self {
        Self::from_addr_unchecked(ptr as u64)
    }
    pub fn from_addr(base_address: u64) -> Result<Self, ()> {
        unsafe {
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address as usize);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute((base_address + dos_header.e_lfanew as u64) as usize);

            if dos_header.e_magic != IMAGE_DOS_SIGNATURE
                && nt_headers.Signature != IMAGE_NT_SIGNATURE
            {
                return Err(());
            }

            let is_64bit = nt_headers.FileHeader.Machine == 0x8664;
            let mut pe = PE {
                base_address,
                dos_header,
                nt_headers: addr_of!(*nt_headers) as u64,
                image_optional_header: addr_of!(nt_headers.OptionalHeader) as u64,
                is_64bit,
                is_mapped: false,
                phantom_data: PhantomData,
            };
            pe.set_is_mapped();

            Ok(pe)
        }
    }
    pub fn from_addr_unchecked(base_address: u64) -> Self {
        unsafe {
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address as usize);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute((base_address + dos_header.e_lfanew as u64) as usize);

            let is_64bit = nt_headers.FileHeader.Machine == 0x8664;
            let mut pe = PE {
                base_address,
                dos_header,
                nt_headers: addr_of!(*nt_headers) as u64,
                image_optional_header: addr_of!(nt_headers.OptionalHeader) as u64,
                is_64bit,
                is_mapped: false,
                phantom_data: PhantomData,
            };
            pe.set_is_mapped();

            pe
        }
    }
    fn set_is_mapped(&mut self) {
        unsafe {
            let first_section: &IMAGE_SECTION_HEADER = mem::transmute(
                (self.base_address
                    + self.dos_header().e_lfanew as u64
                    + self.nt_headers().size_of()) as usize,
            );
            let section_on_disk = self.base_address + first_section.PointerToRawData as u64;
            let ptr_to_zero = section_on_disk as *const u64;

            self.is_mapped = *ptr_to_zero == 0
        }
    }
    pub fn rva_to_foa(&self, rva: u32) -> Option<u32> {
        unsafe {
            let section_headers_pointer = self.nt_headers().address() + self.nt_headers().size_of();
            let section_headers = std::slice::from_raw_parts(
                section_headers_pointer as *const IMAGE_SECTION_HEADER,
                self.nt_headers().file_header().NumberOfSections as usize,
            );

            if rva < section_headers[0].PointerToRawData {
                return Some(rva);
            }

            for section_header in section_headers {
                if (rva >= section_header.VirtualAddress)
                    && (rva <= section_header.VirtualAddress + section_header.SizeOfRawData)
                {
                    return Some(
                        section_header.PointerToRawData + (rva - section_header.VirtualAddress),
                    );
                }
            }
        }

        None
    }
    pub fn get_pe_resource(&self, resource_id: u32) -> Option<&'static [u8]> {
        let optional_header = self.nt_headers().optional_header().data_directory();
        let resource_data_dir = &optional_header[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];

        let mut resource_directory_table_offset = resource_data_dir.VirtualAddress;
        if !self.is_mapped {
            resource_directory_table_offset = self.rva_to_foa(resource_directory_table_offset)?
        }
        unsafe {
            let resource_directory_table: &RESOURCE_DIRECTORY_TABLE = mem::transmute(
                (self.base_address + resource_directory_table_offset as u64) as usize,
            );

            let resource_data_entry =
                get_resource_data_entry(resource_directory_table, resource_id)?;

            let mut data_offset = resource_data_entry.DataRVA;
            if !self.is_mapped {
                data_offset = self.rva_to_foa(data_offset)?
            }

            let data = self.base_address + data_offset as u64;
            Some(std::slice::from_raw_parts(
                data as *const u8,
                resource_data_entry.DataSize as usize,
            ))
        }
    }
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.base_address
    }
    #[inline(always)]
    pub fn dos_header(&self) -> &'static IMAGE_DOS_HEADER {
        self.dos_header
    }
    #[inline(always)]
    pub fn nt_headers(&self) -> PE<NtHeaders> {
        PE {
            base_address: self.base_address,
            dos_header: self.dos_header,
            nt_headers: self.nt_headers,
            image_optional_header: self.image_optional_header,
            is_64bit: self.is_64bit,
            is_mapped: self.is_mapped,
            phantom_data: PhantomData,
        }
    }
    #[inline(always)]
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }
    #[inline(always)]
    pub fn is_mapped(&self) -> bool {
        self.is_mapped
    }
}

impl PE<NtHeaders> {
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.nt_headers
    }
    #[inline(always)]
    fn nt_headers32(&self) -> &'static IMAGE_NT_HEADERS32 {
        unsafe { mem::transmute(self.nt_headers as usize) }
    }
    #[inline(always)]
    fn nt_headers64(&self) -> &'static IMAGE_NT_HEADERS64 {
        unsafe { mem::transmute(self.nt_headers as usize) }
    }
    #[inline(always)]
    pub fn signature(&self) -> u32 {
        self.nt_headers32().Signature
    }
    #[inline(always)]
    pub fn file_header(&self) -> &'static IMAGE_FILE_HEADER {
        &self.nt_headers32().FileHeader
    }
    #[inline(always)]
    pub fn optional_header(&self) -> PE<ImageOptionalHeader> {
        PE {
            base_address: self.base_address,
            dos_header: self.dos_header,
            nt_headers: self.nt_headers,
            image_optional_header: self.image_optional_header,
            is_64bit: self.is_64bit,
            is_mapped: self.is_mapped,
            phantom_data: PhantomData,
        }
    }
    #[inline(always)]
    pub fn size_of(&self) -> u64 {
        if self.is_64bit {
            size_of::<IMAGE_NT_HEADERS64>() as u64
        } else {
            size_of::<IMAGE_NT_HEADERS32>() as u64
        }
    }
}

impl PE<ImageOptionalHeader> {
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.image_optional_header
    }
    #[inline(always)]
    fn optional_header32(&self) -> &'static IMAGE_OPTIONAL_HEADER32 {
        unsafe { mem::transmute(self.image_optional_header as usize) }
    }
    #[inline(always)]
    fn optional_header64(&self) -> &'static IMAGE_OPTIONAL_HEADER64 {
        unsafe { mem::transmute(self.image_optional_header as usize) }
    }
    #[inline(always)]
    pub fn magic(&self) -> u16 {
        self.optional_header32().Magic
    }
    #[inline(always)]
    pub fn major_linker_version(&self) -> u8 {
        self.optional_header32().MajorLinkerVersion
    }
    #[inline(always)]
    pub fn minor_linker_version(&self) -> u8 {
        self.optional_header32().MinorLinkerVersion
    }
    #[inline(always)]
    pub fn size_of_code(&self) -> u32 {
        self.optional_header32().SizeOfCode
    }
    #[inline(always)]
    pub fn size_of_initialized_data(&self) -> u32 {
        self.optional_header32().SizeOfInitializedData
    }
    #[inline(always)]
    pub fn size_of_uninitialized_data(&self) -> u32 {
        self.optional_header32().SizeOfUninitializedData
    }
    #[inline(always)]
    pub fn address_of_entry_point(&self) -> u32 {
        self.optional_header32().AddressOfEntryPoint
    }
    #[inline(always)]
    pub fn base_of_code(&self) -> u32 {
        self.optional_header32().BaseOfCode
    }
    #[inline(always)]
    pub fn image_base(&self) -> u64 {
        if self.is_64bit {
            self.optional_header64().ImageBase
        } else {
            self.optional_header32().ImageBase as u64
        }
    }
    #[inline(always)]
    pub fn section_alignment(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().SectionAlignment
        } else {
            self.optional_header32().SectionAlignment
        }
    }
    #[inline(always)]
    pub fn file_alignment(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().FileAlignment
        } else {
            self.optional_header32().FileAlignment
        }
    }
    #[inline(always)]
    pub fn major_operating_system_version(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().MajorOperatingSystemVersion
        } else {
            self.optional_header32().MajorOperatingSystemVersion
        }
    }
    #[inline(always)]
    pub fn minor_operating_system_version(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().MinorOperatingSystemVersion
        } else {
            self.optional_header32().MinorOperatingSystemVersion
        }
    }
    #[inline(always)]
    pub fn major_image_version(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().MajorImageVersion
        } else {
            self.optional_header32().MajorImageVersion
        }
    }
    #[inline(always)]
    pub fn minor_image_version(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().MinorImageVersion
        } else {
            self.optional_header32().MinorImageVersion
        }
    }
    #[inline(always)]
    pub fn major_subsystem_version(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().MajorSubsystemVersion
        } else {
            self.optional_header32().MajorSubsystemVersion
        }
    }
    #[inline(always)]
    pub fn minor_subsystem_version(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().MinorSubsystemVersion
        } else {
            self.optional_header32().MinorSubsystemVersion
        }
    }
    #[inline(always)]
    pub fn win32_version_value(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().Win32VersionValue
        } else {
            self.optional_header32().Win32VersionValue
        }
    }
    #[inline(always)]
    pub fn size_of_image(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().SizeOfImage
        } else {
            self.optional_header32().SizeOfImage
        }
    }
    #[inline(always)]
    pub fn size_of_headers(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().SizeOfHeaders
        } else {
            self.optional_header32().SizeOfHeaders
        }
    }
    #[inline(always)]
    pub fn check_sum(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().CheckSum
        } else {
            self.optional_header32().CheckSum
        }
    }
    #[inline(always)]
    pub fn subsystem(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().Subsystem
        } else {
            self.optional_header32().Subsystem
        }
    }
    #[inline(always)]
    pub fn dll_characteristics(&self) -> u16 {
        if self.is_64bit {
            self.optional_header64().DllCharacteristics
        } else {
            self.optional_header32().DllCharacteristics
        }
    }
    #[inline(always)]
    pub fn size_of_stack_reserve(&self) -> u64 {
        if self.is_64bit {
            self.optional_header64().SizeOfStackReserve
        } else {
            self.optional_header32().SizeOfStackReserve as u64
        }
    }
    #[inline(always)]
    pub fn size_of_stack_commit(&self) -> u64 {
        if self.is_64bit {
            self.optional_header64().SizeOfStackCommit
        } else {
            self.optional_header32().SizeOfStackCommit as u64
        }
    }
    #[inline(always)]
    pub fn size_of_heap_reserve(&self) -> u64 {
        if self.is_64bit {
            self.optional_header64().SizeOfHeapReserve
        } else {
            self.optional_header32().SizeOfHeapReserve as u64
        }
    }
    #[inline(always)]
    pub fn size_of_heap_commit(&self) -> u64 {
        if self.is_64bit {
            self.optional_header64().SizeOfHeapCommit
        } else {
            self.optional_header32().SizeOfHeapCommit as u64
        }
    }
    #[inline(always)]
    pub fn loader_flags(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().LoaderFlags
        } else {
            self.optional_header32().LoaderFlags
        }
    }
    #[inline(always)]
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        if self.is_64bit {
            self.optional_header64().NumberOfRvaAndSizes
        } else {
            self.optional_header32().NumberOfRvaAndSizes
        }
    }
    #[inline(always)]
    pub fn data_directory(&self) -> &'static [IMAGE_DATA_DIRECTORY; 16] {
        if self.is_64bit {
            &self.optional_header64().DataDirectory
        } else {
            &self.optional_header32().DataDirectory
        }
    }
    #[inline(always)]
    pub fn size_of(&self) -> u64 {
        if self.is_64bit {
            size_of::<IMAGE_OPTIONAL_HEADER64>() as u64
        } else {
            size_of::<IMAGE_OPTIONAL_HEADER32>() as u64
        }
    }
}

fn get_resource_data_entry(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    resource_id: u32,
) -> Option<&'static RESOURCE_DATA_ENTRY> {
    unsafe {
        let resource_directory_table_addr = addr_of!(*resource_directory_table) as usize;

        //level 1: Resource type directory
        let mut offset = get_entry_offset_by_id(resource_directory_table, RT_RCDATA as u32)?;
        offset &= 0x7FFFFFFF;

        //level 2: Resource Name/ID subdirectory
        let resource_directory_table_name_id: &RESOURCE_DIRECTORY_TABLE =
            mem::transmute(resource_directory_table_addr + offset as usize);
        let mut offset = get_entry_offset_by_id(resource_directory_table_name_id, resource_id)?;
        offset &= 0x7FFFFFFF;

        //level 3: language subdirectory - just use the first entry.
        let resource_directory_table_lang: &RESOURCE_DIRECTORY_TABLE =
            mem::transmute(resource_directory_table_addr as usize + offset as usize);
        let resource_directory_table_lang_entries = addr_of!(*resource_directory_table_lang)
            as usize
            + size_of::<RESOURCE_DIRECTORY_TABLE>();
        let resource_directory_table_lang_entry: &IMAGE_RESOURCE_DIRECTORY_ENTRY =
            mem::transmute(resource_directory_table_lang_entries);
        let offset = resource_directory_table_lang_entry.OffsetToData;

        mem::transmute(resource_directory_table_addr as usize + offset as usize)
    }
}

unsafe fn get_entry_offset_by_id(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    id: u32,
) -> Option<u32> {
    // We have to skip the Name entries, here, to iterate over the entires by Id.
    let resource_entries_address = addr_of!(*resource_directory_table) as usize
        + size_of::<RESOURCE_DIRECTORY_TABLE>()
        + (size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>()
            * resource_directory_table.NumberOfNameEntries as usize);
    let resource_directory_entries = std::slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfIDEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        if resource_directory_entry.Id == id {
            return Some(resource_directory_entry.OffsetToData);
        }
    }

    None
}

unsafe fn get_entry_offset_by_name(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    name: &[u8],
) -> Option<u32> {
    let resource_entries_address =
        addr_of!(*resource_directory_table) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let resource_directory_entries = std::slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfNameEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        let name_ptr =
            addr_of!(*resource_directory_table) as usize + resource_directory_entry.Id as usize;
        let resource_name =
            std::slice::from_raw_parts(name_ptr as *const u8, strlen(name_ptr as *const u8));
        if resource_name == name {
            return Some(resource_directory_entry.OffsetToData);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::util::strlen;
    use crate::windows::kernel32::{
        GetModuleHandleA, GetSystemDirectoryA, MAX_PATH,
    };
    use crate::windows::pe::PE;
    use std::fs;

    #[test]
    fn pe_from_memory_address() {
        unsafe {
            let addr = GetModuleHandleA(0 as *const u8);
            let pe = PE::from_addr(addr as u64).unwrap();
            assert_eq!(pe.nt_headers().file_header().Machine, 0x8664)
        }
    }

    #[test]
    fn pe_from_file_32() {
        unsafe {
            let mut buffer = [0; MAX_PATH + 1];
            GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
            let path = String::from_utf8(buffer[..strlen(buffer.as_ptr())].to_vec()).unwrap();
            let file = fs::read(format!("{path}\\..\\SysWOW64\\notepad.exe")).unwrap();
            let pe = PE::from_ptr(file.as_ptr()).unwrap();
            assert_eq!(pe.nt_headers().file_header().Machine, 0x014C)
        }
    }

    #[test]
    fn pe_from_file_64() {
        unsafe {
            let mut buffer = [0; MAX_PATH + 1];
            GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
            let path = String::from_utf8(buffer[..strlen(buffer.as_ptr())].to_vec()).unwrap();
            let file = fs::read(format!("{path}\\notepad.exe")).unwrap();
            let pe = PE::from_ptr(file.as_ptr()).unwrap();
            assert_eq!(pe.nt_headers().file_header().Machine, 0x8664)
        }
    }
}
