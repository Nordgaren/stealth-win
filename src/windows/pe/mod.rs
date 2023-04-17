use crate::consts::RT_RCDATA;
use crate::util::{case_insensitive_compare_strs_as_bytes, compare_xor_str_and_str_bytes, strlen};
use crate::windows::ntdll::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY,
    IMAGE_FILE_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
    IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, MAX_SECTION_HEADER_LEN,
    RESOURCE_DATA_ENTRY, RESOURCE_DIRECTORY_TABLE,
};
use crate::windows::pe::definitions::{
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::addr_of;
use core::{cmp, mem, slice};

mod definitions;
#[cfg(test)]
mod tests;

pub struct PE<'a, T> {
    base_address: usize,
    dos_header: &'a IMAGE_DOS_HEADER,
    nt_headers: usize,
    image_optional_header: usize,
    is_64bit: bool,
    is_mapped: bool,
    phantom_data: PhantomData<T>,
}

pub struct Base;

pub struct NtHeaders;

pub struct ImageOptionalHeader;

impl<'a, T> PE<'a, T> {
    #[inline(always)]
    pub fn base_address(&self) -> usize {
        self.base_address
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

impl<'a> PE<'a, Base> {
    #[inline(always)]
    pub fn from_slice(ptr: &'a [u8]) -> Result<Self, ()> {
        unsafe { Self::from_address(ptr.as_ptr() as usize) }
    }
    #[inline(always)]
    pub fn from_slice_unchecked(ptr: &'a [u8]) -> Self {
        unsafe { Self::from_address_unchecked(ptr.as_ptr() as usize) }
    }
    #[inline(always)]
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Self, ()> {
        Self::from_address(ptr as usize)
    }
    #[inline(always)]
    pub unsafe fn from_ptr_unchecked(ptr: *const u8) -> Self {
        Self::from_address_unchecked(ptr as usize)
    }
    pub unsafe fn from_address(base_address: usize) -> Result<Self, ()> {
        unsafe {
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address as usize);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute(base_address + dos_header.e_lfanew as usize);

            if dos_header.e_magic != IMAGE_DOS_SIGNATURE
                && nt_headers.Signature != IMAGE_NT_SIGNATURE
            {
                return Err(());
            }

            let is_64bit = nt_headers.FileHeader.Machine == 0x8664;
            let mut pe = PE {
                base_address,
                dos_header,
                nt_headers: addr_of!(*nt_headers) as usize,
                image_optional_header: addr_of!(nt_headers.OptionalHeader) as usize,
                is_64bit,
                is_mapped: false,
                phantom_data: PhantomData,
            };
            pe.is_mapped = pe.check_mapped().unwrap_or(true);

            Ok(pe)
        }
    }
    pub unsafe fn from_address_unchecked(base_address: usize) -> Self {
        unsafe {
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_address as usize);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute(base_address + dos_header.e_lfanew as usize);

            let is_64bit = nt_headers.FileHeader.Machine == 0x8664;
            let mut pe = PE {
                base_address,
                dos_header,
                nt_headers: addr_of!(*nt_headers) as usize,
                image_optional_header: addr_of!(nt_headers.OptionalHeader) as usize,
                is_64bit,
                is_mapped: false,
                phantom_data: PhantomData,
            };
            pe.is_mapped = pe.check_mapped().unwrap_or(true);

            pe
        }
    }
    fn check_mapped(&self) -> Option<bool> {
        unsafe {
            let data_dir = self.nt_headers().optional_header().data_directory();
            let import_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            if import_data_dir.Size == 0 {
                return self.check_mapped_export_dir(data_dir);
            }

            let import_table_addr = self.base_address()
                + self.rva_to_foa(import_data_dir.VirtualAddress)? as usize;
            let length = import_data_dir.Size as usize / size_of::<IMAGE_IMPORT_DESCRIPTOR>();

            let import_descriptor_table = slice::from_raw_parts(
                import_table_addr as *const IMAGE_IMPORT_DESCRIPTOR,
                length - 1,
            );

            for import_descriptor in import_descriptor_table {
                let string_foa = self.rva_to_foa(import_descriptor.Name)?;
                let string_addr = self.base_address() + string_foa as usize;
                let string = slice::from_raw_parts(
                    string_addr as *const u8,
                    strlen(string_addr as *const u8),
                );
                if !string.is_ascii() {
                    return Some(true);
                }
            }

            Some(false)
        }
    }
    unsafe fn check_mapped_export_dir(&self, data_dir: &[IMAGE_DATA_DIRECTORY]) -> Option<bool> {
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if export_data_dir.Size == 0 {
            return self.check_mapped_by_section();
        }
        let export_table_addr:&IMAGE_EXPORT_DIRECTORY = mem::transmute(self.base_address()
            + self.rva_to_foa(export_data_dir.VirtualAddress)? as usize);

        let function_name_table = slice::from_raw_parts(
            (self.base_address() + self.rva_to_foa(export_table_addr.AddressOfNames)? as usize) as *const u32,
            export_table_addr.NumberOfNames as usize,
        );

        for rva in function_name_table {
            let string_foa = self.rva_to_foa(*rva)?;
            let string_addr = self.base_address() + string_foa as usize;
            let string = slice::from_raw_parts(
                string_addr as *const u8,
                strlen(string_addr as *const u8),
            );
            if !string.is_ascii() {
                return Some(true);
            }
        }

        Some(false)
    }
    unsafe fn check_mapped_by_section(&self) -> Option<bool> {
        let section_headers = self.section_headers();
        let first_section_header = &section_headers[0];
        let first_section_address = self.base_address() + first_section_header.PointerToRawData as usize;
        let ptr_to_zero = first_section_address as *const u64;

        Some(*ptr_to_zero == 0)
    }
    #[inline(always)]
    pub fn address(&self) -> usize {
        self.base_address
    }
    #[inline(always)]
    pub fn dos_header(&self) -> &'a IMAGE_DOS_HEADER {
        self.dos_header
    }
    #[inline(always)]
    pub fn nt_headers(&self) -> PE<'a, NtHeaders> {
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
    pub fn section_headers(&self) -> &'a [IMAGE_SECTION_HEADER] {
        let section_headers_base = self.nt_headers().address() + self.nt_headers().size_of();
        unsafe {
            slice::from_raw_parts(
                section_headers_base as *mut IMAGE_SECTION_HEADER,
                cmp::min(
                    self.nt_headers()
                        .optional_header()
                        .number_of_rva_and_sizes(),
                    MAX_SECTION_HEADER_LEN,
                ) as usize,
            )
        }
    }
    #[inline(always)]
    pub fn section_headers_mut(&self) -> &'a [IMAGE_SECTION_HEADER] {
        let section_headers_base = self.nt_headers().address() + self.nt_headers().size_of();
        unsafe {
            slice::from_raw_parts_mut(
                section_headers_base as *mut IMAGE_SECTION_HEADER,
                cmp::min(
                    self.nt_headers()
                        .optional_header()
                        .number_of_rva_and_sizes(),
                    MAX_SECTION_HEADER_LEN,
                ) as usize,
            )
        }
    }
    pub fn rva_to_foa(&self, rva: u32) -> Option<u32> {
        unsafe {
            let section_headers = self.section_headers();

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
    pub fn get_pe_resource(&self, resource_id: u32) -> Option<&'a [u8]> {
        let optional_header = self.nt_headers().optional_header().data_directory();
        let resource_data_dir = &optional_header[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];

        let mut resource_directory_table_offset = resource_data_dir.VirtualAddress;
        if !self.is_mapped {
            resource_directory_table_offset = self.rva_to_foa(resource_directory_table_offset)?
        }
        unsafe {
            let resource_directory_table: &RESOURCE_DIRECTORY_TABLE =
                mem::transmute(self.base_address + resource_directory_table_offset as usize);

            let resource_data_entry =
                get_resource_data_entry(resource_directory_table, resource_id)?;

            let mut data_offset = resource_data_entry.DataRVA;
            if !self.is_mapped {
                data_offset = self.rva_to_foa(data_offset)?
            }

            let data = self.base_address + data_offset as usize;
            Some(slice::from_raw_parts(
                data as *const u8,
                resource_data_entry.DataSize as usize,
            ))
        }
    }
    pub unsafe fn get_export_rva_xor_string(&self, xor_name: &[u8], key: &[u8]) -> Option<u32> {
        let data_dir = self.nt_headers().optional_header().data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !self.is_mapped() {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            mem::transmute(self.base_address() + export_directory_offset as usize);

        let mut export_address_table_rva = export_directory.AddressOfFunctions;
        if !self.is_mapped() {
            export_address_table_rva = self.rva_to_foa(export_address_table_rva)?;
        }
        let export_address_table_array = slice::from_raw_parts(
            (self.base_address() + export_address_table_rva as usize) as *const u32,
            export_directory.NumberOfFunctions as usize,
        );

        // We are only loading by name for this function, so remove the ordinal code.
        // checking for ordinal can cause issues, here.
        let mut rva = 0;
        let mut name_table_offset = export_directory.AddressOfNames;
        if !self.is_mapped {
            name_table_offset = self.rva_to_foa(name_table_offset)?;
        }

        let function_name_table_array = slice::from_raw_parts(
            (self.base_address() + name_table_offset as usize) as *const u32,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let mut string_offset = function_name_table_array[i];
            if !self.is_mapped {
                string_offset = self.rva_to_foa(string_offset)?;
            }

            let string_address = self.base_address() + string_offset as usize;
            let name = slice::from_raw_parts(
                string_address as *const u8,
                strlen(string_address as *const u8),
            );

            if compare_xor_str_and_str_bytes(xor_name, name, key) {
                let mut hints_table_offset = export_directory.AddressOfNameOrdinals;
                if !self.is_mapped {
                    hints_table_offset = self.rva_to_foa(hints_table_offset)?;
                }

                let hints_table_array = slice::from_raw_parts(
                    (self.base_address() + hints_table_offset as usize) as *const u16,
                    export_directory.NumberOfNames as usize,
                );

                return Some(export_address_table_array[hints_table_array[i] as usize]);
            }
        }

        None
    }
    pub unsafe fn get_export_rva(&self, export_name: &[u8]) -> Option<u32> {
        let data_dir = self.nt_headers().optional_header().data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !self.is_mapped() {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            mem::transmute(self.base_address() + export_directory_offset as usize);

        let mut export_address_table_rva = export_directory.AddressOfFunctions;
        if !self.is_mapped() {
            export_address_table_rva = self.rva_to_foa(export_address_table_rva)?;
        }
        let export_address_table_array = slice::from_raw_parts(
            (self.base_address() + export_address_table_rva as usize) as *const u32,
            export_directory.NumberOfFunctions as usize,
        );

        let mut rva = 0;
        let ordinal_test = *(export_name.as_ptr() as *const u32);
        if ordinal_test >> 16 == 0 {
            let ordinal = (*(export_name.as_ptr() as *const u16)) as u32;
            let base = export_directory.Base;

            if (ordinal < base) || (ordinal >= base + export_directory.NumberOfFunctions) {
                return None;
            }

            return Some(export_address_table_array[(ordinal - base) as usize]);
        } else {
            let mut name_table_offset = export_directory.AddressOfNames;
            if !self.is_mapped {
                name_table_offset = self.rva_to_foa(name_table_offset)?;
            }

            let function_name_table_array = slice::from_raw_parts(
                (self.base_address() + name_table_offset as usize) as *const u32,
                export_directory.NumberOfNames as usize,
            );

            for i in 0..export_directory.NumberOfNames as usize {
                let mut string_offset = function_name_table_array[i];
                if !self.is_mapped {
                    string_offset = self.rva_to_foa(string_offset)?;
                }

                let string_address = self.base_address() + string_offset as usize;
                let name = slice::from_raw_parts(
                    string_address as *const u8,
                    strlen(string_address as *const u8),
                );

                if case_insensitive_compare_strs_as_bytes(export_name, name) {
                    let mut hints_table_offset = export_directory.AddressOfNameOrdinals;
                    if !self.is_mapped {
                        hints_table_offset = self.rva_to_foa(hints_table_offset)?;
                    }

                    let hints_table_array = slice::from_raw_parts(
                        (self.base_address() + hints_table_offset as usize) as *const u16,
                        export_directory.NumberOfNames as usize,
                    );

                    return Some(export_address_table_array[hints_table_array[i] as usize]);
                }
            }
        }
        None
    }
    fn get_function_ordinal(&self, function_name: &[u8]) -> u16 {
        unsafe {
            let base_addr = self.base_address();
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_addr);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute(base_addr + dos_header.e_lfanew as usize);
            let export_dir =
                &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

            let image_export_directory: &IMAGE_EXPORT_DIRECTORY =
                mem::transmute(base_addr + export_dir.VirtualAddress as usize);

            let name_dir = slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNames as usize) as *const u32,
                image_export_directory.NumberOfNames as usize,
            );
            let ordinal_dir = slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNameOrdinals as usize) as *const u16,
                image_export_directory.NumberOfNames as usize,
            );

            for i in 0..name_dir.len() {
                let name = slice::from_raw_parts(
                    (base_addr + name_dir[i] as usize) as *const u8,
                    strlen((base_addr + name_dir[i] as usize) as *const u8),
                );

                if case_insensitive_compare_strs_as_bytes(name, function_name) {
                    return ordinal_dir[i] + image_export_directory.Base as u16;
                }
            }
        }

        0
    }
    fn get_function_ordinal_xor(&self, function_name: &[u8], key: &[u8]) -> u16 {
        unsafe {
            let base_addr = self.base_address();
            let dos_header: &IMAGE_DOS_HEADER = mem::transmute(base_addr);
            let nt_headers: &IMAGE_NT_HEADERS =
                mem::transmute(base_addr + dos_header.e_lfanew as usize);
            let export_dir =
                &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

            let image_export_directory: &IMAGE_EXPORT_DIRECTORY =
                mem::transmute(base_addr + export_dir.VirtualAddress as usize);

            let name_dir = slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNames as usize) as *const u32,
                image_export_directory.NumberOfNames as usize,
            );
            let ordinal_dir = slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNameOrdinals as usize) as *const u16,
                image_export_directory.NumberOfNames as usize,
            );

            for i in 0..name_dir.len() {
                let name = slice::from_raw_parts(
                    (base_addr + name_dir[i] as usize) as *const u8,
                    strlen((base_addr + name_dir[i] as usize) as *const u8),
                );

                if compare_xor_str_and_str_bytes(name, function_name, key) {
                    return ordinal_dir[i] + image_export_directory.Base as u16;
                }
            }
        }

        0
    }
}

impl<'a> PE<'a, NtHeaders> {
    #[inline(always)]
    pub fn address(&self) -> usize {
        self.nt_headers
    }
    #[inline(always)]
    fn nt_headers32(&self) -> &'a IMAGE_NT_HEADERS32 {
        unsafe { mem::transmute(self.nt_headers) }
    }
    #[inline(always)]
    fn nt_headers64(&self) -> &'a IMAGE_NT_HEADERS64 {
        unsafe { mem::transmute(self.nt_headers) }
    }
    #[inline(always)]
    pub fn signature(&self) -> u32 {
        self.nt_headers32().Signature
    }
    #[inline(always)]
    pub fn file_header(&self) -> &'a IMAGE_FILE_HEADER {
        &self.nt_headers32().FileHeader
    }
    #[inline(always)]
    pub fn optional_header(&self) -> PE<'a, ImageOptionalHeader> {
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
    pub fn size_of(&self) -> usize {
        if self.is_64bit {
            size_of::<IMAGE_NT_HEADERS64>()
        } else {
            size_of::<IMAGE_NT_HEADERS32>()
        }
    }
}

impl<'a> PE<'a, ImageOptionalHeader> {
    #[inline(always)]
    pub fn address(&self) -> usize {
        self.image_optional_header
    }
    #[inline(always)]
    fn optional_header32(&self) -> &'a IMAGE_OPTIONAL_HEADER32 {
        unsafe { mem::transmute(self.image_optional_header) }
    }
    #[inline(always)]
    fn optional_header64(&self) -> &'a IMAGE_OPTIONAL_HEADER64 {
        unsafe { mem::transmute(self.image_optional_header) }
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
    pub fn data_directory(&self) -> &'a [IMAGE_DATA_DIRECTORY] {
        if self.is_64bit {
            &self.optional_header64().DataDirectory
        } else {
            &self.optional_header32().DataDirectory
        }
    }
    #[inline(always)]
    pub fn size_of(&self) -> usize {
        if self.is_64bit {
            size_of::<IMAGE_OPTIONAL_HEADER64>() as usize
        } else {
            size_of::<IMAGE_OPTIONAL_HEADER32>() as usize
        }
    }
}

fn get_resource_data_entry<'a>(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    resource_id: u32,
) -> Option<&'a RESOURCE_DATA_ENTRY> {
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

        Some(mem::transmute(resource_directory_table_addr as usize + offset as usize))
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
    let resource_directory_entries = slice::from_raw_parts(
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
    let resource_directory_entries = slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfNameEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        let name_ptr =
            addr_of!(*resource_directory_table) as usize + resource_directory_entry.Id as usize;
        let resource_name =
            slice::from_raw_parts(name_ptr as *const u8, strlen(name_ptr as *const u8));
        if resource_name == name {
            return Some(resource_directory_entry.OffsetToData);
        }
    }

    None
}
