const API_SET_SCHEMA_VERSION_V2: u32 = 0x00000002;
const API_SET_SCHEMA_VERSION_V3: u32 = 0x00000003;
// No offline support.
const API_SET_SCHEMA_VERSION_V4: u32 = 0x00000004;
const API_SET_SCHEMA_VERSION_V6: u32 = 0x00000006;

//Api set V6
//Windows 10
#[repr(C)]
struct _API_SET_NAMESPACE_V6 {
     pub Version:u32,
     pub Size:u32,
     pub Flags:u32,
     pub Count:u32,
     pub EntryOffset:u32,
     pub HashOffset:u32,
     pub HashFactor:u32,
}

#[repr(C)]
struct _API_SET_NAMESPACE_ENTRY_V6 {
    pub Flags: u32,
    pub NameOffset: u32,
    pub NameLength: u32,
    pub HashedLength: u32,
    pub ValueOffset: u32,
    pub ValueCount: u32,
}

#[repr(C)]
struct _API_SET_HASH_ENTRY_V6 {
    pub Hash:u32,
    pub Index:u32,
}

#[repr(C)]
struct _API_SET_VALUE_ENTRY_V6 {
    pub Flags:u32,
    pub NameOffset:u32,
    pub NameLength:u32,
    pub ValueOffset:u32,
    pub ValueLength:u32,
}