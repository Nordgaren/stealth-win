use lazy_static::lazy_static;

// These strings are required for the crate to run!
lazy_static! {
pub static ref STRINGS: Vec<&'static str> = vec![
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
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualFree",
    "VirtualFreeEx",
    "CreateRemoteThread",
    "WaitForSingleObject",
    "WriteProcessMemory",
    "OpenProcess",
    "CreateProcessA",
    "OpenFile",
    "ResumeThread",
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
    "GetCurrentProcess",
    "WriteFile",
    "CreateFileA",
    "AcquireSRWLockExclusive",
];
}
