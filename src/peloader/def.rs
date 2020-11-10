use std::os::raw::{c_char, c_void};

pub(crate) type PVOID = *const c_void;
pub(crate) type HANDLE = PVOID;
pub(crate) type HMODULE = PVOID;
pub(crate) type LPCSTR = *const c_char;
pub(crate) type ULONG = u32;
pub(crate) type PULONG = *const ULONG;
pub(crate) type ULONG_PTR = usize;
pub(crate) type PSIZE_T = *const ULONG_PTR;
pub(crate) type NTSTATUS = i32;
pub(crate) type BOOL = bool;
pub(crate) type DWORD = u32;

pub(crate) const MEM_COMMIT: DWORD = 0x00001000;
pub(crate) const MEM_RESERVE: DWORD = 0x00002000;

pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const DLL_THREAD_ATTACH: DWORD = 2;
pub const DLL_THREAD_DETACH: DWORD = 3;
pub const DLL_PROCESS_DETACH: DWORD = 0;

/*
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
*/
pub type DllMain = extern "system" fn(HMODULE, DWORD, PVOID) -> BOOL;
