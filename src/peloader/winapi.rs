use super::def::*;
use super::error::{Error, Result};
use std::ffi::CString;
use std::mem;
use std::os::raw::c_char;

extern "system" {
    fn LoadLibraryA(lpLibFileName: LPCSTR) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> PVOID;
    fn GetCurrentProcess() -> HANDLE;
}

pub fn load_library(lib: &str) -> Result<HMODULE> {
    if let Ok(lib) = CString::new(lib) {
        let hmod = unsafe { LoadLibraryA(lib.as_ptr()) };
        if hmod == 0 as HMODULE {
            Err(Error::LoadLibararyFail)
        } else {
            Ok(hmod)
        }
    } else {
        Err(Error::InvalidCString)
    }
}

pub fn get_proc_address_by_name(hmod: HMODULE, proc_name: &str) -> Result<PVOID> {
    if let Ok(proc_name) = CString::new(proc_name) {
        let proc = unsafe { GetProcAddress(hmod, proc_name.as_ptr()) };
        if proc == 0 as PVOID {
            Err(Error::GetProcAddressFail)
        } else {
            Ok(proc)
        }
    } else {
        Err(Error::InvalidCString)
    }
}

pub fn get_proc_address_by_ordinal(hmod: HMODULE, proc_ordinal: isize) -> Result<PVOID> {
    let proc = unsafe { GetProcAddress(hmod, proc_ordinal as *const c_char) };
    if proc == 0 as PVOID {
        Err(Error::GetProcAddressFail)
    } else {
        Ok(proc)
    }
}

// raw pointer doesn't implement `Sync` trait
static mut p_nt_alloc_vm: usize = 0_usize;
static mut p_nt_protect_vm: usize = 0_usize;

/*
#[link(name = "ntdll")]
extern "system" {
    fn NtAllocateVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *const PVOID,
        ZeroBits: ULONG_PTR,
        RegionSize: PSIZE_T,
        AllocationType: ULONG,
        Protect: ULONG,
    ) -> NTSTATUS;
}
*/
// bypass possible hooks
pub unsafe fn nt_alloc_vm(
    base_addr: *const PVOID,
    size: PSIZE_T,
    allocation_typ: ULONG,
    protect: ULONG,
) -> Result<()> {
    if p_nt_alloc_vm == 0 as _ {
        p_nt_alloc_vm =
            get_proc_address_by_name(load_library("ntdll.dll")?, "NtAllocateVirtualMemory")? as _;
    };

    let ret = mem::transmute::<
        usize,
        unsafe extern "system" fn(
            HANDLE,
            *const PVOID,
            ULONG_PTR,
            PSIZE_T,
            ULONG,
            ULONG,
        ) -> NTSTATUS,
    >(p_nt_alloc_vm)(
        GetCurrentProcess(),
        base_addr,
        0,
        size,
        allocation_typ,
        protect,
    );

    if 0 == ret {
        Ok(())
    } else {
        Err(Error::NtAllocVmErr(ret))
    }
}

/*
#[link(name = "ntdll")]
extern "system" {
    fn NtProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *const PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG,
    ) -> NTSTATUS;
}
*/
pub unsafe fn nt_protect_vm(
    base_addr: *const PVOID,
    size: PSIZE_T,
    new_protect: ULONG,
) -> Result<()> {
    if p_nt_protect_vm == 0 as _ {
        p_nt_protect_vm =
            get_proc_address_by_name(load_library("ntdll.dll")?, "NtProtectVirtualMemory")? as _;
    };

    let old_protect: ULONG = 0;
    let ret = mem::transmute::<
        usize,
        unsafe extern "system" fn(HANDLE, *const PVOID, PSIZE_T, ULONG, PULONG) -> NTSTATUS,
    >(p_nt_protect_vm)(
        GetCurrentProcess(),
        base_addr,
        size,
        new_protect,
        &old_protect as PULONG,
    );

    if 0 == ret {
        Ok(())
    } else {
        Err(Error::NtProtectVmErr(ret))
    }
}
