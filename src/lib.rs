#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(overflowing_literals)]
#![allow(non_upper_case_globals)]

pub mod error;
pub mod peloader;
pub mod peparser;

use error::Result;
use peloader::{DllLoader, ExeLoader};
use peparser::PE;
use std::os::raw::c_void;

#[cfg(feature = "hook")]
pub use peloader::hook;
#[cfg(feature = "hook")]
use peloader::hook::ProcDesc;
#[cfg(feature = "hook")]
use std::collections::HashMap;

pub unsafe fn memexec_exe(bs: &[u8]) -> Result<()> {
    let pe = PE::new(bs)?;
    #[cfg(feature = "hook")]
    let loader = ExeLoader::new(&pe, None)?;
    #[cfg(not(feature = "hook"))]
    let loader = ExeLoader::new(&pe)?;
    Ok(loader.invoke_entry_point())
}

#[cfg(feature = "hook")]
pub unsafe fn memexec_exe_with_hooks(
    bs: &[u8],
    hooks: &HashMap<ProcDesc, *const c_void>,
) -> Result<()> {
    let pe = PE::new(bs)?;
    let loader = ExeLoader::new(&pe, Some(hooks))?;
    Ok(loader.invoke_entry_point())
}

pub unsafe fn memexec_dll(
    bs: &[u8],
    hmod: *const c_void,
    reason_for_call: u32,
    lp_reserved: *const c_void,
) -> Result<bool> {
    let pe = PE::new(bs)?;
    #[cfg(feature = "hook")]
    let loader = DllLoader::new(&pe, None)?;
    #[cfg(not(feature = "hook"))]
    let loader = DllLoader::new(&pe)?;
    Ok(loader.invoke_entry_point(hmod, reason_for_call, lp_reserved))
}

#[cfg(feature = "hook")]
pub unsafe fn memexec_dll_with_hooks(
    bs: &[u8],
    hmod: *const c_void,
    reason_for_call: u32,
    lp_reserved: *const c_void,
    hooks: &HashMap<ProcDesc, *const c_void>,
) -> Result<bool> {
    let pe = PE::new(bs)?;
    let loader = DllLoader::new(&pe, Some(hooks))?;
    Ok(loader.invoke_entry_point(hmod, reason_for_call, lp_reserved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    #[cfg(not(feature = "hook"))]
    fn test_dll() {
        let mut buf = Vec::new();
        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        File::open("./test.x64.dll")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        #[cfg(all(target_arch = "x86", target_os = "windows"))]
        File::open("./test.x86.dll")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        unsafe {
            memexec_dll(&buf, 0 as _, peloader::def::DLL_PROCESS_ATTACH, 0 as _).unwrap();
        }
    }

    #[test]
    #[cfg(not(feature = "hook"))]
    fn test_exe() {
        let mut buf = Vec::new();
        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        File::open("./test.x64.exe")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        #[cfg(all(target_arch = "x86", target_os = "windows"))]
        File::open("./test.x86.exe")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        unsafe {
            memexec_exe(&buf).unwrap();
        }
    }

    #[cfg(feature = "hook")]
    use std::mem;

    #[cfg(feature = "hook")]
    #[cfg(all(target_arch = "x86", target_os = "windows"))]
    extern "cdecl" fn __wgetmainargs(
        _Argc: *mut i32,
        _Argv: *mut *const *const u16,
        _Env: *const c_void,
        _DoWildCard: i32,
        _StartInfo: *const c_void,
    ) -> i32 {
        unsafe {
            *_Argc = 2;
            let a0: Vec<_> = "program_name\0"
                .chars()
                .map(|c| (c as u16).to_le())
                .collect();
            let a1: Vec<_> = "token::whoami\0"
                .chars()
                .map(|c| (c as u16).to_le())
                .collect();
            *_Argv = [a0.as_ptr(), a1.as_ptr()].as_ptr();

            mem::forget(a0);
            mem::forget(a1);
        }

        0
    }

    #[test]
    #[cfg(feature = "hook")]
    #[cfg(all(target_arch = "x86", target_os = "windows"))]
    fn hook_x86() {
        let mut buf = Vec::new();
        File::open("./test.x86.exe")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        let mut hooks = HashMap::new();

        unsafe {
            hooks.insert(
                "msvcrt.dll!__wgetmainargs".into(),
                mem::transmute::<
                    extern "cdecl" fn(
                        *mut i32,
                        *mut *const *const u16,
                        *const c_void,
                        i32,
                        *const c_void,
                    ) -> i32,
                    *const c_void,
                >(__wgetmainargs),
            );
            memexec_exe_with_hooks(&buf, &hooks).unwrap();
        }
    }

    #[cfg(feature = "hook")]
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    extern "win64" fn __wgetmainargs(
        _Argc: *mut i32,
        _Argv: *mut *const *const u16,
        _Env: *const c_void,
        _DoWildCard: i32,
        _StartInfo: *const c_void,
    ) -> i32 {
        unsafe {
            *_Argc = 2;

            let a0: Vec<_> = "program_name\0"
                .chars()
                .map(|c| (c as u16).to_le())
                .collect();
            let a1: Vec<_> = "token::whoami\0"
                .chars()
                .map(|c| (c as u16).to_le())
                .collect();
            *_Argv = [a0.as_ptr(), a1.as_ptr()].as_ptr();

            mem::forget(a0);
            mem::forget(a1);
        }

        0
    }

    #[test]
    #[cfg(feature = "hook")]
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    fn hook_x64() {
        let mut buf = Vec::new();
        File::open("./test.x64.exe")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        let mut hooks = HashMap::new();

        unsafe {
            hooks.insert(
                "msvcrt.dll!__wgetmainargs".into(),
                mem::transmute::<
                    extern "win64" fn(
                        *mut i32,
                        *mut *const *const u16,
                        *const c_void,
                        i32,
                        *const c_void,
                    ) -> i32,
                    *const c_void,
                >(__wgetmainargs),
            );
            memexec_exe_with_hooks(&buf, &hooks).unwrap();
        }
    }
}
