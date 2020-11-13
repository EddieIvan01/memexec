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

pub unsafe fn memexec_exe(bs: &[u8]) -> Result<()> {
    let pe = PE::new(bs)?;
    let loader = ExeLoader::new(&pe)?;
    Ok(loader.invoke_entry_point())
}

pub unsafe fn memexec_dll(
    bs: &[u8],
    hmod: *const c_void,
    reason_for_call: u32,
    lp_reserved: *const c_void,
) -> Result<bool> {
    let pe = PE::new(bs)?;
    let loader = DllLoader::new(&pe)?;
    Ok(loader.invoke_entry_point(hmod, reason_for_call, lp_reserved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_dll() {
        let mut buf = Vec::new();
        File::open("./test.dll")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        unsafe {
            memexec_dll(&buf, 0 as _, peloader::def::DLL_PROCESS_ATTACH, 0 as _).unwrap();
        }
    }

    #[test]
    fn test_exe() {
        let mut buf = Vec::new();
        File::open("./test.exe")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        unsafe {
            memexec_exe(&buf).unwrap();
        }
    }
}
