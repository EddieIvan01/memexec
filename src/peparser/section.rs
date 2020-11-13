use super::def::*;
use super::error::Result;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(Debug)]
pub struct SectionArea<'a> {
    pub section_table: &'a [IMAGE_SECTION_HEADER],
    pub section_data: &'a [u8],
}

impl<'a> SectionArea<'a> {
    pub fn new(bs: &'a [u8], n_sections: u16) -> Result<SectionArea<'a>> {
        let section_table = unsafe {
            &*ptr::slice_from_raw_parts(
                mem::transmute::<*const u8, *const IMAGE_SECTION_HEADER>(bs.as_ptr()),
                n_sections as usize,
            )
        };

        Ok(SectionArea {
            section_table: section_table,
            section_data: &bs[(n_sections as usize) * mem::size_of::<IMAGE_SECTION_HEADER>()..],
        })
    }
}

/*
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
*/
impl IMAGE_SECTION_HEADER {
    #[inline]
    pub fn can_read(&self) -> bool {
        self.Characteristics & IMAGE_SCN_MEM_READ != 0
    }

    #[inline]
    pub fn can_write(&self) -> bool {
        self.Characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    #[inline]
    pub fn can_exec(&self) -> bool {
        self.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub fn get_protection(&self) -> DWORD {
        match self.can_exec() {
            true => match self.can_read() {
                true => match self.can_write() {
                    true => PAGE_EXECUTE_READWRITE,
                    false => PAGE_EXECUTE_READ,
                },
                false => PAGE_EXECUTE,
            },
            false => match self.can_read() {
                true => match self.can_write() {
                    true => PAGE_READWRITE,
                    false => PAGE_READONLY,
                },
                false => PAGE_NOACCESS,
            },
        }
    }
}
