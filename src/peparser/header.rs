use super::def::*;
use super::error::{Error, Result};
use std::mem;
use std::os::raw::c_void;

// Zero copy
#[derive(Debug)]
pub enum ImageNtHeaders<'a> {
    x86(&'a IMAGE_NT_HEADERS32),
    x64(&'a IMAGE_NT_HEADERS64),
}

impl<'a> ImageNtHeaders<'a> {
    pub fn get_file_header(&self) -> &IMAGE_FILE_HEADER {
        match *self {
            ImageNtHeaders::x86(h) => &h.FileHeader,
            ImageNtHeaders::x64(h) => &h.FileHeader,
        }
    }

    pub fn get_address_of_entry_point(&self) -> isize {
        match *self {
            ImageNtHeaders::x86(h) => h.OptionalHeader.AddressOfEntryPoint as isize,
            ImageNtHeaders::x64(h) => h.OptionalHeader.AddressOfEntryPoint as isize,
        }
    }

    pub fn get_image_base(&self) -> *const c_void {
        match *self {
            ImageNtHeaders::x86(h) => h.OptionalHeader.ImageBase as *const c_void,
            ImageNtHeaders::x64(h) => h.OptionalHeader.ImageBase as *const c_void,
        }
    }

    pub fn get_size_of_image(&self) -> usize {
        match *self {
            ImageNtHeaders::x86(h) => h.OptionalHeader.SizeOfImage as usize,
            ImageNtHeaders::x64(h) => h.OptionalHeader.SizeOfImage as usize,
        }
    }

    pub fn get_file_alignment(&self) -> u32 {
        match *self {
            ImageNtHeaders::x86(h) => h.OptionalHeader.FileAlignment,
            ImageNtHeaders::x64(h) => h.OptionalHeader.FileAlignment,
        }
    }

    pub fn get_section_alignment(&self) -> u32 {
        match *self {
            ImageNtHeaders::x86(h) => h.OptionalHeader.SectionAlignment,
            ImageNtHeaders::x64(h) => h.OptionalHeader.SectionAlignment,
        }
    }

    pub fn get_data_directory(&self) -> &[IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES] {
        match *self {
            ImageNtHeaders::x86(h) => &h.OptionalHeader.DataDirectory,
            ImageNtHeaders::x64(h) => &h.OptionalHeader.DataDirectory,
        }
    }
}

// Zero copy
#[repr(C)]
#[derive(Debug)]
pub struct PeHeader<'a> {
    pub dos_header: &'a IMAGE_DOS_HEADER,
    pub dos_stub: &'a [u8],
    pub nt_header: ImageNtHeaders<'a>,
}

impl<'a> PeHeader<'a> {
    pub fn new(bs: &'a [u8]) -> Result<PeHeader<'a>> {
        let dos_header =
            unsafe { &*mem::transmute::<*const u8, *const IMAGE_DOS_HEADER>(bs.as_ptr()) };
        dos_header.is_valid()?;

        let dos_stub = &bs[mem::size_of::<IMAGE_DOS_HEADER>()..(dos_header.e_lfanew as _)];

        let nt_headers = unsafe {
            match *mem::transmute::<*const u8, *const WORD>(bs.as_ptr().offset(
                dos_header.e_lfanew as isize
                    + mem::size_of::<DWORD>() as isize
                    + mem::size_of::<IMAGE_FILE_HEADER>() as isize,
            )) {
                IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                    ImageNtHeaders::x64(mem::transmute::<*const u8, &IMAGE_NT_HEADERS64>(
                        bs.as_ptr().offset(dos_header.e_lfanew as isize),
                    ))
                }
                IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                    ImageNtHeaders::x86(mem::transmute::<*const u8, &IMAGE_NT_HEADERS32>(
                        bs.as_ptr().offset(dos_header.e_lfanew as isize),
                    ))
                }
                _ => return Err(Error::InvalidOptionalHeaderMagic),
            }
        };
        nt_headers.is_valid()?;

        Ok(PeHeader {
            dos_header: dos_header,
            dos_stub: dos_stub,
            nt_header: nt_headers,
        })
    }

    pub fn size(&self) -> usize {
        mem::size_of::<IMAGE_DOS_HEADER>()
            + self.dos_stub.len()
            + if let ImageNtHeaders::x86(_) = self.nt_header {
                mem::size_of::<IMAGE_NT_HEADERS32>()
            } else {
                mem::size_of::<IMAGE_NT_HEADERS64>()
            }
    }
}
