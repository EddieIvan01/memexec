use super::def::*;
use super::error::Result;
use super::header::{ImageNtHeaders, PeHeader};
use super::section::SectionArea;

#[repr(C)]
#[derive(Debug)]
pub struct PE<'a> {
    pub pe_header: PeHeader<'a>,
    pub section_area: SectionArea<'a>,
    pub raw: &'a [u8],
}

impl<'a> PE<'a> {
    pub fn new(bs: &'a [u8]) -> Result<PE<'a>> {
        let pe_header = PeHeader::new(bs)?;
        let section_area = SectionArea::new(
            &bs[pe_header.size()..],
            pe_header.nt_header.get_file_header().NumberOfSections,
        )?;

        Ok(PE {
            pe_header: pe_header,
            section_area: section_area,
            raw: bs,
        })
    }

    pub fn is_x86(&self) -> bool {
        match self.pe_header.nt_header {
            ImageNtHeaders::x86(_) => true,
            ImageNtHeaders::x64(_) => false,
        }
    }

    pub fn is_x64(&self) -> bool {
        !self.is_x86()
    }

    pub fn is_dll(&self) -> bool {
        match self.pe_header.nt_header {
            ImageNtHeaders::x86(h) => h.FileHeader.Characteristics & IMAGE_FILE_DLL != 0,
            ImageNtHeaders::x64(h) => h.FileHeader.Characteristics & IMAGE_FILE_DLL != 0,
        }
    }

    pub fn is_dot_net(&self) -> bool {
        let dot_net_desc =
            &self.pe_header.nt_header.get_data_directory()[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        dot_net_desc.Size != 0 && dot_net_desc.VirtualAddress != 0
    }
}
