use super::def::*;
use super::error::{Error, Result};
use super::header::ImageNtHeaders;

impl IMAGE_DOS_HEADER {
    pub(crate) fn is_valid(&self) -> Result<()> {
        if self.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(Error::InvalidDosSignature);
        }

        if self.e_lfanew == 0 {
            return Err(Error::InvalidNtHeaderOffset);
        }

        Ok(())
    }
}

impl<'a> ImageNtHeaders<'a> {
    pub(crate) fn is_valid(&self) -> Result<()> {
        match *self {
            ImageNtHeaders::x86(h) => {
                if h.Signature != IMAGE_NT_SIGNATURE {
                    return Err(Error::InvalidNtSignature);
                };

                if h.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 {
                    return Err(Error::UnsupportedMachine);
                }

                // 32-bit .NET assembly may not set IMAGE_FILE_32BIT_MACHINE
                if h.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
                //    || h.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE == 0
                {
                    return Err(Error::InvalidFileHeaderCharacteristics);
                }
            }
            ImageNtHeaders::x64(h) => {
                if h.Signature != IMAGE_NT_SIGNATURE {
                    return Err(Error::InvalidNtSignature);
                };

                if h.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
                    return Err(Error::UnsupportedMachine);
                }

                if h.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
                //    || h.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE == 0
                {
                    return Err(Error::InvalidFileHeaderCharacteristics);
                }
            }
        };

        Ok(())
    }
}
