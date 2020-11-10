#[derive(Debug)]
pub enum Error {
    InvalidDosSignature,
    InvalidNtHeaderOffset,
    InvalidNtSignature,
    UnsupportedMachine,
    InvalidFileHeaderCharacteristics,
    InvalidOptionalHeaderMagic,
}

pub type Result<T> = std::result::Result<T, Error>;
