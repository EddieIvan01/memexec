use super::peloader;
use super::peparser;

#[derive(Debug)]
pub enum Error {
    PeParserErr(peparser::error::Error),
    PeLoaderErr(peloader::error::Error),
    MismatchedArch,
}

impl std::convert::From<peloader::error::Error> for Error {
    fn from(err: peloader::error::Error) -> Self {
        Error::PeLoaderErr(err)
    }
}

impl std::convert::From<peparser::error::Error> for Error {
    fn from(err: peparser::error::Error) -> Self {
        Error::PeParserErr(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
