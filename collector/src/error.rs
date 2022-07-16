use std::{io, num};

use thiserror::Error;

/// Error type of this crate
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("collector error: {0}")]
    Collector(#[from] ErrorKind),
    #[error("ParseInt error: {0}")]
    Parse(#[from] num::ParseIntError),
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    HashMissmatch,
    HttpError(u16),
    UnsupportedDesc(String),
    MalformedDesc,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use ErrorKind::*;
        match self {
            HashMissmatch => f.write_str("Hash missmatch"),
            HttpError(code) => write!(f, "Http error, code {}", code),
            UnsupportedDesc(msg) => f.write_str(msg),
            MalformedDesc => f.write_str("Malformed descriptor"),
        }
    }
}

impl<T> From<nom::Err<T>> for Error {
    fn from(_: nom::Err<T>) -> Self {
        Error::Collector(ErrorKind::MalformedDesc)
    }
}

/*
impl<'a, T> From<T> for Error
where T: nom::error::ParseError<&'a str> {
    fn from(_: T) -> Self {
        Error::Collector(ErrorKind::MalformedDesc)
    }
}
*/

impl std::error::Error for ErrorKind {}


