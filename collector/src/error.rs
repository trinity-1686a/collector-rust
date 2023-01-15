use std::{io, net, num};

use thiserror::Error;

use crate::descriptor;

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
    #[error("NetworkStatus error: {0}")]
    NetworkStatus(#[from] descriptor::kind::bridge_network_status::NetworkStatusBuilderError),
    #[error("ParseInt error: {0}")]
    ParseInt(#[from] num::ParseIntError),
    #[error("ParseIpV6 error: {0}")]
    ParseIpV6(#[from] net::AddrParseError),
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    HashMissmatch,
    HttpError(u16),
    UnsupportedDesc(String),
    MalformedDesc(String),
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use ErrorKind::*;
        match self {
            HashMissmatch => f.write_str("Hash missmatch"),
            HttpError(code) => write!(f, "Http error, code {}", code),
            UnsupportedDesc(msg) => f.write_str(msg),
            MalformedDesc(msg) => write!(f, "Malformed descriptor {msg}"),
        }
    }
}

impl<T: std::fmt::Debug> From<nom::Err<T>> for Error {
    fn from(e: nom::Err<T>) -> Self {
        Error::Collector(ErrorKind::MalformedDesc(format!("nom: {e:?}")))
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
