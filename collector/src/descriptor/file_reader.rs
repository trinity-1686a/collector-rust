use crate::error::Error;

use std::path::Path;
use std::pin::Pin;

use async_compat::CompatExt;
use async_compression::tokio::bufread::XzDecoder;
use async_stream::try_stream;
use async_tar::Archive;
use futures::io::AsyncReadExt;
use futures::stream::Stream;
use tokio::{
    fs,
    io::{AsyncRead, BufReader},
};

pub struct FileReader;

impl FileReader {
    pub fn read_file<P: AsRef<Path>>(path: P) -> impl Stream<Item = Result<String, Error>> {
        try_stream! {
            let path = path.as_ref();
            let path_string = path.display().to_string();
            if path_string.ends_with(".tar") || path_string.contains(".tar.") {
                let reader = BufReader::new(fs::File::open(&path).await?);
                let reader: Pin<Box<dyn AsyncRead + Send + Sync>> =
                    if path.extension().map(|ext| ext == "xz").unwrap_or(false) {
                        Box::pin(XzDecoder::new(reader))
                    } else {
                        Box::pin(reader)
                    };
                for await entry in Archive::new(reader.compat()).entries()? {
                    let mut entry = entry?;
                    if !entry.header().entry_type().is_file() {
                        continue;
                    }
                    let mut body = String::new();
                    entry.read_to_string(&mut body).await?;
                    yield body;
                }
            } else {
                let body = fs::read_to_string(&path).await?;
                let mut body = body.as_str();
                while let Some(idx) = body[..].find("\n@type") {
                    // account for the '\n'
                    let idx = idx + 1;
                    yield body[..idx].to_owned();
                    body = &body[idx..];
                }
                yield body.to_owned();
            }
        }
    }
}
