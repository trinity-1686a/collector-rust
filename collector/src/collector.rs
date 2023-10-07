use crate::error::{Error, ErrorKind};
use crate::Index;

use std::ops::RangeBounds;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use futures::stream::{self, Stream, StreamExt, TryStreamExt};
use rangetools::{BoundedSet, Rangetools};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::descriptor::file_reader::FileReader;
use crate::descriptor::{Descriptor, Type};
use crate::index::File;

const INDEX_URL: &str = "https://collector.torproject.org/index/index.json";

/// Struct to interact with CollecTor data. Main entry-point of the crate
#[derive(Debug)]
pub struct CollecTor {
    base_path: PathBuf,
    index_url: Option<String>,
    index: Index,
}

impl CollecTor {
    /// Create a new instance storing its data in `base_path`
    pub async fn new<P: Into<PathBuf>>(base_path: P) -> Result<Self, Error> {
        Self::new_with_url(base_path, Some(INDEX_URL.to_owned())).await
    }

    /// Create a new instance storing its data in `base_path`, and downloading index from
    /// `index_url`. If index_url is None, no network access will be made by this instance.
    pub async fn new_with_url<P: Into<PathBuf>>(
        base_path: P,
        index_url: Option<String>,
    ) -> Result<Self, Error> {
        let base_path = base_path.into();
        fs::create_dir_all(&base_path).await?;

        let mut collector = CollecTor {
            base_path,
            index_url,
            index: Index::default(),
        };

        collector.reload_index().await?;

        Ok(collector)
    }

    /// Get the inner [`Index`]
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Re-download the index. If offline, only re-read the file from filesystem.
    pub async fn reload_index(&mut self) -> Result<bool, Error> {
        if let Some(index_url) = self.index_url.as_ref() {
            let json = Client::new().get(index_url).send().await?.text().await?;

            let mut file = fs::File::create(self.base_path.join("index.json")).await?;
            file.write_all(json.as_bytes()).await?;
            file.flush().await?;
            std::mem::drop(file);
        }
        let index = Index::from_file(self.base_path.join("index.json")).await?;

        if self.index == index {
            Ok(false)
        } else {
            self.index = index;
            Ok(true)
        }
    }

    pub async fn download_descriptors<R: RangeBounds<DateTime<Utc>>>(
        &self,
        descriptor_types: &[Type],
        time_range: R,
        client: Option<Client>,
    ) -> Result<(), Vec<(Error, File)>> {
        let client = client.unwrap_or_else(Client::new);
        let mut downloads: Vec<_> = self
            .index
            .files
            .iter()
            .filter(|file| {
                descriptor_types
                    .iter()
                    .any(|ttype| file.type_matches(ttype))
                    && file.overlap(&time_range)
            })
            .map(|file| FileDownloader::new(file, self))
            // insert dummy error to make the type match
            .map(|dl| (Error::Collector(ErrorKind::HashMissmatch), dl))
            .collect();

        for _ in 0..3 {
            downloads = stream::iter(downloads.into_iter().map(|download| {
                download
                    .1
                    .download(client.clone(), self.index_url.is_some())
            }))
            .buffer_unordered(num_cpus::get())
            .filter_map(|res| async { res.err() })
            .collect()
            .await;
        }
        if downloads.is_empty() {
            Ok(())
        } else {
            Err(downloads
                .into_iter()
                .map(|(e, dl)| (e, dl.file.clone()))
                .collect())
        }
    }

    pub fn stream_descriptors<R: 'static + RangeBounds<DateTime<Utc>>>(
        &self,
        ttype: Type,
        time_range: R,
    ) -> impl Stream<Item = Result<Descriptor, (File, Error)>> + '_ {
        stream::iter(
            self.index
                .files
                .iter()
                .filter(move |file| file.type_matches(&ttype) && file.overlap(&time_range))
                .scan(BoundedSet::empty(), |ranges, file| {
                    // assumption: archives don't overlap, and appear first (which is true
                    // because archive/ < recent/
                    if file.is_archive() || ranges.clone().disjoint(file.time_range()) {
                        // could be cleaner if BoundedSet impl Default or union took &self/&mut self
                        *ranges =
                            std::mem::replace(ranges, BoundedSet::empty()).union(file.time_range());
                        Some(Some(file))
                    } else {
                        Some(None)
                    }
                })
                .flatten(),
        )
        .flat_map(|file| {
            self.file_to_descriptor_stream(file)
                .map_err(|e| (file.clone(), e))
        })
    }

    pub fn file_to_descriptor_stream<'a>(
        &'a self,
        file: &'a File,
    ) -> impl Stream<Item = Result<Descriptor, Error>> + 'a {
        FileReader::read_file(self.file_path(file))
            .and_then(|s| futures::future::ready(Descriptor::decode(&s)))
    }

    fn file_path(&self, file: &File) -> PathBuf {
        self.base_path.join(&file.path)
    }
}

struct FileDownloader<'a> {
    file: &'a File,
    collector: &'a CollecTor,
}

impl<'a> FileDownloader<'a> {
    fn new(file: &'a File, collector: &'a CollecTor) -> Self {
        FileDownloader { file, collector }
    }

    fn data_path(&self) -> PathBuf {
        self.collector.base_path.join(&self.file.path)
    }

    fn url(&self) -> String {
        format!("{}/{}", self.collector.index.path, self.file.path)
    }

    pub async fn download(
        self,
        client: Client,
        download: bool,
    ) -> Result<(), (Error, FileDownloader<'a>)> {
        self.download_inner(client, download)
            .await
            .map_err(|e| (dbg!(e), self))
    }

    async fn download_inner(&self, client: Client, download: bool) -> Result<(), Error> {
        let data_path = self.data_path();
        if let Ok(mut file) = fs::File::open(&data_path).await {
            let sha256 = self.file.sha256;
            let hash_ok = tokio::spawn(async move {
                let mut buf = vec![0; 256 * 1024];
                let mut hasher = Sha256::new();

                loop {
                    let Ok(len) = file.read(&mut buf).await else {
                        return false;
                    };
                    if len == 0 {
                        break;
                    }
                    hasher.update(&buf[..len]);
                }

                let res = hasher.finalize();
                res.as_slice() == sha256
            })
            .await
            .unwrap_or(false);
            if hash_ok {
                return Ok(());
            }
        }
        if !download {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found and download disabled",
            )
            .into());
        }

        let resp = client.get(&self.url()).send().await?;
        if resp.status() != StatusCode::OK {
            return Err(ErrorKind::HttpError(resp.status().as_u16()).into());
        }

        if resp
            .content_length()
            .map(|len| len != self.file.size)
            .unwrap_or(false)
        {
            // if len is wrong, hash will be too, don't bother receiving the whole file
            return Err(ErrorKind::HashMissmatch.into());
        }

        fs::create_dir_all(data_path.parent().expect("there is always a parent")).await?;
        let mut file = fs::File::create(&data_path).await?;
        let mut hasher = Sha256::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        let res = hasher.finalize();
        if res.as_slice() != self.file.sha256 {
            return Err(ErrorKind::HashMissmatch.into());
        }

        Ok(())
    }
}
