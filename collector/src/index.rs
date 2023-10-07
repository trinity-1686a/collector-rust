use std::collections::BTreeSet;
use std::ops::RangeBounds;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncReadExt;

use crate::descriptor::{Type, VersionnedType};
use crate::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    /// Creation time of the index
    pub creation_time: DateTime<Utc>,
    /// Base url for content
    pub path: String,
    /// Files contained in the index
    pub files: BTreeSet<File>,
}

impl Default for Index {
    fn default() -> Self {
        Index {
            creation_time: epoch(),
            path: String::new(),
            files: BTreeSet::new(),
        }
    }
}

impl Index {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut file = fs::File::open(path).await?;
        let mut json = Vec::new();
        file.read_to_end(&mut json).await?;
        let index: SerializedIndex = serde_json::from_slice(&json)?;

        let files = index
            .list_files()
            .map(|(p, mut f)| {
                f.path = p;
                f
            })
            .collect();
        Ok(Index {
            creation_time: index.index_created,
            path: index.path,
            files,
        })
    }
}

/// Collector index
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct SerializedIndex {
    /// Creation time of the index
    #[serde(with = "date_format")]
    pub index_created: DateTime<Utc>,
    #[serde(default)]
    pub build_revision: String,
    /// Base url for content
    pub path: String,
    /// Directories contained at the root of fs tree
    #[serde(default)]
    pub directories: Vec<Directory>,
    /// Files contained at the root of fs tree
    #[serde(default)]
    pub files: Vec<File>,
}

impl SerializedIndex {
    fn list_files(&self) -> impl Iterator<Item = (String, File)> + '_ {
        self.directories
            .iter()
            .flat_map(|dir| dir.list_files_rec())
            .map(|(mut path, file)| {
                path.reverse();
                path.push(&file.path);
                (path.join("/"), file)
            })
    }
}

/// A single directory
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Directory {
    /// Path part leading to this directory
    pub path: String,
    /// Directories contained in this directory
    #[serde(default)]
    pub directories: Vec<Directory>,
    /// Files contained in this directory
    #[serde(default)]
    pub files: Vec<File>,
}

impl Directory {
    fn list_files_rec(&self) -> Box<dyn Iterator<Item = (Vec<&str>, File)> + '_> {
        let iter = self
            .directories
            .iter()
            .flat_map(|dir| dir.list_files_rec())
            .map(|(mut path, file)| {
                path.push(&self.path);
                (path, file)
            })
            .chain(
                self.files
                    .iter()
                    .map(|file| (vec![self.path.as_str()], file.clone())),
            );
        Box::new(iter)
    }
}

/// Metadatas of a file
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct File {
    /// Path part leading to this file.
    pub path: String,
    /// File length.
    pub size: u64,
    /// Date when this file was last modified.
    #[serde(with = "date_format")]
    pub last_modified: DateTime<Utc>,
    /// Types of descriptor this file contains.
    #[serde(default)]
    pub types: Vec<VersionnedType>,
    /// Date this file was first published, set to unix epoch if unknown.
    #[serde(with = "date_format", default = "epoch")]
    pub first_published: DateTime<Utc>,
    /// Date this file was last published, set to unix epoch if unknown.
    #[serde(with = "date_format", default = "epoch")]
    pub last_published: DateTime<Utc>,
    /// SHA256 of the file.
    #[serde(with = "base64")]
    pub sha256: [u8; 32],
}

impl File {
    pub fn type_matches(&self, ttype: &Type) -> bool {
        self.types.iter().map(|vt| &vt.ttype).any(|tt| tt == ttype)
    }

    pub fn overlap<R: RangeBounds<DateTime<Utc>>>(&self, time_range: &R) -> bool {
        if time_range.contains(&self.first_published) || time_range.contains(&self.last_published)
        || time_range.contains(&self.last_modified) {
            return true;
        }
        // only case left is when time_range is strictly included in first..=last
        use std::ops::Bound::{Excluded, Included};
        let get_bound = |bound| match bound {
            Included(v) | Excluded(v) => Some(v),
            _ => None,
        };

        let bound = get_bound(time_range.start_bound())
            .or_else(|| get_bound(time_range.end_bound()))
            .expect("if we are here, time_range can't be unbounded");

        self.time_range().contains(bound)
    }

    pub fn time_range(&self) -> std::ops::RangeInclusive<DateTime<Utc>> {
        self.first_published..=self.last_published
    }

    pub fn is_archive(&self) -> bool {
        self.path.ends_with(".tar") || self.path.contains(".tar.")
    }
}

fn epoch() -> DateTime<Utc> {
    std::time::SystemTime::UNIX_EPOCH.into()
}

mod date_format {
    // copied from serde documentation on custom date (de)serializer
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &str = "%Y-%m-%d %H:%M";

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Utc.datetime_from_str(&s, FORMAT)
            .map_err(serde::de::Error::custom)
    }
}

mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let base64 = String::deserialize(d)?;
        let buf = base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)?;
        if buf.len() == N {
            let mut res = [0; N];
            res.copy_from_slice(&buf);
            Ok(res)
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid length {}, expected {}",
                buf.len(),
                N
            )))
        }
    }
}
