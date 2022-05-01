use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::error::{Error, ErrorKind};
use crate::index::File;

/// Type of a descriptor, unversionned
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    BandwidthFile,
    BridgeExtraInfo,
    BridgeNetworkStatus,
    BridgePoolAssignment,
    BridgeServerDescriptor,
    BridgestrapStats,
    DirKeyCertificate3,
    Directory,
    ExtraInfo,
    Microdescriptor,
    NetworkStatus2,
    NetworkStatusConsensus3,
    NetworkStatusMicrodescConsensus3,
    NetworkStatusVote3,
    ServerDescriptor,
    SnowflakeStats,
    Tordnsel,
    Torperf,
    Unknown(String),
}

impl Type {
    pub fn as_str(&self) -> &str {
        use Type::*;
        match self {
            BandwidthFile => "bandwidth-file",
            BridgeExtraInfo => "bridge-extra-info",
            BridgeNetworkStatus => "bridge-network-status",
            BridgePoolAssignment => "bridge-pool-assignment",
            BridgeServerDescriptor => "bridge-server-descriptor",
            BridgestrapStats => "bridgestrap-stats",
            DirKeyCertificate3 => "dir-key-certificate-3",
            Directory => "directory",
            ExtraInfo => "extra-info",
            Microdescriptor => "microdescriptor",
            NetworkStatus2 => "network-status-2",
            NetworkStatusConsensus3 => "network-status-consensus-3",
            NetworkStatusMicrodescConsensus3 => "network-status-microdesc-consensus-3",
            NetworkStatusVote3 => "network-status-vote-3",
            ServerDescriptor => "server-descriptor",
            SnowflakeStats => "snowflake-stats",
            Tordnsel => "tordnsel",
            Torperf => "torperf",
            Unknown(s) => s.as_ref(),
        }
    }
}

impl FromStr for Type {
    type Err = std::convert::Infallible;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        use Type::*;
        Ok(match val {
            "bandwidth-file" => BandwidthFile,
            "bridge-extra-info" => BridgeExtraInfo,
            "bridge-network-status" => BridgeNetworkStatus,
            "bridge-pool-assignment" => BridgePoolAssignment,
            "bridge-server-descriptor" => BridgeServerDescriptor,
            "bridgestrap-stats" => BridgestrapStats,
            "dir-key-certificate-3" => DirKeyCertificate3,
            "directory" => Directory,
            "extra-info" => ExtraInfo,
            "microdescriptor" => Microdescriptor,
            "network-status-2" => NetworkStatus2,
            "network-status-consensus-3" => NetworkStatusConsensus3,
            "network-status-microdesc-consensus-3" => NetworkStatusMicrodescConsensus3,
            "network-status-vote-3" => NetworkStatusVote3,
            "server-descriptor" => ServerDescriptor,
            "snowflake-stats" => SnowflakeStats,
            "tordnsel" => Tordnsel,
            "torperf" => Torperf,
            other => Unknown(other.to_owned()),
        })
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of a descriptor with version
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionnedType {
    pub ttype: Type,
    pub version: (u32, u32),
}

impl VersionnedType {
    pub fn parse(input: &str) -> nom::IResult<&str, Self, nom::error::Error<&str>> {
        use nom_combinators::*;

        let (i, _) = tag("@type ")(input)?;
        let (i, ttype) = map(take_till(|c| c == ' '), |ttype| {
            Type::from_str(ttype).unwrap()
        })(i)?;
        let (i, _) = space1(i)?;
        let (i, major) = u32(i)?;
        let (i, _) = tag(".")(i)?;
        let (i, minor) = u32(i)?;
        let (i, _) = line_ending(i)?;

        Ok((
            i,
            VersionnedType {
                ttype,
                version: (major, minor),
            },
        ))
    }
}

impl fmt::Display for VersionnedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "@type {} {}.{}",
            self.ttype, self.version.0, self.version.1
        )
    }
}

impl Serialize for VersionnedType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{} {}.{}",
            self.ttype.as_str(),
            self.version.0,
            self.version.1
        ))
    }
}

impl<'de> Deserialize<'de> for VersionnedType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let (ttype, version) = s
            .split_once(' ')
            .ok_or_else(|| Error::custom("invalid value: missing space".to_owned()))?;
        let (major, minor) = version
            .split_once('.')
            .ok_or_else(|| Error::custom("invalid value: missing dot".to_owned()))?;

        let ttype = Type::from_str(ttype).unwrap();
        let major = major
            .parse()
            .map_err(|_| Error::custom("invalid value: invalid major".to_owned()))?;
        let minor = minor
            .parse()
            .map_err(|_| Error::custom("invalid value: invalid minor".to_owned()))?;

        Ok(VersionnedType {
            ttype,
            version: (major, minor),
        })
    }
}

pub struct Descriptor {
    path: PathBuf,
    file: File,
}

impl Descriptor {
    pub fn new(path: PathBuf, file: File) -> Self {
        Descriptor { path, file }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub async fn decode(&self) -> Result<DecodedDescriptor, Error> {
        let mut file = tokio::fs::File::open(&self.path).await?;
        let mut buff = String::with_capacity(128 * 1024);
        file.read_to_string(&mut buff).await?;
        drop(file);
        let (buff, vt) = VersionnedType::parse(&buff)?;

        match vt.ttype {
            Type::BridgePoolAssignment => Ok(DecodedDescriptor::BridgePoolAssignment(
                BridgePoolAssignment::parse(buff, vt.version)?,
            )),
            t => Err(ErrorKind::UnsupportedDesc(format!(
                "unsupported descriptor {}, not implemented",
                t
            ))
            .into()),
        }
    }
}

#[derive(Debug)]
pub enum DecodedDescriptor {
    BridgePoolAssignment(BridgePoolAssignment),
    /*
        BandwidthFile,
        BridgeExtraInfo,
        BridgeNetworkStatus,
        BridgeServerDescriptor,
        BridgestrapStats,
        DirKeyCertificate3,
        Directory,
        ExtraInfo,
        Microdescriptor,
        NetworkStatus2,
        NetworkStatusConsensus3,
        NetworkStatusMicrodescConsensus3,
        NetworkStatusVote3,
        ServerDescriptor,
        SnowflakeStats,
        Tordnsel,
        Torperf,
    */
}

#[derive(Debug)]
pub struct BridgePoolAssignment {
    pub timestamp: DateTime<Utc>,
    pub data: BTreeMap<String, (String, HashMap<String, String>)>,
}

impl BridgePoolAssignment {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use nom_combinators::*;

        if version.0 != 1 || version.1 != 0 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "bridge-pool-assignment v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }
        // bridge-pool-assignment 2011-03-13 14:38:03
        //let (i, _) = tag("bridge-pool-assignment ")(input);;
        let (i, _) = t(tag("bridge-pool-assignment ")(input))?;
        let (i, timestamp) = date(i)?;
        let (i, _) = t(line_ending(i))?;

        let mut it = iterator(
            i,
            tuple((
                fingerprint,
                space1,
                take_till(|c| c == ' ' || c == '\n'),
                kv_space,
                line_ending,
            )),
        );

        let data = it.fold(BTreeMap::new(), |mut data, (fp, _, pool, kv, _)| {
            data.insert(fp.to_owned(), (pool.to_owned(), kv));
            data
        });

        let (i, _) = it.finish()?;

        t(eof(i))?;

        Ok(BridgePoolAssignment { timestamp, data })
    }
}

mod nom_combinators {
    use super::*;
    use chrono::TimeZone;

    pub use nom::bytes::complete::{tag, take, take_till};
    pub use nom::character::complete::{
        anychar, char, hex_digit1, line_ending, space0, space1, u32,
    };
    pub use nom::combinator::{eof, iterator, map, map_parser, map_res, peek};
    pub use nom::multi::fold_many_m_n;
    pub use nom::sequence::tuple;

    /// Force type to help rustc find what we want
    pub fn t<T>(r: Result<T, nom::Err<()>>) -> Result<T, nom::Err<()>> {
        r
    }

    pub fn fingerprint(input: &str) -> nom::IResult<&str, &str, nom::error::Error<&str>> {
        map_parser(hex_digit1, take(40usize))(input)
    }

    pub fn date(input: &str) -> nom::IResult<&str, DateTime<Utc>, nom::error::Error<&str>> {
        let format = "%Y-%m-%d %H:%M:%S";
        map_res(take("yyyy-mm-dd hh:mm:ss".len()), |s| {
            Utc.datetime_from_str(s, format)
        })(input)
    }

    pub fn kv_space(
        input: &str,
    ) -> nom::IResult<&str, HashMap<String, String>, nom::error::Error<&str>> {
        let mut it = iterator(
            input,
            tuple((
                char(' '),
                take_till(|c| c == '='),
                char('='),
                take_till(|c| c == ' ' || c == '\n'),
                peek(anychar),
            )),
        );

        let mut kv = HashMap::new();
        for (_, k, _, v, eol) in &mut it {
            kv.insert(k.to_owned(), v.to_owned());
            if eol == '\n' {
                break;
            }
        }

        let (i, _) = it.finish()?;
        Ok((i, kv))
    }
}
