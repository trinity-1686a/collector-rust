mod bridge_pool_assignment;
pub use bridge_pool_assignment::BridgePoolAssignment;

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    pub const ALL_TYPES: [Type; 18] = [
        Type::BandwidthFile,
        Type::BridgeExtraInfo,
        Type::BridgeNetworkStatus,
        Type::BridgePoolAssignment,
        Type::BridgeServerDescriptor,
        Type::BridgestrapStats,
        Type::DirKeyCertificate3,
        Type::Directory,
        Type::ExtraInfo,
        Type::Microdescriptor,
        Type::NetworkStatus2,
        Type::NetworkStatusConsensus3,
        Type::NetworkStatusMicrodescConsensus3,
        Type::NetworkStatusVote3,
        Type::ServerDescriptor,
        Type::SnowflakeStats,
        Type::Tordnsel,
        Type::Torperf,
    ];

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
            other => dbg!(Unknown(other.to_owned())),
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
        use crate::descriptor::nom_combinators::*;

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
