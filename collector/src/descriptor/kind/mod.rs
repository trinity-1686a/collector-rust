mod bridge_extra_info;
pub mod bridge_network_status;
mod bridge_pool_assignment;
mod bridge_server_descriptor;
mod bridgestrap_stats;
mod server_descriptor;
pub(crate) mod utils;

pub use bridge_extra_info::BridgeExtraInfo;
pub use bridge_network_status::BridgeNetworkStatus;
pub use bridge_pool_assignment::BridgePoolAssignment;
pub use bridge_server_descriptor::BridgeServerDescriptor;
pub use bridgestrap_stats::BridgestrapStats;
pub use server_descriptor::{ServerDescriptor, Microdescriptor, NetworkStatusMicrodescConsensus3};

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind};

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

#[derive(Debug)]
pub enum Descriptor {
    BridgeExtraInfo(Box<BridgeExtraInfo>),
    BridgeNetworkStatus(Box<BridgeNetworkStatus>),
    BridgePoolAssignment(BridgePoolAssignment),
    BridgeServerDescriptor(Box<BridgeServerDescriptor>),
    BridgestrapStats(Box<BridgestrapStats>),
    Microdescriptor(Box<Microdescriptor>),
    NetworkStatusMicrodescConsensus3(Box<NetworkStatusMicrodescConsensus3>),
    ServerDescriptor(Box<ServerDescriptor>),
    /*
        BandwidthFile,
        DirKeyCertificate3,
        Directory,
        ExtraInfo,
        NetworkStatus2,
        NetworkStatusConsensus3,
        NetworkStatusVote3,
        SnowflakeStats,
        Tordnsel,
        Torperf,
    */
}

impl Descriptor {
    pub fn decode(raw_descriptor: &str) -> Result<Self, Error> {
        let (buff, vt) = VersionnedType::parse(raw_descriptor).expect(&format!(""));

        match vt.ttype {
            Type::BridgeExtraInfo => Ok(Descriptor::BridgeExtraInfo(Box::new(
                BridgeExtraInfo::parse(buff, vt.version)?,
            ))),
            Type::BridgeNetworkStatus => Ok(Descriptor::BridgeNetworkStatus(Box::new(
                BridgeNetworkStatus::parse(buff, vt.version)?,
            ))),
            Type::BridgePoolAssignment => Ok(Descriptor::BridgePoolAssignment(
                BridgePoolAssignment::parse(buff, vt.version)?,
            )),
            Type::BridgeServerDescriptor => Ok(Descriptor::BridgeServerDescriptor(Box::new(
                BridgeServerDescriptor::parse(buff, vt.version)?,
            ))),
            Type::BridgestrapStats => Ok(Descriptor::BridgestrapStats(Box::new(
                BridgestrapStats::parse(buff, vt.version)?,
            ))),
            Type::Microdescriptor => Ok(Descriptor::Microdescriptor(Box::new(
                Microdescriptor::parse(buff, vt.version)?,
            ))),
            Type::NetworkStatusMicrodescConsensus3 => Ok(Descriptor::NetworkStatusMicrodescConsensus3(Box::new(
                NetworkStatusMicrodescConsensus3::parse(buff, vt.version)?,
            ))),
            Type::ServerDescriptor => Ok(Descriptor::ServerDescriptor(Box::new(
                ServerDescriptor::parse(buff, vt.version)?,
            ))),
            t => Err(ErrorKind::UnsupportedDesc(format!(
                "unsupported descriptor {}, not implemented",
                t
            ))
            .into()),
        }
    }

    pub fn bridge_extra_info(self) -> Result<BridgeExtraInfo, Self> {
        match self {
            Descriptor::BridgeExtraInfo(d) => Ok(*d),
            _ => Err(self),
        }
    }

    pub fn bridge_network_status(self) -> Result<BridgeNetworkStatus, Self> {
        match self {
            Descriptor::BridgeNetworkStatus(d) => Ok(*d),
            _ => Err(self),
        }
    }

    pub fn bridge_pool_assignment(self) -> Result<BridgePoolAssignment, Self> {
        match self {
            Descriptor::BridgePoolAssignment(d) => Ok(d),
            _ => Err(self),
        }
    }

    pub fn bridge_server_descriptor(self) -> Result<BridgeServerDescriptor, Self> {
        match self {
            Descriptor::BridgeServerDescriptor(d) => Ok(*d),
            _ => Err(self),
        }
    }

    pub fn bridgestrap_stats(self) -> Result<BridgestrapStats, Self> {
        match self {
            Descriptor::BridgestrapStats(d) => Ok(*d),
            _ => Err(self),
        }
    }

    pub fn server_descriptor(self) -> Result<ServerDescriptor, Self> {
        match self {
            Descriptor::ServerDescriptor(d) => Ok(*d),
            _ => Err(self),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DescriptorLine<'a> {
    pub name: &'a str,
    pub values: Vec<&'a str>,
    pub cert: Option<&'a str>,
    pub line: u32,
}

impl<'a> DescriptorLine<'a> {
    pub fn parse(input: &'a str) -> nom::IResult<&str, Self, nom::error::Error<&str>> {
        use crate::descriptor::nom_combinators::*;
        let (i, (mut name, mut values)) = sp_separated(input)?;
        if name == "opt" && !values.is_empty() {
            name = values.remove(0);
        }
        let (i, _) = line_ending(i)?;
        let (i, cert) = opt(cert)(i)?;

        Ok((
            i,
            DescriptorLine {
                name,
                values,
                cert,
                line: 0,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::descriptor::file_reader::FileReader;

    use futures::stream::{StreamExt, TryStreamExt};

    use super::*;

    async fn read_test_file(filename: &str) -> Vec<Result<Descriptor, Error>> {
        let desc = FileReader::read_file(filename)
            .and_then(|s| async move { Descriptor::decode(&s) })
            .collect::<Vec<_>>()
            .await;
        desc
    }

    #[tokio::test]
    async fn test_bridge_server_descriptor() {
        let res = read_test_file("tests/bridge_server_descriptor_test").await;
        assert_eq!(res.len(), 1);
        assert!(res[0].is_ok());
    }

    #[tokio::test]
    async fn test_bridge_server_descriptors() {
        let res = read_test_file("tests/bridge_server_descriptor_ex").await;
        res.iter().for_each(|d| {
            assert!(d.is_ok());
        });
    }

    #[tokio::test]
    async fn test_bridge_extra_info() {
        let res = read_test_file("tests/bridge_extra_info_test").await;
        println!("{:?}", res);
        assert_eq!(res.len(), 1);
        assert!(res[0].is_ok());
    }

    #[tokio::test]
    async fn test_server_descriptor() {
        let res = read_test_file("tests/server_descriptor_test").await;
        println!("{:?}", res);
        assert_eq!(res.len(), 1);
        assert!(res[0].is_ok());
    }

    #[tokio::test]
    async fn test_bridge_network_status() {
        let mut res = read_test_file("tests/bridge_network_status_test").await;
        println!("{:?}", res);
        assert!(res[0].is_ok());
        let net = res
            .pop()
            .unwrap()
            .unwrap()
            .bridge_network_status()
            .unwrap()
            .network_status;
        assert_eq!(net.len(), 2);
    }

    #[tokio::test]
    async fn test_bridgestrap_stats() {
        let mut res = read_test_file("tests/bridge_strap_stats_test").await;
        println!("{:?}", res);
        assert!(res[0].is_ok());
        let data = res.pop().unwrap().unwrap().bridgestrap_stats().unwrap().stats;
        assert_eq!(data.len(), 7);
    }
}
