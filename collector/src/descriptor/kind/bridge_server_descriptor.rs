use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

use chrono::{DateTime, Utc};

use super::utils::*;
use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Network {
    Accept(String),
    Reject(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeServerDescriptor {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub or_port: u16,
    pub master_key: String,
    pub ipv6: Option<Ipv6Addr>,
    pub or_port_v6: Option<u16>,
    pub platform: String,
    pub proto: HashMap<String, String>,
    pub fingerprint: String,
    pub uptime: u64,
    pub bandwidth: (u64, u64, u64),
    pub extra_info: String,
    pub hidden_service: bool,
    pub contact: Option<String>,
    pub distribution_request: String,
    pub onion_key: String,
    pub accept_reject: Vec<Network>,
    pub tunnelled: bool,
    pub router_sha256: String,
    pub router: String,
}

impl BridgeServerDescriptor {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;

        if version.0 != 1 || version.1 > 2 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "bridge-server-descriptor v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let mut desc = descriptor_lines(input)?;

        Ok(extract_desc! {
            desc => BridgeServerDescriptor rest {
                uniq("router") [name, ip, port] => {
                    name: name.to_owned(),
                    ipv4: ip.parse().unwrap(),
                    or_port: port.parse().unwrap(),
                },
                uniq("master-key-ed25519") [key] => {
                    master_key: key.to_owned(),
                },
                uniq("published") [day, hour] => {
                    timestamp: date(&format!("{} {}", day, hour))?.1,
                },
                opt("or-address") [address] => {
                    ipv6: address.map(str::parse::<SocketAddrV6>).transpose()?
                        .as_ref().map(SocketAddrV6::ip).copied(),
                    or_port_v6: address.map(str::parse::<SocketAddrV6>).transpose()?
                        .as_ref().map(SocketAddrV6::port),
                },
                uniq("platform") [] => {
                    platform: rest.join(" "),
                },
                uniq("fingerprint") [] => {
                    fingerprint: rest.join(" "),
                },
                uniq("uptime") [uptime] => {
                    uptime: uptime.parse()?,
                },
                uniq("bandwidth") [a, b, c] => {
                    bandwidth: (a.parse()?, b.parse()?, c.parse()?),
                },
                uniq("extra-info-digest") [] => {
                    extra_info: rest.join(" "),
                },
                opt("hidden-service-dir") [] => {
                    hidden_service: rest.is_some(),
                },
                opt("contact") [] => {
                    contact: rest.map(|r| r.join(" ")),
                },
                opt("bridge-distribution-request") [req] => {
                    distribution_request: req.unwrap_or("any").to_owned(),
                },
                uniq("ntor-onion-key") [key] => {
                    onion_key: key.to_owned(),
                },
                uniq("proto") [] => {
                    // TODO should reject when split_once fail
                    proto: rest.iter().filter_map(|v| v.split_once('='))
                        .map(|(k,v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                },
                opt("tunnelled-dir-server") [] => {
                    tunnelled: rest.is_some(),
                },
                multi("accept", "reject") [] => {
                    accept_reject: {
                        rest.iter().map(|e| match e.name {
                            "accept" => Ok(Network::Accept(e.values
                                                           .get(0)
                                                           .ok_or_else(|| ErrorKind::MalformedDesc)?
                                                           .to_string())),
                            "reject" => Ok(Network::Reject(e.values
                                                           .get(0)
                                                           .ok_or_else(|| ErrorKind::MalformedDesc)?
                                                           .to_string())),
                            _ => unreachable!(),
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                    },
                },
                uniq("router-digest-sha256") [sha] => {
                    router_sha256: sha.to_owned(),
                },
                uniq("router-digest") [sha] => {
                    router: sha.to_owned(),
                },
            }
        })
    }

    /// Create a dummy descriptor to allow range over BTree of BridgeServerDescriptor
    pub fn empty(timestamp: DateTime<Utc>) -> Self {
        BridgeServerDescriptor {
            timestamp,
            name: String::new(),
            ipv4: Ipv4Addr::BROADCAST,
            or_port: 0,
            master_key: String::new(),
            ipv6: None,
            or_port_v6: None,
            platform: String::new(),
            proto: HashMap::new(),
            fingerprint: String::new(),
            uptime: 0,
            bandwidth: (0, 0, 0),
            extra_info: String::new(),
            hidden_service: false,
            contact: None,
            distribution_request: String::new(),
            onion_key: String::new(),
            accept_reject: Vec::new(),
            tunnelled: false,
            router_sha256: String::new(),
            router: String::new(),
        }
    }
}

impl Ord for BridgeServerDescriptor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then(self.fingerprint.cmp(&other.fingerprint))
    }
}

impl PartialOrd for BridgeServerDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
