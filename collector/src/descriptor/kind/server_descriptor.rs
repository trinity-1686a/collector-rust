use std::cmp::Ordering;
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
pub struct ServerDescriptor {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub or_port: u16,
    pub ipv6: Option<Ipv6Addr>,
    pub or_port_v6: Option<u16>,
    pub platform: String,
    pub fingerprint: String,
    pub uptime: u64,
    pub bandwidth: (u64, u64, u64),
    pub extra_info: String,
    pub hidden_service: bool,
    pub contact: Option<String>,
    pub onion_key: String,
    pub accept_reject: Vec<Network>,
    pub tunnelled: bool,
}

impl ServerDescriptor {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;

        if version.0 != 1 || version.1 != 0 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "server-descriptor v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let mut desc = descriptor_lines(input)?;

        Ok(extract_desc! {
            desc => ServerDescriptor rest {
                uniq("router") [name, ip, port] => {
                        name: name.to_owned(),
                        ipv4: ip.parse()?,
                        or_port: port.parse()?,
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
                uniq("ntor-onion-key") [key] => {
                    onion_key: key.to_owned(),
                },
                opt("tunnelled-dir-server") [] => {
                    tunnelled: rest.is_some(),
                },
                multi("accept", "reject") [] => {
                    accept_reject: {
                        rest.iter().map(|e| match e.name {
                            "accept" => Ok(Network::Accept(e.values
                                               .get(0)
                                               .ok_or_else(||
                                                    ErrorKind::MalformedDesc(
                                                        "missing parameters to accept".to_owned()
                                                        ))?
                                               .to_string())),
                            "reject" => Ok(Network::Reject(e.values
                                               .get(0)
                                               .ok_or_else(||
                                                    ErrorKind::MalformedDesc(
                                                        "missing parameters to reject".to_owned()
                                                        ))?
                                               .to_string())),
                            _ => unreachable!(),
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                    },
                },
            }
        })
    }

    /// Create a dummy descriptor to allow range over BTree of ServerDescriptor
    pub fn empty(timestamp: DateTime<Utc>) -> Self {
        ServerDescriptor {
            timestamp,
            name: String::new(),
            ipv4: Ipv4Addr::BROADCAST,
            or_port: 0,
            ipv6: None,
            or_port_v6: None,
            platform: String::new(),
            fingerprint: String::new(),
            uptime: 0,
            bandwidth: (0, 0, 0),
            extra_info: String::new(),
            hidden_service: false,
            contact: None,
            onion_key: String::new(),
            accept_reject: Vec::new(),
            tunnelled: false,
        }
    }
}

impl Ord for ServerDescriptor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then(self.fingerprint.cmp(&other.fingerprint))
    }
}

impl PartialOrd for ServerDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
