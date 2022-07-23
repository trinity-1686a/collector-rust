use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{Ipv4Addr, IpAddr, SocketAddr};

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
    pub master_key: Option<String>,
    pub additional_address: Option<IpAddr>,
    pub additional_port: Option<u16>,
    pub platform: String,
    pub proto: HashMap<String, String>,
    pub fingerprint: String,
    pub uptime: Option<u64>,
    pub bandwidth: (u64, u64, u64),
    pub extra_info: Option<String>,
    pub hidden_service: bool,
    pub contact: Option<String>,
    pub distribution_request: String,
    pub onion_key: Option<String>,
    pub accept_reject: Vec<Network>,
    pub tunnelled: bool,
    pub router_sha256: Option<String>,
    pub router: String,
    pub protocols: Vec<String>,
    pub hibernating: bool,
    pub cache_extra_info: bool,
    pub family: Vec<String>,
    pub allow_single_hop_exits: bool,
    pub overload: Option<(u32, DateTime<Utc>)>,
    pub ipv6_policy: Network,
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
                uniq("router") [name, ip, port, _socks_port, _dir_port] => {
                    name: name.to_owned(),
                    ipv4: ip.parse().unwrap(),
                    or_port: port.parse().unwrap(),
                },
                opt("master-key-ed25519") [key] => {
                    master_key: key.map(|k| k.to_owned()),
                },
                uniq("published") [day, hour] => {
                    timestamp: date(&format!("{} {}", day, hour))?.1,
                },
                opt("or-address") [address] => {
                    additional_address: address.map(str::parse::<SocketAddr>).transpose()?
                        .as_ref().map(SocketAddr::ip),
                    additional_port: address.map(str::parse::<SocketAddr>).transpose()?
                        .as_ref().map(SocketAddr::port),
                },
                uniq("platform") [] => {
                    platform: rest.join(" "),
                },
                uniq("fingerprint") [] => {
                    fingerprint: rest.join(" "),
                },
                opt("uptime") [uptime] => {
                    uptime: uptime.map(|u| u.parse()).transpose()?,
                },
                uniq("bandwidth") [a, b, c] => {
                    bandwidth: (a.parse()?, b.parse()?, c.parse()?),
                },
                opt("extra-info-digest") [] => {
                    extra_info: rest.map(|d| d.join(" ")),
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
                opt("ntor-onion-key") [key] => {
                    onion_key: key.map(|k| k.to_owned()),
                },
                opt("proto") [] => {
                    // TODO should reject when split_once fail
                    proto: rest.map(|r|
                                    r.iter()
                                    .filter_map(|v| v.split_once('='))
                                    .map(|(k,v)| (k.to_owned(), v.to_owned()))
                                    .collect()
                                ).unwrap_or_default(),
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
                opt("router-digest-sha256") [sha] => {
                    router_sha256: sha.map(|s| s.to_owned()),
                },
                uniq("router-digest") [sha] => {
                    router: sha.to_owned(),
                },
                opt("protocols") [] => {
                    protocols: rest.unwrap_or_default()
                        .into_iter()
                        .map(|i| (*i).to_owned())
                        .collect(),
                },
                opt("hibernating") [val] => {
                    hibernating: val == Some("1"),
                },
                opt("caches-extra-info") [] => {
                    cache_extra_info: rest.is_some(),
                },
                opt("family") [] => {
                    family: rest.unwrap_or_default()
                        .into_iter()
                        .map(|i| (*i).to_owned())
                        .collect(),
                },
                opt("allow-single-hop-exits") [] => {
                    allow_single_hop_exits: rest.is_some(),
                },
                opt("overload-general") [version, day, hour] => {
                    overload: if let Some(version) = version {
                        let date = date(&format!("{} {}", day.unwrap(), hour.unwrap()))?.1;
                        Some((version.parse()?, date))
                    } else {
                        None
                    },
                },
                opt("ipv6-policy") [kw, policy] => {
                    ipv6_policy: match (kw, policy) {
                            (Some("accept"), Some(policy)) => Network::Accept(policy.to_string()),
                            (Some("reject"), Some(policy)) => Network::Reject(policy.to_string()),
                            (Some(_), _) => return Err(ErrorKind::MalformedDesc(
                                                    "invalid ipv6 policy".to_owned()
                                                    ).into()),
                            (None, _) => Network::Reject("1-65535".to_owned()),
                    },
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
            master_key: None,
            additional_address: None,
            additional_port: None,
            platform: String::new(),
            proto: HashMap::new(),
            fingerprint: String::new(),
            uptime: None,
            bandwidth: (0, 0, 0),
            extra_info: None,
            hidden_service: false,
            contact: None,
            distribution_request: String::new(),
            onion_key: None,
            accept_reject: Vec::new(),
            tunnelled: false,
            router_sha256: None,
            router: String::new(),
            protocols: Vec::new(),
            hibernating: false,
            cache_extra_info: false,
            family: Vec::new(),
            allow_single_hop_exits: false,
            overload: None,
            ipv6_policy: Network::Reject("1-65535".to_owned()),
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
