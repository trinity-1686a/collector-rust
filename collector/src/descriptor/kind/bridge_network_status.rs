use derive_builder;
use std::net::SocketAddrV6;
use std::{
    vec,
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use chrono::{DateTime, Utc};
use derive_builder::Builder;

use super::utils::*;
use crate::error::{Error, ErrorKind};

#[derive(Debug)]
pub struct Header {
    pub published_timestamp: DateTime<Utc>,
    pub flags: HashMap<String, String>,
    pub fingerprint: String,
}

impl Header {
    pub fn parse(input: &str) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;
        let mut desc = descriptor_lines(input)?;
        Ok(extract_desc! {
        desc => Header rest {
            uniq("published") [day, hour] => {
                published_timestamp: date(&format!("{} {}", day, hour))?.1,
            },
           uniq("flag-thresholds") [] => {
                // TODO should reject when split_once fail
                flags: rest.iter()
                            .filter_map(|v| v.split_once('='))
                            .map(|(k,v)| (k.to_owned(), v.to_owned()))
                            .collect(),
            },
            uniq("fingerprint") [] => {
                fingerprint: rest.join(" "),
            },

        }})
    }
}

#[derive(Debug, Clone)]
pub enum Address {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
}

impl Address {
    fn parse(input: &str) -> Result<Self, Error> {
        if let Ok(addr) = input.parse::<SocketAddrV4>() {
            Ok(Self::Ipv4(addr))
        } else {
            Ok(Self::Ipv6(input.parse::<SocketAddrV6>()?))
        }
    }
}

#[derive(Debug, Builder, Clone)]
pub struct NetworkStatus {
    pub nickname: String,
    pub identity: String,
    pub digest: String,
    pub publication: DateTime<Utc>,
    pub ipv4: Ipv4Addr,
    pub or_port: u16,
    pub dir_port: u16,
    #[builder(setter(custom))]
    pub addresses: Vec<Address>,
    pub flags: Vec<String>,
    pub bandwidth: u64,
    #[builder(setter(custom))]
    pub policies: Vec<Policy>,
}

impl NetworkStatusBuilder {
    fn addresses(mut self, value: Address) -> Self {
        match self.addresses {
            Some(ref mut addr) => addr.push(value),
            None => self.addresses = Some(vec![value]),
        }
        self
    }

    fn policies(mut self, value: Policy) -> Self {
        match self.policies {
            Some(ref mut pol) => pol.push(value),
            None => self.policies = Some(vec![value]),
        }
        self
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Policy {
    Accept(String),
    Reject(String),
}

#[derive(Debug)]
pub struct BridgeNetworkStatus {
    pub header: Header,
    pub network_status: Vec<NetworkStatus>,
}

impl BridgeNetworkStatus {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;

        if version.0 != 1 || version.1 > 2 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "bridge-network-status v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let header = Header::parse(&format!("{}\n", input.lines().take(3).collect::<Vec<_>>().join("\n")))?;

        let mut network_status = Vec::new();

        input.lines().skip(3).fold(
            Ok(NetworkStatusBuilder::default()),
            |acc, line| -> Result<NetworkStatusBuilder, Error> {
                match parse_line(line) {
                    ("r", params) => {
                        let mut builder = acc?;

                        if let Ok(net) = builder.build() {
                            network_status.push(net);
                            builder = NetworkStatusBuilder::default();
                        }

                        Ok(builder
                            .nickname(params[0].to_string())
                            .identity(params[1].to_string())
                            .digest(params[2].to_string())
                            .publication(date(&format!("{} {}", params[3], params[4]))?.1)
                            .ipv4(params[5].parse()?)
                            .or_port(params[6].parse()?)
                            .dir_port(params[7].parse()?)
                            .to_owned())
                    }
                    ("a", params) => {
                        let builder = acc?;
                        Ok(builder.addresses(Address::parse(params[0])?))
                    }
                    ("s", params) => {
                        let mut builder = acc?;
                        Ok(builder
                            .flags(params.iter().map(|elem| elem.to_string()).collect())
                            .to_owned())
                    }
                    ("w", params) => {
                        let mut builder = acc?;
                        Ok(builder
                            .bandwidth(
                                params[0]
                                    .split_once('=')
                                    .ok_or_else(|| {
                                        ErrorKind::MalformedDesc("Bandwidth malformed".to_owned())
                                    })?
                                    .1
                                    .parse()?,
                            )
                            .to_owned())
                    }
                    ("p", params) => {
                        let builder = acc?;
                        let pol = match params[0] {
                            "accept" => Policy::Accept(params[1].to_owned()),
                            "reject" => Policy::Reject(params[1].to_owned()),
                            _ => unreachable!(),
                        };
                        Ok(builder.policies(pol))
                    }
                    // handle empty line
                    ("", _) => acc,
                    (_any, _value) => {
                        unreachable!()
                    }
                }
            },
        )?;

        Ok(BridgeNetworkStatus {
            header,
            network_status,
        })
    }
}

fn parse_line(input: &str) -> (&str, Vec<&str>) {
    let t = input.split(' ').collect::<Vec<&str>>();
    (t[0], t[1..].to_vec())
}
