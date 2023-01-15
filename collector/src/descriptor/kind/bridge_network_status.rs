use derive_builder;
use itertools::Itertools;
use std::net::SocketAddr;
use std::{collections::HashMap, net::Ipv4Addr, vec};

use chrono::{DateTime, Utc};
use derive_builder::Builder;

use super::utils::*;
use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone)]
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
                flags: rest.iter()
                            .map(|v| v.split_once('=').ok_or_else(|| ErrorKind::MalformedDesc("Header flags are malformed".to_owned())))
                            .map_ok(|(k,v)| (k.to_owned(), v.to_owned()))
                            .collect::<Result<HashMap<_,_>,_>>()?,
            },
            uniq("fingerprint") [fingerprint] => {
                fingerprint: fingerprint.to_string(),
            },

        }})
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Builder)]
pub struct NetworkStatus {
    pub nickname: String,
    pub identity: String,
    pub digest: String,
    pub publication: DateTime<Utc>,
    pub ipv4: Ipv4Addr,
    pub or_port: u16,
    pub dir_port: u16,
    #[builder(setter(custom), default)]
    pub addresses: Vec<SocketAddr>,
    pub flags: Vec<String>,
    pub bandwidth: u64,
    #[builder(setter(custom))]
    pub policies: Vec<Policy>,
}

impl NetworkStatusBuilder {
    fn addresses(mut self, value: SocketAddr) -> Self {
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

#[derive(Debug, PartialEq, Eq, Clone)]
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

        let header = Header::parse(&format!(
            "{}\n",
            input.lines().take(3).collect::<Vec<_>>().join("\n")
        ))?;

        let mut network_status = Vec::new();
        let mut first = true;

        let builder = input.lines().skip(3).fold(
            Ok(NetworkStatusBuilder::default()),
            |acc, line| -> Result<NetworkStatusBuilder, Error> {
                let mut builder = acc?;
                match parse_line(line)? {
                    ("r", params) => {
                        if params.len() < 8 {
                            return Err(Error::Collector(ErrorKind::MalformedDesc(
                                "r lines need at least 8 parameters".to_owned(),
                            )));
                        }

                        match builder.build() {
                            Ok(net) => {
                                network_status.push(net);
                                builder = NetworkStatusBuilder::default();
                            }
                            Err(err) => {
                                if !first {
                                    return Err(Error::NetworkStatus(err));
                                }
                            }
                        }
                        first = false;

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
                        if params.len() == 0 {
                            return Err(Error::Collector(ErrorKind::MalformedDesc(
                                "a lines need at least 1 parameters".to_owned(),
                            )));
                        }
                        Ok(builder.addresses(params[0].parse()?))
                    }
                    ("s", params) => Ok(builder
                        .flags(params.iter().map(|elem| elem.to_string()).collect())
                        .to_owned()),
                    ("w", params) => {
                        if params.len() == 0 {
                            return Err(Error::Collector(ErrorKind::MalformedDesc(
                                "w lines need at least 1 parameters".to_owned(),
                            )));
                        }
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
                        if params.len() < 2 {
                            return Err(Error::Collector(ErrorKind::MalformedDesc(
                                "p lines need at least 2 parameters".to_owned(),
                            )));
                        }
                        let pol = match params[0] {
                            "accept" => Policy::Accept(params[1].to_owned()),
                            "reject" => Policy::Reject(params[1].to_owned()),
                            any => {
                                return Err(Error::Collector(ErrorKind::MalformedDesc(format!(
                                    "{} is not a valid netywork policy",
                                    any
                                ))));
                            }
                        };
                        Ok(builder.policies(pol))
                    }
                    // handle empty line
                    ("", _) => Ok(builder),
                    (any, _) => Err(Error::Collector(ErrorKind::MalformedDesc(format!(
                        "Lines starting with \"{}\" are not valid",
                        any
                    )))),
                }
            },
        )?;

        //build the last network status parsed
        network_status.push(builder.build()?);

        Ok(BridgeNetworkStatus {
            header,
            network_status,
        })
    }
}

fn parse_line(input: &str) -> Result<(&str, Vec<&str>), Error> {
    let t = input.split(' ').collect::<Vec<&str>>();
    if let Some(first) = t.first() {
        Ok((first, t[1..].to_vec()))
    } else {
        Err(Error::Collector(ErrorKind::MalformedDesc(format!(
            "Line \"{}\" malformed",
            input
        ))))
    }
}
