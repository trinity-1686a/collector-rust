use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV6};
use std::{cmp::Ordering, net::Ipv6Addr};

use chrono::{DateTime, Utc};

use super::DescriptorLine;
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
                "bridge-pool-assignment v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let mut it = iterator(input, DescriptorLine::parse);
        let mut desc: HashMap<&str, Vec<DescriptorLine>> =
            it.fold(HashMap::new(), |mut desc, line| {
                match line.name {
                    "reject" | "accept" => desc.entry("accept reject").or_default().push(line),
                    _ => desc.entry(line.name).or_default().push(line),
                }
                desc
            });
        let (i, _) = it.finish()?;
        t(eof(i))?;

        let (name, ipv4, or_port) = {
            let v = take_uniq(&mut desc, "router", 5)?;

            (
                v[0].to_owned(),
                v[1].parse().unwrap(),
                v[2].parse().unwrap(),
            )
        };

        let master_key = {
            let v = take_uniq(&mut desc, "master-key-ed25519", 1)?;
            v[0].to_owned()
        };

        let (ipv6, or_port_v6) = {
            let v = take_opt(&mut desc, "or-address", 1)?;
            if let Some(t) = v.map(|x| x[0]) {
                let u = t.parse::<SocketAddrV6>()?;
                (
                    Some(u.ip().to_owned()),
                    Some(u.port()),
                )
            } else {
                (None, None)
            }
        };

        let platform = {
            let v = take_uniq(&mut desc, "platform", 1)?;
            v.join(" ")
        };

        let proto = {
            let v = take_uniq(&mut desc, "proto", 12)?;
            let it = v.iter();
            let res: HashMap<String, String> = it.fold(HashMap::new(), |mut res, val| {
                let t = val.split('=').collect::<Vec<_>>();
                res.entry(t[0].to_owned())
                    .or_insert_with(|| t[1].to_owned());
                res
            });
            res
        };

        let timestamp = {
            let v = take_uniq(&mut desc, "published", 2)?;

            let date_str = format!("{} {}", v[0], v[1]);
            date(&date_str)?.1
        };

        let fingerprint = {
            let v = take_uniq(&mut desc, "fingerprint", 10)?;
            v.join("")
        };

        let uptime = {
            let v = take_uniq(&mut desc, "uptime", 1)?;
            v[0].parse()?
        };

        let bandwidth = {
            let v = take_uniq(&mut desc, "bandwidth", 3)?;
            (
                v[0].parse().unwrap(),
                v[1].parse().unwrap(),
                v[2].parse().unwrap(),
            )
        };

        let extra_info = {
            let v = take_uniq(&mut desc, "extra-info-digest", 1)?;
            v.join(" ")
        };

        let hidden_service = matches!(take_opt(&mut desc, "hidden-service-dir", 0)?, Some(_));

        let contact = { take_opt(&mut desc, "contact", 1)?.map(|v| v.join(" ")) };

        let distribution_request =
            if let Some(v) = take_opt(&mut desc, "bridge-distribution-request", 1)? {
                v[0]
            } else {
                "any"
            }
            .to_owned();

        let onion_key = {
            let v = take_uniq(&mut desc, "ntor-onion-key", 1)?;
            v[0].to_owned()
        };

        let accept_reject = {
            let v = take_multi_descriptor_lines(&mut desc, "accept reject", 1)?;
            v.iter()
                .map(|e| match e.name {
                    "accept" => Network::Accept(e.values[0].to_owned()),
                    "reject" => Network::Reject(e.values[0].to_owned()),
                    _ => panic!("parsing went wrong"),
                })
                .collect()
        };

        let tunnelled = matches!(take_opt(&mut desc, "tunnelled-dir-server", 0)?, Some(_));

        let router_sha256 = {
            let v = take_uniq(&mut desc, "router-digest-sha256", 1)?;
            v[0].to_owned()
        };

        let router = {
            let v = take_uniq(&mut desc, "router-digest", 1)?;
            v[0].to_owned()
        };

        Ok(BridgeServerDescriptor {
            timestamp,
            name,
            ipv4,
            or_port,
            master_key,
            ipv6,
            or_port_v6,
            platform,
            proto,
            fingerprint,
            uptime,
            bandwidth,
            extra_info,
            hidden_service,
            contact,
            distribution_request,
            onion_key,
            accept_reject,
            tunnelled,
            router_sha256,
            router,
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

fn take_uniq<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &str,
    len: usize,
) -> Result<Vec<&'a str>, Error> {
    if let Some(mut v) = map.remove(key) {
        if v.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let v = v.pop().unwrap().values;
        if v.len() < len {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(v)
    } else {
        Err(ErrorKind::MalformedDesc.into())
    }
}

fn take_multi_descriptor_lines<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &str,
    len: usize,
) -> Result<Vec<DescriptorLine<'a>>, Error> {
    if let Some(v) = map.remove(key) {
        let format_ok = v.iter().fold(true, |acc, e| {
            if e.values.len() < len {
                false
            } else {
                acc
            }
        });
        if v.len() < len || !format_ok {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(v)
    } else {
        Err(ErrorKind::MalformedDesc.into())
    }
}

fn take_opt<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &str,
    len: usize,
) -> Result<Option<Vec<&'a str>>, Error> {
    if let Some(mut v) = map.remove(key) {
        if v.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let v = v.pop().unwrap().values;
        if v.len() < len {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(Some(v))
    } else {
        Ok(None)
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
