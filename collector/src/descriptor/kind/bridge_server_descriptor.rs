use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::{cmp::Ordering, net::Ipv6Addr};

use chrono::{DateTime, Utc};

use super::DescriptorLine;
use crate::error::{Error, ErrorKind};

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
    pub reject: Option<Vec<String>>,
    pub accept: Option<Vec<String>>,
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
                println!("{:?}", line);
                desc.entry(line.name).or_default().push(line);
                desc
            });
        let (i, _) = it.finish()?;
        t(eof(i))?;

        println!("{:?}", desc);

        println!("router");
        let (name, ipv4, or_port) = {
            let v = take_uniq(&mut desc, "router", 5)?;

            (
                v[0].to_owned(),
                v[1].parse().unwrap(),
                v[2].parse().unwrap(),
            )
        };

        println!("master-key-ed25519");
        let master_key = {
            let v = take_uniq(&mut desc, "master-key-ed25519", 1)?;
            v[0].to_owned()
        };

        println!("or-address");
        let (ipv6, or_port_v6) = {
            let v = take_opt(&mut desc, "or-address", 1)?;
            if let Some(t) = v.map(|x| x[0].split("]:").collect::<Vec<_>>()) {
                (
                    Some(t[0][1..].parse().unwrap()),
                    Some(t[1].parse().unwrap()),
                )
            } else {
                (None, None)
            }
        };

        println!("platform");
        let platform = {
            let v = take_uniq(&mut desc, "platform", 1)?;
            v.join(" ")
        };

        println!("proto");
        let proto = {
            let v = take_uniq(&mut desc, "proto", 12)?;
            let it = v.iter();
            let res: HashMap<String, String> = it.fold(HashMap::new(), |mut res, val| {
                let t = val.split("=").collect::<Vec<_>>();
                res.entry(t[0].to_owned()).or_insert(t[1].to_owned());
                res
            });
            res
        };

        println!("published");
        let timestamp = {
            let v = take_uniq(&mut desc, "published", 2)?;

            let date_str = format!("{} {}", v[0], v[1]);
            date(&date_str)?.1
        };

        println!("fingerprint");
        let fingerprint = {
            let v = take_uniq(&mut desc, "fingerprint", 10)?;
            v.join("")
        };

        println!("uptime");
        let uptime = {
            let v = take_uniq(&mut desc, "uptime", 1)?;
            v[0].parse()?
        };

        println!("bandwidth");
        let bandwidth = {
            let v = take_uniq(&mut desc, "bandwidth", 3)?;
            (
                v[0].parse().unwrap(),
                v[1].parse().unwrap(),
                v[2].parse().unwrap(),
            )
        };

        println!("extra-info-digest");
        let extra_info = {
            let v = take_uniq(&mut desc, "extra-info-digest", 1)?;
            v.join(" ")
        };

        println!("hidden-service-dir");
        let hidden_service = {
            if let Some(_) = take_opt(&mut desc, "hidden-service-dir", 0)? {
                true
            } else {
                false
            }
        };

        println!("contact");
        let contact = { take_opt(&mut desc, "contact", 1)?.map(|v| v.join(" ")) };

        println!("bridge-distribution-request");
        let distribution_request =
            if let Some(v) = take_opt(&mut desc, "bridge-distribution-request", 1)? {
                v[0]
            } else {
                "any"
            }
            .to_owned();

        println!("ntor-onion-key");
        let onion_key = {
            let v = take_uniq(&mut desc, "ntor-onion-key", 1)?;
            v[0].to_owned()
        };

        println!("reject");
        let reject = {
            if let Some(v) = take_multi_opt(&mut desc, "reject", 1)? {
                Some(v.iter().map(|&e| { e.to_owned()}).collect::<Vec<_>>())
            } else {
                None
            }
        };

        println!("accept");
        let accept = {
            if let Some(v) = take_multi_opt(&mut desc, "accept", 1)? {
                Some(v.iter().map(|&e| { e.to_owned()}).collect::<Vec<_>>())
            } else {
                None
            }
        };

        println!("tunnelled-dir-server");
        let tunnelled = {
            if let Some(_) = take_opt(&mut desc, "tunnelled-dir-server", 0)? {
                true
            } else {
                false
            }
        };

        println!("router-digest-sha256");
        let router_sha256 = {
            let v = take_uniq(&mut desc, "router-digest-sha256", 1)?;
            v[0].to_owned()
        };

        println!("router-digest");
        let router = {
            let v = take_uniq(&mut desc, "router-digest", 1)?;
            v[0].to_owned()
        };

        println!("end");
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
            reject,
            accept,
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
            reject: None,
            accept: None,
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

fn take_multi_opt<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &'a str,
    len: usize,
) -> Result<Option<Vec<&'a str>>, Error> {
    if let Some(v) = map.remove(key) {
        let desc = v.iter().fold(
            DescriptorLine {
                name: key,
                values: Vec::new(),
                cert: None,
            },
            |mut acc, line| {
                line.values.iter().for_each(|t| acc.values.push(t));
                acc
            },
        );
        let v = desc.values;
        if v.len() < len {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(Some(v))
    } else {
        Ok(None)
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
