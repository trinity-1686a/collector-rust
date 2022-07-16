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
    pub ipv6: Ipv6Addr,
    pub or_port_v6: u16,
    pub platform: String,
    pub fingerprint: String,
    pub uptime: u64,
    pub contact: Option<String>,
    pub distribution_request: String,
    // many fields are left unparsed
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
            let v = take_uniq(&mut desc, "or-address", 1)?;
            let t = v[0].split("]:").collect::<Vec<_>>();

            (t[0][1..].parse().unwrap(), t[1].parse().unwrap())
        };

        let platform= {
            let v = take_uniq(&mut desc, "platform", 1)?;
            v.join(" ")
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

        let contact = { take_opt(&mut desc, "contact", 1)?.map(|v| v.join(" ")) };

        let distribution_request =
            if let Some(v) = take_opt(&mut desc, "bridge-distribution-request", 1)? {
                v[0]
            } else {
                "any"
            }
            .to_owned();

        Ok(BridgeServerDescriptor {
            timestamp,
            name,
            ipv4,
            or_port,
            master_key,
            ipv6,
            or_port_v6,
            platform,
            fingerprint,
            uptime,
            contact,
            distribution_request,
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
            ipv6: Ipv6Addr::UNSPECIFIED,
            or_port_v6: 0,
            platform: String::new(),
            fingerprint: String::new(),
            uptime: 0,
            contact: None,
            distribution_request: String::new(),
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
