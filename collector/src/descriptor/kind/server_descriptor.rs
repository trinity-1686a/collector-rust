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
    pub distribution_request: String,
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

        let (name, ipv4, or_port) = {
            let v = take_uniq(&mut desc, "router", 5)?;

            (v[0].to_owned(), v[1].parse()?, v[2].parse()?)
        };

        let (ipv6, or_port_v6) = {
            let v = take_opt(&mut desc, "or-address", 1)?;
            if let Some(t) = v.map(|x| x[0]) {
                let u = t.parse::<SocketAddrV6>()?;
                (Some(u.ip().to_owned()), Some(u.port()))
            } else {
                (None, None)
            }
        };

        let platform = {
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

        let bandwidth = {
            let v = take_uniq(&mut desc, "bandwidth", 3)?;
            (v[0].parse()?, v[1].parse()?, v[2].parse()?)
        };

        let extra_info = {
            let v = take_uniq(&mut desc, "extra-info-digest", 1)?;
            v.join(" ")
        };

        let hidden_service = take_opt(&mut desc, "hidden-service-dir", 0)?.is_some();

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

        let tunnelled = take_opt(&mut desc, "tunnelled-dir-server", 0)?.is_some();

        Ok(ServerDescriptor {
            timestamp,
            name,
            ipv4,
            or_port,
            ipv6,
            or_port_v6,
            platform,
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
            distribution_request: String::new(),
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
