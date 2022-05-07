use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};

use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeServerDescriptor {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub or_port: u16,
    pub fingerprint: String,
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
        let mut it = iterator(input, tuple((sp_separated, line_ending)));
        let desc: HashMap<&str, Vec<Vec<&str>>> =
            it.fold(HashMap::new(), |mut desc, ((key, val), _)| {
                // TODO this is slighlty incorrect: a single key can have multiple lines
                desc.entry(key).or_default().push(val);
                desc
            });
        let (i, _) = it.finish()?;
        t(eof(i))?;

        let (name, ipv4, or_port) = {
            let v = get_uniq(&desc, "router", 5)?;

            (
                v[0].to_owned(),
                v[1].parse().unwrap(),
                v[2].parse().unwrap(),
            )
        };

        let timestamp = {
            let v = get_uniq(&desc, "published", 2)?;

            let date_str = format!("{} {}", v[0], v[1]);
            date(&date_str)?.1
        };

        let fingerprint = {
            let v = get_uniq(&desc, "fingerprint", 10)?;
            v.join("")
        };

        let distribution_request =
            if let Some(v) = get_opt(&desc, "bridge-distribution-request", 1)? {
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
            fingerprint,
            distribution_request,
        })
    }
}

fn get_uniq<'a>(
    map: &'a HashMap<&str, Vec<Vec<&str>>>,
    key: &str,
    len: usize,
) -> Result<&'a [&'a str], Error> {
    if let Some(v) = map.get(key) {
        if v.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let v = &v[0];
        if v.len() < len {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(v)
    } else {
        Err(ErrorKind::MalformedDesc.into())
    }
}

fn get_opt<'a>(
    map: &'a HashMap<&str, Vec<Vec<&str>>>,
    key: &str,
    len: usize,
) -> Result<Option<&'a [&'a str]>, Error> {
    if let Some(v) = map.get(key) {
        if v.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let v = &v[0];
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
        self.fingerprint
            .cmp(&other.fingerprint)
            .then(self.timestamp.cmp(&other.timestamp))
    }
}

impl PartialOrd for BridgeServerDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
