use std::collections::HashMap;
use std::cmp::Ordering;

use chrono::{DateTime, Utc};

use super::utils::*;
use super::DescriptorLine;
use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeExtraInfo {
    pub timestamp: DateTime<Utc>,
    pub router_sha256: String,
    pub router: String,
}

impl BridgeExtraInfo {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;

        if version.0 != 1 || version.1 > 3 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "bridge-pool-assignment v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let mut it = iterator(input, DescriptorLine::parse);
        let mut desc: HashMap<&str, Vec<DescriptorLine>> =
            it.fold(HashMap::new(), |mut desc, line| {
                desc.entry(line.name).or_default().push(line);
                desc
            });
        let (i, _) = it.finish()?;
        t(eof(i))?;

        let timestamp = {
            let v = take_uniq(&mut desc, "published", 2)?;

            let date_str = format!("{} {}", v[0], v[1]);
            date(&date_str)?.1
        };

        let router_sha256 = {
            let v = take_uniq(&mut desc, "router-digest-sha256", 1)?;
            v[0].to_owned()
        };

        let router = {
            let v = take_uniq(&mut desc, "router-digest", 1)?;
            v[0].to_owned()
        };

        Ok(BridgeExtraInfo {
            timestamp,
            router_sha256,
            router,
        })
    }

    pub fn empty(timestamp: DateTime<Utc>) -> Self {
        BridgeExtraInfo {
            timestamp,
            router_sha256: String::new(),
            router: String::new(),
        }
    }
}

impl Ord for BridgeExtraInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            //.then(self.fingerprint.cmp(&other.fingerprint))
    }
}

impl PartialOrd for BridgeExtraInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}