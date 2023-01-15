use chrono::{DateTime, Utc};
use itertools::Itertools;

use super::utils::*;
use crate::error::{Error, ErrorKind};

#[derive(Debug)]
pub struct Header {
    pub timestamp: DateTime<Utc>,
    pub duration: u64,
    pub cached_requests: u64,
}

impl Header {
    pub fn parse(input: &str) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;
        let mut desc = descriptor_lines(input)?;
        Ok(extract_desc! {
            desc => Header rest {
                uniq("bridgestrap-stats-end") [day, hour, value, _unit] => {
                    timestamp: date(&format!("{} {}", day, hour))?.1,
                    duration: value[1..].parse()?,
                },
                uniq("bridgestrap-cached-requests") [num] => {
                    cached_requests: num.parse()?,
                },
            }
        })
    }
}

#[derive(Debug)]
pub struct Stats {
    pub is_reachable: bool,
    pub fingerprint: String,
}

#[derive(Debug)]
pub struct BridgestrapStats {
    pub header: Header,
    pub stats: Vec<Stats>,
}

impl BridgestrapStats {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        if version.0 != 1 || version.1 > 0 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "bridgestrap-stats v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let header = Header::parse(&format!("{}\n", input.lines().take(2).join("\n")))?;

        let stats = input
            .lines()
            .skip(2)
            .map(|line| {
                let split = line.split(' ').collect::<Vec<_>>();
                if split.len() < 3 {
                    Err(Error::Collector(ErrorKind::MalformedDesc(format!(
                        "Line \"{}\" is malformed",
                        line
                    ))))
                } else {
                    Ok(Stats {
                        is_reachable: split[1].parse()?,
                        fingerprint: split[2].to_string(),
                    })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(BridgestrapStats { header, stats })
    }
}
