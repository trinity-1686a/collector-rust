use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};

use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq)]
pub struct BridgePoolAssignment {
    pub timestamp: DateTime<Utc>,
    pub data: BTreeMap<String, (String, HashMap<String, String>)>,
}

impl BridgePoolAssignment {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;

        if version.0 != 1 || version.1 != 0 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "bridge-pool-assignment v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }
        let (i, _) = t(tag("bridge-pool-assignment ")(input))?;
        let (i, timestamp) = date(i)?;
        let (i, _) = t(line_ending(i))?;

        let mut it = iterator(
            i,
            tuple((
                fingerprint,
                space1,
                take_till(|c| c == ' ' || c == '\n'),
                kv_space,
                line_ending,
            )),
        );

        let data = it.fold(BTreeMap::new(), |mut data, (fp, _, pool, kv, _)| {
            data.insert(fp.to_owned(), (pool.to_owned(), kv));
            data
        });

        let (i, _) = it.finish()?;

        t(eof(i))?;

        Ok(BridgePoolAssignment { timestamp, data })
    }
}

impl Ord for BridgePoolAssignment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

impl PartialOrd for BridgePoolAssignment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
