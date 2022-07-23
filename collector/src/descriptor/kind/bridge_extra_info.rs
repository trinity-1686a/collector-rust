use std::{cmp::Ordering, collections::HashMap};

use chrono::{DateTime, Utc};

use super::utils::*;
use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct History {
    pub timestamp: DateTime<Utc>,
    pub duration: u64,
    pub data: Vec<u64>,
}

impl History {
    pub fn empty(timestamp: DateTime<Utc>) -> History {
        History {
            timestamp,
            duration: 0,
            data: Vec::new(),
        }
    }

    pub fn from_parsed_vec(data: &Vec<&str>) -> Result<History, Error> {
        use crate::descriptor::nom_combinators::date;

        if data.len() != 5 {
            return Err(ErrorKind::MalformedDesc.into());
        }

        let timestamp = {
            let date_str = format!("{} {}", data[0], data[1]);
            date(&date_str)?.1
        };

        let duration = data[2][1..].parse()?;

        let d = data[4]
            .split(',')
            .map(|x| x.parse())
            .collect::<Result<Vec<u64>, _>>();

        if d.is_err() {
            return Err(ErrorKind::MalformedDesc.into());
        }

        Ok(History {
            timestamp,
            duration,
            data: d.unwrap(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BridgeExtraInfo {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub fingerprint: String,
    pub master_key: String,
    pub transport: String,
    pub write_history: History,
    pub read_history: History,
    pub write_history_v6: History,
    pub read_history_v6: History,
    pub dirreq_write_history: History,
    pub dirreq_read_history: History,
    pub geoip: String,
    pub geoip6: String,
    pub dirreq_stats_end: (DateTime<Utc>, u64),
    pub dirreq_v3_ips: HashMap<String, u64>,
    pub dirreq_v3_reqs: HashMap<String, u64>,
    pub dirreq_v3_resp: HashMap<String, u64>,
    pub dirreq_v3_direct_dl: HashMap<String, u64>,
    pub dirreq_v3_tunneled_dl: HashMap<String, u64>,
    pub hidserv_stats_end: (DateTime<Utc>, u64),
    pub hidserv_rend_relayed_cells: (String, HashMap<String, String>),
    pub hidserv_dir_onions_seen: (String, HashMap<String, String>),
    pub hidserv_v3_stats_end: (DateTime<Utc>, u64),
    pub hidserv_rend_v3_relayed_cells: (String, HashMap<String, String>),
    pub hidserv_dir_v3_onions_seen: (String, HashMap<String, String>),
    pub padding_counts: (DateTime<Utc>, u64, HashMap<String, u64>),
    pub bridge_stats_end: (DateTime<Utc>, u64),
    pub bridge_ips: HashMap<String, u64>,
    pub bridge_ip_versions: HashMap<String, u64>,
    pub bridge_ip_transports: HashMap<String, u64>,
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

        let mut desc = descriptor_lines(input)?;

        let timestamp = {
            let v = take_uniq(&mut desc, "published", 2)?;

            let date_str = format!("{} {}", v[0], v[1]);
            date(&date_str)?.1
        };

        let (name, fingerprint) = {
            let v = take_uniq(&mut desc, "extra-info", 2)?;
            (v[0].to_owned(), v[1].to_owned())
        };

        let master_key = {
            let v = take_uniq(&mut desc, "master-key-ed25519", 1)?;
            v[0].to_owned()
        };

        let transport = {
            let v = take_uniq(&mut desc, "transport", 1)?;
            v[0].to_owned()
        };

        let write_history = {
            let v = take_uniq(&mut desc, "write-history", 5)?;
            History::from_parsed_vec(&v)?
        };

        let read_history = {
            let v = take_uniq(&mut desc, "read-history", 5)?;
            History::from_parsed_vec(&v)?
        };

        let write_history_v6 = {
            let v = take_uniq(&mut desc, "ipv6-write-history", 5)?;
            History::from_parsed_vec(&v)?
        };

        let read_history_v6 = {
            let v = take_uniq(&mut desc, "ipv6-read-history", 5)?;
            History::from_parsed_vec(&v)?
        };

        let dirreq_write_history = {
            let v = take_uniq(&mut desc, "dirreq-write-history", 5)?;
            History::from_parsed_vec(&v)?
        };

        let dirreq_read_history = {
            let v = take_uniq(&mut desc, "dirreq-read-history", 5)?;
            History::from_parsed_vec(&v)?
        };

        let geoip = {
            let v = take_uniq(&mut desc, "geoip-db-digest", 1)?;
            v[0].to_owned()
        };

        let geoip6 = {
            let v = take_uniq(&mut desc, "geoip6-db-digest", 1)?;
            v[0].to_owned()
        };

        let dirreq_stats_end = {
            let v = take_uniq(&mut desc, "dirreq-stats-end", 3)?;
            let date_str = format!("{} {}", v[0], v[1]);

            (date(&date_str)?.1, v[2][1..].parse()?)
        };

        let dirreq_v3_ips = {
            let v = take_uniq(&mut desc, "dirreq-v3-ips", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let dirreq_v3_reqs = {
            let v = take_uniq(&mut desc, "dirreq-v3-reqs", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let dirreq_v3_resp = {
            let v = take_uniq(&mut desc, "dirreq-v3-resp", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let dirreq_v3_direct_dl = {
            let v = take_uniq(&mut desc, "dirreq-v3-direct-dl", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let dirreq_v3_tunneled_dl = {
            let v = take_uniq(&mut desc, "dirreq-v3-tunneled-dl", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let hidserv_stats_end = {
            let v = take_uniq(&mut desc, "hidserv-stats-end", 3)?;
            let date_str = format!("{} {}", v[0], v[1]);

            (date(&date_str)?.1, v[2][1..].parse()?)
        };

        let hidserv_rend_relayed_cells = {
            let v = take_uniq(&mut desc, "hidserv-rend-relayed-cells", 2)?;
            (v[0].to_owned(), hashmap_from_kv_vec(v[1..].to_vec()))
        };

        let hidserv_dir_onions_seen = {
            let v = take_uniq(&mut desc, "hidserv-dir-onions-seen", 2)?;
            (v[0].to_owned(), hashmap_from_kv_vec(v[1..].to_vec()))
        };

        let hidserv_v3_stats_end = {
            let v = take_uniq(&mut desc, "hidserv-v3-stats-end", 3)?;
            let date_str = format!("{} {}", v[0], v[1]);

            (date(&date_str)?.1, v[2][1..].parse()?)
        };

        let hidserv_rend_v3_relayed_cells = {
            let v = take_uniq(&mut desc, "hidserv-rend-v3-relayed-cells", 2)?;
            (v[0].to_owned(), hashmap_from_kv_vec(v[1..].to_vec()))
        };

        let hidserv_dir_v3_onions_seen = {
            let v = take_uniq(&mut desc, "hidserv-dir-v3-onions-seen", 2)?;
            (v[0].to_owned(), hashmap_from_kv_vec(v[1..].to_vec()))
        };

        let padding_counts = {
            let v = take_uniq(&mut desc, "padding-counts", 5)?;
            let date_str = format!("{} {}", v[0], v[1]);

            (
                date(&date_str)?.1,
                v[2][1..].parse()?,
                create_kv_u64(v[4..].to_vec())?,
            )
        };

        let bridge_stats_end = {
            let v = take_uniq(&mut desc, "bridge-stats-end", 3)?;
            let date_str = format!("{} {}", v[0], v[1]);

            (date(&date_str)?.1, v[2][1..].parse()?)
        };

        let bridge_ips = {
            let v = take_uniq(&mut desc, "bridge-ips", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let bridge_ip_versions = {
            let v = take_uniq(&mut desc, "bridge-ip-versions", 1)?;
            create_kv_u64(v[0].split(',').collect())?
        };

        let bridge_ip_transports = {
            let v = take_uniq(&mut desc, "bridge-ip-transports", 1)?;
            create_kv_u64(v[0].split(',').collect())?
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
            name,
            fingerprint,
            master_key,
            transport,
            write_history,
            read_history,
            write_history_v6,
            read_history_v6,
            dirreq_write_history,
            dirreq_read_history,
            geoip,
            geoip6,
            dirreq_stats_end,
            dirreq_v3_ips,
            dirreq_v3_reqs,
            dirreq_v3_resp,
            dirreq_v3_direct_dl,
            dirreq_v3_tunneled_dl,
            hidserv_stats_end,
            hidserv_rend_relayed_cells,
            hidserv_dir_onions_seen,
            hidserv_v3_stats_end,
            hidserv_rend_v3_relayed_cells,
            hidserv_dir_v3_onions_seen,
            padding_counts,
            bridge_stats_end,
            bridge_ips,
            bridge_ip_versions,
            bridge_ip_transports,
            router_sha256,
            router,
        })
    }

    pub fn empty(timestamp: DateTime<Utc>) -> Self {
        BridgeExtraInfo {
            timestamp,
            name: String::new(),
            fingerprint: String::new(),
            master_key: String::new(),
            transport: String::new(),
            write_history: History::empty(timestamp),
            read_history: History::empty(timestamp),
            write_history_v6: History::empty(timestamp),
            read_history_v6: History::empty(timestamp),
            dirreq_write_history: History::empty(timestamp),
            dirreq_read_history: History::empty(timestamp),
            geoip: String::new(),
            geoip6: String::new(),
            dirreq_stats_end: (timestamp, 0),
            dirreq_v3_ips: HashMap::new(),
            dirreq_v3_reqs: HashMap::new(),
            dirreq_v3_resp: HashMap::new(),
            dirreq_v3_direct_dl: HashMap::new(),
            dirreq_v3_tunneled_dl: HashMap::new(),
            hidserv_stats_end: (timestamp, 0),
            hidserv_rend_relayed_cells: (String::new(), HashMap::new()),
            hidserv_dir_onions_seen: (String::new(), HashMap::new()),
            hidserv_v3_stats_end: (timestamp, 0),
            hidserv_rend_v3_relayed_cells: (String::new(), HashMap::new()),
            hidserv_dir_v3_onions_seen: (String::new(), HashMap::new()),
            padding_counts: (timestamp, 0, HashMap::new()),
            bridge_stats_end: (timestamp, 0),
            bridge_ips: HashMap::new(),
            bridge_ip_versions: HashMap::new(),
            bridge_ip_transports: HashMap::new(),
            router_sha256: String::new(),
            router: String::new(),
        }
    }
}

fn create_kv_u64(v: Vec<&str>) -> Result<HashMap<String, u64>, Error> {
    v.iter()
        .map(|val| -> Result<(String, u64), Error> {
            let (a, b) = val
                .split_once('=')
                .ok_or(ErrorKind::MalformedDesc)?;
            Ok((a.to_owned(), b.parse()?))
        })
        .collect()
}

impl Ord for BridgeExtraInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then(self.fingerprint.cmp(&other.fingerprint))
    }
}

impl PartialOrd for BridgeExtraInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
