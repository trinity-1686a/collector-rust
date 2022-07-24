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

    pub fn from_parsed_vec(data: Vec<&str>) -> Result<History, Error> {
        use crate::descriptor::nom_combinators::date;

        if data.len() != 5 {
            return Err(ErrorKind::MalformedDesc("Line does not have 5 entries".to_owned()).into());
        }

        let timestamp = {
            let date_str = format!("{} {}", data[0], data[1]);
            date(&date_str)?.1
        };

        let duration = data[2]
            .get(1..)
            .ok_or_else(|| ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned()))?
            .parse()?;

        let data = data[4]
            .split(',')
            .map(|x| x.parse())
            .collect::<Result<Vec<u64>, _>>()?;

        Ok(History {
            timestamp,
            duration,
            data,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BridgeExtraInfo {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub fingerprint: String,
    pub master_key: Option<String>,
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
    pub router_digest: String,
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

        Ok(extract_desc! {
            desc => BridgeExtraInfo rest {
                uniq("extra-info") [name, fingerprint] => {
                    name: name.to_owned(),
                    fingerprint: fingerprint.to_owned(),
                },
                opt("master-key-ed25519") [key] => {
                    master_key: key.map(|k| k.to_owned()),
                },
                uniq("published") [day, hour] => {
                    timestamp: date(&format!("{} {}", day, hour))?.1,
                },
                uniq("transport") [t] => {
                    transport: t.to_owned(),
                },
                uniq("write-history") [] => {
                    write_history: History::from_parsed_vec(rest.to_vec())?,
                },
                uniq("read-history") [] => {
                    read_history: History::from_parsed_vec(rest.to_vec())?,
                },
                uniq("ipv6-write-history") [] => {
                    write_history_v6: History::from_parsed_vec(rest.to_vec())?,
                },
                uniq("ipv6-read-history") [] => {
                    read_history_v6: History::from_parsed_vec(rest.to_vec())?,
                },
                uniq("dirreq-write-history") [] => {
                    dirreq_write_history: History::from_parsed_vec(rest.to_vec())?,
                },
                uniq("dirreq-read-history") [] => {
                    dirreq_read_history: History::from_parsed_vec(rest.to_vec())?,
                },
                uniq("geoip-db-digest") [digest] => {
                    geoip: digest.to_owned(),
                },
                uniq("geoip6-db-digest") [digest] => {
                    geoip6: digest.to_owned(),
                },
                uniq("dirreq-stats-end") [day, hour, duration] => {
                    dirreq_stats_end: (
                        date(&format!("{} {}", day, hour))?.1,
                        duration
                            .get(1..)
                            .ok_or_else(|| ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned()))?
                            .parse()?,
                    ),
                },
                uniq("dirreq-v3-ips") [kv] => {
                    dirreq_v3_ips: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("dirreq-v3-reqs") [kv] => {
                    dirreq_v3_reqs: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("dirreq-v3-resp") [kv] => {
                    dirreq_v3_resp: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("dirreq-v3-direct-dl") [kv] => {
                    dirreq_v3_direct_dl: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("dirreq-v3-tunneled-dl") [kv] => {
                    dirreq_v3_tunneled_dl: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("hidserv-stats-end") [day, hour, duration] => {
                    hidserv_stats_end: (
                        date(&format!("{} {}", day, hour))?.1,
                        duration
                            .get(1..)
                            .ok_or_else(|| ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned()))?
                            .parse()?,
                    ),
                },
                uniq("hidserv-rend-relayed-cells") [val] => {
                    hidserv_rend_relayed_cells : (
                        val.to_owned(),
                        hashmap_from_kv_vec(rest.to_vec())?,
                    ),
                },
                uniq("hidserv-dir-onions-seen") [val] => {
                    hidserv_dir_onions_seen : (
                        val.to_owned(),
                        hashmap_from_kv_vec(rest.to_vec())?,
                    ),
                },
                uniq("hidserv-v3-stats-end") [day, hour, duration] => {
                    hidserv_v3_stats_end: (
                        date(&format!("{} {}", day, hour))?.1,
                        duration
                            .get(1..)
                            .ok_or_else(|| ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned()))?
                            .parse()?,
                    ),
                },
                uniq("hidserv-rend-v3-relayed-cells") [val] => {
                    hidserv_rend_v3_relayed_cells : (
                        val.to_owned(),
                        hashmap_from_kv_vec(rest.to_vec())?,
                    ),
                },
                uniq("hidserv-dir-v3-onions-seen") [val] => {
                    hidserv_dir_v3_onions_seen : (
                        val.to_owned(),
                        hashmap_from_kv_vec(rest.to_vec())?,
                    ),
                },
                uniq("padding-counts") [day, hour, duration, _unused] => {
                    padding_counts: (
                        date(&format!("{} {}", day, hour))?.1,
                        duration
                            .get(1..)
                            .ok_or_else(|| ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned()))?
                            .parse()?,
                        create_kv_u64(rest.to_vec())?,
                    ),
                },
                uniq("bridge-stats-end") [day, hour, duration] => {
                    bridge_stats_end: (
                        date(&format!("{} {}", day, hour))?.1,
                        duration
                            .get(1..)
                            .ok_or_else(|| ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned()))?
                            .parse()?,
                    ),
                },
                uniq("bridge-ips") [kv] => {
                    bridge_ips: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("bridge-ip-versions") [kv] => {
                    bridge_ip_versions: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("bridge-ip-transports") [kv] => {
                    bridge_ip_transports: create_kv_u64(kv.split(',').collect())?,
                },
                uniq("router-digest-sha256") [digest] => {
                    router_sha256: digest.to_owned(),
                },
                uniq("router-digest") [digest] => {
                    router_digest: digest.to_owned(),
                },

            }
        })
    }

    pub fn empty(timestamp: DateTime<Utc>) -> Self {
        BridgeExtraInfo {
            timestamp,
            name: String::new(),
            fingerprint: String::new(),
            master_key: None,
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
            router_digest: String::new(),
        }
    }
}

fn create_kv_u64(v: Vec<&str>) -> Result<HashMap<String, u64>, Error> {
    v.iter()
        .map(|val| -> Result<(String, u64), Error> {
            let (a, b) = val
                .split_once('=')
                .ok_or_else(|| ErrorKind::MalformedDesc("Key value malformed".to_owned()))?;
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
