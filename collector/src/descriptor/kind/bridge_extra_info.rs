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

    fn from_optional_vec(data: Option<&[&str]>) -> Result<Option<History>, Error> {
        data.map(|d| History::from_parsed_vec(d.to_vec()))
            .transpose()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BridgeExtraInfo {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub fingerprint: String,
    pub master_key: Option<String>,
    pub transport: Vec<String>,
    pub write_history: Option<History>,
    pub read_history: Option<History>,
    pub write_history_v6: Option<History>,
    pub read_history_v6: Option<History>,
    pub dirreq_write_history: Option<History>,
    pub dirreq_read_history: Option<History>,
    pub geoip: Option<String>,
    pub geoip6: Option<String>,
    pub dirreq_stats_end: Option<(DateTime<Utc>, u64)>,
    pub dirreq_v3_ips: Option<HashMap<String, u64>>,
    pub dirreq_v3_reqs: Option<HashMap<String, u64>>,
    pub dirreq_v3_resp: Option<HashMap<String, u64>>,
    pub dirreq_v3_direct_dl: Option<HashMap<String, u64>>,
    pub dirreq_v3_tunneled_dl: Option<HashMap<String, u64>>,
    pub hidserv_stats_end: Option<(DateTime<Utc>, u64)>,
    pub hidserv_rend_relayed_cells: Option<(String, HashMap<String, String>)>,
    pub hidserv_dir_onions_seen: Option<(String, HashMap<String, String>)>,
    pub hidserv_v3_stats_end: Option<(DateTime<Utc>, u64)>,
    pub hidserv_rend_v3_relayed_cells: Option<(String, HashMap<String, String>)>,
    pub hidserv_dir_v3_onions_seen: Option<(String, HashMap<String, String>)>,
    pub padding_counts: Option<(DateTime<Utc>, u64, HashMap<String, u64>)>,
    pub bridge_stats_end: Option<(DateTime<Utc>, u64)>,
    pub bridge_ips: Option<HashMap<String, u64>>,
    pub bridge_ip_versions: Option<HashMap<String, u64>>,
    pub bridge_ip_transports: Option<HashMap<String, u64>>,
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
                multi("transport") [] => {
                    // TODO this is less than ideal; multi should support [xx, yy] params
                    transport:
                        rest.iter()
                            .map(|e| {
                                Ok(e.values.first()
                                    .ok_or_else(||
                                        ErrorKind::MalformedDesc(
                                            "missing parameters to accept".to_owned()
                                        ))?
                                    .to_string())
                            })
                           .collect::<Result<Vec<_>, Error>>()?,
                },
                opt("write-history") [] => {
                    write_history: History::from_optional_vec(rest)?,
                },
                opt("read-history") [] => {
                    read_history: History::from_optional_vec(rest)?,
                },
                opt("ipv6-write-history") [] => {
                    write_history_v6: History::from_optional_vec(rest)?,
                },
                opt("ipv6-read-history") [] => {
                    read_history_v6: History::from_optional_vec(rest)?,
                },
                opt("dirreq-write-history") [] => {
                    dirreq_write_history: History::from_optional_vec(rest)?,
                },
                opt("dirreq-read-history") [] => {
                    dirreq_read_history: History::from_optional_vec(rest)?,
                },
                opt("geoip-db-digest") [digest] => {
                    geoip: digest.map(|digest| digest.to_owned()),
                },
                opt("geoip6-db-digest") [digest] => {
                    geoip6: digest.map(|digest| digest.to_owned()),
                },
                opt("dirreq-stats-end") [day, hour, duration] => {
                    dirreq_stats_end: parse_end(day, hour, duration)?,

                },
                opt("dirreq-v3-ips") [kv] => {
                    dirreq_v3_ips: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("dirreq-v3-reqs") [kv] => {
                    dirreq_v3_reqs: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("dirreq-v3-resp") [kv] => {
                    dirreq_v3_resp: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("dirreq-v3-direct-dl") [kv] => {
                    dirreq_v3_direct_dl: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("dirreq-v3-tunneled-dl") [kv] => {
                    dirreq_v3_tunneled_dl: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("hidserv-stats-end") [day, hour, duration] => {
                    hidserv_stats_end: parse_end(day, hour, duration)?,
                },
                opt("hidserv-rend-relayed-cells") [val] => {
                    hidserv_rend_relayed_cells:
                        val.zip(rest).map(|(val, rest)| -> Result<_, Error> {Ok((
                            val.to_owned(),
                            hashmap_from_kv_vec(rest.to_vec())?,
                        ))}).transpose()?,
                },
                opt("hidserv-dir-onions-seen") [val] => {
                    hidserv_dir_onions_seen:
                        val.zip(rest).map(|(val, rest)| -> Result<_, Error> {Ok((
                            val.to_owned(),
                            hashmap_from_kv_vec(rest.to_vec())?,
                        ))}).transpose()?,
                },
                opt("hidserv-v3-stats-end") [day, hour, duration] => {
                    hidserv_v3_stats_end: parse_end(day, hour, duration)?,
                },
                opt("hidserv-rend-v3-relayed-cells") [val] => {
                    hidserv_rend_v3_relayed_cells:
                        val.zip(rest).map(|(val, rest)| -> Result<_, Error> {Ok((
                            val.to_owned(),
                            hashmap_from_kv_vec(rest.to_vec())?,
                        ))}).transpose()?,
                },
                opt("hidserv-dir-v3-onions-seen") [val] => {
                    hidserv_dir_v3_onions_seen:
                        val.zip(rest).map(|(val, rest)| -> Result<_, Error> {Ok((
                            val.to_owned(),
                            hashmap_from_kv_vec(rest.to_vec())?,
                        ))}).transpose()?,
                },
                opt("padding-counts") [day, hour, duration, _unused] => {
                    padding_counts:
                        if let Some((date, duration)) = parse_end(day, hour, duration)? {
                            Some((date, duration, create_kv_u64(rest.unwrap_or_default().to_vec())?))
                        } else {
                            None
                        },
                },
                opt("bridge-stats-end") [day, hour, duration] => {
                    bridge_stats_end: parse_end(day, hour, duration)?,
                },
                opt("bridge-ips") [kv] => {
                    bridge_ips: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("bridge-ip-versions") [kv] => {
                    bridge_ip_versions: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
                },
                opt("bridge-ip-transports") [kv] => {
                    bridge_ip_transports: kv.map(|kv| create_kv_u64(kv.split(',').collect())).transpose()?,
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
            transport: Vec::new(),
            write_history: None,
            read_history: None,
            write_history_v6: None,
            read_history_v6: None,
            dirreq_write_history: None,
            dirreq_read_history: None,
            geoip: None,
            geoip6: None,
            dirreq_stats_end: None,
            dirreq_v3_ips: None,
            dirreq_v3_reqs: None,
            dirreq_v3_resp: None,
            dirreq_v3_direct_dl: None,
            dirreq_v3_tunneled_dl: None,
            hidserv_stats_end: None,
            hidserv_rend_relayed_cells: None,
            hidserv_dir_onions_seen: None,
            hidserv_v3_stats_end: None,
            hidserv_rend_v3_relayed_cells: None,
            hidserv_dir_v3_onions_seen: None,
            padding_counts: None,
            bridge_stats_end: None,
            bridge_ips: None,
            bridge_ip_versions: None,
            bridge_ip_transports: None,
            router_sha256: String::new(),
            router_digest: String::new(),
        }
    }
}

fn create_kv_u64(v: Vec<&str>) -> Result<HashMap<String, u64>, Error> {
    v.iter()
        .filter(|val| !val.is_empty())
        .map(|val| -> Result<(String, u64), Error> {
            let (a, b) = val
                .split_once('=')
                .ok_or_else(|| ErrorKind::MalformedDesc("Key value malformed".to_owned()))?;
            Ok((a.to_owned(), b.parse()?))
        })
        .collect()
}

fn parse_end(
    day: Option<&str>,
    hour: Option<&str>,
    duration: Option<&str>,
) -> Result<Option<(DateTime<Utc>, u64)>, Error> {
    use crate::descriptor::nom_combinators::date;

    day.zip(hour)
        .zip(duration)
        .map(|((day, hour), duration)| -> Result<_, Error> {
            Ok((
                date(&format!("{} {}", day, hour))?.1,
                duration
                    .get(1..)
                    .ok_or_else(|| {
                        ErrorKind::MalformedDesc("Wrong pattern for the duration".to_owned())
                    })?
                    .parse()?,
            ))
        })
        .transpose()
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
