use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Duration, TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::{kind::*, Type};
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new("data").await.unwrap();
    let start_date = Utc.ymd(2022, 2, 1).and_hms(0, 0, 0);
    println!("Starting download");
    collector
        .download_descriptors(
            &[Type::BridgePoolAssignment, Type::BridgeServerDescriptor],
            start_date..,
            None,
        )
        .await
        .unwrap();
    println!("Download successfull, processing");

    let set: BTreeSet<_> =
        Box::pin(collector.stream_descriptors(Type::BridgePoolAssignment, start_date..))
            .map(|d| d.unwrap().bridge_pool_assignment().unwrap())
            .collect()
            .await;

    let changes = list_changes(set);
    println!("len={}", changes.len());

    let descriptors: HashMap<String, BTreeSet<_>> =
        Box::pin(collector.stream_descriptors(Type::BridgeServerDescriptor, start_date..))
            .map(|d| d.unwrap().bridge_server_descriptor().unwrap())
            .fold(
                HashMap::<String, BTreeSet<_>>::new(),
                |mut data, desc| async {
                    data.entry(desc.fingerprint.clone())
                        .or_default()
                        .insert(desc);
                    data
                },
            )
            .await;

    println!("finished building desc list");

    let mut filtered = Vec::new();
    for change in changes {
        if change.old_mechanism == "unallocated" {
            continue;
        }

        if change.after < Utc.ymd(2022, 5, 12).and_hms(17, 9, 0) {
            continue;
        }

        if change.after == Utc.ymd(2022, 2, 28).and_hms(11, 20, 18) {
            continue;
        }

        let descs = descriptors.get(&change.fingerprint).unwrap();
        let start = BridgeServerDescriptor::empty(change.before - Duration::days(2));
        let end = BridgeServerDescriptor::empty(change.after + Duration::days(1));
        if descs
            .range(start..end)
            .any(|d| d.distribution_request == change.new_mechanism)
        {
            continue;
        }

        let start = BridgeServerDescriptor::empty(change.before - Duration::days(5));
        let end = BridgeServerDescriptor::empty(change.after + Duration::days(2));
        let ips: Vec<_> = descs.range(start..=end).map(|desc| desc.ipv4).collect();
        if ips.len() < 3 {
            println!("wtf={}", change.fingerprint);
        }
        if !ips.windows(2).all(|w| w[0] == w[1]) {
            continue;
        }

        filtered.push(change);
    }

    for c in filtered {
        println!("{}", c);
    }
}

fn list_changes(descs: BTreeSet<BridgePoolAssignment>) -> Vec<Change> {
    let mut iter = descs.into_iter();
    let mut previous_desc = iter.next().unwrap();
    let mut res = Vec::new();
    for new_desc in iter {
        if new_desc.data.is_empty() {
            continue;
        }

        for (k, v1) in &previous_desc.data {
            if let Some(v2) = new_desc.data.get(k) {
                if v1.0 != v2.0 {
                    res.push(Change {
                        fingerprint: k.to_ascii_uppercase(),
                        before: previous_desc.timestamp,
                        after: new_desc.timestamp,
                        old_mechanism: v1.0.clone(),
                        new_mechanism: v2.0.clone(),
                    });
                }
            }
        }

        previous_desc = new_desc;
    }
    res
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Change {
    fingerprint: String,
    before: DateTime<Utc>,
    after: DateTime<Utc>,
    old_mechanism: String,
    new_mechanism: String,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{},{},{},{},{}",
            self.fingerprint, self.before, self.after, self.old_mechanism, self.new_mechanism
        )
    }
}
