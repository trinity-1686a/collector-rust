use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::{kind::*, Descriptor, Type};
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new("data").await.unwrap();
    let start_date = Utc.ymd(2022, 1, 1).and_hms(0, 0, 0);
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
            .map(|d| unwrap_bridge_pool_assignment(d.unwrap()))
            .collect()
            .await;

    let mut iter = set.into_iter();
    let mut previous_desc = iter.next().unwrap();
    for desc in iter {
        if delta_desc(&previous_desc, &desc) {
            previous_desc = desc;
        }
    }

    let _: BTreeSet<_> =
        Box::pin(collector.stream_descriptors(Type::BridgeServerDescriptor, start_date..))
            .map(|d| unwrap_bridge_server_descriptor(d.unwrap()))
            .collect()
            .await;
}

fn unwrap_bridge_pool_assignment(desc: Descriptor) -> BridgePoolAssignment {
    match desc {
        Descriptor::BridgePoolAssignment(r) => r,
        _ => panic!(),
    }
}

fn unwrap_bridge_server_descriptor(desc: Descriptor) -> BridgeServerDescriptor {
    match desc {
        Descriptor::BridgeServerDescriptor(r) => r,
        _ => panic!(),
    }
}

fn delta_desc(old: &BridgePoolAssignment, new: &BridgePoolAssignment) -> bool {
    if new.data.len() < 10 {
        return false;
    }
    let mut count = 0;
    for (k, v1) in &old.data {
        if let Some(v2) = new.data.get(k) {
            if v1.0 != v2.0 {
                count += 1;
            }
        }
    }
    if count >= 5 {
        /*println!(
            "between {} and {}, {} bridges changed distribution method",
            old.timestamp, new.timestamp, count
        );*/

        for (k, v1) in &old.data {
            if let Some(v2) = new.data.get(k) {
                if v1.0 != v2.0 {
                    println!(
                        "{},{},{},{},{}",
                        old.timestamp, new.timestamp, k, v1.0, v2.0
                    );
                }
            }
        }
    }
    true
}
