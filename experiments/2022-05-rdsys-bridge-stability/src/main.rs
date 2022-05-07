use chrono::{TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::{kind::BridgePoolAssignment, DecodedDescriptor, Type};
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new("data").await.unwrap();
    let start_date = Utc.ymd(2022, 2, 20).and_hms(0, 0, 0);
    println!("Starting download");
    collector
        .download_descriptors(&Type::ALL_TYPES, .., None)
        .await
        .unwrap();
    println!("Download successfull, starting decompression");
    let mut descs =
        Box::pin(collector.stream_descriptors(Type::BridgePoolAssignment, start_date..));

    let mut previous_desc =
        unwrap_bridge_pool_assignment(descs.next().await.unwrap().unwrap().decode().await.unwrap());
    while let Some(desc) = descs.next().await {
        let desc = unwrap_bridge_pool_assignment(desc.unwrap().decode().await.unwrap());
        if delta_desc(&previous_desc, &desc) {
            previous_desc = desc;
        }
    }
}

fn unwrap_bridge_pool_assignment(desc: DecodedDescriptor) -> BridgePoolAssignment {
    match desc {
        DecodedDescriptor::BridgePoolAssignment(r) => r,
        _ => panic!(),
    }
}
fn delta_desc(old: &BridgePoolAssignment, new: &BridgePoolAssignment) -> bool {
    if new.data.len() < 10 {
        //println!("{} seems invalid", new.timestamp);
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
