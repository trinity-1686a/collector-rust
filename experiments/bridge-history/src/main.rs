use std::collections::{BTreeMap, HashMap};

use chrono::{Date, DateTime, TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::Type;
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new(
        "/home/trinity/dev/tor/metrics/collector-processing/data",
    )
    .await
    .unwrap();

    let start_date = Utc.ymd(2021, 1, 1).and_hms(0, 0, 0);
    eprintln!("Starting download");
    collector
        .download_descriptors(
            &[Type::BridgePoolAssignment],
            start_date..,
            None,
        )
        .await
        .unwrap();
    eprintln!("Download successfull, processing");

    let res = collector
        .stream_descriptors(Type::BridgePoolAssignment, start_date..)
        .map(|d| d.unwrap().bridge_pool_assignment().unwrap())
        .for_each(|bpa|
                async move {
                    for (fp, (assign, _meta)) in bpa.data {
                        if fp == "4d6e3ca2110fc36d3106c86940a1d4c8c91923ab" {
                            println!("assign={assign}")
                        }
                    }
                }
        )
        .await;
}
