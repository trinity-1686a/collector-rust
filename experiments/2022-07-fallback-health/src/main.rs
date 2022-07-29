use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{Date, DateTime, Datelike, TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::Type;
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new("/home/trinity/dev/tor/metrics/collector-processing/data")
        .await
        .unwrap();
    let start_date = Utc.ymd(2020, 1, 1).and_hms(0, 0, 0);
    println!("Starting download");
    collector
        .download_descriptors(&[Type::ServerDescriptor], start_date.., None)
        .await
        .unwrap();
    println!("Download successfull, processing");

    let fallbacks = fallbacks();

    let collector = Arc::new(collector);
    let mut start_date = start_date;
    let now = Utc::now();
    let mut handles = Vec::new();
    while start_date < now {
        let mut month = start_date.month() + 2;
        let mut year = start_date.year();
        if month > 12 {
            month -= 12;
            year += 1
        }
        let end_date = start_date
            .with_month(month)
            .unwrap()
            .with_year(year)
            .unwrap();
        handles.push(tokio::spawn(process_range(
            collector.clone(),
            fallbacks.clone(),
            start_date,
            end_date,
        )));
        start_date = end_date;
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn process_range(
    collector: Arc<CollecTor>,
    fallbacks: HashMap<String, Vec<SocketAddr>>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) {
    let res = Box::pin(collector.stream_descriptors(Type::ServerDescriptor, start..end))
        .filter_map(|d| futures::future::ready(d.ok().and_then(|d| d.server_descriptor().ok())))
        .filter(|d| futures::future::ready(fallbacks.contains_key(&d.fingerprint)))
        .fold(
            BTreeMap::<Date<Utc>, HashSet<String>>::new(),
            |mut acc, v| {
                futures::future::ready({
                    acc.entry(v.timestamp.date())
                        .or_default()
                        .insert(v.fingerprint);
                    acc
                })
            },
        )
        .await;

    for (k, v) in res {
        println!("{},{}", k, v.len());
    }
}

fn fallbacks() -> HashMap<String, Vec<SocketAddr>> {
    fn fallback(rsa: &str, _ed: &str, addr: &[&str]) -> (String, Vec<SocketAddr>) {
        (
            rsa.to_owned(),
            addr.iter().map(|a| a.parse().unwrap()).collect(),
        )
    }
    include!("fallback_dirs.inc").into_iter().collect()
}
