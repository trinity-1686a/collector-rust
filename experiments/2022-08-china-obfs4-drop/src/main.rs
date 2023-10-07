use std::collections::{BTreeMap, HashMap};

use chrono::{Date, DateTime, TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::Type;
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new(
        "/home/trinity/dev/tor/metrics/collector-processing/data",
        //    None,
    )
    .await
    .unwrap();
    let start_date = Utc.ymd(2023, 4, 20).and_hms(0, 0, 0);
    //let end_date = Utc.ymd(2023, 5, 1).and_hms(0, 0, 0);
    eprintln!("Starting download");
    let time_range = start_date..;
    collector
        .download_descriptors(
            &[Type::BridgeExtraInfo, Type::BridgePoolAssignment],
            time_range.clone(),
            None,
        )
        .await
        .unwrap();
    eprintln!("Download successfull, processing");

    let assigment = stable_bridge_assigment(&collector, time_range.clone()).await;

    let bridge_usage_china = bridge_usage_country(&collector, time_range.clone(), "ir").await;
    // let bridge_usage_china = bridge_usage_country(&collector, time_range.clone(), "cn").await;

    let distribution_usage_china: BTreeMap<Date<Utc>, HashMap<String, u64>> = bridge_usage_china
        .into_iter()
        .map(|(date, usage)| {
            let mut summed = HashMap::new();
            for (fp, usage) in usage {
                if let Some(distrib) = assigment.get(&fp.to_ascii_lowercase()) {
                    *summed.entry(distrib.clone()).or_default() += usage;
                }
            }
            (date, summed)
        })
        .collect();

    let distribs = ["email", "https", "moat", "reserved", "settings", "telegram"];

    print!("date");
    for distrib in distribs {
        print!(",{distrib}")
    }
    println!();

    for (date, vals) in distribution_usage_china {
        print!("{date}");
        for distrib in distribs {
            print!(",{}", vals.get(distrib).copied().unwrap_or_default());
        }
        println!();
    }
}

/// returns assignment for bridges where the assignment did not change over `date_range`
async fn stable_bridge_assigment<R: std::ops::RangeBounds<DateTime<Utc>> + 'static>(
    collector: &CollecTor,
    date_range: R,
) -> HashMap<String, String> {
    let res = collector
        .stream_descriptors(Type::BridgePoolAssignment, date_range)
        .map(|d| d.unwrap().bridge_pool_assignment().unwrap())
        .fold(
            HashMap::<String, Option<String>>::new(),
            |mut acc, bpa| async {
                for (fp, assign) in bpa.data {
                    acc.entry(fp)
                        .and_modify(|current_assign| match current_assign {
                            Some(ass) if *ass == assign.0 => (),
                            _ => *current_assign = None,
                        })
                        .or_insert_with(|| Some(assign.0.clone()));
                }
                acc
            },
        )
        .await;
    res.into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect()
}

/// returns count of users of a given country, per date and bridge
async fn bridge_usage_country<R: std::ops::RangeBounds<DateTime<Utc>> + 'static>(
    collector: &CollecTor,
    date_range: R,
    country_code: &str,
) -> BTreeMap<Date<Utc>, HashMap<String, u64>> {
    collector
        .stream_descriptors(Type::BridgeExtraInfo, date_range)
        .map(|d| d.unwrap().bridge_extra_info().unwrap())
        .map(|d| {
            let fp = d.fingerprint.clone();
            let time = d.timestamp.date();
            let usage = d
                .bridge_ips
                .unwrap_or_default()
                .get(country_code)
                .map(|c| c - 4)
                .unwrap_or_default();
            (time, fp, usage)
        })
        .fold(
            BTreeMap::<Date<Utc>, HashMap<String, u64>>::new(),
            |mut acc, (time, fp, usage)| async move {
                acc.entry(time)
                    .or_default()
                    .entry(fp)
                    .and_modify(|u| *u = (*u).max(usage))
                    .or_insert(usage);
                acc
            },
        )
        .await
}
