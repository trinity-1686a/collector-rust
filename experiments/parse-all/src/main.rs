use std::sync::Arc;

use chrono::{Datelike, TimeZone, Utc};
use futures::stream::StreamExt;

use collector::descriptor::Type;
use collector::CollecTor;

#[tokio::main]
async fn main() {
    let collector = CollecTor::new("/home/trinity/dev/tor/metrics/collector-processing/data")
        .await
        .unwrap();
    println!("Starting download");

    let supported = [Type::BridgeServerDescriptor];
    let supported = [
        Type::BridgeServerDescriptor,
        Type::BridgePoolAssignment,
        Type::ServerDescriptor,
        Type::BridgeNetworkStatus,
    ];
    let supported = [Type::BridgeNetworkStatus];
    collector
        .download_descriptors(
            //&supported,
            &Type::ALL_TYPES,
            Utc.ymd(2023, 6, 1).and_hms(0, 0, 0)..,
            None,
        )
        .await
        .unwrap();
    println!("Download successfull, processing");
    return;

    let collector = Arc::new(collector);

    for typ in supported {
        println!("Decoding {:?}", typ);
        process_type(collector.clone(), typ).await;
    }
}

async fn process_type(collector: Arc<CollecTor>, typ: Type) {
    let mut start_date = Utc.ymd(2020, 9, 1).and_hms(0, 0, 0);
    let now = Utc.ymd(2020, 11, 1).and_hms(0, 0, 0);
    //let now = Utc::now();
    let mut handles = Vec::new();

    while start_date < now {
        let mut month = start_date.month() + 6;
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
        let collector = collector.clone();
        let typ = typ.clone();
        handles.push(tokio::spawn(Box::pin(async move {
            collector
                .stream_descriptors(typ, start_date..end_date)
                .for_each(|d| {
                    futures::future::ready(if let Err(e) = d {
                        println!("error: {:?}", e);
                    })
                })
                .await
        })));
        start_date = end_date;
    }

    for handle in handles {
        let _ = handle.await;
    }
}
