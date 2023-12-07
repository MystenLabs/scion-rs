use std::{env, str::FromStr};

use scion::daemon::DaemonClient;
use scion_proto::address::IsdAsn;

const DEFAULT_DAEMON_ADDRESS: &str = "localhost:30255";
const DEFAULT_DESTINATION_ISD_ASN: &str = "1-ff00:0:112";

async fn daemon_client() -> DaemonClient {
    let mut address = env::var("DAEMON_ADDRESS").unwrap_or(DEFAULT_DAEMON_ADDRESS.into());
    if !address.contains("://") {
        address = format!("http://{}", address);
    }
    DaemonClient::connect(&address)
        .await
        .expect("should be able to connect")
}

#[tokio::test]
#[ignore = "requires running sciond"]
async fn daemon_request_sas_info() {
    let client = daemon_client().await;
    assert!(client.local_sas_info().await.is_ok())
}

#[tokio::test]
#[ignore = "requires running sciond"]
async fn daemon_request_paths() {
    let destination_isd_asn =
        env::var("DESTINATION_ISD_ASN").unwrap_or(DEFAULT_DESTINATION_ISD_ASN.into());
    let paths = daemon_client()
        .await
        .paths_to(IsdAsn::from_str(&destination_isd_asn).expect("correct ISD-ASN"))
        .await;

    assert!(paths.is_ok());
    // This could be a bit brittle in case sciond doesn't actually have any paths.
    // However, in a local topology, this should not be an issue.
    assert!(paths.unwrap().count() > 0);
}

#[tokio::test]
#[ignore = "requires running sciond"]
async fn daemon_request_paths_same_as() -> TestError {
    let destination_isd_asn = "1-ff00:0:111";
    let paths = daemon_client()
        .await
        .paths_to(IsdAsn::from_str(destination_isd_asn).expect("correct ISD-ASN"))
        .await?;

    // This could be a bit brittle in case sciond doesn't actually have any paths.
    // However, in a local topology, this should not be an issue.
    assert!(paths.count() > 0);

    Ok(())
}
