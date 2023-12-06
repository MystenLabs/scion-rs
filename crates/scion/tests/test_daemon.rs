use std::{env, str::FromStr};

use scion::daemon::{get_daemon_address, DaemonClient};
use scion_proto::address::IsdAsn;

type TestError = Result<(), Box<dyn std::error::Error>>;

const DEFAULT_DESTINATION_ISD_ASN: &str = "1-ff00:0:112";

async fn daemon_client() -> DaemonClient {
    DaemonClient::connect(&get_daemon_address())
        .await
        .expect("should be able to connect")
}

#[tokio::test]
#[ignore = "requires running sciond"]
async fn daemon_request_sas_info() -> TestError {
    let client = daemon_client().await;
    client.local_sas_info().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires running sciond"]
async fn daemon_request_paths() -> TestError {
    let destination_isd_asn =
        env::var("DESTINATION_ISD_ASN").unwrap_or(DEFAULT_DESTINATION_ISD_ASN.into());
    let paths = daemon_client()
        .await
        .paths_to(IsdAsn::from_str(&destination_isd_asn).expect("correct ISD-ASN"))
        .await?;

    // This could be a bit brittle in case sciond doesn't actually have any paths.
    // However, in a local topology, this should not be an issue.
    assert!(paths.count() > 0);

    Ok(())
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
