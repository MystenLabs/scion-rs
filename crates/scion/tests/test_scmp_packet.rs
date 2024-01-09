use std::time::Duration;

use scion::{
    daemon::{get_daemon_address, DaemonClient},
    dispatcher::{get_dispatcher_path, DispatcherStream},
};
use scion_proto::{
    address::{ScionAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketScmp},
    scmp::{ScmpInformationalMessage, ScmpMessage, ScmpTracerouteRequest},
    wire_encoding::WireDecode,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const TIMEOUT: Duration = std::time::Duration::from_secs(1);

#[tokio::test]
#[ignore = "requires daemon and dispatcher"]
async fn scmp_traceroute() -> TestResult {
    let endpoints: ByEndpoint<ScionAddr> = ByEndpoint {
        source: "1-ff00:0:111,127.0.0.17".parse().unwrap(),
        destination: "1-ff00:0:112,::1".parse().unwrap(),
    };
    let daemon_client = DaemonClient::connect(&get_daemon_address())
        .await
        .expect("should be able to connect");
    let path_forward = daemon_client
        .paths_to(endpoints.destination.isd_asn())
        .await?
        .next()
        .unwrap();
    println!("Forward path: {:?}", path_forward.dataplane_path);

    let mut stream = DispatcherStream::connect(get_dispatcher_path()).await?;
    let _local_address = stream
        .register(SocketAddr::new(endpoints.source, 0))
        .await?;

    let request = ScionPacketScmp::new_traceroute_request(&endpoints, &path_forward, 1, 1, 3)?;

    stream
        .send_packet_via(path_forward.underlay_next_hop, request.clone())
        .await?;

    let mut packet = tokio::time::timeout(TIMEOUT, stream.receive_packet()).await??;
    let scion_packet_scmp = ScionPacketScmp::decode(&mut packet.content)?;
    let scmp_message = scion_packet_scmp.message;
    assert!(scmp_message.verify_checksum(&scion_packet_scmp.headers.address));

    let ScmpMessage::TracerouteReply(reply) = scmp_message else {
        panic!("Unexpected SCMP reply received.")
    };

    assert_eq!(
        reply.get_message_id(),
        ScmpTracerouteRequest::try_from(request.message)?.get_message_id()
    );

    Ok(())
}
