use std::time::Duration;

use scion::{
    daemon::{get_daemon_address, DaemonClient},
    socket::RawSocket,
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

    let (raw_socket, _port) = RawSocket::bind(SocketAddr::new(endpoints.source, 0)).await?;
    let daemon_client = DaemonClient::connect(&get_daemon_address())
        .await
        .expect("should be able to connect");
    let path_forward = daemon_client
        .paths_to(endpoints.destination.isd_asn())
        .await?
        .next()
        .unwrap();
    println!("Forward path: {:?}", path_forward.dataplane_path);

    let request = ScionPacketScmp::new_traceroute_request(&endpoints, &path_forward, 1, 1, 3)?;
    raw_socket
        .send_packet_via(path_forward.underlay_next_hop, &request)
        .await?;

    let mut buffer = [0_u8; 1500];

    let (payload_length, _common_header, address_header) =
        tokio::time::timeout(TIMEOUT, raw_socket.recv_with_headers(&mut buffer)).await??;
    let scmp_message = ScmpMessage::decode(&mut buffer[..payload_length].as_ref())?;
    assert!(scmp_message.verify_checksum(&address_header));

    let ScmpMessage::TracerouteReply(reply) = scmp_message else {
        panic!("Unexpected SCMP reply received.")
    };

    assert_eq!(
        reply.get_message_id(),
        ScmpTracerouteRequest::try_from(request.message)?.get_message_id()
    );

    Ok(())
}
