use bytes::Bytes;
use scion::{
    daemon::{get_daemon_address, DaemonClient},
    udp_socket::UdpSocket,
};
use scion_proto::{address::SocketAddr, packet::ByEndpoint};

type TestError = Result<(), Box<dyn std::error::Error>>;

static MESSAGE: Bytes = Bytes::from_static(b"Hello SCION!");

macro_rules! test_send_and_receive {
    ($name:ident, $source:expr, $destination:expr) => {
        #[tokio::test]
        #[ignore = "requires daemon and dispatcher"]
        async fn $name() -> TestError {
            let endpoints: ByEndpoint<SocketAddr> = ByEndpoint {
                source: $source.parse().unwrap(),
                destination: $destination.parse().unwrap(),
            };
            let daemon_client_source = DaemonClient::connect(&get_daemon_address())
                .await
                .expect("should be able to connect");
            let mut socket_source = UdpSocket::bind(endpoints.source).await?;
            let socket_destination = UdpSocket::bind(endpoints.destination).await?;

            socket_source.connect(endpoints.destination);
            socket_source.set_path(
                daemon_client_source
                    .paths_to(endpoints.destination.isd_asn())
                    .await?
                    .next()
                    .unwrap(),
            );
            socket_source.send(MESSAGE.clone()).await?;

            let mut buffer = [0_u8; 100];
            let (length, sender, _path) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                socket_destination.recv_from(&mut buffer),
            )
            .await??;
            assert_eq!(sender, endpoints.source);
            assert_eq!(buffer[..length], MESSAGE[..]);

            Ok(())
        }
    };
}

test_send_and_receive!(
    send_and_receive_up_and_down_segment,
    "[1-ff00:0:111,127.0.0.17]:12345",
    "[1-ff00:0:112,fd00:f00d:cafe::7f00:a]:443"
);

test_send_and_receive!(
    send_and_receive_same_as,
    "[1-ff00:0:111,127.0.0.17]:12346",
    "[1-ff00:0:111,127.0.0.17]:8080"
);
