use std::{sync::OnceLock, time::Duration};

use bytes::Bytes;
use scion::{
    daemon::{get_daemon_address, DaemonClient},
    pan::{AsyncScionDatagram, PathAwareDatagram},
    udp_socket::UdpSocket,
};
use scion_proto::{address::SocketAddr, packet::ByEndpoint, path::Path};
use tokio::sync::Mutex;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static MESSAGE: Bytes = Bytes::from_static(b"Hello SCION!");
const TIMEOUT: Duration = std::time::Duration::from_secs(1);

macro_rules! test_send_receive_reply {
    ($name:ident, $source:expr, $destination:expr) => {
        mod $name {
            use super::*;

            // Prevent tests running simultaneously to avoid registration errors from the dispatcher
            fn lock() -> &'static Mutex<()> {
                static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
                LOCK.get_or_init(|| Mutex::default())
            }

            async fn get_sockets(
            ) -> TestResult<(PathAwareDatagram<UdpSocket, Path>, UdpSocket, Path)> {
                let endpoints: ByEndpoint<SocketAddr> = ByEndpoint {
                    source: $source.parse().unwrap(),
                    destination: $destination.parse().unwrap(),
                };
                let daemon_client_source = DaemonClient::connect(&get_daemon_address())
                    .await
                    .expect("should be able to connect");
                let socket_source = UdpSocket::bind(endpoints.source).await?;
                let socket_destination = UdpSocket::bind(endpoints.destination).await?;

                socket_source.connect(endpoints.destination);
                let path_forward = daemon_client_source
                    .paths_to(endpoints.destination.isd_asn())
                    .await?
                    .next()
                    .unwrap();
                println!("Forward path: {:?}", path_forward.dataplane_path);

                let socket_source =
                    PathAwareDatagram::new(socket_source, path_forward.clone().into());

                Ok((socket_source, socket_destination, path_forward))
            }

            #[tokio::test]
            #[ignore = "requires daemon and dispatcher"]
            async fn message() -> TestResult {
                let _lock = lock().lock().await;

                let (socket_source, socket_destination, _) = get_sockets().await?;
                socket_source.send(MESSAGE.clone()).await?;

                let mut buffer = vec![0_u8; 1500];
                let (length, sender) =
                    tokio::time::timeout(TIMEOUT, socket_destination.recv_from(&mut buffer))
                        .await??;
                assert_eq!(sender, socket_source.as_ref().local_addr());
                assert_eq!(buffer[..length], MESSAGE[..]);
                Ok(())
            }

            #[tokio::test]
            #[ignore = "requires daemon and dispatcher"]
            async fn message_and_response() -> TestResult {
                let _lock = lock().lock().await;

                let (socket_source, socket_destination, path_forward) = get_sockets().await?;
                socket_source.send(MESSAGE.clone()).await?;

                let mut buffer = vec![0_u8; 128];
                let mut path_buffer = vec![0_u8; 1024];
                let (length, sender, path) = tokio::time::timeout(
                    TIMEOUT,
                    socket_destination.recv_from_with_path(&mut buffer, &mut path_buffer),
                )
                .await??;
                assert_eq!(sender, socket_source.as_ref().local_addr());
                assert_eq!(buffer[..length], MESSAGE[..]);

                println!("Reply path: {:?}", path.dataplane_path);
                let path: Path = path.into();
                let socket_destination = PathAwareDatagram::new(socket_destination, path.into());

                socket_destination.send_to(MESSAGE.clone(), sender).await?;

                let (_, path_return) = tokio::time::timeout(
                    TIMEOUT,
                    socket_source.recv_with_path(&mut buffer, &mut path_buffer),
                )
                .await??;
                assert_eq!(path_return.isd_asn, path_forward.isd_asn);
                assert_eq!(path_return.dataplane_path, path_forward.dataplane_path);

                Ok(())
            }
        }
    };
}

test_send_receive_reply!(
    send_and_receive_up_and_down_segment,
    "[1-ff00:0:111,127.0.0.17]:12345",
    "[1-ff00:0:112,fd00:f00d:cafe::7f00:a]:443"
);

test_send_receive_reply!(
    send_and_receive_same_as,
    "[1-ff00:0:111,127.0.0.17]:12346",
    "[1-ff00:0:111,127.0.0.17]:8080"
);
