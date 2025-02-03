//! Tests for the path strategy.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use scion::{
    daemon::{self, DaemonClient},
    pan::{
        path_strategy::{refresher::PathRefresher, AsyncPathStrategy},
        AsyncScionDatagram,
        PathAwareDatagram,
    },
    socket::UdpSocket,
};
use scion_proto::address::{IsdAsn, SocketAddr};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type PathService = AsyncPathStrategy<PathRefresher, DaemonClient>;

static MESSAGE: Bytes = Bytes::from_static(b"Hello SCION!");
const TIMEOUT: Duration = std::time::Duration::from_secs(1);

async fn get_path_strategy(destination: IsdAsn) -> PathService {
    let daemon_client = DaemonClient::connect(&daemon::get_daemon_address())
        .await
        .expect("should be able to connect");
    let strategy = PathRefresher::new(destination);

    AsyncPathStrategy::new(strategy, daemon_client)
}

async fn get_source_socket(
    source: SocketAddr,
    destination: IsdAsn,
) -> TestResult<PathAwareDatagram<UdpSocket, PathService>> {
    let strategy = get_path_strategy(destination).await;
    let socket = UdpSocket::bind(source).await?;

    Ok(PathAwareDatagram::new(socket, Arc::new(strategy)))
}

async fn test_sending_message_to_destination(src_address: &str, dst_address: &str) -> TestResult {
    let src_address: SocketAddr = src_address.parse()?;
    let dst_address: SocketAddr = dst_address.parse()?;

    let source = get_source_socket(src_address, dst_address.isd_asn()).await?;
    let destination = UdpSocket::bind(dst_address).await?;

    tokio::time::timeout(TIMEOUT, source.send_to(MESSAGE.clone(), dst_address)).await??;

    let mut buffer = vec![0_u8; 1500];
    let (length, sender) =
        tokio::time::timeout(TIMEOUT, destination.recv_from(&mut buffer)).await??;

    assert_eq!(sender, source.as_ref().local_addr());
    assert_eq!(buffer[..length], MESSAGE[..]);

    Ok(())
}

#[tokio::test]
#[ignore = "requires daemon and dispatcher"]
async fn sends_along_up_down_segment() -> TestResult {
    test_sending_message_to_destination(
        "[1-ff00:0:111,127.0.0.17]:12345",
        "[1-ff00:0:112,fd00:f00d:cafe::7f00:a]:443",
    )
    .await
}

#[tokio::test]
#[ignore = "requires daemon and dispatcher"]
async fn sends_same_as() -> TestResult {
    test_sending_message_to_destination(
        "[1-ff00:0:111,127.0.0.17]:12346",
        "[1-ff00:0:111,127.0.0.17]:8080",
    )
    .await
}
