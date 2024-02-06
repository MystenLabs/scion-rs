//! A socket to send UDP datagrams via SCION.

use std::{
    cmp,
    io,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use chrono::Utc;
use scion_proto::{
    address::SocketAddr,
    datagram::UdpMessage,
    packet::{ByEndpoint, MessageChecksum, ScionPacketRaw, ScionPacketUdp},
    path::{DataplanePath, Path},
    reliable::Packet,
    scmp::{ScmpDecodeError, ScmpErrorMessage, SCMP_PROTOCOL_NUMBER},
    wire_encoding::WireDecode,
};
use tokio::sync::Mutex;

use super::{error::log_err, utils::check_buffers, BindError};
use crate::{
    dispatcher::{self, get_dispatcher_path, DispatcherStream},
    pan::{AsyncScionDatagram, PathErrorKind, ReceiveError, SendError},
};

/// A SCION UDP socket.
///
/// After creating a `UdpSocket` by binding it to a SCION socket address, data can
/// be [sent to][AsyncScionDatagram::send_to_via] and [received from][AsyncScionDatagram::recv_from]
/// any other socket address by using the methods on the [`AsyncScionDatagram`] trait.
///
/// As SCION is a path-aware Internet architecture, sending packets with the `UdpSocket` allows
/// specifying the path over which the packet should be sent. See
/// [`PathAwareDatagram`][crate::pan::PathAwareDatagram] for a wrapping socket than handles
/// the selection of paths.
///
/// Although UDP is a connectionless protocol, this implementation provides an interface to set an
/// address where data should be sent and received from. After setting a remote address with
/// [`connect`][UdpSocket::connect], data can be sent to and received from that address with the
/// [`send_via`][AsyncScionDatagram::send_via] and [`recv`][AsyncScionDatagram::recv] methods.
#[derive(Debug)]
pub struct UdpSocket {
    inner: Arc<UdpSocketInner>,
}

impl UdpSocket {
    /// Creates a new UDP socket bound to the provided SCION socket address.
    ///
    /// When specifying a port `0` in the `address`, the port is assigned automatically by the
    /// dispatcher. In this case, the assigned port can be obtained by calling
    /// [`local_port()`][Self::local_port] on the returned object.
    pub async fn bind(address: SocketAddr) -> Result<Self, BindError> {
        Self::bind_with_dispatcher(address, get_dispatcher_path()).await
    }

    /// Creates a new UDP socket from the given SCION socket address, by connecting to
    /// and registering with the SCION dispatcher at the specified path.
    ///
    /// See [`bind`][Self::bind] for a variant that connects to the system's configured
    /// SCION dispatcher.
    pub async fn bind_with_dispatcher<P>(
        address: SocketAddr,
        dispatcher_path: P,
    ) -> Result<Self, BindError>
    where
        P: AsRef<std::path::Path> + std::fmt::Debug,
    {
        let mut stream = DispatcherStream::connect(dispatcher_path).await?;
        let local_address = stream.register(address).await?;

        Ok(Self::new(stream, local_address))
    }

    fn new(stream: DispatcherStream, local_addr: SocketAddr) -> Self {
        Self {
            inner: Arc::new(UdpSocketInner::new(stream, local_addr)),
        }
    }

    /// Returns the local SCION address to which this socket is bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    /// Returns the port number to which this socket is bound.
    pub fn local_port(&self) -> u16 {
        self.local_addr().port()
    }

    /// Registers a remote address for this socket.
    pub fn connect(&self, remote_address: SocketAddr) {
        self.inner.set_remote_address(Some(remote_address));
    }

    /// Clears the association, if any, with the remote address.
    pub fn disconnect(&self) {
        self.inner.set_remote_address(None);
    }
}

#[async_trait::async_trait]
impl AsyncScionDatagram for UdpSocket {
    /// The type of the address used for sending and receiving datagrams.
    type Addr = SocketAddr;

    async fn recv_from_with_path<'p>(
        &self,
        buffer: &mut [u8],
        path_buffer: &'p mut [u8],
    ) -> Result<(usize, Self::Addr, Path<&'p mut [u8]>), ReceiveError> {
        if buffer.is_empty() {
            return Err(ReceiveError::ZeroLengthBuffer);
        }
        if path_buffer.len() < DataplanePath::<Bytes>::MAX_LEN {
            return Err(ReceiveError::PathBufferTooShort);
        }

        let (len, sender, Some(path)) = self.inner.recv_loop(buffer, Some(path_buffer)).await?
        else {
            unreachable!("path is always returned when providing a buffer")
        };
        Ok((len, sender, path))
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Self::Addr), ReceiveError> {
        self.inner
            .recv_loop(buffer, None)
            .await
            .map(|(len, addr, _)| (len, addr))
    }

    async fn send_to_via(
        &self,
        payload: Bytes,
        destination: Self::Addr,
        path: &Path,
    ) -> Result<(), SendError> {
        self.inner
            .send_to_via(payload, Some(destination), path)
            .await
    }

    async fn send_via(&self, payload: Bytes, path: &Path) -> Result<(), SendError> {
        self.inner.send_to_via(payload, None, path).await
    }

    /// Returns the remote address of the socket, if any.
    fn remote_addr(&self) -> Option<Self::Addr> {
        self.inner.remote_addr()
    }
}

/// Error messages used in private functions in [`UdpSocketInner`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum InternalReceiveError {
    /// An error occurred while parsing an incoming packet or some check failed.
    #[error("an invalid packet was received")]
    InvalidPacket,
    /// An SCMP error message was received.
    #[error("an SCMP error message was received: {0}")]
    ScmpError(ScmpErrorMessage),
}

#[derive(Debug)]
struct UdpSocketInner {
    stream: Mutex<DispatcherStream>,
    state: RwLock<Arc<State>>,
}

impl UdpSocketInner {
    fn new(stream: DispatcherStream, local_address: SocketAddr) -> Self {
        Self {
            state: RwLock::new(Arc::new(State {
                local_address,
                remote_address: None,
            })),
            stream: Mutex::new(stream),
        }
    }

    async fn send_to_via(
        &self,
        payload: Bytes,
        destination: Option<SocketAddr>,
        path: &Path,
    ) -> Result<(), SendError> {
        let state = self.state.read().unwrap().clone();
        let Some(destination) = destination.or(state.remote_address) else {
            return Err(io::ErrorKind::NotConnected.into());
        };

        if let Some(metadata) = &path.metadata {
            if metadata.expiration < Utc::now() {
                return Err(PathErrorKind::Expired.into());
            }
        }

        let relay = if path.underlay_next_hop.is_some() {
            path.underlay_next_hop
        } else if state.local_address.isd_asn() == destination.isd_asn() {
            destination.local_address().map(|mut socket_addr| {
                socket_addr.set_port(dispatcher::UNDERLAY_PORT);
                socket_addr
            })
        } else {
            return Err(PathErrorKind::NoUnderlayNextHop.into());
        };

        let packet = ScionPacketUdp::new(
            &ByEndpoint {
                destination,
                source: state.local_address,
            },
            path,
            payload,
        )?;

        self.stream
            .lock()
            .await
            .send_packet_via(relay, &packet)
            .await?;
        Ok(())
    }

    async fn recv_loop<'p>(
        &self,
        buf: &mut [u8],
        path_buf: Option<&'p mut [u8]>,
    ) -> Result<(usize, SocketAddr, Option<Path<&'p mut [u8]>>), ReceiveError> {
        check_buffers(buf, &path_buf)?;

        // Keep a copy of the connection's remote_addr locally, so that the user connecting to a
        // different destination does not affect what this call should return.
        let remote_addr = self.state.read().unwrap().remote_address;

        loop {
            // Keep the lock until we no longer have a dependency on the internal buffers.
            let mut stream = self.stream.lock().await;
            let receive_result = stream.receive_packet().await;

            return match receive_result {
                Ok(packet) => match self.parse_incoming_from(packet, buf, remote_addr) {
                    Ok((packet_len, sender, path)) => Ok((
                        packet_len,
                        sender,
                        path_buf.map(|b| path.reverse_to_slice(b)),
                    )),
                    Err(InternalReceiveError::ScmpError(s)) => Err(ReceiveError::ScmpError(s)),
                    _ => continue,
                },
                Err(_) => todo!("attempt reconnections to dispatcher"),
            };
        }
    }

    /// Parse a datagram from the provided packet and copy the payload to `buf`.
    ///
    /// # Errors
    ///
    /// - If an SCMP error message is received instead of a UDP datagram, returns an
    ///   [`InternalReceiveError::ScmpError`].
    /// - If the packet cannot be parsed as either a UDP datagram or an SCMP error message,
    ///   returns a [`InternalReceiveError::InvalidPacket`].
    fn parse_incoming_from(
        &self,
        mut packet: Packet,
        buf: &mut [u8],
        remote_addr: Option<SocketAddr>,
    ) -> Result<(usize, SocketAddr, Path), InternalReceiveError> {
        // TODO(jsmith): Need a representation of the packets for logging purposes
        let mut scion_packet = ScionPacketRaw::decode(&mut packet.content).map_err(log_err!(
            "failed to decode SCION packet",
            InternalReceiveError::InvalidPacket
        ))?;

        if scion_packet.headers.common.next_header == SCMP_PROTOCOL_NUMBER {
            return Err(match ScmpErrorMessage::decode(&mut scion_packet.payload) {
                Ok(e) => InternalReceiveError::ScmpError(e),
                Err(ScmpDecodeError::MessageTypeMismatch) => {
                    tracing::debug!("received unexpected SCMP informational message");
                    InternalReceiveError::InvalidPacket
                }
                Err(_) => {
                    tracing::debug!("received SCMP message but failed to decode");
                    InternalReceiveError::InvalidPacket
                }
            });
        }

        let udp_datagram = UdpMessage::decode(&mut scion_packet.payload).map_err(log_err!(
            "failed to decode UDP datagram",
            InternalReceiveError::InvalidPacket
        ))?;

        if !udp_datagram.verify_checksum(&scion_packet.headers.address) {
            tracing::debug!("failed to verify packet checksum");
            return Err(InternalReceiveError::InvalidPacket);
        }

        let source = if let Some(source_scion_addr) = scion_packet.headers.address.source() {
            SocketAddr::new(source_scion_addr, udp_datagram.port.source)
        } else {
            tracing::debug!("dropping packet with unsupported source address type");
            return Err(InternalReceiveError::InvalidPacket);
        };

        if let Some(remote_addr) = remote_addr {
            if remote_addr != source {
                tracing::debug!(%source, %remote_addr, "dropping packet not from connected remote");
                return Err(InternalReceiveError::InvalidPacket);
            }
        }

        let payload_len = udp_datagram.payload.len();
        let copy_length = cmp::min(payload_len, buf.len());
        buf[..copy_length].copy_from_slice(&udp_datagram.payload[..copy_length]);

        Ok((
            payload_len,
            source,
            Path::new(
                scion_packet.headers.path,
                scion_packet.headers.address.ia,
                packet.last_host,
            ),
        ))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.state.read().unwrap().local_address
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.state.read().unwrap().remote_address
    }

    pub fn set_remote_address(&self, remote_address: Option<SocketAddr>) {
        Arc::make_mut(&mut *self.state.write().unwrap()).remote_address = remote_address;
    }
}

#[derive(Debug, Clone)]
struct State {
    local_address: SocketAddr,
    remote_address: Option<SocketAddr>,
}

#[cfg(test)]
mod tests {
    use scion_proto::path::DataplanePath;
    use tokio::net::UnixStream;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    mod utils {

        use super::*;

        pub fn socket_from(source: SocketAddr) -> TestResult<(UdpSocket, DispatcherStream)> {
            let (inner, inner_remote) = UnixStream::pair()?;
            Ok((
                UdpSocket::new(DispatcherStream::new(inner), source),
                DispatcherStream::new(inner_remote),
            ))
        }

        pub async fn read_udp_packet(
            dispatcher: &mut DispatcherStream,
        ) -> TestResult<ScionPacketUdp> {
            let mut packet = dispatcher.receive_packet().await?;
            let packet_raw = ScionPacketRaw::decode(&mut packet.content)?;
            let packet_udp = ScionPacketUdp::try_from(packet_raw)?;

            Ok(packet_udp)
        }

        pub async fn local_send_raw(
            dispatcher: &mut DispatcherStream,
            endpoints: ByEndpoint<SocketAddr>,
            message: &[u8],
        ) -> TestResult<()> {
            debug_assert!(
                endpoints.map(SocketAddr::isd_asn).are_equal(),
                "expected intra-AS addresses"
            );

            let relay = endpoints
                .destination
                .local_address()
                .map(|mut socket_addr| {
                    socket_addr.set_port(dispatcher::UNDERLAY_PORT);
                    socket_addr
                })
                .expect("IPv4/6 local address");

            let packet = ScionPacketUdp::new(
                &endpoints,
                &Path::local(endpoints.source.isd_asn()),
                Bytes::copy_from_slice(message),
            )?;

            dispatcher.send_packet_via(Some(relay), &packet).await?;

            Ok(())
        }

        pub async fn recv_from_helper<'p>(
            socket: &UdpSocket,
            buffer: &mut [u8],
            path_buffer: &'p mut [u8],
            use_from: bool,
        ) -> Result<(usize, Option<SocketAddr>, Path<&'p mut [u8]>), ReceiveError> {
            if use_from {
                let (len, remote_addr, path) =
                    socket.recv_from_with_path(buffer, path_buffer).await?;
                Ok((len, Some(remote_addr), path))
            } else {
                let (len, path) = socket.recv_with_path(buffer, path_buffer).await?;
                Ok((len, None, path))
            }
        }
    }

    macro_rules! async_test_case {
        ($name:ident: $func:ident($($arg:expr),*)) => {
            #[tokio::test]
            async fn $name() -> TestResult {
                $func($($arg,)*).await
            }
        };
    }

    const MESSAGE: &[u8] = b"Hello World! Hello World! Hello World!";

    mod send_to_via {
        use super::*;

        async fn test_send_to_via(
            local_addr: &str,
            remote_addr: &str,
            connect_addr: Option<&str>,
        ) -> TestResult {
            let local_addr = local_addr.parse()?;
            let remote_addr = remote_addr.parse()?;

            let (socket, mut dispatcher) = utils::socket_from(local_addr)?;
            let path = Path::local(local_addr.isd_asn());

            if let Some(connect_addr) = connect_addr {
                socket.connect(connect_addr.parse()?);
            }

            socket
                .send_to_via(Bytes::from_static(MESSAGE), remote_addr, &path)
                .await?;

            let udp_packet = utils::read_udp_packet(&mut dispatcher).await?;
            assert_eq!(udp_packet.source(), Some(local_addr));
            assert_eq!(udp_packet.destination(), Some(remote_addr));
            assert_eq!(udp_packet.payload().as_ref(), MESSAGE);

            Ok(())
        }

        async_test_case! {
            unconnected: test_send_to_via(
                "[1-ff00:0:111,10.0.0.1]:22472", "[1-ff00:0:111,10.0.0.2]:443", None
            )
        }

        async_test_case! {
            connected: test_send_to_via(
                "[1-ff00:0:111,10.0.0.1]:22472",
                "[1-ff00:0:111,10.32.32.32]:443",
                Some("[1-ff00:0:111,10.64.64.64]:1024")
            )
        }

        const REMOTE_ADDR: &str = "[1-ff00:0:111,10.32.32.32]:443";
        async_test_case! {
            connected_same_destination:
                test_send_to_via("[1-ff00:0:111,10.0.0.1]:22472", REMOTE_ADDR, Some(REMOTE_ADDR))
        }
    }

    mod send_via {
        use super::*;

        #[tokio::test]
        async fn errs_when_unconnected() -> TestResult {
            let local_addr = "[1-ff00:0:112,10.0.255.20]:2121".parse()?;
            let (socket, _) = utils::socket_from(local_addr)?;
            let path = Path::local(local_addr.isd_asn());

            let err = socket
                .send_via(Bytes::from_static(MESSAGE), &path)
                .await
                .expect_err("should fail on unconnected socket");

            if let SendError::Io(io_err) = err {
                assert_eq!(io_err.kind(), io::ErrorKind::NotConnected);
            } else {
                panic!("expected Io(ErrorKind::NotConnected), got {}", err);
            }

            Ok(())
        }

        #[tokio::test]
        async fn connected() -> TestResult {
            let local_addr = "[1-ff00:0:112,10.0.255.20]:2020".parse()?;
            let remote_addr = "[1-ff00:0:112,192.168.0.99]:9981".parse()?;
            let (socket, mut dispatcher) = utils::socket_from(local_addr)?;
            let path = Path::local(local_addr.isd_asn());

            socket.connect(remote_addr);
            socket.send_via(Bytes::from(MESSAGE), &path).await?;

            let udp_packet = utils::read_udp_packet(&mut dispatcher).await?;

            assert_eq!(udp_packet.source(), Some(local_addr));
            assert_eq!(udp_packet.destination(), Some(remote_addr));
            assert_eq!(udp_packet.payload().as_ref(), MESSAGE);

            Ok(())
        }
    }

    async fn test_unconnected_recv(
        local_addr: &str,
        remote_addr: &str,
        use_from: bool,
    ) -> TestResult {
        let endpoints = ByEndpoint::<SocketAddr> {
            source: remote_addr.parse()?,
            destination: local_addr.parse()?,
        };
        assert_eq!(endpoints.source.isd_asn(), endpoints.destination.isd_asn());

        let mut buffer = vec![0u8; 64];
        let mut path_buffer = vec![0u8; 1024];
        let (socket, mut dispatcher) = utils::socket_from(endpoints.source)?;
        utils::local_send_raw(&mut dispatcher, endpoints, MESSAGE).await?;

        let (length, incoming_remote_addr, incoming_path) =
            utils::recv_from_helper(&socket, &mut buffer, &mut path_buffer, use_from).await?;

        assert_eq!(&buffer[..length], MESSAGE);
        assert_eq!(
            incoming_path.dataplane_path,
            DataplanePath::<Bytes>::EmptyPath
        );
        assert_eq!(incoming_path.isd_asn, endpoints.map(SocketAddr::isd_asn));
        assert_eq!(incoming_path.metadata, None);
        assert_ne!(incoming_path.underlay_next_hop, None);
        if let Some(incoming_remote_addr) = incoming_remote_addr {
            assert_eq!(incoming_remote_addr, endpoints.source);
        }

        Ok(())
    }

    async fn test_connected_recv(
        local_addr: &str,
        remote_addr: &str,
        other_remote_addr: &str,
        use_from: bool,
    ) -> TestResult {
        let endpoints = ByEndpoint::<SocketAddr> {
            source: remote_addr.parse()?,
            destination: local_addr.parse()?,
        };
        assert_eq!(endpoints.source.isd_asn(), endpoints.destination.isd_asn());

        let messages = [
            b"Message 1!".as_slice(),
            b"Message 2! Message 2!",
            b"Message 3! Message 3! Message 3!",
        ];
        let other_endpoints = ByEndpoint {
            source: other_remote_addr.parse()?,
            ..endpoints
        };
        assert_eq!(other_endpoints.source.isd_asn(), endpoints.source.isd_asn());

        let mut buffer = vec![0u8; 64];
        let mut path_buffer = vec![0u8; 1024];
        let (socket, mut dispatcher) = utils::socket_from(endpoints.source)?;

        // Write packets to be received
        for (send_endpoints, message) in [
            (other_endpoints, messages[0]),
            (endpoints, messages[1]),
            (other_endpoints, messages[2]),
        ] {
            utils::local_send_raw(&mut dispatcher, send_endpoints, message).await?;
        }

        // Connect to the remote source
        socket.connect(endpoints.source);

        let (length, remote_addr, _) =
            utils::recv_from_helper(&socket, &mut buffer, &mut path_buffer, use_from).await?;

        // The first packet received is the second packet written.
        assert_eq!(&buffer[..length], messages[1]);
        if let Some(remote_addr) = remote_addr {
            assert_eq!(remote_addr, endpoints.source);
        }

        // Disconnect the association to receive packets with other addresses
        socket.disconnect();

        let (length, remote_addr, _) =
            utils::recv_from_helper(&socket, &mut buffer, &mut path_buffer, use_from).await?;

        // The second packet packet received is the third packet written.
        assert_eq!(&buffer[..length], messages[2]);
        if let Some(remote_addr) = remote_addr {
            assert_eq!(remote_addr, other_endpoints.source);
        }

        Ok(())
    }

    mod recv_from_with_path {
        use super::*;

        pub const USE_FROM: bool = true;

        async_test_case! {
            connected: test_connected_recv(
                "[1-f:0:3,4.4.0.1]:80",
                "[1-f:0:3,11.10.13.7]:443",
                "[1-f:0:3,10.20.30.40]:981",
                USE_FROM
            )
        }
        async_test_case! {
            unconnected:
                test_unconnected_recv("[1-f:0:3,4.4.0.1]:80", "[1-f:0:3,11.10.13.7]:443", USE_FROM)
        }

        #[tokio::test]
        async fn zero_length_buffer() -> TestResult {
            let endpoints = ByEndpoint::<SocketAddr> {
                source: "[1-f:0:3,4.4.0.1]:80".parse()?,
                destination: "[1-f:0:3,11.10.13.7]:443".parse()?,
            };
            assert_eq!(endpoints.source.isd_asn(), endpoints.destination.isd_asn());

            let mut buffer = vec![0u8; 64];
            let mut path_buffer = vec![0u8; 1024];

            let (socket, mut dispatcher) = utils::socket_from(endpoints.source)?;
            utils::local_send_raw(&mut dispatcher, endpoints, MESSAGE).await?;

            let err = socket
                .recv_from_with_path(&mut [], &mut path_buffer)
                .await
                .expect_err("should fail due to zero-length buffer");
            assert_eq!(err, ReceiveError::ZeroLengthBuffer);

            // The data should still be available to read
            let (length, incoming_remote_addr, _) = socket
                .recv_from_with_path(&mut buffer, &mut path_buffer)
                .await?;

            assert_eq!(&buffer[..length], MESSAGE);
            assert_eq!(incoming_remote_addr, endpoints.source);

            Ok(())
        }
    }

    mod recv_with_path {
        use super::*;

        pub const USE_FROM: bool = true;

        async_test_case! {
            connected:
                test_connected_recv(
                    "[1-f:0:3,4.4.0.1]:80",
                    "[1-f:0:3,11.10.13.7]:443",
                    "[1-f:0:3,10.20.30.40]:981",
                    !USE_FROM
                )
        }
        async_test_case! {
            unconnected:
                test_unconnected_recv("[1-f:0:3,3.3.3.3]:80", "[1-f:0:3,9.9.9.81]:443", !USE_FROM)
        }
    }
}
