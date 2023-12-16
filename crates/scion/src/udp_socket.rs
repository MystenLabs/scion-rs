#![allow(missing_docs)]

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
    datagram::{UdpDatagram, UdpEncodeError},
    packet::{self, ByEndpoint, EncodeError, ScionPacketRaw, ScionPacketUdp},
    path::{DataplanePath, Path, UnsupportedPathType},
    reliable::Packet,
    wire_encoding::WireDecode,
};
use tokio::sync::Mutex;

use crate::dispatcher::{self, get_dispatcher_path, DispatcherStream, RegistrationError};

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("failed to connect to the dispatcher, reason: {0}")]
    DispatcherConnectFailed(#[from] io::Error),
    #[error("failed to bind to the requested port")]
    RegistrationFailed(#[from] RegistrationError),
}

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("packet is too large to be sent")]
    PacketTooLarge,
    #[error("path is expired")]
    PathExpired,
    #[error("remote address is not set")]
    NotConnected,
    #[error("path is not set")]
    NoPath,
    #[error("no underlay next hop provided by path")]
    NoUnderlayNextHop,
}

impl From<dispatcher::SendError> for SendError {
    fn from(value: dispatcher::SendError) -> Self {
        match value {
            dispatcher::SendError::Io(io) => Self::Io(io),
            dispatcher::SendError::PayloadTooLarge(_) => Self::PacketTooLarge,
        }
    }
}

impl From<UdpEncodeError> for SendError {
    fn from(value: UdpEncodeError) -> Self {
        match value {
            UdpEncodeError::PayloadTooLarge => Self::PacketTooLarge,
        }
    }
}

impl From<packet::EncodeError> for SendError {
    fn from(value: packet::EncodeError) -> Self {
        match value {
            EncodeError::PayloadTooLarge | EncodeError::HeaderTooLarge => Self::PacketTooLarge,
        }
    }
}

#[derive(Debug)]
pub struct UdpSocket {
    inner: Arc<UdpSocketInner>,
}

impl UdpSocket {
    pub async fn bind(address: SocketAddr) -> Result<Self, BindError> {
        Self::bind_with_dispatcher(address, get_dispatcher_path()).await
    }

    pub async fn bind_with_dispatcher<P: AsRef<std::path::Path> + std::fmt::Debug>(
        address: SocketAddr,
        dispatcher_path: P,
    ) -> Result<Self, BindError> {
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

    /// Receive a SCION UDP packet.
    ///
    /// The UDP payload is written into the provided buffer. If there is insufficient space, excess
    /// data is dropped. The returned number of bytes always refers to the amount of data in the UDP
    /// payload.
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<usize, ReceiveError> {
        let (packet_len, _) = self.recv_from(buffer).await?;
        Ok(packet_len)
    }

    /// Receive a SCION UDP packet from a remote endpoint.
    ///
    /// This behaves like [`Self::recv`] but additionally returns the remote SCION socket address.
    pub async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), ReceiveError> {
        self.inner
            .recv_loop(buffer, None)
            .await
            .map(|(len, addr, _)| (len, addr))
    }

    /// Receive a SCION UDP packet from a remote endpoint with path information.
    ///
    /// This behaves like [`Self::recv`] but additionally returns
    /// - the remote SCION socket address and
    /// - the path over which the packet was received. For supported path types, this path is
    ///   already reversed such that it can be used directly to send reply packets; for unsupported
    ///   path types, the path is copied unmodified.
    pub async fn recv_from_with_path(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, Path), ReceiveError> {
        if buffer.is_empty() {
            return Err(ReceiveError::ZeroLengthBuffer);
        }
        if buffer.len() < DataplanePath::<Bytes>::MAX_LEN {
            return Err(ReceiveError::PathBufferTooShort);
        }

        // TODO(jsmith): Refactor to accept two buffers and return a Path referring into one.
        let split_point = buffer.len() - DataplanePath::<Bytes>::MAX_LEN;
        let (buffer, path_buf) = buffer.split_at_mut(split_point);

        let (packet_len, sender, path) = self.inner.recv_loop(buffer, Some(path_buf)).await?;
        let Path {
            dataplane_path,
            underlay_next_hop,
            isd_asn,
            ..
        } = path.expect("non-None path since path_buf was provided");

        // Explicit match here in case we add other errors to the `reverse` method at some point
        let dataplane_path = match dataplane_path.to_reversed() {
            Ok(reversed_dataplane) => reversed_dataplane,
            Err(UnsupportedPathType(_)) => dataplane_path.into(),
        };

        Ok((
            packet_len,
            sender,
            Path::new(dataplane_path, isd_asn.into_reversed(), underlay_next_hop),
        ))
    }

    /// Receive a SCION UDP packet with path information.
    ///
    /// This behaves like [`Self::recv`] but additionally returns the path over which the packet was
    /// received. For supported path types, this path is already reversed such that it can be used
    /// directly to send reply packets; for unsupported path types, the path is copied unmodified.
    pub async fn recv_with_path(&self, buffer: &mut [u8]) -> Result<(usize, Path), ReceiveError> {
        let (packet_len, _, path) = self.recv_from_with_path(buffer).await?;
        Ok((packet_len, path))
    }

    /// Returns the remote SCION address set for this socket, if any.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }

    /// Returns the SCION path set for this socket, if any.
    pub fn path(&self) -> Option<Path> {
        self.inner.path()
    }

    /// Registers a remote address for this socket.
    pub fn connect(&self, remote_address: SocketAddr) {
        self.inner.set_remote_address(Some(remote_address));
    }

    /// Clears the association, if any, with the remote address.
    pub fn disconnect(&self) {
        self.inner.set_remote_address(None);
    }

    /// Registers or clears a path for this socket.
    pub fn set_path(&self, path: Option<Path>) -> &Self {
        self.inner.set_path(path);
        self
    }

    /// Sends the payload using the registered remote address and path
    ///
    /// Returns an error if the remote address or path are unset
    pub async fn send(&self, payload: Bytes) -> Result<(), SendError> {
        self.inner.send_to_via(payload, None, None).await
    }

    /// Sends the payload to the specified destination using the registered path
    ///
    /// Returns an error if the path is unset
    pub async fn send_to(&self, payload: Bytes, destination: SocketAddr) -> Result<(), SendError> {
        self.inner
            .send_to_via(payload, Some(destination), None)
            .await
    }

    /// Sends the payload to the registered destination using the specified path
    ///
    /// Returns an error if the remote address is unset
    pub async fn send_via(&self, payload: Bytes, path: &Path) -> Result<(), SendError> {
        self.inner.send_to_via(payload, None, Some(path)).await
    }

    /// Sends the payload to the specified remote address and path
    pub async fn send_to_via(
        &self,
        payload: Bytes,
        destination: SocketAddr,
        path: &Path,
    ) -> Result<(), SendError> {
        self.inner
            .send_to_via(payload, Some(destination), Some(path))
            .await
    }
}

/// Error messages returned from the UDP socket.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiveError {
    #[error("attempted to receive with a zero-length buffer")]
    ZeroLengthBuffer,
    #[error("path buffer too short")]
    PathBufferTooShort,
}

macro_rules! log_err {
    ($message:expr) => {
        |err| {
            tracing::debug!(?err, $message);
            err
        }
    };
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
                path: None,
            })),
            stream: Mutex::new(stream),
        }
    }

    async fn send_to_via(
        &self,
        payload: Bytes,
        destination: Option<SocketAddr>,
        path: Option<&Path>,
    ) -> Result<(), SendError> {
        let state = self.state.read().unwrap().clone();
        let path = path.or(state.path.as_ref()).ok_or(SendError::NoPath)?;
        let Some(destination) = destination.or(state.remote_address) else {
            return Err(SendError::NotConnected);
        };

        if let Some(metadata) = &path.metadata {
            if metadata.expiration < Utc::now() {
                return Err(SendError::PathExpired);
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
            return Err(SendError::NoUnderlayNextHop);
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
            .send_packet_via(relay, packet)
            .await?;
        Ok(())
    }

    async fn recv_loop<'p>(
        &self,
        buf: &mut [u8],
        path_buf: Option<&'p mut [u8]>,
    ) -> Result<(usize, SocketAddr, Option<Path<&'p mut [u8]>>), ReceiveError> {
        if buf.is_empty() {
            return Err(ReceiveError::ZeroLengthBuffer);
        }
        if let Some(path_buf) = path_buf.as_ref() {
            if path_buf.len() < DataplanePath::<Bytes>::MAX_LEN {
                return Err(ReceiveError::PathBufferTooShort);
            }
        }

        // Keep a copy of the connection's remote_addr locally, so that the user connecting to a
        // different destination does not affect what this call should return.
        let remote_addr = self.state.read().unwrap().remote_address;

        loop {
            // Keep the lock until we no longer have a dependency on the internal buffers.
            let mut stream = self.stream.lock().await;
            let receive_result = stream.receive_packet().await;

            match receive_result {
                Ok(packet) => {
                    if let Some((packet_len, sender, path)) =
                        self.parse_incoming_from(packet, buf, remote_addr)
                    {
                        if let Some(path_buf) = path_buf {
                            let path_len = path.dataplane_path.raw().len();
                            let dataplane_path =
                                path.dataplane_path.copy_to_slice(&mut path_buf[..path_len]);
                            let path =
                                Path::new(dataplane_path, path.isd_asn, path.underlay_next_hop);
                            return Ok((packet_len, sender, Some(path)));
                        } else {
                            return Ok((packet_len, sender, None));
                        }
                    } else {
                        continue;
                    }
                }
                Err(_) => todo!("attempt reconnections to dispatcher"),
            }
        }
    }

    /// Parse a datagram from the provided packet.
    ///
    /// # Panics
    ///
    /// Panics if path_buf, when not empty, does not have sufficient length for the SCION path.
    fn parse_incoming_from(
        &self,
        mut packet: Packet,
        buf: &mut [u8],
        remote_addr: Option<SocketAddr>,
    ) -> Option<(usize, SocketAddr, Path)> {
        // TODO(jsmith): Need a representation of the packets for logging purposes
        let mut scion_packet = ScionPacketRaw::decode(&mut packet.content)
            .map_err(log_err!("failed to decode SCION packet"))
            .ok()?;

        let udp_datagram = UdpDatagram::decode(&mut scion_packet.payload)
            .map_err(log_err!("failed to decode UDP datagram"))
            .ok()?;

        if !udp_datagram.verify_checksum(&scion_packet.headers.address) {
            tracing::debug!("failed to verify packet checksum");
            return None;
        }

        let source = if let Some(source_scion_addr) = scion_packet.headers.address.source() {
            SocketAddr::new(source_scion_addr, udp_datagram.port.source)
        } else {
            tracing::debug!("dropping packet with unsupported source address type");
            return None;
        };

        if let Some(remote_addr) = remote_addr {
            if remote_addr != source {
                tracing::debug!(%source, %remote_addr, "dropping packet not from connected remote");
                return None;
            }
        }

        let payload_len = udp_datagram.payload.len();
        let copy_length = cmp::min(payload_len, buf.len());
        buf[..copy_length].copy_from_slice(&udp_datagram.payload[..copy_length]);

        Some((
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

    pub fn path(&self) -> Option<Path> {
        self.state.read().unwrap().path.clone()
    }

    pub fn set_path(&self, path: Option<Path>) {
        Arc::make_mut(&mut *self.state.write().unwrap()).path = path;
    }
}

#[derive(Debug, Clone)]
struct State {
    local_address: SocketAddr,
    remote_address: Option<SocketAddr>,
    path: Option<Path>,
}

#[cfg(test)]
mod tests {
    use scion_proto::path::DataplanePath;
    use tokio::{net::UnixStream, sync::Notify};

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

            dispatcher.send_packet_via(Some(relay), packet).await?;

            Ok(())
        }
    }

    macro_rules! async_test_case {
        ($name:ident: $func:ident($arg1:expr$(, $arg:expr)*)) => {
            #[tokio::test]
            async fn $name() -> TestResult {
                $func($arg1 $(, $arg)*).await
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

            assert!(
                matches!(err, SendError::NotConnected),
                "expected {:?}, got {:?}",
                SendError::NotConnected,
                err
            );

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

        let mut buffer = vec![0u8; 1500];
        let (socket, mut dispatcher) = utils::socket_from(endpoints.source)?;
        utils::local_send_raw(&mut dispatcher, endpoints, MESSAGE).await?;

        let (length, incoming_remote_addr, incoming_path) = if use_from {
            socket.recv_from_with_path(&mut buffer).await?
        } else {
            let res = socket.recv_with_path(&mut buffer).await?;
            (res.0, endpoints.source, res.1)
        };

        assert_eq!(&buffer[..length], MESSAGE);
        assert_eq!(incoming_remote_addr, endpoints.source);
        assert_eq!(incoming_path.dataplane_path, DataplanePath::EmptyPath);
        assert_eq!(incoming_path.isd_asn, endpoints.map(SocketAddr::isd_asn));
        assert_eq!(incoming_path.metadata, None);
        assert_ne!(incoming_path.underlay_next_hop, None);

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

        let mut buffer = vec![0u8; 1500];
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

        let length = if use_from {
            let (length, remote_addr, _) = socket.recv_from_with_path(&mut buffer).await?;
            assert_eq!(remote_addr, endpoints.source);
            length
        } else {
            socket.recv_with_path(&mut buffer).await?.0
        };

        // The first packet received is the second packet written.
        assert_eq!(&buffer[..length], messages[1]);

        // Disconnect the association to receive packets with other addresses
        socket.disconnect();

        let length = if use_from {
            let (length, remote_addr, _) = socket.recv_from_with_path(&mut buffer).await?;
            assert_eq!(remote_addr, other_endpoints.source);
            length
        } else {
            socket.recv_with_path(&mut buffer).await?.0
        };

        // The second packet packet received is the third packet written.
        assert_eq!(&buffer[..length], messages[2]);

        Ok(())
    }

    mod recv_from_with_path {
        use super::*;

        pub const USE_FROM: bool = true;

        async_test_case! {
            connected:
                test_connected_recv(
                    "[1-f:0:3,4.4.0.1]:80", "[1-f:0:3,11.10.13.7]:443", "[1-f:0:3,10.20.30.40]:981", USE_FROM
                )
        }
        async_test_case! {
            unconnected: test_unconnected_recv("[1-f:0:3,4.4.0.1]:80", "[1-f:0:3,11.10.13.7]:443", USE_FROM)
        }

        #[tokio::test]
        async fn zero_length_buffer() -> TestResult {
            let endpoints = ByEndpoint::<SocketAddr> {
                source: "[1-f:0:3,4.4.0.1]:80".parse()?,
                destination: "[1-f:0:3,11.10.13.7]:443".parse()?,
            };
            assert_eq!(endpoints.source.isd_asn(), endpoints.destination.isd_asn());

            let mut buffer = vec![0u8; 1500];
            let (socket, mut dispatcher) = utils::socket_from(endpoints.source)?;
            utils::local_send_raw(&mut dispatcher, endpoints, MESSAGE).await?;

            let err = socket
                .recv_from_with_path(&mut [])
                .await
                .expect_err("should fail due to zero-length buffer");
            assert_eq!(err, ReceiveError::ZeroLengthBuffer);

            // The data should still be available to read
            let (length, incoming_remote_addr, _) = socket.recv_from_with_path(&mut buffer).await?;

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
                    "[1-f:0:3,4.4.0.1]:80", "[1-f:0:3,11.10.13.7]:443", "[1-f:0:3,10.20.30.40]:981", !USE_FROM
                )
        }
        async_test_case! {
            unconnected: test_unconnected_recv("[1-f:0:3,3.3.3.3]:80", "[1-f:0:3,9.9.9.81]:443", !USE_FROM)
        }
    }

    #[tokio::test]
    async fn set_path() -> TestResult {
        let local_addr: SocketAddr = "[1-f:0:1,9.8.7.6]:80".parse()?;
        let (socket, _) = utils::socket_from(local_addr)?;
        let path = Path::local(local_addr.isd_asn());

        let notify = Arc::new(Notify::new());
        let notify2 = Arc::new(Notify::new());

        let (result1, result2) = tokio::join!(
            async {
                let initial = socket.path();
                socket.set_path(Some(path.clone()));
                notify.notify_one();

                notify2.notified().await;
                let last_set = socket.path();

                (initial, last_set)
            },
            async {
                notify.notified().await;
                let first_set = socket.path();
                socket.set_path(None);
                notify2.notify_one();

                first_set
            }
        );

        assert_eq!(result1, (None, None));
        assert_eq!(result2, Some(path));

        Ok(())
    }
}
