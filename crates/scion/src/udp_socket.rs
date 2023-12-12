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
    path::{Path, UnsupportedPathType},
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
    #[error("socket is already connected")]
    AlreadyConnected,
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
        let (packet_len, _) = self.inner.recv_from(buffer).await?;
        Ok(packet_len)
    }

    /// Receive a SCION UDP packet from a remote endpoint.
    ///
    /// This behaves like [`Self::recv`] but additionally returns the remote SCION socket address.
    pub async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), ReceiveError> {
        self.inner.recv_from(buffer).await
    }

    /// Receive a SCION UDP packet from a remote endpoint with path information.
    ///
    /// This behaves like [`Self::recv`] but additionally returns
    /// - the remote SCION socket address and
    /// - the path over which the packet was received. For supported path types, this path is
    ///   already reversed such that it can be used directly to send reply packets; for unsupported
    ///   path types, the path is copied unmodified.
    ///
    /// Note that copying/reversing the path requires allocating memory; if you do not need the path
    /// information, consider using the method [`Self::recv_from`] instead.
    pub async fn recv_from_with_path(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, Path), ReceiveError> {
        self.inner.recv_from_with_path(buffer).await
    }

    /// Receive a SCION UDP packet with path information.
    ///
    /// This behaves like [`Self::recv`] but additionally returns the path over which the packet was
    /// received. For supported path types, this path is already reversed such that it can be used
    /// directly to send reply packets; for unsupported path types, the path is copied unmodified.
    ///
    /// Note that copying/reversing the path requires allocating memory; if you do not need the path
    /// information, consider using the method [`Self::recv`] instead.
    pub async fn recv_with_path(&self, buffer: &mut [u8]) -> Result<(usize, Path), ReceiveError> {
        let (packet_len, _, path) = self.inner.recv_from_with_path(buffer).await?;
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
        self.inner.set_remote_address(remote_address);
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
pub type ReceiveError = std::convert::Infallible;

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
        let Some(destination) = destination.xor(state.remote_address) else {
            // Either both are None or both are Some
            return if state.remote_address.is_none() {
                Err(SendError::NotConnected)
            } else {
                Err(SendError::AlreadyConnected)
            };
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

    async fn recv_from_with_path(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr, Path), ReceiveError> {
        let (packet_len, sender, mut path) = self.recv_loop(buf).await?;
        // Explicit match here in case we add other errors to the `reverse` method at some point
        match path.dataplane_path.reverse() {
            Ok(_) => {
                path.isd_asn.reverse();
            }
            Err(UnsupportedPathType(_)) => path.dataplane_path = path.dataplane_path.deep_copy(),
        };
        Ok((packet_len, sender, path))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ReceiveError> {
        let (packet_len, sender, ..) = self.recv_loop(buf).await?;
        Ok((packet_len, sender))
    }

    async fn recv_loop(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, Path), ReceiveError> {
        loop {
            let receive_result = {
                let stream = &mut *self.stream.lock().await;
                stream.receive_packet().await
            };

            match receive_result {
                Ok(packet) => {
                    if let Some((packet_len, sender, path)) = self.parse_incoming(packet, buf) {
                        return Ok((packet_len, sender, path));
                    } else {
                        continue;
                    }
                }
                Err(_) => todo!("attempt reconnections to dispatcher"),
            }
        }
    }

    fn parse_incoming(
        &self,
        mut packet: Packet,
        buf: &mut [u8],
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

    pub fn set_remote_address(&self, remote_address: SocketAddr) {
        Arc::make_mut(&mut *self.state.write().unwrap()).remote_address = Some(remote_address);
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
    use tokio::{net::UnixStream, sync::Notify};

    use super::*;

    fn new_socket() -> Result<(SocketAddr, UdpSocket), Box<dyn std::error::Error>> {
        let (inner, _) = UnixStream::pair()?;
        let stream = DispatcherStream::new(inner);
        let local_addr: SocketAddr = "[1-ff00:0:111,127.0.0.17]:12300".parse()?;

        Ok((local_addr, UdpSocket::new(stream, local_addr)))
    }

    #[tokio::test]
    async fn set_path() -> Result<(), Box<dyn std::error::Error>> {
        let (local_addr, socket) = new_socket()?;

        let path = Path::empty(ByEndpoint::with_cloned(local_addr.isd_asn()));

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
