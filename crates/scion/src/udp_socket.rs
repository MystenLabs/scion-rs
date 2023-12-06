use std::{cmp, io, sync::Arc};

use bytes::Bytes;
use chrono::Utc;
use scion_proto::{
    address::SocketAddr,
    datagram::{UdpDatagram, UdpEncodeError},
    packet::{self, ByEndpoint, EncodeError, ScionPacketRaw, ScionPacketUdp},
    path::Path,
    reliable::Packet,
    wire_encoding::{MaybeEncoded, WireDecode},
};
use tokio::sync::Mutex;

use crate::dispatcher::{self, get_dispatcher_path, DispatcherStream, RegistrationError};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("failed to connect to the dispatcher, reason: {0}")]
    DispatcherConnectFailed(#[from] io::Error),
    #[error("failed to bind to the requested port")]
    RegistrationFailed(#[from] RegistrationError),
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("packet is too large to be sent")]
    PacketTooLarge,
    #[error("path is expired")]
    PathExpired,
    #[error("remote address is not set")]
    NoRemoteAddress,
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
            EncodeError::MisalignedHeader => panic!("this should never happen"),
        }
    }
}

pub struct UdpSocket {
    inner: Arc<UdpSocketInner>,
    local_address: SocketAddr,
    remote_address: Option<SocketAddr>,
    path: Option<Path>,
}

impl UdpSocket {
    pub async fn bind(address: SocketAddr) -> Result<Self, ConnectError> {
        Self::bind_with_dispatcher(address, get_dispatcher_path()).await
    }

    pub async fn bind_with_dispatcher<P: AsRef<std::path::Path> + std::fmt::Debug>(
        address: SocketAddr,
        dispatcher_path: P,
    ) -> Result<Self, ConnectError> {
        let mut stream = DispatcherStream::connect(dispatcher_path).await?;
        let local_address = stream.register(address).await?;

        Ok(Self {
            inner: Arc::new(UdpSocketInner::new(stream)),
            local_address,
            remote_address: None,
            path: None,
        })
    }

    /// Returns the local SCION address to which this socket is bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_address
    }

    /// Receive a SCION UDP packet from a remote endpoint.
    ///
    /// The UDP payload is written into the provided buffer. If there is insufficient space, excess
    /// data is dropped. The returned number of bytes always refers to the amount of data in the UDP
    /// payload.
    ///
    /// Additionally returns the remote SCION socket address, and the path over which the packet was
    /// received.
    pub async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, Path), ReceiveError> {
        self.inner.recv_from(buffer).await
    }

    /// Returns the remote SCION address set for this socket, if any.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_address
    }

    /// Returns the SCION path set for this socket, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref()
    }

    /// Registers a remote address for this socket.
    pub fn connect(&mut self, remote_address: SocketAddr) -> &mut Self {
        self.remote_address = Some(remote_address);
        self
    }

    /// Registers a path for this socket.
    pub fn set_path(&mut self, path: Path) -> &mut Self {
        self.path = Some(path);
        self
    }

    /// Sends the payload using the registered remote address and path
    ///
    /// Returns an error if the remote address or path are unset
    pub async fn send(&self, payload: Bytes) -> Result<(), SendError> {
        self.send_to_with(
            payload,
            self.remote_address.ok_or(SendError::NoRemoteAddress)?,
            self.path.as_ref().ok_or(SendError::NoPath)?,
        )
        .await
    }

    /// Sends the payload to the specified destination using the registered path
    ///
    /// Returns an error if the path is unset
    pub async fn send_to(&self, payload: Bytes, destination: SocketAddr) -> Result<(), SendError> {
        self.send_to_with(
            payload,
            destination,
            self.path.as_ref().ok_or(SendError::NoPath)?,
        )
        .await
    }

    /// Sends the payload to the registered destination using the specified path
    ///
    /// Returns an error if the remote address is unset
    pub async fn send_with(&self, payload: Bytes, path: &Path) -> Result<(), SendError> {
        self.send_to_with(
            payload,
            self.remote_address.ok_or(SendError::NoRemoteAddress)?,
            path,
        )
        .await
    }

    /// Sends the payload to the specified remote address and path
    pub async fn send_to_with(
        &self,
        payload: Bytes,
        destination: SocketAddr,
        path: &Path,
    ) -> Result<(), SendError> {
        self.inner
            .send_between_with(
                payload,
                &ByEndpoint {
                    destination,
                    source: self.local_addr(),
                },
                path,
            )
            .await?;
        Ok(())
    }
}

pub type ReceiveError = std::convert::Infallible;

struct UdpSocketInner {
    state: Mutex<State>,
}

macro_rules! log_err {
    ($message:expr) => {
        |err| {
            tracing::debug!(?err, $message);
            err
        }
    };
}

impl UdpSocketInner {
    fn new(stream: DispatcherStream) -> Self {
        Self {
            state: Mutex::new(State { stream }),
        }
    }

    async fn send_between_with(
        &self,
        payload: Bytes,
        endhosts: &ByEndpoint<SocketAddr>,
        path: &Path,
    ) -> Result<(), SendError> {
        if let Some(metadata) = &path.metadata {
            if metadata.expiration < Utc::now() {
                return Err(SendError::PathExpired);
            }
        }

        let relay = if path.underlay_next_hop.is_some() {
            path.underlay_next_hop
        } else if endhosts.source.isd_asn() == endhosts.destination.isd_asn() {
            endhosts.destination.local_address().map(|mut socket_addr| {
                socket_addr.set_port(dispatcher::UNDERLAY_PORT);
                socket_addr
            })
        } else {
            return Err(SendError::NoUnderlayNextHop);
        };

        let packet = ScionPacketUdp::new(endhosts, path, payload)?;

        self.state
            .lock()
            .await
            .stream
            .send_packet_via(relay, packet)
            .await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, Path), ReceiveError> {
        loop {
            let receive_result = {
                let state = &mut *self.state.lock().await;
                state.stream.receive_packet().await
            };

            match receive_result {
                Ok(packet) => {
                    if let Some(result) = self.parse_incoming(packet, buf) {
                        return Ok(result);
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

        let MaybeEncoded::Decoded(source_host) = scion_packet.headers.address.host.source else {
            tracing::debug!("dropping packet with unsupported source address type");
            return None;
        };
        let source = SocketAddr::new(
            scion_packet.headers.address.ia.source,
            source_host,
            udp_datagram.port.source,
        );

        let path = {
            let dataplane_path = scion_packet.headers.path.deep_copy();
            Path::new(
                dataplane_path,
                scion_packet.headers.address.ia,
                packet.last_host,
            )
        };

        let payload_len = udp_datagram.payload.len();
        let copy_length = cmp::min(payload_len, buf.len());
        buf[..copy_length].copy_from_slice(&udp_datagram.payload[..copy_length]);

        Some((payload_len, source, path))
    }
}

#[derive(Debug)]
struct State {
    stream: DispatcherStream,
}
