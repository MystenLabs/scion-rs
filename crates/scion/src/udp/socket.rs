#![allow(dead_code)]
use std::{cmp, io, sync::Arc};

use scion_proto::{
    address::SocketAddr,
    packet::ScionPacket,
    path::Path,
    reliable::Packet,
    wire_encoding::{MaybeEncoded, WireDecode},
};
use tokio::sync::Mutex;

use crate::{
    dispatcher::{DispatcherStream, RegistrationError},
    udp::datagram::UdpDatagram,
    DEFAULT_DISPATCHER_PATH,
};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("failed to connect to the dispatcher, reason: {0}")]
    DispatcherConnectFailed(#[from] io::Error),
    #[error("failed to bind to the requested port")]
    RegistrationFailed(#[from] RegistrationError),
}

pub struct UdpSocket {
    inner: Arc<UdpSocketInner>,
    local_address: SocketAddr,
}

impl UdpSocket {
    pub async fn bind(address: SocketAddr) -> Result<Self, ConnectError> {
        Self::bind_with_dispatcher(address, DEFAULT_DISPATCHER_PATH).await
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
        let mut scion_packet = ScionPacket::decode(&mut packet.content)
            .map_err(log_err!("failed to decode SCION packet"))
            .ok()?;

        let udp_datagram = UdpDatagram::decode(&mut scion_packet.payload)
            .map_err(log_err!("failed to decode UDP datagram"))
            .ok()?;

        if !udp_datagram.verify_checksum(&scion_packet.address_header) {
            tracing::debug!("failed to verify packet checksum");
            return None;
        }

        let MaybeEncoded::Decoded(source_host) = scion_packet.address_header.host.source else {
            tracing::debug!("dropping packet with unsupported source address type");
            return None;
        };

        if let Some(source) = scion_packet.headers.address.source() {
        } else {
            tracing::debug!("dropping packet with unsupported source address type");
            return None;
        }

        let source = SocketAddr::new(
            scion_packet.address_header.ia.source,
            source_host,
            udp_datagram.port.source,
        );

        let path = {
            let dataplane_path = scion_packet.path_header.deep_copy();
            Path::new(
                dataplane_path,
                scion_packet.address_header.ia,
                packet.last_host,
            )
        };

        let payload_len = udp_datagram.payload.len();
        let copy_length = cmp::min(payload_len, buf.len());
        buf.copy_from_slice(&udp_datagram.payload[..copy_length]);

        Some((payload_len, source, path))
    }
}

#[derive(Debug)]
struct State {
    stream: DispatcherStream,
}
