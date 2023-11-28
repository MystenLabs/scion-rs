#![allow(dead_code)]
use std::{io, sync::Arc};

use scion_proto::address::SocketAddr;
use tokio::sync::Mutex;

use crate::{
    dispatcher::{DispatcherStream, RegistrationError},
    DEFAULT_DISPATCHER_PATH,
};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("failed to connect to the dispatcher, reason: {0}")]
    DispatcherConnectFailed(#[from] io::Error),
    #[error("failed to bind to the requested port")]
    RegistrationFailed(#[from] RegistrationError),
}

// #[derive(Debug, thiserror::Error)]
// pub enum SendError {
//     #[error(transparent)]
//     Io(#[from] std::io::Error),
// }

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

    //    pub async fn recv_from(
    //        &self,
    //        buffer: &mut [u8],
    //    ) -> Result<(usize, SocketAddr, Path), ReceiveError> {
    //        self.inner.recv_from(buffer).await
    //    }
}

// pub struct ReceiveError;

struct UdpSocketInner {
    state: Mutex<State>,
}

// macro_rules! log_err {
//     ($message:expr) => {
//         |err| {
//             tracing::debug!(?err, $message);
//             err
//         }
//     };
// }

impl UdpSocketInner {
    fn new(stream: DispatcherStream) -> Self {
        Self {
            state: Mutex::new(State { stream }),
        }
    }

    //    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, Path), ReceiveError> {
    //        loop {
    //            let receive_result = {
    //                let state = &mut *self.state.lock().await;
    //                state.stream.receive_packet().await
    //            };
    //
    //            match receive_result {
    //                Ok(packet) => {
    //                    if let Some(result) = self.decode_and_copy_into(packet, buf) {
    //                        return Ok(result);
    //                    } else {
    //                        continue;
    //                    }
    //                }
    //                Err(_) => todo!("attempt reconnections to dispatcher"),
    //            }
    //        }
    //    }
    //
    //    fn decode_and_copy_into(
    //        &self,
    //        mut packet: Packet,
    //        buf: &mut [u8],
    //    ) -> Option<(usize, SocketAddr, Path)> {
    //        let mut scion_packet = ScionPacket::decode(&mut packet.content)
    //            .map_err(log_err!("failed to decode SCION packet"))
    //            .ok()?;
    //
    //        let udp_datagram = UdpDatagram::decode(&mut scion_packet.payload)
    //            .map_err(log_err!("failed to decode UDP datagram"))
    //            .ok()?;
    //
    //        todo!()
    //    }
}

#[derive(Debug)]
struct State {
    stream: DispatcherStream,
}
