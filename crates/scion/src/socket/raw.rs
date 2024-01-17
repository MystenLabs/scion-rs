//! A raw socket to send different types of messages via SCION.

use std::{cmp, net, sync::Arc};

use bytes::Bytes;
use scion_proto::{
    address::SocketAddr,
    packet::{AddressHeader, CommonHeader, ScionPacket, ScionPacketRaw},
    path::{DataplanePath, Path},
    reliable::Packet,
    wire_encoding::WireDecode,
};
use tokio::sync::Mutex;

use super::{error::log_err, utils::check_buffers, BindError};
use crate::{
    dispatcher::{get_dispatcher_path, DispatcherStream},
    pan::{ReceiveError, SendError},
};

/// A SCION raw socket.
#[derive(Debug)]
pub struct RawSocket {
    inner: Arc<RawSocketInner>,
}

impl RawSocket {
    /// Creates a new raw socket bound to the provided SCION socket address and returns this socket
    /// and the port it's bound to.
    ///
    /// When specifying a port `0` in the `address`, the port is assigned automatically by the
    /// dispatcher.
    pub async fn bind(address: SocketAddr) -> Result<(Self, u16), BindError> {
        Self::bind_with_dispatcher(address, get_dispatcher_path()).await
    }

    /// Creates a new raw socket from the given SCION socket address, by connecting to and
    /// registering with the SCION dispatcher at the specified path, and returns this socket
    /// and the port it's bound to.
    ///
    /// See [`bind`][Self::bind] for a variant that connects to the system's configured
    /// SCION dispatcher.
    pub async fn bind_with_dispatcher<P>(
        address: SocketAddr,
        dispatcher_path: P,
    ) -> Result<(Self, u16), BindError>
    where
        P: AsRef<std::path::Path> + std::fmt::Debug,
    {
        let mut stream = DispatcherStream::connect(dispatcher_path).await?;
        let local_address = stream.register(address).await?;

        Ok((Self::new(stream), local_address.port()))
    }

    fn new(stream: DispatcherStream) -> Self {
        Self {
            inner: Arc::new(RawSocketInner::new(stream)),
        }
    }

    /// Receive a packet, its headers, and path from the socket.
    ///
    /// The payload of the packet is written into the provided buffer, which must not be
    /// empty. If there is insufficient space in the buffer, excess data may be dropped.
    ///
    /// This function returns the number of bytes in the payload (irrespective of whether any
    /// were dropped), the SCION headers, and the SCION [`Path`] over which the packet
    /// was received.
    ///
    /// The returned path corresponds to the reversed path observed in the packet for known path
    /// types, or a copy of the opaque path data for unknown path types. In either case, the raw
    /// data comprising the returned path is written to path_buffer, which must be at least
    /// [`DataplanePath::MAX_LEN`][`scion_proto::path::DataplanePath::<Bytes>::MAX_LEN`] bytes in
    /// length.
    pub async fn recv_with_headers_and_path<'p>(
        &self,
        buffer: &mut [u8],
        path_buffer: &'p mut [u8],
    ) -> Result<(usize, CommonHeader, AddressHeader, Path<&'p mut [u8]>), ReceiveError> {
        if buffer.is_empty() {
            return Err(ReceiveError::ZeroLengthBuffer);
        }
        if path_buffer.len() < DataplanePath::<Bytes>::MAX_LEN {
            return Err(ReceiveError::PathBufferTooShort);
        }

        let (len, common_header, address_header, Some(path)) =
            self.inner.recv_loop(buffer, Some(path_buffer)).await?
        else {
            unreachable!("path is always returned when providing a buffer")
        };
        Ok((len, common_header, address_header, path))
    }

    /// Receive a packet and its headers.
    ///
    /// This behaves like [`Self::recv_with_headers_and_path`] but does not return the path over which
    /// the packet was received.
    ///
    /// In the case where the path is not needed, this method should be used as the
    /// implementation may avoid copying the path.
    ///
    /// See [`Self::recv_with_headers_and_path`] for more information.
    pub async fn recv_with_headers(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, CommonHeader, AddressHeader), ReceiveError> {
        self.inner
            .recv_loop(buffer, None)
            .await
            .map(|(len, common_header, address_header, _)| (len, common_header, address_header))
    }

    /// Sends the packet through the dispatcher via the provided relay.
    pub async fn send_packet_via<const N: usize>(
        &self,
        relay: Option<net::SocketAddr>,
        packet: &impl ScionPacket<N>,
    ) -> Result<(), SendError> {
        self.inner
            .stream
            .lock()
            .await
            .send_packet_via(relay, packet)
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
struct RawSocketInner {
    stream: Mutex<DispatcherStream>,
}

impl RawSocketInner {
    fn new(stream: DispatcherStream) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }

    async fn recv_loop<'p>(
        &self,
        buf: &mut [u8],
        path_buf: Option<&'p mut [u8]>,
    ) -> Result<
        (
            usize,
            CommonHeader,
            AddressHeader,
            Option<Path<&'p mut [u8]>>,
        ),
        ReceiveError,
    > {
        check_buffers(buf, &path_buf)?;

        loop {
            // Keep the lock until we no longer have a dependency on the internal buffers.
            let mut stream = self.stream.lock().await;
            let receive_result = stream.receive_packet().await;

            match receive_result {
                Ok(packet) => {
                    if let Some((packet_len, common_header, address_header, path)) =
                        self.parse_incoming(packet, buf)
                    {
                        return Ok((
                            packet_len,
                            common_header,
                            address_header,
                            path_buf.map(|b| path.reverse_to_slice(b)),
                        ));
                    } else {
                        continue;
                    }
                }
                Err(_) => todo!("attempt reconnections to dispatcher"),
            }
        }
    }

    /// Parse a SCION packet from the provided dispatcher packet.
    ///
    /// # Panics
    ///
    /// Panics if path_buf, when not empty, does not have sufficient length for the SCION path.
    fn parse_incoming(
        &self,
        mut packet: Packet,
        buf: &mut [u8],
    ) -> Option<(usize, CommonHeader, AddressHeader, Path)> {
        let scion_packet = ScionPacketRaw::decode(&mut packet.content)
            .map_err(log_err!("failed to decode SCION packet"))
            .ok()?;

        let payload_len = scion_packet.headers.common.payload_size();
        let copy_length = cmp::min(payload_len, buf.len());
        buf[..copy_length].copy_from_slice(&scion_packet.payload[..copy_length]);

        Some((
            payload_len,
            scion_packet.headers.common,
            scion_packet.headers.address,
            Path::new(
                scion_packet.headers.path,
                scion_packet.headers.address.ia,
                packet.last_host,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use scion_proto::path::DataplanePath;
    use tokio::net::UnixStream;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const MESSAGE: &[u8] = b"Hello World! Hello World! Hello World!";

    mod utils {

        use scion_proto::{address::ScionAddr, packet::ByEndpoint};

        use super::*;
        use crate::dispatcher;

        pub fn socket_from() -> TestResult<(RawSocket, DispatcherStream)> {
            let (inner, inner_remote) = UnixStream::pair()?;
            Ok((
                RawSocket::new(DispatcherStream::new(inner)),
                DispatcherStream::new(inner_remote),
            ))
        }

        pub async fn local_send_raw(
            dispatcher: &mut DispatcherStream,
            endpoints: ByEndpoint<ScionAddr>,
            message: &[u8],
        ) -> TestResult<()> {
            debug_assert!(
                endpoints.map(ScionAddr::isd_asn).are_equal(),
                "expected intra-AS addresses"
            );

            let relay = endpoints
                .destination
                .local_address()
                .map(|ip_addr| net::SocketAddr::new(ip_addr, dispatcher::UNDERLAY_PORT))
                .expect("IPv4/6 local address");

            let packet = ScionPacketRaw::new(
                &endpoints,
                &Path::local(endpoints.source.isd_asn()),
                Bytes::copy_from_slice(message),
                0,
                Default::default(),
            )?;

            dispatcher.send_packet_via(Some(relay), &packet).await?;

            Ok(())
        }
    }

    mod send {
        use scion_proto::{address::ScionAddr, packet::ByEndpoint};

        use super::*;

        #[tokio::test]
        async fn test_send_to_via() -> TestResult {
            let local_addr: ScionAddr = "1-ff00:0:111,10.0.0.1".parse()?;
            let remote_addr = "1-ff00:0:111,10.0.0.2".parse()?;

            let (socket, mut dispatcher) = utils::socket_from()?;
            let path = Path::local(local_addr.isd_asn());

            socket
                .send_packet_via(
                    None,
                    &ScionPacketRaw::new(
                        &ByEndpoint {
                            source: local_addr,
                            destination: remote_addr,
                        },
                        &path,
                        Bytes::from_static(MESSAGE),
                        42,
                        Default::default(),
                    )?,
                )
                .await?;

            let mut dispatcher_packet = dispatcher.receive_packet().await?;
            let raw_packet = ScionPacketRaw::decode(&mut dispatcher_packet.content)?;

            assert_eq!(raw_packet.headers.address.source(), Some(local_addr));
            assert_eq!(raw_packet.headers.address.destination(), Some(remote_addr));
            assert_eq!(raw_packet.payload.as_ref(), MESSAGE);

            Ok(())
        }
    }

    mod recv {
        use scion_proto::{address::ScionAddr, packet::ByEndpoint};

        use super::*;

        #[tokio::test]
        async fn test_recv() -> TestResult {
            let endpoints = ByEndpoint::<ScionAddr> {
                source: "1-f:0:3,4.4.0.1".parse()?,
                destination: "1-f:0:3,11.10.13.7".parse()?,
            };
            assert_eq!(endpoints.source.isd_asn(), endpoints.destination.isd_asn());

            let mut buffer = vec![0u8; 64];
            let mut path_buffer = vec![0u8; 1024];
            let (socket, mut dispatcher) = utils::socket_from()?;
            utils::local_send_raw(&mut dispatcher, endpoints, MESSAGE).await?;

            let (length, _incoming_common_header, incoming_address_header, incoming_path) = socket
                .recv_with_headers_and_path(&mut buffer, &mut path_buffer)
                .await?;

            assert_eq!(&buffer[..length], MESSAGE);
            assert_eq!(
                incoming_path.dataplane_path,
                DataplanePath::<Bytes>::EmptyPath
            );
            assert_eq!(incoming_path.isd_asn, endpoints.map(ScionAddr::isd_asn));
            assert_eq!(incoming_path.metadata, None);
            assert_ne!(incoming_path.underlay_next_hop, None);
            assert_eq!(incoming_address_header.source(), Some(endpoints.source));

            Ok(())
        }

        #[tokio::test]
        async fn zero_length_buffer() -> TestResult {
            let endpoints = ByEndpoint::<ScionAddr> {
                source: "1-f:0:3,4.4.0.1".parse()?,
                destination: "1-f:0:3,11.10.13.7".parse()?,
            };
            assert_eq!(endpoints.source.isd_asn(), endpoints.destination.isd_asn());

            let mut buffer = vec![0u8; 64];
            let mut path_buffer = vec![0u8; 1024];

            let (socket, mut dispatcher) = utils::socket_from()?;
            utils::local_send_raw(&mut dispatcher, endpoints, MESSAGE).await?;

            let err = socket
                .recv_with_headers_and_path(&mut [], &mut path_buffer)
                .await
                .expect_err("should fail due to zero-length buffer");
            assert_eq!(err, ReceiveError::ZeroLengthBuffer);

            // The data should still be available to read
            let (length, _incoming_common_header, incoming_address_header, _) = socket
                .recv_with_headers_and_path(&mut buffer, &mut path_buffer)
                .await?;

            assert_eq!(&buffer[..length], MESSAGE);
            assert_eq!(incoming_address_header.source(), Some(endpoints.source));

            Ok(())
        }
    }
}
