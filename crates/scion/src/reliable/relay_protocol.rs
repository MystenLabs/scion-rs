use std::{cmp::min, collections::VecDeque, net::SocketAddr};

use bytes::{Buf, Bytes, BytesMut};

use super::{
    common_header::{CommonHeader, DecodeError},
    parser::StreamParser,
    registration::{RegistrationRequest, RegistrationResponse},
    wire_utils::BytesQueue,
    Packet,
};
use crate::address::{IsdAsn, ServiceAddress};

#[derive(Debug)]
enum State {
    RegistrationRequestPending(RegistrationRequest),
    RegistrationRequestSent {
        bytes_received: BytesQueue,
        request: RegistrationRequest,
    },
    Registered {
        /// The port on which the instance is registered
        port: u16,
        /// Packets waiting to be sent to the dispatcher
        transmit_queue: VecDeque<(CommonHeader, Bytes)>,
        /// Parser for the incoming stream of packets from the dispatcher
        parser: StreamParser,
    },
    Terminated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Registered,
    Terminated { reason: ProtocolError },
    PacketsAvailable,
}

/// The SCION client-to-dispatcher relay protocol.
///
/// A reliable relay protocol to be used with the SCION dispatcher for sending
#[derive(Debug)]
pub struct ReliableRelayProtocol {
    state: State,
    events: VecDeque<Event>,
}

impl ReliableRelayProtocol {
    /// Maximum number of packets to send in a single [`Self::poll_transmit()`] call.
    // This should not be set to anything higher than 1/2 * isize::MAX, as twice its value
    // number of elements may be stored in a Vec.
    pub const MAX_TRANSMIT_BURST: usize = 100;

    /// Register to receive SCION packets destined for the given address and port.
    pub fn register(isd_asn: IsdAsn, public_address: SocketAddr) -> Self {
        Self::register_with_dispatcher(RegistrationRequest::new(isd_asn, public_address))
    }

    /// Register to receive SCION packets destined for the given address and port, or
    /// for a specific SCION service.
    ///
    /// See [`Self::register()`] for more details.
    pub fn register_service(
        isd_asn: IsdAsn,
        public_address: SocketAddr,
        associated_service: ServiceAddress,
    ) -> Self {
        Self::register_with_dispatcher(
            RegistrationRequest::new(isd_asn, public_address)
                .with_associated_service(associated_service),
        )
    }

    fn register_with_dispatcher(request: RegistrationRequest) -> Self {
        Self {
            state: State::RegistrationRequestPending(request),
            events: VecDeque::new(),
        }
    }

    /// Poll for data pending to be sent to the dispatcher.
    ///
    /// Returns at most [`Self::MAX_TRANSMIT_BURST`] packets in a vector with length of at most twice
    /// that value. Therefore, repeated calls may be necessary to fully drain the pending packets.
    pub fn poll_transmit(&mut self) -> Option<Vec<Bytes>> {
        match &mut self.state {
            State::RegistrationRequestPending(request) => {
                let mut buffer = BytesMut::with_capacity(request.encoded_length());
                request.encode_to(&mut buffer);

                self.state = State::RegistrationRequestSent {
                    bytes_received: BytesQueue::default(),
                    request: request.clone(),
                };

                Some(vec![buffer.freeze()])
            }

            State::Registered { transmit_queue, .. } if !transmit_queue.is_empty() => {
                // The value 2 * MAX_TRANSMIT_BURST must be at most isize, which is the limit for
                // number of Vec elements.
                assert!(Self::MAX_TRANSMIT_BURST <= (isize::MAX >> 1) as usize);

                let transmit_burst = min(transmit_queue.len(), Self::MAX_TRANSMIT_BURST);
                let buffer_length = transmit_queue
                    .iter()
                    .take(transmit_burst)
                    .fold(0, |sum, (header, _)| sum + header.encoded_length());

                let mut buffer = BytesMut::with_capacity(buffer_length);
                let mut to_transmit = Vec::new();

                for (header, bytes) in transmit_queue.drain(..transmit_burst) {
                    header.encode_to(&mut buffer);
                    let header_buffer = buffer.split_to(header.encoded_length());

                    to_transmit.push(header_buffer.freeze());
                    to_transmit.push(bytes);
                }

                Some(to_transmit)
            }

            _ => None,
        }
    }

    /// Returns application-facing events.
    ///
    /// The instance should be polled after one or more calls made to [`Self::handle_incoming()`].
    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Returns any packets that have been received from the dispatcher,
    /// along with their last traversed hop.
    ///
    /// # Errors
    ///
    /// Returns an error if the protocol has already terminated or is not yet registered.
    ///
    /// # Panics
    ///
    /// Panics if called before registration is complete.
    pub fn receive(&mut self) -> Result<Option<Packet>, ReceiveError> {
        match &mut self.state {
            State::RegistrationRequestPending(..) | State::RegistrationRequestSent { .. } => {
                panic!("receive should not be called before registration is completed");
            }
            State::Terminated => Err(ReceiveError::ProtocolTerminated),
            State::Registered { parser, .. } => parser.next_packet().map_err(|error| {
                self.terminate_protocol(error.into());

                ReceiveError::ProtocolError(error)
            }),
        }
    }

    /// Send data to the specified destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination is an unspecified IPv4 address (e.g., 0.0.0.0),
    /// if the destination port is 0, or if the packet is larger than [`u32::MAX`] bytes instead
    /// length.
    ///
    /// # Panics
    ///
    /// Panics if called before registration is complete.
    pub fn send(&mut self, packet: Bytes, destination: SocketAddr) -> Result<(), SendError> {
        match &mut self.state {
            State::RegistrationRequestPending { .. } | State::RegistrationRequestSent { .. } => {
                panic!("send should not be called before registration is completed");
            }
            State::Terminated => Err(SendError::ProtocolTerminated),
            State::Registered { transmit_queue, .. } => {
                if destination.ip().is_unspecified() {
                    Err(SendError::DestinationUnspecified)
                } else if destination.port() == 0 {
                    Err(SendError::DestinationPortUnspecified)
                } else {
                    let header = CommonHeader {
                        destination: Some(destination),
                        payload_length: u32::try_from(packet.len())
                            .or(Err(SendError::PacketTooLarge(packet.len())))?,
                    };
                    transmit_queue.push_back((header, packet));
                    Ok(())
                }
            }
        }
    }

    /// Process stream data arriving from the dispatcher, and execute protocol logic on the data.
    ///
    /// This can result in events being generated or packets being available, which can be extracted
    /// via the methods [`Self::poll`] and [`Self::receive`].
    pub fn handle_incoming(&mut self, data: Bytes) {
        match &mut self.state {
            State::RegistrationRequestPending { .. } => {
                // The current SCION dispatcher does not send data to the client before
                // receiving a registration. However, there is a possibility that the
                // source of the data being provided is not following the expected protocol.
                // We therefore treat this as a protocol error and not a programmer error.
                self.terminate_protocol(ProtocolError::DataBeforeRegistration)
            }
            State::RegistrationRequestSent { .. } => {
                let mut data = data;
                if self.maybe_complete_registration(&mut data) {
                    // Registration completed successfully and the state has advanced,
                    // handle the remaining data.
                    self.handle_incoming(data);
                } else {
                    // Discard the data as it no longer usable.
                    assert!(data.is_empty() || self.is_terminated());
                }
            }
            State::Registered { parser, .. } => {
                if parser.append_data(data) {
                    self.events.push_back(Event::PacketsAvailable);
                }
            }
            State::Terminated => (), // Discard the data
        }
    }

    fn terminate_protocol(&mut self, reason: ProtocolError) {
        self.state = State::Terminated;
        self.events.push_back(Event::Terminated { reason });
    }

    /// Return True if a port has been successfully registered.
    pub fn is_registered(&self) -> bool {
        matches!(&self.state, State::Registered { .. })
    }

    /// Return True if the protocol has already terminated.
    pub fn is_terminated(&self) -> bool {
        matches!(&self.state, State::Terminated)
    }

    /// Completes the port registration, if possible, and advances to the next state.
    ///
    /// Takes only as much data as required to complete the registration, and returns true
    /// if the registration completed successfully, false otherwise.
    ///
    /// If registration did not complete, either all the data was consumed or the protocol
    /// terminated.
    fn maybe_complete_registration(&mut self, data: &mut Bytes) -> bool {
        let State::RegistrationRequestSent {
            request,
            bytes_received,
        } = &mut self.state
        else {
            unreachable!("only called while awaiting registration response");
        };

        assert!(bytes_received.remaining() < RegistrationResponse::ENCODED_LENGTH);

        // Add only as much bytes as required and leave the rest in data.
        let bytes_required = RegistrationResponse::ENCODED_LENGTH - bytes_received.remaining();
        let bytes_to_take = min(bytes_required, data.len());
        bytes_received.push_back(data.split_to(bytes_to_take));

        if let Some(response) = RegistrationResponse::decode(bytes_received) {
            let requested_port = request.public_address.port();

            if requested_port != response.assigned_port && requested_port != 0 {
                self.terminate_protocol(ProtocolError::PortMismatch {
                    requested: requested_port,
                    assigned: response.assigned_port,
                });

                false
            } else {
                // We added only as much as was required for decoding the response, so this is empty
                assert_eq!(bytes_received.remaining(), 0);

                self.state = State::Registered {
                    transmit_queue: VecDeque::new(),
                    port: response.assigned_port,
                    parser: StreamParser::new(),
                };
                self.events.push_back(Event::Registered);

                true
            }
        } else {
            false
        }
    }

    /// Returns the port registered to this protocol instance, if any.
    pub fn port(&self) -> Option<u16> {
        match self.state {
            State::Registered { port, .. } => Some(port),
            _ => None,
        }
    }
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("protocol already terminated, receive is no longer possible")]
    ProtocolTerminated,
    #[error("An error occurred in the protocol: {0}")]
    ProtocolError(#[from] DecodeError),
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SendError {
    #[error("protocol already terminated, send is no longer possible")]
    ProtocolTerminated,
    #[error("provided destination address must be specified, not 0.0.0.0 or ::0")]
    DestinationUnspecified,
    #[error("provided destination port mmust be specified")]
    DestinationPortUnspecified,
    #[error("payload size too large ({0}), should be at most {}", u32::MAX)]
    PacketTooLarge(usize),
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("port mismatch, requested port {requested}, received port {assigned}")]
    PortMismatch { requested: u16, assigned: u16 },
    #[error("the protocol received data before the registration request was sent")]
    DataBeforeRegistration,
    #[error("failed to decode the a message")]
    DecodeError(#[from] DecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::parse;

    fn send_registration() -> ReliableRelayProtocol {
        let mut relay =
            ReliableRelayProtocol::register(parse!("1-ff00:0:1"), parse!("10.2.3.4:80"));

        let bytes_to_send = relay.poll_transmit().expect("must have bytes to output");
        assert_eq!(bytes_to_send.len(), 1, "expected only registration message");
        assert_eq!(
            bytes_to_send.first().unwrap(),
            [
                0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 17, 0x03, 17, 0, 1, 0xff, 0, 0, 0,
                0, 0x01, 0, 80, 1, 10, 2, 3, 4
            ]
            .as_slice()
        );

        relay
    }

    mod registration {
        use super::*;

        #[test]
        fn success() {
            let mut relay = send_registration();

            relay.handle_incoming(Bytes::from_static(&[0, 80]));

            assert_eq!(relay.poll(), Some(Event::Registered));
            assert_eq!(relay.port(), Some(80));
        }

        #[test]
        fn port_mismatch() {
            let mut relay = send_registration();

            relay.handle_incoming(Bytes::from_static(&[0, 81]));

            assert_eq!(
                relay.poll(),
                Some(Event::Terminated {
                    reason: ProtocolError::PortMismatch {
                        requested: 80,
                        assigned: 81
                    }
                })
            );
            assert_eq!(relay.port(), None);
        }

        #[test]
        fn incremental_data() {
            let mut relay = send_registration();

            relay.handle_incoming(Bytes::from_static(&[0]));

            assert_eq!(relay.poll(), None);
            assert_eq!(relay.port(), None);

            relay.handle_incoming(Bytes::from_static(&[80]));

            assert_eq!(relay.poll(), Some(Event::Registered));
            assert_eq!(relay.port(), Some(80));
        }
    }

    fn make_registered_protocol() -> ReliableRelayProtocol {
        ReliableRelayProtocol {
            state: State::Registered {
                transmit_queue: VecDeque::new(),
                port: 80,
                parser: StreamParser::default(),
            },
            events: VecDeque::new(),
        }
    }

    mod receive {

        use super::*;
        use crate::test_utils::parse;

        #[test]
        fn full_packet() -> Result<(), ReceiveError> {
            let mut relay = make_registered_protocol();

            assert!(relay.receive()?.is_none());

            relay.handle_incoming(Bytes::from_static(&[
                0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 5, 10, 2, 3, 4, 0, 80, b'H', b'E',
                b'L', b'L', b'O',
            ]));

            let packet = relay.receive()?.expect("data to be available");
            assert_eq!(packet.last_host, Some(parse!("10.2.3.4:80")));
            assert_eq!(packet.content.len(), 1);
            assert_eq!(packet.content[0], b"HELLO".as_slice());

            Ok(())
        }

        #[test]
        fn partial_packet() -> Result<(), ReceiveError> {
            let mut relay = make_registered_protocol();

            let parts = [
                vec![0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0],
                vec![0, 0, 5, 10, 2, 3, 4],
                vec![0, 80, b'h'],
                vec![b'e', b'l', b'l', b'o'],
            ];

            for data in parts.into_iter() {
                assert!(relay.receive()?.is_none());
                relay.handle_incoming(Bytes::from(data));
            }

            let packet = relay.receive()?.expect("data to be available");
            assert_eq!(packet.last_host, Some(parse!("10.2.3.4:80")));
            assert_eq!(packet.content.len(), 2);
            assert_eq!(packet.content[0], b"h".as_slice());
            assert_eq!(packet.content[1], b"ello".as_slice());

            Ok(())
        }

        #[test]
        fn packet_with_error() -> Result<(), ReceiveError> {
            let mut relay = make_registered_protocol();

            const DATA: [u8; 41] = [
                0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 5, 10, 2, 3, 4, 0, 80, b'h', b'e',
                b'l', b'l', b'o', 3, 1, 0, 0, 0, 5, 10, 2, 3, 4, 0, 80, b'H', b'E', b'L', b'L',
                b'O',
            ];

            relay.handle_incoming(Bytes::from_static(&DATA));

            let first_packet = relay
                .receive()?
                .expect("first packet to parse successfully");
            assert_eq!(first_packet.last_host, Some(parse!("10.2.3.4:80")));
            assert_eq!(first_packet.content, vec![b"hello".as_slice()]);

            assert!(!relay.is_terminated());

            assert!(matches!(
                relay.receive().expect_err("should fail due to bad packet"),
                ReceiveError::ProtocolError(DecodeError::InvalidCookie(..))
            ));

            assert!(relay.is_terminated());

            assert!(matches!(
                relay.receive(),
                Err(ReceiveError::ProtocolTerminated)
            ));

            Ok(())
        }
    }

    mod send {
        use super::*;

        #[test]
        fn single() {
            let mut relay = make_registered_protocol();

            relay
                .send(Bytes::from_static(b"Hello"), parse!("10.0.0.1:80"))
                .unwrap();

            let transmit = relay.poll_transmit().unwrap();
            assert_eq!(
                transmit,
                vec![
                    Bytes::from_static(&[
                        0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 5, 10, 0, 0, 1, 0, 80
                    ]),
                    Bytes::from_static(b"Hello")
                ]
            );
        }

        #[test]
        fn multiple() {
            let mut relay = make_registered_protocol();

            relay
                .send(Bytes::from_static(b"Hello"), parse!("192.168.0.1:22"))
                .unwrap();
            relay
                .send(Bytes::from_static(b"World!"), parse!("10.0.0.1:80"))
                .unwrap();

            let transmit = relay.poll_transmit().unwrap();
            assert_eq!(
                transmit,
                vec![
                    Bytes::from_static(&[
                        0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 5, 192, 168, 0, 1, 0, 22,
                    ]),
                    Bytes::from_static(b"Hello"),
                    Bytes::from_static(&[
                        0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 6, 10, 0, 0, 1, 0, 80
                    ]),
                    Bytes::from_static(b"World!")
                ]
            );
        }

        #[test]
        fn unspecified_ip() {
            let mut relay = make_registered_protocol();

            assert!(matches!(
                relay
                    .send(Bytes::from_static(b"Hello"), parse!("0.0.0.0:80"))
                    .unwrap_err(),
                SendError::DestinationUnspecified
            ));
        }

        #[test]
        fn unspecified_port() {
            let mut relay = make_registered_protocol();

            assert!(matches!(
                relay
                    .send(Bytes::from_static(b"Hello"), parse!("10.0.0.1:0"))
                    .unwrap_err(),
                SendError::DestinationPortUnspecified
            ));
        }

        #[test]
        #[should_panic]
        fn not_registered() {
            let mut relay = send_registration();
            let _ = relay.send(Bytes::from_static(b"Hello"), parse!("10.0.0.1:0"));
        }
    }
}
