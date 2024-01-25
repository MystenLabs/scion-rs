//! SCION port registration request and response.
//!
//! This module contains the request and response messages for registering ports
//! with the SCION dispatcher, on which the application would like to receive
//! packets.
//!
//! The encoded format of the request is
//!
//! ```plain
//!  13-bytes : Common header with address type NONE
//!   1-byte  : Command (bit mask with 0x04=Bind address, 0x02=SCMP enable, 0x01 always set)
//!   1-byte  : L4 Proto (IANA number)
//!   8-bytes : ISD-AS
//!   2-bytes : Public L4 port
//!   1-byte  : Public Address type
//! var-byte  : Public Address
//!   2-bytes : L4 bind port  ┐
//!   1-byte  : Address type  ├ (optional bind address)
//! var-byte  : Bind Address  ┘
//!   2-bytes : SVC (optional SVC type)
//! ```
//!
//! whereas the response is the 2-byte port assigned by the dispatcher.
//!
use std::net::{IpAddr, SocketAddr};

use bytes::{Buf, BufMut};

use super::wire_utils::LAYER4_PORT_OCTETS;
use crate::{
    address::{HostType, IsdAsn, ServiceAddr, SocketAddr as ScionSocketAddr},
    datagram::UdpMessage,
    reliable::{
        wire_utils::{encoded_address_and_port_length, encoded_address_length},
        ADDRESS_TYPE_OCTETS,
    },
};

/// A SCION port registration request to the dispatcher.
#[derive(Debug, Clone)]
pub(super) struct RegistrationRequest {
    /// The SCION AS in which the application is registering to listen for packets.
    pub isd_asn: IsdAsn,
    /// The address and port to which the remote SCION endpoint will be sending packets.
    pub public_address: SocketAddr,
    /// A separate "bind address", only used for logging by the dispatcher.
    pub bind_address: Option<SocketAddr>,
    /// The service to associate with
    pub associated_service: Option<ServiceAddr>,
}

impl RegistrationRequest {
    /// Return a new registration request for the specified IsdAsn and public address.
    pub fn new(isd_asn: IsdAsn, public_address: SocketAddr) -> Self {
        Self {
            isd_asn,
            public_address,
            bind_address: None,
            associated_service: None,
        }
    }

    /// Add the provided bind address to the request.
    #[cfg(test)]
    pub fn with_bind_address(mut self, address: SocketAddr) -> Self {
        self.bind_address = Some(address);
        self
    }

    /// Add the provided associated service address to the request.
    #[cfg(test)]
    pub fn with_associated_service(mut self, address: ServiceAddr) -> Self {
        self.associated_service = Some(address);
        self
    }

    /// Encode a registration request to the provided buffer.
    ///
    /// # Panics
    ///
    /// Panics if there is not enough space in the buffer to encode the request.
    // TODO(jsmith): Implement WireEncode for this type.
    pub fn encode_to(&self, buffer: &mut impl BufMut) {
        let initial_remaining = buffer.remaining_mut();

        self.encode_command_flag(buffer);

        buffer.put_u8(UdpMessage::PROTOCOL_NUMBER);
        buffer.put_u64(self.isd_asn.to_u64());

        encode_address(buffer, &self.public_address);

        if let Some(bind_address) = self.bind_address.as_ref() {
            encode_address(buffer, bind_address)
        }
        if let Some(service_address) = self.associated_service.as_ref() {
            buffer.put_u16(u16::from(*service_address))
        }

        let written = initial_remaining - buffer.remaining_mut();
        assert_eq!(written, self.encoded_request_length());
    }

    #[inline]
    fn encoded_request_length(&self) -> usize {
        const BASE_LENGTH: usize = 13;

        BASE_LENGTH
            + encoded_address_length(self.public_address.ip().into())
            + self
                .bind_address
                .as_ref()
                .map(|addr| ADDRESS_TYPE_OCTETS + encoded_address_and_port_length(addr.ip().into()))
                .unwrap_or(0)
            + encoded_address_and_port_length(self.associated_service.into())
    }

    #[inline]
    fn encode_command_flag(&self, buffer: &mut impl BufMut) {
        const FLAG_BASE: u8 = 0b001;
        const FLAG_SCMP: u8 = 0b010;
        const FLAG_BIND: u8 = 0b100;

        buffer.put_u8(FLAG_BASE | FLAG_SCMP | self.bind_address.map_or(0u8, |_| FLAG_BIND));
    }
}

/// The response to a registration request.
///
/// Only successful registrations are responded to by the dispatcher, thus
/// this always contains the assigned port number.
pub(super) struct RegistrationResponse {
    /// The port assigned by the dispatcher.
    pub assigned_port: u16,
}

impl RegistrationResponse {
    /// The length of the encoded registration response.
    pub const ENCODED_LENGTH: usize = LAYER4_PORT_OCTETS;

    /// Decode a registration response from the provided buffer.
    ///
    /// Returns None if the buffer contains less than 2 bytes.
    pub fn decode(buffer: &mut impl Buf) -> Option<Self> {
        if buffer.remaining() >= Self::ENCODED_LENGTH {
            Some(Self {
                assigned_port: buffer.get_u16(),
            })
        } else {
            None
        }
    }
}

fn encode_address(buffer: &mut impl BufMut, address: &SocketAddr) {
    buffer.put_u16(address.port());
    buffer.put_u8(HostType::from(address.ip()).into());

    match address.ip() {
        IpAddr::V4(ipv4) => buffer.put(ipv4.octets().as_slice()),
        IpAddr::V6(ipv6) => buffer.put(ipv6.octets().as_slice()),
    }
}

/// Error returned when attempting to register to a service address.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("cannot register to the provided address type")]
pub struct InvalidRegistrationAddressError;

/// Errors indicating a failure in the registration protocol.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum RegistrationError {
    /// The registration response was not of the expected length.
    #[error("invalid response length")]
    InvalidResponseLength,
    /// The dispatcher assigned a port that did not match with the request.
    #[error("dispatcher assigned incorrect port")]
    PortMismatch {
        /// The port requested
        requested: u16,
        /// The port assigned
        assigned: u16,
    },
}

/// A simple state machine for handling the registration to the dispatcher.
///
/// The methods [`RegistrationExchange::register()`] and [`RegistrationExchange::handle_response()`]
/// are used to initiate the registration and handle registration response respectively.
#[derive(Debug, Default)]
pub struct RegistrationExchange {
    request: Option<RegistrationRequest>,
}

impl RegistrationExchange {
    /// Creates a new instance of the state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register to receive SCION packets destined for the given address and port.
    ///
    /// The registration request to be sent to the dispatcher over a Unix socket is
    /// written into the provided buffer and the number of bytes written are returned.
    ///
    /// Specify a port number of zero to allow the dispatcher to assign the port number.
    ///
    /// # Errors
    ///
    /// Returns an error if an attempt is made to register to a service address, or if
    /// the address has a wildcard ISD-AS number.
    ///
    /// # Panics
    ///
    /// Panics if called repeatedly before a call to [`Self::handle_response()`]
    pub fn register<T: BufMut>(
        &mut self,
        address: ScionSocketAddr,
        buffer: &mut T,
    ) -> Result<usize, InvalidRegistrationAddressError> {
        assert!(self.request.is_none(), "register called repeatedly");

        if address.isd_asn().is_wildcard() {
            return Err(InvalidRegistrationAddressError);
        }

        let public_address: SocketAddr = address
            .local_address()
            .ok_or(InvalidRegistrationAddressError)?;

        let request = RegistrationRequest::new(address.isd_asn(), public_address);
        let encoded_length = request.encoded_request_length();

        request.encode_to(buffer);
        self.request = Some(request);

        Ok(encoded_length)
    }

    /// Handle the response from the dispatcher for the most recent call to [`Self::register()`],
    /// and returns the registered address.
    ///
    /// Returns an error if the response cannot be decoded or if the dispatcher has deviated
    /// from the expected protocol.
    pub fn handle_response(
        &mut self,
        mut response: &[u8],
    ) -> Result<ScionSocketAddr, RegistrationError> {
        assert!(self.request.is_some());

        if response.len() != RegistrationResponse::ENCODED_LENGTH {
            return Err(RegistrationError::InvalidResponseLength);
        }
        let response = RegistrationResponse::decode(&mut response).unwrap();

        let request = self.request.take().unwrap();

        let requested_port = request.public_address.port();
        if requested_port != 0 && requested_port != response.assigned_port {
            Err(RegistrationError::PortMismatch {
                requested: requested_port,
                assigned: response.assigned_port,
            })
        } else {
            let mut socket_addr =
                ScionSocketAddr::from_std(request.isd_asn, request.public_address);
            socket_addr.set_port(response.assigned_port);

            Ok(socket_addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    mod exchange {
        use bytes::BytesMut;

        use super::*;
        use crate::test_utils::parse;

        #[test]
        fn success() -> TestResult {
            let mut buffer = BytesMut::new();
            let address: ScionSocketAddr = parse!("[1-ff00:0:1,10.2.3.4]:80");

            let mut exchange = RegistrationExchange::new();

            exchange.register(address, &mut buffer)?;
            assert_eq!(
                buffer,
                [0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4].as_slice()
            );

            let bound_address = exchange.handle_response(&[0, 80])?;
            assert_eq!(address, bound_address);

            Ok(())
        }

        macro_rules! invalid_address {
            ($name:ident, $addr_str:expr) => {
                #[test]
                fn $name() -> TestResult {
                    let mut backing_array = [0u8; 10];
                    let mut buffer = backing_array.as_mut_slice();

                    let address: ScionSocketAddr = parse!($addr_str);
                    let mut exchange = RegistrationExchange::new();

                    let err = exchange
                        .register(address, &mut buffer)
                        .expect_err("should fail");

                    assert_eq!(err, InvalidRegistrationAddressError);

                    Ok(())
                }
            };
        }

        invalid_address!(zero_isd_fails, "[0-ff00:0:1,10.2.3.4]:80");
        invalid_address!(zero_asn_fails, "[1-0,10.2.3.4]:80");
        invalid_address!(zero_isd_asn_fails, "[0-0,10.2.3.4]:80");
        invalid_address!(service_address_fails, "[1-ff00:0:1,CS]:80");

        #[test]
        fn port_mismatch() -> TestResult {
            let mut buffer = BytesMut::new();
            let address: ScionSocketAddr = parse!("[1-ff00:0:1,10.2.3.4]:80");

            let mut exchange = RegistrationExchange::new();
            exchange.register(address, &mut buffer)?;
            let err = exchange.handle_response(&[0, 81]).expect_err("should fail");

            assert_eq!(
                err,
                RegistrationError::PortMismatch {
                    requested: 80,
                    assigned: 81
                }
            );

            Ok(())
        }

        #[test]
        fn invalid_response_length() -> TestResult {
            let mut buffer = BytesMut::new();
            let address: ScionSocketAddr = parse!("[1-ff00:0:1,10.2.3.4]:80");

            let mut exchange = RegistrationExchange::new();
            exchange.register(address, &mut buffer)?;

            let err = exchange.handle_response(&[80]).expect_err("should fail");
            assert_eq!(err, RegistrationError::InvalidResponseLength);

            let err = exchange
                .handle_response(&[0, 80, 99])
                .expect_err("should fail");
            assert_eq!(err, RegistrationError::InvalidResponseLength);

            Ok(())
        }
    }

    mod encode {
        use super::*;
        use crate::test_utils::parse;

        const BUFFER_LENGTH: usize = 50;

        macro_rules! test_successful {
            ($name:ident, $request:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    let mut backing_array = [0u8; BUFFER_LENGTH];
                    let mut buffer = backing_array.as_mut_slice();

                    $request.encode_to(&mut buffer);

                    let bytes_written = BUFFER_LENGTH - buffer.remaining_mut();
                    assert_eq!(backing_array[..bytes_written], $expected);
                }
            };
        }

        test_successful!(
            public_ipv4_only,
            RegistrationRequest::new(parse!("1-ff00:0:1"), parse!("10.2.3.4:80")),
            [0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4]
        );

        test_successful!(
            public_ipv6_only,
            RegistrationRequest::new(parse!("1-ff00:0:1"), parse!("[2001:db8::1]:80")),
            [
                0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 1
            ]
        );

        test_successful!(
            public_with_bind,
            RegistrationRequest::new(parse!("1-ff00:0:1"), parse!("10.2.3.4:80"))
                .with_bind_address(parse!("10.5.6.7:81")),
            [
                0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4, 0, 81, 1, 10, 5, 6,
                7
            ]
        );

        test_successful!(
            public_ipv4_with_service,
            RegistrationRequest::new(parse!("1-ff00:0:1"), parse!("10.2.3.4:80"))
                .with_associated_service(ServiceAddr::CONTROL),
            [0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4, 0x00, 0x02]
        );

        test_successful!(
            with_bind_and_service,
            RegistrationRequest::new(parse!("1-ff00:0:1"), parse!("10.2.3.4:80"))
                .with_bind_address(parse!("10.5.6.7:81"))
                .with_associated_service(ServiceAddr::CONTROL),
            [
                0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4, 0, 81, 1, 10, 5, 6,
                7, 0, 2
            ]
        );
    }
}
