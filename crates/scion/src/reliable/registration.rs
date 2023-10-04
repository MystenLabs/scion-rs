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
    address::{HostAddress, IsdAsn, ServiceAddress},
    reliable::{
        common_header::CommonHeader,
        wire_utils::{encoded_address_and_port_length, encoded_address_length},
        ADDRESS_TYPE_OCTETS,
    },
};

/// A SCION port registration request to the dispatcher.
pub(super) struct RegistrationRequest {
    /// The SCION AS in which the application is registering to listen for packets.
    pub isd_asn: IsdAsn,
    /// The address and port to which the remote SCION endpoint will be sending packets.
    pub public_address: SocketAddr,
    /// A separate "bind address", only used for logging by the dispatcher.
    pub bind_address: Option<SocketAddr>,
    /// The service to associate with
    pub associated_service: Option<ServiceAddress>,
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
    pub fn with_associated_service(mut self, address: ServiceAddress) -> Self {
        self.associated_service = Some(address);
        self
    }

    #[allow(dead_code)]
    pub fn encoded_length(&self) -> usize {
        CommonHeader::MIN_LENGTH + self.encoded_request_length()
    }

    /// Encode a registration request to the provided buffer.
    ///
    /// # Panics
    ///
    /// Panics if there is not enough space in the buffer to encode the request.
    #[allow(dead_code)]
    pub fn encode_to(&self, buffer: &mut impl BufMut) {
        self.encode_common_header(buffer);
        self.encode_request(buffer);
    }

    fn encode_request(&self, buffer: &mut impl BufMut) {
        let initial_remaining = buffer.remaining_mut();

        const UDP_PROTOCOL_NUMBER: u8 = 17;

        self.encode_command_flag(buffer);

        buffer.put_u8(UDP_PROTOCOL_NUMBER);
        buffer.put_u64(self.isd_asn.as_u64());

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

    #[allow(dead_code)]
    #[inline]
    fn encode_common_header(&self, buffer: &mut impl BufMut) {
        CommonHeader {
            destination: None,
            payload_length: u32::try_from(self.encoded_request_length())
                .expect("requests are short"),
        }
        .encode_to(buffer);
    }

    #[inline]
    fn encoded_request_length(&self) -> usize {
        const BASE_LENGTH: usize = 13;

        BASE_LENGTH
            + encoded_address_length(self.public_address.host_address_type())
            + if self.bind_address.is_some() {
                ADDRESS_TYPE_OCTETS
                    + encoded_address_and_port_length(self.bind_address.host_address_type())
            } else {
                0
            }
            + encoded_address_and_port_length(self.associated_service.host_address_type())
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
    #[allow(dead_code)]
    pub assigned_port: u16,
}

impl RegistrationResponse {
    /// The length of the encoded registration response.
    #[allow(dead_code)]
    pub const ENCODED_LENGTH: usize = LAYER4_PORT_OCTETS;

    /// Decode a registration response from the provided buffer.
    ///
    /// Returns None if the buffer contains less than 2 bytes.
    #[allow(dead_code)]
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
    buffer.put_u8(address.host_address_type().into());

    match address.ip() {
        IpAddr::V4(ipv4) => buffer.put(ipv4.octets().as_slice()),
        IpAddr::V6(ipv6) => buffer.put(ipv6.octets().as_slice()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

                    $request.encode_request(&mut buffer);

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
                .with_associated_service(ServiceAddress::CONTROL),
            [0x03, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4, 0x00, 0x02]
        );

        test_successful!(
            with_bind_and_service,
            RegistrationRequest::new(parse!("1-ff00:0:1"), parse!("10.2.3.4:80"))
                .with_bind_address(parse!("10.5.6.7:81"))
                .with_associated_service(ServiceAddress::CONTROL),
            [
                0x07, 17, 0, 1, 0xff, 0, 0, 0, 0, 0x01, 0, 80, 1, 10, 2, 3, 4, 0, 81, 1, 10, 5, 6,
                7, 0, 2
            ]
        );
    }
}
