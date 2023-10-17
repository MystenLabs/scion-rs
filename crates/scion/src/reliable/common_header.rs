use std::net::{IpAddr, SocketAddr};

use bytes::{Buf, BufMut};
use thiserror::Error;

use super::{
    wire_utils::{encoded_address_and_port_length, IPV6_OCTETS, LAYER4_PORT_OCTETS},
    ADDRESS_TYPE_OCTETS,
};
use crate::address::{HostAddress, HostType};

/// Errors occurring during decoding of packets received over the reliable-relay protocol.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The decoded packet started with an incorrect token. This indicates a
    /// synchronisation issue with the relay.
    #[error("received an invalid cookie when decoding header: {0:x}")]
    InvalidCookie(u64),
    /// The relay provided an invalid or unsupported address type as the
    /// destination of the packet.
    ///
    /// Currently, the only support address types are [`HostType::None`], [`HostType::Ipv4`]
    /// and [`HostType::Ipv6`].
    #[error("invalid or unsupported reliable relay address type: {0}")]
    InvalidAddressType(u8),
}

/// Partial or fully decoded commonHeader
#[allow(dead_code)]
pub(super) enum DecodedHeader {
    Partial(PartialHeader),
    Full(CommonHeader),
}

impl DecodedHeader {
    #[allow(dead_code)]
    pub fn is_fully_decoded(&self) -> bool {
        matches!(self, DecodedHeader::Full(..))
    }
}

/// A partially decoded common header
#[derive(Copy, Clone)]
pub(super) struct PartialHeader {
    pub host_type: HostType,
    pub payload_length: u32,
}

impl PartialHeader {
    /// Decode the non-variable portion of the [`CommonHeader`].
    ///
    /// # Panics
    ///
    /// Panics if there is not at least CommonHeader::MIN_LENGTH bytes available
    /// in the buffer.
    fn decode(buffer: &mut impl Buf) -> Result<Self, DecodeError> {
        assert!(
            buffer.remaining() >= CommonHeader::MIN_LENGTH,
            "insufficient data"
        );

        let cookie = buffer.get_u64();
        if cookie != CommonHeader::COOKIE {
            return Err(DecodeError::InvalidCookie(cookie));
        }

        let host_type = buffer.get_u8();
        let host_type = match HostType::from_byte(host_type) {
            None | Some(HostType::Svc) => return Err(DecodeError::InvalidAddressType(host_type)),
            Some(address_type) => address_type,
        };

        Ok(Self {
            host_type,
            payload_length: buffer.get_u32(),
        })
    }

    /// Number of bytes required to finish decoding the full common header.
    #[allow(dead_code)]
    pub fn required_bytes(&self) -> usize {
        encoded_address_and_port_length(self.host_type)
    }

    /// Finish decoding of the common header.
    ///
    /// # Panics
    ///
    /// Panics if there is not at least self.required_bytes() available in the buffer.
    #[allow(dead_code)]
    pub fn finish_decoding(self, buffer: &mut impl Buf) -> CommonHeader {
        assert!(
            buffer.remaining() >= self.required_bytes(),
            "insufficient data"
        );

        let PartialHeader {
            host_type,
            payload_length,
        } = self;

        let destination = match host_type {
            HostType::None => None,
            HostType::Ipv4 => Some(IpAddr::V4(buffer.get_u32().into())),
            HostType::Ipv6 => Some(IpAddr::V6(buffer.get_u128().into())),
            HostType::Svc => unreachable!(),
        }
        .map(|ip_address| SocketAddr::new(ip_address, buffer.get_u16()));

        CommonHeader {
            destination,
            payload_length,
        }
    }
}

/// The header for packets exchange between the client and relay.
#[derive(Default, Debug, Copy, Clone)]
pub(super) struct CommonHeader {
    /// The destination to which to relay the packet (when sent), or the client's address
    /// when receiving.
    // TODO(jsmith): Need to check if this is always the client's address
    pub destination: Option<SocketAddr>,
    /// The length of the associated payload.
    pub payload_length: u32,
}

impl CommonHeader {
    /// The minimum length of a common header.
    pub const MIN_LENGTH: usize =
        Self::COOKIE_LENGTH + ADDRESS_TYPE_OCTETS + Self::PAYLOAD_SIZE_LENGTH;
    #[allow(dead_code)]
    /// The maximum length of the common header.
    pub const MAX_LENGTH: usize = Self::MIN_LENGTH + IPV6_OCTETS + LAYER4_PORT_OCTETS;

    const COOKIE: u64 = 0xde00ad01be02ef03;
    const COOKIE_LENGTH: usize = 8;
    const PAYLOAD_SIZE_LENGTH: usize = 4;

    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// The size of the payload as a usize.
    #[allow(dead_code)]
    #[inline]
    pub fn payload_size(&self) -> usize {
        self.payload_length
            .try_into()
            .expect("at least 32-bit architecture")
    }

    /// The number of bytes in the encoded common header.
    pub fn encoded_length(&self) -> usize {
        Self::MIN_LENGTH + encoded_address_and_port_length(self.destination.host_address_type())
    }

    /// Serialize a common header to the provided buffer.
    ///
    /// The resulting header is suitable for being written to the network
    /// ahead of the payload.
    ///
    /// # Panic
    ///
    /// Panics if the the buffer is too small to contain the header.
    pub fn encode_to(&self, buffer: &mut impl BufMut) {
        let initial_remaining = buffer.remaining_mut();

        buffer.put_u64(Self::COOKIE);
        buffer.put_u8(self.destination.host_address_type().into());
        buffer.put_u32(self.payload_length);

        if let Some(destination) = self.destination.as_ref() {
            match destination.ip() {
                IpAddr::V4(ipv4) => buffer.put(ipv4.octets().as_slice()),
                IpAddr::V6(ipv6) => buffer.put(ipv6.octets().as_slice()),
            }

            buffer.put_u16(destination.port());
        }

        let bytes_consumed = initial_remaining - buffer.remaining_mut();
        assert_eq!(bytes_consumed, self.encoded_length());
    }

    /// Decodes either a partial or full common header from the provided
    /// buffer.
    ///
    /// # Panics
    ///
    /// Panics if there is not at least [`CommonHeader::MIN_LENGTH`] bytes available
    /// in the buffer.
    #[allow(dead_code)]
    pub fn partial_decode(buffer: &mut impl Buf) -> Result<DecodedHeader, DecodeError> {
        assert!(
            buffer.remaining() >= CommonHeader::MIN_LENGTH,
            "insufficient data"
        );

        let partial_header = PartialHeader::decode(buffer)?;

        if buffer.remaining() >= partial_header.required_bytes() {
            Ok(DecodedHeader::Full(partial_header.finish_decoding(buffer)))
        } else {
            Ok(DecodedHeader::Partial(partial_header))
        }
    }

    /// Decode the full common header form the buffer.
    ///
    /// # Panics
    ///
    /// Panics if there is insufficient data in the buffer to decode the entire header.
    /// To avoid the panic, ensure there is [`Self::MAX_LENGTH`] bytes available, or
    /// use [`Self::partial_decode()`] instead.
    #[allow(dead_code)]
    pub fn decode(buffer: &mut impl Buf) -> Result<Self, DecodeError> {
        PartialHeader::decode(buffer).map(|header| header.finish_decoding(buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod encode {
        use std::str::FromStr;

        use bytes::BytesMut;

        use super::*;

        macro_rules! test_successful_encode {
            ($name:ident, $optional_address:expr, $payload_length:expr, $expected_bytes:expr) => {
                #[test]
                fn $name() {
                    let address = $optional_address
                        .map(|addr_str| SocketAddr::from_str(addr_str).expect("valid address"));

                    let mut buffer = BytesMut::new();
                    CommonHeader {
                        destination: address,
                        payload_length: $payload_length,
                    }
                    .encode_to(&mut buffer);

                    assert_eq!(buffer.as_ref(), $expected_bytes);
                }
            };
        }

        test_successful_encode!(
            no_address_or_data,
            None,
            0,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0]
        );

        test_successful_encode!(
            ipv4_no_data,
            Some("10.2.3.4:80"),
            0,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0, 10, 2, 3, 4, 0, 80]
        );

        test_successful_encode!(
            ipv6_no_data,
            Some("[2001:db8::1]:80"),
            0,
            [
                0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80
            ]
        );

        test_successful_encode!(
            ipv4_big_port_no_data,
            Some("10.2.3.4:65534"),
            0,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0, 10, 2, 3, 4, 0xff, 0xfe]
        );

        test_successful_encode!(
            ipv4_good_payload,
            Some("127.0.0.1:22"),
            4,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 4, 127, 0, 0, 1, 0, 22]
        );

        test_successful_encode!(
            max_payload_length,
            Some("127.0.0.2:88"),
            u32::MAX,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0xff, 0xff, 0xff, 0xff, 127, 0, 0, 2, 0, 88]
        );
    }

    mod decode {
        use bytes::Bytes;

        use super::*;

        macro_rules! test_decode_error {
            ($name:ident, $buffer:expr, $expected_error:expr) => {
                #[test]
                fn $name() {
                    let mut buffer = Bytes::copy_from_slice($buffer.as_slice());
                    assert_eq!(
                        CommonHeader::decode(&mut buffer).expect_err("expected invalid data"),
                        $expected_error
                    );
                }
            };
        }

        test_decode_error!(
            invalid_cookie,
            [0xaa_u8, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0, 0, 0, 0, 0],
            DecodeError::InvalidCookie(0xaabbaabbaabbaabb)
        );

        test_decode_error!(
            invalid_address_type,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 3, 0, 0, 0, 0],
            DecodeError::InvalidAddressType(3)
        );

        macro_rules! test_decode_panic {
            ($name:ident, $buffer:expr) => {
                #[test]
                #[should_panic(expected = "insufficient data")]
                fn $name() {
                    let mut buffer = Bytes::copy_from_slice($buffer.as_slice());
                    let _ = CommonHeader::decode(&mut buffer);
                }
            };
        }

        test_decode_panic!(incomplete_header, [0xaa]);

        test_decode_panic!(
            incomplete_header_address,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0, 10, 2, 3]
        );

        test_decode_panic!(
            incomplete_header_port,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0, 10, 2, 3, 4, 0]
        );

        #[test]
        fn partial_decode_incomplete_address() {
            let mut buffer = Bytes::copy_from_slice(&[
                0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 0, 10, 2, 3,
            ]);

            let Ok(DecodedHeader::Partial(header)) = CommonHeader::partial_decode(&mut buffer)
            else {
                panic!("expected successful partial decode");
            };

            assert_eq!(header.host_type, HostType::Ipv4);
            assert_eq!(header.payload_length, 0);
        }

        macro_rules! test_successful_decode {
            ($name:ident, $buffer:expr, $expected_header:expr) => {
                #[test]
                fn $name() {
                    let mut buffer = Bytes::copy_from_slice($buffer.as_slice());
                    let header = CommonHeader::decode(&mut buffer).unwrap();

                    assert_eq!(header.destination, $expected_header.destination);
                    assert_eq!(header.payload_length, $expected_header.payload_length);
                }
            };
        }

        test_successful_decode!(
            valid_no_address,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 1, 42],
            CommonHeader {
                destination: None,
                payload_length: 1
            }
        );

        test_successful_decode!(
            valid_with_ipv4,
            [0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 1, 10, 2, 3, 4, 0, 80, 42],
            CommonHeader {
                destination: Some("10.2.3.4:80".parse().unwrap()),
                payload_length: 1,
            }
        );

        test_successful_decode!(
            valid_with_ipv6,
            [
                0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80, 42
            ],
            CommonHeader {
                destination: Some("[2001:db8::1]:80".parse().unwrap()),
                payload_length: 1,
            }
        );
    }
}
