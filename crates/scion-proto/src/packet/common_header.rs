use std::num::NonZeroU8;

use bytes::{Buf, BufMut};

use super::{path_header::PathType, ByEndpoint, DecodeError, InadequateBufferSize};
use crate::{
    address::HostType,
    wire_encoding::{self, MaybeEncoded, WireDecode, WireEncode},
};

/// SCION packet common header.
///
/// The common header contains important meta information such as the version number
/// of the header specification to be used while parsed, and the length of the overall
/// length of the headers and payload. See the [IETF SCION-dataplane RFC draft][rfc]
/// for details about the common header.
///
/// Currently, only version 0 of the packet specification is supported.
///
/// [rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#name-common-header
#[derive(Debug, PartialEq, Eq)]
pub struct CommonHeader {
    /// The header version.
    pub version: Version,

    /// Traffic class that can be set to utilise the IPv4 or IPv6 differentiated
    /// services field. More details can be found in [RFC2474] and [RFC3168].
    ///
    /// [RFC2474]: https://www.rfc-editor.org/rfc/rfc2474
    /// [RFC3168]: https://www.rfc-editor.org/rfc/rfc3168
    pub traffic_class: u8,

    /// An identifier for sequences of packets that are to be treated as a single network flow.
    pub flow_id: FlowId,

    /// Next layer SCION protocol number.
    ///
    /// See the IETF SCION-dataplane RFC draft][rfc] for possible values.
    ///
    ///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#protnum
    pub next_header: u8,

    /// The length of the entire header (common, address, and path) as a multiplicand of 4 bytes.
    ///
    /// This corresponds to the `HdrLen` field in the [RFC draft][rfc].
    ///
    /// Note that this value should be at least 9 (i.e., 36 bytes), which corresponds to 12 bytes
    /// for the common header, the minimum of 24 bytes for the address header, and 0 bytes for
    /// the empty path header. This minimum is enforced when decoding the common header.
    ///
    /// See [`Self::header_length()`] for the computed length.
    ///
    /// [rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#name-common-header
    pub header_length_factor: NonZeroU8,

    /// The length of the payload in bytes.
    pub payload_length: u16,

    /// The SCION path type.
    ///
    /// Recognized path types are decoded whereas unrecognized path types are provided
    /// in their wire format.
    pub path_type: MaybeEncoded<PathType, u8>,

    /// The source and destination host address type and length.
    ///
    /// They correspond to the 2-bit type and length fields `DT`, `DL`, `ST`, `SL`
    /// in the [RFC draft][rfc].
    ///
    /// [rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#name-common-header
    pub address_info: ByEndpoint<AddressInfo>,

    /// Reserved bits in the common header.
    pub reserved: u16,
}

impl CommonHeader {
    /// The currently supported header versions.
    pub const SUPPORTED_VERSIONS: &'static [Version] = &[Version(0)];

    /// The length of a version 0 common header in bytes.
    pub const LENGTH: usize = 12;

    /// Minimum header length factor defined as 36 bytes / 4.
    const MIN_HEADER_LENGTH_FACTOR: u8 = 9;

    /// The total length of the entire SCION header
    ///
    /// Equivalent to 4 * [`Self::header_length_factor`].
    pub fn header_length(&self) -> usize {
        usize::from(self.header_length_factor.get()) * 4
    }

    /// Returns the length of the remaining SCION headers.
    ///
    /// Equivalent to `max(0, self.header_length() - Self::LENGTH)`.
    pub fn remaining_header_length(&self) -> usize {
        self.header_length().saturating_sub(Self::LENGTH)
    }

    /// The payload length as a usize.
    pub fn payload_size(&self) -> usize {
        usize::try_from(self.payload_length).expect("usize to be larger than 16-bits")
    }
}

wire_encoding::bounded_uint! {
    /// 4-bit SCION packet version number.
    #[derive(Default)]
    pub struct Version(u8: 4);
}

wire_encoding::bounded_uint! {
    /// A 20-bit SCION packet flow identifier.
    pub struct FlowId(u32 : 20);
}

wire_encoding::bounded_uint!(
    /// An AddressInfo instance describes the type and length of a host address in
    /// the SCION common header.
    pub struct AddressInfo(u8 : 4);
);

impl AddressInfo {
    /// The maximum length of an address.
    pub const MAX_ADDRESS_BYTES: usize = 16;

    /// The address info for an IPv4 host.
    pub const IPV4: Self = Self(0b0000);

    /// The address info for an IPv6 host.
    pub const IPV6: Self = Self(0b0011);

    /// The address info for a Service host.
    pub const SERVICE: Self = Self(0b0100);

    /// Create an AddressInfo from the underlying host type.
    ///
    /// Returns None for a [`HostType::None`].
    pub fn from_host_type(value: HostType) -> Option<Self> {
        match value {
            HostType::None => None,
            HostType::Ipv4 => Some(Self(0b0000)),
            HostType::Ipv6 => Some(Self(0b0011)),
            HostType::Svc => Some(Self(0b0100)),
        }
    }

    /// Gets the total length of the host address in bytes.
    pub fn address_length(&self) -> usize {
        usize::from((self.0 & 0b0011) + 1) * 4
    }

    /// Gets the host type.
    ///
    /// The host type is a combination of the stored type and length. It is returned as
    /// an enum of type [`HostType`] if it is recognised, otherwise the undecoded 4-bit
    /// value is returned as a u8.
    pub fn host_type(&self) -> MaybeEncoded<HostType, u8> {
        match self.0 {
            0b0000 => MaybeEncoded::Decoded(HostType::Ipv4),
            0b0100 => MaybeEncoded::Decoded(HostType::Svc),
            0b0011 => MaybeEncoded::Decoded(HostType::Ipv6),
            other => MaybeEncoded::Encoded(other),
        }
    }
}

impl From<AddressInfo> for u8 {
    fn from(value: AddressInfo) -> Self {
        value.0
    }
}

impl From<ByEndpoint<AddressInfo>> for u8 {
    fn from(value: ByEndpoint<AddressInfo>) -> Self {
        value.destination.get() << 4 | value.source.get()
    }
}

impl<T> WireDecode<T> for CommonHeader
where
    T: Buf,
{
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if !data.has_remaining() {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }

        // Check the version without advancing the buffer.
        let version = Version(data.chunk()[0] >> 4);
        if version != Version(0) {
            return Err(Self::Error::UnsupportedVersion(version));
        }
        if data.remaining() < Self::LENGTH {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }

        let traffic_and_flow_info = data.get_u32();
        let traffic_class = ((traffic_and_flow_info & 0x0f_f0_00_00) >> 20) as u8;
        let flow_id = FlowId(traffic_and_flow_info & 0x000f_ffff);

        let next_header = data.get_u8();

        let header_length_factor = data.get_u8();
        let header_length_factor = if header_length_factor >= Self::MIN_HEADER_LENGTH_FACTOR {
            NonZeroU8::new(header_length_factor).unwrap()
        } else {
            return Err(Self::Error::InvalidHeaderLength(header_length_factor));
        };

        let payload_length = data.get_u16();
        let path_type = data.get_u8().into();

        let address_info_byte = data.get_u8();
        let address_info = ByEndpoint {
            destination: AddressInfo(address_info_byte >> 4),
            source: AddressInfo(address_info_byte & 0x0f),
        };

        let reserved = data.get_u16();

        Ok(Self {
            version,
            traffic_class,
            flow_id,
            next_header,
            header_length_factor,
            payload_length,
            path_type,
            address_info,
            reserved,
        })
    }
}

impl WireEncode for CommonHeader {
    type Error = InadequateBufferSize;

    fn encode_to<T: BufMut>(&self, buffer: &mut T) -> Result<(), Self::Error> {
        if buffer.remaining_mut() < Self::LENGTH {
            return Err(InadequateBufferSize);
        }

        buffer.put_u32(
            (self.version.get() as u32) << 28
                | (self.traffic_class as u32) << 20
                | self.flow_id.get(),
        );
        buffer.put_u8(self.next_header);
        buffer.put_u8(self.header_length_factor.get());
        buffer.put_u16(self.payload_length);
        buffer.put_u8(self.path_type.into_encoded());
        buffer.put_u8(self.address_info.into());
        buffer.put_u16(self.reserved);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header() -> ([u8; 12], CommonHeader) {
        let data: [u8; 12] = [
            0x08, 0x18, 0x00, 0x01, 0x11, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = CommonHeader {
            version: Version(0),
            traffic_class: 0x81,
            flow_id: FlowId(0x80001),
            next_header: 17,
            header_length_factor: NonZeroU8::new(9).unwrap(),
            payload_length: 0,
            path_type: MaybeEncoded::Decoded(PathType::Empty),
            address_info: ByEndpoint {
                destination: AddressInfo::from_host_type(HostType::Ipv4).unwrap(),
                source: AddressInfo::from_host_type(HostType::Ipv4).unwrap(),
            },
            reserved: 0,
        };

        (data, header)
    }

    mod encode {
        use super::*;

        #[test]
        fn valid_ipv4_to_ipv4() {
            let (expected_encoded, header) = base_header();

            assert_eq!(header.encode_to_bytes().as_ref(), expected_encoded);
        }

        #[test]
        fn valid_svc_to_ipv6() {
            let (mut expected_encoded, header) = base_header();

            let header = CommonHeader {
                address_info: ByEndpoint {
                    destination: AddressInfo::from_host_type(HostType::Ipv6).unwrap(),
                    source: AddressInfo::from_host_type(HostType::Svc).unwrap(),
                },
                ..header
            };
            expected_encoded[9] = 0x34;

            assert_eq!(header.encode_to_bytes().as_ref(), expected_encoded);
        }

        #[test]
        fn valid_unknown_path_type() {
            let (mut expected_encoded, header) = base_header();

            let header = CommonHeader {
                path_type: MaybeEncoded::Encoded(5),
                ..header
            };
            expected_encoded[8] = 0x05;

            assert_eq!(header.encode_to_bytes().as_ref(), expected_encoded);
        }

        #[test]
        fn inadequate_buffer_size() {
            let (_, header) = base_header();

            let mut buffer = [0u8; CommonHeader::LENGTH - 1];
            let result = header.encode_to(&mut buffer.as_mut());

            assert_eq!(result, Err(InadequateBufferSize));

            let mut buffer = [0u8; CommonHeader::LENGTH];
            let result = header.encode_to(&mut buffer.as_mut());

            assert_eq!(result, Ok(()));
        }
    }

    mod decode {
        use super::*;

        #[test]
        fn valid_ipv4_to_ipv4() {
            let (data, expected) = base_header();

            let decoded =
                CommonHeader::decode(&mut data.as_slice()).expect("must successfully decode");

            assert_eq!(decoded, expected);
            assert_eq!(decoded.header_length(), 36);
        }

        #[test]
        fn valid_svc_to_ipv6() {
            let (mut data, expected) = base_header();

            data[9] = 0x34;

            assert_eq!(
                CommonHeader::decode(&mut data.as_slice()).expect("must successfully decode"),
                CommonHeader {
                    address_info: ByEndpoint {
                        destination: AddressInfo::from_host_type(HostType::Ipv6).unwrap(),
                        source: AddressInfo::from_host_type(HostType::Svc).unwrap(),
                    },
                    ..expected
                }
            );
        }

        #[test]
        fn valid_unknown_path_type() {
            let (mut data, expected) = base_header();
            data[8] = 0x05;

            assert_eq!(
                CommonHeader::decode(&mut data.as_slice()).expect("must successfully decode"),
                CommonHeader {
                    path_type: MaybeEncoded::Encoded(5),
                    ..expected
                }
            );
        }

        #[test]
        fn unsupported_version() {
            let (mut data, _) = base_header();

            // Unset and reset the version
            data[0] = (data[0] & 0b0000_1111) | 0b0001_0000;

            assert_eq!(
                CommonHeader::decode(&mut data.as_slice()).expect_err("must fail to decode"),
                DecodeError::UnsupportedVersion(Version(1))
            );
        }

        #[test]
        fn invalid_header_length() {
            let (mut data, _) = base_header();
            data[5] = 0x08;

            assert_eq!(
                CommonHeader::decode(&mut data.as_slice()).expect_err("must fail to decode"),
                DecodeError::InvalidHeaderLength(8)
            );
        }
    }

    mod flow_id {
        use super::*;

        #[test]
        fn new() {
            assert_eq!(FlowId::new((1 << 20) - 1), Some(FlowId((1 << 20) - 1)));
            assert_eq!(FlowId::new(1 << 20), None);
        }
    }

    mod version {
        use super::*;

        #[test]
        fn new() {
            assert_eq!(Version::new(15), Some(Version(15)));
            assert_eq!(Version::new(16), None);
        }
    }

    mod address_info {
        use super::*;

        macro_rules! test_valid {
            ($name:ident, $raw:literal, $host_type:expr, $length:literal) => {
                #[test]
                fn $name() {
                    let address_info = AddressInfo::new($raw).expect("valid result");

                    assert_eq!(address_info, AddressInfo($raw));
                    assert_eq!(address_info.host_type(), MaybeEncoded::Decoded($host_type));
                    assert_eq!(address_info.address_length(), $length);
                    assert_eq!(Some(address_info), AddressInfo::from_host_type($host_type));
                }
            };
        }

        test_valid!(ipv4, 0b0000, HostType::Ipv4, 4);
        test_valid!(svc, 0b0100, HostType::Svc, 4);
        test_valid!(ipv6, 0b0011, HostType::Ipv6, 16);

        #[test]
        fn new_invalid() {
            assert_eq!(AddressInfo::new(16), None);
        }

        #[test]
        fn from_host_none() {
            assert_eq!(AddressInfo::from_host_type(HostType::None), None);
        }

        #[test]
        fn test_undecoded_address_info() {
            let address_info = AddressInfo::new(0b1001).expect("valid result");

            assert_eq!(address_info, AddressInfo(0b1001));
            assert_eq!(address_info.host_type(), MaybeEncoded::Encoded(0b1001));
            assert_eq!(address_info.address_length(), 8);
        }
    }
}
