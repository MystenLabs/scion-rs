use bytes::{Buf, BufMut};

use super::AddressInfo;
use crate::{
    address::{HostAddr, HostType, IsdAsn, ScionAddr, ServiceAddr, SocketAddr},
    packet::{ByEndpoint, DecodeError, InadequateBufferSize},
    wire_encoding::{MaybeEncoded, WireDecodeWithContext, WireEncode},
};

/// The bytes of an encoded host address.
///
/// The length of the host address is stored in an associated [`AddressInfo`] instance.
pub type RawHostAddress = [u8; AddressInfo::MAX_ADDRESS_BYTES];

/// The address header of a SCION packet.
///
/// It contains the SCION ISD-AS number and host address of the destination and
/// source endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressHeader {
    /// The ISD-AS numbers of the source and destination hosts.
    pub ia: ByEndpoint<IsdAsn>,
    /// The host addresses of the source and destination.
    pub host: ByEndpoint<MaybeEncoded<HostAddr, (AddressInfo, RawHostAddress)>>,
}

impl AddressHeader {
    const BASE_LENGTH: usize = 2 * core::mem::size_of::<u64>();

    /// Creates a new AddressHeader with the specified ISD-AS numbers and hosts.
    pub const fn new(ia: ByEndpoint<IsdAsn>, host: ByEndpoint<HostAddr>) -> Self {
        Self {
            ia,
            host: ByEndpoint {
                destination: MaybeEncoded::Decoded(host.destination),
                source: MaybeEncoded::Decoded(host.source),
            },
        }
    }

    /// Return the SCION source address if it was decoded, else None.
    pub fn source(&self) -> Option<ScionAddr> {
        self.host
            .source
            .decoded()
            .map(|source| ScionAddr::new(self.ia.source, source))
    }

    /// Return the SCION destination address if it was decoded, else None.
    pub fn destination(&self) -> Option<ScionAddr> {
        self.host
            .destination
            .decoded()
            .map(|destination| ScionAddr::new(self.ia.destination, destination))
    }
}

impl From<ByEndpoint<SocketAddr>> for AddressHeader {
    fn from(value: ByEndpoint<SocketAddr>) -> Self {
        AddressHeader {
            ia: value.map(SocketAddr::isd_asn),
            host: value.map(|e| MaybeEncoded::Decoded(e.host())),
        }
    }
}
impl From<ByEndpoint<ScionAddr>> for AddressHeader {
    fn from(value: ByEndpoint<ScionAddr>) -> Self {
        AddressHeader {
            ia: value.map(ScionAddr::isd_asn),
            host: value.map(|e| MaybeEncoded::Decoded(e.host())),
        }
    }
}

impl<T: Buf> WireDecodeWithContext<T> for AddressHeader {
    type Error = DecodeError;
    type Context = ByEndpoint<AddressInfo>;

    fn decode_with_context(
        data: &mut T,
        context: ByEndpoint<AddressInfo>,
    ) -> Result<Self, Self::Error> {
        if data.remaining() < 2 * core::mem::size_of::<u64>() {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }

        Ok(Self {
            ia: ByEndpoint {
                destination: IsdAsn(data.get_u64()),
                source: IsdAsn(data.get_u64()),
            },
            host: ByEndpoint {
                destination: maybe_decode_host(data, context.destination)?,
                source: maybe_decode_host(data, context.source)?,
            },
        })
    }
}

impl WireEncode for AddressHeader {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        Self::BASE_LENGTH
            + self.host.source.encoded_length()
            + self.host.destination.encoded_length()
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u64(self.ia.destination.into());
        buffer.put_u64(self.ia.source.into());

        self.host.destination.encode_to_unchecked(buffer);
        self.host.source.encode_to_unchecked(buffer);
    }
}

impl WireEncode for MaybeEncoded<HostAddr, (AddressInfo, RawHostAddress)> {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        match self {
            MaybeEncoded::Decoded(host) => AddressInfo::for_host(host).address_length(),
            MaybeEncoded::Encoded((info, _)) => info.address_length(),
        }
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        match self {
            MaybeEncoded::Decoded(host_addr) => match host_addr {
                HostAddr::V4(addr) => buffer.put_slice(&addr.octets()),
                HostAddr::V6(addr) => buffer.put_slice(&addr.octets()),
                HostAddr::Svc(addr) => {
                    buffer.put_u16((*addr).into());
                    buffer.put_u16(0);
                }
            },
            MaybeEncoded::Encoded((addr_info, encoded_host)) => {
                buffer.put_slice(&encoded_host[..addr_info.address_length()]);
            }
        }
    }
}

fn maybe_decode_host<T: Buf>(
    data: &mut T,
    info: AddressInfo,
) -> Result<MaybeEncoded<HostAddr, (AddressInfo, RawHostAddress)>, DecodeError> {
    if data.remaining() < info.address_length() {
        return Err(DecodeError::PacketEmptyOrTruncated);
    }

    Ok(match info.host_type() {
        MaybeEncoded::Decoded(host_type) => MaybeEncoded::Decoded(match host_type {
            HostType::None => unreachable!("AddressInfo never returns None host type"),
            HostType::Ipv4 => HostAddr::V4(data.get_u32().into()),
            HostType::Ipv6 => HostAddr::V6(data.get_u128().into()),
            HostType::Svc => {
                let address = HostAddr::Svc(ServiceAddr(data.get_u16()));
                // Remove service address's 2-byte padding
                let _ = data.get_u16();

                address
            }
        }),
        MaybeEncoded::Encoded(_) => {
            let mut host_address: RawHostAddress = [0u8; AddressInfo::MAX_ADDRESS_BYTES];

            assert!(info.address_length() <= AddressInfo::MAX_ADDRESS_BYTES);
            data.copy_to_slice(&mut host_address[..info.address_length()]);

            MaybeEncoded::Encoded((info, host_address))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! address_info {
        (host $dest_host:expr) => {
            AddressInfo::for_host(&$dest_host)
        };
        (raw $dest_host:expr) => {
            $dest_host.1
        };
    }

    macro_rules! to_encoded {
        (host $dest_host:expr) => {
            MaybeEncoded::Decoded($dest_host)
        };
        (raw $dest_host:expr) => {{
            let mut buffer = RawHostAddress::default();
            buffer[..$dest_host.0.len()].clone_from_slice(&$dest_host.0);
            MaybeEncoded::Encoded(($dest_host.1, buffer))
        }};
    }

    macro_rules! test_encode_decode {
        (
            name: $name:ident,
            destination: {ia: $dst_ia:expr, $dst_type:tt: $dst_host:expr},
            source: {ia: $src_ia:expr, $src_type:tt: $src_host:expr},
            encoded: $encoded:expr
        ) => {
            test_encode_decode!(
                $name,
                ($dst_ia, to_encoded!($dst_type $dst_host), address_info!($dst_type $dst_host)),
                ($src_ia, to_encoded!($src_type $src_host), address_info!($src_type $src_host)),
                $encoded
            );
        };
        (
            $name:ident,
            ($dst_ia:expr, $dst_host:expr, $dst_info:expr),
            ($src_ia:expr, $src_host:expr, $src_info:expr),
            $encoded:expr
        ) => {
            mod $name {
                use super::{ByEndpoint, *};

                #[test]
                fn decode() -> Result<(), Box<dyn std::error::Error>> {
                    let expected_addresses = AddressHeader {
                        ia: ByEndpoint { destination: $dst_ia.parse()?, source: $src_ia.parse()? },
                        host: ByEndpoint { destination: $dst_host, source: $src_host },
                    };

                    let mut data: &'static [u8] = $encoded;
                    let addresses = AddressHeader::decode_with_context(
                        &mut data,
                        ByEndpoint { destination: $dst_info, source: $src_info }
                    )?;

                    assert_eq!(addresses, expected_addresses);
                    Ok(())
                }

                #[test]
                fn encode() -> Result<(), Box<dyn std::error::Error>> {
                    let header = AddressHeader {
                        ia: ByEndpoint { destination: $dst_ia.parse()?, source: $src_ia.parse()? },
                        host: ByEndpoint { destination: $dst_host, source: $src_host },
                    };
                    let expected_encoded: &'static [u8] = $encoded;

                    let encoded = header.encode_to_bytes();

                    assert_eq!(encoded.as_ref(), expected_encoded);
                    Ok(())
                }
            }
        };
    }

    test_encode_decode! {
        name: ipv4_to_ipv4,
        destination: {ia: "1-ff00:0:ab", host: HostAddr::V4("10.0.0.1".parse()?)},
        source: {ia: "1-ff00:0:cd", host: HostAddr::V4("192.168.0.1".parse()?)},
        encoded: &[
            0, 1, 0xff, 0, 0, 0, 0, 0xab,
            0, 1, 0xff, 0, 0, 0, 0, 0xcd,
            10, 0, 0, 1, 192, 168, 0, 1
        ]
    }

    test_encode_decode! {
        name: ipv6_to_service,
        destination: {ia: "31-ff00:96:0", host: HostAddr::Svc(ServiceAddr::DAEMON.multicast())},
        source: {ia: "47-ff13:0:cd", host: HostAddr::V6("2001:0db8:ac10:fe01::".parse()?)},
        encoded: &[
            0, 31, 0xff, 0, 0, 0x96, 0, 0,
            0, 47, 0xff, 0x13, 0, 0, 0, 0xcd,
            0x80, 0x01, 0, 0,
            0x20, 0x01, 0x0d, 0xb8, 0xac, 0x10,
            0xfe, 0x01, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    }

    test_encode_decode! {
        name: unknown_to_unknown,
        destination: {
            ia: "31-ff00:96:0",
            raw: ([1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], AddressInfo::new_unchecked(0b0110))
        },
        source: {
            ia: "47-ff13:0:cd",
            raw: ([8u8, 7, 6, 5, 4, 3, 2, 1], AddressInfo::new_unchecked(0b1001))
        },
        encoded: &[
            0, 31, 0xff, 0, 0, 0x96, 0, 0,
            0, 47, 0xff, 0x13, 0, 0, 0, 0xcd,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            8, 7, 6, 5, 4, 3, 2, 1
        ]
    }

    #[test]
    fn truncated_decode() {
        let data = [0u8; 19];

        let result = AddressHeader::decode_with_context(
            &mut data.as_slice(),
            ByEndpoint {
                destination: AddressInfo::SERVICE,
                source: AddressInfo::IPV6,
            },
        );

        assert_eq!(result, Err(DecodeError::PacketEmptyOrTruncated));
    }
}
