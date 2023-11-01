use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Buf;

use super::{AddressInfo, ByEndpoint, DecodeError};
use crate::{
    address::{Host, HostType, IsdAsn, ServiceAddress},
    wire_encoding::{MaybeEncoded, WireDecodeWithContext},
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
    pub host: ByEndpoint<MaybeEncoded<Host, RawHostAddress>>,
}

impl<T> WireDecodeWithContext<T> for AddressHeader
where
    T: Buf,
{
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

fn maybe_decode_host<T>(
    data: &mut T,
    info: AddressInfo,
) -> Result<MaybeEncoded<Host, RawHostAddress>, DecodeError>
where
    T: Buf,
{
    if data.remaining() < info.address_length() {
        return Err(DecodeError::PacketEmptyOrTruncated);
    }

    Ok(match info.host_type() {
        MaybeEncoded::Decoded(host_type) => MaybeEncoded::Decoded(match host_type {
            HostType::None => unreachable!("AddressInfo never returns None host type"),
            HostType::Ipv4 => Host::Ip(Ipv4Addr::from(data.get_u32()).into()),
            HostType::Ipv6 => Host::Ip(Ipv6Addr::from(data.get_u128()).into()),
            HostType::Svc => {
                let address = Host::Svc(ServiceAddress(data.get_u16()));
                // Remove service address's 2-byte padding
                let _ = data.get_u16();

                address
            }
        }),
        MaybeEncoded::Encoded(_) => {
            let mut host_address: RawHostAddress = [0u8; AddressInfo::MAX_ADDRESS_BYTES];

            assert!(info.address_length() <= AddressInfo::MAX_ADDRESS_BYTES);
            data.copy_to_slice(&mut host_address[..info.address_length()]);

            MaybeEncoded::Encoded(host_address)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    mod decode {
        use bytes::{BufMut, BytesMut};

        use super::*;
        use crate::test_utils::parse;

        #[test]
        fn ipv4_to_ipv4() {
            let destination: IsdAsn = parse!("1-ff00:0:ab");
            let source: IsdAsn = parse!("1-ff00:0:cd");

            let mut data = BytesMut::new();

            data.put_u64(destination.as_u64());
            data.put_u64(source.as_u64());
            data.put_slice(&[10, 0, 0, 1, 192, 168, 0, 1]);

            let mut data = data.freeze();

            let result = AddressHeader::decode_with_context(
                &mut data,
                ByEndpoint {
                    destination: AddressInfo::IPV4,
                    source: AddressInfo::IPV4,
                },
            )
            .expect("should successfully decode");

            assert_eq!(
                result,
                AddressHeader {
                    ia: ByEndpoint {
                        destination,
                        source
                    },
                    host: ByEndpoint {
                        destination: MaybeEncoded::Decoded(Ipv4Addr::new(10, 0, 0, 1).into()),
                        source: MaybeEncoded::Decoded(Ipv4Addr::new(192, 168, 0, 1).into()),
                    }
                }
            );
            assert_eq!(data.remaining(), 0);
        }

        #[test]
        fn ipv6_to_service() {
            let destination: IsdAsn = parse!("31-ff00:96:0");
            let source: IsdAsn = parse!("47-ff13:0:cd");
            let ipv6_source: Ipv6Addr = parse!("2001:0db8:ac10:fe01::");
            let service_destination = ServiceAddress::DAEMON.multicast();

            let mut data = BytesMut::new();

            data.put_u64(destination.as_u64());
            data.put_u64(source.as_u64());
            data.put_u16(service_destination.into());
            data.put_u16(0);
            data.put_slice(&ipv6_source.octets());

            let mut data = data.freeze();

            let result = AddressHeader::decode_with_context(
                &mut data,
                ByEndpoint {
                    destination: AddressInfo::SERVICE,
                    source: AddressInfo::IPV6,
                },
            )
            .expect("should successfully decode");

            assert_eq!(
                result,
                AddressHeader {
                    ia: ByEndpoint {
                        destination,
                        source
                    },
                    host: ByEndpoint {
                        destination: MaybeEncoded::Decoded(service_destination.into()),
                        source: MaybeEncoded::Decoded(ipv6_source.into()),
                    }
                }
            );
            assert_eq!(data.remaining(), 0);
        }

        #[test]
        fn unknown_to_unknown() {
            let destination: IsdAsn = parse!("31-ff00:96:0");
            let source: IsdAsn = parse!("47-ff13:0:cd");
            let destination_host = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
            let source_host = [8u8, 7, 6, 5, 4, 3, 2, 1];

            let mut data = BytesMut::new();

            data.put_u64(destination.as_u64());
            data.put_u64(source.as_u64());
            data.put_slice(&destination_host);
            data.put_slice(&source_host);

            let mut data = data.freeze();

            let result = AddressHeader::decode_with_context(
                &mut data,
                ByEndpoint {
                    source: AddressInfo::new(0b1001).unwrap(),
                    destination: AddressInfo::new(0b0110).unwrap(),
                },
            )
            .expect("should successfully decode");

            assert_eq!(
                result,
                AddressHeader {
                    ia: ByEndpoint {
                        destination,
                        source
                    },
                    host: ByEndpoint {
                        destination: MaybeEncoded::Encoded([
                            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0
                        ]),
                        source: MaybeEncoded::Encoded([
                            8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0
                        ]),
                    }
                }
            );
            assert_eq!(data.remaining(), 0);
        }

        #[test]
        fn truncated() {
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
}
