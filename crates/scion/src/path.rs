use std::net::SocketAddr;

use bytes::Bytes;
use scion_grpc::daemon::v1 as daemon_grpc;

use crate::{address::IsdAsn, packet::ByEndpoint};

pub mod error;
pub use error::{DataplanePathErrorKind, PathParseError, PathParseErrorKind};

pub mod standard;

mod metadata;
pub use metadata::PathMetadata;

pub mod epic;
pub use epic::EpicAuths;

pub mod linktype;
use linktype::LinkType;

use self::standard::StandardPath;

/// A SCION end-to-end path with metadata
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    /// The raw bytes to be added as the path header to SCION dataplane packets
    dataplane_path: StandardPath,
    /// The underlay address (IP + port) of the next hop; i.e., the local border router
    underlay_next_hop: SocketAddr,
    /// The ISD-ASN where the path starts and ends
    pub isd_asn: ByEndpoint<IsdAsn>,
    /// Path metadata
    metadata: Option<PathMetadata>,
}

impl Path {
    pub fn try_from_grpc_with_endpoints(
        mut value: daemon_grpc::Path,
        isd_asn: ByEndpoint<IsdAsn>,
    ) -> Result<Self, PathParseError> {
        let dataplane_path = Bytes::from(std::mem::take(&mut value.raw));
        if dataplane_path.is_empty() {
            return Err(PathParseErrorKind::EmptyRaw.into());
        };
        let dataplane_path = StandardPath::decode_from_buffer(dataplane_path)
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidRaw))?;
        let underlay_next_hop = match &value.interface {
            Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay { address }),
            }) => address
                .parse()
                .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidInterface))?,
            _ => return Err(PathParseErrorKind::NoInterface.into()),
        };
        let metadata = Some(PathMetadata::try_from(value)?);

        Ok(Self {
            dataplane_path,
            underlay_next_hop,
            isd_asn,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    // Question(mlegner): Can we test this with real gRPC samples?

    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    const MINIMAL_RAW_PATH: [u8; 24] = [
        0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    fn empty_grpc_path() -> daemon_grpc::Path {
        daemon_grpc::Path {
            raw: MINIMAL_RAW_PATH.into(),
            interface: None,
            interfaces: vec![],
            mtu: 0,
            expiration: None,
            latency: vec![],
            bandwidth: vec![],
            geo: vec![],
            link_type: vec![],
            internal_hops: vec![],
            notes: vec![],
            epic_auths: None,
        }
    }

    #[test]
    fn successful_conversion() {
        let mut p = empty_grpc_path();
        p.interface = Some(daemon_grpc::Interface {
            address: Some(daemon_grpc::Underlay {
                address: "0.0.0.0:42".into(),
            }),
        });
        assert_eq!(
            Path::try_from_grpc_with_endpoints(
                p,
                ByEndpoint {
                    source: IsdAsn::WILDCARD,
                    destination: IsdAsn::WILDCARD
                }
            ),
            Ok(Path {
                dataplane_path: StandardPath::decode_from_buffer(MINIMAL_RAW_PATH.as_slice())
                    .unwrap(),
                underlay_next_hop: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 42),
                isd_asn: ByEndpoint {
                    source: IsdAsn::WILDCARD,
                    destination: IsdAsn::WILDCARD,
                },
                metadata: Some(PathMetadata::default()),
            })
        )
    }

    macro_rules! test_conversion_failure {
        ($name:ident, $path:ident, $statements:block, $error:expr) => {
            #[test]
            fn $name() {
                #[allow(unused_mut)] // False positive
                let mut $path = empty_grpc_path();
                $statements
                assert_eq!(
                    Path::try_from_grpc_with_endpoints(
                        $path,
                        ByEndpoint {
                            source: IsdAsn::WILDCARD,
                            destination: IsdAsn::WILDCARD,
                        },
                    ),
                    Err($error)
                )
            }
        };
    }

    test_conversion_failure!(
        empty_raw_path,
        p,
        {
            p.raw = vec![];
        },
        PathParseErrorKind::EmptyRaw.into()
    );
    test_conversion_failure!(no_interface, p, {}, PathParseErrorKind::NoInterface.into());
    test_conversion_failure!(
        invalid_interface,
        p,
        {
            p.interface = Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay {
                    address: "invalid address".into(),
                }),
            });
        },
        PathParseErrorKind::InvalidInterface.into()
    );
}
