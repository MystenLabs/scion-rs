//! SCION path types.
//!
//! This module contains types for SCION paths and metadata as well as encoding and decoding
//! functions.

use std::{net::SocketAddr, ops::Deref};

use bytes::Bytes;
use scion_grpc::daemon::v1 as daemon_grpc;
use tracing::warn;

use crate::{address::IsdAsn, packet::ByEndpoint, wire_encoding::WireDecode};

pub mod error;
pub use error::{DataplanePathErrorKind, PathParseError, PathParseErrorKind};

pub mod dataplane;
pub use dataplane::{DataplanePath, PathType, UnsupportedPathType};

pub mod standard;
pub use standard::StandardPath;

mod metadata;
pub use metadata::{GeoCoordinates, LinkType, PathInterface, PathMetadata};

pub mod epic;
pub use epic::EpicAuths;

/// A SCION end-to-end path with optional metadata.
#[derive(Debug, Clone)]
pub struct Path<T = Bytes> {
    /// The raw bytes to be added as the path header to SCION dataplane packets.
    pub dataplane_path: DataplanePath<T>,
    /// The underlay address (IP + port) of the next hop; i.e., the local border router.
    pub underlay_next_hop: Option<SocketAddr>,
    /// The ISD-ASN where the path starts and ends.
    pub isd_asn: ByEndpoint<IsdAsn>,
    /// Path metadata.
    pub metadata: Option<PathMetadata>,
}

#[allow(missing_docs)]
impl<T> Path<T> {
    pub fn new(
        dataplane_path: DataplanePath<T>,
        isd_asn: ByEndpoint<IsdAsn>,
        underlay_next_hop: Option<SocketAddr>,
    ) -> Self {
        Self {
            dataplane_path,
            underlay_next_hop,
            isd_asn,
            metadata: None,
        }
    }

    /// Returns a path for sending packets within the specified AS.
    ///
    /// # Panics
    ///
    /// Panics if the AS is a wildcard AS.
    pub fn local(isd_asn: IsdAsn) -> Self {
        assert!(!isd_asn.is_wildcard(), "no local path for wildcard AS");
        Self::empty(ByEndpoint::with_cloned(isd_asn))
    }

    pub fn empty(isd_asn: ByEndpoint<IsdAsn>) -> Self {
        Self {
            dataplane_path: DataplanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn,
            metadata: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.dataplane_path.is_empty()
    }
}

#[allow(missing_docs)]
impl Path<Bytes> {
    #[tracing::instrument]
    pub fn try_from_grpc_with_endpoints(
        mut value: daemon_grpc::Path,
        isd_asn: ByEndpoint<IsdAsn>,
    ) -> Result<Self, PathParseError> {
        let mut dataplane_path = Bytes::from(std::mem::take(&mut value.raw));
        if dataplane_path.is_empty() {
            return if isd_asn.are_equal() {
                Ok(Path::empty(isd_asn))
            } else {
                Err(PathParseErrorKind::EmptyRaw.into())
            };
        };
        let dataplane_path = StandardPath::decode(&mut dataplane_path)
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidRaw))?
            .into();

        let underlay_next_hop = match &value.interface {
            Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay { address }),
            }) => address
                .parse()
                .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidInterface))?,
            // TODO: Determine if the daemon returns paths that are strictly on the host.
            // If so, this is only an error if the path is non-empty
            _ => return Err(PathParseErrorKind::NoInterface.into()),
        };
        let underlay_next_hop = Some(underlay_next_hop);

        let metadata = PathMetadata::try_from(value)
            .map_err(|e| {
                warn!("{}", e);
                e
            })
            .ok();

        Ok(Self {
            dataplane_path,
            underlay_next_hop,
            isd_asn,
            metadata,
        })
    }
}

impl From<Path<&mut [u8]>> for Path<Bytes> {
    fn from(value: Path<&mut [u8]>) -> Self {
        Self {
            dataplane_path: value.dataplane_path.into(),
            underlay_next_hop: value.underlay_next_hop,
            isd_asn: value.isd_asn,
            metadata: value.metadata,
        }
    }
}

impl<T> PartialEq for Path<T>
where
    T: Deref<Target = [u8]>,
{
    fn eq(&self, other: &Self) -> bool {
        self.dataplane_path == other.dataplane_path
            && self.underlay_next_hop == other.underlay_next_hop
            && self.isd_asn == other.isd_asn
            && self.metadata == other.metadata
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::path::metadata::{test_utils::*, PathInterface};

    #[test]
    fn successful_empty_path() {
        let path = Path::try_from_grpc_with_endpoints(
            daemon_grpc::Path {
                raw: vec![],
                ..minimal_grpc_path()
            },
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            },
        )
        .expect("conversion should succeed");
        assert!(path.underlay_next_hop.is_none());
        assert!(path.metadata.is_none());
        assert!(path.dataplane_path.is_empty());
        assert_eq!(
            path.isd_asn,
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            }
        );
    }

    #[test]
    fn successful_conversion() {
        let path = Path::try_from_grpc_with_endpoints(
            minimal_grpc_path(),
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            },
        )
        .expect("conversion should succeed");
        assert_eq!(
            path.underlay_next_hop.unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 42)
        );
        assert_eq!(
            path.isd_asn,
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            }
        );
        assert_eq!(
            path.metadata,
            Some(PathMetadata {
                interfaces: vec![
                    Some(PathInterface {
                        isd_asn: IsdAsn::WILDCARD,
                        id: 0
                    });
                    2
                ],
                internal_hops: Some(vec![]),
                ..Default::default()
            })
        );
    }

    macro_rules! test_conversion_failure {
        ($name:ident; $($field:ident : $value:expr),* ; $error:expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    Path::try_from_grpc_with_endpoints(
                        daemon_grpc::Path {
                            $($field : $value,)*
                            ..minimal_grpc_path()
                        },
                        ByEndpoint {
                            source: "1-1".parse().unwrap(),
                            destination: "1-2".parse().unwrap(),
                        },
                    ),
                    Err($error)
                )
            }
        };
    }

    test_conversion_failure!(
        empty_raw_path_different_ases;
        raw: vec![];
        PathParseErrorKind::EmptyRaw.into()
    );
    test_conversion_failure!(no_interface; interface: None; PathParseErrorKind::NoInterface.into());
    test_conversion_failure!(
        invalid_interface;
        interface: Some(daemon_grpc::Interface {
            address: Some(daemon_grpc::Underlay {
                address: "invalid address".into(),
            }),
        });
        PathParseErrorKind::InvalidInterface.into()
    );
}
