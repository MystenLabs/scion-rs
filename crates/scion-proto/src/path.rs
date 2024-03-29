//! SCION path types.
//!
//! This module contains types for SCION paths and metadata as well as encoding and decoding
//! functions.
//!
//! # Organisation
//!
//! - [`Path`] is the primary path type used with SCION sockets and applications. It encapsulates a
//!   [datplane path][DataplanePath] along with optional metadata about that path, such as its
//!   source and destination ASes, next hop on the SCION underlay, expiry time, and interface hops.
//!
//! - [`PathMetadata`] is metadata about a SCION [`Path`] that is communicated during beaconing or
//!   parsed from the path.
//!
//! - [`DataplanePath`] represents the various SCION paths that be placed within a SCION packet,
//!   and sent on the network. Currently, only the empty and standard SCION datplane path types are
//!   supported (see [`standard`]).

use std::{net::SocketAddr, ops::Deref};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use scion_grpc::daemon::v1 as daemon_grpc;
use tracing::warn;

use crate::{address::IsdAsn, packet::ByEndpoint, wire_encoding::WireDecode};

mod error;
pub use error::{DataplanePathErrorKind, PathParseError, PathParseErrorKind};

mod dataplane;
pub use dataplane::{DataplanePath, PathType, UnsupportedPathType};

pub mod standard;
pub use standard::StandardPath;

pub mod epic;
pub use epic::EpicAuths;

mod fingerprint;
pub use fingerprint::{FingerprintError, PathFingerprint};

mod metadata;
pub use metadata::{GeoCoordinates, LinkType, PathInterface, PathMetadata};

/// Minimum MTU along any path or within any AS.
pub const PATH_MIN_MTU: u16 = 1280;

/// A SCION end-to-end path with optional metadata.
///
/// `Path`s are generic over the underlying representation used by the [`DataplanePath`]. By
/// default, this is a [`Bytes`] object which allows relatively cheap copying of the overall path
/// as the Path data can then be shared across several `Path` instances.
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

impl<T> Path<T> {
    /// Creates a new `Path` instance with the provided dataplane path, its endpoints, and the
    /// next hop in the network underlay, but with no metadata.
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

        Self {
            dataplane_path: DataplanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn: ByEndpoint::with_cloned(isd_asn),
            metadata: Some(PathMetadata {
                expiration: DateTime::<Utc>::MAX_UTC,
                mtu: PATH_MIN_MTU,
                interfaces: vec![],
                ..PathMetadata::default()
            }),
        }
    }

    /// Returns the source of this path.
    pub const fn source(&self) -> IsdAsn {
        self.isd_asn.source
    }

    /// Returns the destination of this path.
    pub const fn destination(&self) -> IsdAsn {
        self.isd_asn.destination
    }

    /// Creates a new empty path with the provided source and destination ASes.
    ///
    /// For creating an empty, AS-local path see [`local()`][Self::local] instead.
    pub fn empty(isd_asn: ByEndpoint<IsdAsn>) -> Self {
        Self {
            dataplane_path: DataplanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn,
            metadata: None,
        }
    }

    /// Returns true iff the dataplane path is an empty path.
    pub fn is_empty(&self) -> bool {
        self.dataplane_path.is_empty()
    }

    /// Returns a fingerprint of the path.
    ///
    /// See [`PathFingerprint`] for more details.
    pub fn fingerprint(&self) -> Result<PathFingerprint, FingerprintError> {
        PathFingerprint::try_from(self)
    }

    /// Returns the length of the path in terms of the number of interfaces, if available.
    pub fn len(&self) -> Option<usize> {
        if self.is_empty() {
            Some(0)
        } else {
            self.metadata.as_ref().map(|m| m.interfaces.len())
        }
    }

    /// Returns the expiry time of the path if the path contains metadata, otherwise None.
    pub fn expiry_time(&self) -> Option<DateTime<Utc>> {
        self.metadata.as_ref().map(|metadata| metadata.expiration)
    }

    /// Returns true if the path contains an expiry time, and it is after now,
    /// false if the contained expiry time is at or before now, and None if the path
    /// does not contain an expiry time.
    pub fn is_expired(&self, now: DateTime<Utc>) -> Option<bool> {
        self.expiry_time().map(|t| t <= now)
    }

    /// Returns the number of interfaces traversed by the path, if available. Otherwise None.
    pub fn interface_count(&self) -> Option<usize> {
        self.metadata
            .as_ref()
            .map(|metadata| metadata.interfaces.len())
    }
}

impl<T> Path<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns a new `Path` with the old path's `dataplane_path` reversed and written to the
    /// provided buffer.
    ///
    /// Also reverses the order of `isd_asn`.
    ///
    /// # Panics
    ///
    /// Panics if `buf` has insufficient length. This can be prevented by ensuring a buffer size
    /// of at least [`DataplanePath::MAX_LEN`].
    pub fn reverse_to_slice(self, buf: &mut [u8]) -> Path<&mut [u8]> {
        let path_len = self.dataplane_path.raw().len();
        let dataplane_path = self.dataplane_path.reverse_to_slice(&mut buf[..path_len]);

        Path::new(
            dataplane_path,
            self.isd_asn.into_reversed(),
            self.underlay_next_hop,
        )
    }
}

impl Path<Bytes> {
    /// Attempts to parse the GRPC representation of a path into a [`Path`].
    #[tracing::instrument]
    pub fn try_from_grpc(
        mut value: daemon_grpc::Path,
        isd_asn: ByEndpoint<IsdAsn>,
    ) -> Result<Self, PathParseError> {
        let mut dataplane_path = Bytes::from(std::mem::take(&mut value.raw));
        if dataplane_path.is_empty() {
            return if isd_asn.are_equal() && isd_asn.destination.is_wildcard() {
                Ok(Path::empty(isd_asn))
            } else if isd_asn.are_equal() {
                Ok(Path::local(isd_asn.destination))
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
        let path = Path::try_from_grpc(
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
        let path = Path::try_from_grpc(
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
                    Path::try_from_grpc(
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
