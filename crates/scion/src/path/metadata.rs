use std::net::SocketAddr;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use scion_grpc::daemon::v1 as daemon_grpc;
use tracing::{span, warn, Level};

use super::{EpicAuths, LinkType, PathParseError};
use crate::{address::IsdAsn, packet::ByEndpoint, path::error::PathParseErrorKind};

/// A SCION end-to-end path with metadata
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    /// The raw bytes to be added as the path header to SCION dataplane packets
    dataplane_path: Bytes,
    /// The underlay address (IP + port) of the next hop; i.e., the local border router
    underlay_next_hop: SocketAddr,
    /// The ISD-ASN where the path starts and ends
    pub isd_asn: ByEndpoint<IsdAsn>,
    /// Path metadata
    metadata: Option<PathMetadata>,
}

/// Metadata of SCION end-to-end paths
///
/// Fields are set to `None` if unset or trying to convert an invalid value.
/// For vectors, individual entries are `None` if trying to convert an invalid value.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathMetadata {
    /// The point in time when this path expires.
    pub expiration: DateTime<Utc>,
    /// The maximum transmission unit (MTU) on the path in bytes.
    pub mtu: u16,
    /// The list of interfaces the path is composed of.
    pub interfaces: Vec<Option<PathInterface>>,
    /// Latencies between any two consecutive interfaces.
    /// Entry i describes the latency between interface i and i+1.
    /// Consequently, there are N-1 entries for N interfaces.
    /// A 0-value indicates that the AS did not announce a latency for this hop.
    pub latency: Option<Vec<Option<Duration>>>,
    /// The bandwidth between any two consecutive interfaces, in kbps.
    /// Entry i describes the bandwidth between interfaces i and i+1.
    /// A 0-value indicates that the AS did not announce a bandwidth for this
    /// hop.
    pub bandwidth_kbps: Option<Vec<u64>>,
    /// Geographical position of the border routers along the path.
    /// Entry i describes the position of the router for interface i.
    /// A 0-value indicates that the AS did not announce a position for this
    /// router.
    pub geo: Option<Vec<GeoCoordinates>>,
    /// LinkType contains the announced link type of inter-domain links.
    /// Entry i describes the link between interfaces 2*i and 2*i+1.
    pub link_type: Option<Vec<LinkType>>,
    /// Number of AS-internal hops for the ASes on path.
    /// Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same
    /// AS.
    /// Consequently, there are no entries for the first and last ASes, as these
    /// are not traversed completely by the path.
    pub internal_hops: Option<Vec<u32>>,
    /// Notes added by ASes on the path, in the order of occurrence.
    /// Entry i is the note of AS i on the path.
    pub notes: Option<Vec<String>>,
    /// EpicAuths contains the EPIC authenticators used to calculate the PHVF and LHVF.
    pub epic_auths: Option<EpicAuths>,
}

/// Geographic coordinates with latitude and longitude
// Using a custom type to prevent importing a library here
#[derive(PartialEq, Clone, Debug, Default)]
pub struct GeoCoordinates {
    pub lat: f32,
    pub long: f32,
    pub address: String,
}

/// SCION interface with the AS's ISD-ASN and the interface's ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathInterface {
    pub isd_asn: IsdAsn,
    pub id: u16,
}

impl From<daemon_grpc::GeoCoordinates> for GeoCoordinates {
    fn from(value: daemon_grpc::GeoCoordinates) -> Self {
        Self {
            lat: value.latitude,
            long: value.longitude,
            address: value.address,
        }
    }
}

macro_rules! some_if_length_matches {
    ($input_vec:expr, $expected_length:expr, $result:expr) => {
        if $input_vec.len() == $expected_length {
            Some($result)
        } else {
            None
        }
    };
    (($input_vec:expr, $expected_length:expr) => $($method:ident ($($param:expr),*)).*) => {
        some_if_length_matches!($input_vec, $expected_length, $input_vec.$($method ($($param),*)).*)
    };
    ($input_vec:expr, $expected_length:expr) => {
        some_if_length_matches!($input_vec, $expected_length, $input_vec)
    };
}

impl TryFrom<daemon_grpc::Path> for PathMetadata {
    type Error = PathParseError;

    fn try_from(grpc_path: daemon_grpc::Path) -> Result<Self, Self::Error> {
        span!(
            Level::WARN,
            "trying to convert metadata from gRPC path to internal type"
        );

        // We check that the metadata is itself consistent, including the lengths of various metadata vectors.
        // We *do not* check if it is consistent with the raw dataplane path.
        let count_interfaces = grpc_path.interfaces.len();
        if count_interfaces == 0 || count_interfaces % 2 != 0 {
            return Err(PathParseErrorKind::InvalidNumberOfInterfaces.into());
        }
        let expected_count_ases = count_interfaces / 2 + 1;
        let expected_count_links = count_interfaces - 1;
        let expected_count_links_intra = count_interfaces / 2 - 1;
        let expected_count_links_inter = count_interfaces / 2;

        let expiration = grpc_path
            .expiration
            .and_then(|t| {
                u32::try_from(t.nanos)
                    .ok()
                    .and_then(|n| DateTime::<Utc>::from_timestamp(t.seconds, n))
            })
            .ok_or(PathParseError::from(PathParseErrorKind::InvalidExpiration))?;

        let mtu = grpc_path
            .mtu
            .try_into()
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidMtu))?;

        let interfaces = grpc_path
            .interfaces
            .into_iter()
            .map(|i| {
                if let Ok(id) = u16::try_from(i.id) {
                    Some(PathInterface {
                        isd_asn: IsdAsn::from(i.isd_as),
                        id,
                    })
                } else {
                    warn!("invalid path interface");
                    None
                }
            })
            .collect();

        let latency = some_if_length_matches!(
            (grpc_path.latency, expected_count_links) =>
                into_iter()
                .map(|mut d| {
                    d.normalize();
                    if d.seconds < 0 {
                        warn!("negative path latency");
                        None
                    } else {
                        Duration::seconds(d.seconds)
                            .checked_add(&Duration::nanoseconds(d.nanos.into()))
                    }
                })
                .collect()
        );

        let bandwidth_kbps = some_if_length_matches!(grpc_path.bandwidth, expected_count_links);

        let geo = some_if_length_matches!((grpc_path.geo, count_interfaces) =>
            into_iter()
            .map(GeoCoordinates::from)
            .collect()
        );

        let link_type = some_if_length_matches!((grpc_path.link_type, expected_count_links_inter) =>
            into_iter()
            .map(LinkType::from)
            .collect()
        );

        let internal_hops =
            some_if_length_matches!(grpc_path.internal_hops, expected_count_links_intra);

        let notes = some_if_length_matches!(grpc_path.notes, expected_count_ases);

        let epic_auths = grpc_path.epic_auths.map(EpicAuths::from);

        Ok(Self {
            expiration,
            mtu,
            interfaces,
            latency,
            bandwidth_kbps,
            geo,
            link_type,
            internal_hops,
            notes,
            epic_auths,
        })
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    pub const MINIMAL_RAW_PATH: [u8; 24] = [
        0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    pub fn minimal_grpc_path() -> daemon_grpc::Path {
        daemon_grpc::Path {
            raw: MINIMAL_RAW_PATH.into(),
            interface: Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay {
                    address: "0.0.0.0:42".into(),
                }),
            }),
            interfaces: vec![daemon_grpc::PathInterface { isd_as: 0, id: 0 }; 2],
            mtu: 0,
            expiration: Some(prost_types::Timestamp::default()),
            latency: vec![],
            bandwidth: vec![],
            geo: vec![],
            link_type: vec![],
            internal_hops: vec![],
            notes: vec![],
            epic_auths: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use prost_types::Timestamp;

    use super::{test_utils::*, *};

    macro_rules! test_invalid_metadata {
        ($name:ident; $($field:ident : $value:expr),*; $error_type:expr) => {
            #[test]
            fn $name() {
                assert_eq!(PathMetadata::try_from(daemon_grpc::Path {
                    $($field : $value,)*
                    ..minimal_grpc_path()
                }), Err($error_type.into()))
            }
        };
    }

    test_invalid_metadata!(
        empty_interfaces;
        interfaces: vec![];
        PathParseErrorKind::InvalidNumberOfInterfaces
    );
    test_invalid_metadata!(
        single_interfaces;
        interfaces: vec![daemon_grpc::PathInterface{ isd_as: 0, id: 0 }];
        PathParseErrorKind::InvalidNumberOfInterfaces
    );
    test_invalid_metadata!(
        missing_mtu;
        mtu: u32::from(u16::MAX) + 1;
        PathParseErrorKind::InvalidMtu
    );
    test_invalid_metadata!(
        missing_expiration;
        expiration: None;
        PathParseErrorKind::InvalidExpiration
    );
    test_invalid_metadata!(
        negative_expiration_nanos;
        expiration: Some(Timestamp{ seconds: 0, nanos: -1 });
        PathParseErrorKind::InvalidExpiration
    );
    test_invalid_metadata!(
        invalid_expiration;
        expiration: Some(Timestamp{ seconds: i64::MAX, nanos: 0 });
        PathParseErrorKind::InvalidExpiration
    );
}
