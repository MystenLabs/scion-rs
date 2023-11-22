use std::num::{NonZeroU32, NonZeroU64};

use chrono::{DateTime, Duration, Utc};
use scion_grpc::daemon::v1 as daemon_grpc;
use tracing::warn;

use super::{EpicAuths, PathParseError};
use crate::path::error::PathParseErrorKind;

pub mod linktype;
pub use linktype::LinkType;

pub mod geo;
pub use geo::GeoCoordinates;

pub mod path_interface;
pub use path_interface::PathInterface;

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
    pub latency: Option<Vec<Option<Duration>>>,
    /// The bandwidth between any two consecutive interfaces, in kbps.
    /// Entry i describes the bandwidth between interfaces i and i+1.
    pub bandwidth_kbps: Option<Vec<Option<NonZeroU64>>>,
    /// Geographical position of the border routers along the path.
    /// Entry i describes the position of the router for interface i.
    pub geo: Option<Vec<Option<GeoCoordinates>>>,
    /// LinkType contains the announced link type of inter-domain links.
    /// Entry i describes the link between interfaces 2*i and 2*i+1.
    pub link_type: Option<Vec<LinkType>>,
    /// Number of AS-internal hops for the ASes on path.
    /// Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same
    /// AS.
    /// Consequently, there are no entries for the first and last ASes, as these
    /// are not traversed completely by the path.
    pub internal_hops: Option<Vec<Option<NonZeroU32>>>,
    /// Notes added by ASes on the path, in the order of occurrence.
    /// Entry i is the note of AS i on the path.
    pub notes: Option<Vec<String>>,
    /// Optional EPIC-HP authenticators used to calculate the PHVF and LHVF.
    pub epic_auths: Option<EpicAuths>,
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

    #[tracing::instrument]
    fn try_from(grpc_path: daemon_grpc::Path) -> Result<Self, Self::Error> {
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
            .and_then(|t| DateTime::from_timestamp(t.seconds, t.nanos.try_into().ok()?))
            .ok_or(PathParseError::from(PathParseErrorKind::InvalidExpiration))?;

        let mtu = grpc_path
            .mtu
            .try_into()
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidMtu))?;

        let interfaces = grpc_path
            .interfaces
            .into_iter()
            .map(|i| i.try_into().map_err(|e| warn!("{}", e)).ok())
            .collect();

        let latency = some_if_length_matches!(
            (grpc_path.latency, expected_count_links) =>
                into_iter()
                .map(|d| {
                    Duration::seconds(d.seconds)
                        .checked_add(&Duration::nanoseconds(d.nanos.into()))
                        .filter(|d| d >= &Duration::zero())
                })
                .collect()
        );

        let bandwidth_kbps = some_if_length_matches!(
            (grpc_path.bandwidth, expected_count_links) =>
                into_iter()
                .map(NonZeroU64::new)
                .collect()
        );

        let geo = some_if_length_matches!(
            (grpc_path.geo, count_interfaces) =>
                into_iter()
                .map(GeoCoordinates::from_grpc_or_none)
                .collect()
        );

        let link_type = some_if_length_matches!(
            (grpc_path.link_type, expected_count_links_inter) =>
                into_iter()
                .map(LinkType::from)
                .collect()
        );

        let internal_hops = some_if_length_matches!(
            (grpc_path.internal_hops, expected_count_links_intra) =>
                into_iter()
                .map(NonZeroU32::new)
                .collect()
        );

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
