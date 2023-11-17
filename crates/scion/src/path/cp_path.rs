use std::net::SocketAddr;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use scion_grpc::daemon::v1 as daemon_grpc;
use tracing::{span, warn, Level};

use super::{EpicAuths, LinkType};
use crate::{address::IsdAsn, packet::ByEndpoint};

#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub enum PathParseError {
    #[error("Empty raw path")]
    EmptyRaw,
    #[error("No underlay address for local border router")]
    NoInterface,
    #[error("Invalid underlay address for local border router {0}")]
    InvalidInterface(String),
    #[error("Invalid interface {0} for on-path AS {1}")]
    InvalidPathInterface(u64, IsdAsn),
    #[error("Invalid expiration timestamp")]
    InvalidExpiration,
    #[error("Negative on-path latency")]
    NegativeLatency,
    #[error("Invalid on-path latency")]
    InvalidLatency,
    #[error("Invalid link type")]
    InvalidLinkType,
    #[error("Invalid MTU")]
    InvalidMtu,
}

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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathMetadata {
    /// The point in time when this path expires.
    expiration: Option<DateTime<Utc>>,
    /// The maximum transmission unit (MTU) on the path in bytes.
    mtu: u16,
    /// The list of interfaces the path is composed of.
    interfaces: Vec<(IsdAsn, u16)>,
    /// Latencies between any two consecutive interfaces.
    /// Entry i describes the latency between interface i and i+1.
    /// Consequently, there are N-1 entries for N interfaces.
    /// A 0-value indicates that the AS did not announce a latency for this hop.
    latency: Vec<Duration>,
    /// The bandwidth between any two consecutive interfaces, in kbps.
    /// Entry i describes the bandwidth between interfaces i and i+1.
    /// A 0-value indicates that the AS did not announce a bandwidth for this
    /// hop.
    bandwidth_kbps: Vec<u64>,
    /// Geographical position of the border routers along the path.
    /// Entry i describes the position of the router for interface i.
    /// A 0-value indicates that the AS did not announce a position for this
    /// router.
    geo: Vec<GeoCoordinates>,
    /// LinkType contains the announced link type of inter-domain links.
    /// Entry i describes the link between interfaces 2*i and 2*i+1.
    link_type: Vec<LinkType>,
    /// Number of AS-internal hops for the ASes on path.
    /// Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same
    /// AS.
    /// Consequently, there are no entries for the first and last ASes, as these
    /// are not traversed completely by the path.
    internal_hops: Vec<u32>,
    /// Notes added by ASes on the path, in the order of occurrence.
    /// Entry i is the note of AS i on the path.
    notes: Vec<String>,
    /// EpicAuths contains the EPIC authenticators used to calculate the PHVF and LHVF.
    epic_auths: Option<EpicAuths>,
}

/// Geographic coordinates with latitude and longitude
// Using a custom type to prevent importing a library here
#[derive(PartialEq, Clone, Debug, Default)]
pub struct GeoCoordinates {
    pub lat: f32,
    pub long: f32,
    pub address: String,
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

impl TryFrom<daemon_grpc::Path> for PathMetadata {
    type Error = PathParseError;

    fn try_from(grpc_path: daemon_grpc::Path) -> Result<Self, Self::Error> {
        span!(
            Level::WARN,
            "trying to convert metadata from gRPC path to internal type"
        );

        // TODO(mlegner): Check length of various entries.

        let expiration = match &grpc_path.expiration {
            Some(t) => Some(
                DateTime::<Utc>::from_timestamp(
                    t.seconds,
                    t.nanos
                        .try_into()
                        .map_err(|_| PathParseError::InvalidExpiration)?,
                )
                .ok_or(PathParseError::InvalidExpiration)?,
            ),
            None => {
                warn!("path without expiration");
                None
            }
        };
        let mtu = grpc_path
            .mtu
            .try_into()
            .map_err(|_| PathParseError::InvalidMtu)?;
        let interfaces = grpc_path
            .interfaces
            .into_iter()
            .map(|i| {
                let isd_asn = IsdAsn::from(i.isd_as);
                Ok((
                    isd_asn,
                    u16::try_from(i.id)
                        .map_err(|_| PathParseError::InvalidPathInterface(i.id, isd_asn))?,
                ))
            })
            .collect::<Result<Vec<_>, PathParseError>>()
            .unwrap_or_else(|e| {
                // We cannot simply skip the problematic entries as otherwise the order would be wrong;
                // an alternative would be to use a map instead of a vector.
                warn!(?e, "invalid path interfaces");
                vec![]
            });
        let latency = grpc_path
            .latency
            .into_iter()
            .map(|mut d| {
                d.normalize();
                if d.seconds < 0 {
                    Err(PathParseError::NegativeLatency)
                } else {
                    Duration::seconds(d.seconds)
                        .checked_add(&Duration::nanoseconds(d.nanos.into()))
                        .ok_or(PathParseError::InvalidLatency)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| {
                // We cannot simply skip the problematic entries as otherwise the order would be wrong;
                // an alternative would be to use a map instead of a vector.
                warn!(?e, "invalid path latencies");
                vec![]
            });
        let bandwidth = grpc_path.bandwidth;
        let geo = grpc_path
            .geo
            .into_iter()
            .map(GeoCoordinates::from)
            .collect();
        let link_type = grpc_path
            .link_type
            .into_iter()
            .map(LinkType::try_from)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| {
                // We cannot simply skip the problematic entries as otherwise the order would be wrong;
                // an alternative would be to use a map instead of a vector.
                warn!(?e, "invalid interface types");
                vec![]
            });
        let internal_hops = grpc_path.internal_hops;
        let notes = grpc_path.notes;
        let epic_auths = grpc_path.epic_auths.map(EpicAuths::from);

        Ok(Self {
            expiration,
            mtu,
            interfaces,
            latency,
            bandwidth_kbps: bandwidth,
            geo,
            link_type,
            internal_hops,
            notes,
            epic_auths,
        })
    }
}

impl Path {
    pub fn try_from_grpc_with_endpoints(
        mut value: daemon_grpc::Path,
        isd_asn: ByEndpoint<IsdAsn>,
    ) -> Result<Self, PathParseError> {
        let dataplane_path = Bytes::from(std::mem::take(&mut value.raw));
        if dataplane_path.is_empty() {
            return Err(PathParseError::EmptyRaw);
        };
        let underlay_next_hop = match &value.interface {
            Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay { address }),
            }) => address
                .parse()
                .map_err(|_| PathParseError::InvalidInterface(address.clone()))?,
            _ => return Err(PathParseError::NoInterface),
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

    fn empty_grpc_path() -> daemon_grpc::Path {
        daemon_grpc::Path {
            raw: vec![],
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
        p.raw = vec![1];
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
                dataplane_path: Bytes::from_static(&[1]),
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

    test_conversion_failure!(empty_raw_path, p, {}, PathParseError::EmptyRaw);
    test_conversion_failure!(
        no_interface,
        p,
        {
            p.raw = vec![0];
        },
        PathParseError::NoInterface
    );
    test_conversion_failure!(
        invalid_interface,
        p,
        {
            p.raw = vec![0];
            p.interface = Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay {
                    address: "invalid address".into(),
                }),
            });
        },
        PathParseError::InvalidInterface("invalid address".into())
    );
}
