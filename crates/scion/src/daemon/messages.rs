use std::num::TryFromIntError;

use scion_grpc::daemon::v1::{self as daemon_grpc};
use scion_proto::address::IsdAsn;

pub fn sas_request_from(value: IsdAsn) -> daemon_grpc::AsRequest {
    daemon_grpc::AsRequest {
        isd_as: value.as_u64(),
    }
}

/// Information about an AS
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AsInfo {
    /// The AS's ISD-ASN
    pub isd_asn: IsdAsn,
    /// Is the AS a core AS?
    pub core: bool,
    /// The maximum transmission unit (MTU) in the AS
    pub mtu: u16,
}

impl TryFrom<daemon_grpc::AsResponse> for AsInfo {
    type Error = TryFromIntError;
    fn try_from(value: daemon_grpc::AsResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            isd_asn: value.isd_as.into(),
            core: value.core,
            mtu: value.mtu.try_into()?,
        })
    }
}

/// Path requests specifying source and destination ISD-ASN with some flags.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathRequest {
    /// The source ISD-ASN from which paths are requested.
    pub source: IsdAsn,
    /// The destination ISD-ASN to which paths are requested.
    pub destination: IsdAsn,
    /// Flags to request specific server behavior for this request.
    pub flags: PathRequestFlags,
}

/// Flags for path requests.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PathRequestFlags {
    /// Request fresh paths for this request instead of having the server reply from its cache.
    pub refresh: bool,
    /// Request hidden paths instead of standard paths.
    pub hidden: bool,
}

impl From<&PathRequest> for daemon_grpc::PathsRequest {
    fn from(value: &PathRequest) -> Self {
        Self {
            source_isd_as: value.source.as_u64(),
            destination_isd_as: value.destination.as_u64(),
            refresh: value.flags.refresh,
            hidden: value.flags.hidden,
        }
    }
}

impl PathRequest {
    /// Creates a new `PathRequest` to the provided destination with default flags and using the
    /// [`WILDCARD`][IsdAsn::WILDCARD] ISD-ASN indicating the local AS as the source.
    pub fn new(dst_isd_asn: IsdAsn) -> Self {
        Self {
            source: IsdAsn::WILDCARD,
            destination: dst_isd_asn,
            flags: PathRequestFlags::default(),
        }
    }

    /// Specifies an explicit source ISD-ASN in the request.
    pub fn with_src_isd_asn(mut self, src_isd_asn: IsdAsn) -> Self {
        self.source = src_isd_asn;
        self
    }

    /// Sets the [refresh][PathRequestFlags::refresh] flag for the request.
    pub fn with_refresh(mut self) -> Self {
        self.flags.refresh = true;
        self
    }

    /// Sets the [hidden][PathRequestFlags::hidden] flag for the request.
    pub fn with_hidden(mut self) -> Self {
        self.flags.hidden = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod as_info {
        use super::*;

        #[test]
        fn request_conversion() {
            assert_eq!(
                sas_request_from(IsdAsn::from(42)),
                daemon_grpc::AsRequest { isd_as: 42 }
            )
        }

        #[test]
        fn response_conversion() {
            assert_eq!(
                AsInfo::try_from(daemon_grpc::AsResponse {
                    isd_as: 42,
                    core: true,
                    mtu: 1500
                }),
                Ok(AsInfo {
                    isd_asn: IsdAsn::from(42),
                    core: true,
                    mtu: 1500
                })
            )
        }
    }

    mod path {
        use super::*;

        #[test]
        fn grpc_conversion() {
            assert_eq!(
                daemon_grpc::PathsRequest::from(&PathRequest::new(IsdAsn::from(1))),
                daemon_grpc::PathsRequest {
                    source_isd_as: 0,
                    destination_isd_as: 1,
                    refresh: false,
                    hidden: false,
                }
            )
        }

        #[test]
        fn full_construction() {
            let source = IsdAsn::from(42);
            let destination = IsdAsn::from(314);
            let request = PathRequest::new(destination);
            assert_eq!(
                request,
                PathRequest {
                    source: IsdAsn::WILDCARD,
                    destination,
                    flags: PathRequestFlags::default()
                }
            );
            assert_eq!(
                request.with_src_isd_asn(source),
                PathRequest {
                    source,
                    destination,
                    flags: PathRequestFlags::default()
                }
            );
            assert_eq!(
                request.with_hidden().with_refresh(),
                PathRequest {
                    source: IsdAsn::WILDCARD,
                    destination,
                    flags: PathRequestFlags {
                        refresh: true,
                        hidden: true
                    }
                }
            );
        }
    }
}
