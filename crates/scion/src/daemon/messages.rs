use scion_grpc::daemon::v1::{self as daemon_grpc};

use crate::address::IsdAsn;

impl From<IsdAsn> for daemon_grpc::AsRequest {
    fn from(value: IsdAsn) -> Self {
        Self {
            isd_as: value.as_u64(),
        }
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

impl From<daemon_grpc::AsResponse> for AsInfo {
    fn from(value: daemon_grpc::AsResponse) -> Self {
        Self {
            isd_asn: value.isd_as.into(),
            core: value.core,
            // Question(mlegner): Should we return an error instead?
            mtu: value.mtu.try_into().expect("MTU should fit into a u16"),
        }
    }
}

/// Path requests specifying source and destination ISD-ASN with some flags
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathRequest {
    pub src_isd_asn: IsdAsn,
    pub dst_isd_asn: IsdAsn,
    pub flags: PathRequestFlags,
}

/// Flags for path requests
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PathRequestFlags {
    pub refresh: bool,
    pub hidden: bool,
}

impl From<&PathRequest> for daemon_grpc::PathsRequest {
    fn from(value: &PathRequest) -> Self {
        Self {
            source_isd_as: value.src_isd_asn.as_u64(),
            destination_isd_as: value.dst_isd_asn.as_u64(),
            refresh: value.flags.refresh,
            hidden: value.flags.hidden,
        }
    }
}

impl PathRequest {
    pub fn new(dst_isd_asn: IsdAsn) -> Self {
        Self {
            src_isd_asn: IsdAsn::WILDCARD,
            dst_isd_asn,
            flags: PathRequestFlags::default(),
        }
    }

    pub fn with_src_isd_asn(mut self, src_isd_asn: IsdAsn) -> Self {
        self.src_isd_asn = src_isd_asn;
        self
    }

    pub fn with_refresh(mut self) -> Self {
        self.flags.refresh = true;
        self
    }

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
                daemon_grpc::AsRequest::from(IsdAsn::from(42)),
                daemon_grpc::AsRequest { isd_as: 42 }
            )
        }

        #[test]
        fn response_conversion() {
            assert_eq!(
                AsInfo::from(daemon_grpc::AsResponse {
                    isd_as: 42,
                    core: true,
                    mtu: 1500
                }),
                AsInfo {
                    isd_asn: IsdAsn::from(42),
                    core: true,
                    mtu: 1500
                }
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
            let src_isd_asn = IsdAsn::from(42);
            let dst_isd_asn = IsdAsn::from(314);
            let request = PathRequest::new(dst_isd_asn);
            assert_eq!(
                request,
                PathRequest {
                    src_isd_asn: IsdAsn::WILDCARD,
                    dst_isd_asn,
                    flags: PathRequestFlags::default()
                }
            );
            assert_eq!(
                request.with_src_isd_asn(src_isd_asn),
                PathRequest {
                    src_isd_asn,
                    dst_isd_asn,
                    flags: PathRequestFlags::default()
                }
            );
            assert_eq!(
                request.with_hidden().with_refresh(),
                PathRequest {
                    src_isd_asn: IsdAsn::WILDCARD,
                    dst_isd_asn,
                    flags: PathRequestFlags {
                        refresh: true,
                        hidden: true
                    }
                }
            );
        }
    }
}
