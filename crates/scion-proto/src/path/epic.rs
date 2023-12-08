//! Types required for the EPIC path type.

use bytes::Bytes;
use scion_grpc::daemon::v1 as daemon_grpc;

/// Authenticators to compute EPIC hop validation fields (HVFs)
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EpicAuths {
    /// Key to compute the penultimate hop validation field
    pub phvf: Bytes,
    /// Key to compute the last hop validation field
    pub lhvf: Bytes,
}

impl From<daemon_grpc::EpicAuths> for EpicAuths {
    fn from(value: daemon_grpc::EpicAuths) -> Self {
        Self {
            phvf: value.auth_phvf.into(),
            lhvf: value.auth_lhvf.into(),
        }
    }
}
