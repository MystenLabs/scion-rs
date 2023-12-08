use scion_grpc::daemon::v1 as daemon_grpc;

use crate::{
    address::IsdAsn,
    path::{PathParseError, PathParseErrorKind},
};

/// SCION interface with the AS's ISD-ASN and the interface's ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathInterface {
    /// The ISD-ASN of the AS where the interface is located
    pub isd_asn: IsdAsn,
    /// The AS-local interface ID
    pub id: u16,
}

impl TryFrom<daemon_grpc::PathInterface> for PathInterface {
    type Error = PathParseError;

    fn try_from(i: daemon_grpc::PathInterface) -> Result<Self, Self::Error> {
        u16::try_from(i.id)
            .map(|id| PathInterface {
                isd_asn: IsdAsn::from(i.isd_as),
                id,
            })
            .map_err(|_| PathParseErrorKind::InvalidPathInterface.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_value() {
        assert_eq!(
            Ok(PathInterface {
                isd_asn: IsdAsn::WILDCARD,
                id: 0
            }),
            daemon_grpc::PathInterface { isd_as: 0, id: 0 }.try_into()
        );
    }

    #[test]
    fn id_out_of_range() {
        assert_eq!(
            PathInterface::try_from(daemon_grpc::PathInterface {
                isd_as: 0,
                id: u16::MAX as u64 + 1
            }),
            Err(PathParseError::from(
                PathParseErrorKind::InvalidPathInterface
            ))
        )
    }
}
