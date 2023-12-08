mod common_header;
use std::num::NonZeroU8;

use bytes::BufMut;
pub use common_header::{AddressInfo, CommonHeader, FlowId, Version};

mod address_header;
pub use address_header::{AddressHeader, RawHostAddress};

mod path_header;
pub use path_header::DataplanePath;

use super::{EncodeError, InadequateBufferSize};
use crate::{address::SocketAddr, path::Path, wire_encoding::WireEncode};

/// SCION packet headers
#[derive(Debug, Clone)]
pub struct ScionHeaders {
    /// Metadata about the remaining headers and payload.
    pub common: CommonHeader,
    /// Source and destination addresses.
    pub address: AddressHeader,
    /// The path to the destination, when necessary.
    pub path: DataplanePath,
}

impl ScionHeaders {
    pub fn new(
        endhosts: &ByEndpoint<SocketAddr>,
        path: &Path,
        next_header: u8,
        payload_length: usize,
    ) -> Result<Self, EncodeError> {
        let address_header = AddressHeader::from(*endhosts);

        let header_length = CommonHeader::LENGTH
            + address_header.encoded_length()
            + path.dataplane_path.encoded_length();
        let header_length_factor = NonZeroU8::new(
            (header_length / CommonHeader::HEADER_LENGTH_MULTIPLICAND)
                .try_into()
                .map_err(|_| EncodeError::HeaderTooLarge)?,
        )
        .expect("cannot be 0");

        let common_header = CommonHeader {
            version: Version::default(),
            traffic_class: 0,
            flow_id: Self::simple_flow_id(endhosts),
            next_header,
            header_length_factor,
            payload_length: payload_length
                .try_into()
                .map_err(|_| EncodeError::PayloadTooLarge)?,
            path_type: path.dataplane_path.path_type(),
            address_info: endhosts.map(SocketAddr::address_info),
            reserved: 0,
        };

        Ok(Self {
            common: common_header,
            address: address_header,
            path: path.dataplane_path.clone(),
        })
    }

    // TODO(mlegner): More sophisticated flow ID?
    /// Simple flow ID containing the XOR of source and destination port with a prepended 1
    /// to prevent a value of 0.
    fn simple_flow_id(endhosts: &ByEndpoint<SocketAddr>) -> FlowId {
        (0x1_0000 | (endhosts.source.port() ^ endhosts.destination.port()) as u32).into()
    }
}

impl WireEncode for ScionHeaders {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        CommonHeader::LENGTH + self.address.encoded_length() + self.path.encoded_length()
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        self.common.encode_to_unchecked(buffer);
        self.address.encode_to_unchecked(buffer);
        self.path.encode_to_unchecked(buffer);
    }
}

/// Instances of an object associated with both a source and destination endpoint.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ByEndpoint<T> {
    pub destination: T,
    pub source: T,
}

impl<T: Clone> ByEndpoint<T> {
    /// Create a new instance where both the source and destination have the same value.
    pub fn with_cloned(source_and_destination: T) -> Self {
        Self {
            destination: source_and_destination.clone(),
            source: source_and_destination,
        }
    }
}

impl<T> ByEndpoint<T> {
    pub fn map<U, F>(&self, function: F) -> ByEndpoint<U>
    where
        F: Fn(&T) -> U,
    {
        ByEndpoint {
            destination: function(&self.destination),
            source: function(&self.source),
        }
    }
}

impl<T: PartialEq> ByEndpoint<T> {
    pub fn are_equal(&self) -> bool {
        self.source == self.destination
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::packet::headers::path_header::PathType;

    #[test]
    fn new_success() -> Result<(), Box<dyn std::error::Error>> {
        let endpoints = ByEndpoint {
            source: SocketAddr::from_str("[1-1,10.0.0.1]:10001").unwrap(),
            destination: SocketAddr::from_str("[1-2,10.0.0.2]:10002").unwrap(),
        };
        let headers = ScionHeaders::new(
            &endpoints,
            &Path::empty(endpoints.map(SocketAddr::isd_asn)),
            0,
            0,
        )?;
        let common_header = headers.common;
        assert_eq!(common_header.flow_id, 0x1_0003.into());
        assert!(CommonHeader::SUPPORTED_VERSIONS
            .iter()
            .any(|v| v == &common_header.version));
        assert_eq!(common_header.header_length_factor, 9.try_into().unwrap());
        assert_eq!(common_header.path_type, PathType::Empty);
        assert_eq!(common_header.remaining_header_length(), 24);
        assert_eq!(common_header.payload_size(), 0);
        Ok(())
    }
}