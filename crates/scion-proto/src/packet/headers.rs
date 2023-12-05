mod common_header;
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

        Ok(Self {
            common: CommonHeader::new(
                endhosts,
                &path.dataplane_path,
                CommonHeader::LENGTH
                    + address_header.encoded_length()
                    + path.dataplane_path.encoded_length(),
                payload_length,
                next_header,
            )?,
            address: address_header,
            path: path.dataplane_path.clone(),
        })
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
