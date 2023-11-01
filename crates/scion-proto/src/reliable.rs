use std::net::SocketAddr;

use bytes::Bytes;

mod common_header;
pub use common_header::DecodeError;

mod relay_protocol;
pub use relay_protocol::{ReceiveError, ReliableRelayProtocol, SendError};

mod parser;
mod registration;
mod wire_utils;

const ADDRESS_TYPE_OCTETS: usize = 1;

/// A packet received over the [`ReliableRelayProtocol`].
#[derive(Debug)]
pub struct Packet {
    /// The last AS-level host the packet traversed, such as the ingress border router or the
    /// sending host if it is located in the same AS.
    pub last_host: Option<SocketAddr>,
    /// The content of the single packet as a sequence of Bytes objects.
    pub content: Vec<Bytes>,
}
