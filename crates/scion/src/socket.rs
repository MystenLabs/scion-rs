//! Sockets to send different types of higher-layer messages via SCION.

mod error;
pub use error::BindError;

mod raw;
pub use raw::RawSocket;

mod udp;
pub use udp::UdpSocket;

mod utils;
