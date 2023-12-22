//! Sockets to send different types of higher-layer messages via SCION.

mod error;
pub use error::BindError;

mod udp;
pub use udp::UdpSocket;
