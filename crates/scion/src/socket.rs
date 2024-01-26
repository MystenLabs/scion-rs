//! Sockets to send different types of higher-layer messages via SCION.
//!
//! The module has a similar functionality as the [Go snet library][snet].
//!
//! The [`UdpSocket`] implements the [`AsyncScionDatagram`][crate::pan::AsyncScionDatagram] trait and can thus
//! be used to send and receive UDP datagrams with a simple interface to specify the communication paths. This
//! can be composed with additional path management implemented in the
//! [pan::path_strategy][super::pan::path_strategy] module.
//!
//! The [`RawSocket`] can be used to send manually created [`ScionPacket`s][scion_proto::packet::ScionPacket]
//! including [SCMP packets][scion_proto::packet::ScionPacketScmp] and receive [raw SCION
//! packets][scion_proto::packet::ScionPacketRaw].
//!
//! [snet]: https://pkg.go.dev/github.com/scionproto/scion/pkg/snet

mod error;
pub use error::BindError;

mod raw;
pub use raw::RawSocket;

mod udp;
pub use udp::UdpSocket;

mod utils;
