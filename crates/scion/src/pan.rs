//! Path-aware networking socket and services.
//!
//! This module has similar goals like the [Go pan library][pan].
//!
//! [pan]: https://pkg.go.dev/github.com/netsec-ethz/scion-apps/pkg/pan

mod datagram;
pub use datagram::{AsyncScionDatagram, PathAwareDatagram};

mod path_service;
pub use path_service::{AsyncPathService, PathLookupError};

mod error;
pub use error::{PathErrorKind, ReceiveError, SendError};

pub mod path_strategy;
