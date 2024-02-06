//! Types and conversion for the SCION Control Message Protocol.
//!
//! This implements the specification at the [SCION documentation page][scion-doc-scmp] but currently
//! does not cover DRKey-based authentication.
//!
//! [scion-doc-scmp]: https://docs.scion.org/en/latest/protocols/scmp.html

mod error;
pub use error::ScmpDecodeError;

mod messages;
pub use messages::*;

mod raw;
pub use raw::ScmpMessageRaw;

/// Trait implemented by all SCMP messages.
pub trait ScmpMessageBase {
    /// Returns the SCMP type of this message.
    fn get_type(&self) -> ScmpType;

    /// Returns the additional SCMP code of this message.
    fn code(&self) -> u8 {
        0
    }

    /// Returns true iff `self` is an error message.
    fn is_error(&self) -> bool {
        self.get_type().is_error()
    }

    /// Returns true iff `self` is an informational message.
    fn is_informational(&self) -> bool {
        self.get_type().is_informational()
    }
}

/// SCION protocol number for SCMP.
///
/// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
///
///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#protnum
pub const SCMP_PROTOCOL_NUMBER: u8 = 202;
