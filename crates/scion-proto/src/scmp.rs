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

use crate::packet::AddressHeader;

/// Trait implemented by all SCMP messages.
pub trait ScmpMessageBase {
    /// Returns the SCMP type of this message.
    fn get_type(&self) -> ScmpType;

    /// Returns the additional SCMP code of this message.
    fn code(&self) -> u8 {
        0
    }
}

/// Trait implemented by all SCMP messages to handle checksums.
pub trait ScmpMessageChecksum: ScmpMessageBase {
    /// Returns the currently stored checksum of the message.
    fn checksum(&self) -> u16;

    /// Clears then sets the checksum to the value returned by [`Self::calculate_checksum()`].
    fn set_checksum(&mut self, address_header: &AddressHeader);

    /// Compute the checksum for this SCMP message using the provided address header.
    fn calculate_checksum(&self, address_header: &AddressHeader) -> u16;

    /// Returns true if the checksum successfully verifies, otherwise false.
    fn verify_checksum(&self, address_header: &AddressHeader) -> bool {
        self.calculate_checksum(address_header) == 0
    }
}

/// SCION protocol number for SCMP.
///
/// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
///
///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#protnum
pub const SCMP_PROTOCOL_NUMBER: u8 = 202;
