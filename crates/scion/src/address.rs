use thiserror;

mod asn;
pub use asn::Asn;

mod isd;
pub use isd::Isd;

mod ia;
pub use ia::IA;

#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub enum AddressParseError {
    #[error("AS number out of range, expected at most 2^48 - 1")]
    AsnOutOfRange,
    #[error("AS string contains a part that is not a 2-byte HEX")]
    InvalidAsnPart(String),
    #[error("invalid AS number string (expected format xxxx:xxxx:xxxx, found {0})")]
    InvalidAsnString(String),
    #[error("ISD number not parsable as u16")]
    InvalidIsdString(String),
    #[error("invalid string (expected format d-xxxx:xxxx:xxxx, found {0})")]
    InvalidIaString(String),
}
