mod common_header;
pub use common_header::DecodeError;

mod registration;
mod wire_utils;

const ADDRESS_TYPE_OCTETS: usize = 1;
