use bytes::Bytes;
use scion_proto::path::DataplanePath;

use crate::pan::ReceiveError;

pub(super) fn check_buffers(buf: &[u8], path_buf: &Option<&mut [u8]>) -> Result<(), ReceiveError> {
    if buf.is_empty() {
        return Err(ReceiveError::ZeroLengthBuffer);
    }
    if let Some(path_buf) = path_buf.as_ref() {
        if path_buf.len() < DataplanePath::<Bytes>::MAX_LEN {
            return Err(ReceiveError::PathBufferTooShort);
        }
    }
    Ok(())
}
