use bytes::Bytes;
use chrono::Utc;
use scion_proto::{address::IsdAsn, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum PathLookupError {
    #[error("no path available to destination")]
    NoPath,
}

/// Trait for asynchronously retrieving paths to SCION ASes.
#[async_trait::async_trait]
pub trait AsyncPathService {
    /// Return a path to the specified AS.
    async fn path_to<'a>(&'a self, scion_as: IsdAsn) -> Result<&'a Path, PathLookupError>;
}

#[async_trait::async_trait]
impl AsyncPathService for Path<Bytes> {
    /// Return a path to the specified AS.
    async fn path_to(&self, scion_as: IsdAsn) -> Result<&Path, PathLookupError> {
        if self.isd_asn.destination != scion_as {
            return Err(PathLookupError::NoPath);
        }
        if let Some(metadata) = self.metadata.as_ref() {
            if metadata.expiration < Utc::now() {
                tracing::warn!(
                    destination=%scion_as,
                    path=?self,
                    "attempted to send packet with expired, static path"
                );
                return Err(PathLookupError::NoPath);
            }
        }
        Ok(self)
    }
}
