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

    /// Provide the service with a path that it may choose to store.
    ///
    /// Returns true if the path was stored by the service.
    ///
    /// Since [`Path<Bytes>`] stores the raw path data as a Bytes object, this method allows
    /// the service to cheaply clone the Path without copying the raw data.
    ///
    /// See [`Self::maybe_add_path`] for a variant that always copies the path.
    fn maybe_add_shared_path(&self, path: &Path<Bytes>) -> bool;

    /// Provide the service with a path that it may choose to store.
    ///
    /// Similarly to [`Self::maybe_add_shared_path`] this returns true if the path was copied.
    /// However, this method always copies the path to an owned variety for storage.
    ///
    /// See [`Self::maybe_add_shared_path`] for a variant which may avoid copying the path.
    fn maybe_add_path(&self, path: &Path<&mut [u8]>) -> bool;
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

    fn maybe_add_shared_path(&self, _path: &Path<Bytes>) -> bool {
        false
    }

    fn maybe_add_path(&self, _path: &Path<&mut [u8]>) -> bool {
        false
    }
}
