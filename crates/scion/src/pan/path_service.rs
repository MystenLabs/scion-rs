use bytes::Bytes;
use scion_proto::{address::IsdAsn, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum PathLookupError {}

/// Trait for asynchronously retrieving paths to SCION ASes.
#[async_trait::async_trait]
pub trait AsyncPathService {
    /// Return a path to the specified AS.
    async fn path_to(&self, scion_as: IsdAsn) -> Result<&Path, PathLookupError>;

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
