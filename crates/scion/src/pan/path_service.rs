use std::future::Future;

use bytes::Bytes;
use chrono::Utc;
use scion_proto::{address::IsdAsn, path::Path};

/// Errors returned on a failed path lookup.
#[derive(Debug, thiserror::Error)]
pub enum PathLookupError {
    /// Wildcard destinations cannot be queried for paths.
    #[error("cannot query paths to wildcard destinations")]
    WildcardDestination,
    /// Path queries for the provided destination are not supported by this [`AsyncPathService`].
    #[error("unsupported destination")]
    UnsupportedDestination,
    /// The destination can be queried, but there are no paths available to it.
    #[error("no path available to destination")]
    NoPath,
}

/// Trait for asynchronously retrieving paths to SCION ASes.
pub trait AsyncPathService {
    /// Associated iterator over returned paths.
    type PathsTo: Iterator<Item = Path> + Send;

    /// Returns a *non-empty* iterator over paths to the specified SCION AS.
    ///
    /// The order of the returned paths is arbitrary unless otherwise
    /// specified by the implementation.
    ///
    /// Returns an error if a wildcard AS is requested, if the destination is not supported
    /// by this `AsyncPathService`, or if there are no paths available to the destination.
    fn paths_to(
        &self,
        scion_as: IsdAsn,
    ) -> impl Future<Output = Result<Self::PathsTo, PathLookupError>> + Send;

    /// Return the preferred path to the specified AS.
    ///
    /// Returns an error if a wildcard AS is requested, if the destination is not supported
    /// by this `AsyncPathService`, or if there are no paths available to the destination.
    fn path_to(
        &self,
        scion_as: IsdAsn,
    ) -> impl Future<Output = Result<Path, PathLookupError>> + Send;

    /// Returns true if the specified destination is supported by this `AsyncPathService`,
    /// false otherwise.
    ///
    /// A supported destination is one to which paths may be successfully queried, wildcard ASes are
    /// therefore not supported.
    fn is_supported_destination(&self, scion_as: IsdAsn) -> bool {
        !scion_as.is_wildcard()
    }

    /// Returns an error if the destination is a wildcard SCION AS or is not otherwise supported by this
    /// `AsyncPathService`, as determined by [`is_supported_destination`][Self::is_supported_destination].
    fn check_destination(&self, scion_as: IsdAsn) -> Result<(), PathLookupError> {
        if scion_as.is_wildcard() {
            return Err(PathLookupError::WildcardDestination);
        }
        if !self.is_supported_destination(scion_as) {
            return Err(PathLookupError::NoPath);
        }

        Ok(())
    }
}

impl AsyncPathService for Path<Bytes> {
    type PathsTo = std::iter::Once<Path>;

    async fn paths_to(&self, scion_as: IsdAsn) -> Result<Self::PathsTo, PathLookupError> {
        Ok(std::iter::once(self.path_to(scion_as).await?))
    }

    async fn path_to(&self, scion_as: IsdAsn) -> Result<Path, PathLookupError> {
        self.check_destination(scion_as)?;

        if let Some(expiry_time) = self.expiry_time() {
            if expiry_time <= Utc::now() {
                tracing::warn!(
                    destination=%scion_as,
                    path=?self,
                    "attempted to send packet with expired, static path"
                );
                return Err(PathLookupError::NoPath);
            }
        }
        Ok(self.clone())
    }

    fn is_supported_destination(&self, scion_as: IsdAsn) -> bool {
        self.isd_asn.destination == scion_as
    }
}
