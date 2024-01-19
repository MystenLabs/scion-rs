//! A client to communicate with the SCION daemon.

use std::{env, vec};

use scion_grpc::daemon::{v1 as daemon_grpc, v1::daemon_service_client::DaemonServiceClient};
use scion_proto::{address::IsdAsn, packet::ByEndpoint, path::Path};
use tonic::transport::Channel;
use tracing::warn;

use super::{
    messages::{self, PathRequest},
    AsInfo,
};
use crate::pan::{AsyncPathService, PathLookupError};

/// The default address of the SCION daemon.
pub const DEFAULT_DAEMON_ADDRESS: &str = "https://localhost:30255";

/// The environment variable to configure the address of the SCION daemon.
pub const DAEMON_ADDRESS_ENV_VARIABLE: &str = "SCION_DAEMON_ADDRESS";

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum DaemonClientError {
    #[error("A communication error occurred: {0}")]
    ConnectionError(#[from] tonic::transport::Error),
    #[error("A gRPC error occurred: {0}")]
    GrpcError(#[from] tonic::Status),
    #[error("Response contained invalid data")]
    InvalidData,
}

/// Get the daemon address.
///
/// Depending on the environment, this is the [`DEFAULT_DAEMON_ADDRESS`] or manually configured
pub fn get_daemon_address() -> String {
    let mut address =
        env::var(DAEMON_ADDRESS_ENV_VARIABLE).unwrap_or(DEFAULT_DAEMON_ADDRESS.into());
    if !address.contains("://") {
        address = format!("http://{}", address);
    }
    address
}

/// A service to communicate with the local SCION daemon
#[derive(Clone, Debug)]
pub struct DaemonClient {
    connection: Channel,
    local_isd_asn: IsdAsn,
}

impl DaemonClient {
    /// Create a new client to communicate with the SCION daemon located at `address`
    ///
    /// This attempts to connect to the daemon directly and fetch the local ISD-ASN.
    ///
    /// Errors:
    ///
    /// This returns an error, if any error occurs during the connection setup or during the request
    /// for the AS info.
    pub async fn connect(address: &str) -> Result<Self, DaemonClientError> {
        let mut client = Self {
            connection: tonic::transport::Endpoint::new(address.to_string())?
                .connect()
                .await?,
            local_isd_asn: IsdAsn::WILDCARD,
        };
        client.local_isd_asn = client.sas_info(IsdAsn::WILDCARD).await?.isd_asn;

        Ok(client)
    }

    /// Request information about an AS; [`IsdAsn::WILDCARD`] can be used to obtain information
    /// about the local AS.
    pub async fn sas_info(&self, isd_asn: IsdAsn) -> Result<AsInfo, DaemonClientError> {
        self.client()
            .r#as(messages::sas_request_from(isd_asn))
            .await?
            .into_inner()
            .try_into()
            .map_err(|_| DaemonClientError::InvalidData)
    }

    /// Request information about the local AS.
    #[inline]
    pub async fn local_sas_info(&self) -> Result<AsInfo, DaemonClientError> {
        self.sas_info(IsdAsn::WILDCARD).await
    }

    /// Request a set of end-to-end paths between the source and destination AS
    pub async fn paths(&self, request: &PathRequest) -> Result<Paths, DaemonClientError> {
        let src_isd_asn = if request.source.is_wildcard() {
            self.local_isd_asn
        } else {
            request.source
        };
        let isd_asn = ByEndpoint {
            source: src_isd_asn,
            destination: request.destination,
        };
        Ok(Paths {
            isd_asn,
            grpc_paths: self
                .client()
                .paths(daemon_grpc::PathsRequest::from(request))
                .await?
                .into_inner()
                .paths
                .into_iter(),
        })
    }

    /// Request paths from the local AS to the specified destination AS.
    #[inline]
    pub async fn paths_to(&self, destination: IsdAsn) -> Result<Paths, DaemonClientError> {
        self.paths(&PathRequest::new(destination)).await
    }

    fn client(&self) -> DaemonServiceClient<Channel> {
        DaemonServiceClient::new(self.connection.clone())
    }
}

/// Iterator for SCION [Path]s obtained from the SCION Daemon via gRPC
#[derive(Debug)]
pub struct Paths {
    isd_asn: ByEndpoint<IsdAsn>,
    grpc_paths: vec::IntoIter<daemon_grpc::Path>,
}

impl Iterator for Paths {
    type Item = Path;

    fn next(&mut self) -> Option<Self::Item> {
        for grpc_path in self.grpc_paths.by_ref() {
            match Path::try_from_grpc_with_endpoints(grpc_path, self.isd_asn) {
                Ok(path) => return Some(path),
                Err(e) => warn!(?e, "a parse error occurred for a path"),
            }
        }
        None
    }
}

impl AsyncPathService for DaemonClient {
    type PathsTo = Paths;

    async fn paths_to(&self, scion_as: IsdAsn) -> Result<Self::PathsTo, PathLookupError> {
        self.check_destination(scion_as)?;

        Ok(self.paths(&PathRequest::new(scion_as)).await?)
    }

    async fn path_to(&self, scion_as: IsdAsn) -> Result<Path, PathLookupError> {
        self.check_destination(scion_as)?;

        self.paths(&PathRequest::new(scion_as))
            .await?
            .next()
            .ok_or(PathLookupError::NoPath)
    }
}

impl From<DaemonClientError> for PathLookupError {
    fn from(value: DaemonClientError) -> Self {
        PathLookupError::Other(Box::new(value))
    }
}
