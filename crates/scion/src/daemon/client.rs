use scion_grpc::daemon::{v1 as daemon_grpc, v1::daemon_service_client::DaemonServiceClient};
use thiserror::Error;
use tonic::transport::Channel;
use tracing::warn;

use super::{messages::PathRequest, AsInfo};
use crate::{address::IsdAsn, packet::ByEndpoint, path::Path};

#[derive(Debug, Error)]
pub enum DaemonClientError {
    #[error("A communication error occurred: {0}")]
    ConnectionError(#[from] tonic::transport::Error),
    #[error("A gRPC error occurred: {0}")]
    GrpcError(#[from] tonic::Status),
    #[error("Response contained invalid data")]
    InvalidData,
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
        client.local_isd_asn = client.as_info(IsdAsn::WILDCARD).await?.isd_asn;

        Ok(client)
    }

    /// Request information about an AS; [`IsdAsn::WILDCARD`] can be used to obtain information
    /// about the local AS.
    pub async fn as_info(&self, isd_asn: IsdAsn) -> Result<AsInfo, DaemonClientError> {
        self.client()
            .r#as(daemon_grpc::AsRequest::from(isd_asn))
            .await?
            .into_inner()
            .try_into()
            .map_err(|_| DaemonClientError::InvalidData)
    }

    /// Request a set of end-to-end paths between the source and destination AS
    pub async fn paths(
        &self,
        request: &PathRequest,
    ) -> Result<impl Iterator<Item = Path>, DaemonClientError> {
        let src_isd_asn = if request.source.is_wildcard() {
            self.local_isd_asn
        } else {
            request.source
        };
        let isd_asn = ByEndpoint {
            source: src_isd_asn,
            destination: request.destination,
        };
        Ok(self
            .client()
            .paths(daemon_grpc::PathsRequest::from(request))
            .await?
            .into_inner()
            .paths
            .into_iter()
            .map(move |grpc_path| Path::try_from_grpc_with_endpoints(grpc_path, isd_asn))
            .filter_map(|x| {
                x.map_err(|e| warn!(?e, "a parse error occurred for a path"))
                    .ok()
            }))
    }

    #[inline]
    pub async fn paths_to(
        &self,
        destination: IsdAsn,
    ) -> Result<impl Iterator<Item = Path>, DaemonClientError> {
        self.paths(&PathRequest::new(destination)).await
    }

    fn client(&self) -> DaemonServiceClient<Channel> {
        DaemonServiceClient::new(self.connection.clone())
    }
}