use std::{io::ErrorKind, sync::Arc};

use async_trait;
use bytes::Bytes;
use scion_proto::{
    address::IsdAsn,
    path::{DataplanePath, Path},
};
use tokio::sync::Mutex;

use super::{AsyncPathService, ReceiveError, SendError};

/// Interface for sending and receiving datagrams asynchronously on the SCION network.
#[async_trait::async_trait]
pub trait AsyncScionDatagram {
    /// The type of the address used for sending and receiving datagrams.
    type Addr: AsRef<IsdAsn> + Sync + Send;

    /// Receive a datagram, its sender, and path from the socket.
    ///
    /// The payload of the datagram is written into the provided buffer, which must not be
    /// empty. If there is insufficient space in the buffer, excess data may be dropped.
    ///
    /// This function returns the number of bytes in the payload (irrespective of whether any
    /// were dropped), the address of the sender, and the SCION [`Path`] over which the packet
    /// was received.
    ///
    /// The returned path corresponds to the reversed path observed in the packet for known path
    /// types, or a copy of the opaque path data for unknown path types. In either case, the raw
    /// raw data comprising the returned path is written to path_buffer, which must be at least
    /// [DataplanePath::MAX_LEN][`DataplanePath::<Bytes>::MAX_LEN`] bytes in length.
    async fn recv_from_with_path<'p>(
        &self,
        buffer: &mut [u8],
        path_buffer: &'p mut [u8],
    ) -> Result<(usize, Self::Addr, Path<&'p mut [u8]>), ReceiveError>;

    /// Receive a datagram and its sender.
    ///
    /// This behaves like [`Self::recv_from_with_path`] but does not return the path over which
    /// the packet was received.
    ///
    /// In the case where the path is not needed, this method should be used as the
    /// implementation may avoid copying the path.
    ///
    /// See [`Self::recv_from_with_path`] for more information.
    async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Self::Addr), ReceiveError>;

    /// Receive a datagram and its path from the socket.
    ///
    /// Similar to [`Self::recv_from_with_path`], this receives the datagram into the provided
    /// buffer. However, as this does not return any information about the sender, this is
    /// primarily used where the sender is already known, such as with connected sockets
    ///
    /// See [`Self::recv_from_with_path`] for more information.
    async fn recv_with_path<'p>(
        &self,
        buffer: &mut [u8],
        path_buffer: &'p mut [u8],
    ) -> Result<(usize, Path<&'p mut [u8]>), ReceiveError> {
        let (len, _, path) = self.recv_from_with_path(buffer, path_buffer).await?;
        Ok((len, path))
    }

    /// Receive a datagram.
    ///
    /// Similar to [`Self::recv_from_with_path`], this receives the datagram into the provided
    /// buffer. However, as this does not return any information about the sender, this is
    /// primarily used where the sender is already known, such as with connected sockets
    ///
    /// In the case where neither the path nor the sender is needed, this method should be used
    /// instead of [`Self::recv_with_path`] as the implementation may avoid copying the path.
    ///
    /// See [`Self::recv_from_with_path`] for more information.
    async fn recv(&self, buffer: &mut [u8]) -> Result<usize, ReceiveError> {
        let (len, _) = self.recv_from(buffer).await?;
        Ok(len)
    }

    /// Sends the payload to the specified remote address and using the specified path.
    async fn send_to_via(
        &self,
        payload: Bytes,
        destination: Self::Addr,
        path: &Path,
    ) -> Result<(), SendError>;

    /// Sends the payload using the specified path.
    ///
    /// This assumes that the underlying socket is aware of the destination, and will
    /// return an error if the socket cannot identify the destination.
    async fn send_via(&self, payload: Bytes, path: &Path) -> Result<(), SendError>;

    /// Returns the remote address of the socket, if any.
    fn remote_addr(&self) -> Option<Self::Addr>;
}

/// A SCION path-aware socket.
///
/// This socket wraps an [`AsyncScionDatagram`] and [`AsyncPathService`] and handles providing
/// paths to the socket from the path service and notifying the path service of any observed
/// paths from the network as well as any issues related to the paths.
pub struct PathAwareDatagram<D, P> {
    socket: D,
    path_service: Arc<P>,
    path_buffer: Mutex<Vec<u8>>,
}

impl<D, P> PathAwareDatagram<D, P>
where
    D: AsyncScionDatagram + Send + Sync,
    P: AsyncPathService + Send + Sync,
{
    /// Creates a new socket that wraps the provided socket and path service.
    pub fn new(socket: D, path_service: Arc<P>) -> Self {
        Self {
            socket,
            path_service,
            path_buffer: Mutex::new(vec![0u8; DataplanePath::<Bytes>::MAX_LEN]),
        }
    }

    /// Changes the path service associated with this socket.
    pub fn set_path_service(&mut self, path_service: Arc<P>) {
        self.path_service = path_service;
    }

    /// Returns the path service associated with this socket.
    pub fn path_service(&self) -> &P {
        &self.path_service
    }

    /// Send a datagram using [`AsyncScionDatagram::send_to_via`] with a path from the path service.
    pub async fn send_to(
        &self,
        payload: Bytes,
        destination: <Self as AsyncScionDatagram>::Addr,
    ) -> Result<(), SendError> {
        let path = self.path_to(*destination.as_ref()).await?;
        self.send_to_via(payload, destination, path).await
    }

    /// Send a datagram using [`AsyncScionDatagram::send_via`] with a path from the path service.
    pub async fn send(&self, payload: Bytes) -> Result<(), SendError> {
        if let Some(remote_addr) = self.remote_addr() {
            let path = self.path_to(*remote_addr.as_ref()).await?;
            self.send_via(payload, path).await
        } else {
            Err(SendError::Io(ErrorKind::NotConnected.into()))
        }
    }

    async fn path_to(&self, remote_ia: IsdAsn) -> Result<&Path, SendError> {
        self.path_service
            .path_to(remote_ia)
            .await
            .map_err(|_err| todo!("handle path failures"))
    }
}

// TODO(jsmith): We could allow the AsyncPathService to disable receiving paths from the network.
// This could improve the performance in these special cases.
#[async_trait::async_trait]
impl<D, P> AsyncScionDatagram for PathAwareDatagram<D, P>
where
    D: AsyncScionDatagram + Send + Sync,
    P: AsyncPathService + Send + Sync,
{
    type Addr = <D as AsyncScionDatagram>::Addr;

    async fn recv_from_with_path<'p>(
        &self,
        buffer: &mut [u8],
        path_buffer: &'p mut [u8],
    ) -> Result<(usize, Self::Addr, Path<&'p mut [u8]>), ReceiveError> {
        let (len, sender, path) = self.socket.recv_from_with_path(buffer, path_buffer).await?;

        self.path_service.maybe_add_path(&path);

        Ok((len, sender, path))
    }

    /// Receive a datagram and its sender.
    ///
    /// In order to observe the network path, this implementation of recv_from uses an internal
    /// path_buffer guarded by a mutex. As a result, only one recv_from call can be ongoing at
    /// a time. If multiple asynchronous recvs are desired, then use the recv_from_with_path
    /// method instead.
    ///
    /// See the trait [`AsyncScionDatagram::recv_from_with_path`] for more information on the
    /// method.
    async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Self::Addr), ReceiveError> {
        // TODO(jsmith): Determine if we need to remove this mutex.
        // The use of this mutex means only a single recv_from call be in progress at once. To await
        // allow multiple calls we would likely need multiple buffers.
        let mut path_buffer = self.path_buffer.lock().await;
        let (len, sender, _) = self
            .recv_from_with_path(buffer, path_buffer.as_mut_slice())
            .await?;
        Ok((len, sender))
    }

    async fn send_to_via(
        &self,
        payload: Bytes,
        destination: Self::Addr,
        path: &Path,
    ) -> Result<(), SendError> {
        self.path_service.maybe_add_shared_path(path);
        self.socket.send_to_via(payload, destination, path).await
    }

    async fn send_via(&self, payload: Bytes, path: &Path) -> Result<(), SendError> {
        self.path_service.maybe_add_shared_path(path);
        self.socket.send_via(payload, path).await
    }

    fn remote_addr(&self) -> Option<Self::Addr> {
        self.socket.remote_addr()
    }
}
