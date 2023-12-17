//! Path aware networking socket and services.
mod datagram;
pub use datagram::{AsyncScionDatagram, PathAwareDatagram};

mod path_service;
pub use path_service::AsyncPathService;

mod error;
pub use error::{PathErrorKind, ReceiveError, SendError};

// use std::{
//     borrow::Borrow,
//     collections::{HashMap, VecDeque},
//     marker::PhantomData,
//     sync::Arc,
// };
//
// use bytes::Bytes;
// use scion_proto::{
//     address::{IsdAsn, SocketAddr},
//     path::Path,
// };

// TODO(jsmith):

// pub struct PathLookupError;
//
// /// Trait for retrieving paths to SCION ASes.
// #[async_trait::async_trait]
// pub trait PathService {
//     /// Return a path to the specified AS.
//     async fn path_to(&self, scion_as: IsdAsn) -> Result<Path, PathLookupError>;
//
//     /// Propose a path to the service.
//     ///
//     /// The service may or may not choose to store the path.
//     fn add_path(&self, path: &Path);
//
//     /// Notify the service of a path-related SCMP message.
//     fn on_scmp(&self, _args: ()) {
//         todo!()
//     }
// }
//
// #[derive(Debug, Default)]
// pub struct PathSet {
//     paths: HashMap<IsdAsn, VecDeque<Path>>,
// }
//
// impl PathSet {
//     pub fn new() -> Self {
//         Self::default()
//     }
// }
//
// #[async_trait::async_trait]
// impl PathService for PathSet {
//     async fn path_to(&self, scion_as: IsdAsn) -> Result<Path, PathLookupError> {
//         todo!()
//     }
//
//     fn add_path(&self, path: &Path) {
//         todo!()
//     }
// }
//
//
// impl<D, P> PathAwareDatagram<D, P>
// where
//     D: ScionDatagramSocket,
//     P: PathService,
// {
//     pub fn new(datagram_socket: D, path_service: Arc<P>) -> Self {
//         Self {
//             datagram_socket,
//             path_service,
//         }
//     }
//
//     pub fn set_path_service(&mut self, path_service: Arc<P>) {
//         self.path_service = path_service;
//     }
//
//     // pub fn set_path_service(&mut self, path_service: P) {
//     //     self.path_service = path_service;
//     // }
// }
//
// // #[async_trait::async_trait]
// // impl<D, P> ScionDatagramSocket for PathAwareDatagram<D, P>
// // where
// //     D: ScionDatagramSocket,
// //     P: PathService,
// // {
// //     async fn recv_with_path(&self, buffer: &mut [u8]) -> Result<(usize, Path), ReceiveError> {
// //         self.datagram_socket.recv_with_path(buffer).await
// //     }
// //     // async fn recv_from_with_path(
// //     //     &self,
// //     //     buffer: &mut [u8],
// //     // ) -> Result<(usize, SocketAddr, Path), Self::RecvErr>;
// //     // async fn send_via(&self, payload: Bytes, path: &Path) -> Result<(), Self::SendErr>;
// //     // async fn send_to_via(
// //     //     &self,
// //     //     payload: Bytes,
// //     //     destination: SocketAddr,
// //     //     path: &Path,
// //     // ) -> Result<(), Self::SendErr>;
// // }
//
// #[cfg(test)]
// mod tests {
//
//     use std::time::Duration;
//
//     use tokio::net::UnixStream;
//
//     use super::*;
//     use crate::{dispatcher::DispatcherStream, udp_socket::UdpSocket};
//
//     type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
//
//     pub fn socket_from(source: SocketAddr) -> TestResult<(UdpSocket, DispatcherStream)> {
//         let (inner, inner_remote) = UnixStream::pair()?;
//         Ok((
//             UdpSocket::new(DispatcherStream::new(inner), source),
//             DispatcherStream::new(inner_remote),
//         ))
//     }
//
//     //    #[test]
//     //    fn sanity() -> TestResult {
//     //        let (socket, _) = socket_from("[1-ff00:0:110,3.3.3.3]:8080".parse()?)?;
//     //        let dgram_socket2 = PathAwareDatagram::new(socket, Arc::new(PathSet::new()));
//     //        dgram_socket2.hello();
//     //
//     //        let (socket, _) = socket_from("[1-ff00:0:110,3.3.3.3]:8080".parse()?)?;
//     //        let dgram_socket2 = PathAwareDatagram::new(socket, Arc::new(PathSet::new()));
//     //        dgram_socket2.hello();
//     //        Ok(())
//     //    }
// }
