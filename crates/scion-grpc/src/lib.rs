//! `scion-grpc` provides bindings [gRPC](https://grpc.io/) types and services used within SCION's
//! control plane.
pub use prost::Message;

pub mod drkey {
    pub mod v1 {
        tonic::include_proto!("proto.drkey.v1");
    }
}

pub mod daemon {
    //! Types and services for interacting with the SCION daemon (sciond).

    pub mod v1 {
        //! Version 1 sciond types and services.
        //!
        //! The primary entry point is the [daemon_service_client::DaemonServiceClient] that
        //! enables an application to query its local sciond service.

        tonic::include_proto!("proto.daemon.v1");
    }
    pub use v1::daemon_service_client::DaemonServiceClient;
}
