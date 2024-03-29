//! Bindings for [gRPC](https://grpc.io/) types and services used within SCION's control plane.
//!
//! The code is autogenerated using [tonic] from the protobuf definitions copied from the [SCION reference
//! implementation][scionproto].
//!
//! [scionproto]: https://github.com/scionproto/scion

pub use prost::Message;

pub mod drkey {
    //! Types and services for dynamically re-creatable keys (DRKeys).

    pub mod v1 {
        //! Version 1 DRKey types.

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
