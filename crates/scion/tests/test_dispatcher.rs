use scion::dispatcher::{get_dispatcher_path, DispatcherStream, RegistrationError};
use scion_proto::address::SocketAddr;

type TestError = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
#[ignore = "requires dispatcher"]
async fn registration_success() -> TestError {
    let socket_addr: SocketAddr = "[1-ff00:0:110,0.0.0.0]:34500".parse().unwrap();
    let mut dispatcher = DispatcherStream::connect(get_dispatcher_path()).await?;
    let bound_address = dispatcher.register(socket_addr).await?;

    assert_eq!(bound_address, socket_addr);

    Ok(())
}

#[tokio::test]
#[ignore = "requires dispatcher"]
async fn port_in_use() -> TestError {
    let dispatcher_path = get_dispatcher_path();

    let socket_addr: SocketAddr = "[1-ff00:0:110,0.0.0.0]:8080".parse().unwrap();

    let mut first_dispatcher = DispatcherStream::connect(&dispatcher_path).await?;
    let bound_address = first_dispatcher.register(socket_addr).await?;
    assert_eq!(bound_address, socket_addr);

    let mut second_dispatcher = DispatcherStream::connect(&dispatcher_path).await?;
    let err = second_dispatcher
        .register(socket_addr)
        .await
        .expect_err("should fail");
    assert!(matches!(err, RegistrationError::Refused), "err={:?}", err);

    Ok(())
}
