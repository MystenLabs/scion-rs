# SCION in Rust

This library provides an end-host networking stack for SCION and can be used in Rust applications to communicate over a
SCION network. The library is fully compatible with the [reference implementation](https://github.com/scionproto/scion)
written in Go. In terms of functionality, it is a combination of the Go
[snet](https://pkg.go.dev/github.com/scionproto/scion/pkg/snet) and
[pan](https://pkg.go.dev/github.com/netsec-ethz/scion-apps/pkg/pan) libraries. See the [section about the repository
structure](#repository-structure-and-crates) for further details.

In the future, it will be extended to offer QUIC-over-SCION sockets similar to the
[shttp3 library](https://pkg.go.dev/github.com/netsec-ethz/scion-apps/pkg/shttp3).

If you observe a bug or want to request a feature, please search for an existing [issue](https://github.com/MystenLabs/scion-rs/issues)
on this topic and, if none exists, create a new one. If you would like to contribute code directly (which we highly
appreciate), please familiarize yourself with our [contributing workflow](./CONTRIBUTING.md).

## How to use this library

As our crates are not yet published to crates.io, you need to include them as a Git dependency in your `Cargo.toml`
file. Most likely, you will need the `scion` crate as explained [below](#repository-structure-and-crates), but you can
also use the `scion_proto` crate if you only need the main types and no asynchronous communication.

In the `[Dependencies]` section of your `Cargo.toml` file, add the following:

```toml
scion = { git = "ssh://git@github.com/MystenLabs/scion-rs" }
```

Optionally, you can specify a tag or branch, for example:

```toml
scion = { git = "ssh://git@github.com/MystenLabs/scion-rs", tag = "v0.1.0" }
```

Further details are provided in
[this documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories).

### Prerequisites

Due to its use of gRPC for communicating with external SCION components, this library requires protobuf to be installed.

For Ubuntu and MacOS, you can use the following snippets to install all prerequisites.

#### Ubuntu

```sh
# Install C/C++ compilers, protobuf, SQLite3, clang
sudo apt install -y build-essential protobuf-compiler libsqlite3-dev llvm-dev libclang-dev clang
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### MacOS

```sh
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install protobuf
brew install protobuf
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Logging

We use [tracing](https://github.com/tokio-rs/tracing) to log messages during program execution. By instantiating an
appropriate [subscriber](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/) in your application, you can
control which messages are logged and how.

## Repository structure and crates

This codebase consists of three different crates in the [`crates`](./crates) subdirectory:

1. [`scion-proto`](./crates/scion-proto/) contains the main types and conversions to represent SCION packets, addresses,
   paths, etc.
1. [`scion-grpc`](./crates/scion-grpc/) contains the automatically generated gRPC code to interact with external SCION
   components like the SCION daemon.
1. [`scion`](./crates/scion/) contains all asynchronous code for sockets, to send and receive packets, to fetch and
   cache paths, etc.

If you build an application that uses SCION, you will most likely need the `scion` crate, which includes the others as
dependencies.

All crates contain extensive documentation. Please see the following section on how to access it.

## Documentation

Most of our code has associated documentation. You can build and access this documentation locally by cloning the
repository and using `cargo-doc`:

```sh
git clone https://github.com/MystenLabs/scion-rs
cd scion-rs
cargo doc --workspace --open
```

## Specification and standards

We use the protobuf definitions and other specification from [scionproto/scion](https://github.com/scionproto/scion) and
the [SCION documentation](https://docs.scion.org) as well as the SCION-related Internet drafts, see
[draft-dekater-panrg-scion-overview](https://datatracker.ietf.org/doc/draft-dekater-panrg-scion-overview/) and
references therein.

## License

This project is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<https://www.apache.org/licenses/LICENSE-2.0>).
