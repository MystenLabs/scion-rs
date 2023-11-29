# SCION in Rust

This library provides an end-host networking stack for SCION and can be used in Rust applications to communicate over a
SCION network.

If you would like to contribute (which we highly appreciate), please familiarize yourself with our [contributing
workflow](./CONTRIBUTING.md).

## Prerequisites

### Ubuntu

```sh
# Install C/C++ compilers, protobuf, SQLite3, clang
sudo apt install -y build-essential protobuf-compiler libsqlite3-dev llvm-dev libclang-dev clang
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Mac

```sh
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install protobuf
brew install protobuf
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build and test

- Build the project: `cargo build`
- Run the tests: `cargo test`

## Logging

We use [tracing](https://github.com/tokio-rs/tracing) to log messages during program execution. By default, only
warnings and errors are printed. You can control the level of messages to be printed through the environment variable
`RUST_LOG`. For example, to print info messages in addition, you can execute the following:

```sh
export RUST_LOG=info
```

## Specification and standards

We use the protobuf definitions and other specification from [scionproto/scion](https://github.com/scionproto/scion) and
the [SCION documentation](https://docs.scion.org).

## License

This project is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<https://www.apache.org/licenses/LICENSE-2.0>).
