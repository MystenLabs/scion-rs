# How to Contribute

## GitHub flow

We generally follow the [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow) in our project. In
a nutshell, this requires the following steps to contribute:

1. [Fork the repository](https://docs.github.com/en/get-started/quickstart/contributing-to-projects) (only required if
   you don't have write access to the repository).
1. [Create a feature branch](https://docs.github.com/en/get-started/quickstart/github-flow#create-a-branch).
1. [Make changes and create a
   commit](https://docs.github.com/en/get-started/quickstart/contributing-to-projects#making-and-pushing-changes);
   note that we enforce a particular style for commit messages, see [below](#commit-messages).
1. Push your changes to GitHub and [create a pull
   request](https://docs.github.com/en/get-started/quickstart/contributing-to-projects#making-a-pull-request) (PR).
1. Wait for maintainers to review your changes and, if necessary, revise your PR.

## Commit messages

To ensure a consistent Git history (from which we can later easily generate changelogs automatically), we enforce that
all commit messages and PR titles comply with the [conventional-commit format](https://www.conventionalcommits.org/en/v1.0.0/).
For examples, please take a look at our [commit history](https://github.com/MystenLabs/scion-rs/commits/main).

## Pre-commit hooks

We have CI jobs running for every PR to test and lint the repository. You can install Git pre-commit hooks to ensure
that these check pass even *before pushing your changes* to GitHub. To use this, the following steps are required:

1. Install [Rust](https://www.rust-lang.org/tools/install).
1. [Install pre-commit](https://pre-commit.com/#install) using `pip` or your OS's package manager.
1. Install required cargo tools: `cargo install cargo-sort cargo-deny``
1. Run `pre-commit install` in the repository.

After this setup, the code will be checked, reformatted, and tested whenever you create a Git commit.

You can also use a custom pre-commit configuration:

1. Create a file `.custom-pre-commit-config.yaml` (this is set to be ignored by Git).
1. Run `pre-commit install -c .custom-pre-commit-config.yaml`.

## Test coverage

We would like to cover as much code as possible with tests. Ideally you would add unit tests for all code you contribute.
To analyze test coverage, we use [Tarpaulin](https://crates.io/crates/cargo-tarpaulin). You can install and run the tool as follows:

```sh
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --skip-clean --lib --bins --examples --tests --doc --out html
```

This creates a file `tarpaulin-report.html`, which shows you coverage statistics as well as which individual lines are or aren't covered by tests.
Other valid output formats are `json`, `stdout`, `xml`, and `lcov`.

The exact command we use in our CI pipeline is visible in [.github/workflows/rust.yml](.github/workflows/rust.yml).

## Integration tests

Most integration tests are disabled by default because they depend on certain running SCION applications.
You can run the integration tests by executing `cargo test -- --ignored` or the full test suite (unit and integration
tests) through `cargo test -- --include-ignored`.

Some integration tests allow you to control addresses of SCION components and other data through environment variables.
For example, if your SCION Daemon is accessible at `192.168.0.42:12345` instead of the default `localhost:30255`, you
can run integration tests like this:

```sh
SCION_DAEMON_ADDRESS="http://192.168.0.42:12345" cargo test -- --ignored
```

The following section describes how to set up the SCION components used for integration tests locally.

### Local SCION topology with multipass

If you are on a [supported Linux distribution](https://docs.scion.org/en/latest/dev/setup.html#prerequisites) you can
set up a [local SCION development environment](https://docs.scion.org/en/latest/dev/setup.html) directly on your machine
and [run a local SCION topology](https://docs.scion.org/en/latest/dev/run.html).

If you run a different operating system, you can conveniently manage Ubuntu VMs with
[Multipass](https://multipass.run/install). The following command can be used to launch a new VM, install prerequisites
inside the VM, install the latest version of SCION, and run a local topology with services accessible from the host
machine:

```sh
multipass launch --name scion --disk 10G --memory 4G --cpus 2 --timeout 600 \
    --cloud-init multipass/cloud-config.yaml
```

This will take several minutes as it builds SCION from source (hence the increased timeout).

After the launch, you can check that the network started successfully and that you see paths:

```sh
multipass shell scion

sudo systemctl status scion-network.service

cd /etc/scion-rs-integration/scion/
bin/scion showpaths --sciond $(./scion.sh sciond-addr 111) 1-ff00:0:112
```

Now you can access SCION services from the host system and forward the dispatcher UNIX socket to run integration tests.
For convenience, you can use the [test_setup.sh](./multipass/test_setup.sh) script:

```sh
chmod 0600 ./multipass/test_id_ed25519
. ./multipass/test_setup.sh
cargo test -- --ignored
```

## Signed commits

We appreciate it if you configure Git to [sign your commits](https://gist.github.com/troyfontaine/18c9146295168ee9ca2b30c00bd1b41e).
