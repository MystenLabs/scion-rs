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
1. Install [cargo-deny](https://embarkstudios.github.io/cargo-deny/cli/index.html).
1. [Install pre-commit](https://pre-commit.com/#install) using `pip` or your OS's package manager.
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
cargo tarpaulin --workspace --all-targets --doc --out html
```

This creates a file `tarpaulin-report.html`, which shows you coverage statistics as well as which individual lines are or aren't covered by tests.
Other valid output formats are `json`, `stdout`, `xml`, and `lcov`.

## Integration tests

Most integration tests are disabled by default because they depend on certain running SCION applications.
You can run the full test suite (including integration tests) by executing `cargo test -- --ignored`.

Some integration tests allow you to control addresses of SCION components and other data through environment variables.
For example, if your SCION Daemon is accessible at `192.168.0.42:12345` instead of the default `localhost:30255`, you
can run integration tests like this:

```sh
SCION_DAEMON_ADDRESS="http://192.168.0.42:12345" cargo test -- --ignored
```

To run both unit and integration tests, run

```sh
cargo test -- --include-ignored
```

### Local SCION topology with multipass

If you are on a [supported Linux distribution](https://docs.scion.org/en/latest/dev/setup.html#prerequisites) you can
set up a [local SCION development environment](https://docs.scion.org/en/latest/dev/setup.html) directly on your machine
and [run a local SCION topology](https://docs.scion.org/en/latest/dev/run.html).

If you run a different operating system, you can conveniently manage Ubuntu VMs with
[Multipass](https://multipass.run/install). The following commands can be used to launch a new VM, install prerequisites
inside the VM, install the latest version of SCION, and run a local topology with services accessible from the host
machine.

```sh
# set up VM and enable direct SSH access
# if you have sufficient resources on the host, you may want to increase the VM's resources
multipass launch --disk 10G --memory 4G --cpus 2 --name scion --cloud-init - <<EOF
users:
- name: ubuntu
  sudo: ALL=(ALL) NOPASSWD:ALL
  ssh_authorized_keys:
  - $( cat ~/.ssh/id*.pub )
EOF
multipass shell scion

# install prerequisites
sudo apt-get update
sudo apt-get install make python3-pip ca-certificates curl gnupg

# set up Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
exit

# download and install SCION
multipass shell scion
git clone https://github.com/scionproto/scion
cd scion
./tools/install_bazel
./tools/install_deps
./scion.sh bazel-remote
export PATH=/home/ubuntu/.local/bin/:$PATH
make build

# enable routing to local addresses
echo "net.ipv4.conf.all.route_localnet = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl --system

# optional: run local topology and check that everything works
./scion.sh topology -c topology/tiny.topo
./scion.sh run
sleep 5
bin/scion showpaths --sciond $(./scion.sh sciond-addr 111) 1-ff00:0:112
```

Now you can access SCION services from the host system and forward the dispatcher UNIX socket to run integration tests.
For convenience, you can use the [test_setup.sh](./test_setup.sh) script:

```sh
. ./test_setup.sh
cargo test -- --ignored
```

## Signed commits

We appreciate it if you configure Git to [sign your commits](https://gist.github.com/troyfontaine/18c9146295168ee9ca2b30c00bd1b41e).
