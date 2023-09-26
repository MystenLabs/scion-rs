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
cargo tarpaulin --workspace --out html
```

This creates a file `tarpaulin-report.html`, which shows you coverage statistics as well as which individual lines are or aren't covered by tests.
Other valid output formats are `json`, `stdout`, `xml`, and `lcov`.

## Signed commits

We appreciate it if you configure Git to [sign your commits](https://gist.github.com/troyfontaine/18c9146295168ee9ca2b30c00bd1b41e).
