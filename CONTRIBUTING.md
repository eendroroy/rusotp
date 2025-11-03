# Contributing to rusotp

Thank you for contributing. This document describes the recommended workflow and standards to make contributions smooth
and consistent.

## Code of conduct

Please follow the project's Code of Conduct. Be respectful and constructive in all interactions.

## Getting started

1. Fork the repository and clone your fork.
2. Add the upstream remote if needed:
    ```shell
    git remote add upstream git@github.com:eendroroy/rusotp.git
    ```
3. Create a feature branch from the `development` branch:
    ```shell
    git fetch upstream
    git checkout development
    git pull upstream development
    git checkout -b my-feature-name
    ```

## Branching and commits

- Branch naming: use short, descriptive names
    - Hotfix - use `master` as base branch (e.g. `hotfix/hotp-edge-case`)
    - Feature - use `development` as base branch (e.g. `feature/totp-radix`)
- Commit messages: keep a short summary line, followed by an optional body. Prefer imperative tense (e.g. "Add
  validation for secret length").

## Tests and examples

- Run the test suite:
    ```shell
    cargo test
    ```
- Run examples or demo:
    ```shell
    cargo run --example totp_provisioning_uri
    cargo demo
    ```
- If you add behavior or fix a bug, include or update tests.

## Formatting and linting

- Format Rust code:
    ```shell 
    cargo fmt
    ```
- Lint with Clippy:
    ```shell
    cargo clippy -- -D warnings
    ```

Ensure PRs pass CI and lints before requesting review.

## C bindings and examples

C examples are in `contrib/`. Build or run examples as documented; keep C bindings changes well-tested.

## Submitting a Pull Request

1. Push your branch to your fork:
    ```shell
    git push origin my-feature-name
    ```
2. Open a Pull Request targeting the `development` branch of the main repository.
3. Describe the change, include relevant test results, and reference any related issues.
4. Respond to review comments and update the branch as needed.

## Reporting bugs and requesting features

- Open issues on GitHub with clear steps to reproduce (for bugs) or motivation and proposed API (for features).
- Include platform and version info when relevant.

## Licensing and contributor obligations

This project is licensed under the GNU AGPL-3.0 License. By contributing, you agree your contributions will be licensed
under the project's license.

## Misc

- Keep changes small and focused for easier review.
- Follow existing code style and patterns.
- Maintain backwards compatibility where reasonable; document breaking changes clearly.

Thank you for helping improve [`rusotp`](https://github.com/eendroroy/rusotp).
