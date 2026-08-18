# setools-rs

`setools-rs` is a standalone Rust implementation of the SETools command-line
policy analysis tools. Its CLI compatibility target and version identity are
SETools 4.7.1.

The project does not depend on the Python/Cython SETools implementation. It
builds from this repository using Rust, libsepol, and libselinux only.

## Status

`sesearch` is implemented. It supports standard and extended TE rules,
conditionals, filename transitions, RBAC, MLS range transitions,
running-policy discovery, and verbose/debug diagnostics.

`seinfo` is implemented. It provides the compatibility statistics view and all
SETools 4.7.1 component queries: symbols, commons and classes, constraints,
defaults, type bounds, users and MLS data, policy capabilities, and SELinux or
Xen labeling statements. It supports component filtering, `--all`, `--expand`,
`--flat`, platform validation, running-policy discovery, and verbose/debug
diagnostics.

`sediff`, `sedta`, `seinfoflow`, and `sechecker` remain scaffolds. See [the
progress document](docs/RUST_REWRITE_PROGRESS.md) for details.

## Requirements

- Rust 1.85 or newer
- a C compiler
- `pkg-config`
- libsepol 3.9 or newer, including development headers
- libselinux, including development headers
- `checkpolicy` only when running integration tests

The generated binaries are dynamically linked to libsepol and libselinux. The
current implementation targets Linux systems with SELinux userspace libraries.

## Build

Build the complete workspace:

```bash
cargo build --workspace
```

Build the implemented command binaries:

```bash
cargo build -p setools-cli --bin sesearch --bin seinfo
```

Build an optimized binary:

```bash
cargo build --release -p setools-cli --bin sesearch --bin seinfo
```

Cargo uses its standard output layout:

```text
target/debug/sesearch
target/debug/seinfo
target/release/sesearch
target/release/seinfo
```

Install from a checkout with:

```bash
cargo install --path crates/setools-cli --bin sesearch --bin seinfo
```

Example usage:

```bash
target/release/sesearch --allow -s sshd_t -t shadow_t /path/to/policy
target/release/seinfo --type sshd_t --expand /path/to/policy
```

If the policy argument is omitted, `sesearch` and `seinfo` first try the current
SELinuxfs policy and then installed `policy.N` files.

## Test

With the development requirements installed:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The repository contains only tests for the Rust implementation. Historical
oracle implementations and cross-implementation differential tooling are not
build or test dependencies of this project.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/setools-sepol` | project-owned C bridge and native loading |
| `crates/setools-policy` | immutable owned policy model |
| `crates/setools-query` | query preparation and matching |
| `crates/setools-diff` | semantic policy comparison |
| `crates/setools-graph` | graph analyses |
| `crates/setools-cli` | CLI rendering and binary entry points |
| `docs` | design, progress, and architecture decisions |

## Publication state

This repository can be cloned, built, tested, tagged, and released on its own.
The internal crates currently set `publish = false`: source and binary releases
are supported, while crates.io publication is deferred until the library APIs
and remaining commands are stable. See [RELEASING.md](RELEASING.md).

## License

The library crates are licensed under LGPL-2.1-only. The command-line programs
and test code are licensed under GPL-2.0-only. See [COPYING](COPYING) and the
complete texts in [LICENSES](LICENSES).
