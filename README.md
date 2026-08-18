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

`seinfo`, `sediff`, `sedta`, `seinfoflow`, and `sechecker` are currently
scaffolds and are not ready for production use. See
[the progress document](docs/RUST_REWRITE_PROGRESS.md) for details.

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

Build only `sesearch`:

```bash
cargo build -p setools-cli --bin sesearch
```

Build an optimized binary:

```bash
cargo build --release -p setools-cli --bin sesearch
```

Cargo uses its standard output layout:

```text
target/debug/sesearch
target/release/sesearch
```

Install from a checkout with:

```bash
cargo install --path crates/setools-cli --bin sesearch
```

Example usage:

```bash
target/release/sesearch --allow -s sshd_t -t shadow_t /path/to/policy
```

If the policy argument is omitted, `sesearch` first tries the current
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
