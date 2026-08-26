# setools-rs

`setools-rs` is a standalone Rust implementation of the SETools command-line
policy analysis tools. Its CLI compatibility target and version identity are
SETools 4.7.1.

The project does not depend on the Python/Cython SETools implementation. It
builds from this repository using Rust, libsepol, and libselinux only.

## Status

`sesearch` is implemented. It supports standard and extended TE rules,
conditionals, filename transitions, RBAC, MLS range transitions,
running-policy discovery, and verbose/debug diagnostics. It also provides an
additive versioned JSON output mode.

`seinfo` is implemented. It provides the compatibility statistics view and all
SETools 4.7.1 component queries: symbols, commons and classes, constraints,
defaults, type bounds, users and MLS data, policy capabilities, and SELinux or
Xen labeling statements. It supports component filtering, `--all`, `--expand`,
`--flat`, platform validation, running-policy discovery, and verbose/debug
diagnostics. Its additive JSON mode covers typed statistics and every SELinux
or Xen component section.

`sediff` is implemented. It compares every SETools 4.7.1 CLI component:
symbols and properties, defaults and bounds, TE/xperm rules, RBAC and MLS
rules, constraints, and SELinux labeling statements. Cross-policy keys use
canonical names rather than policy-local IDs; AV rules expand attributes,
merge duplicate grants, and remove conditional permissions already granted
unconditionally. It supports individual component selection, `-A`, `-T`,
`--stats`, the default all-component mode, and verbose/debug diagnostics.

`sedta` is implemented. It builds standard and dynamic domain-transition
graphs, expands type attributes, filters domains and entrypoints, and supports
forward/reverse transitions, all shortest paths, depth-limited simple paths,
full rule output, limits, statistics, and verbose/debug diagnostics.

`seinfoflow` is implemented. It ships its own SETools 4.7.1-compatible default
permission map, accepts alternative maps with `-m`, builds weighted directed
information-flow graphs from allow rules, expands attributes, evaluates
optional Boolean assignments, and supports forward/reverse flows, all shortest
paths, depth-limited simple paths, exclusions, full rules, limits, statistics,
and verbose/debug diagnostics.

`sechecker` is implemented. It reads the compatible INI configuration format,
supports `empty_typeattr`, `assert_te`, `assert_rbac`, `ro_execs`, and
`ro_kmods`, produces the 4.7.1 report and summary format, and preserves
disabled checks, output-file mode, verbose/debug diagnostics, and exit status.

## Requirements

- Rust 1.85 or newer
- a C compiler
- `pkg-config`
- libsepol 3.9 or newer, including development headers
- libselinux, including development headers
- `checkpolicy` only when running integration tests
- Graphviz `dot` only when using `sedta --output_file` or
  `seinfoflow --output_file`

The generated binaries are dynamically linked to libsepol and libselinux. The
current implementation targets Linux systems with SELinux userspace libraries.

## Build

Build the complete workspace:

```bash
cargo build --workspace
```

Build the implemented command binaries:

```bash
cargo build -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
```

Build an optimized binary:

```bash
cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
```

Cargo uses its standard output layout:

```text
target/debug/sesearch
target/debug/seinfo
target/debug/sediff
target/debug/sedta
target/debug/seinfoflow
target/debug/sechecker
target/release/sesearch
target/release/seinfo
target/release/sediff
target/release/sedta
target/release/seinfoflow
target/release/sechecker
```

Install from a checkout with:

```bash
cargo install --path crates/setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
```

Example usage:

```bash
target/release/sesearch --allow -s sshd_t -t shadow_t /path/to/policy
target/release/sesearch --json --allow -s sshd_t -t shadow_t /path/to/policy
target/release/seinfo --type sshd_t --expand /path/to/policy
target/release/seinfo --json --type sshd_t --expand /path/to/policy
target/release/sediff old.policy new.policy
target/release/sediff --allow --allowxperm --stats old.policy new.policy
target/release/sedta -p /path/to/policy -s init -t shell -S
target/release/seinfoflow -p /path/to/policy -s init --stats
target/release/seinfoflow -p /path/to/policy -m custom-perm-map -s source_t -t target_t -S
target/release/sechecker checks.ini /path/to/policy
```

If the policy argument is omitted, `sesearch`, `seinfo`, `sedta`, `seinfoflow`,
and `sechecker` first try the current SELinuxfs policy and then installed
`policy.N` files. `sedta` and `seinfoflow` use `-p/--policy` for an explicit
policy path, matching SETools 4.7.1. `seinfoflow` uses its embedded default
permission map unless `-m/--map` is supplied.

## Structured output

`sesearch --json` and `seinfo --json` each write one compact JSON document
followed by a newline. Both include `schema_version: 1` and use a
command-specific schema identifier.

`sesearch` records the effective query criteria and ordered TE/RBAC/MLS
results. Empty searches produce `result_count: 0` and `results: []`.

`seinfo` records `--all`/`--expand`/`--flat`, explicit component criteria,
typed policy statistics when applicable, and every ordered SELinux or Xen
component section. Each section has a stable component ID, its compatibility
heading, item count, and unindented compatibility values/statements.

The default text mode and frozen 4.7.1 help output are unchanged, so `--json`
is documented here instead of being added to compatibility help. Help,
version, usage errors, policy-load errors, and analysis errors remain text;
verbose/debug diagnostics remain on stderr. See
[ADR 0002](docs/adr/0002-structured-output-v1.md) and the normative
[sesearch v1](docs/schema/sesearch-v1.schema.json) and
[seinfo v1](docs/schema/seinfo-v1.schema.json) JSON Schemas.

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
| `crates/setools-checker` | configuration-driven policy checks |
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
