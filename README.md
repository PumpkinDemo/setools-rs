# setools-rs

`setools-rs` is a standalone Rust implementation of the SETools command-line
policy analysis tools. Its CLI compatibility target and version identity are
SETools 4.7.1.

The project does not depend on the Python/Cython SETools implementation. A
normal source build uses the pure Rust binary-policy loader and requires no
libsepol, libselinux, C compiler, or `pkg-config`. The optional native
compatibility loader remains available behind a Cargo feature.

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
`--stats`, the default all-component mode, and verbose/debug diagnostics. Its
additive JSON mode covers every component with canonical added, removed, and
modified results.

`sedta` is implemented. It builds standard and dynamic domain-transition
graphs, expands type attributes, filters domains and entrypoints, and supports
forward/reverse transitions, all shortest paths, depth-limited simple paths,
full rule output, limits, statistics, and verbose/debug diagnostics. Its
additive JSON mode provides typed transition/path results, rule provenance,
and graph statistics.

`seinfoflow` is implemented. It ships its own SETools 4.7.1-compatible default
permission map, accepts alternative maps with `-m`, builds weighted directed
information-flow graphs from allow rules, expands attributes, evaluates
optional Boolean assignments, and supports forward/reverse flows, all shortest
paths, depth-limited simple paths, exclusions, full rules, limits, statistics,
and verbose/debug diagnostics. Its additive JSON mode provides weighted
flow/path results, permission-map and Boolean query metadata, contributing
rules, and graph statistics.

`sechecker` is implemented. It reads the compatible INI configuration format,
supports `empty_typeattr`, `assert_te`, `assert_rbac`, `ro_execs`, and
`ro_kmods`, produces the 4.7.1 report and summary format, and preserves
disabled checks, output-file mode, verbose/debug diagnostics, and exit status.
Its additive JSON mode provides typed check findings, evidence, disabled
reasons, and summary counts.

Pure Rust binary-policy parsing is implemented in the independent
`setools-policy-binary` crate. The bounded parser validates the exact
SELinux/Xen version compatibility entry, decodes the leading bitmaps plus the
common-permission, object-class, role, type, user, Boolean, sensitivity, and
category symbol families, and applies explicit serialized-byte, count, string,
and total-allocation limits. Object classes
include inherited/local permissions, constraints, validation transitions, and
defaults; roles/types include dominance and authorized-type bitmaps, bounds,
type/attribute flavor, aliases, and permissive state. Users retain versioned
bounds and MLS default levels/ranges; MLS symbols retain aliases and category
sets. It now also decodes the unconditional AVTAB plus Boolean postfix
conditionals and both rule branches, including the version 15–19 merged AVTAB
layout, the version 20+ compact layout, standard/type rules, version 30+ xperm,
and version 34+ conditional xperm. The resulting symbols, conditionals, and TE
rule body are differentially tested against the libsepol owned model.
The parser also decodes role transitions/allows and both the version 25–32
expanded and version 33+ compressed filename-transition layouts. Security
contexts, all versioned SELinux/Xen object-context families, the trailing
genfs table, MLS range transitions, policy capabilities, and every
`type_attr_map` row are decoded with reference, range, protocol, duplicate-key,
membership, and allocation validation. Named attributes receive the same
concrete type expansion as libsepol, including compatibility with unnamed
attribute gaps in versions 20–23. Product SELinux/Xen/MLS fixtures and the
current real policy match the supported libsepol-owned model, and the real
policy is consumed through its exact final byte. `PureRustPolicyLoader` now
reconstructs the complete immutable `Policy`; product SELinux/Xen, filename,
RBAC, and MLS fixtures plus the current 1.9 MiB real policy pass full-model
differential comparison with the libsepol loader. Its allocation limit covers
the parser-owned representation and the complete reconstructed model under one
conservative logical budget, including owned strings, nested collections, name
indexes, and temporary compatibility expansion. Input bytes have a separate
serialized-size cap. `policy-prefix` reports both the parser-retained charge
and the estimated complete-load peak. The CLI supports `SETOOLS_POLICY_BACKEND`
for loader-parity work. The default build uses pure Rust; `rust` and
`pure-rust` select it explicitly. Build with `--features native-libsepol` to
enable the optional `libsepol` backend. Product fixtures and the current 1.9
MiB policy produce byte-identical selected CLI results under both loaders.
Inspect the metadata or decoded prefix without any native loader using:

```bash
cargo run -p setools-policy-binary --example policy-header -- /path/to/policy
cargo run -p setools-policy-binary --example policy-prefix -- /path/to/policy
```

Parser unit tests include exhaustive truncation and deterministic one-bit
mutation passes. The separate non-published cargo-fuzz workspace exercises
header parsing, complete parsing, and owned reconstruction:

```bash
cargo +nightly fuzz run parse_policy
```

## Requirements

- Rust 1.85 or newer
- a C compiler, `pkg-config`, and libsepol 3.9 or newer only for the optional
  `native-libsepol` feature or for building every workspace member
- `checkpolicy` only when running integration tests
- Graphviz `dot` only when using `sedta --output_file` or
  `seinfoflow --output_file`

The normal generated binaries do not link libsepol. Builds using the optional
`native-libsepol` feature dynamically link libsepol but never libselinux or
PCRE2.

## Build

Build the default pure Rust command binaries:

```bash
cargo build -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
```

Build every workspace member, including the optional native loader:

```bash
cargo build --workspace
```

Build an optimized binary:

```bash
cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
```

Build the native compatibility flavor for direct loader comparison:

```bash
cargo build -p setools-cli --features native-libsepol --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
```

Build the publishable x86_64 Linux pure Rust static archive:

```bash
scripts/build-portable-release.sh
```

The default portable script builds the pure Rust loader. It does not download,
compile, or link libsepol, statically links the Rust/C runtime, and fails if any
binary retains an ELF `NEEDED` entry. To additionally exercise the finished
binaries against a policy during packaging:

```bash
scripts/build-portable-release.sh --policy /path/to/policy
```

On a fresh checkout, the script first downloads the complete locked Cargo
dependency set so that the corresponding-source bundle can vendor every locked
crate offline. This includes build dependencies of the optional native
compatibility feature, but does not download or link libsepol for the default
pure Rust artifact.

The optional static native compatibility artifact remains available for direct
loader comparison. It downloads the official libsepol 3.11 source only when it
is not cached, verifies its pinned SHA-256, and includes that corresponding
source archive:

```bash
scripts/build-portable-release.sh --native-libsepol --policy /path/to/policy
```

The archive and checksum are written to `dist/`. It includes licenses, man
pages, shell completions, per-file hashes, and corresponding setools-rs source;
the source archive vendors the locked Cargo dependencies for offline rebuilds.
The native compatibility archive additionally includes the exact libsepol
source. See [the release guide](RELEASING.md) and [third-party notice](THIRD_PARTY.md).

Pushing a tag whose name exactly matches the package version, such as
`v4.7.1`, starts the GitHub Actions release workflow. It runs the full Fedora
workspace verification, builds and smoke-tests the pure Rust portable archive
on x86_64 Linux, checks its checksum, then creates or updates the matching
GitHub Release with the archive and `.sha256` file. See
[the release guide](RELEASING.md) for the tag command and repository setting.

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

Generate or verify the committed man pages and shell completions:

```bash
cargo run -p setools-xtask -- generate
cargo run -p setools-xtask -- check
```

The generated files are under `man/man1/` and `completions/{bash,zsh,fish}/`.
For example, inspect a page directly with `man -l man/man1/sesearch.1`.

Run the versioned end-to-end performance suite against a representative policy:

```bash
python3 scripts/benchmark-cli.py --policy /path/to/policy
```

The Linux runner records per-process wall time and peak RSS without depending
on legacy SETools. See [the performance guide](docs/PERFORMANCE.md) for the
scenario contract, retained baseline, heavyweight full-diff command, and
comparison rules.

Example usage:

```bash
target/release/sesearch --allow -s sshd_t -t shadow_t /path/to/policy
target/release/sesearch --json --allow -s sshd_t -t shadow_t /path/to/policy
target/release/seinfo --type sshd_t --expand /path/to/policy
target/release/seinfo --json --type sshd_t --expand /path/to/policy
target/release/sediff old.policy new.policy
target/release/sediff --allow --allowxperm --stats old.policy new.policy
target/release/sediff --json --allow --allowxperm old.policy new.policy
target/release/sedta -p /path/to/policy -s init -t shell -S
target/release/sedta --json -p /path/to/policy -s init -t shell -S --full
target/release/seinfoflow -p /path/to/policy -s init --stats
target/release/seinfoflow --json -p /path/to/policy -s init --stats -l 3
target/release/seinfoflow -p /path/to/policy -m custom-perm-map -s source_t -t target_t -S
target/release/sechecker checks.ini /path/to/policy
target/release/sechecker --json checks.ini /path/to/policy
```

If the policy argument is omitted, `sesearch`, `seinfo`, `sedta`, `seinfoflow`,
and `sechecker` first try the current SELinuxfs policy and then installed
`policy.N` files. `sedta` and `seinfoflow` use `-p/--policy` for an explicit
policy path, matching SETools 4.7.1. `seinfoflow` uses its embedded default
permission map unless `-m/--map` is supplied.

## Structured output

`sesearch --json`, `seinfo --json`, `sediff --json`, `sedta --json`,
`seinfoflow --json`, and `sechecker --json` each write one compact JSON document
followed by a newline. All include `schema_version: 1` and use a command-specific
schema identifier.

`sesearch` records the effective query criteria and ordered TE/RBAC/MLS
results. Empty searches produce `result_count: 0` and `results: []`.

`seinfo` records `--all`/`--expand`/`--flat`, explicit component criteria,
typed policy statistics when applicable, and every ordered SELinux or Xen
component section. Each section has a stable component ID, its compatibility
heading, item count, and unindented compatibility values/statements.

`sediff` records both policy paths, the effective component selection, and
ordered semantic differences for all 38 components. Each result has stable
added/removed/modified counts and canonical detail arrays. Explicit empty
components are retained; default all mode omits them. With `--stats`, counts
remain complete while detail arrays are empty.

`sedta` records the effective forward/reverse transition or path query and
returns tagged transitions or ordered paths. `--full` adds structured standard
and dynamic rule provenance, including entrypoint details; `--stats` adds typed
graph counts. `--json` and Graphviz `--output_file` are mutually exclusive.

`seinfoflow` records the effective flow/path query, minimum weight, exclusions,
permission-map source, and optional Boolean evaluation. Results retain every
edge weight; `--full` adds ordered contributing allow rules and `--stats` adds
typed full-graph counts. `--json` and Graphviz `--output_file` are mutually
exclusive.

`sechecker` records the configuration path, typed result for every configured
check, canonical rule evidence, disabled reasons, and pass/fail summary counts.
A completed check run exits 0 when clean or 1 when findings exist; both statuses
write a full JSON document. Configuration and operational errors remain text.
`--json` and text-report `--output_file` are mutually exclusive.

The default text mode and frozen 4.7.1 help output are unchanged, so `--json`
is documented here instead of being added to compatibility help. Help,
version, usage errors, policy-load errors, and analysis errors remain text;
verbose/debug diagnostics remain on stderr. See
[ADR 0002](docs/adr/0002-structured-output-v1.md) and the normative
[sesearch v1](docs/schema/sesearch-v1.schema.json),
[seinfo v1](docs/schema/seinfo-v1.schema.json),
[sediff v1](docs/schema/sediff-v1.schema.json),
[sedta v1](docs/schema/sedta-v1.schema.json),
[seinfoflow v1](docs/schema/seinfoflow-v1.schema.json), and
[sechecker v1](docs/schema/sechecker-v1.schema.json) JSON Schemas.

## Test

With the development requirements installed:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p setools-xtask -- check
python3 scripts/benchmark-cli.py --list
```

The repository contains only tests for the Rust implementation. Historical
oracle implementations and cross-implementation differential tooling are not
build or test dependencies of this project.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/setools-sepol` | project-owned C bridge and native loading |
| `crates/setools-policy` | immutable owned policy model |
| `crates/setools-policy-binary` | bounded pure Rust binary-policy parser |
| `fuzz` | independent binary-policy libFuzzer target |
| `crates/setools-query` | query preparation and matching |
| `crates/setools-checker` | configuration-driven policy checks |
| `crates/setools-diff` | semantic policy comparison |
| `crates/setools-graph` | graph analyses |
| `crates/setools-cli` | CLI rendering and binary entry points |
| `xtask` | deterministic man-page and completion generator |
| `man/man1` | generated section-1 manual pages |
| `completions` | generated Bash, Zsh, and Fish completions |
| `benchmarks` | versioned standalone CLI benchmark scenarios |
| `scripts/benchmark-cli.py` | Linux wall-time and peak-RSS runner |
| `docs` | design, progress, and architecture decisions |

## Publication state

This repository can be cloned, built, tested, tagged, and released on its own.
The x86_64 Linux pure Rust static archive is the first portable binary
distribution. The internal crates currently set `publish = false`: crates.io
publication is deferred until the library APIs stabilize. See
[RELEASING.md](RELEASING.md).

## License

The library crates are licensed under LGPL-2.1-only. The command-line programs
and test code are licensed under GPL-2.0-only. See [COPYING](COPYING) and the
complete texts in [LICENSES](LICENSES).
