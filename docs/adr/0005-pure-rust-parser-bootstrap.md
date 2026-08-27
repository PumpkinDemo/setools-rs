# ADR 0005: pure Rust binary-policy parser bootstrap

- Status: Accepted
- Date: 2026-08-27
- Scope: `setools-policy-binary`, loader migration

## Context

The immutable owned `Policy` already isolates queries, diff, graph analyses,
and CLIs from native pointers. Replacing libsepol therefore requires another
loader that produces the same complete model, but switching the CLIs after
parsing only a subset would silently remove policy semantics.

Binary policies are privileged and may be supplied by untrusted callers. The
new parser needs explicit bounds, deterministic errors, fuzzing, and snapshot
parity rather than a direct translation of unchecked C pointer traversal.

## Decision

Pure Rust format work lives in the independent LGPL-2.1-only
`setools-policy-binary` crate. It has no C build script, FFI, or `unsafe` code
and depends only on `setools-policy` for shared metadata types.

The first vertical slice parses the bounded kernel-policy header:

- little-endian kernel magic and target identifier;
- SELinux and Xen targets;
- kernel policy versions 15 through 35;
- MLS and unknown-class handling configuration;
- symbol-table and object-context family counts.

The file loader reads at most the maximum fixed-header size. It rejects module
policies, invalid lengths, unsupported targets or versions, invalid unknown
handling, and truncation with typed errors. A differential integration test
compiles one product-owned policy and requires the pure Rust metadata to equal
the libsepol-backed owned metadata.

This metadata loader deliberately does not implement `PolicyLoader`. The CLI
continues to use `LibsepolLoader` until the pure Rust implementation can build
the entire owned model and passes model-snapshot differential tests.

## Consequences

- Pure Rust parsing has started behind the already established loader/model
  boundary without weakening existing CLI behavior.
- Supporting header versions 15 through 35 does not mean all records in those
  versions are parsed yet.
- The next slices should decode compatibility table selection and symbol
  tables, add per-section allocation/count limits, then expand to rules and
  contexts.
- Fuzz targets and a total allocation budget are required before exposing the
  pure Rust loader to arbitrary CLI inputs.
