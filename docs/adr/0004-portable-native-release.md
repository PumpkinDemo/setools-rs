# ADR 0004: libsepol-only native backend and portable Linux release

- Status: Accepted
- Date: 2026-08-27
- Scope: `setools-sepol`, CLI binary distribution

## Context

The original native build linked both libsepol and libselinux. libselinux was
used only to discover the running-policy paths, but it added an ABI-sensitive
runtime dependency and also pulled in PCRE2. A user copying a release binary
therefore needed compatible libsepol, libselinux, and PCRE2 shared libraries.

The policy parser itself still needs low-level libsepol data until the pure
Rust parser can construct the complete owned `Policy`. A first release must be
usable without installing that native dependency stack while retaining a
normal distribution-friendly source build.

## Decision

The native backend links only libsepol. Running-policy discovery is implemented
in safe Rust from `/proc/filesystems`, `/proc/mounts`, SELinuxfs `policy` and
`policyvers`, and `/etc/selinux/config`. The candidate order remains current
SELinuxfs policy first, followed by installed `policy.N` files from the maximum
libsepol version down to the minimum.

The bridge ABI is version 6. It exposes only libsepol's minimum and maximum
kernel policy versions for discovery; all libselinux string views and calls are
removed.

Two build modes are supported:

- The default source build uses `pkg-config` and dynamically links libsepol
  3.9 or newer.
- `SETOOLS_LIBSEPOL_STATIC_ROOT` points at a prefix containing
  `include/sepol/policydb.h` and `lib/libsepol.a`. This is the explicit static
  bridge mode used by release automation.

The first portable artifact is an x86_64 Linux static PIE. The release script
downloads libsepol 3.11 from the upstream release URL, verifies the pinned
SHA-256 before extraction, builds it without CIL or a shared library, enables
Rust's static CRT, and rejects any resulting ELF with a `DT_NEEDED` entry. It
then runs all six `--version` commands and can load a caller-supplied binary
policy as a smoke test.

The archive includes the six stripped binaries, licenses, README, man pages,
completions, per-file hashes, the exact libsepol source archive, and the
setools-rs source used for rebuilding and relinking. The latter also vendors
the exact Cargo dependency sources selected by `Cargo.lock` and contains an
offline Cargo source configuration.

## Consequences

- Dynamic source builds no longer require libselinux or PCRE2.
- Portable archive users do not need libsepol, libselinux, PCRE2, libgcc, or a
  particular glibc shared object installed.
- The portable binaries still contain the C libsepol parser and must not be
  described as memory-safe or C-free.
- Static glibc is acceptable for these file-oriented CLIs because they do not
  use DNS or account-service lookups. The artifact is still limited to the
  tested x86_64 Linux target; other architectures need their own builds and
  verification.
- Graphviz `dot` remains an optional external executable for PNG output. It is
  not a linked runtime library.
