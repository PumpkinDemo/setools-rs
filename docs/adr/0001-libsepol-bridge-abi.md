# ADR 0001: libsepol bridge ABI and ownership

- Status: Accepted
- Date: 2026-08-17
- Scope: `setools-sepol`

## Context

SETools needs data that is only available through libsepol's internal
`policydb` representation. Binding that representation directly in Rust would
make the Rust model depend on unstable C layouts and would spread unsafe
pointer traversal beyond the FFI crate.

The first vertical slice only loads policy metadata, but its ownership and
error rules must also work for the iterators added later for types, classes,
permissions, and AV rules.

## Decision

`setools-sepol` compiles a small project-owned C ABI against the installed
libsepol headers. Rust binds only this ABI.

### ABI surface

- Native objects use incomplete C types such as `st_policy`.
- ABI values use fixed-width integers. No libsepol structure, enum type,
  bitmap, hash table, or pointer is exposed.
- `st_policy_load` returns an owned handle. A non-null handle must be released
  exactly once with `st_policy_free`.
- `st_policy_metadata` copies scalar values into a caller-owned POD structure.
- Functions return zero for success and a non-zero `st_status` for failure;
  constructors return null on failure.

The bridge and its Rust binding are versioned and shipped together. This is a
project-internal ABI, not a separately supported system ABI. `st_bridge_abi_version`
allows the Rust wrapper to reject an accidental object-version mismatch.

### Error ownership

`st_error` starts zero-initialized. A failing bridge call may allocate its
UTF-8 diagnostic with the C allocator. The caller copies the diagnostic and
calls `st_error_clear` exactly once. `st_error_clear` accepts a null pointer
and resets both fields, so Rust can use one cleanup path.

An error object must be empty before it is passed to another bridge call. The
Rust wrapper enforces this by creating a fresh value for every call.

### Lifetime and thread rules

- A policy handle is thread-confined. The Rust RAII owner is deliberately
  neither `Send` nor `Sync`.
- Metadata is copied and has no native lifetime.
- Future string views will be pointer-plus-length, read-only, and valid only
  until their owning iterator advances or is freed. Rust must copy each view
  before advancing.
- Future iterators own their traversal state, borrow one policy handle, and
  have an explicit free function. Freeing the policy while an iterator exists
  is invalid; the safe Rust wrapper will encode that relationship.
- No callback may unwind or panic across the FFI boundary. The current message
  callback is implemented entirely in C.

The loader eagerly copies the complete Rust policy model and releases the
native handle before returning `setools_policy::Policy`. Query, diff, graph,
and CLI crates therefore never depend on native pointers or lifetimes.

### Compatibility and build

The bridge includes public libsepol APIs for allocation and loading and
contains any required internal `policydb` access in `bridge.c`. It is compiled
with the `cc` crate. Normal system discovery uses `pkg-config` and requires
libsepol 3.9 or newer; libselinux is not linked. Development environments may
set `USERSPACE_SRC` to compile and link against an explicit SELinux userspace
source build outside the repository. Bridge ABI 6 moves running-policy
filesystem/config discovery to safe Rust and retains only scalar libsepol
version limits in the C ABI.

Portable release builds may instead set `SETOOLS_LIBSEPOL_STATIC_ROOT` to a
verified prefix containing the libsepol headers and static archive, as recorded
in ADR 0004.

All numeric values read from C are validated before constructing Rust enums or
IDs. A new libsepol value therefore produces an explicit loader error instead
of undefined behavior or an invalid Rust value.

## Consequences

- Unsafe code and libsepol layout knowledge remain inside `setools-sepol` and
  its C source.
- The bridge must be tested against every supported libsepol version and under
  ASan/UBSan. Malformed-policy fuzzing remains necessary because the binary
  parser is C; this design does not make untrusted policy loading end-to-end
  memory safe.
- Adding a view or iterator requires updating this ADR if its ownership differs
  from the rules above.
