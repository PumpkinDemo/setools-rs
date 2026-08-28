# ADR 0005: pure Rust binary-policy parser bootstrap

- Status: Accepted
- Date: 2026-08-27
- Scope: `setools-policy-binary`, loader migration

## Context

The immutable owned `Policy` already isolates queries, diff, graph analyses,
and CLIs from native pointers. Replacing libsepol therefore requires another
loader that produces the same complete model, but switching the CLIs after
parsing only a subset would silently remove policy semantics.

Binary policies may be malformed or unusually large in normal use. The new
parser therefore needs explicit bounds, deterministic errors, parser coverage
tests, and snapshot parity rather than a direct translation of unchecked C
pointer traversal.

## Decision

Pure Rust format work lives in the independent LGPL-2.1-only
`setools-policy-binary` crate. It has no C build script, FFI, or `unsafe` code
and depends only on `setools-policy` for the shared owned model types.

The first vertical slice parses the bounded kernel-policy header:

- little-endian kernel magic and target identifier;
- SELinux and Xen targets;
- kernel policy versions 15 through 35;
- MLS and unknown-class handling configuration;
- symbol-table and object-context family counts.

The second slice validates those counts against the exact SELinux/Xen
target/version compatibility entry, skips fully validated leading extensible
bitmaps, and decodes the common-permission symbol family. It retains names and
one-based values in a parser-owned prefix model, canonicalizes order, rejects
duplicate names/values, and applies explicit limits to serialized prefix bytes,
bitmap nodes, symbol counts, string length, and total retained allocation.

The third slice decodes the object-class family. It validates dense one-based
class values, inherited common references, inherited/local permission-bit
layout, ordinary constraints, version 19+ validation transitions, version 29+
constraint type sets, and version 27/28+ defaults. Constraint expressions are
retained as validated postfix records with bitmap indices until the later
user/role/type symbol families can resolve every name independently. A
differential test uses the libsepol-owned symbol tables only for that name
resolution and requires the reconstructed `ObjectClass`, `ConstraintRule`, and
`DefaultRule` values to match exactly.

The fourth slice decodes the kernel role and type families. It validates dense
one-based roles (including implicit `object_r`), role dominance and authorized
type bitmaps, version 24+ bounds, primary type/attribute properties, kernel
aliases, and the leading permissive-type map. Versions 20 through 23 permit the
format's unnamed attribute gaps; other supported versions require dense
primary type values. Differential tests require the reconstructed role model
and every locally available type field (canonical name, flavor, aliases,
permissive state, and bounds) to match libsepol. Attribute membership is not
claimed by this slice because kernel policies serialize `type_attr_map` after
the rule and context bodies near the end of the file.

The fifth slice completes the kernel symbol-table prefix with users, Booleans,
sensitivities, and categories. It handles version 24+ user bounds, expanded MLS
default levels and ranges, Boolean default state, and sensitivity/category
aliases. Kernel expansion counts MLS aliases in the serialized `nprim` field,
so the parser groups entries by their actual value and validates the canonical
values as the dense prefix used by libsepol's value-to-name index. User role and
MLS references are range checked. Differential tests reconstruct `User`,
`Boolean`, `Sensitivity`, `Category`, `MlsLevel`, and `MlsRange` values and
require exact equality with the libsepol-owned model.

The sixth slice decodes the unconditional access-vector table and version 16+
Boolean conditional list. It splits version 15 through 19 merged AVTAB records
into independent owned rules, handles the compact version 20+ layout, restores
the positive permission set of complemented dontaudit data, and expands ioctl
and netlink xperm bitmaps. Conditional postfix expressions are stack-validated,
range checked against the Boolean table, and retain true/false branch
ownership. Differential tests compare the resulting conditionals and the
complete non-filename TE-rule multiset against libsepol for product fixtures;
the current 1.9 MiB policy also matches all 112,585 non-filename rules.

The seventh slice decodes the two RBAC lists and filename type transitions.
Role transitions before version 26 recover the target class from the target's
`process` or `domain` class; newer records carry it explicitly. Filename
transitions use one expanded rule per record in versions 25 through 32 and a
grouped source bitmap plus default-type datum list from version 33 onward. The
parser preserves the old reader's first-record-wins duplicate behavior,
validates compressed group uniqueness, disjoint source sets, and distinct
defaults, then exposes deterministic expanded rules. Product RBAC and filename
fixtures match the libsepol-owned model; the current version 30 policy matches
all 94 filename transitions.

The eighth slice decodes the shared security-context primitive, all nine
SELinux and six Xen object-context families selected by the compatibility
table, and the trailing genfs filesystem/path table. It preserves the legacy
filesystem context pair even though the current shared labeling model does not
expose it, handles version 24 Xen 32-bit versus version 30 64-bit I/O-memory
ranges, and retains network-order IPv4/IPv6/InfiniBand addresses. Context
symbol/authorization/MLS references, numeric ranges, supported protocols,
filesystem behaviors, duplicate genfs keys, strings, record counts, and
allocation are bounded and validated. Role authorization through an attribute
is accepted provisionally during context decoding and finalized after the
trailing `type_attr_map` has been read. Product-owned SELinux and Xen fixtures
reconstruct the complete supported labeling model exactly; the current real
policy's 1,531 labeling records also match libsepol and parsing now reaches
byte offset 1,780,531.

The ninth slice completes consumption of the kernel-policy serialization. It
retains and validates canonical policy-capability numbers, decodes MLS range
transitions with the version 19–20 implicit `process` class and version 21+
explicit class layouts, and reads one trailing `type_attr_map` bitmap for every
primary type value in version 20+ policies. Concrete membership is reversed
into named attribute expansion, while version 20–23 unnamed attribute gaps are
preserved in containing-attribute membership. The final maps also turn the
earlier provisional role/context check into an exact authorization check.
Product policy-capability and type-expansion snapshots match libsepol, all 38
rules in the product MLS fixture match as a multiset, and the current version
30 real policy consumes exactly 1,947,827 bytes through EOF.

The metadata file loader reads at most the maximum fixed-header size. The
complete-policy loader reads one byte beyond its configured serialized bound
so an oversized file cannot masquerade as an exactly bounded input. Direct
complete parsing rejects input larger than the byte limit and rejects any data
after the version-selected serialization. The loaders also reject
module policies, invalid lengths, unsupported target/version combinations,
incompatible table sizes, malformed bitmaps/symbol tables/constraint postfix,
invalid defaults or unknown handling, resource-limit violations, and
truncation with typed errors.
The tenth slice converts the validated parser-owned representation into every
component accepted by `Policy::from_all_parts`. `PureRustPolicyLoader`
therefore implements the shared `PolicyLoader` trait without native code.
Versions 20 through 23 synthesize libsepol-compatible `@ttr##########` names
for unnamed attributes and reverse their retained containing-membership into
concrete expansion. Product SELinux/Xen, filename, RBAC, and MLS fixtures pass
full owned-model differential comparison. The current 1.9 MiB real policy also
matches the libsepol snapshot for all components; rule and labeling collections
are compared as multisets where native hash iteration does not define order.

The crate includes exhaustive synthetic truncation, deterministic one-bit
mutation tests, and a separate cargo-fuzz target covering header parsing,
complete parsing, and owned reconstruction. The parser retains a conservative
logical allocation charge. Reconstruction starts from that charge and applies
the same `max_total_allocation_bytes` limit to the entire owned `Policy`, its
strings, nested collections, B-tree name indexes, and the temporary map used
to expand version 20 through 23 unnamed attributes. Input bytes are limited
separately. `to_policy` reports an over-budget reconstruction as the existing
typed `LimitExceeded` error, and `PureRustPolicyLoader` preserves that typed
parse error. The default CLI build selects `PureRustPolicyLoader` and does not
depend on libsepol. `native-libsepol` is an opt-in Cargo feature for comparison;
when compiled, `SETOOLS_POLICY_BACKEND=libsepol` selects it, while `rust` and
`pure-rust` select the Rust loader. A product integration test compares the
status, stdout, and stderr of all six binaries under both loaders.

## Consequences

- Pure Rust parsing and complete immutable-policy reconstruction now exist
  behind the already established loader/model boundary without changing CLI
  behavior.
- Supporting header versions 15 through 35 still follows the exact target
  compatibility table; Xen has entries only for versions 24 and 30 in this
  range.
- The binary serialization is consumed end to end and can be returned as the
  shared immutable `Policy` through `PureRustPolicyLoader`.
- Property tests and a libFuzzer target now exist. The allocation budget now
  covers parsing plus owned-model reconstruction. The CLI can select either
  backend, and product fixture plus selected real-policy results match at the
  CLI boundary. The pure Rust loader is now the default build; the native
  loader remains an opt-in comparison feature.
