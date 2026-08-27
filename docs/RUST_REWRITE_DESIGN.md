# SETools Rust Rewrite Design

Status: Draft  
Compatibility baseline: SETools 4.7.1  
Last updated: 2026-08-27

Project tracking: [RUST_REWRITE_PROGRESS.md](RUST_REWRITE_PROGRESS.md)  
Instructions for future agent sessions: [AGENT.md](AGENT.md)

## 1. Purpose

This document describes a staged rewrite of the SETools command-line and
analysis libraries in Rust. The rewrite will initially provide the existing
command names, including `sesearch`, `seinfo`, `sediff`, `sedta`,
`seinfoflow`, and `sechecker`.

The first release should focus on `sesearch`, `seinfo`, and `sediff`. These
tools cover policy loading, most policy objects, rule querying, semantic
normalization, and deterministic output. The graph-based tools can reuse the
same model after it is stable.

The rewrite is not intended to change the default CLI behavior. New output
formats and APIs should be additive.

## 2. Goals

- Keep the existing executable names, options, defaults, exit status, and
  text output compatible with SETools 4.7.1.
- Place policy data in an immutable, owned Rust model after loading.
- Restrict C FFI and `unsafe` code to one small crate.
- Share policy loading, matching, rendering, and error handling among all
  binaries.
- Preserve semantic behavior such as indirect attribute matching and
  attribute-expanded rule differences.
- Produce deterministic output regardless of hash-map order or parallel
  execution.
- Allow an external development harness to use historical policy fixtures and
  the Python implementation as a differential oracle during migration,
  without making either a repository, build, test, or runtime dependency.
- Implement a pure Rust binary-policy parser without changing the
  query and diff layers.

## 3. Non-goals for the first release

- Replacing `libsepol` with a new binary-policy parser.
- Redesigning or simplifying existing command-line options.
- Reimplementing the Qt GUI.
- Promising a stable public Rust API before CLI compatibility is reached.
- Shipping portable binaries for every architecture or bundling optional
  Graphviz output support.
- Improving questionable legacy behavior in the default compatibility mode.

Compatibility fixes and intentional behavior changes should be introduced
behind a new option or in a separately versioned mode.

## 4. Architecture

```text
policy.N or the running policy
              |
     +--------+--------+
     |                 |
libsepol C bridge   pure Rust parser
 (current loader)   (metadata slice)
     |                 |
     +--------+--------+
              v
      immutable Rust Policy
     symbols, rules, contexts,
       MLS data, and indexes
          |             |
          v             v
       queries      semantic diff
          |             |
          +------|------+
                 v
        compatibility/JSON renderers
                 |
     sesearch, seinfo, sediff, ...
```

The important boundary is the owned `Policy`. Query and diff code must not
depend on `libsepol` pointers, C structure layouts, or native lifetimes.

Loading has two stages:

1. `libsepol` reads the binary policy and the bridge exposes read-only views.
2. Rust copies and normalizes those views into an owned `Policy`, then releases
   the native policy handle.

This boundary permits the in-progress `PureRustPolicyLoader` to produce the same model.
It also allows query execution to be parallelized without sharing a mutable
`policydb`.

## 5. Cargo workspace

```text
Cargo.toml
crates/
  setools-sepol/
    build.rs
    c/
      bridge.c
      bridge.h
    src/
  setools-policy/
  setools-policy-binary/
  setools-query/
  setools-diff/
  setools-graph/
  setools-checker/
  setools-cli/
    src/
      lib.rs
      bin/
        sesearch.rs
        seinfo.rs
        sediff.rs
        sedta.rs
        seinfoflow.rs
        sechecker.rs
xtask/
tests/
  policies/
  cli/
  golden/
```

### 5.1 Crate responsibilities

`setools-sepol`

- Build and link the C bridge and libsepol.
- Own all raw native handles.
- Translate native errors into typed Rust errors.
- Expose safe iterators or snapshot-building operations to
  `setools-policy`.
- Contain all `unsafe` Rust used by the project.

`setools-policy`

- Define strongly typed IDs and the immutable `Policy` model.
- Resolve policy-local names and aliases.
- Normalize attributes, permissions, contexts, MLS values, and conditional
  expressions.
- Build indexes needed by queries and graph analysis.
- Define a loader boundary that can support both libsepol and future pure
  Rust implementations.

`setools-policy-binary`

- Parse binary-policy data without C, FFI, or `unsafe`.
- Enforce explicit section, count, string, and allocation limits.
- Produce the same metadata and eventually the same complete owned `Policy` as
  the libsepol loader.
- Stay disconnected from CLI loader selection until complete snapshot
  differential tests pass.

`setools-query`

- Define query specifications independent of CLI argument parsing.
- Compile names, sets, and regular expressions before rule scanning.
- Implement component queries and TE, RBAC, and MLS rule queries.
- Return IDs or borrowed records instead of formatted strings.

`setools-diff`

- Compare two policies by semantic names rather than policy-local numeric IDs.
- Expand and coalesce rules where required by SETools behavior.
- Compute component results independently so their memory can be released
  after rendering.
- Provide a count-only path for `sediff --stats` where practical.

`setools-graph`

- Implement domain-transition and information-flow graphs.
- Reuse `setools-query` rather than interpreting policy records separately.
- Load permission maps independently of the core policy representation.

`setools-checker`

- Parse and validate the `sechecker` INI registry independently of CLI parsing.
- Implement typed `empty_typeattr`, TE/RBAC assertion, executable, and kernel
  module read-only results over the immutable owned policy.
- Return typed findings and debug traces; do not own report formatting, logging,
  output files, or process exit behavior.

`setools-cli`

- Produce all command-line binaries from one Cargo package.
- Own argument parsing, logging, running-policy discovery, output selection,
  and process exit behavior.
- Keep compatibility text rendering separate from the core model.
- Optionally provide versioned JSON/JSON Lines output.

Library crates should retain the existing LGPL-2.1-only licensing model when
code is ported from the current library. The CLI package should retain the
GPL-2.0-only model used by the current programs.

## 6. libsepol bridge

### 6.1 Why use a C bridge

SETools traverses libsepol's internal `policydb` structures. Binding every
structure from `sepol/policydb/policydb.h` directly would expose a large,
version-sensitive C
layout to Rust and spread unsafe pointer traversal through the project.

A bridge compiled against the installed SELinux userspace headers creates a
small project-owned ABI. The bridge may change internally for a new libsepol
version while its Rust-facing API remains stable.

### 6.2 Bridge API rules

- Export opaque handles, fixed-width integers, and simple read-only view
  structures only.
- Do not expose `policydb_t`, `hashtab_t`, `avtab_t`, or `ebitmap_t` directly.
- Represent strings as pointer and length. Views are valid only while their
  owner and current iterator item remain alive.
- Provide explicit constructors, destructors, and error-message free
  functions.
- Do not allow Rust panics to cross an FFI callback boundary.
- Validate null pointers, enum values, numeric ranges, and policy object
  relationships before creating Rust objects.
- Keep the native handle thread-confined.
- Copy all data needed by the Rust model, then free the native handle.

The bridge can expose opaque iterators, for example:

```c
st_policy *st_policy_load(const char *path, st_error *error);
void st_policy_free(st_policy *policy);

st_type_iter *st_policy_types(st_policy *policy);
int st_type_next(st_type_iter *iter, st_type_view *view);
void st_type_iter_free(st_type_iter *iter);
```

The exact ABI should be specified in a separate ADR before implementation.

### 6.3 Normalization without mutating policydb

The current implementation reconstructs some information by modifying the
loaded `policydb`. The Rust loader should prefer reading the underlying maps
and constructing equivalent owned data:

- `attr_type_map` becomes attribute-to-type membership.
- The reverse type-to-attribute index is generated in Rust.
- `permissive_map` becomes a flag on the Rust type record.
- Missing attribute names use the compatible synthesized `@ttr...` name.
- Alias hash entries become explicit alias-to-primary-name mappings.

This keeps the native policy read-only and reduces ownership hazards.

### 6.4 Build and version policy

- Use `pkg-config` to locate system libsepol and `cc` to compile the
  bridge.
- Do not require bindgen or libclang for a normal build.
- Initially support the same minimum libsepol version as the compatibility
  baseline.
- Test the minimum version, the latest stable version, and SELinux userspace
  `main` in CI.
- Dynamic system linking is the default.
- A static-prefix mode builds the portable artifact with pinned libsepol 3.11;
  it does not replace the pure Rust parser when C-free parsing is required.
- Release automation rejects portable ELF files with any dynamic `NEEDED`
  library and includes corresponding setools-rs and libsepol source.

## 7. Policy model

### 7.1 Typed IDs

Use dense, policy-local IDs instead of strings for internal relationships:

```rust
pub struct TypeId(u32);
pub struct AttributeId(u32);
pub struct ClassId(u32);
pub struct PermissionId(u32);
pub struct BooleanId(u32);
pub struct ConditionalId(u32);

pub enum TypeOrAttributeId {
    Type(TypeId),
    Attribute(AttributeId),
}
```

IDs from different policies must never be compared in `sediff`. Diff keys use
canonical names and semantic values.

### 7.2 Policy contents

The model must eventually include all objects needed by the supported tools:

- Policy version, target platform, MLS flag, and unknown handling.
- Commons, classes, permissions, and policy capabilities.
- Types, attributes, aliases, bounds, and permissive state.
- Roles, users, Booleans, sensitivities, categories, levels, and ranges.
- TE, xperm, filename transition, RBAC, and MLS rules.
- Conditional expression ASTs and true/false rule branches.
- Constraints and validation-transition expressions.
- Initial SIDs, fs-use, genfscon, portcon, nodecon, netifcon, InfiniBand, and
  Xen labeling records.
- Default rules and security contexts.

Names should be interned once per policy. Dense membership sets should use a
compact bitset representation unless benchmarks show that a sparse structure
is superior.

### 7.3 Indexes

Indexes should be built once during loading or lazily with immutable one-time
initialization:

- Name and alias to ID.
- Attribute to member types and type to containing attributes.
- Class to permissions and permission name to class-local bit.
- Rule-kind ranges.
- Boolean to conditionals.
- Optional source, target, and class rule indexes if benchmarks justify their
  memory cost.

The first implementation should prefer a simple linear rule scan with compiled
criteria. Real-policy benchmarks should drive additional indexes.

## 8. Query design

CLI argument types and query execution types should be separate. For example:

```rust
pub struct TeRuleQuery {
    pub kinds: RuleKindSet,
    pub source: Option<SymbolMatcher>,
    pub target: Option<SymbolMatcher>,
    pub classes: ClassMatcher,
    pub permissions: PermissionMatcher,
    pub xpermissions: XpermissionMatcher,
    pub default: Option<SymbolMatcher>,
    pub booleans: BooleanMatcher,
}
```

Before scanning rules, query preparation should:

- Resolve exact names and aliases to IDs.
- Compile each regular expression once.
- Expand indirect attribute criteria into membership bitsets.
- Resolve class and permission sets.
- Normalize xpermission ranges.
- Validate incompatible TE/RBAC/MLS options.

The implementation must preserve the existing meanings of:

- Exact versus regex matching.
- Direct versus indirect source and target matching.
- Permission intersection, equality, and subset matching.
- Extended-permission equality and ranges.
- Boolean intersection, equality, and regex matching.
- Transition default matching.
- TE, RBAC, and MLS rule selection restrictions.

`sesearch --allow` is the preferred first vertical slice because it exercises
loading, attribute membership, class permissions, AV rules, query preparation,
sorting, and rendering.

## 9. Semantic diff design

`sediff` is not a textual or raw-record comparison. Rules that are encoded
differently can have the same semantics, and attributes must be expanded before
some rules are compared.

For AV rules, build a canonical key:

```text
rule kind
+ canonical conditional expression
+ conditional branch
+ expanded source type name
+ expanded target type name
+ class name
```

The permission set is the value associated with that key. The algorithm is:

1. Expand source and target attributes to concrete types.
2. Merge duplicate keys by unioning permissions.
3. Apply the compatibility rule for permissions already granted by an
   unconditional rule.
4. Compare key sets between policies.
5. Report a shared key with changed permissions as modified.
6. Report keys present on one side only as added or removed.

Other components use component-specific normalized keys and values. Important
examples include:

- Types: aliases, attributes, and permissive state.
- Roles: authorized type names.
- Users: roles and MLS values.
- Classes and commons: permission names and common association.
- Booleans: default state.
- Constraints: normalized expression trees.
- Contexts and labeling statements: semantic address, range, protocol, path,
  and context fields.

Compute and render components in a fixed order. A component result can be
released after it is written, preventing a full-policy diff from retaining all
detail records at once. Independent component computation may later use
parallel workers, but collection and rendering must remain deterministic.

## 10. Graph analysis design

`setools-graph` consumes only the immutable owned `Policy`; no libsepol handle,
pointer, layout, or lifetime crosses into graph analysis. Graph edges remain in
policy declaration order, with ordered indexes used for lookup, so breadth-first
and path enumeration are deterministic and compatible with the 4.7.1 tools.

The information-flow permission map is independent runtime semantic data. The
4.7.1-compatible default map is shipped inside `setools-graph` under its
LGPL-2.1-only library boundary, while `-m/--map` loads an alternative file.
Neither path reads a legacy SETools installation or a parent repository.

For information flow, only allow rules contribute. Source and target attributes
expand to concrete type pairs; `w` permissions create subject-to-object edges,
`r` permissions create object-to-subject edges, `b` creates both, and `n`/`u`
create none. Self-edges are discarded. Multiple rules merge on an ordered type
pair, retain their rule provenance, and use the maximum contributing permission
weight in each direction.

Queries derive a subgraph by removing excluded types, edges below the minimum
weight, and optionally rules disabled by a Boolean assignment. A missing Boolean
criterion retains both conditional branches for compatibility; an empty
assignment evaluates policy defaults, and named assignments override those
defaults. Full-graph statistics remain separate from filtered query results.

## 11. CLI and output compatibility

Each executable should have a thin `main` that delegates to shared CLI code.
Compatibility tests must freeze:

- Long and short option names.
- Positional arguments and running-policy defaults.
- Validation errors and exit status.
- stdout versus stderr selection.
- Text, indentation, section order, sorting, and blank lines.
- `--stats`, empty-result, verbose, and debug behavior.
- SIGPIPE/broken-pipe behavior.

Do not use core-model `Debug` or incidental `Display` output as the CLI format.
Use explicit renderers:

```text
CompatTextRenderer
JsonRenderer
JsonLinesRenderer (optional)
```

The compatibility renderer is the default. Structured output is additive and
must include a schema version. JSON records use stable names and values, not
internal numeric IDs.

The accepted structured-output contracts are documented in
[ADR 0002](adr/0002-structured-output-v1.md). `sesearch`, `seinfo`, `sediff`,
`sedta`, `seinfoflow`, and `sechecker` have separate normative schemas in
[`docs/schema`](schema/): search results use family/rule identifiers, component
information uses typed statistics and stable section identifiers, semantic
differences use stable component IDs plus canonical added/removed/modified
results, domain-transition analysis uses tagged transition/path results with
optional typed rule provenance, and information-flow analysis uses tagged
weighted flow/path results with permission-map and Boolean query metadata.
Checker analysis uses typed per-check evidence and summary counts; completed
runs write JSON at both clean status 0 and findings status 1. Compatibility help,
version, error streams, error text, and exit status remain unchanged; the
additive option is therefore documented outside the frozen legacy help text.

Generated release documentation follows
[ADR 0003](adr/0003-generated-cli-assets.md). The compatibility help assets
consumed directly by the binaries are also the source of public option metadata
for the dependency-free `setools-xtask` generator. It deterministically writes
six man1 pages and Bash/Zsh/Fish completions, adds the intentionally hidden
`--json` metadata, and provides a byte-exact `check` mode for CI and releases.
Generation never loads a policy or reads a legacy/parent repository.

Suggested process exit policy, subject to verification against every legacy
tool:

- `0`: successful execution, including no matches.
- `1`: policy loading or analysis failure.
- `2`: invalid command-line usage.

Broken pipe should terminate quietly rather than produce a Rust panic message.

## 12. Errors and observability

- Library crates expose typed errors with useful source chains.
- The CLI translates errors into compatibility text and status codes.
- Native errors include the policy path and the libsepol diagnostic.
- Debug logs may include loading phases, object counts, query preparation, and
  per-component diff timing.
- Normal operation must not log nondeterministic addresses or native IDs.
- `anyhow`-style dynamic errors, if used, remain in the executable layer;
  libraries keep explicit error enums.

## 13. Testing strategy

### 13.1 Rust-owned fixtures

The crate integration tests compile repository-owned synthetic `.conf`
fixtures with `checkpolicy` and load the resulting binary policies. These
fixtures exercise the Rust implementation without requiring an oracle tree.

### 13.2 Differential CLI tests

During migration, an external development harness may run the Python 4.7.1
tool and the Rust tool with the same policy and arguments. Compare:

- stdout bytes.
- stderr bytes.
- process exit status.

Do not normalize sorting or whitespace. Normalize only values proven to be
inherently unstable, and document every normalization.

The argument matrix should cover success, no results, malformed criteria,
unknown symbols, regex errors, running-policy lookup, verbose/debug logging,
and broken pipes.

### 13.3 Library tests

- Exact, regex, direct, and indirect symbol matching.
- Permission intersection, equality, and subset behavior.
- xpermission range normalization.
- Conditional expression and Boolean matching.
- MLS level/range ordering and equality.
- Context and network-range normalization.
- Added, removed, modified, redundant, and expanded rule differences.
- Deterministic ordering across repeated runs.

Property tests are appropriate for set matching, range normalization, and
canonical expression keys.

### 13.4 Native and parser testing

- Run the bridge under AddressSanitizer and UndefinedBehaviorSanitizer.
- Test failure cleanup for partially loaded policies and iterators.
- Fuzz malformed policy input through the loader, recognizing that libsepol is
  still a C parser.
- Differentially test pure Rust metadata and eventually the produced `Policy`
  against the libsepol loader, and fuzz it independently.

### 13.5 Compatibility matrix

CI should cover:

- The minimum supported libsepol release.
- The latest stable SELinux userspace release.
- SELinux userspace `main` as an allowed-to-fail early-warning job, becoming
  required once compatibility is confirmed.
- Representative distribution and Android binary policies where licensing
  permits storing or downloading fixtures.

## 14. Performance plan

Record a baseline for the Python implementation before optimization:

- Policy load wall time and peak RSS.
- `sesearch` exact-name and regex scans.
- `sesearch` indirect attribute queries.
- Full and selected-component `sediff`.
- Graph construction for `sedta` and `seinfoflow`.

Optimization order should be:

1. Avoid repeated string conversion and regex compilation.
2. Use dense IDs and bitsets.
3. Avoid retaining native and Rust representations simultaneously after load.
4. Release diff components after rendering.
5. Add measured indexes.
6. Parallelize independent diff components while preserving output order.

No async runtime is needed for local policy analysis.

The accepted CLI benchmark contract is stored in `benchmarks/cli-v1.toml` and
executed by the standalone, legacy-free `scripts/benchmark-cli.py` runner. On
Linux it records end-to-end wall time and per-child peak RSS from `wait4(2)`,
retains raw samples plus min/median/max summaries, and fingerprints the policy
and binaries. The seven default scenarios use warm runs; heavyweight
`sediff-full` remains an explicit manual scenario. Machine-specific results are
evidence, not CI thresholds. Legacy adapters and cross-implementation ratios
remain outside the standalone product repository.

## 15. Security considerations

Using Rust above the bridge does not make the libsepol binary parser memory
safe. If hostile policy files are in scope, choose one of these approaches:

- Move the pure Rust parser earlier in the roadmap.
- Parse in a restricted helper process with resource and syscall limits.
- Clearly document trusted-input requirements for the libsepol backend.

Both loaders must enforce reasonable allocation and object-count limits where
possible. The Rust layer must validate every native length and discriminant
before allocating or constructing an enum.

File paths should remain OS-native paths rather than requiring UTF-8. Policy
identifiers should be validated according to the policy format before they are
converted to Rust strings.

## 16. Migration milestones

### M0: Freeze the compatibility contract

- Record the exact 4.7.1 commit and dependency baseline.
- Snapshot every command's `--help` and `--version` output.
- Add representative CLI golden cases and status-code checks.
- Add benchmark commands for the Python baseline.

Exit criterion: expected legacy behavior is executable and reviewable in CI.

### M1: Workspace, bridge, and minimal policy model

- Create the Cargo workspace and license boundaries.
- Write the bridge ABI ADR.
- Load policy metadata, types, attributes, classes, permissions, and AV rules.
- Support explicit paths and running-policy discovery.
- Verify cleanup with sanitizers.

Exit criterion: a Rust diagnostic program can load every existing non-Xen test
policy and produce matching basic counts.

### M2: `sesearch`

- Implement allow rules and compatibility rendering first.
- Add all standard and extended TE rules.
- Add filename transitions and conditionals.
- Add RBAC and MLS rule searches.
- Match option validation, sorting, errors, and exit status.

Exit criterion: the differential `sesearch` matrix passes against 4.7.1.

### M3: `seinfo`

- Complete remaining symbol, context, constraint, default, and labeling data.
- Implement component-specific queries and counts.
- Match statement rendering and expansion options.

Exit criterion: all `seinfo` golden and differential cases pass.

### M4: `sediff`

- Implement properties and simple symbol components.
- Add types, roles, users, classes, commons, MLS, and contexts.
- Add TE/xperm, RBAC, MLS, and constraint semantic diffs.
- Implement component selection and `--stats`.

Exit criterion: all existing diff fixtures and the CLI differential matrix
pass, including redundant and attribute-expanded rules.

### M5: Graph tools

- Introduce `setools-graph`.
- Port domain-transition analysis.
- Port permission-map and information-flow analysis.
- Add deterministic path and graph result rendering.

Exit criterion: `sedta` and `seinfoflow` pass differential tests on existing
fixtures.

### M6: Remaining tools and structured output

- Port `sechecker`.
- Add versioned JSON output to stable commands.
- Generate shell completions and man pages from the Rust CLI definitions.
- Decide whether Python bindings, MCP support, or GUI integration use the Rust
  model directly or remain a separate compatibility layer.

### M7: Pure Rust parser

- [Completed slice] Parse bounded SELinux/Xen kernel-policy metadata for
  versions 15 through 35 behind a separate loader.
- Decode compatibility tables, symbols, rules, constraints, and contexts.
- Differentially compare full snapshots with libsepol.
- Add parser-specific fuzzing and allocation limits.
- Make the backend selectable until parity is demonstrated.

Exit criterion: selected real and fixture policies produce equivalent owned
models and identical tool results under both backends.

## 17. Definition of done for the first Rust release

- All six compatible commands are installed as separate binaries.
- Default CLI behavior is compatible with SETools 4.7.1 for the agreed matrix.
- The native handle is released after creation of the owned `Policy`.
- No raw libsepol type or pointer is exposed outside `setools-sepol`.
- No `unsafe` exists outside the FFI crate without a reviewed exception.
- Output is deterministic.
- Project CI covers supported libsepol versions; release qualification also
  records results from the separately maintained differential harness.
- C bridge sanitizer jobs pass.
- Release artifacts include licenses, man pages, and dependency documentation.
- The x86_64 Linux portable archive contains static PIE binaries with no ELF
  `NEEDED` entries and includes corresponding source for rebuilding/relinking.
- Performance and peak memory are measured against the recorded Python
  baseline, with material regressions documented before release.

## 18. Decisions to record as ADRs

Before implementation grows, record at least these decisions:

1. The precise C bridge ABI and iterator/view lifetime rules.
2. Whether the owned model eagerly loads every component or supports deferred
   sections.
3. The internal bitset representation.
4. Conditional expression canonicalization and compatibility rendering.
5. The structured-output schema and versioning policy. All six command-specific
   v1 schemas are accepted in [ADR 0002](adr/0002-structured-output-v1.md).
6. Generated documentation/completion metadata and drift checks are accepted in
   [ADR 0003](adr/0003-generated-cli-assets.md).
7. Dynamic versus pinned static libsepol builds are accepted in
   [ADR 0004](adr/0004-portable-native-release.md).
8. The public Rust API and crate publication policy.
9. The threat model for untrusted binary policies.
10. The pure Rust parser bootstrap and CLI cutover gate are accepted in
    [ADR 0005](adr/0005-pure-rust-parser-bootstrap.md).

The first implementation task after M0 should be a narrow vertical slice:
load one compiled fixture, construct types/attributes/classes/allow rules, and
produce one compatibility-formatted `sesearch --allow` result.
