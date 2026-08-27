# ADR 0002: Versioned structured output v1

- Status: Accepted
- Date: 2026-08-21

## Context

The compatibility text output of every command is a byte-level SETools 4.7.1
contract. Machine consumers need a stable representation which does not depend
on indentation or policy-language statement parsing, but adding it must not
change existing arguments, help text, default stdout/stderr, or exit status.

The first structured-output slice was `sesearch`, whose TE, RBAC, and MLS result
ordering was already deterministic. `seinfo` was the second adopted command;
it reuses the envelope while defining statistics and component-section results.
`sediff` is the third adopted command and represents two policy paths plus
added, removed, and modified semantic results. `sedta` is the fourth adopted
command and represents typed transition or path results from one policy graph.
`seinfoflow` is the fifth adopted command and represents weighted flow or path
results, Boolean evaluation, and permission-map provenance. `sechecker` is the
sixth adopted command and represents configured checks, typed findings, and a
machine-readable result summary.

## Decision

`sesearch`, `seinfo`, `sediff`, `sedta`, `seinfoflow`, and `sechecker` accept an
additive `--json` option. The option is documented in the README and this ADR,
but is intentionally absent from each frozen 4.7.1 compatibility help text.
Running without `--json` is unchanged.

A successful `--json` invocation writes exactly one compact UTF-8 JSON document
followed by one newline. It is not JSON Lines. The document uses this common
envelope:

```json
{
  "schema": "setools-rs.sesearch",
  "schema_version": 1,
  "tool": { "name": "sesearch", "version": "4.7.1" },
  "policy": { "path": "/path/to/policy" },
  "query": {
    "rule_types": [{ "family": "te", "rule_type": "allow" }],
    "source": null,
    "target": null,
    "class": null,
    "permissions": null,
    "xpermissions": null,
    "default": null,
    "boolean": null
  },
  "result_count": 0,
  "results": []
}
```

The normative schema is
[`docs/schema/sesearch-v1.schema.json`](../schema/sesearch-v1.schema.json).
Its command-specific rules are:

- `query.rule_types` identifies both the rule family (`te`, `rbac`, or `mls`)
  and the policy-language rule type. This avoids the ambiguity between TE and
  RBAC `allow`.
- A criterion is `null` when it is not active. An active criterion records its
  exact CLI value plus the matching modifiers which affect it. Values are not
  split or normalized, so callers can distinguish their requested expression
  from policy results.
- Each result carries `family`, `rule_type`, and `statement`. `statement` is the
  existing compatibility rendering and preserves all rule semantics currently
  exposed by `sesearch`, including conditionals and filename transitions.
- Results retain the same deterministic family and statement ordering as text
  output. Consumers should still treat an array as ordered data rather than
  infer declaration order from it.
- JSON strings use standard escaping. Policy paths are rendered as UTF-8; an
  OS-native non-UTF-8 path is represented with Unicode replacement characters.

The normative `seinfo` schema is
[`docs/schema/seinfo-v1.schema.json`](../schema/seinfo-v1.schema.json). It keeps
the same envelope and uses these command-specific fields:

- `query` records `all`, `expand`, and `flat` exactly as selected. Its
  `components` array contains explicit component options in deterministic
  component order. A component selected without a value has a null criterion;
  `--all` remains a separate flag rather than expanding into synthetic query
  entries.
- `statistics` is the typed equivalent of the compatibility statistics block,
  or null whenever that block would not be shown in text mode. Metadata has
  stable names and `counts` uses command-specific keys. Target-specific SELinux
  or Xen counts are present only for the loaded policy platform. The
  `neverallow` counters retain the compatibility value exposed by text mode.
- `results` contains the same ordered sections and items as text rendering.
  `component` is a stable machine identifier, `description` preserves the human
  compatibility heading, `count` is the section item count, and `items` are the
  existing unindented compatibility values or expanded statements.
- Top-level `result_count` is the sum of all section item counts. Empty
  component queries retain their zero-count section so consumers can
  distinguish an executed empty query from an omitted component.

The normative `sediff` schema is
[`docs/schema/sediff-v1.schema.json`](../schema/sediff-v1.schema.json). It keeps
the same envelope and uses these command-specific fields:

- `policy.left_path` and `policy.right_path` identify the policies in the same
  left/removed and right/added orientation as compatibility text.
- `query.all` is true only when no component selector was supplied. Explicit
  component selectors are recorded once in deterministic result order;
  aggregate `-A` therefore records both `allow` and `allowxperm`.
- Every result has a stable component ID, compatibility description, and
  separate added, removed, and modified counts. Added and removed arrays contain
  canonical names or statements. Modified items contain their canonical summary
  and unindented detail lines; the JSON renderer consumes semantic diff objects
  directly and never parses compatibility stdout.
- Explicitly selected components retain a zero-count result. Default all mode
  omits empty components, matching compatibility text. `result_count` is the
  sum of all added, removed, and modified counts in returned components.
- With `--stats`, counts and `result_count` retain their full values while all
  added, removed, and modified detail arrays are empty. This mirrors the text
  option's count-only behavior without making the result shape conditional.

The normative `sedta` schema is
[`docs/schema/sedta-v1.schema.json`](../schema/sedta-v1.schema.json). It keeps
the same envelope and uses these command-specific fields:

- `query.mode` is one of `transitions_out`, `transitions_in`,
  `shortest_paths`, or `all_paths`. The query also records the exact source,
  optional target, reverse flag, optional maximum steps, transition limit,
  ordered exclusions, full-detail flag, and statistics flag.
- `result_type` selects tagged `transition` or `path` entries. A transition
  carries canonical source and target names. A path carries its step count and
  ordered transition steps. `result_count` counts top-level transitions or
  paths after applying the compatibility `--limit_trans` behavior.
- Without `--full`, each transition's `details` is null. With `--full`, details
  contain sorted canonical transition, setexec, dyntransition, and setcurrent
  rule statements plus typed entrypoints and their entrypoint, execute, and
  type-transition rule statements. The renderer consumes graph result objects
  directly and never parses compatibility stdout.
- `statistics` is null unless `--stats` was requested. When present, its node
  and edge counts describe the same unfiltered domain-transition graph as the
  compatibility statistics block.
- `--json` and Graphviz `--output_file` are mutually exclusive output modes.
  Their combination is a text usage error with exit status 2.

The normative `seinfoflow` schema is
[`docs/schema/seinfoflow-v1.schema.json`](../schema/seinfoflow-v1.schema.json).
It keeps the same envelope and uses these command-specific fields:

- `query.mode` is one of `flows_out`, `flows_in`, `shortest_paths`, or
  `all_paths`. The query also records the exact source, optional target,
  reverse flag, optional maximum steps, minimum edge weight, top-level result
  limit, ordered exclusions, full-detail flag, and statistics flag.
- `query.booleans` is null when both branches of conditional rules remain in
  the graph. Otherwise it records either policy-default evaluation or ordered
  explicit assignments. `query.permission_map` distinguishes the embedded
  built-in map from a user-supplied file and records the latter's CLI path.
- `result_type` selects tagged `flow` or `path` entries. Every flow carries
  canonical source and target names plus its maximum contributing permission
  weight. A path carries its step count and ordered flow steps. `result_count`
  counts top-level flows or paths after applying `--limit_flows`.
- Without `--full`, a flow's `rules` is null. With `--full`, it contains sorted
  canonical allow-rule statements which contribute to the flow. The renderer
  consumes graph result objects directly and never parses compatibility stdout.
- `statistics` is null unless `--stats` was requested. When present, its node
  and edge counts describe the same full, unfiltered information-flow graph as
  the compatibility statistics block.
- `--json` and Graphviz `--output_file` are mutually exclusive output modes.
  Their combination is a text usage error with exit status 2.

The normative `sechecker` schema is
[`docs/schema/sechecker-v1.schema.json`](../schema/sechecker-v1.schema.json).
It keeps the same envelope and uses these command-specific fields:

- `query.configuration_path` records the exact CLI path of the validated INI
  configuration. The policy path remains in the common `policy` object.
- `summary` records configured, passed, failed, and disabled check counts plus
  the total number of findings. `result_count` is the number of configured
  checks, including disabled checks, and results retain INI section order.
- Every result records the section name, optional description, stable registry
  check type, `passed`/`failed`/`disabled` status, and finding count. Tagged
  details distinguish disabled reasons, type-attribute members, canonical
  TE/RBAC rule findings and missing expectations, executable or kernel-module
  writable-file evidence, and unexpected per-check failures.
- A completed run with no findings writes JSON and exits 0. A completed run
  with findings still writes the full JSON document and exits 1; this is a
  semantic check result, not a structured operational error. Configuration and
  operational failures retain their existing text streams and status behavior.
- Dynamic start/end timestamps belong to the compatibility text report and are
  intentionally absent from v1 so identical semantic results remain stable.
- `--json` and text-report `--output_file` are mutually exclusive output modes.
  Their combination is a text usage error with exit status 2.

The v1 schema is immutable. Renaming/removing a field, changing its type or
meaning, or changing the schema identifier requires a new `schema_version` and
a new schema file. Other commands use their own identifier, such as
`setools-rs.seinfo`, while reusing envelope field names where their semantics
match.

Successful empty searches are JSON documents with `result_count: 0` and an
empty `results` array. `--verbose` and `--debug` diagnostics remain on stderr,
so stdout stays a valid JSON document.

Help and version actions remain compatibility text. Command-line usage errors,
policy-load failures, and query failures retain their existing text stream and
exit status even when `--json` is present. Structured errors are outside v1;
adding them later requires an explicit, versioned contract rather than silently
changing existing automation.

## Consequences

- Existing invocations and frozen help snapshots remain byte-for-byte stable.
- Machine consumers can verify both `schema` and `schema_version` before
  reading command-specific data.
- The first implementation needs no serialization dependency; the CLI owns a
  small JSON string encoder with direct escaping tests.
- The compatibility `statement` is intentionally retained alongside structured
  metadata. Further decomposition of rules is additive only in a later schema
  version.
- The adopted identifiers are `setools-rs.sesearch`, `setools-rs.seinfo`,
  `setools-rs.sediff`, `setools-rs.sedta`, `setools-rs.seinfoflow`, and
  `setools-rs.sechecker`.
