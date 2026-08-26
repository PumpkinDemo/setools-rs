# ADR 0002: Versioned structured output v1

- Status: Accepted
- Date: 2026-08-21

## Context

The compatibility text output of every command is a byte-level SETools 4.7.1
contract. Machine consumers need a stable representation which does not depend
on indentation or policy-language statement parsing, but adding it must not
change existing arguments, help text, default stdout/stderr, or exit status.

The first structured-output slice was `sesearch`, whose TE, RBAC, and MLS result
ordering was already deterministic. `seinfo` is the second adopted command; it
reuses the envelope while defining statistics and component-section results.
Other commands can adopt the common envelope after their command-specific
result schemas are designed.

## Decision

`sesearch` and `seinfo` accept an additive `--json` option. The option is
documented in the README and this ADR, but is intentionally absent from each
frozen 4.7.1 compatibility help text. Running without `--json` is unchanged.

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
- Until another command explicitly implements its schema, passing `--json` to
  that command remains an ordinary unrecognized-argument error. The currently
  adopted identifiers are `setools-rs.sesearch` and `setools-rs.seinfo`.
