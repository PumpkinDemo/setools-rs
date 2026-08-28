# ADR 0003: Generated CLI documentation and completions

- Status: Accepted
- Date: 2026-08-27

## Context

The six compatibility parsers are deliberately hand-written because their
argument validation, error streams, and frozen SETools 4.7.1 help text are part
of the byte-level compatibility contract. Replacing them with a CLI framework
solely to generate release documentation would add dependencies and risk
changing that contract.

Tagged releases nevertheless need reviewable man pages and shell completions in
the source tree, even though the compact binary archive contains only binaries.
Duplicating every public option and description in a separate generator would
allow those assets to drift away from the text actually printed by each binary.
The additive `--json` option is the one intentional exception: it is hidden
from compatibility help and documented by ADR 0002.

## Decision

The files in `crates/setools-cli/assets/*-help.txt` are the source of truth for
public compatibility option spellings, metavariables, section ordering, and
descriptions. Each CLI consumes its corresponding file directly with
`include_str!`, so generation reads the same product-owned data that the binary
prints. The generator adds the common hidden `--json` metadata explicitly and
does not read a legacy installation or parent directory.

The dependency-free `setools-xtask` workspace package provides two commands:

```text
cargo run -p setools-xtask -- generate
cargo run -p setools-xtask -- check
```

`generate` deterministically writes these committed release assets:

- `man/man1/<command>.1` for all six commands;
- `completions/bash/<command>`;
- `completions/zsh/_<command>`;
- `completions/fish/<command>.fish`.

Man pages preserve the compatibility synopsis, sections, option signatures,
descriptions, and notes, then add a structured-output section for `--json`.
Completions expose all compatibility options plus `--json`. They complete
known policy, permission-map, and output-file arguments as paths, while policy
symbol values remain ordinary user input; the generator does not load a policy
or execute a command during shell completion.

`check` regenerates all content in memory, compares it byte-for-byte with the
committed files, rejects missing or unexpected generated assets, and exits
nonzero on drift. CI and the release checklist run this command. Bash and Zsh
files receive syntax checks where those shells are available, and all man pages
are checked with a man formatter in the development environment.

## Consequences

- The frozen `--help` output and parser behavior do not change.
- Updating a public help option requires regenerating and reviewing every
  affected man/completion artifact.
- Source releases can ship conventional, deterministic assets without Python,
  legacy SETools, clap, or shell-completion dependencies; the compact binary
  archive deliberately leaves them in the tagged source tree.
- Completion is intentionally static. Adding policy-aware symbol completion
  later requires a separate design for latency, policy selection, and errors.
