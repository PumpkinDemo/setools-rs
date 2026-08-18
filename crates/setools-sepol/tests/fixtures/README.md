# Loader test policies

These synthetic source policies exercise the TE, filename-transition, RBAC,
and MLS paths of the `setools-sepol` integration tests. They are compiled at
test time with `checkpolicy` and are never used by the library or installed
with a binary.

The policies were originally derived from the GPL-2.0-only SETools 4.7.1 test
suite and remain GPL-2.0-only.
