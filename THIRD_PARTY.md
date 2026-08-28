# Third-party software

The default source build and the Linux/macOS pure Rust binary archives do not
link libsepol. The optional `native-libsepol` compatibility feature uses a
system libsepol, while the optional Linux native compatibility archive builds a
pinned libsepol 3.11.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| libsepol | 3.11 | LGPL-2.1-or-later | <https://github.com/SELinuxProject/selinux/releases/tag/3.11> |

The expected SHA-256 of `libsepol-3.11.tar.gz` is
`79f3d2c88f44b7eb5cf54d9792e03232297e17f97a179163f2750099a00f164d`.
The pinned source coordinates are retained for rebuilding and separate
corresponding-source publication when that optional compatibility flavor is
distributed. The corresponding LGPL-2.1 text is in
`LICENSES/LGPL-2.1-only.txt`.

Rust crate dependencies and their resolved versions are recorded in
`Cargo.lock`. Binary archives contain only executables; the tagged repository
and GitHub-generated source archives provide project source and dependency
metadata. A release must not update a pinned third-party version or digest
without reviewing its source, license, and bridge compatibility.
