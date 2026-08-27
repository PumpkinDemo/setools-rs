# Third-party software

The normal source build links to libsepol found on the system. The portable
Linux binary archive instead statically links a pinned libsepol 3.11 build.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| libsepol | 3.11 | LGPL-2.1-or-later | <https://github.com/SELinuxProject/selinux/releases/tag/3.11> |

The expected SHA-256 of `libsepol-3.11.tar.gz` is
`79f3d2c88f44b7eb5cf54d9792e03232297e17f97a179163f2750099a00f164d`.
The portable archive includes this exact upstream source tarball and a source
archive of setools-rs, so recipients can inspect, modify, rebuild, and relink
the complete work. The corresponding LGPL-2.1 text is in
`LICENSES/LGPL-2.1-only.txt`.

Rust crate dependencies and their resolved versions are recorded in
`Cargo.lock`. The corresponding source archive inside each portable release
also vendors those exact crate sources and configures Cargo to use them
offline. A release must not update a pinned third-party version or digest
without reviewing its source, license, and bridge compatibility.
