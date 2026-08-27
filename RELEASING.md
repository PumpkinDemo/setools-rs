# Releasing

The project currently supports standalone source releases and a portable
x86_64 Linux static archive for `sesearch`, `seinfo`, `sediff`, `sedta`,
`seinfoflow`, and `sechecker`.
Crates.io publication remains disabled until the public library APIs stabilize.

## Release checklist

1. Update `docs/RUST_REWRITE_PROGRESS.md` and decide the release version. The
   current `4.7.1` package version preserves the compatible CLI version string.
2. From a clean checkout, run:

   ```bash
   cargo fmt --all --check
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo run -p setools-xtask -- check
   cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
   ```

3. Build and smoke-test the portable archive against a representative policy:

   ```bash
   scripts/build-portable-release.sh --policy /path/to/policy
   ```

   This must create `dist/setools-rs-4.7.1-x86_64-linux-static.tar.gz` and its
   checksum. Extract it into a fresh directory, run `sha256sum --check
   SHA256SUMS`, and confirm `readelf -d bin/TOOL` has no `NEEDED` entry for all
   six tools. Record the rustc, C compiler, target, and pinned libsepol version
   from `BUILD-INFO.txt` in the release notes.
4. On the benchmark host, run the default suite against the retained
   representative policy and archive the JSON with the release evidence:

   ```bash
   python3 scripts/benchmark-cli.py \
     --policy /path/to/policy \
     --output setools-rs-performance.json
   ```

   Review `docs/PERFORMANCE.md` before comparing results. Run the manual
   `sediff-full` scenario separately because it is intentionally excluded from
   the default suite.
5. Commit the release state and create a signed or annotated tag:

   ```bash
   git tag -a v4.7.1 -m "setools-rs v4.7.1"
   git push origin main v4.7.1
   ```

6. Create a source archive directly from the tag:

   ```bash
   git archive --format=tar.gz --prefix=setools-rs-4.7.1/ \
     --output=setools-rs-4.7.1.tar.gz v4.7.1
   sha256sum setools-rs-4.7.1.tar.gz
   ```

7. Attach the portable archive and its `.sha256` file to the release. The
   packaging script already includes `README.md`, `COPYING`, both license texts,
   man pages, Bash/Zsh/Fish completions, the exact libsepol source, and the
   setools-rs corresponding source with locked Cargo dependencies vendored for
   offline rebuilds. Do not label untested architectures or platforms as
   supported.

The static artifact is intentionally separate from the default dynamic source
build. Updating `LIBSEPOL_VERSION` or `LIBSEPOL_SHA256` requires a source,
license, ABI, full-workspace, and real-policy review.
