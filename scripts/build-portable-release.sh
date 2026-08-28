#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

readonly PROJECT_VERSION="4.7.1"
readonly LIBSEPOL_VERSION="3.11"
readonly LIBSEPOL_SHA256="79f3d2c88f44b7eb5cf54d9792e03232297e17f97a179163f2750099a00f164d"
readonly LIBSEPOL_URL="https://github.com/SELinuxProject/selinux/releases/download/${LIBSEPOL_VERSION}/libsepol-${LIBSEPOL_VERSION}.tar.gz"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly PORTABLE_ROOT="${PROJECT_ROOT}/target/portable"
readonly DIST_DIR="${PROJECT_ROOT}/dist"
readonly BINARIES=(sesearch seinfo sediff sedta seinfoflow sechecker)
source_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$PROJECT_ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}
if [[ ! $source_epoch =~ ^[0-9]+$ ]]; then
    printf 'SOURCE_DATE_EPOCH must be an integer\n' >&2
    exit 1
fi
export SOURCE_DATE_EPOCH="$source_epoch"

policy_path=""
release_mode="pure-rust"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --native-libsepol)
            release_mode="native-libsepol"
            shift
            ;;
        --policy)
            if [[ $# -lt 2 || -n $policy_path ]]; then
                printf 'usage: %s [--native-libsepol] [--policy BINARY_POLICY]\n' "$0" >&2
                exit 2
            fi
            policy_path=$2
            shift 2
            ;;
        --help|-h)
            printf 'usage: %s [--native-libsepol] [--policy BINARY_POLICY]\n' "$0"
            exit 0
            ;;
        *)
            printf 'usage: %s [--native-libsepol] [--policy BINARY_POLICY]\n' "$0" >&2
            exit 2
            ;;
    esac
done

if [[ $(uname -s) != "Linux" || $(uname -m) != "x86_64" ]]; then
    printf 'portable release currently supports x86_64 Linux only\n' >&2
    exit 1
fi

for command in cargo file find install readelf sha256sum sort strip tar; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'required command is missing: %s\n' "$command" >&2
        exit 1
    fi
done

if [[ $release_mode == "native-libsepol" ]]; then
    for command in cc curl make; do
        if ! command -v "$command" >/dev/null 2>&1; then
            printf 'required for --native-libsepol: %s\n' "$command" >&2
            exit 1
        fi
    done
fi

mkdir -p "$PORTABLE_ROOT" "$DIST_DIR"

libsepol_archive=""
if [[ $release_mode == "native-libsepol" ]]; then
    mkdir -p "$PORTABLE_ROOT/downloads"
    if [[ -n ${LIBSEPOL_ARCHIVE:-} ]]; then
        libsepol_archive=$(cd -- "$(dirname -- "$LIBSEPOL_ARCHIVE")" && pwd -P)/$(basename -- "$LIBSEPOL_ARCHIVE")
    else
        libsepol_archive="${PORTABLE_ROOT}/downloads/libsepol-${LIBSEPOL_VERSION}.tar.gz"
        if [[ ! -f "$libsepol_archive" ]]; then
            curl --fail --location --retry 3 --output "${libsepol_archive}.part" "$LIBSEPOL_URL"
            mv -- "${libsepol_archive}.part" "$libsepol_archive"
        fi
    fi

    if [[ ! -f "$libsepol_archive" ]]; then
        printf 'libsepol source archive does not exist: %s\n' "$libsepol_archive" >&2
        exit 1
    fi
    printf '%s  %s\n' "$LIBSEPOL_SHA256" "$libsepol_archive" | sha256sum --check --status
fi

build_dir=$(mktemp -d "${PORTABLE_ROOT}/build.XXXXXX")
if [[ -z ${build_dir:-} || ! -d "$build_dir" || $build_dir != "$PORTABLE_ROOT"/build.* ]]; then
    printf 'refusing unexpected build directory: %s\n' "${build_dir:-<empty>}" >&2
    exit 1
fi

cleanup() {
    if [[ -n ${build_dir:-} && -d "$build_dir" && $build_dir == "$PORTABLE_ROOT"/build.* ]]; then
        rm -rf -- "$build_dir"
    fi
}
trap cleanup EXIT

if [[ $release_mode == "native-libsepol" ]]; then
    readonly LIBSEPOL_SOURCE="${build_dir}/libsepol-${LIBSEPOL_VERSION}"
    readonly LIBSEPOL_PREFIX="${build_dir}/libsepol-prefix"
    tar -xzf "$libsepol_archive" -C "$build_dir"
    if [[ ! -f "${LIBSEPOL_SOURCE}/src/Makefile" || ! -f "${LIBSEPOL_SOURCE}/include/sepol/policydb.h" ]]; then
        printf 'verified archive has an unexpected layout\n' >&2
        exit 1
    fi

    make -C "${LIBSEPOL_SOURCE}/src" \
        DISABLE_CIL=y DISABLE_SHARED=y \
        CFLAGS="-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2"
    install -d "${LIBSEPOL_PREFIX}/include" "${LIBSEPOL_PREFIX}/lib"
    cp -a "${LIBSEPOL_SOURCE}/include/." "${LIBSEPOL_PREFIX}/include/"
    install -m 0644 "${LIBSEPOL_SOURCE}/src/libsepol.a" "${LIBSEPOL_PREFIX}/lib/libsepol.a"
fi

readonly CARGO_TARGET_DIR="${build_dir}/cargo-target"
export CARGO_TARGET_DIR
export RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none"

if [[ $release_mode == "native-libsepol" ]]; then
    export SETOOLS_LIBSEPOL_STATIC_ROOT="$LIBSEPOL_PREFIX"
    cargo build --locked --release -p setools-cli --features native-libsepol \
        --bin sesearch --bin seinfo --bin sediff \
        --bin sedta --bin seinfoflow --bin sechecker
    readonly PACKAGE_NAME="setools-rs-${PROJECT_VERSION}-linux-x86_64-native"
else
    cargo build --locked --release -p setools-cli \
        --bin sesearch --bin seinfo --bin sediff \
        --bin sedta --bin seinfoflow --bin sechecker
    readonly PACKAGE_NAME="setools-rs-${PROJECT_VERSION}-linux-x86_64"
fi

readonly PACKAGE_ROOT="${build_dir}/${PACKAGE_NAME}"
install -d "$PACKAGE_ROOT/bin"

for binary in "${BINARIES[@]}"; do
    artifact="${CARGO_TARGET_DIR}/release/${binary}"
    strip --strip-unneeded "$artifact"
    if readelf -d "$artifact" 2>/dev/null | grep -q '(NEEDED)'; then
        printf 'portable binary still has a dynamic dependency: %s\n' "$binary" >&2
        readelf -d "$artifact" >&2
        exit 1
    fi
    if ! file "$artifact" | grep -Eq 'static-pie linked|statically linked'; then
        printf 'portable binary is not statically linked: %s\n' "$binary" >&2
        file "$artifact" >&2
        exit 1
    fi
    if [[ $("$artifact" --version) != "$PROJECT_VERSION" ]]; then
        printf 'unexpected version output from %s\n' "$binary" >&2
        exit 1
    fi
    install -m 0755 "$artifact" "$PACKAGE_ROOT/bin/$binary"
done

if [[ -n "$policy_path" ]]; then
    if [[ ! -f "$policy_path" ]]; then
        printf 'smoke-test policy does not exist: %s\n' "$policy_path" >&2
        exit 1
    fi
    "$PACKAGE_ROOT/bin/seinfo" "$policy_path" >/dev/null
    "$PACKAGE_ROOT/bin/sesearch" --allow "$policy_path" >/dev/null
fi

expected_entries=$(printf 'bin/%s\n' "${BINARIES[@]}" | LC_ALL=C sort)
actual_entries=$(cd "$PACKAGE_ROOT" && find . -type f -printf '%P\n' | LC_ALL=C sort)
if [[ $actual_entries != "$expected_entries" ]]; then
    printf 'portable archive must contain only the six CLI binaries\n' >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected_entries" "$actual_entries" >&2
    exit 1
fi

readonly ARTIFACT="${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
tar --sort=name --mtime="@${source_epoch}" --owner=0 --group=0 --numeric-owner \
    -czf "${ARTIFACT}.part" -C "$build_dir" "$PACKAGE_NAME"
mv -- "${ARTIFACT}.part" "$ARTIFACT"
(
    cd "$DIST_DIR"
    sha256sum "${PACKAGE_NAME}.tar.gz" >"${PACKAGE_NAME}.tar.gz.sha256"
)

printf 'portable release: %s\n' "$ARTIFACT"
printf 'checksum: '
cat "${ARTIFACT}.sha256"
