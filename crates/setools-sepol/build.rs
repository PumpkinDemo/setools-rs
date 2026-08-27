//! Builds the project-owned C bridge and locates libsepol.

use std::env;
use std::path::{Path, PathBuf};

const MINIMUM_LIBSEPOL_VERSION: &str = "3.9";

fn main() {
    println!("cargo:rerun-if-changed=c/bridge.c");
    println!("cargo:rerun-if-changed=c/bridge.h");
    println!("cargo:rerun-if-env-changed=USERSPACE_SRC");
    println!("cargo:rerun-if-env-changed=SETOOLS_LIBSEPOL_STATIC_ROOT");

    let mut bridge = cc::Build::new();
    bridge
        .file("c/bridge.c")
        .include("c")
        .warnings(true)
        .flag_if_supported("-std=c11");

    let link = if let Some(prefix) = env::var_os("SETOOLS_LIBSEPOL_STATIC_ROOT") {
        configure_static_prefix(&mut bridge, Path::new(&prefix))
    } else if let Some(source_root) = env::var_os("USERSPACE_SRC") {
        configure_source_tree(&mut bridge, Path::new(&source_root))
    } else {
        configure_system(&mut bridge)
    };

    bridge.compile("setools_sepol_bridge");
    link.emit();
}

struct LinkInstructions {
    search_paths: Vec<PathBuf>,
    libraries: Vec<(LinkKind, String)>,
}

#[derive(Clone, Copy)]
enum LinkKind {
    Static,
    Dynamic,
}

impl LinkInstructions {
    fn emit(self) {
        for path in self.search_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for (kind, library) in self.libraries {
            let kind = match kind {
                LinkKind::Static => "static",
                LinkKind::Dynamic => "dylib",
            };
            println!("cargo:rustc-link-lib={kind}={library}");
        }
    }
}

fn configure_static_prefix(bridge: &mut cc::Build, prefix: &Path) -> LinkInstructions {
    let include = prefix.join("include");
    let library = prefix.join("lib");
    let archive = library.join("libsepol.a");

    if !include.join("sepol/policydb.h").is_file() || !archive.is_file() {
        panic!(
            "SETOOLS_LIBSEPOL_STATIC_ROOT={} must contain include/sepol/policydb.h and lib/libsepol.a",
            prefix.display()
        );
    }

    bridge.include(include);
    LinkInstructions {
        search_paths: vec![library],
        libraries: vec![(LinkKind::Static, "sepol".to_owned())],
    }
}

fn configure_source_tree(bridge: &mut cc::Build, source_root: &Path) -> LinkInstructions {
    let sepol_include = source_root.join("libsepol/include");
    let sepol_library = source_root.join("libsepol/src");
    let sepol_shared_object = sepol_library.join("libsepol.so");

    if !sepol_include.join("sepol/policydb.h").is_file() || !sepol_shared_object.is_file() {
        panic!(
            "USERSPACE_SRC={} does not contain built libsepol headers and shared library",
            source_root.display()
        );
    }

    bridge.include(sepol_include);
    LinkInstructions {
        search_paths: vec![sepol_library],
        libraries: vec![(LinkKind::Dynamic, "sepol".to_owned())],
    }
}

fn configure_system(bridge: &mut cc::Build) -> LinkInstructions {
    let sepol = pkg_config::Config::new()
        .atleast_version(MINIMUM_LIBSEPOL_VERSION)
        .cargo_metadata(false)
        .probe("libsepol")
        .unwrap_or_else(|error| {
            panic!("libsepol {MINIMUM_LIBSEPOL_VERSION}+ development files are required: {error}")
        });
    for include in &sepol.include_paths {
        bridge.include(include);
    }

    LinkInstructions {
        search_paths: sepol.link_paths,
        libraries: sepol
            .libs
            .into_iter()
            .map(|library| (LinkKind::Dynamic, library))
            .collect(),
    }
}
