//! Builds the project-owned C bridge and locates libsepol/libselinux.

use std::env;
use std::path::{Path, PathBuf};

const MINIMUM_LIBSEPOL_VERSION: &str = "3.9";

fn main() {
    println!("cargo:rerun-if-changed=c/bridge.c");
    println!("cargo:rerun-if-changed=c/bridge.h");
    println!("cargo:rerun-if-env-changed=USERSPACE_SRC");

    let mut bridge = cc::Build::new();
    bridge
        .file("c/bridge.c")
        .include("c")
        .warnings(true)
        .flag_if_supported("-std=c11");

    let link = if let Some(source_root) = env::var_os("USERSPACE_SRC") {
        configure_source_tree(&mut bridge, Path::new(&source_root))
    } else {
        configure_system(&mut bridge)
    };

    bridge.compile("setools_sepol_bridge");
    link.emit();
}

struct LinkInstructions {
    search_paths: Vec<PathBuf>,
    libraries: Vec<String>,
}

impl LinkInstructions {
    fn emit(self) {
        for path in self.search_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for library in self.libraries {
            println!("cargo:rustc-link-lib=dylib={library}");
        }
    }
}

fn configure_source_tree(bridge: &mut cc::Build, source_root: &Path) -> LinkInstructions {
    let sepol_include = source_root.join("libsepol/include");
    let selinux_include = source_root.join("libselinux/include");
    let sepol_library = source_root.join("libsepol/src");
    let selinux_library = source_root.join("libselinux/src");
    let sepol_shared_object = sepol_library.join("libsepol.so");
    let selinux_shared_object = selinux_library.join("libselinux.so");

    if !sepol_include.join("sepol/policydb.h").is_file()
        || !selinux_include.join("selinux/selinux.h").is_file()
        || !sepol_shared_object.is_file()
        || !selinux_shared_object.is_file()
    {
        panic!(
            "USERSPACE_SRC={} does not contain built libsepol/libselinux headers and shared libraries",
            source_root.display()
        );
    }

    bridge.include(sepol_include).include(selinux_include);
    LinkInstructions {
        search_paths: vec![sepol_library, selinux_library],
        libraries: vec!["sepol".to_owned(), "selinux".to_owned()],
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
    let selinux = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("libselinux")
        .unwrap_or_else(|error| panic!("libselinux development files are required: {error}"));

    for include in sepol.include_paths.iter().chain(&selinux.include_paths) {
        bridge.include(include);
    }

    let mut search_paths = sepol.link_paths;
    search_paths.extend(selinux.link_paths);
    let mut libraries = sepol.libs;
    libraries.extend(selinux.libs);
    LinkInstructions {
        search_paths,
        libraries,
    }
}
