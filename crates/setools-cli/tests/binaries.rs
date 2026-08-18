//! Smoke tests for every installed executable name.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static POLICY_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct CompiledPolicy(PathBuf);

impl CompiledPolicy {
    fn build() -> Self {
        Self::build_fixture("te.conf", None)
    }

    fn build_xen() -> Self {
        Self::build_fixture("xen.conf", Some("xen"))
    }

    fn build_fixture(name: &str, target: Option<&str>) -> Self {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../setools-sepol/tests/fixtures")
            .join(name);
        let output_dir = env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        let output = output_dir.join(format!(
            "setools-rust-{}-{}-{}.policy",
            name.trim_end_matches(".conf"),
            std::process::id(),
            POLICY_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        let checkpolicy = env::var_os("CHECKPOLICY").unwrap_or_else(|| "checkpolicy".into());
        let mut command = Command::new(checkpolicy);
        command.args(["-M", "-U", "reject"]);
        if let Some(target) = target {
            command.args(["-c", "30", "-t", target]);
        }
        let result = command
            .arg("-o")
            .arg(&output)
            .arg(source)
            .output()
            .expect("checkpolicy must start");
        assert!(
            result.status.success(),
            "checkpolicy failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Self(output)
    }
}

impl Drop for CompiledPolicy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn every_binary_reports_compatibility_version() {
    let binaries = [
        ("sesearch", env!("CARGO_BIN_EXE_sesearch")),
        ("seinfo", env!("CARGO_BIN_EXE_seinfo")),
        ("sediff", env!("CARGO_BIN_EXE_sediff")),
        ("sedta", env!("CARGO_BIN_EXE_sedta")),
        ("seinfoflow", env!("CARGO_BIN_EXE_seinfoflow")),
        ("sechecker", env!("CARGO_BIN_EXE_sechecker")),
    ];

    for (name, binary) in binaries {
        let output = Command::new(binary)
            .arg("--version")
            .output()
            .expect("binary should execute");

        assert!(output.status.success(), "{name} should exit successfully");
        assert_eq!(output.stdout, b"4.7.1\n", "unexpected {name} stdout");
        assert!(output.stderr.is_empty(), "unexpected {name} stderr");
    }
}

#[test]
fn sesearch_requires_a_rule_kind() {
    let output = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .output()
        .expect("sesearch should execute");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.starts_with(b"usage: sesearch "));
    assert!(
        output
            .stderr
            .ends_with(b"sesearch: error: At least one rule type must be specified.\n")
    );
}

#[test]
fn seinfo_expands_a_type_from_a_binary_policy() {
    let policy = CompiledPolicy::build();
    let output = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--type", "test1FAIL", "--expand"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"\nTypes: 1\n   type test1FAIL, test1a;\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn seinfo_reports_every_selinux_component_family() {
    let policy = CompiledPolicy::build_fixture("seinfo.conf", None);
    let output = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--all", "--expand"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("seinfo output is UTF-8");
    for expected in [
        "Statistics for policy file:",
        "Constraints: 2",
        "default_role infoflow2 target;",
        "type permissive_example;",
        "policycap network_peer_controls;",
        "role system types system;",
        "typebounds bounded_parent bounded_child;",
        "user system roles system level low_s:c0 range low_s:c0 - high_s:c0.c1;",
        "validatetrans infoflow (u1 == u2);",
        "fs_use_trans devpts system:object_r:system:low_s:c0;",
        "genfscon proc /sys  system:object_r:system:high_s:c0.c1",
        "ibendportcon mlx5_0 1 system:object_r:system:low_s:c0",
        "ibpkeycon fe80:: 0x0010 system:object_r:system:low_s:c0",
        "sid kernel system:system:system:low_s:c0",
        "netifcon eth0 system:object_r:system:low_s:c0 system:object_r:system:low_s:c0",
        "nodecon 127.0.0.1 255.255.255.255 system:object_r:system:low_s:c0",
        "portcon tcp 80 system:object_r:system:low_s:c0",
    ] {
        assert!(stdout.contains(expected), "missing output: {expected}");
    }
}

#[test]
fn seinfo_reports_every_xen_component_family() {
    let policy = CompiledPolicy::build_xen();
    let output = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--all", "--expand"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("seinfo output is UTF-8");
    for expected in [
        "Target Policy:              xen",
        "devicetreecon /soc/device system:system:system:s0:c0",
        "iomemcon 0x0010-0x0012 system:system:system:s0:c0",
        "ioportcon 0x0020-0x0022 system:system:system:s0:c0",
        "pcidevicecon 0x0030 system:system:system:s0:c0",
        "pirqcon 40 system:system:system:s0:c0",
    ] {
        assert!(stdout.contains(expected), "missing output: {expected}");
    }
}

#[test]
fn seinfo_preserves_query_and_error_contracts() {
    let policy = CompiledPolicy::build_fixture("seinfo.conf", None);
    let selected = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--flat", "--portcon", "80"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");
    assert!(selected.status.success());
    assert_eq!(
        selected.stdout,
        b"portcon tcp 80 system:object_r:system:low_s:c0\n"
    );
    assert!(selected.stderr.is_empty());

    let invalid = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--constrain", "missing_class"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");
    assert_eq!(invalid.status.code(), Some(1));
    assert_eq!(invalid.stdout, b"missing_class is not a valid class\n");
    assert!(invalid.stderr.is_empty());
}
