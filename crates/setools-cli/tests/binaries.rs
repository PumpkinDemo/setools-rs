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

#[cfg(feature = "native-libsepol")]
fn assert_cli_backend_parity(binary: &str, arguments: &[&str], paths: &[&Path]) {
    let native = Command::new(binary)
        .args(arguments)
        .args(paths)
        .output()
        .expect("libsepol backend command should execute");
    let pure_rust = Command::new(binary)
        .env("SETOOLS_POLICY_BACKEND", "pure-rust")
        .args(arguments)
        .args(paths)
        .output()
        .expect("pure Rust backend command should execute");

    assert_eq!(pure_rust.status, native.status, "{binary} exit status");
    assert_eq!(pure_rust.stdout, native.stdout, "{binary} stdout");
    assert_eq!(pure_rust.stderr, native.stderr, "{binary} stderr");
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
#[cfg(feature = "native-libsepol")]
fn pure_rust_loader_matches_libsepol_at_the_cli_boundary() {
    let te = CompiledPolicy::build_fixture("te.conf", None);
    assert_cli_backend_parity(
        env!("CARGO_BIN_EXE_sesearch"),
        &["--json", "--allow"],
        &[&te.0],
    );

    let seinfo = CompiledPolicy::build_fixture("seinfo.conf", None);
    assert_cli_backend_parity(env!("CARGO_BIN_EXE_seinfo"), &["--json"], &[&seinfo.0]);

    let left = CompiledPolicy::build_fixture("diff-simple-left.conf", None);
    let right = CompiledPolicy::build_fixture("diff-simple-right.conf", None);
    assert_cli_backend_parity(
        env!("CARGO_BIN_EXE_sediff"),
        &["--json", "--stats", "--type"],
        &[&left.0, &right.0],
    );

    let dta = CompiledPolicy::build_fixture("dta.conf", None);
    assert_cli_backend_parity(
        env!("CARGO_BIN_EXE_sedta"),
        &["--json", "--source", "alpha", "--stats", "--policy"],
        &[&dta.0],
    );

    let infoflow = CompiledPolicy::build_fixture("infoflow.conf", None);
    let permission_map =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-graph/tests/fixtures/perm_map");
    assert_cli_backend_parity(
        env!("CARGO_BIN_EXE_seinfoflow"),
        &[
            "--json",
            "--source",
            "flow_source",
            "--stats",
            "--policy",
            "--map",
        ],
        &[&infoflow.0, &permission_map],
    );

    let checker = CompiledPolicy::build_fixture("checker.conf", None);
    let config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures/pass.ini");
    assert_cli_backend_parity(
        env!("CARGO_BIN_EXE_sechecker"),
        &["--json"],
        &[&config, &checker.0],
    );
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
fn sesearch_emits_versioned_json_for_all_rule_families() {
    let policy = CompiledPolicy::build_fixture("filename-transition.conf", None);
    let output = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .args([
            "--json",
            "--allow",
            "--allowxperm",
            "--role_allow",
            "--role_transition",
            "--range_transition",
        ])
        .arg(&policy.0)
        .output()
        .expect("sesearch should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!(
        concat!(
            "{{\"schema\":\"setools-rs.sesearch\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"sesearch\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"rule_types\":[",
            "{{\"family\":\"te\",\"rule_type\":\"allow\"}},",
            "{{\"family\":\"te\",\"rule_type\":\"allowxperm\"}},",
            "{{\"family\":\"rbac\",\"rule_type\":\"allow\"}},",
            "{{\"family\":\"rbac\",\"rule_type\":\"role_transition\"}},",
            "{{\"family\":\"mls\",\"rule_type\":\"range_transition\"}}",
            "],\"source\":null,\"target\":null,\"class\":null,",
            "\"permissions\":null,\"xpermissions\":null,\"default\":null,",
            "\"boolean\":null}},\"result_count\":6,\"results\":[",
            "{{\"family\":\"te\",\"rule_type\":\"allow\",",
            "\"statement\":\"allow system system:infoflow hi_w;\"}},",
            "{{\"family\":\"te\",\"rule_type\":\"allow\",",
            "\"statement\":\"allow system type30:infoflow3 null;\"}},",
            "{{\"family\":\"te\",\"rule_type\":\"allowxperm\",",
            "\"statement\":\"allowxperm type30 type31a:infoflow ioctl 0x00ff;\"}},",
            "{{\"family\":\"rbac\",\"rule_type\":\"allow\",",
            "\"statement\":\"allow role21a_r role21b_r;\"}},",
            "{{\"family\":\"rbac\",\"rule_type\":\"role_transition\",",
            "\"statement\":\"role_transition role21b_r type30:infoflow role20_r;\"}},",
            "{{\"family\":\"mls\",\"rule_type\":\"range_transition\",",
            "\"statement\":\"range_transition type30 system:infoflow7 s0:c1 - s2:c0.c4;\"}}",
            "]}}\n"
        ),
        policy.0.display()
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn sesearch_json_represents_an_empty_result_set() {
    let policy = CompiledPolicy::build_fixture("filename-transition.conf", None);
    let output = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .args(["--json", "--allow", "-s", "type31b", "-ds"])
        .arg(&policy.0)
        .output()
        .expect("sesearch should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("JSON output is UTF-8");
    assert!(stdout.contains("\"schema\":\"setools-rs.sesearch\""));
    assert!(
        stdout.contains("\"source\":{\"value\":\"type31b\",\"indirect\":false,\"regex\":false}")
    );
    assert!(stdout.ends_with("\"result_count\":0,\"results\":[]}\n"));
}

#[test]
fn sesearch_json_preserves_help_and_error_contracts() {
    let regular_help = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .arg("--help")
        .output()
        .expect("sesearch should execute");
    let json_help = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .args(["--json", "--help"])
        .output()
        .expect("sesearch should execute");
    assert_eq!(json_help.status.code(), regular_help.status.code());
    assert_eq!(json_help.stdout, regular_help.stdout);
    assert_eq!(json_help.stderr, regular_help.stderr);
    assert!(
        !json_help
            .stdout
            .windows(6)
            .any(|window| window == b"--json")
    );

    let regular_usage = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .output()
        .expect("sesearch should execute");
    let json_usage = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .arg("--json")
        .output()
        .expect("sesearch should execute");
    assert_eq!(json_usage.status.code(), regular_usage.status.code());
    assert_eq!(json_usage.stdout, regular_usage.stdout);
    assert_eq!(json_usage.stderr, regular_usage.stderr);

    let regular_error = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .arg("--allow")
        .arg("-s")
        .arg("missing_type")
        .arg("/definitely/missing/policy")
        .output()
        .expect("sesearch should execute");
    let json_error = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .args(["--json", "--allow", "-s", "missing_type"])
        .arg("/definitely/missing/policy")
        .output()
        .expect("sesearch should execute");
    assert_eq!(json_error.status.code(), regular_error.status.code());
    assert_eq!(json_error.stdout, regular_error.stdout);
    assert_eq!(json_error.stderr, regular_error.stderr);

    let policy = CompiledPolicy::build_fixture("filename-transition.conf", None);
    let regular_query_error = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .args(["--allow", "-s", "missing_type"])
        .arg(&policy.0)
        .output()
        .expect("sesearch should execute");
    let json_query_error = Command::new(env!("CARGO_BIN_EXE_sesearch"))
        .args(["--json", "--allow", "-s", "missing_type"])
        .arg(&policy.0)
        .output()
        .expect("sesearch should execute");
    assert_eq!(
        json_query_error.status.code(),
        regular_query_error.status.code()
    );
    assert_eq!(json_query_error.stdout, regular_query_error.stdout);
    assert_eq!(json_query_error.stderr, regular_query_error.stderr);
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
fn seinfo_emits_versioned_json_statistics_and_type_results() {
    let statistics_policy = CompiledPolicy::build_fixture("seinfo.conf", None);
    let statistics = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .arg("--json")
        .arg(&statistics_policy.0)
        .output()
        .expect("seinfo should execute");
    assert!(statistics.status.success());
    assert!(statistics.stderr.is_empty());
    let statistics_stdout =
        String::from_utf8(statistics.stdout).expect("JSON output should be UTF-8");
    assert!(statistics_stdout.starts_with(
        "{\"schema\":\"setools-rs.seinfo\",\"schema_version\":1,\"tool\":{\"name\":\"seinfo\",\"version\":\"4.7.1\"}"
    ));
    assert!(
        statistics_stdout.contains(
            "\"query\":{\"all\":false,\"expand\":false,\"flat\":false,\"components\":[]}"
        )
    );
    assert!(statistics_stdout.contains("\"statistics\":{\"policy_version\":"));
    assert!(statistics_stdout.contains("\"target\":\"selinux\""));
    assert!(statistics_stdout.contains("\"handle_unknown\":\"reject\""));
    for count in [
        "classes",
        "types",
        "allow",
        "constraints",
        "allowxperm",
        "initial_sids",
        "nodecon",
    ] {
        assert!(
            statistics_stdout.contains(&format!("\"{count}\":")),
            "missing statistics count: {count}"
        );
    }
    assert!(statistics_stdout.ends_with("\"result_count\":0,\"results\":[]}\n"));

    let type_policy = CompiledPolicy::build();
    let selected = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--json", "--type", "test1FAIL", "--expand"])
        .arg(&type_policy.0)
        .output()
        .expect("seinfo should execute");
    assert!(selected.status.success());
    assert!(selected.stderr.is_empty());
    let expected = format!(
        concat!(
            "{{\"schema\":\"setools-rs.seinfo\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"seinfo\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"all\":false,\"expand\":true,\"flat\":false,",
            "\"components\":[{{\"component\":\"type\",\"criterion\":\"test1FAIL\"}}]}},",
            "\"statistics\":null,\"result_count\":1,\"results\":[",
            "{{\"component\":\"type\",\"description\":\"Types\",\"count\":1,",
            "\"items\":[\"type test1FAIL, test1a;\"]}}]}}\n"
        ),
        type_policy.0.display()
    );
    assert_eq!(selected.stdout, expected.as_bytes());
}

#[test]
fn seinfo_json_covers_selinux_and_xen_component_families() {
    let selinux_policy = CompiledPolicy::build_fixture("seinfo.conf", None);
    let selinux = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--json", "--all", "--expand"])
        .arg(&selinux_policy.0)
        .output()
        .expect("seinfo should execute");
    assert!(selinux.status.success());
    assert!(selinux.stderr.is_empty());
    let selinux_stdout = String::from_utf8(selinux.stdout).expect("JSON output should be UTF-8");
    for component in [
        "boolean",
        "category",
        "class",
        "common",
        "constraint",
        "default",
        "permissive",
        "polcap",
        "role",
        "sensitivity",
        "typebounds",
        "type",
        "attribute",
        "user",
        "validatetrans",
        "fs_use",
        "genfscon",
        "ibendportcon",
        "ibpkeycon",
        "initialsid",
        "netifcon",
        "nodecon",
        "portcon",
    ] {
        assert!(
            selinux_stdout.contains(&format!("\"component\":\"{component}\"")),
            "missing SELinux component: {component}"
        );
    }

    let xen_policy = CompiledPolicy::build_xen();
    let xen = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--json", "--all", "--expand"])
        .arg(&xen_policy.0)
        .output()
        .expect("seinfo should execute");
    assert!(xen.status.success());
    assert!(xen.stderr.is_empty());
    let xen_stdout = String::from_utf8(xen.stdout).expect("JSON output should be UTF-8");
    assert!(xen_stdout.contains("\"target\":\"xen\""));
    for component in [
        "devicetreecon",
        "iomemcon",
        "ioportcon",
        "pcidevicecon",
        "pirqcon",
    ] {
        assert!(
            xen_stdout.contains(&format!("\"component\":\"{component}\"")),
            "missing Xen component: {component}"
        );
    }
}

#[test]
fn seinfo_json_preserves_help_and_error_contracts() {
    let regular_help = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .arg("--help")
        .output()
        .expect("seinfo should execute");
    let json_help = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--json", "--help"])
        .output()
        .expect("seinfo should execute");
    assert_eq!(json_help.status.code(), regular_help.status.code());
    assert_eq!(json_help.stdout, regular_help.stdout);
    assert_eq!(json_help.stderr, regular_help.stderr);
    assert!(!json_help.stdout.windows(6).any(|value| value == b"--json"));

    let policy = CompiledPolicy::build_fixture("seinfo.conf", None);
    let regular_error = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--constrain", "missing_class"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");
    let json_error = Command::new(env!("CARGO_BIN_EXE_seinfo"))
        .args(["--json", "--constrain", "missing_class"])
        .arg(&policy.0)
        .output()
        .expect("seinfo should execute");
    assert_eq!(json_error.status.code(), regular_error.status.code());
    assert_eq!(json_error.stdout, regular_error.stdout);
    assert_eq!(json_error.stderr, regular_error.stderr);
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

#[test]
fn sediff_reports_simple_semantic_components() {
    let left = CompiledPolicy::build_fixture("diff-simple-left.conf", None);
    let right = CompiledPolicy::build_fixture("diff-simple-right.conf", None);
    let arguments = [
        "--property",
        "--polcap",
        "--bool",
        "--attribute",
        "--category",
        "--sensitivity",
    ];
    let output = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .args(arguments)
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("sediff should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        concat!(
            "Policy Properties (0 Modified)\n",
            "\n",
            "Policy Capabilities (1 Added, 1 Removed)\n",
            "   Added Policy Capabilities: 1\n",
            "      + always_check_network\n",
            "   Removed Policy Capabilities: 1\n",
            "      - network_peer_controls\n",
            "\n",
            "Booleans (1 Added, 1 Removed, 1 Modified)\n",
            "   Added Booleans: 1\n",
            "      + added_bool\n",
            "   Removed Booleans: 1\n",
            "      - removed_bool\n",
            "   Modified Booleans: 1\n",
            "      * modified_bool (Modified default state)\n",
            "          + True\n",
            "          - False\n",
            "\n",
            "Type Attributes (1 Added, 1 Removed, 1 Modified)\n",
            "   Added Type Attributes: 1\n",
            "      + added_attr\n",
            "   Removed Type Attributes: 1\n",
            "      - removed_attr\n",
            "   Modified Type Attributes: 1\n",
            "      * changing_attr (1 Added types, 1 Removed types)\n",
            "          + right_member\n",
            "          - left_member\n",
            "\n",
            "Categories (1 Added, 1 Removed, 1 Modified)\n",
            "   Added Categories: 1\n",
            "      + added_category\n",
            "   Removed Categories: 1\n",
            "      - removed_category\n",
            "   Modified Categories: 1\n",
            "      * c0 (1 Added Aliases, 1 Removed Aliases)\n",
            "          Aliases:\n",
            "          + added_category_alias\n",
            "          - removed_category_alias\n",
            "\n",
            "Sensitivities (1 Added, 1 Removed, 1 Modified)\n",
            "   Added Sensitivities: 1\n",
            "      + added_sensitivity\n",
            "   Removed Sensitivities: 1\n",
            "      - removed_sensitivity\n",
            "   Modified Sensitivities: 1\n",
            "      * s0 (1 Added Aliases, 1 Removed Aliases)\n",
            "          Aliases:\n",
            "          + added_sens_alias\n",
            "          - removed_sens_alias\n",
            "\n",
        )
        .as_bytes()
    );

    let stats = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .arg("--stats")
        .args(arguments)
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("sediff --stats should execute");
    assert!(stats.status.success());
    assert!(stats.stderr.is_empty());
    assert_eq!(
        stats.stdout,
        concat!(
            "Policy Properties (0 Modified)\n\n",
            "Policy Capabilities (1 Added, 1 Removed)\n\n",
            "Booleans (1 Added, 1 Removed, 1 Modified)\n\n",
            "Type Attributes (1 Added, 1 Removed, 1 Modified)\n\n",
            "Categories (1 Added, 1 Removed, 1 Modified)\n\n",
            "Sensitivities (1 Added, 1 Removed, 1 Modified)\n\n",
        )
        .as_bytes()
    );
}

#[test]
fn sediff_emits_versioned_json_for_semantic_components() {
    let left = CompiledPolicy::build_fixture("diff-simple-left.conf", None);
    let right = CompiledPolicy::build_fixture("diff-simple-right.conf", None);
    let output = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .args([
            "--json",
            "--property",
            "--polcap",
            "--bool",
            "--attribute",
            "--category",
            "--sensitivity",
        ])
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("sediff --json should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!(
        concat!(
            "{{\"schema\":\"setools-rs.sediff\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"sediff\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"left_path\":\"{}\",\"right_path\":\"{}\"}},",
            "\"query\":{{\"all\":false,\"stats\":false,\"components\":[",
            "\"property\",\"polcap\",\"boolean\",\"attribute\",",
            "\"category\",\"sensitivity\"]}},\"result_count\":14,\"results\":[",
            "{{\"component\":\"property\",\"description\":\"Policy Properties\",",
            "\"counts\":{{\"added\":0,\"removed\":0,\"modified\":0}},",
            "\"added\":[],\"removed\":[],\"modified\":[]}},",
            "{{\"component\":\"polcap\",\"description\":\"Policy Capabilities\",",
            "\"counts\":{{\"added\":1,\"removed\":1,\"modified\":0}},",
            "\"added\":[\"always_check_network\"],",
            "\"removed\":[\"network_peer_controls\"],\"modified\":[]}},",
            "{{\"component\":\"boolean\",\"description\":\"Booleans\",",
            "\"counts\":{{\"added\":1,\"removed\":1,\"modified\":1}},",
            "\"added\":[\"added_bool\"],\"removed\":[\"removed_bool\"],",
            "\"modified\":[{{\"summary\":\"modified_bool (Modified default state)\",",
            "\"details\":[\"+ True\",\"- False\"]}}]}},",
            "{{\"component\":\"attribute\",\"description\":\"Type Attributes\",",
            "\"counts\":{{\"added\":1,\"removed\":1,\"modified\":1}},",
            "\"added\":[\"added_attr\"],\"removed\":[\"removed_attr\"],",
            "\"modified\":[{{\"summary\":",
            "\"changing_attr (1 Added types, 1 Removed types)\",",
            "\"details\":[\"+ right_member\",\"- left_member\"]}}]}},",
            "{{\"component\":\"category\",\"description\":\"Categories\",",
            "\"counts\":{{\"added\":1,\"removed\":1,\"modified\":1}},",
            "\"added\":[\"added_category\"],\"removed\":[\"removed_category\"],",
            "\"modified\":[{{\"summary\":",
            "\"c0 (1 Added Aliases, 1 Removed Aliases)\",",
            "\"details\":[\"Aliases:\",\"+ added_category_alias\",",
            "\"- removed_category_alias\"]}}]}},",
            "{{\"component\":\"sensitivity\",\"description\":\"Sensitivities\",",
            "\"counts\":{{\"added\":1,\"removed\":1,\"modified\":1}},",
            "\"added\":[\"added_sensitivity\"],",
            "\"removed\":[\"removed_sensitivity\"],",
            "\"modified\":[{{\"summary\":",
            "\"s0 (1 Added Aliases, 1 Removed Aliases)\",",
            "\"details\":[\"Aliases:\",\"+ added_sens_alias\",",
            "\"- removed_sens_alias\"]}}]}}]}}\n"
        ),
        left.0.display(),
        right.0.display(),
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn sediff_json_stats_and_empty_all_query_preserve_the_contract() {
    let left = CompiledPolicy::build_fixture("diff-simple-left.conf", None);
    let right = CompiledPolicy::build_fixture("diff-simple-right.conf", None);
    let stats = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .args(["--json", "--stats", "--property", "--polcap"])
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("sediff --json --stats should execute");
    assert!(stats.status.success());
    assert!(stats.stderr.is_empty());
    let stats = String::from_utf8(stats.stdout).expect("JSON should be UTF-8");
    assert!(stats.contains("\"stats\":true"));
    assert!(stats.contains("\"result_count\":2"));
    assert!(stats.contains(
        "\"component\":\"polcap\",\"description\":\"Policy Capabilities\",\"counts\":{\"added\":1,\"removed\":1,\"modified\":0},\"added\":[],\"removed\":[],\"modified\":[]"
    ));

    let empty = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .arg("--json")
        .arg(&left.0)
        .arg(&left.0)
        .output()
        .expect("identical sediff --json should execute");
    assert!(empty.status.success());
    assert!(empty.stderr.is_empty());
    let empty = String::from_utf8(empty.stdout).expect("JSON should be UTF-8");
    assert!(empty.contains(
        "\"query\":{\"all\":true,\"stats\":false,\"components\":[]},\"result_count\":0,\"results\":[]"
    ));
}

#[test]
fn sediff_json_preserves_help_and_error_contracts() {
    let help = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .args(["--json", "--help"])
        .output()
        .expect("sediff help should execute");
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(!help.stdout.windows(6).any(|value| value == b"--json"));

    let missing = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .args(["--json", "left"])
        .output()
        .expect("sediff usage error should execute");
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    assert!(
        missing
            .stderr
            .ends_with(b"sediff: error: the following arguments are required: POLICY2\n")
    );
}

#[test]
fn sediff_accepts_every_component_and_defaults_to_all_differences() {
    let left = CompiledPolicy::build_fixture("diff-simple-left.conf", None);
    let right = CompiledPolicy::build_fixture("diff-simple-right.conf", None);
    let components = [
        "--property",
        "--polcap",
        "--common",
        "--class",
        "--type",
        "--attribute",
        "--role",
        "--user",
        "--bool",
        "--sensitivity",
        "--category",
        "--level",
        "--allow",
        "--auditallow",
        "--dontaudit",
        "--allowxperm",
        "--auditallowxperm",
        "--dontauditxperm",
        "--type_trans",
        "--type_change",
        "--type_member",
        "--role_allow",
        "--role_trans",
        "--range_trans",
        "--constrain",
        "--mlsconstrain",
        "--validatetrans",
        "--mlsvalidatetrans",
        "--ibendportcon",
        "--ibpkeycon",
        "--initialsid",
        "--fs_use",
        "--genfscon",
        "--netifcon",
        "--nodecon",
        "--portcon",
        "--default",
        "--typebounds",
    ];
    let explicit = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .arg("--stats")
        .args(components)
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("complete sediff should execute");
    assert!(explicit.status.success());
    assert!(explicit.stderr.is_empty());
    let explicit = String::from_utf8(explicit.stdout).expect("sediff output should be UTF-8");
    for heading in [
        "Policy Properties",
        "Commons",
        "Types",
        "Allow Rules",
        "Allowxperm Rules",
        "Role_transition Rules",
        "Range_transition Rules",
        "MLS Validatetrans",
        "Initial SIDs",
        "Ibpkeycons",
        "Portcons",
    ] {
        assert!(explicit.contains(heading), "missing {heading} section");
    }

    let json_stats = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .args(["--json", "--stats"])
        .args(components)
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("complete sediff --json should execute");
    assert!(json_stats.status.success());
    assert!(json_stats.stderr.is_empty());
    let json_stats = String::from_utf8(json_stats.stdout).expect("sediff JSON should be UTF-8");
    assert_eq!(
        json_stats.matches("\"component\":").count(),
        components.len()
    );
    assert!(!json_stats.contains("\"added\":[\""));
    assert!(!json_stats.contains("\"removed\":[\""));
    assert!(!json_stats.contains("\"modified\":[{"));

    let all = Command::new(env!("CARGO_BIN_EXE_sediff"))
        .arg(&left.0)
        .arg(&right.0)
        .output()
        .expect("default all-component sediff should execute");
    assert!(all.status.success());
    assert!(all.stderr.is_empty());
    assert!(!all.stdout.is_empty());
    assert!(!all.stdout.starts_with(b"Policy Properties (0 Modified)"));
}

#[test]
fn sedta_reports_transitions_paths_and_graph_statistics() {
    let policy = CompiledPolicy::build_fixture("dta.conf", None);
    let direct = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--source", "alpha", "--stats"])
        .arg("--policy")
        .arg(&policy.0)
        .output()
        .expect("sedta should execute");
    assert!(direct.status.success());
    assert!(direct.stderr.is_empty());
    assert_eq!(
        direct.stdout,
        concat!(
            "Transition 1: alpha -> beta\n\n",
            "Transition 2: alpha -> dynamic\n\n",
            "\n2 domain transition(s) found.\n",
            "\nGraph statistics:\n",
            "nx.number_of_nodes(self.G)=8\n",
            "nx.number_of_edges(self.G)=5\n",
            "len(self.G)=8\n\n",
        )
        .as_bytes()
    );

    let paths = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["-s", "alpha", "-t", "delta", "-A", "3"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("sedta all-paths should execute");
    assert!(paths.status.success());
    assert!(paths.stderr.is_empty());
    assert_eq!(
        paths.stdout,
        concat!(
            "Domain transition path 1:\n",
            "Step 1: alpha -> beta\n\n",
            "Step 2: beta -> gamma\n\n",
            "Step 3: gamma -> delta\n\n",
            "\n",
            "Domain transition path 2:\n",
            "Step 1: alpha -> dynamic\n\n",
            "Step 2: dynamic -> delta\n\n",
            "\n\n2 domain transition path(s) found.\n",
        )
        .as_bytes()
    );
}

#[test]
fn sedta_emits_versioned_json_for_transitions_and_statistics() {
    let policy = CompiledPolicy::build_fixture("dta.conf", None);
    let output = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "--source", "alpha", "--stats"])
        .arg("--policy")
        .arg(&policy.0)
        .output()
        .expect("sedta --json should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!(
        concat!(
            "{{\"schema\":\"setools-rs.sedta\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"sedta\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"mode\":\"transitions_out\",\"source\":\"alpha\",",
            "\"target\":null,\"reverse\":false,\"max_steps\":null,",
            "\"limit\":0,\"exclude\":[],\"full\":false,\"stats\":true}},",
            "\"result_type\":\"transition\",",
            "\"statistics\":{{\"nodes\":8,\"edges\":5}},\"result_count\":2,",
            "\"results\":[",
            "{{\"kind\":\"transition\",\"source\":\"alpha\",",
            "\"target\":\"beta\",\"details\":null}},",
            "{{\"kind\":\"transition\",\"source\":\"alpha\",",
            "\"target\":\"dynamic\",\"details\":null}}]}}\n"
        ),
        policy.0.display(),
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn sedta_json_covers_paths_limits_and_full_rule_details() {
    let policy = CompiledPolicy::build_fixture("dta.conf", None);
    let path = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "-s", "alpha", "-t", "delta", "-A", "3", "-l", "1"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("sedta path JSON should execute");
    assert!(path.status.success());
    assert!(path.stderr.is_empty());
    let expected_path = format!(
        concat!(
            "{{\"schema\":\"setools-rs.sedta\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"sedta\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"mode\":\"all_paths\",\"source\":\"alpha\",",
            "\"target\":\"delta\",\"reverse\":false,\"max_steps\":3,",
            "\"limit\":1,\"exclude\":[],\"full\":false,\"stats\":false}},",
            "\"result_type\":\"path\",\"statistics\":null,\"result_count\":1,",
            "\"results\":[{{\"kind\":\"path\",\"step_count\":3,\"steps\":[",
            "{{\"source\":\"alpha\",\"target\":\"beta\",\"details\":null}},",
            "{{\"source\":\"beta\",\"target\":\"gamma\",\"details\":null}},",
            "{{\"source\":\"gamma\",\"target\":\"delta\",",
            "\"details\":null}}]}}]}}\n"
        ),
        policy.0.display(),
    );
    assert_eq!(path.stdout, expected_path.as_bytes());

    let full = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "-s", "dynamic", "--full"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("sedta full JSON should execute");
    assert!(full.status.success());
    assert!(full.stderr.is_empty());
    let full = String::from_utf8(full.stdout).expect("JSON should be UTF-8");
    for expected in [
        "\"result_type\":\"transition\"",
        "\"source\":\"dynamic\",\"target\":\"delta\"",
        "\"transition_rules\":[\"allow dynamic delta:process { dyntransition transition };\"]",
        "\"setexec_rules\":[\"allow dynamic dynamic:process { setcurrent setexec };\"]",
        "\"name\":\"dynamic_exec\"",
        "\"entrypoint_rules\":[\"allow delta dynamic_exec:file entrypoint;\"]",
        "\"execute_rules\":[\"allow dynamic dynamic_exec:file execute;\"]",
        "\"type_transition_rules\":[\"type_transition dynamic dynamic_exec:process delta;\"]",
        "\"dyntransition_rules\":[\"allow dynamic delta:process { dyntransition transition };\"]",
        "\"setcurrent_rules\":[\"allow dynamic dynamic:process { setcurrent setexec };\"]",
    ] {
        assert!(full.contains(expected), "missing JSON detail: {expected}");
    }
}

#[test]
fn sedta_json_preserves_empty_help_and_error_contracts() {
    let policy = CompiledPolicy::build_fixture("dta.conf", None);
    let empty = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "-s", "delta"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("empty sedta JSON should execute");
    assert!(empty.status.success());
    assert!(empty.stderr.is_empty());
    let empty = String::from_utf8(empty.stdout).expect("JSON should be UTF-8");
    assert!(empty.contains(
        "\"result_type\":\"transition\",\"statistics\":null,\"result_count\":0,\"results\":[]"
    ));

    let help = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "--help"])
        .output()
        .expect("sedta help should execute");
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(!help.stdout.windows(6).any(|value| value == b"--json"));

    let unknown = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "-s", "missing"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("sedta invalid-type JSON query should execute");
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(unknown.stdout, b"missing is not a valid type\n");
    assert!(unknown.stderr.is_empty());

    let output_conflict = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["--json", "-s", "alpha", "--output_file", "graph.png"])
        .output()
        .expect("sedta conflicting output modes should execute");
    assert_eq!(output_conflict.status.code(), Some(2));
    assert!(output_conflict.stdout.is_empty());
    assert!(
        output_conflict
            .stderr
            .ends_with(b"sedta: error: --json cannot be used with --output_file.\n")
    );
}

#[test]
fn sedta_renders_full_rules_and_preserves_error_channels() {
    let policy = CompiledPolicy::build_fixture("dta.conf", None);
    let full = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["-s", "beta", "--full"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("sedta --full should execute");
    assert!(full.status.success());
    assert!(full.stderr.is_empty());
    let stdout = String::from_utf8(full.stdout).expect("sedta output should be UTF-8");
    for expected in [
        "Transition 1: beta -> gamma",
        "Domain transition rule(s):",
        "allow beta gamma:process transition;",
        "Set execution context rule(s):",
        "allow beta beta:process setexec;",
        "Entrypoint gamma_exec:",
        "allow gamma gamma_exec:file entrypoint;",
        "allow beta gamma_exec:file execute;",
    ] {
        assert!(stdout.contains(expected), "missing output: {expected}");
    }

    let invalid_type = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["-s", "missing", "-p"])
        .arg(&policy.0)
        .output()
        .expect("sedta invalid-type query should execute");
    assert_eq!(invalid_type.status.code(), Some(1));
    assert_eq!(invalid_type.stdout, b"missing is not a valid type\n");
    assert!(invalid_type.stderr.is_empty());

    let missing_target = Command::new(env!("CARGO_BIN_EXE_sedta"))
        .args(["-s", "alpha", "-S"])
        .output()
        .expect("sedta invalid arguments should execute");
    assert_eq!(missing_target.status.code(), Some(2));
    assert!(missing_target.stdout.is_empty());
    assert!(missing_target.stderr.starts_with(b"usage: sedta "));
    assert!(
        missing_target
            .stderr
            .ends_with(b"sedta: error: The target type must be specified to determine a path.\n")
    );
}

#[test]
fn seinfoflow_reports_direct_flows_paths_booleans_and_statistics() {
    let policy = CompiledPolicy::build_fixture("infoflow.conf", None);
    let permission_map =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-graph/tests/fixtures/perm_map");
    let direct = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args([
            "-s",
            "flow_source",
            "--full",
            "--stats",
            "-w",
            "1",
            "-b",
            "default",
        ])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow should execute");
    assert!(direct.status.success());
    assert!(direct.stderr.is_empty());
    assert_eq!(
        direct.stdout,
        concat!(
            "Flow 1: flow_source -> middle\n",
            "   allow flow_source middle:channel write_low;\n",
            "   allow middle flow_source:channel read_medium;\n",
            "\n",
            "Flow 2: flow_source -> low_target\n",
            "   allow flow_source low_target:channel write_low;\n",
            "\n",
            "Flow 3: flow_source -> flow_false\n",
            "   allow flow_source flow_false:channel write_high; [ enabled ]:False\n",
            "\n",
            "\n3 information flow(s) found.\n",
            "\nGraph statistics:\n",
            "nx.number_of_nodes(self.G)=7\n",
            "nx.number_of_edges(self.G)=6\n",
            "len(self.G)=7\n\n",
        )
        .as_bytes()
    );

    let path = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["-s", "flow_source", "-t", "flow_target", "-S"])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow shortest path should execute");
    assert!(path.status.success());
    assert!(path.stderr.is_empty());
    assert_eq!(
        path.stdout,
        concat!(
            "Flow 1:\n",
            "  Step 1: flow_source -> middle\n",
            "  Step 2: middle -> flow_target\n",
            "\n1 information flow(s) found.\n",
        )
        .as_bytes()
    );
}

#[test]
fn seinfoflow_emits_versioned_json_for_flows_and_statistics() {
    let policy = CompiledPolicy::build_fixture("infoflow.conf", None);
    let permission_map =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-graph/tests/fixtures/perm_map");
    let output = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args([
            "--json",
            "-s",
            "flow_source",
            "--full",
            "--stats",
            "-w",
            "1",
            "-b",
            "default",
        ])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow --json should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!(
        concat!(
            "{{\"schema\":\"setools-rs.seinfoflow\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"seinfoflow\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"mode\":\"flows_out\",\"source\":\"flow_source\",",
            "\"target\":null,\"reverse\":false,\"max_steps\":null,",
            "\"minimum_weight\":1,\"limit\":0,\"exclude\":[],",
            "\"booleans\":{{\"mode\":\"default\",\"values\":[]}},",
            "\"permission_map\":{{\"kind\":\"file\",\"path\":\"{}\"}},",
            "\"full\":true,\"stats\":true}},\"result_type\":\"flow\",",
            "\"statistics\":{{\"nodes\":7,\"edges\":6}},\"result_count\":3,",
            "\"results\":[",
            "{{\"kind\":\"flow\",\"source\":\"flow_source\",",
            "\"target\":\"middle\",\"weight\":5,\"rules\":[",
            "\"allow flow_source middle:channel write_low;\",",
            "\"allow middle flow_source:channel read_medium;\"]}},",
            "{{\"kind\":\"flow\",\"source\":\"flow_source\",",
            "\"target\":\"low_target\",\"weight\":1,\"rules\":[",
            "\"allow flow_source low_target:channel write_low;\"]}},",
            "{{\"kind\":\"flow\",\"source\":\"flow_source\",",
            "\"target\":\"flow_false\",\"weight\":10,\"rules\":[",
            "\"allow flow_source flow_false:channel write_high; [ enabled ]:False\"]}}]}}\n"
        ),
        policy.0.display(),
        permission_map.display(),
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn seinfoflow_json_covers_paths_weights_booleans_and_limits() {
    let policy = CompiledPolicy::build_fixture("infoflow.conf", None);
    let permission_map =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-graph/tests/fixtures/perm_map");
    let path = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["--json", "-s", "flow_source", "-t", "flow_target", "-S"])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow path JSON should execute");
    assert!(path.status.success());
    assert!(path.stderr.is_empty());
    let expected_path = format!(
        concat!(
            "{{\"schema\":\"setools-rs.seinfoflow\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"seinfoflow\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"mode\":\"shortest_paths\",",
            "\"source\":\"flow_source\",\"target\":\"flow_target\",",
            "\"reverse\":false,\"max_steps\":null,\"minimum_weight\":3,",
            "\"limit\":0,\"exclude\":[],\"booleans\":null,",
            "\"permission_map\":{{\"kind\":\"file\",\"path\":\"{}\"}},",
            "\"full\":false,\"stats\":false}},\"result_type\":\"path\",",
            "\"statistics\":null,\"result_count\":1,\"results\":[",
            "{{\"kind\":\"path\",\"step_count\":2,\"steps\":[",
            "{{\"source\":\"flow_source\",\"target\":\"middle\",",
            "\"weight\":5,\"rules\":null}},",
            "{{\"source\":\"middle\",\"target\":\"flow_target\",",
            "\"weight\":10,\"rules\":null}}]}}]}}\n"
        ),
        policy.0.display(),
        permission_map.display(),
    );
    assert_eq!(path.stdout, expected_path.as_bytes());

    let assigned = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args([
            "--json",
            "-s",
            "flow_source",
            "-w",
            "1",
            "-b",
            "enabled:true",
            "-l",
            "2",
        ])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow assigned-Boolean JSON should execute");
    assert!(assigned.status.success());
    assert!(assigned.stderr.is_empty());
    let assigned = String::from_utf8(assigned.stdout).expect("JSON should be UTF-8");
    assert!(assigned.contains(
        "\"booleans\":{\"mode\":\"assignments\",\"values\":[{\"name\":\"enabled\",\"state\":true}]}"
    ));
    assert!(assigned.contains("\"result_count\":2"));
    assert_eq!(assigned.matches("\"kind\":\"flow\"").count(), 2);
}

#[test]
fn seinfoflow_json_preserves_empty_help_and_error_contracts() {
    let policy = CompiledPolicy::build_fixture("infoflow.conf", None);
    let permission_map =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-graph/tests/fixtures/perm_map");
    let empty = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["--json", "-s", "low_target"])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("empty seinfoflow JSON should execute");
    assert!(empty.status.success());
    assert!(empty.stderr.is_empty());
    let empty = String::from_utf8(empty.stdout).expect("JSON should be UTF-8");
    assert!(empty.contains(
        "\"result_type\":\"flow\",\"statistics\":null,\"result_count\":0,\"results\":[]"
    ));

    let built_in = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["--json", "-s", "flow_source"])
        .arg("-p")
        .arg(&policy.0)
        .output()
        .expect("built-in permission-map JSON should execute");
    assert!(built_in.status.success());
    let built_in = String::from_utf8(built_in.stdout).expect("JSON should be UTF-8");
    assert!(built_in.contains("\"permission_map\":{\"kind\":\"built_in\",\"path\":null}"));

    let help = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["--json", "--help"])
        .output()
        .expect("seinfoflow help should execute");
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(!help.stdout.windows(6).any(|value| value == b"--json"));

    let unknown = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["--json", "-s", "missing"])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow invalid-type JSON query should execute");
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(unknown.stdout, b"missing is not a valid type\n");
    assert!(unknown.stderr.is_empty());

    let output_conflict = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["--json", "-s", "flow_source", "--output_file", "graph.png"])
        .output()
        .expect("seinfoflow conflicting output modes should execute");
    assert_eq!(output_conflict.status.code(), Some(2));
    assert!(output_conflict.stdout.is_empty());
    assert!(
        output_conflict
            .stderr
            .ends_with(b"seinfoflow: error: --json cannot be used with --output_file.\n")
    );
}

#[test]
fn seinfoflow_preserves_reverse_filter_and_error_contracts() {
    let policy = CompiledPolicy::build_fixture("infoflow.conf", None);
    let permission_map =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-graph/tests/fixtures/perm_map");
    let reverse = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["-s", "flow_source", "-r"])
        .arg("-p")
        .arg(&policy.0)
        .arg("-m")
        .arg(&permission_map)
        .output()
        .expect("seinfoflow reverse query should execute");
    assert!(reverse.status.success());
    assert_eq!(
        reverse.stdout,
        b"Flow 1: inbound -> flow_source\n\n1 information flow(s) found.\n"
    );
    assert!(reverse.stderr.is_empty());

    let invalid_boolean = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["-s", "flow_source", "-b", "enabled:maybe"])
        .output()
        .expect("seinfoflow invalid Boolean query should execute");
    assert_eq!(invalid_boolean.status.code(), Some(2));
    assert!(invalid_boolean.stdout.is_empty());
    assert!(invalid_boolean.stderr.starts_with(b"usage: seinfoflow "));
    assert!(
        invalid_boolean
            .stderr
            .ends_with(b"seinfoflow: error: Conditional value must be true or false.\n")
    );

    let missing_target = Command::new(env!("CARGO_BIN_EXE_seinfoflow"))
        .args(["-s", "flow_source", "-S"])
        .output()
        .expect("seinfoflow invalid path arguments should execute");
    assert_eq!(missing_target.status.code(), Some(2));
    assert!(missing_target.stdout.is_empty());
    assert!(
        missing_target.stderr.ends_with(
            b"seinfoflow: error: The target type must be specified to determine a path.\n"
        )
    );
}

#[test]
fn sechecker_emits_versioned_json_for_all_check_types() {
    let policy = CompiledPolicy::build_fixture("checker.conf", None);
    let config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures/pass.ini");
    let output = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg("--json")
        .arg(&config)
        .arg(&policy.0)
        .output()
        .expect("sechecker --json should execute");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!(
        concat!(
            "{{\"schema\":\"setools-rs.sechecker\",\"schema_version\":1,",
            "\"tool\":{{\"name\":\"sechecker\",\"version\":\"4.7.1\"}},",
            "\"policy\":{{\"path\":\"{}\"}},",
            "\"query\":{{\"configuration_path\":\"{}\"}},",
            "\"summary\":{{\"check_count\":7,\"passed_check_count\":6,",
            "\"failed_check_count\":0,\"disabled_check_count\":1,",
            "\"failure_count\":0}},\"result_count\":7,\"results\":[",
            "{{\"name\":\"empty\",\"description\":\"empty attribute passes\",",
            "\"check_type\":\"empty_typeattr\",\"status\":\"passed\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"empty_typeattr\",",
            "\"attribute\":\"empty_attr\",\"missing\":false,\"members\":[]}}}},",
            "{{\"name\":\"missing\",\"description\":null,",
            "\"check_type\":\"empty_typeattr\",\"status\":\"passed\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"empty_typeattr\",",
            "\"attribute\":\"optional_attr\",\"missing\":true,\"members\":[]}}}},",
            "{{\"name\":\"te\",\"description\":null,",
            "\"check_type\":\"assert_te\",\"status\":\"passed\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"assert_te\",",
            "\"rules\":[],\"missing_sources\":[],\"missing_targets\":[]}}}},",
            "{{\"name\":\"rbac\",\"description\":null,",
            "\"check_type\":\"assert_rbac\",\"status\":\"passed\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"assert_rbac\",",
            "\"rules\":[],\"missing_sources\":[],\"missing_targets\":[]}}}},",
            "{{\"name\":\"executables\",\"description\":null,",
            "\"check_type\":\"ro_execs\",\"status\":\"passed\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"read_only\",",
            "\"category\":\"executable\",\"checked_types\":[\"executable\"],",
            "\"files\":[]}}}},",
            "{{\"name\":\"modules\",\"description\":null,",
            "\"check_type\":\"ro_kmods\",\"status\":\"passed\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"read_only\",",
            "\"category\":\"kernel_module\",",
            "\"checked_types\":[\"kernel_module\"],\"files\":[]}}}},",
            "{{\"name\":\"disabled\",\"description\":null,",
            "\"check_type\":\"empty_typeattr\",\"status\":\"disabled\",",
            "\"failure_count\":0,\"details\":{{\"kind\":\"disabled\",",
            "\"reason\":\"accepted exception\"}}}}]}}\n"
        ),
        policy.0.display(),
        config.display(),
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn sechecker_json_preserves_findings_and_failure_status() {
    let policy = CompiledPolicy::build_fixture("checker.conf", None);
    let config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures/fail.ini");
    let output = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .args(["--json", "--verbose"])
        .arg(&config)
        .arg(&policy.0)
        .output()
        .expect("failing sechecker JSON should execute");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.ends_with(b"8 failures found in 7 checks.\n"));
    let stdout = String::from_utf8(output.stdout).expect("JSON should be UTF-8");
    for expected in [
        "\"summary\":{\"check_count\":7,\"passed_check_count\":0,\"failed_check_count\":7,\"disabled_check_count\":0,\"failure_count\":8}",
        "\"name\":\"nonempty\",\"description\":null,\"check_type\":\"empty_typeattr\",\"status\":\"failed\",\"failure_count\":1,\"details\":{\"kind\":\"empty_typeattr\",\"attribute\":\"nonempty_attr\",\"missing\":false,\"members\":[\"attribute_member\"]}",
        "\"kind\":\"assert_te\",\"rules\":[\"allow te_source te_target:file read;\"]",
        "\"missing_sources\":[\"expected_but_absent\"]",
        "\"kind\":\"assert_rbac\",\"rules\":[\"allow source_role target_role;\"]",
        "\"missing_targets\":[\"absent_role\"]",
        "\"category\":\"executable\",\"checked_types\":[\"executable\"],\"files\":[{\"type_name\":\"executable\",\"use_rules\":[\"allow exec_domain executable:file execute;\"],\"write_rules\":[\"allow writer executable:file write;\"]}]",
        "\"category\":\"kernel_module\",\"checked_types\":[\"kernel_module\"],\"files\":[{\"type_name\":\"kernel_module\",\"use_rules\":[\"allow loader kernel_module:system module_load;\"],\"write_rules\":[\"allow writer kernel_module:file append;\"]}]",
    ] {
        assert!(stdout.contains(expected), "missing JSON result: {expected}");
    }
}

#[test]
fn sechecker_json_preserves_help_and_error_contracts() {
    let policy = CompiledPolicy::build_fixture("checker.conf", None);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures");

    let help = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .args(["--json", "--help"])
        .output()
        .expect("sechecker help should execute");
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(!help.stdout.windows(6).any(|value| value == b"--json"));

    let invalid = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg("--json")
        .arg(fixtures.join("invalid.ini"))
        .arg(&policy.0)
        .output()
        .expect("invalid sechecker JSON config should execute");
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(invalid.stdout, b"invalid: Invalid option: unknown_option\n");
    assert!(invalid.stderr.is_empty());

    let missing_policy = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg("--json")
        .arg(fixtures.join("pass.ini"))
        .arg(fixtures.join("missing.policy"))
        .output()
        .expect("missing-policy sechecker JSON should execute");
    assert_eq!(missing_policy.status.code(), Some(3));
    assert!(missing_policy.stderr.is_empty());
    assert!(
        missing_policy
            .stdout
            .starts_with(b"[Errno 2] No such file or directory:")
    );

    let output_conflict = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .args(["--json", "--output_file", "report.txt"])
        .arg(fixtures.join("pass.ini"))
        .arg(&policy.0)
        .output()
        .expect("sechecker conflicting output modes should execute");
    assert_eq!(output_conflict.status.code(), Some(2));
    assert!(output_conflict.stdout.is_empty());
    assert!(
        output_conflict
            .stderr
            .ends_with(b"sechecker: error: --json cannot be used with --output_file.\n")
    );
}

#[test]
fn sechecker_runs_every_registered_check_type() {
    let policy = CompiledPolicy::build_fixture("checker.conf", None);
    let config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures/pass.ini");
    let output = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg(&config)
        .arg(&policy.0)
        .output()
        .expect("sechecker should execute");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("sechecker report should be UTF-8");
    for expected in [
        "Description: empty attribute passes",
        "Member types of empty_attr:\n\nCheck PASSED",
        "optional_attr does not exist.",
        "Check DISABLED.  Reason: accepted exception",
        "empty                                   PASSED",
        "missing                                 PASSED",
        "te                                      PASSED",
        "rbac                                    PASSED",
        "executables                             PASSED",
        "modules                                 PASSED",
        "disabled                                DISABLED (accepted exception)",
        "0 failure(s) found.",
    ] {
        assert!(stdout.contains(expected), "missing output: {expected}");
    }
    assert!(stdout.contains("Start time: 20"));
    assert!(stdout.contains("+00:00\n"));
}

#[test]
fn sechecker_reports_findings_and_failure_exit_status() {
    let policy = CompiledPolicy::build_fixture("checker.conf", None);
    let config =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures/fail.ini");
    let output = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg(&config)
        .arg(&policy.0)
        .output()
        .expect("sechecker should execute");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("sechecker report should be UTF-8");
    for expected in [
        "    * attribute_member",
        "    * allow te_source te_target:file read;",
        "Expected rule with source \"expected_but_absent\" not found.",
        "    * allow source_role target_role;",
        "Expected rule with target \"absent_role\" not found.",
        "Executable type executable is writable.",
        "Kernel module type kernel_module is writable.",
        "8 failure(s) found.",
    ] {
        assert!(stdout.contains(expected), "missing output: {expected}");
    }
}

#[test]
fn sechecker_preserves_config_errors_and_output_file_behavior() {
    let policy = CompiledPolicy::build_fixture("checker.conf", None);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../setools-checker/tests/fixtures");
    let invalid = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg(fixtures.join("invalid.ini"))
        .arg(&policy.0)
        .output()
        .expect("sechecker invalid config should execute");
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(invalid.stdout, b"invalid: Invalid option: unknown_option\n");
    assert!(invalid.stderr.is_empty());

    let output_dir = env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let report = output_dir.join(format!(
        "sechecker-report-{}-{}.txt",
        std::process::id(),
        POLICY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let written = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .arg("-o")
        .arg(&report)
        .arg(fixtures.join("pass.ini"))
        .arg(&policy.0)
        .output()
        .expect("sechecker output-file mode should execute");
    assert!(written.status.success());
    assert!(written.stdout.is_empty());
    assert!(written.stderr.is_empty());
    let report_text = std::fs::read_to_string(&report).expect("report should be written");
    assert!(report_text.contains("Result Summary:"));
    assert!(report_text.contains("0 failure(s) found."));
    let _ = std::fs::remove_file(report);
}

#[test]
fn sechecker_requires_a_configuration_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_sechecker"))
        .output()
        .expect("sechecker should execute");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.starts_with(b"usage: sechecker "));
    assert!(
        output
            .stderr
            .ends_with(b"sechecker: error: the following arguments are required: config\n")
    );
}
