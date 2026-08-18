//! Smoke tests for every installed executable name.

use std::process::Command;

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
