//! End-to-end binary policy metadata loading test.

use setools_policy::{
    ConditionalToken, HandleUnknown, PolicyLoader, RbacRuleData, TargetPlatform, TeRuleData,
    TeRuleKind,
};
use setools_sepol::LibsepolLoader;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

struct CompiledPolicy(PathBuf);

impl CompiledPolicy {
    fn build() -> Self {
        Self::build_fixture("te.conf", "te")
    }

    fn build_fixture(relative_source: &str, label: &str) -> Self {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(relative_source);
        let output_dir = env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        let output = output_dir.join(format!(
            "setools-rust-{label}-test-{}.policy",
            std::process::id()
        ));
        let checkpolicy = env::var_os("CHECKPOLICY").unwrap_or_else(|| "checkpolicy".into());

        let result = Command::new(checkpolicy)
            .args(["-M", "-U", "reject", "-o"])
            .arg(&output)
            .arg(&source)
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

#[test]
fn loads_filename_transitions() {
    let compiled = CompiledPolicy::build_fixture("filename-transition.conf", "filename-transition");
    let policy = LibsepolLoader
        .load(&compiled.0)
        .expect("the filename fixture must load");
    let filename_rule = policy
        .te_rules()
        .iter()
        .find(|rule| {
            matches!(
                rule.data(),
                TeRuleData::DefaultType {
                    filename: Some(filename),
                    ..
                } if filename == "the_filename"
            )
        })
        .expect("filename transition must be copied");
    assert_eq!(filename_rule.kind(), TeRuleKind::TypeTransition);
}

#[test]
fn loads_roles_and_rbac_rules() {
    let compiled = CompiledPolicy::build_fixture("rbac.conf", "rbac");
    let policy = LibsepolLoader
        .load(&compiled.0)
        .expect("the RBAC fixture must load");

    assert!(policy.role_by_name("test31s").is_some());
    assert_eq!(policy.rbac_rules().len(), 26);
    assert!(policy.rbac_rules().iter().any(|rule| {
        matches!(
            rule.data(),
            RbacRuleData::RoleTransition { default, .. }
                if policy.role(*default).is_some_and(|role| role.name() == "test31d3")
        )
    }));
}

#[test]
fn loads_mls_range_transitions() {
    let compiled = CompiledPolicy::build_fixture("mls.conf", "mls");
    let policy = LibsepolLoader
        .load(&compiled.0)
        .expect("the MLS fixture must load");

    assert_eq!(policy.mls_rules().len(), 38);
    assert_eq!(
        policy
            .sensitivity_by_name("s40")
            .expect("s40 sensitivity declaration must resolve")
            .categories()
            .len(),
        5
    );
    let rule = policy
        .mls_rules()
        .iter()
        .find(|rule| {
            policy
                .type_symbol(rule.source())
                .is_some_and(|symbol| symbol.name() == "test40")
        })
        .expect("complex MLS range fixture rule must be copied");
    assert_eq!(
        policy
            .sensitivity(rule.default().low().sensitivity())
            .expect("low sensitivity must resolve")
            .name(),
        "s40"
    );
    assert_eq!(rule.default().low().categories().len(), 1);
    assert_eq!(rule.default().high().categories().len(), 5);
}

impl Drop for CompiledPolicy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn loads_owned_metadata_from_binary_policy() {
    let compiled = CompiledPolicy::build();
    let policy = LibsepolLoader
        .load(&compiled.0)
        .expect("the fixture must load through libsepol");

    assert_eq!(policy.source(), compiled.0);
    assert_eq!(policy.metadata().version, 35);
    assert!(policy.metadata().mls);
    assert_eq!(policy.metadata().target, TargetPlatform::Selinux);
    assert_eq!(policy.metadata().handle_unknown, HandleUnknown::Reject);

    assert_eq!(policy.type_symbols().len(), 72);
    assert_eq!(
        policy
            .type_symbols()
            .iter()
            .filter(|symbol| symbol.is_attribute())
            .count(),
        18
    );
    assert_eq!(policy.object_classes().len(), 7);
    assert_eq!(policy.booleans().len(), 7);
    assert_eq!(policy.conditionals().len(), 8);
    assert_eq!(policy.te_rules().len(), 56);
    assert_eq!(
        policy
            .sensitivity_by_name("med")
            .expect("sensitivity alias must resolve")
            .name(),
        "medium_s"
    );
    assert_eq!(
        policy
            .category_by_name("lost")
            .expect("category alias must resolve")
            .name(),
        "elsewhere"
    );

    let test202a = policy
        .boolean_by_name("test202a")
        .expect("fixture Boolean must be copied");
    let conditional_allow = policy
        .te_rules()
        .iter()
        .find(|rule| {
            rule.condition().is_some()
                && policy
                    .type_symbol(rule.source())
                    .is_some_and(|symbol| symbol.name() == "test202t1")
        })
        .expect("the conditional allow fixture rule must be copied");
    let condition = policy
        .conditional(
            conditional_allow
                .condition()
                .expect("rule was selected as conditional")
                .conditional(),
        )
        .expect("rule conditional must resolve");
    assert_eq!(
        condition.tokens(),
        &[ConditionalToken::Boolean(test202a.id())]
    );

    let direct_allow = policy
        .te_rules()
        .iter()
        .find(|rule| {
            rule.kind() == TeRuleKind::Allow
                && policy
                    .type_symbol(rule.source())
                    .is_some_and(|symbol| symbol.name() == "test1a")
        })
        .expect("the direct allow fixture rule must be copied");
    let target_class = policy
        .object_class(direct_allow.target_class())
        .expect("rule class must resolve");
    let TeRuleData::Permissions(permissions) = direct_allow.data() else {
        panic!("direct allow must carry standard permissions");
    };
    assert_eq!(
        permissions
            .iter()
            .map(|id| target_class
                .permission(*id)
                .expect("permission must resolve")
                .name())
            .collect::<Vec<_>>(),
        ["hi_w"]
    );
}
