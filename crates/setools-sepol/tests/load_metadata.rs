//! End-to-end binary policy metadata loading test.

use setools_policy::{
    AttributeId, Boolean, BooleanId, Category, CategoryId, ClassId, CommonPermissionSet,
    Conditional, ConditionalId, ConditionalToken, ConstraintExpressionToken, ConstraintKind,
    ConstraintOperator, ConstraintRule, DefaultRule, DefaultRuleKind, FsUseKind, HandleUnknown,
    LabelingRule, MlsLevel, MlsRange, MlsRule, ObjectClass, Permission, PermissionId, Policy,
    PolicyLoader, PortProtocol, RbacRule, RbacRuleData, Role, RoleId, RuleCondition,
    SecurityContext, Sensitivity, SensitivityId, TargetPlatform, TeRule, TeRuleData, TeRuleKind,
    TypeId, TypeOrAttributeId, User, UserId,
};
use setools_policy_binary::{
    BinaryConstraint, BinaryConstraintExpression, BinaryLabelingRule, BinaryMlsLevel,
    BinaryPolicyPrefix, BinaryRbacRuleData, BinarySecurityContext, BinaryTeRule, BinaryTeRuleData,
    BinaryTypeKind, ClassSymbol, PureRustMetadataLoader, PureRustPolicyLoader,
    PureRustPrefixLoader, policy_capability_name,
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
        Self::build_fixture_for_target(relative_source, label, None)
    }

    fn build_fixture_for_target(relative_source: &str, label: &str, target: Option<&str>) -> Self {
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

        let mut command = Command::new(checkpolicy);
        command.args(["-M", "-U", "reject"]);
        if let Some(target) = target {
            command.args(["-c", "30", "-t", target]);
        }
        let result = command
            .arg("-o")
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

    let prefix = PureRustPrefixLoader::default()
        .load(&compiled.0)
        .expect("the pure Rust prefix parser must accept the filename fixture");
    assert_owned_policy_semantically_matches(
        &prefix
            .to_policy(compiled.0.clone())
            .expect("the pure Rust model must fit the default allocation budget"),
        &policy,
    );
    assert_te_rule_body_matches(&prefix, &policy);
    assert_rbac_rule_body_matches(&prefix, &policy);
    assert_filename_transition_body_matches(&prefix, &policy);
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

    let prefix = PureRustPrefixLoader::default()
        .load(&compiled.0)
        .expect("the pure Rust prefix parser must accept the RBAC fixture");
    assert_owned_policy_semantically_matches(
        &prefix
            .to_policy(compiled.0.clone())
            .expect("the pure Rust model must fit the default allocation budget"),
        &policy,
    );
    assert_rbac_rule_body_matches(&prefix, &policy);
    assert_filename_transition_body_matches(&prefix, &policy);
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

    let prefix = PureRustPrefixLoader::default()
        .load(&compiled.0)
        .expect("the pure Rust parser must accept the MLS fixture");
    assert_owned_policy_semantically_matches(
        &prefix
            .to_policy(compiled.0.clone())
            .expect("the pure Rust model must fit the default allocation budget"),
        &policy,
    );
    assert_mls_rule_body_matches(&prefix, &policy);
    assert_type_symbol_prefix_matches(&prefix, &policy);
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

    let pure_rust_header = PureRustMetadataLoader
        .load(&compiled.0)
        .expect("the pure Rust metadata parser must accept the same policy");
    assert_eq!(pure_rust_header.metadata(), policy.metadata());

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

#[test]
fn pure_rust_symbol_prefix_matches_libsepol_owned_model() {
    let compiled = CompiledPolicy::build_fixture("seinfo.conf", "pure-rust-symbol-prefix");
    let policy = LibsepolLoader
        .load(&compiled.0)
        .expect("the seinfo fixture must load through libsepol");
    let prefix = PureRustPrefixLoader::default()
        .load(&compiled.0)
        .expect("the pure Rust prefix parser must accept the same policy");
    let reconstructed = prefix
        .to_policy(compiled.0.clone())
        .expect("the pure Rust model must fit the default allocation budget");
    assert_owned_policy_semantically_matches(&reconstructed, &policy);
    let loaded = PureRustPolicyLoader::default()
        .load(&compiled.0)
        .expect("the pure Rust policy loader must reconstruct the same policy");
    assert_eq!(loaded, reconstructed);
    assert_eq!(prefix.booleans().len(), 1);
    assert_eq!(prefix.booleans()[0].name(), "feature_enabled");
    assert!(prefix.booleans()[0].state());

    let mut parsed_commons = prefix
        .commons()
        .iter()
        .map(|common| {
            CommonPermissionSet::new(
                common.name().to_owned(),
                common
                    .permissions()
                    .iter()
                    .map(|permission| permission.name().to_owned())
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    parsed_commons.sort_unstable_by(|left, right| left.name().cmp(right.name()));

    let mut expected_commons = policy.seinfo().commons().to_vec();
    expected_commons.sort_unstable_by(|left, right| left.name().cmp(right.name()));
    assert_eq!(parsed_commons, expected_commons);
    assert_eq!(pure_object_classes(&prefix), policy.object_classes());
    assert_eq!(pure_roles(&prefix), policy.roles());
    assert_type_symbol_prefix_matches(&prefix, &policy);
    assert_eq!(pure_users(&prefix), policy.seinfo().users());
    assert_eq!(pure_booleans(&prefix), policy.booleans());
    assert_eq!(pure_sensitivities(&prefix), policy.sensitivities());
    assert_eq!(pure_categories(&prefix), policy.categories());
    assert_eq!(
        pure_policy_capabilities(&prefix),
        policy.seinfo().policy_capabilities()
    );
    assert_eq!(pure_conditionals(&prefix), policy.conditionals());
    assert_labeling_rules_match(&prefix, &policy);
    assert_te_rule_body_matches(&prefix, &policy);
    assert_rbac_rule_body_matches(&prefix, &policy);
    assert_filename_transition_body_matches(&prefix, &policy);
    assert_eq!(pure_defaults(&prefix), policy.seinfo().defaults());
    assert_eq!(
        pure_constraints(&prefix, &policy),
        policy.seinfo().constraints()
    );
}

fn assert_owned_policy_semantically_matches(actual: &Policy, expected: &Policy) {
    assert_eq!(actual.source(), expected.source());
    assert_eq!(actual.metadata(), expected.metadata());
    assert_eq!(actual.type_symbols().len(), expected.type_symbols().len());
    for (actual, expected) in actual.type_symbols().iter().zip(expected.type_symbols()) {
        assert_eq!(actual.id(), expected.id());
        assert_eq!(actual.name(), expected.name());
        assert_eq!(actual.expanded_types(), expected.expanded_types());
        assert_eq!(actual.is_permissive(), expected.is_permissive());
        assert_eq!(actual.bound(), expected.bound());
        let mut actual_aliases = actual.aliases().to_vec();
        actual_aliases.sort_unstable();
        let mut expected_aliases = expected.aliases().to_vec();
        expected_aliases.sort_unstable();
        assert_eq!(actual_aliases, expected_aliases);
    }
    assert_eq!(actual.object_classes(), expected.object_classes());
    assert_eq!(actual.roles(), expected.roles());
    assert_eq!(actual.booleans(), expected.booleans());
    assert_eq!(actual.conditionals(), expected.conditionals());
    assert_same_multiset(actual.te_rules(), expected.te_rules(), "TE rules");
    assert_same_multiset(actual.rbac_rules(), expected.rbac_rules(), "RBAC rules");
    assert_eq!(actual.sensitivities(), expected.sensitivities());
    assert_eq!(actual.categories(), expected.categories());
    assert_same_multiset(actual.mls_rules(), expected.mls_rules(), "MLS rules");
    assert_same_multiset(
        actual.seinfo().commons(),
        expected.seinfo().commons(),
        "common permission sets",
    );
    assert_eq!(actual.seinfo().users(), expected.seinfo().users());
    assert_eq!(
        actual.seinfo().constraints(),
        expected.seinfo().constraints()
    );
    assert_eq!(actual.seinfo().defaults(), expected.seinfo().defaults());
    assert_eq!(
        actual.seinfo().policy_capabilities(),
        expected.seinfo().policy_capabilities()
    );
    assert_same_multiset(
        actual.seinfo().labeling_rules(),
        expected.seinfo().labeling_rules(),
        "labeling rules",
    );
}

fn assert_same_multiset<T>(actual: &[T], expected: &[T], label: &str)
where
    T: Clone + std::fmt::Debug + Eq,
{
    assert_eq!(actual.len(), expected.len(), "different {label} counts");
    let mut unmatched = expected.to_vec();
    for value in actual {
        let index = unmatched
            .iter()
            .position(|candidate| candidate == value)
            .unwrap_or_else(|| {
                panic!("pure Rust {label} entry is absent from libsepol: {value:?}")
            });
        unmatched.remove(index);
    }
    assert!(
        unmatched.is_empty(),
        "libsepol has unmatched {label}: {unmatched:?}"
    );
}

#[test]
fn pure_rust_xen_labeling_matches_libsepol_owned_model() {
    let compiled =
        CompiledPolicy::build_fixture_for_target("xen.conf", "pure-rust-xen-labeling", Some("xen"));
    let policy = LibsepolLoader
        .load(&compiled.0)
        .expect("the Xen fixture must load through libsepol");
    let prefix = PureRustPrefixLoader::default()
        .load(&compiled.0)
        .expect("the pure Rust parser must accept the Xen fixture");

    assert_eq!(prefix.header().metadata(), policy.metadata());
    assert_eq!(
        prefix.encoded_len(),
        std::fs::metadata(&compiled.0).unwrap().len() as usize
    );
    assert_owned_policy_semantically_matches(
        &prefix
            .to_policy(compiled.0.clone())
            .expect("the pure Rust model must fit the default allocation budget"),
        &policy,
    );
    assert_labeling_rules_match(&prefix, &policy);
}

#[test]
#[ignore = "requires SETOOLS_BINARY_POLICY to name an external real policy"]
fn pure_rust_real_policy_labeling_matches_libsepol_owned_model() {
    let path = env::var_os("SETOOLS_BINARY_POLICY")
        .map(PathBuf::from)
        .expect("SETOOLS_BINARY_POLICY must name a binary policy");
    let policy = LibsepolLoader
        .load(&path)
        .expect("the real policy must load through libsepol");
    let prefix = PureRustPrefixLoader::default()
        .load(&path)
        .expect("the pure Rust parser must accept the real policy");

    assert_eq!(prefix.header().metadata(), policy.metadata());
    assert_eq!(
        prefix.encoded_len(),
        std::fs::metadata(&path).unwrap().len() as usize
    );
    assert_eq!(
        pure_policy_capabilities(&prefix),
        policy.seinfo().policy_capabilities()
    );
    assert_owned_policy_semantically_matches(
        &prefix
            .to_policy(path.clone())
            .expect("the pure Rust model must fit the default allocation budget"),
        &policy,
    );
    assert_type_symbol_prefix_matches(&prefix, &policy);
    assert_mls_rule_body_matches(&prefix, &policy);
    assert_labeling_rules_match(&prefix, &policy);
}

fn pure_conditionals(prefix: &BinaryPolicyPrefix) -> Vec<Conditional> {
    prefix
        .conditionals()
        .iter()
        .enumerate()
        .map(|(index, conditional)| {
            Conditional::new(
                ConditionalId::from_raw(index as u32),
                conditional.tokens().to_vec(),
            )
        })
        .collect()
}

fn pure_policy_capabilities(prefix: &BinaryPolicyPrefix) -> Vec<String> {
    let mut capabilities = prefix
        .policy_capabilities()
        .iter()
        .map(|value| {
            policy_capability_name(*value)
                .expect("the parser rejects unknown policy capabilities")
                .to_owned()
        })
        .collect::<Vec<_>>();
    capabilities.sort_unstable();
    capabilities
}

fn assert_mls_rule_body_matches(prefix: &BinaryPolicyPrefix, policy: &Policy) {
    let mut expected = policy.mls_rules().to_vec();
    for rule in prefix.mls_rules() {
        let parsed = MlsRule::new(
            pure_type_symbol_id(prefix, rule.source()),
            pure_type_symbol_id(prefix, rule.target()),
            ClassId::from_raw(rule.target_class() - 1),
            MlsRange::new(
                pure_mls_level(rule.default().low()),
                pure_mls_level(rule.default().high()),
            ),
        );
        let index = expected
            .iter()
            .position(|candidate| candidate == &parsed)
            .unwrap_or_else(|| panic!("pure Rust MLS rule is absent from libsepol: {parsed:?}"));
        expected.remove(index);
    }
    assert!(
        expected.is_empty(),
        "libsepol has unmatched MLS rules: {expected:?}"
    );
}

fn assert_te_rule_body_matches(prefix: &BinaryPolicyPrefix, policy: &Policy) {
    let mut parsed = prefix
        .te_rules()
        .iter()
        .map(|rule| pure_te_rule(prefix, rule, None))
        .collect::<Vec<_>>();
    for conditional_index in 0..prefix.conditionals().len() {
        let conditional = ConditionalId::from_raw(conditional_index as u32);
        parsed.extend(conditional_rules(prefix, conditional, true));
        parsed.extend(conditional_rules(prefix, conditional, false));
    }

    assert!(
        parsed
            .iter()
            .any(|rule| rule.kind() == TeRuleKind::AllowXperm)
    );
    assert!(parsed.iter().any(|rule| rule.condition().is_some()));
    let mut expected = policy
        .te_rules()
        .iter()
        .filter(|rule| {
            !matches!(
                rule.data(),
                TeRuleData::DefaultType {
                    filename: Some(_),
                    ..
                }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    for rule in parsed {
        let index = expected
            .iter()
            .position(|candidate| candidate == &rule)
            .unwrap_or_else(|| panic!("pure Rust TE rule is absent from libsepol: {rule:?}"));
        expected.remove(index);
    }
    assert!(
        expected.is_empty(),
        "libsepol has unmatched TE rules: {expected:?}"
    );
}

fn assert_rbac_rule_body_matches(prefix: &BinaryPolicyPrefix, policy: &Policy) {
    let parsed = prefix
        .rbac_rules()
        .iter()
        .map(|rule| {
            let source = RoleId::from_raw(rule.source() - 1);
            let data = match rule.data() {
                BinaryRbacRuleData::Allow { target } => RbacRuleData::Allow {
                    target: RoleId::from_raw(*target - 1),
                },
                BinaryRbacRuleData::RoleTransition {
                    target,
                    target_class,
                    default,
                } => RbacRuleData::RoleTransition {
                    target: pure_type_symbol_id(prefix, *target),
                    target_class: ClassId::from_raw(*target_class - 1),
                    default: RoleId::from_raw(*default - 1),
                },
            };
            RbacRule::new(source, data)
        })
        .collect::<Vec<_>>();
    let mut expected = policy.rbac_rules().to_vec();
    for rule in parsed {
        let index = expected
            .iter()
            .position(|candidate| candidate == &rule)
            .unwrap_or_else(|| panic!("pure Rust RBAC rule is absent from libsepol: {rule:?}"));
        expected.remove(index);
    }
    assert!(
        expected.is_empty(),
        "libsepol has unmatched RBAC rules: {expected:?}"
    );
}

fn assert_filename_transition_body_matches(prefix: &BinaryPolicyPrefix, policy: &Policy) {
    let parsed = prefix
        .filename_transitions()
        .iter()
        .map(|rule| {
            TeRule::new(
                TeRuleKind::TypeTransition,
                pure_type_symbol_id(prefix, rule.source()),
                pure_type_symbol_id(prefix, rule.target()),
                ClassId::from_raw(rule.target_class() - 1),
                TeRuleData::DefaultType {
                    default: TypeId::from_raw(rule.default_type() - 1),
                    filename: Some(rule.filename().to_owned()),
                },
            )
        })
        .collect::<Vec<_>>();
    let mut expected = policy
        .te_rules()
        .iter()
        .filter(|rule| {
            matches!(
                rule.data(),
                TeRuleData::DefaultType {
                    filename: Some(_),
                    ..
                }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    for rule in parsed {
        let index = expected
            .iter()
            .position(|candidate| candidate == &rule)
            .unwrap_or_else(|| {
                panic!("pure Rust filename transition is absent from libsepol: {rule:?}")
            });
        expected.remove(index);
    }
    assert!(
        expected.is_empty(),
        "libsepol has unmatched filename transitions: {expected:?}"
    );
}

fn conditional_rules(
    prefix: &BinaryPolicyPrefix,
    conditional: ConditionalId,
    block: bool,
) -> Vec<TeRule> {
    let raw = &prefix.conditionals()[conditional.as_raw() as usize];
    let rules = if block {
        raw.true_rules()
    } else {
        raw.false_rules()
    };
    rules
        .iter()
        .map(|rule| pure_te_rule(prefix, rule, Some(RuleCondition::new(conditional, block))))
        .collect()
}

fn pure_te_rule(
    prefix: &BinaryPolicyPrefix,
    rule: &BinaryTeRule,
    condition: Option<RuleCondition>,
) -> TeRule {
    let data = match rule.data() {
        BinaryTeRuleData::Permissions(permissions) => TeRuleData::Permissions(
            permissions
                .iter()
                .copied()
                .map(PermissionId::from_raw)
                .collect(),
        ),
        BinaryTeRuleData::ExtendedPermissions { kind, values } => TeRuleData::ExtendedPermissions {
            kind: *kind,
            values: values.clone(),
        },
        BinaryTeRuleData::DefaultType(default) => TeRuleData::DefaultType {
            default: TypeId::from_raw(default - 1),
            filename: None,
        },
    };
    let rule = TeRule::new(
        rule.kind(),
        pure_type_symbol_id(prefix, rule.source()),
        pure_type_symbol_id(prefix, rule.target()),
        ClassId::from_raw(rule.target_class() - 1),
        data,
    );
    match condition {
        Some(condition) => rule.with_condition(condition),
        None => rule,
    }
}

fn pure_type_symbol_id(prefix: &BinaryPolicyPrefix, value: u32) -> TypeOrAttributeId {
    let symbol = prefix
        .types()
        .iter()
        .find(|symbol| symbol.value() == value)
        .expect("the v35 fixture has no implicit attribute gaps");
    match symbol.kind() {
        BinaryTypeKind::Type => TypeOrAttributeId::Type(TypeId::from_raw(value - 1)),
        BinaryTypeKind::Attribute => TypeOrAttributeId::Attribute(AttributeId::from_raw(value - 1)),
    }
}

fn pure_users(prefix: &BinaryPolicyPrefix) -> Vec<User> {
    prefix
        .users()
        .iter()
        .map(|user| {
            let roles = user
                .roles()
                .iter()
                .copied()
                .filter(|index| prefix.roles()[*index as usize].name() != "object_r")
                .map(RoleId::from_raw)
                .collect();
            User::new(
                UserId::from_raw(user.value() - 1),
                user.name().to_owned(),
                roles,
                user.default_level().map(pure_mls_level),
                user.range().map(|range| {
                    MlsRange::new(pure_mls_level(range.low()), pure_mls_level(range.high()))
                }),
            )
        })
        .collect()
}

fn pure_booleans(prefix: &BinaryPolicyPrefix) -> Vec<Boolean> {
    prefix
        .booleans()
        .iter()
        .map(|boolean| {
            Boolean::new(
                BooleanId::from_raw(boolean.value() - 1),
                boolean.name().to_owned(),
                boolean.state(),
            )
        })
        .collect()
}

fn pure_sensitivities(prefix: &BinaryPolicyPrefix) -> Vec<Sensitivity> {
    prefix
        .sensitivities()
        .iter()
        .map(|sensitivity| {
            Sensitivity::new(
                SensitivityId::from_raw(sensitivity.value() - 1),
                sensitivity.name().to_owned(),
            )
            .with_aliases(sensitivity.aliases().to_vec())
            .with_categories(
                sensitivity
                    .categories()
                    .iter()
                    .copied()
                    .map(CategoryId::from_raw)
                    .collect(),
            )
        })
        .collect()
}

fn pure_categories(prefix: &BinaryPolicyPrefix) -> Vec<Category> {
    prefix
        .categories()
        .iter()
        .map(|category| {
            Category::new(
                CategoryId::from_raw(category.value() - 1),
                category.name().to_owned(),
            )
            .with_aliases(category.aliases().to_vec())
        })
        .collect()
}

fn pure_mls_level(level: &BinaryMlsLevel) -> MlsLevel {
    MlsLevel::new(
        SensitivityId::from_raw(level.sensitivity() - 1),
        level
            .categories()
            .iter()
            .copied()
            .map(CategoryId::from_raw)
            .collect(),
    )
}

fn assert_labeling_rules_match(prefix: &BinaryPolicyPrefix, policy: &Policy) {
    let mut actual = pure_labeling_rules(prefix);
    assert_eq!(actual.len(), policy.seinfo().labeling_rules().len());
    for expected in policy.seinfo().labeling_rules() {
        let position = actual
            .iter()
            .position(|rule| rule == expected)
            .unwrap_or_else(|| panic!("pure Rust labeling model is missing {expected:?}"));
        actual.remove(position);
    }
    assert!(actual.is_empty());
}

fn pure_labeling_rules(prefix: &BinaryPolicyPrefix) -> Vec<LabelingRule> {
    prefix
        .labeling_rules()
        .iter()
        .filter_map(|rule| match rule {
            BinaryLabelingRule::InitialSid { sid, context } => Some(LabelingRule::InitialSid {
                name: initial_sid_name(prefix.header().metadata().target, *sid).to_owned(),
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::FsContext { .. } => None,
            BinaryLabelingRule::Portcon {
                protocol,
                low,
                high,
                context,
            } => Some(LabelingRule::Portcon {
                protocol: match protocol {
                    6 => PortProtocol::Tcp,
                    17 => PortProtocol::Udp,
                    33 => PortProtocol::Dccp,
                    132 => PortProtocol::Sctp,
                    _ => unreachable!("the parser validates port protocols"),
                },
                low: *low,
                high: *high,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Netifcon {
                interface,
                interface_context,
                packet_context,
            } => Some(LabelingRule::Netifcon {
                interface: interface.clone(),
                interface_context: pure_security_context(interface_context),
                packet_context: pure_security_context(packet_context),
            }),
            BinaryLabelingRule::Nodecon {
                address,
                mask,
                context,
            } => Some(LabelingRule::Nodecon {
                address: *address,
                mask: *mask,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::FsUse {
                behavior,
                filesystem,
                context,
            } => Some(LabelingRule::FsUse {
                kind: match behavior {
                    1 => FsUseKind::Xattr,
                    2 => FsUseKind::Transition,
                    3 => FsUseKind::Task,
                    _ => unreachable!("the parser validates fs_use behavior"),
                },
                filesystem: filesystem.clone(),
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Ibpkeycon {
                subnet_prefix,
                low,
                high,
                context,
            } => Some(LabelingRule::Ibpkeycon {
                subnet_prefix: (*subnet_prefix).into(),
                low: *low,
                high: *high,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Ibendportcon {
                device,
                port,
                context,
            } => Some(LabelingRule::Ibendportcon {
                device: device.clone(),
                port: *port,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Pirqcon { irq, context } => Some(LabelingRule::Pirqcon {
                irq: *irq,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Ioportcon { low, high, context } => Some(LabelingRule::Ioportcon {
                low: *low,
                high: *high,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Iomemcon { low, high, context } => Some(LabelingRule::Iomemcon {
                low: *low,
                high: *high,
                context: pure_security_context(context),
            }),
            BinaryLabelingRule::Pcidevicecon { device, context } => {
                Some(LabelingRule::Pcidevicecon {
                    device: *device,
                    context: pure_security_context(context),
                })
            }
            BinaryLabelingRule::Devicetreecon { path, context } => {
                Some(LabelingRule::Devicetreecon {
                    path: path.clone(),
                    context: pure_security_context(context),
                })
            }
            BinaryLabelingRule::Genfscon {
                filesystem,
                path,
                target_class,
                context,
            } => Some(LabelingRule::Genfscon {
                filesystem: filesystem.clone(),
                path: path.clone(),
                target_class: target_class.map(|value| ClassId::from_raw(value - 1)),
                context: pure_security_context(context),
            }),
        })
        .collect()
}

fn pure_security_context(context: &BinarySecurityContext) -> SecurityContext {
    SecurityContext::new(
        UserId::from_raw(context.user() - 1),
        RoleId::from_raw(context.role() - 1),
        TypeId::from_raw(context.type_id() - 1),
        context
            .range()
            .map(|range| MlsRange::new(pure_mls_level(range.low()), pure_mls_level(range.high()))),
    )
}

fn initial_sid_name(target: TargetPlatform, sid: u32) -> &'static str {
    const SELINUX: [&str; 28] = [
        "undefined",
        "kernel",
        "security",
        "unlabeled",
        "fs",
        "file",
        "file_labels",
        "init",
        "any_socket",
        "port",
        "netif",
        "netmsg",
        "node",
        "igmp_packet",
        "icmp_socket",
        "tcp_socket",
        "sysctl_modprobe",
        "sysctl",
        "sysctl_fs",
        "sysctl_kernel",
        "sysctl_net",
        "sysctl_net_unix",
        "sysctl_vm",
        "sysctl_dev",
        "kmod",
        "policy",
        "scmp_packet",
        "devnull",
    ];
    const XEN: [&str; 12] = [
        "xen",
        "dom0",
        "domxen",
        "domio",
        "unlabeled",
        "security",
        "irq",
        "iomem",
        "ioport",
        "device",
        "domU",
        "domDM",
    ];
    match target {
        TargetPlatform::Selinux => SELINUX[sid as usize],
        TargetPlatform::Xen => XEN[sid as usize],
    }
}

fn pure_roles(prefix: &BinaryPolicyPrefix) -> Vec<Role> {
    prefix
        .roles()
        .iter()
        .map(|role| {
            let id = RoleId::from_raw(role.value() - 1);
            Role::new(id, role.name().to_owned(), vec![id]).with_authorized_types(
                role.authorized_types()
                    .iter()
                    .copied()
                    .map(TypeId::from_raw)
                    .collect(),
            )
        })
        .collect()
}

fn assert_type_symbol_prefix_matches(prefix: &BinaryPolicyPrefix, policy: &Policy) {
    assert_eq!(
        prefix.type_primary_count() as usize,
        policy.type_symbols().len()
    );
    assert_eq!(prefix.types().len(), policy.type_symbols().len());
    for raw in prefix.types() {
        let expected = &policy.type_symbols()[(raw.value() - 1) as usize];
        assert_eq!(raw.name(), expected.name());
        assert_eq!(
            raw.kind() == BinaryTypeKind::Attribute,
            expected.is_attribute()
        );
        assert_eq!(raw.is_permissive(), expected.is_permissive());
        assert_eq!(
            raw.bound(),
            expected.bound().map(|bound| bound.as_raw() + 1)
        );
        let mut raw_aliases = raw.aliases().to_vec();
        raw_aliases.sort_unstable();
        let mut expected_aliases = expected.aliases().to_vec();
        expected_aliases.sort_unstable();
        assert_eq!(raw_aliases, expected_aliases);
        assert_eq!(
            raw.expanded_types()
                .iter()
                .copied()
                .map(TypeId::from_raw)
                .collect::<Vec<_>>(),
            expected.expanded_types()
        );
    }
}

fn pure_object_classes(prefix: &BinaryPolicyPrefix) -> Vec<ObjectClass> {
    prefix
        .classes()
        .iter()
        .map(|target_class| {
            let mut permissions = target_class
                .common()
                .into_iter()
                .flat_map(|name| {
                    prefix
                        .commons()
                        .iter()
                        .find(|common| common.name() == name)
                        .expect("the parser validated the inherited common")
                        .permissions()
                })
                .chain(target_class.local_permissions())
                .map(|permission| (permission.value(), permission.name().to_owned()))
                .collect::<Vec<_>>();
            permissions.sort_unstable_by_key(|(value, _)| *value);
            ObjectClass::new(
                ClassId::from_raw(target_class.value() - 1),
                target_class.name().to_owned(),
                permissions
                    .into_iter()
                    .map(|(value, name)| Permission::new(PermissionId::from_raw(value - 1), name))
                    .collect(),
            )
            .with_declaration(
                target_class.common().map(str::to_owned),
                target_class
                    .local_permissions()
                    .iter()
                    .map(|permission| permission.name().to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn pure_defaults(prefix: &BinaryPolicyPrefix) -> Vec<DefaultRule> {
    let mut defaults = Vec::new();
    for target_class in prefix.classes() {
        let target = ClassId::from_raw(target_class.value() - 1);
        for (kind, value) in [
            (DefaultRuleKind::User, target_class.defaults().user()),
            (DefaultRuleKind::Role, target_class.defaults().role()),
            (DefaultRuleKind::Type, target_class.defaults().object_type()),
        ] {
            if let Some(value) = value {
                defaults.push(DefaultRule::new(kind, target, value, None));
            }
        }
        if let Some((value, range)) = target_class.defaults().range() {
            defaults.push(DefaultRule::new(
                DefaultRuleKind::Range,
                target,
                value,
                range,
            ));
        }
    }
    defaults
}

fn pure_constraints(prefix: &BinaryPolicyPrefix, policy: &Policy) -> Vec<ConstraintRule> {
    prefix
        .classes()
        .iter()
        .flat_map(|target_class| {
            target_class
                .constraints()
                .iter()
                .chain(target_class.validation_constraints())
                .map(move |constraint| pure_constraint(target_class, constraint, policy))
        })
        .collect()
}

fn pure_constraint(
    target_class: &ClassSymbol,
    constraint: &BinaryConstraint,
    policy: &Policy,
) -> ConstraintRule {
    let kind = match (constraint.is_validate_transition(), constraint.is_mls()) {
        (false, false) => ConstraintKind::Constrain,
        (false, true) => ConstraintKind::MlsConstrain,
        (true, false) => ConstraintKind::ValidateTransition,
        (true, true) => ConstraintKind::MlsValidateTransition,
    };
    let permissions = (0..target_class.permission_count())
        .filter(|bit| constraint.permissions() & (1_u32 << bit) != 0)
        .map(PermissionId::from_raw)
        .collect();
    let mut expression = Vec::new();
    for raw in constraint.expressions() {
        match raw {
            BinaryConstraintExpression::Not => {
                expression.push(ConstraintExpressionToken::Operator(ConstraintOperator::Not))
            }
            BinaryConstraintExpression::And => {
                expression.push(ConstraintExpressionToken::Operator(ConstraintOperator::And))
            }
            BinaryConstraintExpression::Or => {
                expression.push(ConstraintExpressionToken::Operator(ConstraintOperator::Or))
            }
            BinaryConstraintExpression::Attribute {
                attribute,
                operator,
            } => {
                let (left, right) = constraint_operands(*attribute);
                expression.push(ConstraintExpressionToken::Operand(left.to_owned()));
                expression.push(ConstraintExpressionToken::Operand(
                    right
                        .expect("attribute comparisons have two operands")
                        .to_owned(),
                ));
                expression.push(ConstraintExpressionToken::Operator(*operator));
            }
            BinaryConstraintExpression::Names {
                attribute,
                operator,
                ..
            } => {
                let (left, _) = constraint_operands(*attribute);
                expression.push(ConstraintExpressionToken::Operand(left.to_owned()));
                expression.push(ConstraintExpressionToken::Names(
                    raw.effective_names()
                        .expect("named expressions expose their symbol indices")
                        .iter()
                        .map(|index| constraint_symbol_name(policy, *attribute, *index))
                        .collect(),
                ));
                expression.push(ConstraintExpressionToken::Operator(*operator));
            }
        }
    }
    ConstraintRule::new(
        kind,
        ClassId::from_raw(target_class.value() - 1),
        permissions,
        expression,
    )
}

fn constraint_symbol_name(policy: &Policy, attribute: u32, index: u32) -> String {
    if attribute & 4 != 0 {
        policy
            .type_symbols()
            .get(index as usize)
            .expect("constraint type index must resolve")
            .name()
            .to_owned()
    } else if attribute & 2 != 0 {
        policy
            .roles()
            .get(index as usize)
            .expect("constraint role index must resolve")
            .name()
            .to_owned()
    } else {
        policy
            .seinfo()
            .users()
            .get(index as usize)
            .expect("constraint user index must resolve")
            .name()
            .to_owned()
    }
}

fn constraint_operands(attribute: u32) -> (&'static str, Option<&'static str>) {
    match attribute {
        1 => ("u1", Some("u2")),
        9 => ("u2", None),
        17 => ("u3", None),
        2 => ("r1", Some("r2")),
        10 => ("r2", None),
        18 => ("r3", None),
        4 => ("t1", Some("t2")),
        12 => ("t2", None),
        20 => ("t3", None),
        32 => ("l1", Some("l2")),
        64 => ("l1", Some("h2")),
        128 => ("h1", Some("l2")),
        256 => ("h1", Some("h2")),
        512 => ("l1", Some("h1")),
        1024 => ("l2", Some("h2")),
        _ => panic!("the parser rejects unknown constraint attributes"),
    }
}
