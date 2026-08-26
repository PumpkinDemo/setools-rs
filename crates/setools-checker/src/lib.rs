//! Configuration-driven checks over an owned SELinux policy.
//!
//! This crate contains the `sechecker` configuration and analysis semantics.
//! Report rendering, process exit codes, and logging remain CLI concerns.

use setools_policy::{
    Policy, RbacRule, RbacRuleData, RbacRuleKind, RoleId, TeRule, TeRuleKind, TypeId,
    TypeOrAttributeId,
};
use setools_query::{RbacRuleQuery, TeRuleQuery};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const GLOBAL_KEYS: &[&str] = &["check_type", "desc", "disable"];

/// A checker configuration or value is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerConfigError(String);

impl CheckerConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CheckerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CheckerConfigError {}

/// Severity of a non-fatal configuration diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoticeLevel {
    /// Informational validation message.
    Info,
    /// Debug-only validation message.
    Debug,
}

/// A non-fatal message produced while validating checker configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notice {
    /// Message severity.
    pub level: NoticeLevel,
    /// Compatible Python logger name.
    pub module: &'static str,
    /// Human-readable message.
    pub message: String,
}

/// Registered policy-check type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckType {
    /// Assert that a type attribute is empty.
    EmptyTypeAttribute,
    /// Assert the selected TE allow rules are expected or exempt.
    AssertTe,
    /// Assert the selected RBAC allow rules are expected or exempt.
    AssertRbac,
    /// Assert executable file types are read-only.
    ReadOnlyExecutables,
    /// Assert kernel-module file types are read-only.
    ReadOnlyKernelModules,
}

impl CheckType {
    /// Returns the configuration registry key.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EmptyTypeAttribute => "empty_typeattr",
            Self::AssertTe => "assert_te",
            Self::AssertRbac => "assert_rbac",
            Self::ReadOnlyExecutables => "ro_execs",
            Self::ReadOnlyKernelModules => "ro_kmods",
        }
    }

    /// Returns the compatible logger module name.
    #[must_use]
    pub const fn logger(self) -> &'static str {
        match self {
            Self::EmptyTypeAttribute => "setools.checker.emptyattr",
            Self::AssertTe => "setools.checker.assertte",
            Self::AssertRbac => "setools.checker.assertrbac",
            Self::ReadOnlyExecutables => "setools.checker.roexec",
            Self::ReadOnlyKernelModules => "setools.checker.rokmod",
        }
    }

    /// Returns the compatible high-level run message.
    #[must_use]
    pub const fn run_message(self) -> &'static str {
        match self {
            Self::EmptyTypeAttribute => "Checking type attribute is empty.",
            Self::AssertTe => "Checking TE allow rule assertion.",
            Self::AssertRbac => "Checking RBAC allow rule assertion.",
            Self::ReadOnlyExecutables => "Checking executables are read-only.",
            Self::ReadOnlyKernelModules => "Checking kernel modules are read-only.",
        }
    }
}

/// A validated checker configuration bound to a policy.
#[derive(Debug)]
pub struct Checker<'policy> {
    policy: &'policy Policy,
    checks: Vec<Check>,
    notices: Vec<Notice>,
}

impl<'policy> Checker<'policy> {
    /// Parses and validates an INI checker configuration.
    pub fn from_config(
        policy: &'policy Policy,
        source: &str,
        contents: &str,
    ) -> Result<Self, CheckerConfigError> {
        let sections = parse_ini(contents).map_err(|error| {
            CheckerConfigError::new(format!("Unable to parse checker config {source}: {error}"))
        })?;
        let mut checks = Vec::new();
        let mut notices = Vec::new();
        for section in sections {
            let check_type = section
                .options
                .get("check_type")
                .ok_or_else(|| {
                    CheckerConfigError::new(format!("{}: Missing check_type option.", section.name))
                })?
                .clone();
            let check = Check::from_section(policy, section, &check_type, &mut notices)?;
            checks.push(check);
        }
        if checks.is_empty() {
            return Err(CheckerConfigError::new(format!(
                "No checks found in {source}."
            )));
        }
        notices.push(Notice {
            level: NoticeLevel::Debug,
            module: "setools.checker.checker",
            message: "Validated 0 checks.".to_owned(),
        });
        Ok(Self {
            policy,
            checks,
            notices,
        })
    }

    /// Returns non-fatal messages emitted during validation.
    #[must_use]
    pub fn notices(&self) -> &[Notice] {
        &self.notices
    }

    /// Returns the number of configured checks, including disabled checks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Returns whether the configuration has no checks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Runs every configured check in section order.
    #[must_use]
    pub fn run(&self) -> Vec<CheckResult<'policy>> {
        self.checks
            .iter()
            .map(|check| check.run(self.policy))
            .collect()
    }
}

/// Result of one configured check.
#[derive(Debug)]
pub struct CheckResult<'policy> {
    /// INI section name.
    pub name: String,
    /// Optional section description.
    pub description: Option<String>,
    /// Registered check type.
    pub check_type: CheckType,
    /// Typed result details.
    pub outcome: CheckOutcome<'policy>,
    /// Typed trace used by debug-compatible front ends.
    pub debug: CheckDebug<'policy>,
}

impl CheckResult<'_> {
    /// Returns the number of findings attributed to this check.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        match &self.outcome {
            CheckOutcome::Disabled { .. } => 0,
            CheckOutcome::EmptyTypeAttribute { members, .. } => members.len(),
            CheckOutcome::AssertTe {
                rules,
                missing_sources,
                missing_targets,
            } => rules.len() + missing_sources.len() + missing_targets.len(),
            CheckOutcome::AssertRbac {
                rules,
                missing_sources,
                missing_targets,
            } => rules.len() + missing_sources.len() + missing_targets.len(),
            CheckOutcome::ReadOnly { files, .. } => files.len(),
            CheckOutcome::Unexpected { .. } => 1,
        }
    }
}

/// Typed details emitted by a policy check.
#[derive(Debug)]
pub enum CheckOutcome<'policy> {
    /// The check was disabled by configuration.
    Disabled {
        /// The unparsed disable value, used as the reason.
        reason: String,
    },
    /// Type-attribute membership result.
    EmptyTypeAttribute {
        /// Configured attribute name.
        attribute: String,
        /// Whether a missing attribute caused an automatic pass.
        missing: bool,
        /// Concrete member type names in deterministic order.
        members: Vec<String>,
    },
    /// TE assertion findings.
    AssertTe {
        /// Unexpected allow rules.
        rules: Vec<&'policy TeRule>,
        /// Expected concrete sources not observed.
        missing_sources: Vec<String>,
        /// Expected concrete targets not observed.
        missing_targets: Vec<String>,
    },
    /// RBAC assertion findings.
    AssertRbac {
        /// Unexpected role allow rules.
        rules: Vec<&'policy RbacRule>,
        /// Expected concrete sources not observed.
        missing_sources: Vec<String>,
        /// Expected concrete targets not observed.
        missing_targets: Vec<String>,
    },
    /// Writable executable or kernel-module file types.
    ReadOnly {
        /// Kind of protected file type.
        kind: ReadOnlyKind,
        /// Concrete protected types that were checked for writes.
        checked_types: Vec<String>,
        /// Writable file-type findings.
        files: Vec<WritableFile<'policy>>,
    },
    /// A check encountered an unexpected runtime error.
    Unexpected {
        /// Compatible error text.
        message: String,
    },
}

/// Read-only check category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyKind {
    /// Executable file types.
    Executable,
    /// Kernel-module file types.
    KernelModule,
}

/// Evidence that one protected file type is writable.
#[derive(Debug)]
pub struct WritableFile<'policy> {
    /// Concrete file-type name.
    pub type_name: String,
    /// Rules that identify this type as executable or loadable.
    pub use_rules: Vec<&'policy TeRule>,
    /// Rules that make the type writable.
    pub write_rules: Vec<&'policy TeRule>,
}

/// Typed execution trace for debug logging.
#[derive(Debug)]
pub enum CheckDebug<'policy> {
    /// No execution trace, for a disabled or unexpectedly failed check.
    None,
    /// Type-attribute check; details are fully represented by the outcome.
    EmptyTypeAttribute,
    /// TE assertion query and each evaluated rule.
    AssertTe {
        /// Query settings.
        query: TeQuerySettings,
        /// Rules in compatible evaluation order.
        evaluated: Vec<RuleEvaluation<'policy, TeRule>>,
    },
    /// RBAC assertion query and each evaluated rule.
    AssertRbac {
        /// Query settings.
        query: RbacQuerySettings,
        /// Rules in compatible evaluation order.
        evaluated: Vec<RuleEvaluation<'policy, RbacRule>>,
    },
    /// Read-only collection and checking trace.
    ReadOnly {
        /// Concrete domains exempt from execution or module loading.
        exempt_users: Vec<String>,
        /// Candidate use rules and the accepted concrete target names.
        use_rules: Vec<UseRuleEvaluation<'policy>>,
    },
}

/// Settings for a TE assertion query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeQuerySettings {
    /// Optional source type or attribute.
    pub source: Option<String>,
    /// Optional target type or attribute.
    pub target: Option<String>,
    /// Selected object classes.
    pub classes: Vec<String>,
    /// Selected permissions.
    pub permissions: Vec<String>,
}

/// Settings for an RBAC assertion query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RbacQuerySettings {
    /// Optional source role.
    pub source: Option<String>,
    /// Optional target role.
    pub target: Option<String>,
}

/// One rule evaluated by an assertion check.
#[derive(Debug)]
pub struct RuleEvaluation<'policy, Rule> {
    /// Evaluated rule.
    pub rule: &'policy Rule,
    /// Whether the rule became a finding.
    pub failed: bool,
}

/// One execute or module-load rule examined by a read-only check.
#[derive(Debug)]
pub struct UseRuleEvaluation<'policy> {
    /// Evaluated rule.
    pub rule: &'policy TeRule,
    /// Accepted concrete target names; empty means the rule was ignored.
    pub targets: Vec<String>,
}

#[derive(Debug)]
struct Check {
    name: String,
    description: Option<String>,
    disabled: Option<String>,
    kind: CheckKind,
}

#[derive(Debug)]
enum CheckKind {
    EmptyAttribute {
        attribute: String,
        id: Option<TypeOrAttributeId>,
    },
    AssertTe(AssertTe),
    AssertRbac(AssertRbac),
    ReadOnly(ReadOnly),
}

#[derive(Debug)]
struct AssertTe {
    source: Option<String>,
    target: Option<String>,
    classes: Vec<String>,
    permissions: Vec<String>,
    exempt_sources: BTreeSet<TypeId>,
    exempt_targets: BTreeSet<TypeId>,
    expect_sources: BTreeSet<TypeId>,
    expect_targets: BTreeSet<TypeId>,
}

#[derive(Debug)]
struct AssertRbac {
    source: Option<String>,
    target: Option<String>,
    exempt_sources: BTreeSet<RoleId>,
    exempt_targets: BTreeSet<RoleId>,
    expect_sources: BTreeSet<RoleId>,
    expect_targets: BTreeSet<RoleId>,
}

#[derive(Debug)]
struct ReadOnly {
    kind: ReadOnlyKind,
    exempt_writers: BTreeSet<TypeId>,
    exempt_users: BTreeSet<TypeId>,
    exempt_files: BTreeSet<TypeId>,
}

impl Check {
    fn from_section(
        policy: &Policy,
        section: IniSection,
        check_type: &str,
        notices: &mut Vec<Notice>,
    ) -> Result<Self, CheckerConfigError> {
        let name = section.name;
        let description = nonempty(section.options.get("desc"));
        let disabled = nonempty(section.options.get("disable"));
        let kind = match check_type {
            "empty_typeattr" => {
                validate_keys(&name, &section.options, &["attr", "missing_ok"])?;
                let attribute = section
                    .options
                    .get("attr")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        CheckerConfigError::new(format!("{name}: \"attr\" setting is missing."))
                    })?
                    .to_owned();
                let missing_ok = config_bool(section.options.get("missing_ok"));
                let id = policy
                    .type_symbol_by_name(&attribute)
                    .filter(|symbol| symbol.is_attribute())
                    .map(|symbol| symbol.id());
                if id.is_none() && !missing_ok {
                    return Err(CheckerConfigError::new(format!(
                        "{name}: attr setting error: {attribute} is not a valid type attribute"
                    )));
                }
                CheckKind::EmptyAttribute { attribute, id }
            }
            "assert_te" => {
                validate_keys(
                    &name,
                    &section.options,
                    &[
                        "source",
                        "target",
                        "tclass",
                        "perms",
                        "exempt_source",
                        "exempt_target",
                        "expect_source",
                        "expect_target",
                    ],
                )?;
                CheckKind::AssertTe(parse_assert_te(policy, &name, &section.options, notices)?)
            }
            "assert_rbac" => {
                validate_keys(
                    &name,
                    &section.options,
                    &[
                        "source",
                        "target",
                        "exempt_source",
                        "exempt_target",
                        "expect_source",
                        "expect_target",
                    ],
                )?;
                CheckKind::AssertRbac(parse_assert_rbac(policy, &name, &section.options, notices)?)
            }
            "ro_execs" => {
                validate_keys(
                    &name,
                    &section.options,
                    &["exempt_write_domain", "exempt_exec_domain", "exempt_file"],
                )?;
                CheckKind::ReadOnly(parse_read_only(
                    policy,
                    &name,
                    &section.options,
                    ReadOnlyKind::Executable,
                    notices,
                ))
            }
            "ro_kmods" => {
                validate_keys(
                    &name,
                    &section.options,
                    &["exempt_write_domain", "exempt_load_domain", "exempt_file"],
                )?;
                CheckKind::ReadOnly(parse_read_only(
                    policy,
                    &name,
                    &section.options,
                    ReadOnlyKind::KernelModule,
                    notices,
                ))
            }
            _ => {
                return Err(CheckerConfigError::new(format!(
                    "{name}: Unknown policy check type: {check_type}"
                )));
            }
        };
        Ok(Self {
            name,
            description,
            disabled,
            kind,
        })
    }

    fn check_type(&self) -> CheckType {
        match self.kind {
            CheckKind::EmptyAttribute { .. } => CheckType::EmptyTypeAttribute,
            CheckKind::AssertTe(_) => CheckType::AssertTe,
            CheckKind::AssertRbac(_) => CheckType::AssertRbac,
            CheckKind::ReadOnly(ReadOnly {
                kind: ReadOnlyKind::Executable,
                ..
            }) => CheckType::ReadOnlyExecutables,
            CheckKind::ReadOnly(ReadOnly {
                kind: ReadOnlyKind::KernelModule,
                ..
            }) => CheckType::ReadOnlyKernelModules,
        }
    }

    fn run<'policy>(&self, policy: &'policy Policy) -> CheckResult<'policy> {
        let check_type = self.check_type();
        let (outcome, debug) = if let Some(reason) = &self.disabled {
            (
                CheckOutcome::Disabled {
                    reason: reason.clone(),
                },
                CheckDebug::None,
            )
        } else {
            match self.run_enabled(policy) {
                Ok(value) => value,
                Err(message) => (CheckOutcome::Unexpected { message }, CheckDebug::None),
            }
        };
        CheckResult {
            name: self.name.clone(),
            description: self.description.clone(),
            check_type,
            outcome,
            debug,
        }
    }

    fn run_enabled<'policy>(
        &self,
        policy: &'policy Policy,
    ) -> Result<(CheckOutcome<'policy>, CheckDebug<'policy>), String> {
        match &self.kind {
            CheckKind::EmptyAttribute { attribute, id } => {
                let members = id.map_or_else(Vec::new, |id| {
                    policy
                        .type_symbol(id)
                        .into_iter()
                        .flat_map(|symbol| symbol.expanded_types())
                        .filter_map(|id| {
                            policy
                                .type_symbol(TypeOrAttributeId::Type(*id))
                                .map(|symbol| symbol.name().to_owned())
                        })
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                });
                Ok((
                    CheckOutcome::EmptyTypeAttribute {
                        attribute: attribute.clone(),
                        missing: id.is_none(),
                        members,
                    },
                    CheckDebug::EmptyTypeAttribute,
                ))
            }
            CheckKind::AssertTe(options) => run_assert_te(policy, options),
            CheckKind::AssertRbac(options) => run_assert_rbac(policy, options),
            CheckKind::ReadOnly(options) => run_read_only(policy, options),
        }
    }
}

fn parse_assert_te(
    policy: &Policy,
    name: &str,
    options: &BTreeMap<String, String>,
    notices: &mut Vec<Notice>,
) -> Result<AssertTe, CheckerConfigError> {
    let source = parse_type_criterion(policy, name, "source", options.get("source"))?;
    let target = parse_type_criterion(policy, name, "target", options.get("target"))?;
    let classes = split_value(options.get("tclass"));
    for class in &classes {
        if policy.object_class_by_name(class).is_none() {
            return Err(CheckerConfigError::new(format!(
                "{name}: Invalid _internal_tclass item: {class} is not a valid class"
            )));
        }
    }
    let permissions = split_value(options.get("perms"));
    if !permissions.is_empty() {
        let selected = if classes.is_empty() {
            policy.object_classes().iter().collect::<Vec<_>>()
        } else {
            classes
                .iter()
                .filter_map(|class| policy.object_class_by_name(class))
                .collect()
        };
        let invalid = permissions
            .iter()
            .filter(|permission| {
                !selected
                    .iter()
                    .any(|class| class.permission_by_name(permission).is_some())
            })
            .cloned()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            let message = if classes.is_empty() {
                format!(
                    "Permission(s) do not exist any class: {}",
                    invalid.join(", ")
                )
            } else {
                format!(
                    "Permission(s) do not exist in the specified classes: {}",
                    invalid.join(", ")
                )
            };
            return Err(CheckerConfigError::new(format!(
                "{name}: Invalid _internal_perms setting: {message}"
            )));
        }
    }
    if source.is_none() && target.is_none() && classes.is_empty() && permissions.is_empty() {
        return Err(CheckerConfigError::new(
            "At least one of source, target, tclass, or perms options must be set.",
        ));
    }
    let exempt_sources = parse_type_set(
        policy,
        name,
        "exempt_source",
        options.get("exempt_source"),
        false,
        CheckType::AssertTe.logger(),
        notices,
    )?;
    let exempt_targets = parse_type_set(
        policy,
        name,
        "exempt_target",
        options.get("exempt_target"),
        false,
        CheckType::AssertTe.logger(),
        notices,
    )?;
    let expect_sources = parse_type_set(
        policy,
        name,
        "expect_source",
        options.get("expect_source"),
        true,
        CheckType::AssertTe.logger(),
        notices,
    )?;
    let expect_targets = parse_type_set(
        policy,
        name,
        "expect_target",
        options.get("expect_target"),
        true,
        CheckType::AssertTe.logger(),
        notices,
    )?;
    add_overlap_notice(
        policy,
        "expect_source",
        "exempt_source",
        &expect_sources,
        &exempt_sources,
        CheckType::AssertTe.logger(),
        notices,
    );
    add_overlap_notice(
        policy,
        "expect_target",
        "exempt_target",
        &expect_targets,
        &exempt_targets,
        CheckType::AssertTe.logger(),
        notices,
    );
    Ok(AssertTe {
        source,
        target,
        classes,
        permissions,
        exempt_sources,
        exempt_targets,
        expect_sources,
        expect_targets,
    })
}

fn parse_assert_rbac(
    policy: &Policy,
    name: &str,
    options: &BTreeMap<String, String>,
    notices: &mut Vec<Notice>,
) -> Result<AssertRbac, CheckerConfigError> {
    let source = parse_role_criterion(policy, name, "source", options.get("source"))?;
    let target = parse_role_criterion(policy, name, "target", options.get("target"))?;
    if source.is_none() && target.is_none() {
        return Err(CheckerConfigError::new(
            "At least one of source or target options must be set.",
        ));
    }
    let exempt_sources = parse_role_set(
        policy,
        name,
        "exempt_source",
        options.get("exempt_source"),
        false,
        notices,
    )?;
    let exempt_targets = parse_role_set(
        policy,
        name,
        "exempt_target",
        options.get("exempt_target"),
        false,
        notices,
    )?;
    let expect_sources = parse_role_set(
        policy,
        name,
        "expect_source",
        options.get("expect_source"),
        true,
        notices,
    )?;
    let expect_targets = parse_role_set(
        policy,
        name,
        "expect_target",
        options.get("expect_target"),
        true,
        notices,
    )?;
    add_role_overlap_notice(
        policy,
        "expect_source",
        "exempt_source",
        &expect_sources,
        &exempt_sources,
        notices,
    );
    add_role_overlap_notice(
        policy,
        "expect_target",
        "exempt_target",
        &expect_targets,
        &exempt_targets,
        notices,
    );
    Ok(AssertRbac {
        source,
        target,
        exempt_sources,
        exempt_targets,
        expect_sources,
        expect_targets,
    })
}

fn parse_read_only(
    policy: &Policy,
    name: &str,
    options: &BTreeMap<String, String>,
    kind: ReadOnlyKind,
    notices: &mut Vec<Notice>,
) -> ReadOnly {
    let logger = match kind {
        ReadOnlyKind::Executable => CheckType::ReadOnlyExecutables.logger(),
        ReadOnlyKind::KernelModule => CheckType::ReadOnlyKernelModules.logger(),
    };
    let user_option = match kind {
        ReadOnlyKind::Executable => "exempt_exec_domain",
        ReadOnlyKind::KernelModule => "exempt_load_domain",
    };
    let exempt_writers = parse_type_set(
        policy,
        name,
        "exempt_write_domain",
        options.get("exempt_write_domain"),
        false,
        logger,
        notices,
    )
    .expect("non-strict type set cannot fail");
    let exempt_users = parse_type_set(
        policy,
        name,
        user_option,
        options.get(user_option),
        false,
        logger,
        notices,
    )
    .expect("non-strict type set cannot fail");
    let exempt_files = parse_type_set(
        policy,
        name,
        "exempt_file",
        options.get("exempt_file"),
        false,
        logger,
        notices,
    )
    .expect("non-strict type set cannot fail");
    ReadOnly {
        kind,
        exempt_writers,
        exempt_users,
        exempt_files,
    }
}

fn run_assert_te<'policy>(
    policy: &'policy Policy,
    options: &AssertTe,
) -> Result<(CheckOutcome<'policy>, CheckDebug<'policy>), String> {
    let mut query = TeRuleQuery::new(policy);
    query.select_kind(TeRuleKind::Allow);
    if let Some(source) = &options.source {
        query
            .set_source(source, true, false)
            .map_err(|error| error.to_string())?;
    }
    if let Some(target) = &options.target {
        query
            .set_target(target, true, false)
            .map_err(|error| error.to_string())?;
    }
    if !options.classes.is_empty() {
        query
            .set_classes(options.classes.iter().map(String::as_str))
            .map_err(|error| error.to_string())?;
    }
    if !options.permissions.is_empty() {
        query
            .set_permissions(options.permissions.iter().map(String::as_str), false, false)
            .map_err(|error| error.to_string())?;
    }
    let mut unseen_sources = options.expect_sources.clone();
    let mut unseen_targets = options.expect_targets.clone();
    let mut rules = Vec::new();
    let mut evaluated = Vec::new();
    for rule in query.results() {
        let sources = expand_types(policy, rule.source());
        let targets = expand_types(policy, rule.target());
        unseen_sources.retain(|item| !sources.contains(item));
        unseen_targets.retain(|item| !targets.contains(item));
        let failed = has_unexpected(&sources, &options.expect_sources, &options.exempt_sources)
            && has_unexpected(&targets, &options.expect_targets, &options.exempt_targets);
        if failed {
            rules.push(rule);
        }
        evaluated.push(RuleEvaluation { rule, failed });
    }
    Ok((
        CheckOutcome::AssertTe {
            rules,
            missing_sources: type_names(policy, &unseen_sources),
            missing_targets: type_names(policy, &unseen_targets),
        },
        CheckDebug::AssertTe {
            query: TeQuerySettings {
                source: options.source.clone(),
                target: options.target.clone(),
                classes: options.classes.clone(),
                permissions: options.permissions.clone(),
            },
            evaluated,
        },
    ))
}

fn run_assert_rbac<'policy>(
    policy: &'policy Policy,
    options: &AssertRbac,
) -> Result<(CheckOutcome<'policy>, CheckDebug<'policy>), String> {
    let mut query = RbacRuleQuery::new(policy);
    query.select_kind(RbacRuleKind::Allow);
    if let Some(source) = &options.source {
        query
            .set_source(source, true, false)
            .map_err(|error| error.to_string())?;
    }
    if let Some(target) = &options.target {
        query
            .set_target(target, true, false)
            .map_err(|error| error.to_string())?;
    }
    let mut unseen_sources = options.expect_sources.clone();
    let mut unseen_targets = options.expect_targets.clone();
    let mut rules = Vec::new();
    let mut evaluated = Vec::new();
    for rule in query.results() {
        let sources = expand_roles(policy, rule.source());
        let RbacRuleData::Allow { target } = rule.data() else {
            continue;
        };
        let targets = expand_roles(policy, *target);
        unseen_sources.retain(|item| !sources.contains(item));
        unseen_targets.retain(|item| !targets.contains(item));
        let failed = has_unexpected(&sources, &options.expect_sources, &options.exempt_sources)
            && has_unexpected(&targets, &options.expect_targets, &options.exempt_targets);
        if failed {
            rules.push(rule);
        }
        evaluated.push(RuleEvaluation { rule, failed });
    }
    Ok((
        CheckOutcome::AssertRbac {
            rules,
            missing_sources: role_names(policy, &unseen_sources),
            missing_targets: role_names(policy, &unseen_targets),
        },
        CheckDebug::AssertRbac {
            query: RbacQuerySettings {
                source: options.source.clone(),
                target: options.target.clone(),
            },
            evaluated,
        },
    ))
}

fn run_read_only<'policy>(
    policy: &'policy Policy,
    options: &ReadOnly,
) -> Result<(CheckOutcome<'policy>, CheckDebug<'policy>), String> {
    let (use_class, use_permissions) = match options.kind {
        ReadOnlyKind::Executable => ("file", vec!["execute", "execute_no_trans"]),
        ReadOnlyKind::KernelModule => ("system", vec!["module_load"]),
    };
    let mut use_query = TeRuleQuery::new(policy);
    use_query.select_kind(TeRuleKind::Allow);
    use_query
        .set_classes([use_class])
        .map_err(|error| error.to_string())?;
    use_query
        .set_permissions(use_permissions, false, false)
        .map_err(|error| error.to_string())?;
    let mut protected: BTreeMap<TypeId, Vec<&TeRule>> = BTreeMap::new();
    let mut use_rule_trace = Vec::new();
    for rule in use_query.results() {
        let sources = expand_types(policy, rule.source())
            .difference(&options.exempt_users)
            .copied()
            .collect::<BTreeSet<_>>();
        let mut targets = expand_types(policy, rule.target())
            .difference(&options.exempt_files)
            .copied()
            .collect::<BTreeSet<_>>();
        if options.kind == ReadOnlyKind::KernelModule {
            targets.retain(|target| !sources.contains(target));
        }
        let target_names = type_names(policy, &targets);
        if sources.is_empty() || targets.is_empty() {
            use_rule_trace.push(UseRuleEvaluation {
                rule,
                targets: Vec::new(),
            });
            continue;
        }
        for target in &targets {
            protected.entry(*target).or_default().push(rule);
        }
        use_rule_trace.push(UseRuleEvaluation {
            rule,
            targets: target_names,
        });
    }

    let mut write_query = TeRuleQuery::new(policy);
    write_query.select_kind(TeRuleKind::Allow);
    write_query
        .set_classes(["file"])
        .map_err(|error| error.to_string())?;
    write_query
        .set_permissions(["write", "append"], false, false)
        .map_err(|error| error.to_string())?;
    let write_rules = write_query.results();
    let mut checked_types = Vec::new();
    let mut files = Vec::new();
    for (type_id, use_rules) in protected {
        let type_name = policy
            .type_symbol(TypeOrAttributeId::Type(type_id))
            .map_or_else(
                || format!("<type {}>", type_id.as_raw()),
                |value| value.name().to_owned(),
            );
        checked_types.push(type_name.clone());
        let mut writable_by = Vec::new();
        for rule in &write_rules {
            if !expand_types(policy, rule.target()).contains(&type_id) {
                continue;
            }
            let writers = expand_types(policy, rule.source());
            if writers.difference(&options.exempt_writers).next().is_some() {
                writable_by.push(*rule);
            }
        }
        if !writable_by.is_empty() {
            files.push(WritableFile {
                type_name,
                use_rules,
                write_rules: writable_by,
            });
        }
    }
    files.sort_unstable_by(|left, right| left.type_name.cmp(&right.type_name));
    Ok((
        CheckOutcome::ReadOnly {
            kind: options.kind,
            checked_types,
            files,
        },
        CheckDebug::ReadOnly {
            exempt_users: type_names(policy, &options.exempt_users),
            use_rules: use_rule_trace,
        },
    ))
}

fn parse_type_criterion(
    policy: &Policy,
    check: &str,
    option: &str,
    value: Option<&String>,
) -> Result<Option<String>, CheckerConfigError> {
    let Some(value) = nonempty(value) else {
        return Ok(None);
    };
    if policy.type_symbol_by_name(&value).is_none() {
        return Err(CheckerConfigError::new(format!(
            "{check}: Invalid _internal_{option} setting: {value} is not a valid type attribute"
        )));
    }
    Ok(Some(value))
}

fn parse_role_criterion(
    policy: &Policy,
    check: &str,
    option: &str,
    value: Option<&String>,
) -> Result<Option<String>, CheckerConfigError> {
    let Some(value) = nonempty(value) else {
        return Ok(None);
    };
    if policy.role_by_name(&value).is_none() {
        return Err(CheckerConfigError::new(format!(
            "{check}: Invalid _internal_{option} setting: {value} is not a valid role"
        )));
    }
    Ok(Some(value))
}

#[allow(clippy::too_many_arguments)]
fn parse_type_set(
    policy: &Policy,
    check: &str,
    option: &str,
    value: Option<&String>,
    strict: bool,
    logger: &'static str,
    notices: &mut Vec<Notice>,
) -> Result<BTreeSet<TypeId>, CheckerConfigError> {
    let mut result = BTreeSet::new();
    for item in split_value(value) {
        let Some(symbol) = policy.type_symbol_by_name(&item) else {
            let message = format!("{item} is not a valid type attribute");
            if strict {
                return Err(CheckerConfigError::new(format!(
                    "{check}: Invalid _internal_{option} item: {message}"
                )));
            }
            notices.push(Notice {
                level: NoticeLevel::Info,
                module: logger,
                message: format!("{check}: Invalid _internal_{option} item: {message}"),
            });
            continue;
        };
        result.extend(symbol.expanded_types());
    }
    Ok(result)
}

fn parse_role_set(
    policy: &Policy,
    check: &str,
    option: &str,
    value: Option<&String>,
    strict: bool,
    notices: &mut Vec<Notice>,
) -> Result<BTreeSet<RoleId>, CheckerConfigError> {
    let mut result = BTreeSet::new();
    for item in split_value(value) {
        let Some(role) = policy.role_by_name(&item) else {
            let message = format!("{item} is not a valid role");
            if strict {
                return Err(CheckerConfigError::new(format!(
                    "{check}: Invalid _internal_{option} item: {message}"
                )));
            }
            notices.push(Notice {
                level: NoticeLevel::Info,
                module: CheckType::AssertRbac.logger(),
                message: format!("{check}: Invalid _internal_{option} item: {message}"),
            });
            continue;
        };
        result.extend(role.expanded_roles());
    }
    Ok(result)
}

fn add_overlap_notice(
    policy: &Policy,
    expected_name: &str,
    exempt_name: &str,
    expected: &BTreeSet<TypeId>,
    exempt: &BTreeSet<TypeId>,
    logger: &'static str,
    notices: &mut Vec<Notice>,
) {
    let overlap = expected.intersection(exempt).copied().collect();
    let names = type_names(policy, &overlap);
    if !names.is_empty() {
        notices.push(Notice {
            level: NoticeLevel::Info,
            module: logger,
            message: format!(
                "Overlap in {expected_name} and {exempt_name}: {}",
                names.join(", ")
            ),
        });
    }
}

fn add_role_overlap_notice(
    policy: &Policy,
    expected_name: &str,
    exempt_name: &str,
    expected: &BTreeSet<RoleId>,
    exempt: &BTreeSet<RoleId>,
    notices: &mut Vec<Notice>,
) {
    let overlap = expected.intersection(exempt).copied().collect();
    let names = role_names(policy, &overlap);
    if !names.is_empty() {
        notices.push(Notice {
            level: NoticeLevel::Info,
            module: CheckType::AssertRbac.logger(),
            message: format!(
                "Overlap in {expected_name} and {exempt_name}: {}",
                names.join(", ")
            ),
        });
    }
}

fn validate_keys(
    check: &str,
    options: &BTreeMap<String, String>,
    local: &[&str],
) -> Result<(), CheckerConfigError> {
    for key in options.keys() {
        if !GLOBAL_KEYS.contains(&key.as_str()) && !local.contains(&key.as_str()) {
            return Err(CheckerConfigError::new(format!(
                "{check}: Invalid option: {key}"
            )));
        }
    }
    Ok(())
}

fn has_unexpected<T: Ord>(
    actual: &BTreeSet<T>,
    expected: &BTreeSet<T>,
    exempt: &BTreeSet<T>,
) -> bool {
    actual
        .iter()
        .any(|item| !expected.contains(item) && !exempt.contains(item))
}

fn expand_types(policy: &Policy, id: TypeOrAttributeId) -> BTreeSet<TypeId> {
    policy
        .type_symbol(id)
        .into_iter()
        .flat_map(|symbol| symbol.expanded_types())
        .copied()
        .collect()
}

fn expand_roles(policy: &Policy, id: RoleId) -> BTreeSet<RoleId> {
    policy
        .role(id)
        .into_iter()
        .flat_map(|role| role.expanded_roles())
        .copied()
        .collect()
}

fn type_names(policy: &Policy, ids: &BTreeSet<TypeId>) -> Vec<String> {
    let mut names = ids
        .iter()
        .filter_map(|id| policy.type_symbol(TypeOrAttributeId::Type(*id)))
        .map(|symbol| symbol.name().to_owned())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn role_names(policy: &Policy, ids: &BTreeSet<RoleId>) -> Vec<String> {
    let mut names = ids
        .iter()
        .filter_map(|id| policy.role(*id))
        .map(|role| role.name().to_owned())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn nonempty(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn split_value(value: Option<&String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| value.split_whitespace())
        .map(str::to_owned)
        .collect()
}

fn config_bool(value: Option<&String>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "yes" | "true" | "1"
        )
    })
}

#[derive(Debug)]
struct IniSection {
    name: String,
    options: BTreeMap<String, String>,
    explicit: BTreeSet<String>,
}

fn parse_ini(contents: &str) -> Result<Vec<IniSection>, String> {
    let mut defaults = BTreeMap::new();
    let mut sections = Vec::<IniSection>::new();
    let mut current: Option<usize> = None;
    let mut in_default = false;
    let mut last_key: Option<String> = None;
    for (offset, raw) in contents.lines().enumerate() {
        let line_number = offset + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') {
            let Some(name) = trimmed
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            else {
                return Err(format!("invalid section header at line {line_number}"));
            };
            if name.is_empty() {
                return Err(format!("empty section name at line {line_number}"));
            }
            if name == "DEFAULT" {
                current = None;
                in_default = true;
            } else {
                if sections.iter().any(|section| section.name == name) {
                    return Err(format!("section '{name}' already exists"));
                }
                sections.push(IniSection {
                    name: name.to_owned(),
                    options: defaults.clone(),
                    explicit: BTreeSet::new(),
                });
                current = Some(sections.len() - 1);
                in_default = false;
            }
            last_key = None;
            continue;
        }
        if raw.starts_with(char::is_whitespace) {
            let Some(key) = &last_key else {
                return Err(format!("unexpected continuation at line {line_number}"));
            };
            let target = if let Some(index) = current {
                &mut sections[index].options
            } else if in_default {
                &mut defaults
            } else {
                return Err(format!("unexpected continuation at line {line_number}"));
            };
            let value = target
                .get_mut(key)
                .expect("last key must belong to the current section");
            value.push('\n');
            value.push_str(trimmed);
            continue;
        }
        let separator = raw
            .char_indices()
            .find(|(_, value)| *value == '=' || *value == ':')
            .map(|(index, _)| index)
            .ok_or_else(|| format!("option line has no separator at line {line_number}"))?;
        let key = raw[..separator].trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(format!("empty option name at line {line_number}"));
        }
        let value = raw[separator + 1..].trim().to_owned();
        if let Some(index) = current {
            if !sections[index].explicit.insert(key.clone()) {
                return Err(format!("option '{key}' already exists"));
            }
            sections[index].options.insert(key.clone(), value);
        } else if in_default {
            if defaults.contains_key(&key) {
                return Err(format!("option '{key}' already exists"));
            }
            defaults.insert(key.clone(), value.clone());
            for section in &mut sections {
                if !section.explicit.contains(&key) {
                    section.options.insert(key.clone(), value.clone());
                }
            }
        } else {
            return Err(format!(
                "option found before any section at line {line_number}"
            ));
        }
        last_key = Some(key);
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::{Checker, CheckerConfigError};
    use setools_policy::{HandleUnknown, Policy, PolicyMetadata, TargetPlatform};
    use std::path::PathBuf;

    fn empty_policy() -> Policy {
        Policy::new(
            PathBuf::from("test.policy"),
            PolicyMetadata {
                version: 33,
                mls: false,
                target: TargetPlatform::Selinux,
                handle_unknown: HandleUnknown::Reject,
            },
        )
    }

    #[test]
    fn rejects_empty_configuration() {
        let policy = empty_policy();
        assert_eq!(
            Checker::from_config(&policy, "empty.ini", "").expect_err("empty config should fail"),
            CheckerConfigError::new("No checks found in empty.ini.")
        );
    }

    #[test]
    fn accepts_missing_attribute_when_configured() {
        let policy = empty_policy();
        let checker = Checker::from_config(
            &policy,
            "missing.ini",
            "[missing]\ncheck_type = empty_typeattr\nattr = absent\nmissing_ok = yes\n",
        )
        .expect("configuration should validate");
        let results = checker.run();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].failure_count(), 0);
    }

    #[test]
    fn rejects_unknown_check_type() {
        let policy = empty_policy();
        let error =
            Checker::from_config(&policy, "unknown.ini", "[unknown]\ncheck_type = mystery\n")
                .expect_err("unknown check should fail");
        assert_eq!(
            error.to_string(),
            "unknown: Unknown policy check type: mystery"
        );
    }
}
