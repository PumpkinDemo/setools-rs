//! Query specifications over an owned [`setools_policy::Policy`].

use regex::Regex;
use setools_policy::{
    BooleanId, CategoryId, ClassId, MlsLevel, MlsRange, MlsRule, ObjectClass, Policy, RbacRule,
    RbacRuleData, RbacRuleKind, RoleId, TeRule, TeRuleData, TypeId, TypeOrAttributeId, TypeSymbol,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

pub use setools_policy::TeRuleKind;

/// A query criterion could not be compiled or resolved in the policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryError {
    /// Exact type or attribute name was not found.
    UnknownTypeOrAttribute(String),
    /// Exact object-class name was not found.
    UnknownObjectClass(String),
    /// Exact Boolean name was not found.
    UnknownBoolean(String),
    /// Exact role name was not found.
    UnknownRole(String),
    /// An MLS range criterion could not be parsed or resolved.
    InvalidRange(String),
    /// Permissions do not exist in any class considered by the query.
    UnknownPermissions {
        /// Unknown names in deterministic order.
        names: Vec<String>,
        /// Whether an explicit class criterion constrained validation.
        classes_were_selected: bool,
    },
    /// A regular expression could not be compiled.
    InvalidRegex(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTypeOrAttribute(name) => {
                write!(formatter, "{name} is not a valid type attribute")
            }
            Self::UnknownObjectClass(name) => {
                write!(formatter, "{name} is not a valid class")
            }
            Self::UnknownBoolean(name) => write!(formatter, "{name} is not a valid Boolean"),
            Self::UnknownRole(name) => write!(formatter, "{name} is not a valid role"),
            Self::InvalidRange(message) => formatter.write_str(message),
            Self::UnknownPermissions {
                names,
                classes_were_selected,
            } => {
                if *classes_were_selected {
                    write!(
                        formatter,
                        "Permission(s) do not exist in the specified classes: {}",
                        names.join(", ")
                    )
                } else {
                    write!(
                        formatter,
                        "Permission(s) do not exist any class: {}",
                        names.join(", ")
                    )
                }
            }
            Self::InvalidRegex(message) => formatter.write_str(message),
        }
    }
}

#[derive(Debug)]
enum RoleMatcher {
    Exact(RoleId),
    Regex(Regex),
}

#[derive(Debug)]
struct RoleCriterion {
    matcher: RoleMatcher,
    indirect: bool,
}

#[derive(Debug)]
enum RbacTargetMatcher {
    Role(RoleCriterion),
    Type(SymbolCriterion),
    Regex(Regex),
}

impl Error for QueryError {}

#[derive(Debug)]
enum SymbolMatcher {
    Exact(TypeOrAttributeId),
    Regex(Regex),
}

#[derive(Debug)]
struct SymbolCriterion {
    matcher: SymbolMatcher,
    indirect: bool,
}

#[derive(Debug)]
enum ClassMatcher {
    Exact(BTreeSet<ClassId>),
    Regex(Regex),
}

#[derive(Debug)]
enum BooleanMatcher {
    Exact {
        ids: BTreeSet<BooleanId>,
        equal: bool,
    },
    Regex(Regex),
}

/// Prepared type-enforcement query.
#[derive(Debug)]
pub struct TeRuleQuery<'policy> {
    policy: &'policy Policy,
    kinds: BTreeSet<TeRuleKind>,
    source: Option<SymbolCriterion>,
    target: Option<SymbolCriterion>,
    classes: Option<ClassMatcher>,
    permissions: Option<BTreeSet<String>>,
    permissions_equal: bool,
    permissions_subset: bool,
    xpermissions: Option<BTreeSet<u16>>,
    xpermissions_equal: bool,
    default_type: Option<SymbolCriterion>,
    booleans: Option<BooleanMatcher>,
}

impl<'policy> TeRuleQuery<'policy> {
    /// Creates an empty query bound to a policy.
    #[must_use]
    pub fn new(policy: &'policy Policy) -> Self {
        Self {
            policy,
            kinds: BTreeSet::new(),
            source: None,
            target: None,
            classes: None,
            permissions: None,
            permissions_equal: false,
            permissions_subset: false,
            xpermissions: None,
            xpermissions_equal: false,
            default_type: None,
            booleans: None,
        }
    }

    /// Adds a selected rule kind.
    pub fn select_kind(&mut self, kind: TeRuleKind) {
        self.kinds.insert(kind);
    }

    /// Sets the source symbol criterion.
    pub fn set_source(
        &mut self,
        value: &str,
        indirect: bool,
        regex: bool,
    ) -> Result<(), QueryError> {
        self.source = Some(SymbolCriterion {
            matcher: compile_symbol(self.policy, value, regex)?,
            indirect,
        });
        Ok(())
    }

    /// Sets the target symbol criterion.
    pub fn set_target(
        &mut self,
        value: &str,
        indirect: bool,
        regex: bool,
    ) -> Result<(), QueryError> {
        self.target = Some(SymbolCriterion {
            matcher: compile_symbol(self.policy, value, regex)?,
            indirect,
        });
        Ok(())
    }

    /// Sets an exact comma-separated object-class list.
    pub fn set_classes<'name>(
        &mut self,
        names: impl IntoIterator<Item = &'name str>,
    ) -> Result<(), QueryError> {
        let mut classes = BTreeSet::new();
        for name in names {
            let target_class = self
                .policy
                .object_class_by_name(name)
                .ok_or_else(|| QueryError::UnknownObjectClass(name.to_owned()))?;
            classes.insert(target_class.id());
        }
        self.classes = Some(ClassMatcher::Exact(classes));
        Ok(())
    }

    /// Sets an object-class regular expression.
    pub fn set_class_regex(&mut self, pattern: &str) -> Result<(), QueryError> {
        self.classes = Some(ClassMatcher::Regex(compile_regex(pattern)?));
        Ok(())
    }

    /// Sets standard permission criteria and matching mode.
    pub fn set_permissions<'name>(
        &mut self,
        names: impl IntoIterator<Item = &'name str>,
        equal: bool,
        subset: bool,
    ) -> Result<(), QueryError> {
        let permissions = names
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let selected_classes = self.matching_classes().collect::<Vec<_>>();
        let invalid = permissions
            .iter()
            .filter(|name| {
                !selected_classes
                    .iter()
                    .any(|target_class| target_class.permission_by_name(name).is_some())
            })
            .cloned()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return Err(QueryError::UnknownPermissions {
                names: invalid,
                classes_were_selected: self.classes.is_some(),
            });
        }

        self.permissions = Some(permissions);
        self.permissions_equal = equal;
        self.permissions_subset = subset;
        Ok(())
    }

    /// Sets extended-permission values and equality mode.
    pub fn set_xpermissions(&mut self, values: BTreeSet<u16>, equal: bool) {
        self.xpermissions = Some(values);
        self.xpermissions_equal = equal;
    }

    /// Sets the default type criterion used by type rules.
    pub fn set_default(&mut self, value: &str, regex: bool) -> Result<(), QueryError> {
        self.default_type = Some(SymbolCriterion {
            matcher: compile_symbol(self.policy, value, regex)?,
            indirect: true,
        });
        Ok(())
    }

    /// Sets exact Boolean names and intersection/equality behavior.
    pub fn set_booleans<'name>(
        &mut self,
        names: impl IntoIterator<Item = &'name str>,
        equal: bool,
    ) -> Result<(), QueryError> {
        let mut ids = BTreeSet::new();
        for name in names {
            let boolean = self
                .policy
                .boolean_by_name(name)
                .ok_or_else(|| QueryError::UnknownBoolean(name.to_owned()))?;
            ids.insert(boolean.id());
        }
        self.booleans = Some(BooleanMatcher::Exact { ids, equal });
        Ok(())
    }

    /// Sets a Boolean-name regular expression.
    pub fn set_boolean_regex(&mut self, pattern: &str) -> Result<(), QueryError> {
        self.booleans = Some(BooleanMatcher::Regex(compile_regex(pattern)?));
        Ok(())
    }

    /// Returns the policy queried by this specification.
    #[must_use]
    pub const fn policy(&self) -> &'policy Policy {
        self.policy
    }

    /// Returns selected rule kinds in deterministic order.
    pub fn kinds(&self) -> impl Iterator<Item = TeRuleKind> + '_ {
        self.kinds.iter().copied()
    }

    /// Executes a deterministic linear scan over the owned rule snapshot.
    #[must_use]
    pub fn results(&self) -> Vec<&'policy TeRule> {
        self.policy
            .te_rules()
            .iter()
            .filter(|rule| self.matches(rule))
            .collect()
    }

    fn matches(&self, rule: &TeRule) -> bool {
        if !self.kinds.is_empty() && !self.kinds.contains(&rule.kind()) {
            return false;
        }
        if self
            .source
            .as_ref()
            .is_some_and(|criterion| !symbol_matches(self.policy, rule.source(), criterion))
        {
            return false;
        }
        if self
            .target
            .as_ref()
            .is_some_and(|criterion| !symbol_matches(self.policy, rule.target(), criterion))
        {
            return false;
        }
        if self
            .classes
            .as_ref()
            .is_some_and(|matcher| !class_matches(self.policy, rule.target_class(), matcher))
        {
            return false;
        }
        if !self.matches_permissions(rule) || !self.matches_xpermissions(rule) {
            return false;
        }
        if self.default_type.as_ref().is_some_and(|criterion| {
            let TeRuleData::DefaultType { default, .. } = rule.data() else {
                return true;
            };
            !symbol_matches(self.policy, TypeOrAttributeId::Type(*default), criterion)
        }) {
            return false;
        }
        if self
            .booleans
            .as_ref()
            .is_some_and(|matcher| !self.matches_booleans(rule, matcher))
        {
            return false;
        }
        true
    }

    fn matches_permissions(&self, rule: &TeRule) -> bool {
        let Some(criteria) = &self.permissions else {
            return true;
        };
        match rule.data() {
            TeRuleData::Permissions(ids) => {
                let Some(target_class) = self.policy.object_class(rule.target_class()) else {
                    return false;
                };
                let names = ids
                    .iter()
                    .filter_map(|id| target_class.permission(*id))
                    .map(|permission| permission.name().to_owned())
                    .collect::<BTreeSet<_>>();
                if self.permissions_subset {
                    criteria.is_subset(&names)
                } else if self.permissions_equal {
                    &names == criteria
                } else {
                    !names.is_disjoint(criteria)
                }
            }
            TeRuleData::ExtendedPermissions { kind, .. } => {
                if self.permissions_equal && criteria.len() > 1 {
                    false
                } else {
                    criteria.contains(kind.keyword())
                }
            }
            TeRuleData::DefaultType { .. } => false,
        }
    }

    fn matches_xpermissions(&self, rule: &TeRule) -> bool {
        let Some(criteria) = &self.xpermissions else {
            return true;
        };
        let TeRuleData::ExtendedPermissions { values, .. } = rule.data() else {
            return false;
        };
        let values = values.iter().copied().collect::<BTreeSet<_>>();
        if self.xpermissions_equal {
            &values == criteria
        } else {
            !values.is_disjoint(criteria)
        }
    }

    fn matches_booleans(&self, rule: &TeRule, matcher: &BooleanMatcher) -> bool {
        let Some(rule_condition) = rule.condition() else {
            return false;
        };
        let Some(conditional) = self.policy.conditional(rule_condition.conditional()) else {
            return false;
        };
        match matcher {
            BooleanMatcher::Exact { ids, equal } => {
                let actual = conditional
                    .booleans()
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                if *equal {
                    &actual == ids
                } else {
                    !actual.is_disjoint(ids)
                }
            }
            BooleanMatcher::Regex(regex) => conditional.booleans().iter().any(|id| {
                self.policy
                    .boolean(*id)
                    .is_some_and(|boolean| regex.is_match(boolean.name()))
            }),
        }
    }

    fn matching_classes(&self) -> impl Iterator<Item = &ObjectClass> {
        self.policy.object_classes().iter().filter(|target_class| {
            self.classes
                .as_ref()
                .is_none_or(|matcher| class_matches(self.policy, target_class.id(), matcher))
        })
    }
}

/// Prepared RBAC rule query.
#[derive(Debug)]
pub struct RbacRuleQuery<'policy> {
    policy: &'policy Policy,
    kinds: BTreeSet<RbacRuleKind>,
    source: Option<RoleCriterion>,
    target: Option<RbacTargetMatcher>,
    classes: Option<ClassMatcher>,
    default_role: Option<RoleCriterion>,
}

impl<'policy> RbacRuleQuery<'policy> {
    /// Creates an empty RBAC query.
    #[must_use]
    pub fn new(policy: &'policy Policy) -> Self {
        Self {
            policy,
            kinds: BTreeSet::new(),
            source: None,
            target: None,
            classes: None,
            default_role: None,
        }
    }

    /// Adds a selected rule kind.
    pub fn select_kind(&mut self, kind: RbacRuleKind) {
        self.kinds.insert(kind);
    }

    /// Sets the source role criterion.
    pub fn set_source(
        &mut self,
        value: &str,
        indirect: bool,
        regex: bool,
    ) -> Result<(), QueryError> {
        self.source = Some(compile_role(self.policy, value, indirect, regex)?);
        Ok(())
    }

    /// Sets a target role/type criterion.
    pub fn set_target(
        &mut self,
        value: &str,
        indirect: bool,
        regex: bool,
    ) -> Result<(), QueryError> {
        self.target = Some(if regex {
            RbacTargetMatcher::Regex(compile_regex(value)?)
        } else if let Some(symbol) = self.policy.type_symbol_by_name(value) {
            RbacTargetMatcher::Type(SymbolCriterion {
                matcher: SymbolMatcher::Exact(symbol.id()),
                indirect,
            })
        } else {
            RbacTargetMatcher::Role(compile_role(self.policy, value, indirect, false)?)
        });
        Ok(())
    }

    /// Sets exact object classes.
    pub fn set_classes<'name>(
        &mut self,
        names: impl IntoIterator<Item = &'name str>,
    ) -> Result<(), QueryError> {
        self.classes = Some(compile_classes(self.policy, names)?);
        Ok(())
    }

    /// Sets an object-class regex.
    pub fn set_class_regex(&mut self, pattern: &str) -> Result<(), QueryError> {
        self.classes = Some(ClassMatcher::Regex(compile_regex(pattern)?));
        Ok(())
    }

    /// Sets the default role criterion.
    pub fn set_default(&mut self, value: &str, regex: bool) -> Result<(), QueryError> {
        self.default_role = Some(compile_role(self.policy, value, true, regex)?);
        Ok(())
    }

    /// Executes the query.
    #[must_use]
    pub fn results(&self) -> Vec<&'policy RbacRule> {
        self.policy
            .rbac_rules()
            .iter()
            .filter(|rule| self.matches(rule))
            .collect()
    }

    fn matches(&self, rule: &RbacRule) -> bool {
        if !self.kinds.is_empty() && !self.kinds.contains(&rule.kind()) {
            return false;
        }
        if self
            .source
            .as_ref()
            .is_some_and(|criterion| !role_matches(self.policy, rule.source(), criterion))
        {
            return false;
        }
        match rule.data() {
            RbacRuleData::Allow { target } => {
                if self.classes.is_some() || self.default_role.is_some() {
                    return false;
                }
                self.target.as_ref().is_none_or(|matcher| match matcher {
                    RbacTargetMatcher::Role(criterion) => {
                        role_matches(self.policy, *target, criterion)
                    }
                    RbacTargetMatcher::Regex(regex) => self
                        .policy
                        .role(*target)
                        .is_some_and(|role| regex.is_match(role.name())),
                    RbacTargetMatcher::Type(_) => false,
                })
            }
            RbacRuleData::RoleTransition {
                target,
                target_class,
                default,
            } => {
                if self.target.as_ref().is_some_and(|matcher| match matcher {
                    RbacTargetMatcher::Type(criterion) => {
                        !symbol_matches(self.policy, *target, criterion)
                    }
                    RbacTargetMatcher::Regex(regex) => !self
                        .policy
                        .type_symbol(*target)
                        .is_some_and(|symbol| regex.is_match(symbol.name())),
                    RbacTargetMatcher::Role(_) => true,
                }) {
                    return false;
                }
                if self
                    .classes
                    .as_ref()
                    .is_some_and(|matcher| !class_matches(self.policy, *target_class, matcher))
                {
                    return false;
                }
                self.default_role
                    .as_ref()
                    .is_none_or(|criterion| role_matches(self.policy, *default, criterion))
            }
        }
    }
}

/// Prepared MLS range-transition query.
#[derive(Debug)]
pub struct MlsRuleQuery<'policy> {
    policy: &'policy Policy,
    source: Option<SymbolCriterion>,
    target: Option<SymbolCriterion>,
    classes: Option<ClassMatcher>,
    default_range: Option<MlsRange>,
}

impl<'policy> MlsRuleQuery<'policy> {
    /// Creates an empty MLS query.
    #[must_use]
    pub fn new(policy: &'policy Policy) -> Self {
        Self {
            policy,
            source: None,
            target: None,
            classes: None,
            default_range: None,
        }
    }

    /// Sets the source type criterion.
    pub fn set_source(
        &mut self,
        value: &str,
        indirect: bool,
        regex: bool,
    ) -> Result<(), QueryError> {
        self.source = Some(SymbolCriterion {
            matcher: compile_symbol(self.policy, value, regex)?,
            indirect,
        });
        Ok(())
    }

    /// Sets the target type criterion.
    pub fn set_target(
        &mut self,
        value: &str,
        indirect: bool,
        regex: bool,
    ) -> Result<(), QueryError> {
        self.target = Some(SymbolCriterion {
            matcher: compile_symbol(self.policy, value, regex)?,
            indirect,
        });
        Ok(())
    }

    /// Sets exact object classes.
    pub fn set_classes<'name>(
        &mut self,
        names: impl IntoIterator<Item = &'name str>,
    ) -> Result<(), QueryError> {
        self.classes = Some(compile_classes(self.policy, names)?);
        Ok(())
    }

    /// Sets an object-class regex.
    pub fn set_class_regex(&mut self, pattern: &str) -> Result<(), QueryError> {
        self.classes = Some(ClassMatcher::Regex(compile_regex(pattern)?));
        Ok(())
    }

    /// Sets an exact MLS range criterion.
    pub fn set_default(&mut self, value: &str) -> Result<(), QueryError> {
        self.default_range = Some(parse_mls_range(self.policy, value)?);
        Ok(())
    }

    /// Executes the query.
    #[must_use]
    pub fn results(&self) -> Vec<&'policy MlsRule> {
        self.policy
            .mls_rules()
            .iter()
            .filter(|rule| {
                self.source
                    .as_ref()
                    .is_none_or(|criterion| symbol_matches(self.policy, rule.source(), criterion))
                    && self.target.as_ref().is_none_or(|criterion| {
                        symbol_matches(self.policy, rule.target(), criterion)
                    })
                    && self.classes.as_ref().is_none_or(|matcher| {
                        class_matches(self.policy, rule.target_class(), matcher)
                    })
                    && self
                        .default_range
                        .as_ref()
                        .is_none_or(|range| rule.default() == range)
            })
            .collect()
    }
}

fn compile_role(
    policy: &Policy,
    value: &str,
    indirect: bool,
    regex: bool,
) -> Result<RoleCriterion, QueryError> {
    let matcher = if regex {
        RoleMatcher::Regex(compile_regex(value)?)
    } else {
        RoleMatcher::Exact(
            policy
                .role_by_name(value)
                .ok_or_else(|| QueryError::UnknownRole(value.to_owned()))?
                .id(),
        )
    };
    Ok(RoleCriterion { matcher, indirect })
}

fn role_matches(policy: &Policy, object: RoleId, criterion: &RoleCriterion) -> bool {
    let Some(object) = policy.role(object) else {
        return false;
    };
    if !criterion.indirect {
        return match &criterion.matcher {
            RoleMatcher::Exact(id) => object.id() == *id,
            RoleMatcher::Regex(regex) => regex.is_match(object.name()),
        };
    }
    match &criterion.matcher {
        RoleMatcher::Exact(id) => policy.role(*id).is_some_and(|criteria| {
            object
                .expanded_roles()
                .iter()
                .any(|role| criteria.expanded_roles().binary_search(role).is_ok())
        }),
        RoleMatcher::Regex(regex) => object.expanded_roles().iter().any(|id| {
            policy
                .role(*id)
                .is_some_and(|role| regex.is_match(role.name()))
        }),
    }
}

fn compile_classes<'name>(
    policy: &Policy,
    names: impl IntoIterator<Item = &'name str>,
) -> Result<ClassMatcher, QueryError> {
    let mut classes = BTreeSet::new();
    for name in names {
        let target_class = policy
            .object_class_by_name(name)
            .ok_or_else(|| QueryError::UnknownObjectClass(name.to_owned()))?;
        classes.insert(target_class.id());
    }
    Ok(ClassMatcher::Exact(classes))
}

fn parse_mls_range(policy: &Policy, value: &str) -> Result<MlsRange, QueryError> {
    let mut pieces = value.splitn(2, '-');
    let low = parse_mls_level(policy, pieces.next().unwrap_or_default().trim(), value)?;
    let high = match pieces.next() {
        Some(high) => parse_mls_level(policy, high.trim(), value)?,
        None => low.clone(),
    };
    if high.sensitivity().as_raw() < low.sensitivity().as_raw()
        || !level_categories_contain(&high, &low)
    {
        return Err(QueryError::InvalidRange(format!(
            "{value} is not a valid range ({} is not dominated by {}).",
            format_mls_level(policy, &low).unwrap_or_else(|| "<invalid>".to_owned()),
            format_mls_level(policy, &high).unwrap_or_else(|| "<invalid>".to_owned())
        )));
    }
    Ok(MlsRange::new(low, high))
}

fn parse_mls_level(policy: &Policy, value: &str, range: &str) -> Result<MlsLevel, QueryError> {
    let (sensitivity_name, categories) = value.split_once(':').unwrap_or((value, ""));
    let sensitivity = policy.sensitivity_by_name(sensitivity_name).ok_or_else(|| {
        QueryError::InvalidRange(format!(
            "{range} is not a valid range ({value} is not a valid level ({sensitivity_name} is not a valid sensitivity))."
        ))
    })?;
    let mut ids = BTreeSet::new();
    if !categories.is_empty() {
        for item in categories.split(',') {
            if let Some((low, high)) = item.split_once('.') {
                let low = category_id(policy, low, value, range)?;
                let high = category_id(policy, high, value, range)?;
                if low.as_raw() > high.as_raw() {
                    return Err(invalid_category_range(range, value, item));
                }
                ids.extend((low.as_raw()..=high.as_raw()).map(CategoryId::from_raw));
            } else {
                ids.insert(category_id(policy, item, value, range)?);
            }
        }
    }
    Ok(MlsLevel::new(sensitivity.id(), ids.into_iter().collect()))
}

fn category_id(
    policy: &Policy,
    name: &str,
    level: &str,
    range: &str,
) -> Result<CategoryId, QueryError> {
    policy.category_by_name(name).map(|value| value.id()).ok_or_else(|| {
        QueryError::InvalidRange(format!(
            "{range} is not a valid range ({level} is not a valid level ({name} is not a valid category))."
        ))
    })
}

fn invalid_category_range(range: &str, level: &str, item: &str) -> QueryError {
    QueryError::InvalidRange(format!(
        "{range} is not a valid range ({level} is not a valid level ({item} is not a valid category range))."
    ))
}

fn level_categories_contain(container: &MlsLevel, contained: &MlsLevel) -> bool {
    contained
        .categories()
        .iter()
        .all(|category| container.categories().binary_search(category).is_ok())
}

/// Formats an owned MLS range using SETools' compact category notation.
#[must_use]
pub fn format_mls_range(policy: &Policy, range: &MlsRange) -> Option<String> {
    let low = format_mls_level(policy, range.low())?;
    let high = format_mls_level(policy, range.high())?;
    if range.low() == range.high() {
        Some(low)
    } else {
        Some(format!("{low} - {high}"))
    }
}

fn format_mls_level(policy: &Policy, level: &MlsLevel) -> Option<String> {
    let mut rendered = policy.sensitivity(level.sensitivity())?.name().to_owned();
    let mut groups = Vec::new();
    let Some(first) = level.categories().first().copied() else {
        return Some(rendered);
    };
    let mut low = first;
    let mut high = first;
    for category in &level.categories()[1..] {
        if category.as_raw() == high.as_raw() + 1 {
            high = *category;
        } else {
            groups.push(format_category_group(policy, low, high)?);
            low = *category;
            high = *category;
        }
    }
    groups.push(format_category_group(policy, low, high)?);
    rendered.push(':');
    rendered.push_str(&groups.join(","));
    Some(rendered)
}

fn format_category_group(policy: &Policy, low: CategoryId, high: CategoryId) -> Option<String> {
    let low = policy.category(low)?.name();
    let high = policy.category(high)?.name();
    if low == high {
        Some(low.to_owned())
    } else {
        Some(format!("{low}.{high}"))
    }
}

fn compile_symbol(policy: &Policy, value: &str, regex: bool) -> Result<SymbolMatcher, QueryError> {
    if regex {
        compile_regex(value).map(SymbolMatcher::Regex)
    } else {
        policy
            .type_symbol_by_name(value)
            .map(TypeSymbol::id)
            .map(SymbolMatcher::Exact)
            .ok_or_else(|| QueryError::UnknownTypeOrAttribute(value.to_owned()))
    }
}

fn compile_regex(pattern: &str) -> Result<Regex, QueryError> {
    Regex::new(pattern).map_err(|error| {
        let message = if pattern == "[" {
            "unterminated character set at position 0".to_owned()
        } else {
            error.to_string()
        };
        QueryError::InvalidRegex(message)
    })
}

fn symbol_matches(policy: &Policy, object: TypeOrAttributeId, criterion: &SymbolCriterion) -> bool {
    let Some(object) = policy.type_symbol(object) else {
        return false;
    };
    if !criterion.indirect {
        return match &criterion.matcher {
            SymbolMatcher::Exact(id) => object.id() == *id,
            SymbolMatcher::Regex(regex) => regex.is_match(object.name()),
        };
    }

    match &criterion.matcher {
        SymbolMatcher::Exact(id) => {
            let Some(criteria) = policy.type_symbol(*id) else {
                return false;
            };
            expansions_intersect(object.expanded_types(), criteria.expanded_types())
        }
        SymbolMatcher::Regex(regex) => object.expanded_types().iter().any(|id| {
            policy
                .type_symbol(TypeOrAttributeId::Type(*id))
                .is_some_and(|symbol| regex.is_match(symbol.name()))
        }),
    }
}

fn expansions_intersect(left: &[TypeId], right: &[TypeId]) -> bool {
    left.iter().any(|id| right.binary_search(id).is_ok())
}

fn class_matches(policy: &Policy, id: ClassId, matcher: &ClassMatcher) -> bool {
    match matcher {
        ClassMatcher::Exact(classes) => classes.contains(&id),
        ClassMatcher::Regex(regex) => policy
            .object_class(id)
            .is_some_and(|target_class| regex.is_match(target_class.name())),
    }
}

#[cfg(test)]
mod tests {
    use super::{QueryError, TeRuleQuery};
    use setools_policy::{
        HandleUnknown, Policy, PolicyMetadata, TargetPlatform, TypeId, TypeSymbol,
    };
    use std::path::PathBuf;

    fn policy() -> Policy {
        Policy::from_parts(
            PathBuf::from("policy.35"),
            PolicyMetadata {
                version: 35,
                mls: true,
                target: TargetPlatform::Selinux,
                handle_unknown: HandleUnknown::Reject,
            },
            vec![TypeSymbol::new_type(
                TypeId::from_raw(0),
                "example_t".to_owned(),
            )],
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn unknown_exact_source_is_reported_during_preparation() {
        let policy = policy();
        let mut query = TeRuleQuery::new(&policy);
        assert_eq!(
            query.set_source("missing_t", true, false),
            Err(QueryError::UnknownTypeOrAttribute("missing_t".to_owned()))
        );
    }

    #[test]
    fn invalid_regex_has_legacy_message_for_golden_case() {
        let policy = policy();
        let mut query = TeRuleQuery::new(&policy);
        assert_eq!(
            query.set_source("[", true, true),
            Err(QueryError::InvalidRegex(
                "unterminated character set at position 0".to_owned()
            ))
        );
    }
}
