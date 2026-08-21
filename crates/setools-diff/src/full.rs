//! Compatibility-oriented semantic components used by `sediff`.

use crate::{NameSetDifference, PolicyDiff, map_name_difference, set_difference};
use setools_policy::{
    ConditionalToken, ConstraintExpressionToken, ConstraintKind, ConstraintOperator,
    ConstraintRule, LabelingRule, MlsLevel, MlsRange, Policy, RbacRuleData, RbacRuleKind,
    SecurityContext, TeRuleData, TeRuleKind, TypeOrAttributeId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A modified compatibility item and its already canonical detail lines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifiedCompatibilityItem {
    summary: String,
    detail_lines: Vec<String>,
}

impl ModifiedCompatibilityItem {
    /// Returns the summary printed after the modification marker.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Returns canonical detail lines, including compatibility indentation.
    #[must_use]
    pub fn detail_lines(&self) -> &[String] {
        &self.detail_lines
    }
}

/// Added, removed, and modified canonical compatibility statements.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityDifference {
    added: Vec<String>,
    removed: Vec<String>,
    modified: Vec<ModifiedCompatibilityItem>,
}

impl CompatibilityDifference {
    /// Returns items present only in the right policy.
    #[must_use]
    pub fn added(&self) -> &[String] {
        &self.added
    }

    /// Returns items present only in the left policy.
    #[must_use]
    pub fn removed(&self) -> &[String] {
        &self.removed
    }

    /// Returns matched items whose semantic value differs.
    #[must_use]
    pub fn modified(&self) -> &[ModifiedCompatibilityItem] {
        &self.modified
    }

    /// Returns whether this component has no semantic changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypeValue {
    attributes: BTreeSet<String>,
    aliases: BTreeSet<String>,
    permissive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserValue {
    roles: BTreeSet<String>,
    level: String,
    range: String,
}

impl PolicyDiff<'_> {
    /// Compares common permission sets.
    #[must_use]
    pub fn commons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .commons()
                .iter()
                .map(|value| {
                    (
                        value.name().to_owned(),
                        value.permissions().iter().cloned().collect::<BTreeSet<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        permission_component(map(self.left()), map(self.right()))
    }

    /// Compares object classes using their complete inherited permission sets.
    #[must_use]
    pub fn classes(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .object_classes()
                .iter()
                .map(|value| {
                    (
                        value.name().to_owned(),
                        value
                            .permissions()
                            .iter()
                            .map(|permission| permission.name().to_owned())
                            .collect::<BTreeSet<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        permission_component(map(self.left()), map(self.right()))
    }

    /// Compares concrete types, attributes, aliases, and permissive state.
    #[must_use]
    pub fn types(&self) -> CompatibilityDifference {
        let left = type_map(self.left());
        let right = type_map(self.right());
        let names = map_name_difference(&left, &right);
        let mut modified = Vec::new();
        for (name, left_value) in &left {
            let Some(right_value) = right.get(name) else {
                continue;
            };
            let attributes = set_difference(
                left_value.attributes.iter().cloned(),
                right_value.attributes.iter().cloned(),
            );
            let aliases = set_difference(
                left_value.aliases.iter().cloned(),
                right_value.aliases.iter().cloned(),
            );
            let permissive = left_value.permissive != right_value.permissive;
            if attributes.is_empty() && aliases.is_empty() && !permissive {
                continue;
            }
            let mut changes = Vec::new();
            count_change(&mut changes, attributes.added(), "Added attributes");
            count_change(&mut changes, attributes.removed(), "Removed attributes");
            count_change(&mut changes, aliases.added(), "Added aliases");
            count_change(&mut changes, aliases.removed(), "Removed aliases");
            if permissive {
                changes.push(if right_value.permissive {
                    "Added permissive".to_owned()
                } else {
                    "Removed permissive".to_owned()
                });
            }
            let mut details = Vec::new();
            detail_group(
                &mut details,
                "Attributes",
                attributes.added(),
                attributes.removed(),
            );
            detail_group(&mut details, "Aliases", aliases.added(), aliases.removed());
            modified.push(ModifiedCompatibilityItem {
                summary: format!("{name} ({})", changes.join(",")),
                detail_lines: details,
            });
        }
        compatibility_from_names(names, modified)
    }

    /// Compares roles and their authorized concrete type sets.
    #[must_use]
    pub fn roles(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .roles()
                .iter()
                .map(|role| {
                    let types = role
                        .authorized_types()
                        .iter()
                        .filter_map(|id| policy.type_symbol(TypeOrAttributeId::Type(*id)))
                        .map(|value| value.name().to_owned())
                        .collect::<BTreeSet<_>>();
                    (role.name().to_owned(), types)
                })
                .collect::<BTreeMap<_, _>>()
        };
        named_set_component(map(self.left()), map(self.right()), "types", None)
    }

    /// Compares users, role sets, MLS default levels, and MLS ranges.
    #[must_use]
    pub fn users(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .users()
                .iter()
                .map(|user| {
                    let roles = user
                        .roles()
                        .iter()
                        .filter_map(|id| policy.role(*id))
                        .map(|role| role.name().to_owned())
                        .collect();
                    let level = user.default_level().map_or_else(
                        || "None (MLS Disabled)".to_owned(),
                        |value| render_level(policy, value),
                    );
                    let range = user.range().map_or_else(
                        || "None (MLS Disabled)".to_owned(),
                        |value| render_range(policy, value),
                    );
                    (
                        user.name().to_owned(),
                        UserValue {
                            roles,
                            level,
                            range,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let left = map(self.left());
        let right = map(self.right());
        let names = map_name_difference(&left, &right);
        let mut modified = Vec::new();
        for (name, left_value) in &left {
            let Some(right_value) = right.get(name) else {
                continue;
            };
            let roles = set_difference(
                left_value.roles.iter().cloned(),
                right_value.roles.iter().cloned(),
            );
            let level_changed = left_value.level != right_value.level;
            let range_changed = left_value.range != right_value.range;
            if roles.is_empty() && !level_changed && !range_changed {
                continue;
            }
            let mut changes = Vec::new();
            count_change(&mut changes, roles.added(), "Added roles");
            count_change(&mut changes, roles.removed(), "Removed roles");
            if level_changed {
                changes.push("Modified default level".to_owned());
            }
            if range_changed {
                changes.push("Modified range".to_owned());
            }
            let mut details = Vec::new();
            detail_group(&mut details, "Roles", roles.added(), roles.removed());
            if level_changed {
                details.push("          Default level:".to_owned());
                details.push(format!("          + {}", right_value.level));
                details.push(format!("          - {}", left_value.level));
            }
            if range_changed {
                details.push("          Range:".to_owned());
                details.push(format!("          + {}", right_value.range));
                details.push(format!("          - {}", left_value.range));
            }
            modified.push(ModifiedCompatibilityItem {
                summary: format!("{name} ({})", changes.join(", ")),
                detail_lines: details,
            });
        }
        compatibility_from_names(names, modified)
    }

    /// Compares sensitivity level declarations and their authorized categories.
    #[must_use]
    pub fn levels(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .sensitivities()
                .iter()
                .map(|sensitivity| {
                    let categories = sensitivity
                        .categories()
                        .iter()
                        .filter_map(|id| policy.category(*id))
                        .map(|category| category.name().to_owned())
                        .collect::<BTreeSet<_>>();
                    (sensitivity.name().to_owned(), categories)
                })
                .collect::<BTreeMap<_, _>>()
        };
        let left = map(self.left());
        let right = map(self.right());
        let names = map_name_difference(&left, &right);
        let added = names
            .added()
            .iter()
            .map(|name| render_level_declaration(name, &right[name]))
            .collect();
        let removed = names
            .removed()
            .iter()
            .map(|name| render_level_declaration(name, &left[name]))
            .collect();
        let mut modified = Vec::new();
        for (name, left_categories) in &left {
            let Some(right_categories) = right.get(name) else {
                continue;
            };
            let categories = set_difference(
                left_categories.iter().cloned(),
                right_categories.iter().cloned(),
            );
            if categories.is_empty() {
                continue;
            }
            let mut changes = Vec::new();
            count_change(&mut changes, categories.added(), "Added Categories");
            count_change(&mut changes, categories.removed(), "Removed Categories");
            let mut details = Vec::new();
            add_remove_lines(&mut details, categories.added(), categories.removed());
            modified.push(ModifiedCompatibilityItem {
                summary: format!("level {name} ({})", changes.join(", ")),
                detail_lines: details,
            });
        }
        CompatibilityDifference {
            added,
            removed,
            modified,
        }
    }

    /// Compares typebounds rules by canonical child and parent type names.
    #[must_use]
    pub fn typebounds(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .type_symbols()
                .iter()
                .filter(|symbol| !symbol.is_attribute())
                .filter_map(|symbol| {
                    symbol.bound().and_then(|bound| {
                        policy
                            .type_symbol(TypeOrAttributeId::Type(bound))
                            .map(|parent| (symbol.name().to_owned(), parent.name().to_owned()))
                    })
                })
                .collect::<BTreeMap<_, _>>()
        };
        let left = map(self.left());
        let right = map(self.right());
        let names = map_name_difference(&left, &right);
        let added = names
            .added()
            .iter()
            .map(|child| format!("typebounds {} {child};", right[child]))
            .collect();
        let removed = names
            .removed()
            .iter()
            .map(|child| format!("typebounds {} {child};", left[child]))
            .collect();
        let modified = left
            .iter()
            .filter_map(|(child, old)| {
                right.get(child).and_then(|new| {
                    (old != new).then(|| ModifiedCompatibilityItem {
                        summary: format!("typebounds +{new} -{old} {child};"),
                        detail_lines: Vec::new(),
                    })
                })
            })
            .collect();
        CompatibilityDifference {
            added,
            removed,
            modified,
        }
    }

    /// Compares default_* statements using kind and object class as identity.
    #[must_use]
    pub fn defaults(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .defaults()
                .iter()
                .filter_map(|rule| {
                    policy.object_class(rule.target_class()).map(|class| {
                        let key = (rule.kind().keyword().to_owned(), class.name().to_owned());
                        let value = (
                            rule.value().keyword().to_owned(),
                            rule.range_part().map(|part| part.keyword().to_owned()),
                        );
                        (key, value)
                    })
                })
                .collect::<BTreeMap<_, _>>()
        };
        let left = map(self.left());
        let right = map(self.right());
        keyed_value_difference(
            &left,
            &right,
            |(kind, class), (value, part)| {
                let suffix = part
                    .as_ref()
                    .map_or(String::new(), |part| format!(" {part}"));
                format!("{kind} {class} {value}{suffix};")
            },
            |(kind, class), old, new| {
                let mut values = if old.0 == new.0 {
                    new.0.clone()
                } else {
                    format!("+{} -{}", new.0, old.0)
                };
                match (&old.1, &new.1) {
                    (Some(old), Some(new)) if old == new => values.push_str(&format!(" {new}")),
                    (Some(old), Some(new)) if old != new => {
                        values.push_str(&format!(" +{new} -{old}"))
                    }
                    (None, Some(new)) => values.push_str(&format!(" +{new}")),
                    (Some(old), None) => values.push_str(&format!(" -{old}")),
                    _ => {}
                }
                format!("{kind} {class} {values};")
            },
        )
    }

    /// Compares one constraint family as canonical policy statements.
    #[must_use]
    pub fn constraints(&self, kind: ConstraintKind) -> CompatibilityDifference {
        let statements = |policy: &Policy| {
            policy
                .seinfo()
                .constraints()
                .iter()
                .filter(|rule| rule.kind() == kind)
                .map(|rule| render_constraint(policy, rule))
                .collect::<BTreeSet<_>>()
        };
        let left = statements(self.left());
        let right = statements(self.right());
        CompatibilityDifference {
            added: right.difference(&left).cloned().collect(),
            removed: left.difference(&right).cloned().collect(),
            modified: Vec::new(),
        }
    }
}

fn compatibility_from_names(
    names: NameSetDifference,
    modified: Vec<ModifiedCompatibilityItem>,
) -> CompatibilityDifference {
    CompatibilityDifference {
        added: names.added,
        removed: names.removed,
        modified,
    }
}

fn type_map(policy: &Policy) -> BTreeMap<String, TypeValue> {
    let mut attributes = BTreeMap::<String, BTreeSet<String>>::new();
    for attribute in policy
        .type_symbols()
        .iter()
        .filter(|symbol| symbol.is_attribute())
    {
        for member in attribute.expanded_types() {
            if let Some(symbol) = policy.type_symbol(TypeOrAttributeId::Type(*member)) {
                attributes
                    .entry(symbol.name().to_owned())
                    .or_default()
                    .insert(attribute.name().to_owned());
            }
        }
    }
    policy
        .type_symbols()
        .iter()
        .filter(|symbol| !symbol.is_attribute())
        .map(|symbol| {
            (
                symbol.name().to_owned(),
                TypeValue {
                    attributes: attributes.remove(symbol.name()).unwrap_or_default(),
                    aliases: symbol.aliases().iter().cloned().collect(),
                    permissive: symbol.is_permissive(),
                },
            )
        })
        .collect()
}

fn permission_component(
    left: BTreeMap<String, BTreeSet<String>>,
    right: BTreeMap<String, BTreeSet<String>>,
) -> CompatibilityDifference {
    named_set_component(left, right, "permissions", None)
}

fn named_set_component(
    left: BTreeMap<String, BTreeSet<String>>,
    right: BTreeMap<String, BTreeSet<String>>,
    noun: &str,
    group: Option<&str>,
) -> CompatibilityDifference {
    let names = map_name_difference(&left, &right);
    let mut modified = Vec::new();
    for (name, left_values) in &left {
        let Some(right_values) = right.get(name) else {
            continue;
        };
        let values = set_difference(left_values.iter().cloned(), right_values.iter().cloned());
        if values.is_empty() {
            continue;
        }
        let mut changes = Vec::new();
        count_change(&mut changes, values.added(), &format!("Added {noun}"));
        count_change(&mut changes, values.removed(), &format!("Removed {noun}"));
        let mut details = Vec::new();
        if let Some(group) = group {
            detail_group(&mut details, group, values.added(), values.removed());
        } else {
            add_remove_lines(&mut details, values.added(), values.removed());
        }
        modified.push(ModifiedCompatibilityItem {
            summary: format!("{name} ({})", changes.join(", ")),
            detail_lines: details,
        });
    }
    compatibility_from_names(names, modified)
}

fn count_change(changes: &mut Vec<String>, values: &[String], label: &str) {
    if !values.is_empty() {
        changes.push(format!("{} {label}", values.len()));
    }
}

fn detail_group(details: &mut Vec<String>, name: &str, added: &[String], removed: &[String]) {
    if added.is_empty() && removed.is_empty() {
        return;
    }
    details.push(format!("          {name}:"));
    add_remove_lines(details, added, removed);
}

fn add_remove_lines(details: &mut Vec<String>, added: &[String], removed: &[String]) {
    details.extend(added.iter().map(|value| format!("          + {value}")));
    details.extend(removed.iter().map(|value| format!("          - {value}")));
}

fn render_level_declaration(name: &str, categories: &BTreeSet<String>) -> String {
    if categories.is_empty() {
        name.to_owned()
    } else {
        let mut values = categories.iter().cloned().collect::<Vec<_>>();
        values.sort_unstable_by(|left, right| {
            numeric_suffix(left)
                .cmp(&numeric_suffix(right))
                .then_with(|| left.cmp(right))
        });
        format!("{name}:{}", compress_category_names(&values))
    }
}

fn compress_category_names(values: &[String]) -> String {
    let mut output = Vec::new();
    let mut start = 0;
    while start < values.len() {
        let mut end = start;
        while end + 1 < values.len() && consecutive_names(&values[end], &values[end + 1]) {
            end += 1;
        }
        if start == end {
            output.push(values[start].clone());
        } else {
            output.push(format!("{}.{}", values[start], values[end]));
        }
        start = end + 1;
    }
    output.join(",")
}

fn numeric_suffix(value: &str) -> Option<u64> {
    numeric_name(value).map(|(_, suffix)| suffix)
}

fn numeric_name(value: &str) -> Option<(&str, u64)> {
    let digits = value
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    if digits.is_empty() {
        None
    } else {
        digits
            .parse()
            .ok()
            .map(|suffix| (&value[..value.len() - digits.len()], suffix))
    }
}

fn consecutive_names(left: &str, right: &str) -> bool {
    matches!(
        (numeric_name(left), numeric_name(right)),
        (Some((left_prefix, left_value)), Some((right_prefix, right_value)))
            if left_prefix == right_prefix && left_value.checked_add(1) == Some(right_value)
    )
}

fn keyed_value_difference<Key, Value, Render, Modify>(
    left: &BTreeMap<Key, Value>,
    right: &BTreeMap<Key, Value>,
    render: Render,
    modify: Modify,
) -> CompatibilityDifference
where
    Key: Ord,
    Value: Eq,
    Render: Fn(&Key, &Value) -> String,
    Modify: Fn(&Key, &Value, &Value) -> String,
{
    let added = right
        .iter()
        .filter(|(key, _)| !left.contains_key(*key))
        .map(|(key, value)| render(key, value))
        .collect();
    let removed = left
        .iter()
        .filter(|(key, _)| !right.contains_key(*key))
        .map(|(key, value)| render(key, value))
        .collect();
    let modified = left
        .iter()
        .filter_map(|(key, old)| {
            right.get(key).and_then(|new| {
                (old != new).then(|| ModifiedCompatibilityItem {
                    summary: modify(key, old, new),
                    detail_lines: Vec::new(),
                })
            })
        })
        .collect();
    CompatibilityDifference {
        added,
        removed,
        modified,
    }
}

fn render_constraint(policy: &Policy, rule: &ConstraintRule) -> String {
    let class = policy
        .object_class(rule.target_class())
        .expect("loader validates constraint classes");
    let expression = render_constraint_expression(rule.expression());
    if rule.kind().is_validate_transition() {
        format!("{} {} ({expression});", rule.kind().keyword(), class.name())
    } else {
        let mut permissions = rule
            .permissions()
            .iter()
            .filter_map(|id| class.permission(*id))
            .map(|permission| permission.name())
            .collect::<Vec<_>>();
        permissions.sort_unstable();
        let permissions = match permissions.as_slice() {
            [permission] => (*permission).to_owned(),
            _ => format!("{{ {} }}", permissions.join(" ")),
        };
        format!(
            "{} {} {permissions} ({expression});",
            rule.kind().keyword(),
            class.name()
        )
    }
}

fn render_constraint_expression(tokens: &[ConstraintExpressionToken]) -> String {
    let mut stack: Vec<(u8, String)> = Vec::new();
    for token in tokens {
        match token {
            ConstraintExpressionToken::Operand(value) => stack.push((4, value.clone())),
            ConstraintExpressionToken::Names(values) => {
                let mut values = values.clone();
                values.sort_unstable();
                stack.push((
                    4,
                    if values.len() > 1 {
                        format!("{{ {} }}", values.join(" "))
                    } else {
                        values.join(" ")
                    },
                ));
            }
            ConstraintExpressionToken::Operator(operator) => {
                let precedence = operator.precedence();
                if *operator == ConstraintOperator::Not {
                    let Some((actual, value)) = stack.pop() else {
                        return "<invalid expression>".to_owned();
                    };
                    stack.push((
                        precedence,
                        format!("not {}", parenthesize(actual, precedence, value)),
                    ));
                } else {
                    let Some((right_actual, right)) = stack.pop() else {
                        return "<invalid expression>".to_owned();
                    };
                    let Some((left_actual, left)) = stack.pop() else {
                        return "<invalid expression>".to_owned();
                    };
                    stack.push((
                        precedence,
                        format!(
                            "{} {} {}",
                            parenthesize(left_actual, precedence, left),
                            operator.keyword(),
                            parenthesize(right_actual, precedence, right)
                        ),
                    ));
                }
            }
        }
    }
    stack
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(" ")
}

fn parenthesize(actual: u8, required: u8, value: String) -> String {
    if actual < required {
        format!("( {value} )")
    } else {
        value
    }
}

fn render_level(policy: &Policy, level: &MlsLevel) -> String {
    let sensitivity = policy
        .sensitivity(level.sensitivity())
        .expect("validated sensitivity");
    let mut value = sensitivity.name().to_owned();
    let names = level
        .categories()
        .iter()
        .filter_map(|id| policy.category(*id))
        .map(|category| category.name().to_owned())
        .collect::<Vec<_>>();
    if !names.is_empty() {
        value.push(':');
        value.push_str(&compress_category_names(&names));
    }
    value
}

fn render_range(policy: &Policy, range: &MlsRange) -> String {
    let low = render_level(policy, range.low());
    let high = render_level(policy, range.high());
    if low == high {
        low
    } else {
        format!("{low} - {high}")
    }
}

fn render_context(policy: &Policy, context: &SecurityContext) -> String {
    let user = &policy.seinfo().users()[context.user().as_raw() as usize];
    let role = &policy.roles()[context.role().as_raw() as usize];
    let target_type = policy
        .type_symbol(TypeOrAttributeId::Type(context.type_id()))
        .expect("validated context type");
    let mut value = format!("{}:{}:{}", user.name(), role.name(), target_type.name());
    if let Some(range) = context.range() {
        value.push(':');
        value.push_str(&render_range(policy, range));
    }
    value
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TeKey {
    source: String,
    target: String,
    target_class: String,
    condition: Option<(String, bool)>,
    filename: Option<String>,
    xperm_kind: Option<String>,
}

impl PolicyDiff<'_> {
    /// Compares one standard access-vector rule family after semantic expansion.
    #[must_use]
    pub fn av_rules(&self, kind: TeRuleKind) -> CompatibilityDifference {
        let left = av_rule_map(self.left(), kind);
        let right = av_rule_map(self.right(), kind);
        permission_rule_difference(kind.keyword(), &left, &right)
    }

    /// Compares one extended-permission access-vector rule family.
    #[must_use]
    pub fn xperm_rules(&self, kind: TeRuleKind) -> CompatibilityDifference {
        let left = xperm_rule_map(self.left(), kind);
        let right = xperm_rule_map(self.right(), kind);
        xpermission_rule_difference(kind.keyword(), &left, &right)
    }

    /// Compares one type_transition/type_change/type_member family.
    #[must_use]
    pub fn type_rules(&self, kind: TeRuleKind) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            let mut output = BTreeMap::new();
            for rule in policy.te_rules().iter().filter(|rule| rule.kind() == kind) {
                let TeRuleData::DefaultType { default, filename } = rule.data() else {
                    continue;
                };
                let Some(default) = policy.type_symbol(TypeOrAttributeId::Type(*default)) else {
                    continue;
                };
                let Some(class) = policy.object_class(rule.target_class()) else {
                    continue;
                };
                let condition = render_rule_condition(policy, rule.condition());
                for source in expanded_type_names(policy, rule.source()) {
                    for target in expanded_type_names(policy, rule.target()) {
                        output.insert(
                            TeKey {
                                source: source.clone(),
                                target,
                                target_class: class.name().to_owned(),
                                condition: condition.clone(),
                                filename: filename.clone(),
                                xperm_kind: None,
                            },
                            default.name().to_owned(),
                        );
                    }
                }
            }
            output
        };
        let left = map(self.left());
        let right = map(self.right());
        keyed_value_difference(
            &left,
            &right,
            |key, default| render_type_rule(kind.keyword(), key, default),
            |key, old, new| {
                let mut statement = format!(
                    "{} {} {}:{} +{new} -{old}",
                    kind.keyword(),
                    key.source,
                    key.target,
                    key.target_class
                );
                if let Some(filename) = &key.filename {
                    statement.push(' ');
                    statement.push_str(filename);
                }
                statement.push(';');
                statement.push_str(&render_condition_suffix(&key.condition));
                statement
            },
        )
    }

    /// Compares RBAC allow rules after role-attribute expansion.
    #[must_use]
    pub fn role_allows(&self) -> CompatibilityDifference {
        let statements = |policy: &Policy| {
            let mut values = BTreeSet::new();
            for rule in policy
                .rbac_rules()
                .iter()
                .filter(|rule| rule.kind() == RbacRuleKind::Allow)
            {
                let RbacRuleData::Allow { target } = rule.data() else {
                    continue;
                };
                for source in expanded_role_names(policy, rule.source()) {
                    for target in expanded_role_names(policy, *target) {
                        values.insert(format!("allow {source} {target};"));
                    }
                }
            }
            values
        };
        statement_set_difference(statements(self.left()), statements(self.right()))
    }

    /// Compares role_transition rules after role/type attribute expansion.
    #[must_use]
    pub fn role_transitions(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            let mut values = BTreeMap::new();
            for rule in policy
                .rbac_rules()
                .iter()
                .filter(|rule| rule.kind() == RbacRuleKind::RoleTransition)
            {
                let RbacRuleData::RoleTransition {
                    target,
                    target_class,
                    default,
                } = rule.data()
                else {
                    continue;
                };
                let Some(class) = policy.object_class(*target_class) else {
                    continue;
                };
                let Some(default) = policy.role(*default) else {
                    continue;
                };
                for source in expanded_role_names(policy, rule.source()) {
                    for target in expanded_type_names(policy, *target) {
                        values.insert(
                            (source.clone(), target, class.name().to_owned()),
                            default.name().to_owned(),
                        );
                    }
                }
            }
            values
        };
        let left = map(self.left());
        let right = map(self.right());
        keyed_value_difference(
            &left,
            &right,
            |(source, target, class), default| {
                format!("role_transition {source} {target}:{class} {default};")
            },
            |(source, target, class), old, new| {
                format!("role_transition {source} {target}:{class} +{new} -{old};")
            },
        )
    }

    /// Compares MLS range_transition rules after type-attribute expansion.
    #[must_use]
    pub fn range_transitions(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            let mut values = BTreeMap::new();
            for rule in policy.mls_rules() {
                let Some(class) = policy.object_class(rule.target_class()) else {
                    continue;
                };
                for source in expanded_type_names(policy, rule.source()) {
                    for target in expanded_type_names(policy, rule.target()) {
                        values.insert(
                            (source.clone(), target, class.name().to_owned()),
                            render_range(policy, rule.default()),
                        );
                    }
                }
            }
            values
        };
        let left = map(self.left());
        let right = map(self.right());
        keyed_value_difference(
            &left,
            &right,
            |(source, target, class), default| {
                format!("range_transition {source} {target}:{class} {default};")
            },
            |(source, target, class), old, new| {
                format!("range_transition {source} {target}:{class} +[{new}] -[{old}];")
            },
        )
    }
}

fn av_rule_map(policy: &Policy, kind: TeRuleKind) -> BTreeMap<TeKey, BTreeSet<String>> {
    let mut values = BTreeMap::<TeKey, BTreeSet<String>>::new();
    for rule in policy.te_rules().iter().filter(|rule| rule.kind() == kind) {
        let TeRuleData::Permissions(permissions) = rule.data() else {
            continue;
        };
        let Some(class) = policy.object_class(rule.target_class()) else {
            continue;
        };
        let permissions = permissions
            .iter()
            .filter_map(|id| class.permission(*id))
            .map(|permission| permission.name().to_owned())
            .collect::<BTreeSet<_>>();
        let condition = render_rule_condition(policy, rule.condition());
        for source in expanded_type_names(policy, rule.source()) {
            for target in expanded_type_names(policy, rule.target()) {
                values
                    .entry(TeKey {
                        source: source.clone(),
                        target,
                        target_class: class.name().to_owned(),
                        condition: condition.clone(),
                        filename: None,
                        xperm_kind: None,
                    })
                    .or_default()
                    .extend(permissions.iter().cloned());
            }
        }
    }

    let unconditional = values
        .iter()
        .filter(|(key, _)| key.condition.is_none())
        .map(|(key, permissions)| {
            (
                (
                    key.source.clone(),
                    key.target.clone(),
                    key.target_class.clone(),
                ),
                permissions.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (key, permissions) in &mut values {
        if key.condition.is_some()
            && let Some(granted) = unconditional.get(&(
                key.source.clone(),
                key.target.clone(),
                key.target_class.clone(),
            ))
        {
            permissions.retain(|permission| !granted.contains(permission));
        }
    }
    values.retain(|_, permissions| !permissions.is_empty());
    values
}

fn xperm_rule_map(policy: &Policy, kind: TeRuleKind) -> BTreeMap<TeKey, BTreeSet<u16>> {
    let mut output = BTreeMap::<TeKey, BTreeSet<u16>>::new();
    for rule in policy.te_rules().iter().filter(|rule| rule.kind() == kind) {
        let TeRuleData::ExtendedPermissions { kind, values } = rule.data() else {
            continue;
        };
        let Some(class) = policy.object_class(rule.target_class()) else {
            continue;
        };
        let condition = render_rule_condition(policy, rule.condition());
        for source in expanded_type_names(policy, rule.source()) {
            for target in expanded_type_names(policy, rule.target()) {
                output
                    .entry(TeKey {
                        source: source.clone(),
                        target,
                        target_class: class.name().to_owned(),
                        condition: condition.clone(),
                        filename: None,
                        xperm_kind: Some(kind.keyword().to_owned()),
                    })
                    .or_default()
                    .extend(values.iter().copied());
            }
        }
    }
    output
}

fn permission_rule_difference(
    keyword: &str,
    left: &BTreeMap<TeKey, BTreeSet<String>>,
    right: &BTreeMap<TeKey, BTreeSet<String>>,
) -> CompatibilityDifference {
    let added = right
        .iter()
        .filter(|(key, _)| !left.contains_key(*key))
        .map(|(key, permissions)| render_permission_rule(keyword, key, permissions))
        .collect::<Vec<_>>();
    let removed = left
        .iter()
        .filter(|(key, _)| !right.contains_key(*key))
        .map(|(key, permissions)| render_permission_rule(keyword, key, permissions))
        .collect::<Vec<_>>();
    let modified = left
        .iter()
        .filter_map(|(key, old)| {
            right.get(key).and_then(|new| {
                let matched = old.intersection(new).cloned().collect::<Vec<_>>();
                let added = new.difference(old).cloned().collect::<Vec<_>>();
                let removed = old.difference(new).cloned().collect::<Vec<_>>();
                if added.is_empty() && removed.is_empty() {
                    return None;
                }
                let mut permissions = matched;
                permissions.extend(added.into_iter().map(|value| format!("+{value}")));
                permissions.extend(removed.into_iter().map(|value| format!("-{value}")));
                Some(ModifiedCompatibilityItem {
                    summary: format!(
                        "{keyword} {} {}:{} {{ {} }};{}",
                        key.source,
                        key.target,
                        key.target_class,
                        permissions.join(" "),
                        render_condition_suffix(&key.condition)
                    ),
                    detail_lines: Vec::new(),
                })
            })
        })
        .collect();
    sorted_difference(CompatibilityDifference {
        added,
        removed,
        modified,
    })
}

fn xpermission_rule_difference(
    keyword: &str,
    left: &BTreeMap<TeKey, BTreeSet<u16>>,
    right: &BTreeMap<TeKey, BTreeSet<u16>>,
) -> CompatibilityDifference {
    let added = right
        .iter()
        .filter(|(key, _)| !left.contains_key(*key))
        .map(|(key, values)| render_xpermission_rule(keyword, key, values))
        .collect::<Vec<_>>();
    let removed = left
        .iter()
        .filter(|(key, _)| !right.contains_key(*key))
        .map(|(key, values)| render_xpermission_rule(keyword, key, values))
        .collect::<Vec<_>>();
    let modified = left
        .iter()
        .filter_map(|(key, old)| {
            right.get(key).and_then(|new| {
                let matched = old.intersection(new).copied().collect::<Vec<_>>();
                let added = new.difference(old).copied().collect::<Vec<_>>();
                let removed = old.difference(new).copied().collect::<Vec<_>>();
                if added.is_empty() && removed.is_empty() {
                    return None;
                }
                let mut permissions = xpermission_ranges(&matched);
                permissions.extend(
                    xpermission_ranges(&added)
                        .into_iter()
                        .map(|value| format!("+{value}")),
                );
                permissions.extend(
                    xpermission_ranges(&removed)
                        .into_iter()
                        .map(|value| format!("-{value}")),
                );
                Some(ModifiedCompatibilityItem {
                    summary: format!(
                        "{keyword} {} {}:{} {} {{ {} }};{}",
                        key.source,
                        key.target,
                        key.target_class,
                        key.xperm_kind.as_deref().unwrap_or("ioctl"),
                        permissions.join(" "),
                        render_condition_suffix(&key.condition)
                    ),
                    detail_lines: Vec::new(),
                })
            })
        })
        .collect();
    sorted_difference(CompatibilityDifference {
        added,
        removed,
        modified,
    })
}

fn render_permission_rule(keyword: &str, key: &TeKey, permissions: &BTreeSet<String>) -> String {
    let permissions = if permissions.len() == 1 {
        permissions.first().cloned().unwrap_or_default()
    } else {
        format!(
            "{{ {} }}",
            permissions.iter().cloned().collect::<Vec<_>>().join(" ")
        )
    };
    format!(
        "{keyword} {} {}:{} {permissions};{}",
        key.source,
        key.target,
        key.target_class,
        render_condition_suffix(&key.condition)
    )
}

fn render_xpermission_rule(keyword: &str, key: &TeKey, values: &BTreeSet<u16>) -> String {
    let ranges = xpermission_ranges(&values.iter().copied().collect::<Vec<_>>());
    let permissions = if ranges.len() == 1 {
        ranges[0].clone()
    } else {
        format!("{{ {} }}", ranges.join(" "))
    };
    format!(
        "{keyword} {} {}:{} {} {permissions};{}",
        key.source,
        key.target,
        key.target_class,
        key.xperm_kind.as_deref().unwrap_or("ioctl"),
        render_condition_suffix(&key.condition)
    )
}

fn render_type_rule(keyword: &str, key: &TeKey, default: &str) -> String {
    let filename = key
        .filename
        .as_ref()
        .map_or(String::new(), |value| format!(" {value}"));
    format!(
        "{keyword} {} {}:{} {default}{filename};{}",
        key.source,
        key.target,
        key.target_class,
        render_condition_suffix(&key.condition)
    )
}

fn expanded_type_names(policy: &Policy, id: TypeOrAttributeId) -> Vec<String> {
    let Some(symbol) = policy.type_symbol(id) else {
        return Vec::new();
    };
    if symbol.is_attribute() {
        symbol
            .expanded_types()
            .iter()
            .filter_map(|id| policy.type_symbol(TypeOrAttributeId::Type(*id)))
            .map(|value| value.name().to_owned())
            .collect()
    } else {
        vec![symbol.name().to_owned()]
    }
}

fn expanded_role_names(policy: &Policy, id: setools_policy::RoleId) -> Vec<String> {
    let Some(role) = policy.role(id) else {
        return Vec::new();
    };
    if role.expanded_roles().is_empty() {
        vec![role.name().to_owned()]
    } else {
        role.expanded_roles()
            .iter()
            .filter_map(|id| policy.role(*id))
            .map(|value| value.name().to_owned())
            .collect()
    }
}

fn render_rule_condition(
    policy: &Policy,
    condition: Option<setools_policy::RuleCondition>,
) -> Option<(String, bool)> {
    condition.and_then(|condition| {
        policy.conditional(condition.conditional()).map(|value| {
            (
                render_conditional(policy, value.tokens()),
                condition.block(),
            )
        })
    })
}

fn render_condition_suffix(condition: &Option<(String, bool)>) -> String {
    condition
        .as_ref()
        .map_or(String::new(), |(expression, block)| {
            format!(
                " [ {expression} ]:{}",
                if *block { "True" } else { "False" }
            )
        })
}

#[derive(Debug)]
struct ConditionalOperand {
    tokens: Vec<String>,
    compound: bool,
}

fn render_conditional(policy: &Policy, tokens: &[ConditionalToken]) -> String {
    let mut stack = Vec::<ConditionalOperand>::new();
    let mut previous_precedence = 5_u8;
    for token in tokens {
        if let ConditionalToken::Boolean(id) = token {
            if let Some(boolean) = policy.boolean(*id) {
                stack.push(ConditionalOperand {
                    tokens: vec![boolean.name().to_owned()],
                    compound: false,
                });
            }
            continue;
        }
        if *token == ConditionalToken::Not {
            let Some(operand) = stack.pop() else {
                return "<invalid expression>".to_owned();
            };
            let mut rendered = vec!["!".to_owned()];
            if operand.compound {
                rendered.push("(".to_owned());
                rendered.extend(operand.tokens);
                rendered.push(")".to_owned());
            } else {
                rendered.extend(operand.tokens);
            }
            stack.push(ConditionalOperand {
                tokens: rendered,
                compound: true,
            });
            previous_precedence = 5;
            continue;
        }
        let (operator, precedence) = match token {
            ConditionalToken::Or => ("||", 1),
            ConditionalToken::Xor => ("^", 2),
            ConditionalToken::And => ("&&", 3),
            ConditionalToken::Equal => ("==", 4),
            ConditionalToken::NotEqual => ("!=", 4),
            ConditionalToken::Boolean(_) | ConditionalToken::Not => unreachable!(),
        };
        let Some(first) = stack.pop() else {
            return "<invalid expression>".to_owned();
        };
        let Some(second) = stack.pop() else {
            return "<invalid expression>".to_owned();
        };
        let mut rendered = Vec::new();
        let parenthesized = previous_precedence <= precedence;
        if parenthesized {
            rendered.push("(".to_owned());
        }
        rendered.extend(first.tokens);
        rendered.push(operator.to_owned());
        rendered.extend(second.tokens);
        if parenthesized {
            rendered.push(")".to_owned());
        }
        stack.push(ConditionalOperand {
            tokens: rendered,
            compound: true,
        });
        previous_precedence = precedence;
    }
    if stack.len() == 1 {
        stack.pop().unwrap().tokens.join(" ")
    } else {
        "<invalid expression>".to_owned()
    }
}

fn xpermission_ranges(values: &[u16]) -> Vec<String> {
    let Some(&first) = values.first() else {
        return Vec::new();
    };
    let mut output = Vec::new();
    let mut low = first;
    let mut high = first;
    for &value in &values[1..] {
        if value == high.saturating_add(1) {
            high = value;
        } else {
            output.push(format_xpermission_range(low, high));
            low = value;
            high = value;
        }
    }
    output.push(format_xpermission_range(low, high));
    output
}

fn format_xpermission_range(low: u16, high: u16) -> String {
    if low == high {
        format!("{low:#06x}")
    } else {
        format!("{low:#06x}-{high:#06x}")
    }
}

fn statement_set_difference(
    left: BTreeSet<String>,
    right: BTreeSet<String>,
) -> CompatibilityDifference {
    CompatibilityDifference {
        added: right.difference(&left).cloned().collect(),
        removed: left.difference(&right).cloned().collect(),
        modified: Vec::new(),
    }
}

fn sorted_difference(mut value: CompatibilityDifference) -> CompatibilityDifference {
    value.added.sort_unstable();
    value.removed.sort_unstable();
    value
        .modified
        .sort_unstable_by(|left, right| left.summary.cmp(&right.summary));
    value
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextRecord {
    prefix: String,
    context: String,
    added_suffix: &'static str,
    modified_suffix: &'static str,
}

impl PolicyDiff<'_> {
    /// Compares initial SID declarations.
    #[must_use]
    pub fn initial_sids(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::InitialSid { name, context } => Some((
                        name.clone(),
                        ContextRecord {
                            prefix: format!("sid {name}"),
                            context: render_context(policy, context),
                            added_suffix: "",
                            modified_suffix: ";",
                        },
                    )),
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        context_record_difference(map(self.left()), map(self.right()))
    }

    /// Compares fs_use_* labeling rules.
    #[must_use]
    pub fn fs_uses(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::FsUse {
                        kind,
                        filesystem,
                        context,
                    } => {
                        let prefix = format!("{} {filesystem}", kind.keyword());
                        Some((
                            prefix.clone(),
                            ContextRecord {
                                prefix,
                                context: render_context(policy, context),
                                added_suffix: ";",
                                modified_suffix: ";",
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        context_record_difference(map(self.left()), map(self.right()))
    }

    /// Compares genfscon labeling rules.
    #[must_use]
    pub fn genfscons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::Genfscon {
                        filesystem,
                        path,
                        target_class,
                        context,
                    } => {
                        let filetype = target_class
                            .and_then(|id| policy.object_class(id))
                            .map_or("", |class| class_filetype(class.name()));
                        let key = format!("{filesystem}\0{path}\0{filetype}");
                        Some((
                            key,
                            ContextRecord {
                                prefix: format!("genfscon {filesystem} {path} {filetype}"),
                                context: render_context(policy, context),
                                added_suffix: "",
                                modified_suffix: ";",
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        context_record_difference(map(self.left()), map(self.right()))
    }

    /// Compares portcon labeling rules.
    #[must_use]
    pub fn portcons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::Portcon {
                        protocol,
                        low,
                        high,
                        context,
                    } => {
                        let prefix = format!(
                            "portcon {} {}",
                            protocol.keyword(),
                            decimal_range(*low, *high)
                        );
                        Some((
                            prefix.clone(),
                            ContextRecord {
                                prefix,
                                context: render_context(policy, context),
                                added_suffix: "",
                                modified_suffix: ";",
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        context_record_difference(map(self.left()), map(self.right()))
    }

    /// Compares nodecon labeling rules by normalized network and mask.
    #[must_use]
    pub fn nodecons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::Nodecon {
                        address,
                        mask,
                        context,
                    } => {
                        let prefix = format!(
                            "nodecon {} {mask}",
                            normalized_network_address(*address, *mask)
                        );
                        Some((
                            prefix.clone(),
                            ContextRecord {
                                prefix,
                                context: render_context(policy, context),
                                added_suffix: "",
                                modified_suffix: ";",
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        context_record_difference(map(self.left()), map(self.right()))
    }

    /// Compares InfiniBand partition-key labeling rules.
    #[must_use]
    pub fn ibpkeycons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::Ibpkeycon {
                        subnet_prefix,
                        low,
                        high,
                        context,
                    } => {
                        let key = format!("{subnet_prefix}\0{low}\0{high}");
                        Some((
                            key,
                            ContextRecord {
                                prefix: format!(
                                    "ibpkeycon {subnet_prefix} {}",
                                    compact_hex_range(*low, *high)
                                ),
                                context: render_context(policy, context),
                                added_suffix: "",
                                modified_suffix: "",
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        let mut result = context_record_difference(map(self.left()), map(self.right()));
        // Policy statements pad pkeys to four digits; modified summaries in
        // legacy sediff use Rust/Python-style compact hexadecimal.
        let restatement = |statement: &str| {
            let mut pieces = statement.splitn(4, ' ');
            let keyword = pieces.next().unwrap_or_default();
            let prefix = pieces.next().unwrap_or_default();
            let range = pieces.next().unwrap_or_default();
            let context = pieces.next().unwrap_or_default();
            let padded = range.split_once('-').map_or_else(
                || {
                    u16::from_str_radix(range.trim_start_matches("0x"), 16)
                        .map(|value| format!("{value:#06x}"))
                        .unwrap_or_else(|_| range.to_owned())
                },
                |(low, high)| {
                    let low =
                        u16::from_str_radix(low.trim_start_matches("0x"), 16).unwrap_or_default();
                    let high =
                        u16::from_str_radix(high.trim_start_matches("0x"), 16).unwrap_or_default();
                    format!("{low:#06x}-{high:#06x}")
                },
            );
            format!("{keyword} {prefix} {padded} {context}")
        };
        result.added = result
            .added
            .iter()
            .map(|value| restatement(value))
            .collect();
        result.removed = result
            .removed
            .iter()
            .map(|value| restatement(value))
            .collect();
        result
    }

    /// Compares InfiniBand end-port labeling rules.
    #[must_use]
    pub fn ibendportcons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::Ibendportcon {
                        device,
                        port,
                        context,
                    } => {
                        let prefix = format!("ibendportcon {device} {port}");
                        Some((
                            prefix.clone(),
                            ContextRecord {
                                prefix,
                                context: render_context(policy, context),
                                added_suffix: "",
                                modified_suffix: "",
                            },
                        ))
                    }
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        context_record_difference(map(self.left()), map(self.right()))
    }

    /// Compares netifcon interface and packet contexts independently.
    #[must_use]
    pub fn netifcons(&self) -> CompatibilityDifference {
        let map = |policy: &Policy| {
            policy
                .seinfo()
                .labeling_rules()
                .iter()
                .filter_map(|rule| match rule {
                    LabelingRule::Netifcon {
                        interface,
                        interface_context,
                        packet_context,
                    } => Some((
                        interface.clone(),
                        (
                            render_context(policy, interface_context),
                            render_context(policy, packet_context),
                        ),
                    )),
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>()
        };
        let left = map(self.left());
        let right = map(self.right());
        let names = map_name_difference(&left, &right);
        let added = names
            .added()
            .iter()
            .map(|name| format!("netifcon {name} {} {}", right[name].0, right[name].1))
            .collect();
        let removed = names
            .removed()
            .iter()
            .map(|name| format!("netifcon {name} {} {}", left[name].0, left[name].1))
            .collect();
        let mut modified = Vec::new();
        for (name, old) in &left {
            let Some(new) = right.get(name) else { continue };
            let context_changed = old.0 != new.0;
            let packet_changed = old.1 != new.1;
            if !context_changed && !packet_changed {
                continue;
            }
            let mut changes = Vec::new();
            if context_changed {
                changes.push("Modified Context");
            }
            if packet_changed {
                changes.push("Modified Packet Context");
            }
            let mut details = Vec::new();
            if context_changed {
                details.push("          Context:".to_owned());
                details.push(format!("             + {}", new.0));
                details.push(format!("             - {}", old.0));
            }
            if packet_changed {
                details.push("          Packet Context:".to_owned());
                details.push(format!("             + {}", new.1));
                details.push(format!("             - {}", old.1));
            }
            modified.push(ModifiedCompatibilityItem {
                summary: format!("netif {name} ({})", changes.join(", ")),
                detail_lines: details,
            });
        }
        CompatibilityDifference {
            added,
            removed,
            modified,
        }
    }
}

fn context_record_difference(
    left: BTreeMap<String, ContextRecord>,
    right: BTreeMap<String, ContextRecord>,
) -> CompatibilityDifference {
    let added = right
        .iter()
        .filter(|(key, _)| !left.contains_key(*key))
        .map(|(_, record)| {
            format!(
                "{} {}{}",
                record.prefix, record.context, record.added_suffix
            )
        })
        .collect();
    let removed = left
        .iter()
        .filter(|(key, _)| !right.contains_key(*key))
        .map(|(_, record)| {
            format!(
                "{} {}{}",
                record.prefix, record.context, record.added_suffix
            )
        })
        .collect();
    let modified = left
        .iter()
        .filter_map(|(key, old)| {
            right.get(key).and_then(|new| {
                (old.context != new.context).then(|| ModifiedCompatibilityItem {
                    summary: format!(
                        "{} +[{}] -[{}]{}",
                        old.prefix, new.context, old.context, old.modified_suffix
                    ),
                    detail_lines: Vec::new(),
                })
            })
        })
        .collect();
    sorted_difference(CompatibilityDifference {
        added,
        removed,
        modified,
    })
}

fn class_filetype(name: &str) -> &'static str {
    match name {
        "blk_file" => "-b",
        "chr_file" => "-c",
        "dir" => "-d",
        "fifo_file" => "-p",
        "file" => "--",
        "lnk_file" => "-l",
        "sock_file" => "-s",
        _ => "",
    }
}

fn decimal_range(low: u16, high: u16) -> String {
    if low == high {
        low.to_string()
    } else {
        format!("{low}-{high}")
    }
}

fn compact_hex_range(low: u16, high: u16) -> String {
    if low == high {
        format!("{low:#x}")
    } else {
        format!("{low:#x}-{high:#x}")
    }
}

fn normalized_network_address(address: IpAddr, mask: IpAddr) -> IpAddr {
    match (address, mask) {
        (IpAddr::V4(address), IpAddr::V4(mask)) => {
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & u32::from(mask)))
        }
        (IpAddr::V6(address), IpAddr::V6(mask)) => {
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & u128::from(mask)))
        }
        (address, _) => address,
    }
}
