//! Semantic comparison of two owned SELinux policies.
//!
//! Every public result is expressed with canonical names and semantic values.
//! Policy-local numeric IDs are resolved inside their owning policy and are
//! never compared across policies.

use setools_policy::{HandleUnknown, Policy, TypeOrAttributeId};
use std::collections::{BTreeMap, BTreeSet};

mod full;

pub use full::{CompatibilityDifference, ModifiedCompatibilityItem};

/// A lazily evaluated semantic policy comparison.
#[derive(Debug)]
pub struct PolicyDiff<'policy> {
    left: &'policy Policy,
    right: &'policy Policy,
}

/// A property value which can differ between two policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyValue {
    /// Unknown-class and unknown-permission handling.
    HandleUnknown(HandleUnknown),
    /// A Boolean policy property.
    Boolean(bool),
    /// The binary policy version.
    Version(u32),
}

/// One modified policy property.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropertyChange {
    property: &'static str,
    added: PropertyValue,
    removed: PropertyValue,
}

impl PropertyChange {
    /// Returns the compatibility property name.
    #[must_use]
    pub const fn property(&self) -> &'static str {
        self.property
    }

    /// Returns the value from the right policy.
    #[must_use]
    pub const fn added(&self) -> PropertyValue {
        self.added
    }

    /// Returns the value from the left policy.
    #[must_use]
    pub const fn removed(&self) -> PropertyValue {
        self.removed
    }
}

/// Added and removed canonical names for a set-like component.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NameSetDifference {
    added: Vec<String>,
    removed: Vec<String>,
}

impl NameSetDifference {
    /// Returns names present only in the right policy.
    #[must_use]
    pub fn added(&self) -> &[String] {
        &self.added
    }

    /// Returns names present only in the left policy.
    #[must_use]
    pub fn removed(&self) -> &[String] {
        &self.removed
    }

    /// Returns whether neither side has a unique name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Added, removed, and modified results for a named policy component.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComponentDifference<Modified> {
    names: NameSetDifference,
    modified: Vec<Modified>,
}

impl<Modified> ComponentDifference<Modified> {
    /// Returns names present only in the right policy.
    #[must_use]
    pub fn added(&self) -> &[String] {
        self.names.added()
    }

    /// Returns names present only in the left policy.
    #[must_use]
    pub fn removed(&self) -> &[String] {
        self.names.removed()
    }

    /// Returns matched names whose semantic value changed.
    #[must_use]
    pub fn modified(&self) -> &[Modified] {
        &self.modified
    }

    /// Returns whether the component is semantically equal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.modified.is_empty()
    }
}

/// A Boolean whose default state changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifiedBoolean {
    name: String,
    added_state: bool,
    removed_state: bool,
}

impl ModifiedBoolean {
    /// Returns the Boolean's canonical name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the default state from the right policy.
    #[must_use]
    pub const fn added_state(&self) -> bool {
        self.added_state
    }

    /// Returns the default state from the left policy.
    #[must_use]
    pub const fn removed_state(&self) -> bool {
        self.removed_state
    }
}

/// A category or sensitivity whose aliases changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifiedAliases {
    name: String,
    added_aliases: Vec<String>,
    removed_aliases: Vec<String>,
}

impl ModifiedAliases {
    /// Returns the canonical category or sensitivity name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns aliases present only in the right policy.
    #[must_use]
    pub fn added_aliases(&self) -> &[String] {
        &self.added_aliases
    }

    /// Returns aliases present only in the left policy.
    #[must_use]
    pub fn removed_aliases(&self) -> &[String] {
        &self.removed_aliases
    }
}

/// A type attribute whose concrete type expansion changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifiedTypeAttribute {
    name: String,
    added_types: Vec<String>,
    removed_types: Vec<String>,
}

impl ModifiedTypeAttribute {
    /// Returns the attribute's canonical name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns concrete types added to the attribute in the right policy.
    #[must_use]
    pub fn added_types(&self) -> &[String] {
        &self.added_types
    }

    /// Returns concrete types removed from the attribute in the right policy.
    #[must_use]
    pub fn removed_types(&self) -> &[String] {
        &self.removed_types
    }
}

impl<'policy> PolicyDiff<'policy> {
    /// Creates a comparison without computing any components.
    #[must_use]
    pub const fn new(left: &'policy Policy, right: &'policy Policy) -> Self {
        Self { left, right }
    }

    /// Returns the left policy.
    #[must_use]
    pub const fn left(&self) -> &'policy Policy {
        self.left
    }

    /// Returns the right policy.
    #[must_use]
    pub const fn right(&self) -> &'policy Policy {
        self.right
    }

    /// Compares policy metadata properties in compatibility order.
    #[must_use]
    pub fn properties(&self) -> Vec<PropertyChange> {
        let left = self.left.metadata();
        let right = self.right.metadata();
        let mut changes = Vec::new();
        if left.handle_unknown != right.handle_unknown {
            changes.push(PropertyChange {
                property: "handle_unknown",
                added: PropertyValue::HandleUnknown(right.handle_unknown),
                removed: PropertyValue::HandleUnknown(left.handle_unknown),
            });
        }
        if left.mls != right.mls {
            changes.push(PropertyChange {
                property: "MLS",
                added: PropertyValue::Boolean(right.mls),
                removed: PropertyValue::Boolean(left.mls),
            });
        }
        if left.version != right.version {
            changes.push(PropertyChange {
                property: "version",
                added: PropertyValue::Version(right.version),
                removed: PropertyValue::Version(left.version),
            });
        }
        changes.sort_unstable_by_key(PropertyChange::property);
        changes
    }

    /// Compares policy capability names.
    #[must_use]
    pub fn policy_capabilities(&self) -> NameSetDifference {
        set_difference(
            self.left.seinfo().policy_capabilities().iter().cloned(),
            self.right.seinfo().policy_capabilities().iter().cloned(),
        )
    }

    /// Compares Boolean names and default states.
    #[must_use]
    pub fn booleans(&self) -> ComponentDifference<ModifiedBoolean> {
        let left = self
            .left
            .booleans()
            .iter()
            .map(|value| (value.name().to_owned(), value.state()))
            .collect::<BTreeMap<_, _>>();
        let right = self
            .right
            .booleans()
            .iter()
            .map(|value| (value.name().to_owned(), value.state()))
            .collect::<BTreeMap<_, _>>();
        let names = map_name_difference(&left, &right);
        let modified = left
            .iter()
            .filter_map(|(name, removed_state)| {
                right.get(name).and_then(|added_state| {
                    (added_state != removed_state).then(|| ModifiedBoolean {
                        name: name.clone(),
                        added_state: *added_state,
                        removed_state: *removed_state,
                    })
                })
            })
            .collect();
        ComponentDifference { names, modified }
    }

    /// Compares type-attribute names and their concrete type expansions.
    #[must_use]
    pub fn type_attributes(&self) -> ComponentDifference<ModifiedTypeAttribute> {
        let left = attribute_map(self.left);
        let right = attribute_map(self.right);
        let names = map_name_difference(&left, &right);
        let modified = left
            .iter()
            .filter_map(|(name, left_types)| {
                right.get(name).and_then(|right_types| {
                    let difference =
                        set_difference(left_types.iter().cloned(), right_types.iter().cloned());
                    (!difference.is_empty()).then(|| ModifiedTypeAttribute {
                        name: name.clone(),
                        added_types: difference.added,
                        removed_types: difference.removed,
                    })
                })
            })
            .collect();
        ComponentDifference { names, modified }
    }

    /// Compares category names and aliases.
    #[must_use]
    pub fn categories(&self) -> ComponentDifference<ModifiedAliases> {
        let left = self
            .left
            .categories()
            .iter()
            .map(|value| (value.name().to_owned(), string_set(value.aliases())))
            .collect::<BTreeMap<_, _>>();
        let right = self
            .right
            .categories()
            .iter()
            .map(|value| (value.name().to_owned(), string_set(value.aliases())))
            .collect::<BTreeMap<_, _>>();
        alias_difference(&left, &right)
    }

    /// Compares sensitivity names and aliases.
    #[must_use]
    pub fn sensitivities(&self) -> ComponentDifference<ModifiedAliases> {
        let left = self
            .left
            .sensitivities()
            .iter()
            .map(|value| (value.name().to_owned(), string_set(value.aliases())))
            .collect::<BTreeMap<_, _>>();
        let right = self
            .right
            .sensitivities()
            .iter()
            .map(|value| (value.name().to_owned(), string_set(value.aliases())))
            .collect::<BTreeMap<_, _>>();
        alias_difference(&left, &right)
    }
}

fn string_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn set_difference(
    left: impl IntoIterator<Item = String>,
    right: impl IntoIterator<Item = String>,
) -> NameSetDifference {
    let left = left.into_iter().collect::<BTreeSet<_>>();
    let right = right.into_iter().collect::<BTreeSet<_>>();
    NameSetDifference {
        added: right.difference(&left).cloned().collect(),
        removed: left.difference(&right).cloned().collect(),
    }
}

fn map_name_difference<Value>(
    left: &BTreeMap<String, Value>,
    right: &BTreeMap<String, Value>,
) -> NameSetDifference {
    set_difference(left.keys().cloned(), right.keys().cloned())
}

fn alias_difference(
    left: &BTreeMap<String, BTreeSet<String>>,
    right: &BTreeMap<String, BTreeSet<String>>,
) -> ComponentDifference<ModifiedAliases> {
    let names = map_name_difference(left, right);
    let modified = left
        .iter()
        .filter_map(|(name, left_aliases)| {
            right.get(name).and_then(|right_aliases| {
                let difference =
                    set_difference(left_aliases.iter().cloned(), right_aliases.iter().cloned());
                (!difference.is_empty()).then(|| ModifiedAliases {
                    name: name.clone(),
                    added_aliases: difference.added,
                    removed_aliases: difference.removed,
                })
            })
        })
        .collect();
    ComponentDifference { names, modified }
}

fn attribute_map(policy: &Policy) -> BTreeMap<String, BTreeSet<String>> {
    policy
        .type_symbols()
        .iter()
        .filter(|symbol| symbol.is_attribute())
        .map(|attribute| {
            let members = attribute
                .expanded_types()
                .iter()
                .filter_map(|id| policy.type_symbol(TypeOrAttributeId::Type(*id)))
                .map(|member| member.name().to_owned())
                .collect();
            (attribute.name().to_owned(), members)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{PolicyDiff, PropertyValue};
    use setools_policy::{
        AttributeId, Boolean, BooleanId, Category, CategoryId, HandleUnknown, Policy,
        PolicyMetadata, SeinfoData, Sensitivity, SensitivityId, TargetPlatform, TypeId, TypeSymbol,
    };
    use std::path::PathBuf;

    fn policy(right: bool) -> Policy {
        let metadata = PolicyMetadata {
            version: if right { 35 } else { 33 },
            mls: right,
            target: TargetPlatform::Selinux,
            handle_unknown: if right {
                HandleUnknown::Allow
            } else {
                HandleUnknown::Reject
            },
        };
        let types = vec![
            TypeSymbol::new_type(TypeId::from_raw(0), "shared_type".to_owned()),
            TypeSymbol::new_type(TypeId::from_raw(1), "left_member".to_owned()),
            TypeSymbol::new_type(TypeId::from_raw(2), "right_member".to_owned()),
            TypeSymbol::new_attribute(
                AttributeId::from_raw(3),
                "changing_attr".to_owned(),
                if right {
                    vec![TypeId::from_raw(0), TypeId::from_raw(2)]
                } else {
                    vec![TypeId::from_raw(0), TypeId::from_raw(1)]
                },
            ),
            TypeSymbol::new_attribute(
                AttributeId::from_raw(4),
                if right {
                    "added_attr".to_owned()
                } else {
                    "removed_attr".to_owned()
                },
                Vec::new(),
            ),
        ];
        let booleans = vec![
            Boolean::new(BooleanId::from_raw(0), "same_bool".to_owned(), true),
            Boolean::new(
                BooleanId::from_raw(1),
                if right {
                    "added_bool".to_owned()
                } else {
                    "removed_bool".to_owned()
                },
                true,
            ),
            Boolean::new(BooleanId::from_raw(2), "modified_bool".to_owned(), right),
        ];
        let sensitivities = vec![
            Sensitivity::new(SensitivityId::from_raw(0), "s0".to_owned()).with_aliases(vec![
                "same_sens_alias".to_owned(),
                if right {
                    "added_sens_alias".to_owned()
                } else {
                    "removed_sens_alias".to_owned()
                },
            ]),
            Sensitivity::new(
                SensitivityId::from_raw(1),
                if right {
                    "added_sensitivity".to_owned()
                } else {
                    "removed_sensitivity".to_owned()
                },
            ),
        ];
        let categories = vec![
            Category::new(CategoryId::from_raw(0), "c0".to_owned()).with_aliases(vec![
                "same_category_alias".to_owned(),
                if right {
                    "added_category_alias".to_owned()
                } else {
                    "removed_category_alias".to_owned()
                },
            ]),
            Category::new(
                CategoryId::from_raw(1),
                if right {
                    "added_category".to_owned()
                } else {
                    "removed_category".to_owned()
                },
            ),
        ];
        let seinfo = SeinfoData::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![if right {
                "always_check_network".to_owned()
            } else {
                "network_peer_controls".to_owned()
            }],
            Vec::new(),
        );
        Policy::from_all_parts(
            PathBuf::from(if right { "right.policy" } else { "left.policy" }),
            metadata,
            types,
            Vec::new(),
            Vec::new(),
            booleans,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            sensitivities,
            categories,
            Vec::new(),
            seinfo,
        )
    }

    #[test]
    fn canonical_components_never_compare_policy_local_ids() {
        let left = policy(false);
        let right = policy(true);
        let diff = PolicyDiff::new(&left, &right);

        let properties = diff.properties();
        assert_eq!(properties.len(), 3);
        assert_eq!(properties[0].property(), "MLS");
        assert_eq!(properties[0].added(), PropertyValue::Boolean(true));
        assert_eq!(properties[1].property(), "handle_unknown");
        assert_eq!(properties[2].property(), "version");

        let polcaps = diff.policy_capabilities();
        assert_eq!(polcaps.added(), ["always_check_network"]);
        assert_eq!(polcaps.removed(), ["network_peer_controls"]);

        let booleans = diff.booleans();
        assert_eq!(booleans.added(), ["added_bool"]);
        assert_eq!(booleans.removed(), ["removed_bool"]);
        assert_eq!(booleans.modified()[0].name(), "modified_bool");
        assert!(booleans.modified()[0].added_state());
        assert!(!booleans.modified()[0].removed_state());

        let attributes = diff.type_attributes();
        assert_eq!(attributes.added(), ["added_attr"]);
        assert_eq!(attributes.removed(), ["removed_attr"]);
        assert_eq!(attributes.modified()[0].name(), "changing_attr");
        assert_eq!(attributes.modified()[0].added_types(), ["right_member"]);
        assert_eq!(attributes.modified()[0].removed_types(), ["left_member"]);

        let categories = diff.categories();
        assert_eq!(categories.added(), ["added_category"]);
        assert_eq!(categories.removed(), ["removed_category"]);
        assert_eq!(categories.modified()[0].name(), "c0");

        let sensitivities = diff.sensitivities();
        assert_eq!(sensitivities.added(), ["added_sensitivity"]);
        assert_eq!(sensitivities.removed(), ["removed_sensitivity"]);
        assert_eq!(sensitivities.modified()[0].name(), "s0");
    }
}
