//! Memory-safe parsing primitives for SELinux kernel binary policies.
//!
//! In addition to the validated parser-owned representation, this crate
//! provides [`PureRustPolicyLoader`], which reconstructs the complete shared
//! immutable [`Policy`] without C, FFI, or `unsafe`. The command-line tools
//! continue to use the libsepol-backed loader while fuzzing and whole-load
//! allocation hardening remain in progress.

use setools_policy::{
    AttributeId, Boolean, BooleanId, Category, CategoryId, ClassId, CommonPermissionSet,
    Conditional, ConditionalId, ConditionalToken, ConstraintExpressionToken, ConstraintKind,
    ConstraintOperator, ConstraintRule, DefaultRangePart, DefaultRule, DefaultRuleKind,
    DefaultValue, FsUseKind, HandleUnknown, LabelingRule, MlsLevel, MlsRange, MlsRule, ObjectClass,
    Permission, PermissionId, Policy, PolicyLoader, PolicyMetadata, PortProtocol, RbacRule,
    RbacRuleData, Role, RoleId, RuleCondition, SecurityContext, SeinfoData, Sensitivity,
    SensitivityId, TargetPlatform, TeRule, TeRuleData, TeRuleKind, TypeId, TypeOrAttributeId,
    TypeSymbol, User, UserId, XpermKind,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str;

/// Oldest kernel binary policy version understood by this parser slice.
pub const MIN_SUPPORTED_POLICY_VERSION: u32 = 15;
/// Newest kernel binary policy version understood by this parser slice.
pub const MAX_SUPPORTED_POLICY_VERSION: u32 = 35;

const POLICYDB_MAGIC: u32 = 0xf97c_ff8c;
const POLICYDB_MODULE_MAGIC: u32 = 0xf97c_ff8d;
const MAX_IDENTIFIER_LENGTH: usize = 32;
const MAX_HEADER_LENGTH: usize = 8 + MAX_IDENTIFIER_LENGTH + 16;
const CONFIG_MLS: u32 = 1;
const CONFIG_UNKNOWN_MASK: u32 = 6;
const BITMAP_MAP_SIZE: u32 = 64;
const PERMISSION_SYMBOL_LIMIT: u32 = 32;
const POLICY_VERSION_POLCAP: u32 = 22;
const POLICY_VERSION_PERMISSIVE: u32 = 23;
const POLICY_VERSION_NEVERAUDIT: u32 = 35;
const POLICY_VERSION_RANGE_TRANSITION_CLASS: u32 = 21;
const POLICY_VERSION_VALIDATETRANS: u32 = 19;
const POLICY_VERSION_MLS: u32 = 19;
const POLICY_VERSION_BOOL: u32 = 16;
const POLICY_VERSION_AVTAB: u32 = 20;
const POLICY_VERSION_FILENAME_TRANSITION: u32 = 25;
const POLICY_VERSION_ROLE_TRANSITION_CLASS: u32 = 26;
const POLICY_VERSION_XPERMS_IOCTL: u32 = 30;
const POLICY_VERSION_COMPRESSED_FILENAME_TRANSITION: u32 = 33;
const POLICY_VERSION_COND_XPERMS: u32 = 34;
const POLICY_VERSION_NEW_OBJECT_DEFAULTS: u32 = 27;
const POLICY_VERSION_DEFAULT_TYPE: u32 = 28;
const POLICY_VERSION_CONSTRAINT_NAMES: u32 = 29;
const POLICY_VERSION_BOUNDARY: u32 = 24;
const POLICY_VERSION_XEN_DEVICETREE: u32 = 30;
const CONSTRAINT_MAX_DEPTH: i32 = 5;
const CONSTRAINT_TYPE: u32 = 4;
const CONSTRAINT_XTARGET: u32 = 16;
const TYPE_PROPERTY_PRIMARY: u32 = 0x0001;
const TYPE_PROPERTY_ATTRIBUTE: u32 = 0x0002;
const KERNEL_TYPE_PROPERTY_MASK: u32 = TYPE_PROPERTY_PRIMARY | TYPE_PROPERTY_ATTRIBUTE;
const AVTAB_ALLOWED: u32 = 0x0001;
const AVTAB_AUDITALLOW: u32 = 0x0002;
const AVTAB_AUDITDENY: u32 = 0x0004;
const AVTAB_AV: u32 = AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY;
const AVTAB_TRANSITION: u32 = 0x0010;
const AVTAB_MEMBER: u32 = 0x0020;
const AVTAB_CHANGE: u32 = 0x0040;
const AVTAB_TYPE: u32 = AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE;
const AVTAB_XPERMS_ALLOWED: u32 = 0x0100;
const AVTAB_XPERMS_AUDITALLOW: u32 = 0x0200;
const AVTAB_XPERMS_DONTAUDIT: u32 = 0x0400;
const AVTAB_XPERMS: u32 = AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT;
const AVTAB_ENABLED_OLD: u32 = 0x8000_0000;
const AVTAB_ENABLED: u32 = 0x8000;
const AVTAB_XPERMS_IOCTLFUNCTION: u8 = 0x01;
const AVTAB_XPERMS_IOCTLDRIVER: u8 = 0x02;
const AVTAB_XPERMS_NLMSG: u8 = 0x03;
const CONDITIONAL_EXPRESSION_MAX_DEPTH: u32 = 10;

/// Resource limits applied while decoding the kernel policy.
///
/// The serialized-byte limit bounds the input buffer used by the file loader.
/// The allocation limit covers retained decoded vectors and strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimits {
    /// Maximum serialized bytes consumed by the complete parser.
    pub max_serialized_prefix_bytes: usize,
    /// Maximum nodes accepted in any extensible bitmap in the parsed slice.
    pub max_bitmap_nodes: u32,
    /// Maximum primary values or entries accepted in the common symbol table.
    pub max_common_symbols: u32,
    /// Maximum primary values or entries accepted in the object-class table.
    pub max_class_symbols: u32,
    /// Maximum primary values or entries accepted in the role table.
    pub max_role_symbols: u32,
    /// Maximum primary values or entries accepted in the type table.
    pub max_type_symbols: u32,
    /// Maximum primary values or entries accepted in the user table.
    pub max_user_symbols: u32,
    /// Maximum primary values or entries accepted in the Boolean table.
    pub max_boolean_symbols: u32,
    /// Maximum primary values or entries accepted in the sensitivity table.
    pub max_sensitivity_symbols: u32,
    /// Maximum primary values or entries accepted in the category table.
    pub max_category_symbols: u32,
    /// Maximum decoded unconditional plus conditional TE rules.
    pub max_te_rules: u32,
    /// Maximum conditional-expression nodes.
    pub max_conditionals: u32,
    /// Maximum postfix tokens accepted in one conditional expression.
    pub max_conditional_tokens: u32,
    /// Maximum decoded role-transition plus role-allow rules.
    pub max_rbac_rules: u32,
    /// Maximum serialized filename-transition records.
    pub max_filename_transition_records: u32,
    /// Maximum datum records accepted in one compressed filename transition.
    pub max_filename_transition_datums: u32,
    /// Maximum decoded filename-transition rules after bitmap expansion.
    pub max_filename_transitions: u32,
    /// Maximum decoded object-context records across all target families.
    pub max_object_contexts: u32,
    /// Maximum filesystem groups accepted in the genfs table.
    pub max_genfs_filesystems: u32,
    /// Maximum decoded genfs context records across all filesystem groups.
    pub max_genfs_contexts: u32,
    /// Maximum decoded MLS range-transition records.
    pub max_mls_range_transitions: u32,
    /// Maximum memberships retained while expanding trailing type-attribute maps.
    pub max_type_attribute_memberships: u32,
    /// Maximum permissions accepted in one common permission set.
    pub max_permissions_per_common: u32,
    /// Maximum total or local permissions accepted in one object class.
    pub max_permissions_per_class: u32,
    /// Maximum normal or validation constraints accepted in one object class.
    pub max_constraints_per_class: u32,
    /// Maximum postfix expressions accepted in one constraint record.
    pub max_constraint_expressions: u32,
    /// Maximum UTF-8 byte length of one symbol or filename component.
    pub max_string_bytes: usize,
    /// Maximum conservative logical allocation charge across parsing and reconstruction.
    pub max_total_allocation_bytes: usize,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_serialized_prefix_bytes: 16 * 1024 * 1024,
            max_bitmap_nodes: 262_144,
            max_common_symbols: 65_536,
            max_class_symbols: u32::from(u16::MAX),
            max_role_symbols: 65_536,
            max_type_symbols: 1_048_576,
            max_user_symbols: 65_536,
            max_boolean_symbols: 1_048_576,
            max_sensitivity_symbols: 65_536,
            max_category_symbols: 1_048_576,
            max_te_rules: 16_777_216,
            max_conditionals: 1_048_576,
            max_conditional_tokens: 4_096,
            max_rbac_rules: 4_194_304,
            max_filename_transition_records: 4_194_304,
            max_filename_transition_datums: 1_048_576,
            max_filename_transitions: 16_777_216,
            max_object_contexts: 4_194_304,
            max_genfs_filesystems: 1_048_576,
            max_genfs_contexts: 4_194_304,
            max_mls_range_transitions: 4_194_304,
            max_type_attribute_memberships: 16_777_216,
            max_permissions_per_common: PERMISSION_SYMBOL_LIMIT,
            max_permissions_per_class: PERMISSION_SYMBOL_LIMIT,
            max_constraints_per_class: 65_536,
            max_constraint_expressions: 4_096,
            max_string_bytes: 64 * 1024,
            max_total_allocation_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Decoded fixed header of a kernel binary policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryPolicyHeader {
    metadata: PolicyMetadata,
    symbol_table_count: u32,
    object_context_count: u32,
    encoded_len: usize,
}

impl BinaryPolicyHeader {
    /// Returns metadata in the shared owned-policy representation.
    #[must_use]
    pub const fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }

    /// Returns the number of serialized symbol-table families.
    #[must_use]
    pub const fn symbol_table_count(&self) -> u32 {
        self.symbol_table_count
    }

    /// Returns the number of serialized object-context families.
    #[must_use]
    pub const fn object_context_count(&self) -> u32 {
        self.object_context_count
    }

    /// Returns the byte offset immediately after the fixed header.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

/// One permission entry retained from the binary common symbol table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSymbol {
    name: String,
    value: u32,
}

impl PermissionSymbol {
    /// Returns the permission name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }
}

/// One common permission-set entry retained from the binary symbol table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonSymbol {
    name: String,
    value: u32,
    permissions: Vec<PermissionSymbol>,
}

impl CommonSymbol {
    /// Returns the common permission-set name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns permissions sorted by canonical name.
    #[must_use]
    pub fn permissions(&self) -> &[PermissionSymbol] {
        &self.permissions
    }
}

/// A type-set payload appended to version 29+ named type constraints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryTypeSet {
    types: Vec<u32>,
    negative_types: Vec<u32>,
    flags: u32,
}

impl BinaryTypeSet {
    /// Returns zero-based type or attribute indices in the positive set.
    #[must_use]
    pub fn types(&self) -> &[u32] {
        &self.types
    }

    /// Returns zero-based type or attribute indices in the negative set.
    #[must_use]
    pub fn negative_types(&self) -> &[u32] {
        &self.negative_types
    }

    /// Returns the serialized type-set flag (`0`, star, or complement).
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }
}

/// One postfix expression record from a binary class constraint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryConstraintExpression {
    /// Unary logical negation.
    Not,
    /// Binary logical conjunction.
    And,
    /// Binary logical disjunction.
    Or,
    /// Attribute-to-attribute comparison.
    Attribute {
        /// Serialized constraint attribute selector.
        attribute: u32,
        /// Comparison operator.
        operator: ConstraintOperator,
    },
    /// Attribute-to-named-symbol-set comparison.
    Names {
        /// Serialized constraint attribute selector.
        attribute: u32,
        /// Equality or inequality operator.
        operator: ConstraintOperator,
        /// Expanded zero-based symbol indices serialized in all versions.
        names: Vec<u32>,
        /// Source type-set representation serialized in version 29+ policies.
        type_names: Option<BinaryTypeSet>,
    },
}

impl BinaryConstraintExpression {
    /// Returns the symbol indices used by the existing owned-model loader.
    ///
    /// Version 29+ type constraints retain the source type set; other named
    /// expressions use the expanded bitmap.
    #[must_use]
    pub fn effective_names(&self) -> Option<&[u32]> {
        match self {
            Self::Names {
                attribute,
                names,
                type_names,
                ..
            } => {
                if attribute & CONSTRAINT_TYPE != 0 {
                    Some(
                        type_names
                            .as_ref()
                            .map_or(names.as_slice(), BinaryTypeSet::types),
                    )
                } else {
                    Some(names)
                }
            }
            _ => None,
        }
    }
}

/// One ordinary constraint or validation-transition record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryConstraint {
    permissions: u32,
    validate_transition: bool,
    expressions: Vec<BinaryConstraintExpression>,
}

impl BinaryConstraint {
    /// Returns the serialized access-vector permission mask.
    #[must_use]
    pub const fn permissions(&self) -> u32 {
        self.permissions
    }

    /// Returns whether this is a validation-transition constraint.
    #[must_use]
    pub const fn is_validate_transition(&self) -> bool {
        self.validate_transition
    }

    /// Returns whether any expression compares MLS levels.
    #[must_use]
    pub fn is_mls(&self) -> bool {
        self.expressions.iter().any(|expression| {
            matches!(
                expression,
                BinaryConstraintExpression::Attribute { attribute, .. } if *attribute >= 32
            )
        })
    }

    /// Returns the postfix expression records.
    #[must_use]
    pub fn expressions(&self) -> &[BinaryConstraintExpression] {
        &self.expressions
    }
}

/// Validated object-default values stored on one class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BinaryClassDefaults {
    user: Option<DefaultValue>,
    role: Option<DefaultValue>,
    object_type: Option<DefaultValue>,
    range: Option<(DefaultValue, Option<DefaultRangePart>)>,
}

impl BinaryClassDefaults {
    /// Returns the default user source.
    #[must_use]
    pub const fn user(&self) -> Option<DefaultValue> {
        self.user
    }

    /// Returns the default role source.
    #[must_use]
    pub const fn role(&self) -> Option<DefaultValue> {
        self.role
    }

    /// Returns the default type source.
    #[must_use]
    pub const fn object_type(&self) -> Option<DefaultValue> {
        self.object_type
    }

    /// Returns the default range source and selected range part.
    #[must_use]
    pub const fn range(&self) -> Option<(DefaultValue, Option<DefaultRangePart>)> {
        self.range
    }
}

/// One object-class entry retained from the second binary symbol family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassSymbol {
    name: String,
    value: u32,
    permission_count: u32,
    common: Option<String>,
    local_permissions: Vec<PermissionSymbol>,
    constraints: Vec<BinaryConstraint>,
    validation_constraints: Vec<BinaryConstraint>,
    defaults: BinaryClassDefaults,
}

/// One regular kernel-policy role symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleSymbol {
    name: String,
    value: u32,
    dominates: Vec<u32>,
    authorized_types: Vec<u32>,
    bound: Option<u32>,
}

impl RoleSymbol {
    /// Returns the role name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns zero-based indices from the serialized dominance bitmap.
    #[must_use]
    pub fn dominates(&self) -> &[u32] {
        &self.dominates
    }

    /// Returns zero-based type or attribute indices authorized for this role.
    #[must_use]
    pub fn authorized_types(&self) -> &[u32] {
        &self.authorized_types
    }

    /// Returns the one-based bound role value, when present.
    #[must_use]
    pub const fn bound(&self) -> Option<u32> {
        self.bound
    }
}

/// Kind of one primary kernel-policy type-table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryTypeKind {
    /// A concrete SELinux type.
    Type,
    /// A type attribute. Its member map is serialized at the end of the file.
    Attribute,
}

/// One primary kernel-policy type or type-attribute symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryTypeSymbol {
    name: String,
    value: u32,
    kind: BinaryTypeKind,
    aliases: Vec<String>,
    permissive: bool,
    bound: Option<u32>,
    expanded_types: Vec<u32>,
    attributes: Vec<u32>,
}

/// One expanded MLS level retained from the kernel policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryMlsLevel {
    sensitivity: u32,
    categories: Vec<u32>,
}

impl BinaryMlsLevel {
    /// Returns the one-based sensitivity value.
    #[must_use]
    pub const fn sensitivity(&self) -> u32 {
        self.sensitivity
    }

    /// Returns zero-based category indices in this level.
    #[must_use]
    pub fn categories(&self) -> &[u32] {
        &self.categories
    }
}

/// One inclusive expanded MLS range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryMlsRange {
    low: BinaryMlsLevel,
    high: BinaryMlsLevel,
}

impl BinaryMlsRange {
    /// Returns the low MLS level.
    #[must_use]
    pub const fn low(&self) -> &BinaryMlsLevel {
        &self.low
    }

    /// Returns the high MLS level.
    #[must_use]
    pub const fn high(&self) -> &BinaryMlsLevel {
        &self.high
    }
}

/// One MLS range transition retained from the binary policy tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryMlsRule {
    source: u32,
    target: u32,
    target_class: u32,
    default: BinaryMlsRange,
}

impl BinaryMlsRule {
    /// Returns the one-based source type or attribute value.
    #[must_use]
    pub const fn source(&self) -> u32 {
        self.source
    }

    /// Returns the one-based target type or attribute value.
    #[must_use]
    pub const fn target(&self) -> u32 {
        self.target
    }

    /// Returns the one-based target object-class value.
    #[must_use]
    pub const fn target_class(&self) -> u32 {
        self.target_class
    }

    /// Returns the range assigned by this transition.
    #[must_use]
    pub const fn default(&self) -> &BinaryMlsRange {
        &self.default
    }
}

/// One SELinux user symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSymbol {
    name: String,
    value: u32,
    roles: Vec<u32>,
    bound: Option<u32>,
    default_level: Option<BinaryMlsLevel>,
    range: Option<BinaryMlsRange>,
}

impl UserSymbol {
    /// Returns the user name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns zero-based authorized role indices, including implicit object_r.
    #[must_use]
    pub fn roles(&self) -> &[u32] {
        &self.roles
    }

    /// Returns the one-based bound user value, when present.
    #[must_use]
    pub const fn bound(&self) -> Option<u32> {
        self.bound
    }

    /// Returns the default MLS level when MLS is enabled.
    #[must_use]
    pub const fn default_level(&self) -> Option<&BinaryMlsLevel> {
        self.default_level.as_ref()
    }

    /// Returns the authorized MLS range when MLS is enabled.
    #[must_use]
    pub const fn range(&self) -> Option<&BinaryMlsRange> {
        self.range.as_ref()
    }
}

/// One policy Boolean symbol and its default state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryBooleanSymbol {
    name: String,
    value: u32,
    state: bool,
}

impl BinaryBooleanSymbol {
    /// Returns the Boolean name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns the default Boolean state.
    #[must_use]
    pub const fn state(&self) -> bool {
        self.state
    }
}

/// One canonical MLS sensitivity and its aliases/category declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitivitySymbol {
    name: String,
    value: u32,
    aliases: Vec<String>,
    categories: Vec<u32>,
}

impl SensitivitySymbol {
    /// Returns the canonical sensitivity name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based sensitivity value.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns aliases in serialized symbol-table order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    /// Returns zero-based categories authorized by this sensitivity.
    #[must_use]
    pub fn categories(&self) -> &[u32] {
        &self.categories
    }
}

/// One canonical MLS category and its aliases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategorySymbol {
    name: String,
    value: u32,
    aliases: Vec<String>,
}

impl CategorySymbol {
    /// Returns the canonical category name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based category value.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns aliases in serialized symbol-table order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

/// Rule-kind-specific payload decoded from an access-vector table record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryTeRuleData {
    /// Zero-based permission indices valid for the target class.
    Permissions(Vec<u32>),
    /// Expanded 16-bit extended-permission values.
    ExtendedPermissions {
        /// Extended-permission namespace.
        kind: XpermKind,
        /// Sorted individual values.
        values: Vec<u16>,
    },
    /// One-based concrete default type value.
    DefaultType(u32),
}

/// One type-enforcement rule decoded from an access-vector table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryTeRule {
    kind: TeRuleKind,
    source: u32,
    target: u32,
    target_class: u32,
    data: BinaryTeRuleData,
}

impl BinaryTeRule {
    /// Returns the normalized rule kind.
    #[must_use]
    pub const fn kind(&self) -> TeRuleKind {
        self.kind
    }

    /// Returns the one-based source type or attribute value.
    #[must_use]
    pub const fn source(&self) -> u32 {
        self.source
    }

    /// Returns the one-based target type or attribute value.
    #[must_use]
    pub const fn target(&self) -> u32 {
        self.target
    }

    /// Returns the one-based target object-class value.
    #[must_use]
    pub const fn target_class(&self) -> u32 {
        self.target_class
    }

    /// Returns the rule-kind-specific payload.
    #[must_use]
    pub const fn data(&self) -> &BinaryTeRuleData {
        &self.data
    }
}

/// One Boolean conditional and its true/false access-vector rule lists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryConditional {
    current_state: bool,
    tokens: Vec<ConditionalToken>,
    true_rules: Vec<BinaryTeRule>,
    false_rules: Vec<BinaryTeRule>,
}

impl BinaryConditional {
    /// Returns the state serialized after evaluating default Boolean values.
    #[must_use]
    pub const fn current_state(&self) -> bool {
        self.current_state
    }

    /// Returns the validated postfix expression.
    #[must_use]
    pub fn tokens(&self) -> &[ConditionalToken] {
        &self.tokens
    }

    /// Returns rules from the expression's true block.
    #[must_use]
    pub fn true_rules(&self) -> &[BinaryTeRule] {
        &self.true_rules
    }

    /// Returns rules from the expression's false block.
    #[must_use]
    pub fn false_rules(&self) -> &[BinaryTeRule] {
        &self.false_rules
    }
}

/// Kind-specific payload decoded from the kernel RBAC rule lists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryRbacRuleData {
    /// Target role of a role-allow rule.
    Allow {
        /// One-based role value which may be entered.
        target: u32,
    },
    /// Target type/class and default role of a role transition.
    RoleTransition {
        /// One-based target type or attribute value.
        target: u32,
        /// One-based object-class value.
        target_class: u32,
        /// One-based default role value.
        default: u32,
    },
}

/// One role-allow or role-transition rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryRbacRule {
    source: u32,
    data: BinaryRbacRuleData,
}

impl BinaryRbacRule {
    /// Returns the one-based source role value.
    #[must_use]
    pub const fn source(&self) -> u32 {
        self.source
    }

    /// Returns the kind-specific RBAC payload.
    #[must_use]
    pub const fn data(&self) -> &BinaryRbacRuleData {
        &self.data
    }
}

/// One expanded filename type-transition rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryFilenameTransition {
    source: u32,
    target: u32,
    target_class: u32,
    default_type: u32,
    filename: String,
}

impl BinaryFilenameTransition {
    /// Returns the one-based source type or attribute value.
    #[must_use]
    pub const fn source(&self) -> u32 {
        self.source
    }

    /// Returns the one-based target type or attribute value.
    #[must_use]
    pub const fn target(&self) -> u32 {
        self.target
    }

    /// Returns the one-based target object-class value.
    #[must_use]
    pub const fn target_class(&self) -> u32 {
        self.target_class
    }

    /// Returns the one-based concrete default type value.
    #[must_use]
    pub const fn default_type(&self) -> u32 {
        self.default_type
    }

    /// Returns the final path component matched by the transition.
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }
}

/// One fully expanded security context from an object-labeling record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinarySecurityContext {
    user: u32,
    role: u32,
    type_id: u32,
    range: Option<BinaryMlsRange>,
}

impl BinarySecurityContext {
    /// Returns the one-based user value.
    #[must_use]
    pub const fn user(&self) -> u32 {
        self.user
    }

    /// Returns the one-based role value.
    #[must_use]
    pub const fn role(&self) -> u32 {
        self.role
    }

    /// Returns the one-based concrete type value.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        self.type_id
    }

    /// Returns the expanded MLS range when MLS is enabled.
    #[must_use]
    pub const fn range(&self) -> Option<&BinaryMlsRange> {
        self.range.as_ref()
    }
}

/// One SELinux or Xen object-labeling record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinaryLabelingRule {
    /// A target-specific initial security identifier.
    InitialSid {
        /// Numeric initial SID serialized by the kernel policy format.
        sid: u32,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Legacy filesystem pair containing filesystem and root contexts.
    FsContext {
        /// Filesystem name.
        filesystem: String,
        /// Filesystem context.
        filesystem_context: BinarySecurityContext,
        /// Root inode context.
        root_context: BinarySecurityContext,
    },
    /// SELinux network-port labeling record.
    Portcon {
        /// IP protocol number.
        protocol: u32,
        /// Inclusive low port.
        low: u16,
        /// Inclusive high port.
        high: u16,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// SELinux network-interface labeling record.
    Netifcon {
        /// Interface name.
        interface: String,
        /// Interface object context.
        interface_context: BinarySecurityContext,
        /// Packet context.
        packet_context: BinarySecurityContext,
    },
    /// SELinux IPv4 or IPv6 node labeling record.
    Nodecon {
        /// Network address in serialized network byte order.
        address: IpAddr,
        /// Network mask in serialized network byte order.
        mask: IpAddr,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// SELinux filesystem-labeling behavior record.
    FsUse {
        /// Serialized filesystem-use behavior: xattr, transition, or task.
        behavior: u32,
        /// Filesystem name.
        filesystem: String,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// SELinux InfiniBand partition-key labeling record.
    Ibpkeycon {
        /// IPv6 subnet prefix; the low 64 bits are zero in this format.
        subnet_prefix: Ipv6Addr,
        /// Inclusive low partition key.
        low: u16,
        /// Inclusive high partition key.
        high: u16,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// SELinux InfiniBand end-port labeling record.
    Ibendportcon {
        /// InfiniBand device name.
        device: String,
        /// One-based device port.
        port: u8,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Xen physical-interrupt labeling record.
    Pirqcon {
        /// Physical interrupt number.
        irq: u16,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Xen I/O-port labeling record.
    Ioportcon {
        /// Inclusive low I/O port.
        low: u32,
        /// Inclusive high I/O port.
        high: u32,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Xen I/O-memory labeling record.
    Iomemcon {
        /// Inclusive low machine-frame number.
        low: u64,
        /// Inclusive high machine-frame number.
        high: u64,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Xen PCI-device labeling record.
    Pcidevicecon {
        /// Packed PCI device identifier.
        device: u32,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Xen device-tree path labeling record.
    Devicetreecon {
        /// Device-tree path.
        path: String,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
    /// Filesystem/path labeling record shared by the trailing genfs table.
    Genfscon {
        /// Filesystem type.
        filesystem: String,
        /// Path within the filesystem.
        path: String,
        /// Optional one-based object-class value.
        target_class: Option<u32>,
        /// Assigned security context.
        context: BinarySecurityContext,
    },
}

impl BinaryTypeSymbol {
    /// Returns the canonical symbol name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns whether this primary entry is a concrete type or an attribute.
    #[must_use]
    pub const fn kind(&self) -> BinaryTypeKind {
        self.kind
    }

    /// Returns aliases in serialized symbol-table order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    /// Returns whether this concrete type occurs in the leading permissive map.
    #[must_use]
    pub const fn is_permissive(&self) -> bool {
        self.permissive
    }

    /// Returns the one-based bound type value, when present.
    #[must_use]
    pub const fn bound(&self) -> Option<u32> {
        self.bound
    }

    /// Returns zero-based concrete type indices used for indirect matching.
    ///
    /// A concrete type expands to itself. An attribute expands to the concrete
    /// members reconstructed from the trailing `type_attr_map` bitmaps.
    #[must_use]
    pub fn expanded_types(&self) -> &[u32] {
        &self.expanded_types
    }

    /// Returns zero-based attribute indices containing this symbol.
    ///
    /// This also preserves unnamed attribute values used by kernel policy
    /// versions 20 through 23.
    #[must_use]
    pub fn attributes(&self) -> &[u32] {
        &self.attributes
    }
}

impl ClassSymbol {
    /// Returns the object-class name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the one-based class value serialized in the policy.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Returns the total inherited plus local permission bit width.
    #[must_use]
    pub const fn permission_count(&self) -> u32 {
        self.permission_count
    }

    /// Returns the inherited common permission-set name.
    #[must_use]
    pub fn common(&self) -> Option<&str> {
        self.common.as_deref()
    }

    /// Returns class-local permissions sorted by canonical name.
    #[must_use]
    pub fn local_permissions(&self) -> &[PermissionSymbol] {
        &self.local_permissions
    }

    /// Returns ordinary constraints in serialized order.
    #[must_use]
    pub fn constraints(&self) -> &[BinaryConstraint] {
        &self.constraints
    }

    /// Returns validation-transition constraints in serialized order.
    #[must_use]
    pub fn validation_constraints(&self) -> &[BinaryConstraint] {
        &self.validation_constraints
    }

    /// Returns validated default values for this class.
    #[must_use]
    pub const fn defaults(&self) -> &BinaryClassDefaults {
        &self.defaults
    }
}

/// Decoded kernel policy body retained by the pure Rust parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryPolicyPrefix {
    header: BinaryPolicyHeader,
    policy_capabilities: Vec<u32>,
    commons: Vec<CommonSymbol>,
    classes: Vec<ClassSymbol>,
    roles: Vec<RoleSymbol>,
    types: Vec<BinaryTypeSymbol>,
    type_primary_count: u32,
    users: Vec<UserSymbol>,
    booleans: Vec<BinaryBooleanSymbol>,
    sensitivities: Vec<SensitivitySymbol>,
    categories: Vec<CategorySymbol>,
    te_rules: Vec<BinaryTeRule>,
    conditionals: Vec<BinaryConditional>,
    rbac_rules: Vec<BinaryRbacRule>,
    filename_transitions: Vec<BinaryFilenameTransition>,
    labeling_rules: Vec<BinaryLabelingRule>,
    mls_rules: Vec<BinaryMlsRule>,
    encoded_len: usize,
    retained_allocation_bytes: usize,
    allocation_limit: usize,
}

impl BinaryPolicyPrefix {
    /// Returns the validated fixed header.
    #[must_use]
    pub const fn header(&self) -> &BinaryPolicyHeader {
        &self.header
    }

    /// Returns zero-based policy-capability numbers in numeric order.
    #[must_use]
    pub fn policy_capabilities(&self) -> &[u32] {
        &self.policy_capabilities
    }

    /// Returns common permission sets sorted by canonical name.
    #[must_use]
    pub fn commons(&self) -> &[CommonSymbol] {
        &self.commons
    }

    /// Returns object classes in one-based numeric value order.
    #[must_use]
    pub fn classes(&self) -> &[ClassSymbol] {
        &self.classes
    }

    /// Returns roles in one-based numeric value order.
    #[must_use]
    pub fn roles(&self) -> &[RoleSymbol] {
        &self.roles
    }

    /// Returns primary type and attribute entries in one-based value order.
    ///
    /// For kernel policy versions 20 through 23, unnamed attributes exist only
    /// in the trailing type-attribute map, so this slice can contain fewer
    /// entries than [`Self::type_primary_count`].
    #[must_use]
    pub fn types(&self) -> &[BinaryTypeSymbol] {
        &self.types
    }

    /// Returns the type table's declared primary-value count.
    #[must_use]
    pub const fn type_primary_count(&self) -> u32 {
        self.type_primary_count
    }

    /// Returns users in one-based numeric value order.
    #[must_use]
    pub fn users(&self) -> &[UserSymbol] {
        &self.users
    }

    /// Returns Booleans in one-based numeric value order.
    #[must_use]
    pub fn booleans(&self) -> &[BinaryBooleanSymbol] {
        &self.booleans
    }

    /// Returns canonical sensitivities in one-based numeric value order.
    #[must_use]
    pub fn sensitivities(&self) -> &[SensitivitySymbol] {
        &self.sensitivities
    }

    /// Returns canonical categories in one-based numeric value order.
    #[must_use]
    pub fn categories(&self) -> &[CategorySymbol] {
        &self.categories
    }

    /// Returns unconditional type-enforcement rules in serialized order.
    #[must_use]
    pub fn te_rules(&self) -> &[BinaryTeRule] {
        &self.te_rules
    }

    /// Returns conditional expressions and their branch rules in policy order.
    #[must_use]
    pub fn conditionals(&self) -> &[BinaryConditional] {
        &self.conditionals
    }

    /// Returns role transitions followed by role-allow rules.
    #[must_use]
    pub fn rbac_rules(&self) -> &[BinaryRbacRule] {
        &self.rbac_rules
    }

    /// Returns expanded filename transitions in canonical order.
    #[must_use]
    pub fn filename_transitions(&self) -> &[BinaryFilenameTransition] {
        &self.filename_transitions
    }

    /// Returns SELinux/Xen object contexts followed by trailing genfs records.
    #[must_use]
    pub fn labeling_rules(&self) -> &[BinaryLabelingRule] {
        &self.labeling_rules
    }

    /// Returns MLS range transitions in serialized order.
    #[must_use]
    pub fn mls_rules(&self) -> &[BinaryMlsRule] {
        &self.mls_rules
    }

    /// Returns the byte offset immediately after all decoded kernel-policy data.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Returns the parser-owned allocation charged while decoding this policy.
    #[must_use]
    pub const fn retained_allocation_bytes(&self) -> usize {
        self.retained_allocation_bytes
    }

    /// Estimates the conservative peak logical allocation charge during conversion.
    ///
    /// The estimate includes the parser-owned representation, the complete
    /// shared policy, its name indexes, and nested strings and vectors.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::LimitExceeded`] if the estimate overflows `usize`.
    pub fn estimated_peak_allocation_bytes(&self, source: &Path) -> Result<usize, ParseError> {
        let mut budget = AllocationBudget::with_used(usize::MAX, self.retained_allocation_bytes)?;
        charge_owned_policy_allocation(self, source, &mut budget)?;
        Ok(budget.used)
    }

    /// Reconstructs the shared immutable policy model without native code.
    ///
    /// The parser has already validated every numeric reference used during
    /// this conversion. Kernel versions 20 through 23 receive the same
    /// synthetic names for unnamed attributes as the libsepol-backed loader.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::LimitExceeded`] when the parsed representation
    /// and complete owned model exceed the loader's allocation budget.
    pub fn to_policy(&self, source: PathBuf) -> Result<Policy, ParseError> {
        build_owned_policy(self, source)
    }
}

/// Returns the canonical name of a supported policy-capability number.
#[must_use]
pub const fn policy_capability_name(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("network_peer_controls"),
        1 => Some("open_perms"),
        2 => Some("extended_socket_class"),
        3 => Some("always_check_network"),
        4 => Some("cgroup_seclabel"),
        5 => Some("nnp_nosuid_transition"),
        6 => Some("genfs_seclabel_symlinks"),
        7 => Some("ioctl_skip_cloexec"),
        8 => Some("userspace_initial_context"),
        9 => Some("netlink_xperm"),
        10 => Some("netif_wildcard"),
        11 => Some("genfs_seclabel_wildcard"),
        12 => Some("functionfs_seclabel"),
        13 => Some("memfd_class"),
        14 => Some("bpf_token_perms"),
        _ => None,
    }
}

const OWNED_ALLOCATION_RESOURCE: &str = "owned policy reconstruction";
const OWNED_BTREE_BASE_BYTES: usize = 1024;
const OWNED_BTREE_ENTRY_OVERHEAD_BYTES: usize = size_of::<[usize; 8]>();
const IMPLICIT_ATTRIBUTE_NAME_BYTES: usize = 14;

fn charge_owned_items<T>(budget: &mut AllocationBudget, count: usize) -> Result<(), ParseError> {
    let bytes = count
        .checked_mul(size_of::<T>())
        .ok_or(ParseError::LimitExceeded {
            resource: OWNED_ALLOCATION_RESOURCE,
            requested: u64::MAX,
            limit: usize_to_u64(budget.limit),
        })?;
    budget.charge(bytes, OWNED_ALLOCATION_RESOURCE)
}

fn charge_owned_string_bytes(
    budget: &mut AllocationBudget,
    length: usize,
) -> Result<(), ParseError> {
    budget.charge(length, OWNED_ALLOCATION_RESOURCE)
}

fn charge_owned_strings(
    budget: &mut AllocationBudget,
    strings: &[String],
) -> Result<(), ParseError> {
    charge_owned_items::<String>(budget, strings.len())?;
    for value in strings {
        charge_owned_string_bytes(budget, value.len())?;
    }
    Ok(())
}

fn charge_name_index_base(
    budget: &mut AllocationBudget,
    populated: bool,
) -> Result<(), ParseError> {
    if populated {
        budget.charge(OWNED_BTREE_BASE_BYTES, OWNED_ALLOCATION_RESOURCE)?;
    }
    Ok(())
}

fn charge_name_index_entry<Id>(
    budget: &mut AllocationBudget,
    name_length: usize,
) -> Result<(), ParseError> {
    charge_owned_items::<(String, Id)>(budget, 1)?;
    budget.charge(OWNED_BTREE_ENTRY_OVERHEAD_BYTES, OWNED_ALLOCATION_RESOURCE)?;
    charge_owned_string_bytes(budget, name_length)
}

fn charge_owned_mls_level(
    budget: &mut AllocationBudget,
    level: &BinaryMlsLevel,
) -> Result<(), ParseError> {
    charge_owned_items::<CategoryId>(budget, level.categories.len())
}

fn charge_owned_mls_range(
    budget: &mut AllocationBudget,
    range: &BinaryMlsRange,
) -> Result<(), ParseError> {
    charge_owned_mls_level(budget, &range.low)?;
    charge_owned_mls_level(budget, &range.high)
}

fn charge_owned_security_context(
    budget: &mut AllocationBudget,
    context: &BinarySecurityContext,
) -> Result<(), ParseError> {
    if let Some(range) = &context.range {
        charge_owned_mls_range(budget, range)?;
    }
    Ok(())
}

fn charge_owned_te_rule_data(
    budget: &mut AllocationBudget,
    rule: &BinaryTeRule,
) -> Result<(), ParseError> {
    match &rule.data {
        BinaryTeRuleData::Permissions(permissions) => {
            charge_owned_items::<PermissionId>(budget, permissions.len())
        }
        BinaryTeRuleData::ExtendedPermissions { values, .. } => {
            charge_owned_items::<u16>(budget, values.len())
        }
        BinaryTeRuleData::DefaultType(_) => Ok(()),
    }
}

fn constraint_symbol_name_length(prefix: &BinaryPolicyPrefix, attribute: u32, index: u32) -> usize {
    if attribute & CONSTRAINT_TYPE != 0 {
        let value = index + 1;
        prefix
            .types
            .binary_search_by_key(&value, |symbol| symbol.value)
            .map_or(IMPLICIT_ATTRIBUTE_NAME_BYTES, |symbol| {
                prefix.types[symbol].name.len()
            })
    } else if attribute & 2 != 0 {
        prefix.roles[index as usize].name.len()
    } else {
        prefix.users[index as usize].name.len()
    }
}

fn charge_owned_constraint(
    prefix: &BinaryPolicyPrefix,
    budget: &mut AllocationBudget,
    target_class: &ClassSymbol,
    constraint: &BinaryConstraint,
) -> Result<(), ParseError> {
    charge_owned_items::<PermissionId>(budget, target_class.permission_count as usize)?;
    for raw in &constraint.expressions {
        match raw {
            BinaryConstraintExpression::Not
            | BinaryConstraintExpression::And
            | BinaryConstraintExpression::Or => {
                charge_owned_items::<ConstraintExpressionToken>(budget, 1)?;
            }
            BinaryConstraintExpression::Attribute { attribute, .. } => {
                charge_owned_items::<ConstraintExpressionToken>(budget, 3)?;
                let (left, right) = constraint_operands(*attribute);
                charge_owned_string_bytes(budget, left.len())?;
                charge_owned_string_bytes(
                    budget,
                    right
                        .expect("validated attribute comparison must have a right operand")
                        .len(),
                )?;
            }
            BinaryConstraintExpression::Names { attribute, .. } => {
                charge_owned_items::<ConstraintExpressionToken>(budget, 3)?;
                let (left, _) = constraint_operands(*attribute);
                charge_owned_string_bytes(budget, left.len())?;
                let names = raw
                    .effective_names()
                    .expect("validated named constraint must expose names");
                charge_owned_items::<String>(budget, names.len())?;
                for index in names {
                    charge_owned_string_bytes(
                        budget,
                        constraint_symbol_name_length(prefix, *attribute, *index),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn charge_owned_labeling_rule(
    prefix: &BinaryPolicyPrefix,
    budget: &mut AllocationBudget,
    rule: &BinaryLabelingRule,
) -> Result<bool, ParseError> {
    match rule {
        BinaryLabelingRule::InitialSid { sid, context } => {
            charge_owned_string_bytes(
                budget,
                initial_sid_name(prefix.header.metadata.target, *sid).len(),
            )?;
            charge_owned_security_context(budget, context)?;
        }
        BinaryLabelingRule::FsContext { .. } => return Ok(false),
        BinaryLabelingRule::Portcon { context, .. }
        | BinaryLabelingRule::Nodecon { context, .. }
        | BinaryLabelingRule::Ibpkeycon { context, .. }
        | BinaryLabelingRule::Pirqcon { context, .. }
        | BinaryLabelingRule::Ioportcon { context, .. }
        | BinaryLabelingRule::Iomemcon { context, .. }
        | BinaryLabelingRule::Pcidevicecon { context, .. } => {
            charge_owned_security_context(budget, context)?;
        }
        BinaryLabelingRule::Netifcon {
            interface,
            interface_context,
            packet_context,
        } => {
            charge_owned_string_bytes(budget, interface.len())?;
            charge_owned_security_context(budget, interface_context)?;
            charge_owned_security_context(budget, packet_context)?;
        }
        BinaryLabelingRule::FsUse {
            filesystem,
            context,
            ..
        } => {
            charge_owned_string_bytes(budget, filesystem.len())?;
            charge_owned_security_context(budget, context)?;
        }
        BinaryLabelingRule::Ibendportcon {
            device, context, ..
        } => {
            charge_owned_string_bytes(budget, device.len())?;
            charge_owned_security_context(budget, context)?;
        }
        BinaryLabelingRule::Devicetreecon { path, context } => {
            charge_owned_string_bytes(budget, path.len())?;
            charge_owned_security_context(budget, context)?;
        }
        BinaryLabelingRule::Genfscon {
            filesystem,
            path,
            context,
            ..
        } => {
            charge_owned_string_bytes(budget, filesystem.len())?;
            charge_owned_string_bytes(budget, path.len())?;
            charge_owned_security_context(budget, context)?;
        }
    }
    Ok(true)
}

fn charge_owned_policy_allocation(
    prefix: &BinaryPolicyPrefix,
    source: &Path,
    budget: &mut AllocationBudget,
) -> Result<(), ParseError> {
    charge_owned_string_bytes(budget, source.as_os_str().as_encoded_bytes().len())?;

    charge_owned_items::<TypeSymbol>(budget, prefix.type_primary_count as usize)?;
    charge_name_index_base(budget, prefix.type_primary_count != 0)?;
    let mut implicit_members_started = false;
    for value in 1..=prefix.type_primary_count {
        match prefix
            .types
            .binary_search_by_key(&value, |symbol| symbol.value)
        {
            Ok(index) => {
                let symbol = &prefix.types[index];
                charge_owned_string_bytes(budget, symbol.name.len())?;
                charge_name_index_entry::<TypeOrAttributeId>(budget, symbol.name.len())?;
                match symbol.kind {
                    BinaryTypeKind::Type => {
                        charge_owned_strings(budget, &symbol.aliases)?;
                        for alias in &symbol.aliases {
                            charge_name_index_entry::<TypeOrAttributeId>(budget, alias.len())?;
                        }
                        charge_owned_items::<TypeId>(budget, 1)?;
                    }
                    BinaryTypeKind::Attribute => {
                        charge_owned_items::<TypeId>(budget, symbol.expanded_types.len())?;
                    }
                }
            }
            Err(_) => {
                charge_owned_string_bytes(budget, IMPLICIT_ATTRIBUTE_NAME_BYTES)?;
                charge_name_index_entry::<TypeOrAttributeId>(
                    budget,
                    IMPLICIT_ATTRIBUTE_NAME_BYTES,
                )?;
            }
        }
    }
    for symbol in &prefix.types {
        if symbol.kind != BinaryTypeKind::Type {
            continue;
        }
        for attribute in &symbol.attributes {
            if prefix
                .types
                .binary_search_by_key(&(*attribute + 1), |candidate| candidate.value)
                .is_err()
            {
                charge_owned_items::<TypeId>(budget, 1)?;
                if !implicit_members_started {
                    budget.charge(OWNED_BTREE_BASE_BYTES, OWNED_ALLOCATION_RESOURCE)?;
                    implicit_members_started = true;
                }
                charge_owned_items::<(u32, Vec<TypeId>)>(budget, 1)?;
                budget.charge(OWNED_BTREE_ENTRY_OVERHEAD_BYTES, OWNED_ALLOCATION_RESOURCE)?;
            }
        }
    }

    charge_owned_items::<ObjectClass>(budget, prefix.classes.len())?;
    charge_name_index_base(budget, !prefix.classes.is_empty())?;
    for target_class in &prefix.classes {
        charge_owned_string_bytes(budget, target_class.name.len())?;
        charge_name_index_entry::<ClassId>(budget, target_class.name.len())?;
        charge_owned_items::<Permission>(budget, target_class.permission_count as usize)?;
        if let Some(common_name) = &target_class.common {
            charge_owned_string_bytes(budget, common_name.len())?;
            let common = prefix
                .commons
                .iter()
                .find(|common| common.name == *common_name)
                .expect("validated class common must resolve");
            for permission in &common.permissions {
                charge_owned_string_bytes(budget, permission.name.len())?;
            }
        }
        charge_owned_items::<String>(budget, target_class.local_permissions.len())?;
        for permission in &target_class.local_permissions {
            charge_owned_string_bytes(budget, permission.name.len())?;
            charge_owned_string_bytes(budget, permission.name.len())?;
        }
    }

    charge_owned_items::<Role>(budget, prefix.roles.len())?;
    charge_name_index_base(budget, !prefix.roles.is_empty())?;
    for role in &prefix.roles {
        charge_owned_string_bytes(budget, role.name.len())?;
        charge_name_index_entry::<RoleId>(budget, role.name.len())?;
        charge_owned_items::<RoleId>(budget, role.dominates.len().max(1))?;
        charge_owned_items::<TypeId>(budget, role.authorized_types.len())?;
    }

    charge_owned_items::<Boolean>(budget, prefix.booleans.len())?;
    charge_name_index_base(budget, !prefix.booleans.is_empty())?;
    for boolean in &prefix.booleans {
        charge_owned_string_bytes(budget, boolean.name.len())?;
        charge_name_index_entry::<BooleanId>(budget, boolean.name.len())?;
    }

    charge_owned_items::<Conditional>(budget, prefix.conditionals.len())?;
    for conditional in &prefix.conditionals {
        charge_owned_items::<ConditionalToken>(budget, conditional.tokens.len())?;
        charge_owned_items::<BooleanId>(budget, conditional.tokens.len())?;
    }

    charge_owned_items::<TeRule>(budget, prefix.te_rules.len())?;
    charge_owned_items::<&BinaryTeRule>(budget, prefix.te_rules.len())?;
    for rule in &prefix.te_rules {
        charge_owned_te_rule_data(budget, rule)?;
    }
    for conditional in &prefix.conditionals {
        charge_owned_items::<TeRule>(budget, conditional.true_rules.len())?;
        charge_owned_items::<TeRule>(budget, conditional.false_rules.len())?;
        for rule in conditional
            .true_rules
            .iter()
            .chain(conditional.false_rules.iter())
        {
            charge_owned_te_rule_data(budget, rule)?;
        }
    }
    charge_owned_items::<TeRule>(budget, prefix.filename_transitions.len())?;
    for rule in &prefix.filename_transitions {
        charge_owned_string_bytes(budget, rule.filename.len())?;
    }

    charge_owned_items::<RbacRule>(budget, prefix.rbac_rules.len())?;

    charge_owned_items::<Sensitivity>(budget, prefix.sensitivities.len())?;
    charge_name_index_base(budget, !prefix.sensitivities.is_empty())?;
    for sensitivity in &prefix.sensitivities {
        charge_owned_string_bytes(budget, sensitivity.name.len())?;
        charge_name_index_entry::<SensitivityId>(budget, sensitivity.name.len())?;
        charge_owned_strings(budget, &sensitivity.aliases)?;
        for alias in &sensitivity.aliases {
            charge_name_index_entry::<SensitivityId>(budget, alias.len())?;
        }
        charge_owned_items::<CategoryId>(budget, sensitivity.categories.len())?;
    }

    charge_owned_items::<Category>(budget, prefix.categories.len())?;
    charge_name_index_base(budget, !prefix.categories.is_empty())?;
    for category in &prefix.categories {
        charge_owned_string_bytes(budget, category.name.len())?;
        charge_name_index_entry::<CategoryId>(budget, category.name.len())?;
        charge_owned_strings(budget, &category.aliases)?;
        for alias in &category.aliases {
            charge_name_index_entry::<CategoryId>(budget, alias.len())?;
        }
    }

    charge_owned_items::<MlsRule>(budget, prefix.mls_rules.len())?;
    for rule in &prefix.mls_rules {
        charge_owned_mls_range(budget, &rule.default)?;
    }

    charge_owned_items::<CommonPermissionSet>(budget, prefix.commons.len())?;
    for common in &prefix.commons {
        charge_owned_string_bytes(budget, common.name.len())?;
        charge_owned_items::<String>(budget, common.permissions.len())?;
        for permission in &common.permissions {
            charge_owned_string_bytes(budget, permission.name.len())?;
        }
    }

    charge_owned_items::<User>(budget, prefix.users.len())?;
    for user in &prefix.users {
        charge_owned_string_bytes(budget, user.name.len())?;
        charge_owned_items::<RoleId>(budget, user.roles.len())?;
        if let Some(default_level) = &user.default_level {
            charge_owned_mls_level(budget, default_level)?;
        }
        if let Some(range) = &user.range {
            charge_owned_mls_range(budget, range)?;
        }
    }

    for target_class in &prefix.classes {
        let constraints = target_class
            .constraints
            .iter()
            .chain(target_class.validation_constraints.iter());
        for constraint in constraints {
            charge_owned_items::<ConstraintRule>(budget, 1)?;
            charge_owned_constraint(prefix, budget, target_class, constraint)?;
        }
        let default_count = usize::from(target_class.defaults.user.is_some())
            + usize::from(target_class.defaults.role.is_some())
            + usize::from(target_class.defaults.object_type.is_some())
            + usize::from(target_class.defaults.range.is_some());
        charge_owned_items::<DefaultRule>(budget, default_count)?;
    }

    charge_owned_items::<String>(budget, prefix.policy_capabilities.len())?;
    for capability in &prefix.policy_capabilities {
        charge_owned_string_bytes(
            budget,
            policy_capability_name(*capability)
                .expect("validated policy capability must have a canonical name")
                .len(),
        )?;
    }

    for rule in &prefix.labeling_rules {
        if charge_owned_labeling_rule(prefix, budget, rule)? {
            charge_owned_items::<LabelingRule>(budget, 1)?;
        }
    }
    Ok(())
}

fn build_owned_policy(prefix: &BinaryPolicyPrefix, source: PathBuf) -> Result<Policy, ParseError> {
    let mut budget =
        AllocationBudget::with_used(prefix.allocation_limit, prefix.retained_allocation_bytes)?;
    charge_owned_policy_allocation(prefix, &source, &mut budget)?;
    let type_symbols = owned_type_symbols(prefix);
    let object_classes = owned_object_classes(prefix);
    let roles = owned_roles(prefix);
    let booleans = owned_booleans(prefix);
    let conditionals = owned_conditionals(prefix);
    let mut te_rules = ordered_unconditional_te_rules(prefix)
        .into_iter()
        .map(|rule| owned_te_rule(prefix, rule, None))
        .collect::<Vec<_>>();
    for (conditional_index, conditional) in prefix.conditionals.iter().enumerate() {
        let conditional_id = ConditionalId::from_raw(conditional_index as u32);
        te_rules.extend(conditional.true_rules.iter().map(|rule| {
            owned_te_rule(prefix, rule, Some(RuleCondition::new(conditional_id, true)))
        }));
        te_rules.extend(conditional.false_rules.iter().map(|rule| {
            owned_te_rule(
                prefix,
                rule,
                Some(RuleCondition::new(conditional_id, false)),
            )
        }));
    }
    te_rules.extend(prefix.filename_transitions.iter().map(|rule| {
        TeRule::new(
            TeRuleKind::TypeTransition,
            owned_type_symbol_id(prefix, rule.source),
            owned_type_symbol_id(prefix, rule.target),
            ClassId::from_raw(rule.target_class - 1),
            TeRuleData::DefaultType {
                default: TypeId::from_raw(rule.default_type - 1),
                filename: Some(rule.filename.clone()),
            },
        )
    }));
    let rbac_rules = owned_rbac_rules(prefix);
    let categories = owned_categories(prefix);
    let sensitivities = owned_sensitivities(prefix);
    let mls_rules = owned_mls_rules(prefix);
    let seinfo = SeinfoData::new(
        owned_commons(prefix),
        owned_users(prefix),
        owned_constraints(prefix),
        owned_defaults(prefix),
        prefix
            .policy_capabilities
            .iter()
            .map(|value| {
                policy_capability_name(*value)
                    .expect("validated policy capability must have a canonical name")
                    .to_owned()
            })
            .collect(),
        owned_labeling_rules(prefix),
    );
    Ok(Policy::from_all_parts(
        source,
        *prefix.header.metadata(),
        type_symbols,
        object_classes,
        roles,
        booleans,
        conditionals,
        te_rules,
        rbac_rules,
        sensitivities,
        categories,
        mls_rules,
        seinfo,
    ))
}

fn ordered_unconditional_te_rules(prefix: &BinaryPolicyPrefix) -> Vec<&BinaryTeRule> {
    let mut rules = prefix.te_rules.iter().collect::<Vec<_>>();
    let mask = avtab_hash_mask(prefix.te_rules.len());
    rules.sort_by_key(|rule| {
        (
            avtab_bucket(rule.source, rule.target, rule.target_class, mask),
            rule.source,
            rule.target,
            rule.target_class,
        )
    });
    rules
}

fn avtab_hash_mask(record_count: usize) -> u32 {
    let mut shift = 0_u32;
    let mut remaining = u32::try_from(record_count).unwrap_or(u32::MAX);
    while remaining != 0 {
        remaining >>= 1;
        shift += 1;
    }
    let shift = shift.saturating_sub(2).min(20);
    (1_u32 << shift) - 1
}

fn avtab_bucket(source: u32, target: u32, target_class: u32, mask: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    let mut hash = 0_u32;
    for value in [target_class, target, source] {
        let mixed = value.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        hash ^= mixed;
        hash = hash
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe6546b64);
    }
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    hash & mask
}

fn owned_type_symbols(prefix: &BinaryPolicyPrefix) -> Vec<TypeSymbol> {
    let mut implicit_members = BTreeMap::<u32, Vec<TypeId>>::new();
    for symbol in &prefix.types {
        if symbol.kind != BinaryTypeKind::Type {
            continue;
        }
        for attribute in &symbol.attributes {
            if prefix
                .types
                .binary_search_by_key(&(*attribute + 1), |candidate| candidate.value)
                .is_err()
            {
                implicit_members
                    .entry(*attribute)
                    .or_default()
                    .push(TypeId::from_raw(symbol.value - 1));
            }
        }
    }
    (1..=prefix.type_primary_count)
        .map(|value| {
            let id = value - 1;
            match prefix
                .types
                .binary_search_by_key(&value, |symbol| symbol.value)
            {
                Ok(index) => {
                    let symbol = &prefix.types[index];
                    match symbol.kind {
                        BinaryTypeKind::Type => {
                            TypeSymbol::new_type(TypeId::from_raw(id), symbol.name.clone())
                                .with_aliases(symbol.aliases.clone())
                                .with_seinfo_properties(
                                    symbol.permissive,
                                    symbol.bound.map(|bound| TypeId::from_raw(bound - 1)),
                                )
                        }
                        BinaryTypeKind::Attribute => TypeSymbol::new_attribute(
                            AttributeId::from_raw(id),
                            symbol.name.clone(),
                            symbol
                                .expanded_types
                                .iter()
                                .copied()
                                .map(TypeId::from_raw)
                                .collect(),
                        ),
                    }
                }
                Err(_) => TypeSymbol::new_attribute(
                    AttributeId::from_raw(id),
                    format!("@ttr{value:010}"),
                    implicit_members.remove(&id).unwrap_or_default(),
                ),
            }
        })
        .collect()
}

fn owned_type_symbol_id(prefix: &BinaryPolicyPrefix, value: u32) -> TypeOrAttributeId {
    match prefix
        .types
        .binary_search_by_key(&value, |symbol| symbol.value)
    {
        Ok(index) if prefix.types[index].kind == BinaryTypeKind::Type => {
            TypeOrAttributeId::Type(TypeId::from_raw(value - 1))
        }
        _ => TypeOrAttributeId::Attribute(AttributeId::from_raw(value - 1)),
    }
}

fn owned_object_classes(prefix: &BinaryPolicyPrefix) -> Vec<ObjectClass> {
    prefix
        .classes
        .iter()
        .map(|target_class| {
            let mut permissions = target_class
                .common
                .iter()
                .flat_map(|common_name| {
                    prefix
                        .commons
                        .iter()
                        .find(|common| common.name == *common_name)
                        .expect("validated class common must resolve")
                        .permissions
                        .iter()
                })
                .chain(target_class.local_permissions.iter())
                .map(|permission| (permission.value, permission.name.clone()))
                .collect::<Vec<_>>();
            permissions.sort_unstable_by_key(|(value, _)| *value);
            ObjectClass::new(
                ClassId::from_raw(target_class.value - 1),
                target_class.name.clone(),
                permissions
                    .into_iter()
                    .map(|(value, name)| Permission::new(PermissionId::from_raw(value - 1), name))
                    .collect(),
            )
            .with_declaration(
                target_class.common.clone(),
                target_class
                    .local_permissions
                    .iter()
                    .map(|permission| permission.name.clone())
                    .collect(),
            )
        })
        .collect()
}

fn owned_roles(prefix: &BinaryPolicyPrefix) -> Vec<Role> {
    prefix
        .roles
        .iter()
        .map(|role| {
            let id = RoleId::from_raw(role.value - 1);
            let mut expanded_roles = role
                .dominates
                .iter()
                .copied()
                .map(RoleId::from_raw)
                .collect::<Vec<_>>();
            if expanded_roles.is_empty() {
                expanded_roles.push(id);
            }
            Role::new(id, role.name.clone(), expanded_roles).with_authorized_types(
                role.authorized_types
                    .iter()
                    .copied()
                    .map(TypeId::from_raw)
                    .collect(),
            )
        })
        .collect()
}

fn owned_booleans(prefix: &BinaryPolicyPrefix) -> Vec<Boolean> {
    prefix
        .booleans
        .iter()
        .map(|boolean| {
            Boolean::new(
                BooleanId::from_raw(boolean.value - 1),
                boolean.name.clone(),
                boolean.state,
            )
        })
        .collect()
}

fn owned_conditionals(prefix: &BinaryPolicyPrefix) -> Vec<Conditional> {
    prefix
        .conditionals
        .iter()
        .enumerate()
        .map(|(index, conditional)| {
            Conditional::new(
                ConditionalId::from_raw(index as u32),
                conditional.tokens.clone(),
            )
        })
        .collect()
}

fn owned_te_rule(
    prefix: &BinaryPolicyPrefix,
    rule: &BinaryTeRule,
    condition: Option<RuleCondition>,
) -> TeRule {
    let data = match &rule.data {
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
        rule.kind,
        owned_type_symbol_id(prefix, rule.source),
        owned_type_symbol_id(prefix, rule.target),
        ClassId::from_raw(rule.target_class - 1),
        data,
    );
    match condition {
        Some(condition) => rule.with_condition(condition),
        None => rule,
    }
}

fn owned_rbac_rules(prefix: &BinaryPolicyPrefix) -> Vec<RbacRule> {
    prefix
        .rbac_rules
        .iter()
        .map(|rule| {
            let data = match &rule.data {
                BinaryRbacRuleData::Allow { target } => RbacRuleData::Allow {
                    target: RoleId::from_raw(*target - 1),
                },
                BinaryRbacRuleData::RoleTransition {
                    target,
                    target_class,
                    default,
                } => RbacRuleData::RoleTransition {
                    target: owned_type_symbol_id(prefix, *target),
                    target_class: ClassId::from_raw(*target_class - 1),
                    default: RoleId::from_raw(*default - 1),
                },
            };
            RbacRule::new(RoleId::from_raw(rule.source - 1), data)
        })
        .collect()
}

fn owned_categories(prefix: &BinaryPolicyPrefix) -> Vec<Category> {
    prefix
        .categories
        .iter()
        .map(|category| {
            Category::new(
                CategoryId::from_raw(category.value - 1),
                category.name.clone(),
            )
            .with_aliases(category.aliases.clone())
        })
        .collect()
}

fn owned_sensitivities(prefix: &BinaryPolicyPrefix) -> Vec<Sensitivity> {
    prefix
        .sensitivities
        .iter()
        .map(|sensitivity| {
            Sensitivity::new(
                SensitivityId::from_raw(sensitivity.value - 1),
                sensitivity.name.clone(),
            )
            .with_aliases(sensitivity.aliases.clone())
            .with_categories(
                sensitivity
                    .categories
                    .iter()
                    .copied()
                    .map(CategoryId::from_raw)
                    .collect(),
            )
        })
        .collect()
}

fn owned_mls_level(level: &BinaryMlsLevel) -> MlsLevel {
    MlsLevel::new(
        SensitivityId::from_raw(level.sensitivity - 1),
        level
            .categories
            .iter()
            .copied()
            .map(CategoryId::from_raw)
            .collect(),
    )
}

fn owned_mls_rules(prefix: &BinaryPolicyPrefix) -> Vec<MlsRule> {
    prefix
        .mls_rules
        .iter()
        .map(|rule| {
            MlsRule::new(
                owned_type_symbol_id(prefix, rule.source),
                owned_type_symbol_id(prefix, rule.target),
                ClassId::from_raw(rule.target_class - 1),
                MlsRange::new(
                    owned_mls_level(&rule.default.low),
                    owned_mls_level(&rule.default.high),
                ),
            )
        })
        .collect()
}

fn owned_commons(prefix: &BinaryPolicyPrefix) -> Vec<CommonPermissionSet> {
    prefix
        .commons
        .iter()
        .map(|common| {
            CommonPermissionSet::new(
                common.name.clone(),
                common
                    .permissions
                    .iter()
                    .map(|permission| permission.name.clone())
                    .collect(),
            )
        })
        .collect()
}

fn owned_users(prefix: &BinaryPolicyPrefix) -> Vec<User> {
    prefix
        .users
        .iter()
        .map(|user| {
            User::new(
                UserId::from_raw(user.value - 1),
                user.name.clone(),
                user.roles
                    .iter()
                    .copied()
                    .filter(|index| prefix.roles[*index as usize].name != "object_r")
                    .map(RoleId::from_raw)
                    .collect(),
                user.default_level.as_ref().map(owned_mls_level),
                user.range.as_ref().map(|range| {
                    MlsRange::new(owned_mls_level(&range.low), owned_mls_level(&range.high))
                }),
            )
        })
        .collect()
}

fn owned_defaults(prefix: &BinaryPolicyPrefix) -> Vec<DefaultRule> {
    let mut defaults = Vec::new();
    for target_class in &prefix.classes {
        let target = ClassId::from_raw(target_class.value - 1);
        for (kind, value) in [
            (DefaultRuleKind::User, target_class.defaults.user),
            (DefaultRuleKind::Role, target_class.defaults.role),
            (DefaultRuleKind::Type, target_class.defaults.object_type),
        ] {
            if let Some(value) = value {
                defaults.push(DefaultRule::new(kind, target, value, None));
            }
        }
        if let Some((value, range_part)) = target_class.defaults.range {
            defaults.push(DefaultRule::new(
                DefaultRuleKind::Range,
                target,
                value,
                range_part,
            ));
        }
    }
    defaults
}

fn owned_constraints(prefix: &BinaryPolicyPrefix) -> Vec<ConstraintRule> {
    prefix
        .classes
        .iter()
        .flat_map(|target_class| {
            target_class
                .constraints
                .iter()
                .chain(target_class.validation_constraints.iter())
                .map(move |constraint| owned_constraint(prefix, target_class, constraint))
        })
        .collect()
}

fn owned_constraint(
    prefix: &BinaryPolicyPrefix,
    target_class: &ClassSymbol,
    constraint: &BinaryConstraint,
) -> ConstraintRule {
    let kind = match (constraint.validate_transition, constraint.is_mls()) {
        (false, false) => ConstraintKind::Constrain,
        (false, true) => ConstraintKind::MlsConstrain,
        (true, false) => ConstraintKind::ValidateTransition,
        (true, true) => ConstraintKind::MlsValidateTransition,
    };
    let permissions = (0..target_class.permission_count)
        .filter(|bit| constraint.permissions & (1_u32 << bit) != 0)
        .map(PermissionId::from_raw)
        .collect();
    let mut expression = Vec::new();
    for raw in &constraint.expressions {
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
                        .expect("validated attribute comparison must have a right operand")
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
                        .expect("validated named constraint must expose names")
                        .iter()
                        .map(|index| owned_constraint_symbol_name(prefix, *attribute, *index))
                        .collect(),
                ));
                expression.push(ConstraintExpressionToken::Operator(*operator));
            }
        }
    }
    ConstraintRule::new(
        kind,
        ClassId::from_raw(target_class.value - 1),
        permissions,
        expression,
    )
}

fn owned_constraint_symbol_name(prefix: &BinaryPolicyPrefix, attribute: u32, index: u32) -> String {
    if attribute & CONSTRAINT_TYPE != 0 {
        let value = index + 1;
        match prefix
            .types
            .binary_search_by_key(&value, |symbol| symbol.value)
        {
            Ok(symbol) => prefix.types[symbol].name.clone(),
            Err(_) => format!("@ttr{value:010}"),
        }
    } else if attribute & 2 != 0 {
        prefix.roles[index as usize].name.clone()
    } else {
        prefix.users[index as usize].name.clone()
    }
}

const fn constraint_operands(attribute: u32) -> (&'static str, Option<&'static str>) {
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
        _ => unreachable!(),
    }
}

fn owned_labeling_rules(prefix: &BinaryPolicyPrefix) -> Vec<LabelingRule> {
    prefix
        .labeling_rules
        .iter()
        .filter_map(|rule| match rule {
            BinaryLabelingRule::InitialSid { sid, context } => Some(LabelingRule::InitialSid {
                name: initial_sid_name(prefix.header.metadata.target, *sid).to_owned(),
                context: owned_security_context(context),
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
                    _ => unreachable!("validated port protocol"),
                },
                low: *low,
                high: *high,
                context: owned_security_context(context),
            }),
            BinaryLabelingRule::Netifcon {
                interface,
                interface_context,
                packet_context,
            } => Some(LabelingRule::Netifcon {
                interface: interface.clone(),
                interface_context: owned_security_context(interface_context),
                packet_context: owned_security_context(packet_context),
            }),
            BinaryLabelingRule::Nodecon {
                address,
                mask,
                context,
            } => Some(LabelingRule::Nodecon {
                address: *address,
                mask: *mask,
                context: owned_security_context(context),
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
                    _ => unreachable!("validated fs_use behavior"),
                },
                filesystem: filesystem.clone(),
                context: owned_security_context(context),
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
                context: owned_security_context(context),
            }),
            BinaryLabelingRule::Ibendportcon {
                device,
                port,
                context,
            } => Some(LabelingRule::Ibendportcon {
                device: device.clone(),
                port: *port,
                context: owned_security_context(context),
            }),
            BinaryLabelingRule::Pirqcon { irq, context } => Some(LabelingRule::Pirqcon {
                irq: *irq,
                context: owned_security_context(context),
            }),
            BinaryLabelingRule::Ioportcon { low, high, context } => Some(LabelingRule::Ioportcon {
                low: *low,
                high: *high,
                context: owned_security_context(context),
            }),
            BinaryLabelingRule::Iomemcon { low, high, context } => Some(LabelingRule::Iomemcon {
                low: *low,
                high: *high,
                context: owned_security_context(context),
            }),
            BinaryLabelingRule::Pcidevicecon { device, context } => {
                Some(LabelingRule::Pcidevicecon {
                    device: *device,
                    context: owned_security_context(context),
                })
            }
            BinaryLabelingRule::Devicetreecon { path, context } => {
                Some(LabelingRule::Devicetreecon {
                    path: path.clone(),
                    context: owned_security_context(context),
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
                context: owned_security_context(context),
            }),
        })
        .collect()
}

fn owned_security_context(context: &BinarySecurityContext) -> SecurityContext {
    SecurityContext::new(
        UserId::from_raw(context.user - 1),
        RoleId::from_raw(context.role - 1),
        TypeId::from_raw(context.type_id - 1),
        context
            .range
            .as_ref()
            .map(|range| MlsRange::new(owned_mls_level(&range.low), owned_mls_level(&range.high))),
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

/// A rejected or incomplete binary policy parser slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The input ended before a bounded field was complete.
    Truncated {
        /// Offset at which the read was attempted.
        offset: usize,
        /// Number of bytes required at that offset.
        needed: usize,
        /// Number of bytes available at that offset.
        available: usize,
    },
    /// Complete policy data was followed by unconsumed bytes.
    TrailingData {
        /// First unconsumed byte offset.
        offset: usize,
        /// Number of unconsumed bytes.
        remaining: usize,
    },
    /// The file has neither the kernel nor module policy magic.
    InvalidMagic(u32),
    /// Loadable modules are not part of this kernel-policy parser slice.
    UnsupportedModulePolicy,
    /// The target identifier length is zero or exceeds the format limit.
    InvalidIdentifierLength(u32),
    /// The target identifier is not `SE Linux` or `XenFlask`.
    UnsupportedTarget(Vec<u8>),
    /// The kernel binary policy version is outside the supported range.
    UnsupportedVersion(u32),
    /// The target has no binary format entry for this version.
    UnsupportedTargetVersion {
        /// Parsed target platform.
        target: TargetPlatform,
        /// Parsed binary policy version.
        version: u32,
    },
    /// Header table counts do not match the target/version compatibility entry.
    IncompatibleTableCounts {
        /// Expected symbol-table family count.
        expected_symbols: u32,
        /// Actual symbol-table family count.
        actual_symbols: u32,
        /// Expected object-context family count.
        expected_object_contexts: u32,
        /// Actual object-context family count.
        actual_object_contexts: u32,
    },
    /// The unknown-class handling bits do not encode deny, reject, or allow.
    InvalidUnknownHandling(u32),
    /// A leading extensible bitmap violates the binary format invariants.
    InvalidBitmap(&'static str),
    /// A symbol table violates a structural binary format invariant.
    InvalidSymbolTable {
        /// Symbol table being decoded.
        table: &'static str,
        /// Rejected invariant.
        reason: &'static str,
    },
    /// A one-based symbol value is outside the table primary-value range.
    InvalidSymbolValue {
        /// Symbol table being decoded.
        table: &'static str,
        /// Rejected serialized value.
        value: u32,
        /// Declared maximum primary value.
        primary_count: u32,
    },
    /// An object class references a common permission set that was not parsed.
    UnknownCommon(String),
    /// A class constraint violates a structural or semantic invariant.
    InvalidConstraint(&'static str),
    /// An access-vector-table record violates a structural or semantic invariant.
    InvalidAvtab(&'static str),
    /// A Boolean conditional violates a structural or postfix invariant.
    InvalidConditional(&'static str),
    /// An RBAC rule violates a structural or semantic invariant.
    InvalidRbac(&'static str),
    /// A filename transition violates a structural or semantic invariant.
    InvalidFilenameTransition(&'static str),
    /// A security context violates a structural or semantic invariant.
    InvalidSecurityContext(&'static str),
    /// An SELinux or Xen object context violates a format invariant.
    InvalidObjectContext(&'static str),
    /// A trailing genfs record violates a format invariant.
    InvalidGenfs(&'static str),
    /// An MLS range transition violates a structural or semantic invariant.
    InvalidMlsRule(&'static str),
    /// A trailing type-attribute map violates a structural invariant.
    InvalidTypeAttributeMap(&'static str),
    /// A class default has an unsupported serialized discriminant.
    InvalidDefault {
        /// Default field being decoded.
        field: &'static str,
        /// Rejected serialized value.
        value: u32,
    },
    /// Two entries use the same symbol name or numeric value.
    DuplicateSymbol {
        /// Symbol table being decoded.
        table: &'static str,
        /// Duplicate name or numeric value rendered for diagnostics.
        symbol: String,
    },
    /// A symbol name is not valid UTF-8.
    InvalidUtf8 {
        /// Field being decoded.
        field: &'static str,
    },
    /// A symbol name contains an embedded C-string terminator.
    EmbeddedNul {
        /// Field being decoded.
        field: &'static str,
    },
    /// A configured parser resource bound was exceeded.
    LimitExceeded {
        /// Bounded resource.
        resource: &'static str,
        /// Requested count or byte size.
        requested: u64,
        /// Configured maximum.
        limit: u64,
    },
    /// A fallible collection reservation failed.
    AllocationFailed {
        /// Collection being reserved.
        resource: &'static str,
        /// Number of entries or bytes requested.
        requested: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                offset,
                needed,
                available,
            } => write!(
                formatter,
                "binary policy is truncated at offset {offset}: need {needed} bytes, have {available}"
            ),
            Self::TrailingData { offset, remaining } => write!(
                formatter,
                "binary policy has {remaining} trailing bytes after offset {offset}"
            ),
            Self::InvalidMagic(magic) => {
                write!(formatter, "invalid binary policy magic 0x{magic:08x}")
            }
            Self::UnsupportedModulePolicy => {
                formatter.write_str("loadable policy modules are not supported")
            }
            Self::InvalidIdentifierLength(length) => {
                write!(formatter, "invalid binary policy target length {length}")
            }
            Self::UnsupportedTarget(target) => write!(
                formatter,
                "unsupported binary policy target {:?}",
                String::from_utf8_lossy(target)
            ),
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported binary policy version {version}; expected {MIN_SUPPORTED_POLICY_VERSION}..={MAX_SUPPORTED_POLICY_VERSION}"
            ),
            Self::UnsupportedTargetVersion { target, version } => write!(
                formatter,
                "binary policy target {target:?} does not support format version {version}"
            ),
            Self::IncompatibleTableCounts {
                expected_symbols,
                actual_symbols,
                expected_object_contexts,
                actual_object_contexts,
            } => write!(
                formatter,
                "binary policy table counts ({actual_symbols},{actual_object_contexts}) do not match target/version counts ({expected_symbols},{expected_object_contexts})"
            ),
            Self::InvalidUnknownHandling(value) => {
                write!(formatter, "invalid unknown-class handling value {value}")
            }
            Self::InvalidBitmap(reason) => write!(formatter, "invalid policy bitmap: {reason}"),
            Self::InvalidSymbolTable { table, reason } => {
                write!(formatter, "invalid {table} symbol table: {reason}")
            }
            Self::InvalidSymbolValue {
                table,
                value,
                primary_count,
            } => write!(
                formatter,
                "invalid {table} symbol value {value}; expected 1..={primary_count}"
            ),
            Self::UnknownCommon(name) => {
                write!(formatter, "object class references unknown common {name:?}")
            }
            Self::InvalidConstraint(reason) => {
                write!(formatter, "invalid object-class constraint: {reason}")
            }
            Self::InvalidAvtab(reason) => {
                write!(formatter, "invalid type-enforcement rule table: {reason}")
            }
            Self::InvalidConditional(reason) => {
                write!(formatter, "invalid Boolean conditional: {reason}")
            }
            Self::InvalidRbac(reason) => write!(formatter, "invalid RBAC rule: {reason}"),
            Self::InvalidFilenameTransition(reason) => {
                write!(formatter, "invalid filename transition: {reason}")
            }
            Self::InvalidSecurityContext(reason) => {
                write!(formatter, "invalid security context: {reason}")
            }
            Self::InvalidObjectContext(reason) => {
                write!(formatter, "invalid object context: {reason}")
            }
            Self::InvalidGenfs(reason) => {
                write!(formatter, "invalid genfs table: {reason}")
            }
            Self::InvalidMlsRule(reason) => {
                write!(formatter, "invalid MLS range transition: {reason}")
            }
            Self::InvalidTypeAttributeMap(reason) => {
                write!(formatter, "invalid type-attribute map: {reason}")
            }
            Self::InvalidDefault { field, value } => {
                write!(formatter, "invalid class {field} value {value}")
            }
            Self::DuplicateSymbol { table, symbol } => {
                write!(formatter, "duplicate {table} symbol {symbol:?}")
            }
            Self::InvalidUtf8 { field } => write!(formatter, "{field} is not valid UTF-8"),
            Self::EmbeddedNul { field } => {
                write!(formatter, "{field} contains an embedded NUL byte")
            }
            Self::LimitExceeded {
                resource,
                requested,
                limit,
            } => write!(
                formatter,
                "binary policy {resource} limit exceeded: requested {requested}, limit {limit}"
            ),
            Self::AllocationFailed {
                resource,
                requested,
            } => write!(
                formatter,
                "could not reserve {requested} entries or bytes for {resource}"
            ),
        }
    }
}

impl Error for ParseError {}

/// Failure while reading or parsing a kernel binary policy from a file.
#[derive(Debug)]
pub enum MetadataLoadError {
    /// The policy file could not be opened or read.
    Io {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The bounded bytes were not a supported kernel binary policy.
    Parse {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Parser diagnostic.
        source: ParseError,
    },
}

impl fmt::Display for MetadataLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(formatter, "could not parse {}: {source}", path.display())
            }
        }
    }
}

impl Error for MetadataLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

/// File loader for the pure Rust bounded metadata parser.
#[derive(Clone, Copy, Debug, Default)]
pub struct PureRustMetadataLoader;

impl PureRustMetadataLoader {
    /// Reads at most the maximum fixed header size and decodes its metadata.
    pub fn load(self, path: &Path) -> Result<BinaryPolicyHeader, MetadataLoadError> {
        let mut file = File::open(path).map_err(|source| MetadataLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut bytes = [0_u8; MAX_HEADER_LENGTH];
        let mut length = 0;
        while length < bytes.len() {
            let read = file
                .read(&mut bytes[length..])
                .map_err(|source| MetadataLoadError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            length += read;
        }
        parse_policy_header(&bytes[..length]).map_err(|source| MetadataLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// File loader for the bounded pure Rust kernel-policy parser.
#[derive(Clone, Copy, Debug, Default)]
pub struct PureRustPrefixLoader {
    limits: ParserLimits,
}

impl PureRustPrefixLoader {
    /// Creates a file loader with explicit parser limits.
    #[must_use]
    pub const fn with_limits(limits: ParserLimits) -> Self {
        Self { limits }
    }

    /// Reads a bounded kernel binary policy.
    pub fn load(self, path: &Path) -> Result<BinaryPolicyPrefix, MetadataLoadError> {
        let file = File::open(path).map_err(|source| MetadataLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let read_limit = u64::try_from(self.limits.max_serialized_prefix_bytes.saturating_add(1))
            .unwrap_or(u64::MAX);
        let mut bytes = Vec::new();
        file.take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|source| MetadataLoadError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        parse_policy_prefix_with_limits(&bytes, self.limits).map_err(|source| {
            MetadataLoadError::Parse {
                path: path.to_path_buf(),
                source,
            }
        })
    }
}

/// Pure Rust loader for the complete shared immutable policy model.
#[derive(Clone, Copy, Debug, Default)]
pub struct PureRustPolicyLoader {
    limits: ParserLimits,
}

impl PureRustPolicyLoader {
    /// Creates a complete-policy loader with explicit parser limits.
    #[must_use]
    pub const fn with_limits(limits: ParserLimits) -> Self {
        Self { limits }
    }

    /// Reads, validates, and reconstructs one kernel binary policy.
    pub fn load(self, path: &Path) -> Result<Policy, MetadataLoadError> {
        let prefix = PureRustPrefixLoader::with_limits(self.limits).load(path)?;
        prefix
            .to_policy(path.to_path_buf())
            .map_err(|source| MetadataLoadError::Parse {
                path: path.to_path_buf(),
                source,
            })
    }
}

impl PolicyLoader for PureRustPolicyLoader {
    type Error = MetadataLoadError;

    fn load(&self, path: &Path) -> Result<Policy, Self::Error> {
        PureRustPolicyLoader::load(*self, path)
    }
}

/// Parses and validates the fixed metadata header of a kernel binary policy.
pub fn parse_policy_header(bytes: &[u8]) -> Result<BinaryPolicyHeader, ParseError> {
    parse_header(&mut Cursor::new(bytes))
}

/// Parses the bounded kernel binary policy.
pub fn parse_policy_prefix(bytes: &[u8]) -> Result<BinaryPolicyPrefix, ParseError> {
    parse_policy_prefix_with_limits(bytes, ParserLimits::default())
}

/// Parses the bounded kernel binary policy with explicit limits.
pub fn parse_policy_prefix_with_limits(
    bytes: &[u8],
    limits: ParserLimits,
) -> Result<BinaryPolicyPrefix, ParseError> {
    if bytes.len() > limits.max_serialized_prefix_bytes {
        return Err(ParseError::LimitExceeded {
            resource: "serialized prefix bytes",
            requested: usize_to_u64(bytes.len()),
            limit: usize_to_u64(limits.max_serialized_prefix_bytes),
        });
    }
    let mut cursor = Cursor::with_limit(bytes, limits.max_serialized_prefix_bytes);
    let header = parse_header(&mut cursor)?;
    let version = header.metadata().version;
    let mut budget = AllocationBudget::new(limits.max_total_allocation_bytes);

    let policy_capabilities = if version >= POLICY_VERSION_POLCAP {
        let values = read_bitmap_bits(
            &mut cursor,
            &limits,
            &mut budget,
            "policy capability bitmap",
        )?;
        validate_policy_capabilities(&values)?;
        values
    } else {
        Vec::new()
    };
    let permissive_types = if version >= POLICY_VERSION_PERMISSIVE {
        read_bitmap_bits(&mut cursor, &limits, &mut budget, "permissive type bitmap")?
    } else {
        Vec::new()
    };
    let neveraudit_types = if version >= POLICY_VERSION_NEVERAUDIT {
        read_bitmap_bits(&mut cursor, &limits, &mut budget, "neveraudit type bitmap")?
    } else {
        Vec::new()
    };

    let mut commons = read_commons(&mut cursor, &limits, &mut budget)?;
    commons.sort_unstable_by_key(|common| common.value);
    reject_duplicate_common_values(&commons)?;
    commons.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    reject_duplicate_common_names(&commons)?;
    let classes = read_classes(&mut cursor, &limits, &mut budget, version, &commons)?;
    let roles = read_roles(&mut cursor, &limits, &mut budget, version)?;
    let (mut types, type_primary_count) = read_types(
        &mut cursor,
        &limits,
        &mut budget,
        version,
        &permissive_types,
        &neveraudit_types,
    )?;
    validate_role_type_references(&roles, type_primary_count, &types, version)?;
    let users = read_users(
        &mut cursor,
        &limits,
        &mut budget,
        version,
        header.metadata().mls,
        &roles,
    )?;
    let booleans = if header.symbol_table_count() >= 6 {
        read_booleans(&mut cursor, &limits, &mut budget)?
    } else {
        Vec::new()
    };
    let (sensitivities, categories) = if header.symbol_table_count() >= 8 {
        let sensitivities = read_sensitivities(&mut cursor, &limits, &mut budget)?;
        let categories = read_categories(&mut cursor, &limits, &mut budget)?;
        (sensitivities, categories)
    } else {
        (Vec::new(), Vec::new())
    };
    validate_mls_symbol_references(&users, &sensitivities, &categories, header.metadata().mls)?;
    let mut decoded_rule_count = 0_u64;
    let te_rules = read_avtab(
        &mut cursor,
        &limits,
        &mut budget,
        version,
        header.metadata().target,
        type_primary_count,
        &types,
        &classes,
        false,
        &mut decoded_rule_count,
    )?;
    let conditionals = if version >= POLICY_VERSION_BOOL {
        read_conditionals(
            &mut cursor,
            &limits,
            &mut budget,
            version,
            header.metadata().target,
            type_primary_count,
            &types,
            &classes,
            &booleans,
            &mut decoded_rule_count,
        )?
    } else {
        Vec::new()
    };
    let rbac_rules = read_rbac_rules(
        &mut cursor,
        &limits,
        &mut budget,
        version,
        header.metadata().target,
        type_primary_count,
        &types,
        &classes,
        &roles,
    )?;
    let filename_transitions = if version >= POLICY_VERSION_FILENAME_TRANSITION {
        read_filename_transitions(
            &mut cursor,
            &limits,
            &mut budget,
            version,
            type_primary_count,
            &types,
            &classes,
        )?
    } else {
        Vec::new()
    };
    let (labeling_rules, mls_rules) = {
        let context_symbols = ContextSymbols {
            version,
            mls: header.metadata().mls,
            type_primary_count,
            types: &types,
            roles: &roles,
            users: &users,
            sensitivities: &sensitivities,
            categories: &categories,
        };
        let mut labeling_rules = read_object_contexts(
            &mut cursor,
            &limits,
            &mut budget,
            header.metadata().target,
            header.object_context_count(),
            &context_symbols,
        )?;
        read_genfs_contexts(
            &mut cursor,
            &limits,
            &mut budget,
            &context_symbols,
            &classes,
            &mut labeling_rules,
        )?;
        let mls_rules = if version >= POLICY_VERSION_MLS {
            read_mls_range_transitions(
                &mut cursor,
                &limits,
                &mut budget,
                &context_symbols,
                &classes,
            )?
        } else {
            Vec::new()
        };
        (labeling_rules, mls_rules)
    };
    read_type_attribute_maps(
        &mut cursor,
        &limits,
        &mut budget,
        version,
        type_primary_count,
        &mut types,
    )?;
    validate_labeling_role_authorization(&labeling_rules, &roles, &types)?;
    if cursor.offset != bytes.len() {
        return Err(ParseError::TrailingData {
            offset: cursor.offset,
            remaining: bytes.len() - cursor.offset,
        });
    }

    Ok(BinaryPolicyPrefix {
        header,
        policy_capabilities,
        commons,
        classes,
        roles,
        types,
        type_primary_count,
        users,
        booleans,
        sensitivities,
        categories,
        te_rules,
        conditionals,
        rbac_rules,
        filename_transitions,
        labeling_rules,
        mls_rules,
        encoded_len: cursor.offset,
        retained_allocation_bytes: budget.used,
        allocation_limit: budget.limit,
    })
}

fn parse_header(cursor: &mut Cursor<'_>) -> Result<BinaryPolicyHeader, ParseError> {
    let magic = cursor.read_u32()?;
    match magic {
        POLICYDB_MAGIC => {}
        POLICYDB_MODULE_MAGIC => return Err(ParseError::UnsupportedModulePolicy),
        other => return Err(ParseError::InvalidMagic(other)),
    }

    let identifier_length = cursor.read_u32()?;
    let identifier_length = usize::try_from(identifier_length)
        .ok()
        .filter(|length| (1..=MAX_IDENTIFIER_LENGTH).contains(length))
        .ok_or(ParseError::InvalidIdentifierLength(identifier_length))?;
    let identifier = cursor.read_bytes(identifier_length)?;
    let target = match identifier {
        b"SE Linux" => TargetPlatform::Selinux,
        b"XenFlask" => TargetPlatform::Xen,
        other => return Err(ParseError::UnsupportedTarget(other.to_vec())),
    };

    let version = cursor.read_u32()?;
    if !(MIN_SUPPORTED_POLICY_VERSION..=MAX_SUPPORTED_POLICY_VERSION).contains(&version) {
        return Err(ParseError::UnsupportedVersion(version));
    }
    let config = cursor.read_u32()?;
    let handle_unknown = match config & CONFIG_UNKNOWN_MASK {
        0 => HandleUnknown::Deny,
        2 => HandleUnknown::Reject,
        4 => HandleUnknown::Allow,
        other => return Err(ParseError::InvalidUnknownHandling(other)),
    };
    let symbol_table_count = cursor.read_u32()?;
    let object_context_count = cursor.read_u32()?;
    let Some((expected_symbols, expected_object_contexts)) = compatibility_counts(target, version)
    else {
        return Err(ParseError::UnsupportedTargetVersion { target, version });
    };
    if symbol_table_count != expected_symbols || object_context_count != expected_object_contexts {
        return Err(ParseError::IncompatibleTableCounts {
            expected_symbols,
            actual_symbols: symbol_table_count,
            expected_object_contexts,
            actual_object_contexts: object_context_count,
        });
    }

    Ok(BinaryPolicyHeader {
        metadata: PolicyMetadata {
            version,
            mls: config & CONFIG_MLS != 0,
            target,
            handle_unknown,
        },
        symbol_table_count,
        object_context_count,
        encoded_len: cursor.offset,
    })
}

const fn compatibility_counts(target: TargetPlatform, version: u32) -> Option<(u32, u32)> {
    match target {
        TargetPlatform::Selinux => match version {
            15 => Some((5, 6)),
            16 => Some((6, 6)),
            17..=18 => Some((6, 7)),
            19..=30 => Some((8, 7)),
            31..=35 => Some((8, 9)),
            _ => None,
        },
        TargetPlatform::Xen => match version {
            24 => Some((8, 5)),
            30 => Some((8, 6)),
            _ => None,
        },
    }
}

fn validate_policy_capabilities(values: &[u32]) -> Result<(), ParseError> {
    if values
        .iter()
        .copied()
        .any(|value| policy_capability_name(value).is_none())
    {
        return Err(ParseError::InvalidSymbolTable {
            table: "policy capability bitmap",
            reason: "a capability number has no canonical name",
        });
    }
    Ok(())
}

fn read_bitmap_bits(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<Vec<u32>, ParseError> {
    let mut bits = Vec::new();
    read_bitmap_nodes(cursor, limits, |start_bit, map| {
        let additional = map.count_ones() as usize;
        reserve_additional(&mut bits, additional, budget, resource)?;
        for offset in 0..BITMAP_MAP_SIZE {
            if map & (1_u64 << offset) != 0 {
                bits.push(start_bit + offset);
            }
        }
        Ok(())
    })?;
    Ok(bits)
}

fn read_bitmap_nodes(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    mut visit: impl FnMut(u32, u64) -> Result<(), ParseError>,
) -> Result<(), ParseError> {
    let map_size = cursor.read_u32()?;
    let high_bit = cursor.read_u32()?;
    let node_count = cursor.read_u32()?;
    if map_size != BITMAP_MAP_SIZE {
        return Err(ParseError::InvalidBitmap("map size is not 64 bits"));
    }
    if high_bit == 0 {
        return if node_count == 0 {
            Ok(())
        } else {
            Err(ParseError::InvalidBitmap(
                "an empty bitmap declares non-empty nodes",
            ))
        };
    }
    if high_bit % BITMAP_MAP_SIZE != 0 {
        return Err(ParseError::InvalidBitmap(
            "high bit is not aligned to the map size",
        ));
    }
    if node_count == 0 {
        return Err(ParseError::InvalidBitmap("a non-empty bitmap has no nodes"));
    }
    enforce_u32_limit("bitmap nodes", node_count, limits.max_bitmap_nodes)?;

    let mut previous_start = None;
    for _ in 0..node_count {
        let start_bit = cursor.read_u32()?;
        let map = cursor.read_u64()?;
        if start_bit % BITMAP_MAP_SIZE != 0 {
            return Err(ParseError::InvalidBitmap(
                "node start bit is not map-size aligned",
            ));
        }
        if start_bit > high_bit - BITMAP_MAP_SIZE {
            return Err(ParseError::InvalidBitmap(
                "node starts beyond the bitmap high bit",
            ));
        }
        if previous_start.is_some_and(|previous| start_bit <= previous) {
            return Err(ParseError::InvalidBitmap(
                "node start bits are not strictly increasing",
            ));
        }
        if map == 0 {
            return Err(ParseError::InvalidBitmap("a bitmap node has no set bits"));
        }
        visit(start_bit, map)?;
        previous_start = Some(start_bit);
    }
    if previous_start != Some(high_bit - BITMAP_MAP_SIZE) {
        return Err(ParseError::InvalidBitmap(
            "last node does not reach the bitmap high bit",
        ));
    }
    Ok(())
}

fn read_commons(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<Vec<CommonSymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != 0 && primary_count == 0 {
        return Err(ParseError::InvalidSymbolTable {
            table: "common",
            reason: "entries exist without primary values",
        });
    }
    enforce_u32_limit(
        "common primary values",
        primary_count,
        limits.max_common_symbols,
    )?;
    enforce_u32_limit(
        "common symbol entries",
        entry_count,
        limits.max_common_symbols,
    )?;

    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "common symbol entries",
        requested: u64::MAX,
        limit: usize_to_u64(limits.max_common_symbols as usize),
    })?;
    let mut commons = Vec::new();
    reserve_exact(&mut commons, entry_count, budget, "common symbols")?;
    for _ in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let value = cursor.read_u32()?;
        let permission_primary_count = cursor.read_u32()?;
        let permission_entry_count = cursor.read_u32()?;
        validate_symbol_value("common", value, primary_count)?;
        if permission_primary_count == 0 {
            return Err(ParseError::InvalidSymbolTable {
                table: "common permission",
                reason: "a common symbol has no permissions",
            });
        }
        if permission_primary_count != permission_entry_count {
            return Err(ParseError::InvalidSymbolTable {
                table: "common permission",
                reason: "primary-value and entry counts differ",
            });
        }
        if permission_primary_count > PERMISSION_SYMBOL_LIMIT {
            return Err(ParseError::InvalidSymbolTable {
                table: "common permission",
                reason: "more than 32 permission bits are declared",
            });
        }
        enforce_u32_limit(
            "permissions per common",
            permission_entry_count,
            limits.max_permissions_per_common,
        )?;

        let name = read_symbol_name(cursor, name_length, limits, budget, "common symbol name")?;
        let permission_count =
            usize::try_from(permission_entry_count).map_err(|_| ParseError::LimitExceeded {
                resource: "permissions per common",
                requested: u64::MAX,
                limit: usize_to_u64(limits.max_permissions_per_common as usize),
            })?;
        let mut permissions = Vec::new();
        reserve_exact(
            &mut permissions,
            permission_count,
            budget,
            "common permissions",
        )?;
        for _ in 0..permission_count {
            let permission_name_length = cursor.read_u32()?;
            let permission_value = cursor.read_u32()?;
            validate_symbol_value(
                "common permission",
                permission_value,
                permission_primary_count,
            )?;
            let permission_name = read_symbol_name(
                cursor,
                permission_name_length,
                limits,
                budget,
                "common permission name",
            )?;
            permissions.push(PermissionSymbol {
                name: permission_name,
                value: permission_value,
            });
        }
        permissions.sort_unstable_by_key(|permission| permission.value);
        reject_duplicate_permission_values(&permissions)?;
        permissions.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        reject_duplicate_permission_names(&permissions)?;
        commons.push(CommonSymbol {
            name,
            value,
            permissions,
        });
    }
    Ok(commons)
}

fn read_classes(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    commons: &[CommonSymbol],
) -> Result<Vec<ClassSymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != primary_count {
        return Err(ParseError::InvalidSymbolTable {
            table: "object class",
            reason: "the owned model requires dense primary values",
        });
    }
    if primary_count > u32::from(u16::MAX) {
        return Err(ParseError::InvalidSymbolTable {
            table: "object class",
            reason: "more than 65535 primary values are declared",
        });
    }
    enforce_u32_limit(
        "object-class primary values",
        primary_count,
        limits.max_class_symbols,
    )?;
    enforce_u32_limit(
        "object-class symbol entries",
        entry_count,
        limits.max_class_symbols,
    )?;

    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "object-class symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_class_symbols),
    })?;
    let mut classes = Vec::new();
    reserve_exact(&mut classes, entry_count, budget, "object-class symbols")?;
    for _ in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let common_name_length = cursor.read_u32()?;
        let value = cursor.read_u32()?;
        let permission_primary_count = cursor.read_u32()?;
        let local_permission_count = cursor.read_u32()?;
        let constraint_count = cursor.read_u32()?;

        validate_symbol_value("object class", value, primary_count)?;
        if value > u32::from(u16::MAX) {
            return Err(ParseError::InvalidSymbolTable {
                table: "object class",
                reason: "a class value does not fit the binary format",
            });
        }
        if permission_primary_count > PERMISSION_SYMBOL_LIMIT {
            return Err(ParseError::InvalidSymbolTable {
                table: "object-class permission",
                reason: "more than 32 permission bits are declared",
            });
        }
        enforce_u32_limit(
            "permissions per object class",
            permission_primary_count,
            limits.max_permissions_per_class,
        )?;
        enforce_u32_limit(
            "local permissions per object class",
            local_permission_count,
            limits.max_permissions_per_class,
        )?;
        enforce_u32_limit(
            "constraints per object class",
            constraint_count,
            limits.max_constraints_per_class,
        )?;

        let name = read_symbol_name(cursor, name_length, limits, budget, "object-class name")?;
        let common = if common_name_length == 0 {
            None
        } else {
            Some(read_symbol_name(
                cursor,
                common_name_length,
                limits,
                budget,
                "class common name",
            )?)
        };
        let inherited_permission_count = match common.as_deref() {
            Some(common_name) => commons
                .binary_search_by(|candidate| candidate.name.as_str().cmp(common_name))
                .ok()
                .map(|index| commons[index].permissions.len() as u32)
                .ok_or_else(|| ParseError::UnknownCommon(common_name.to_owned()))?,
            None => 0,
        };
        if permission_primary_count
            != inherited_permission_count
                .checked_add(local_permission_count)
                .ok_or(ParseError::InvalidSymbolTable {
                    table: "object-class permission",
                    reason: "permission counts overflow",
                })?
        {
            return Err(ParseError::InvalidSymbolTable {
                table: "object-class permission",
                reason: "total permissions do not equal inherited plus local entries",
            });
        }

        let local_permission_count =
            usize::try_from(local_permission_count).map_err(|_| ParseError::LimitExceeded {
                resource: "local permissions per object class",
                requested: u64::MAX,
                limit: u64::from(limits.max_permissions_per_class),
            })?;
        let mut local_permissions = Vec::new();
        reserve_exact(
            &mut local_permissions,
            local_permission_count,
            budget,
            "object-class local permissions",
        )?;
        for _ in 0..local_permission_count {
            let permission_name_length = cursor.read_u32()?;
            let permission_value = cursor.read_u32()?;
            validate_symbol_value(
                "object-class permission",
                permission_value,
                permission_primary_count,
            )?;
            if permission_value <= inherited_permission_count {
                return Err(ParseError::InvalidSymbolTable {
                    table: "object-class permission",
                    reason: "a local permission overrides an inherited value",
                });
            }
            let permission_name = read_symbol_name(
                cursor,
                permission_name_length,
                limits,
                budget,
                "object-class permission name",
            )?;
            local_permissions.push(PermissionSymbol {
                name: permission_name,
                value: permission_value,
            });
        }
        local_permissions.sort_unstable_by_key(|permission| permission.value);
        reject_duplicate_permission_values_for(
            &local_permissions,
            "object-class permission value",
        )?;
        local_permissions.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        reject_duplicate_permission_names_for(&local_permissions, "object-class permission name")?;

        let constraints = read_constraints(
            cursor,
            constraint_count,
            false,
            permission_primary_count,
            version,
            limits,
            budget,
        )?;
        let validation_constraints = if version >= POLICY_VERSION_VALIDATETRANS {
            let count = cursor.read_u32()?;
            enforce_u32_limit(
                "validation constraints per object class",
                count,
                limits.max_constraints_per_class,
            )?;
            read_constraints(
                cursor,
                count,
                true,
                permission_primary_count,
                version,
                limits,
                budget,
            )?
        } else {
            Vec::new()
        };
        let defaults = read_class_defaults(cursor, version)?;
        classes.push(ClassSymbol {
            name,
            value,
            permission_count: permission_primary_count,
            common,
            local_permissions,
            constraints,
            validation_constraints,
            defaults,
        });
    }

    classes.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    reject_duplicate_class_names(&classes)?;
    classes.sort_unstable_by_key(|target_class| target_class.value);
    reject_duplicate_class_values(&classes)?;
    for (index, target_class) in classes.iter().enumerate() {
        let expected = u32::try_from(index + 1).map_err(|_| ParseError::InvalidSymbolTable {
            table: "object class",
            reason: "class index does not fit the binary format",
        })?;
        if target_class.value != expected {
            return Err(ParseError::InvalidSymbolTable {
                table: "object class",
                reason: "class values are not dense and one-based",
            });
        }
    }
    Ok(classes)
}

fn read_roles(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
) -> Result<Vec<RoleSymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if primary_count == 0 || entry_count != primary_count {
        return Err(ParseError::InvalidSymbolTable {
            table: "role",
            reason: "kernel roles must be nonempty dense primary values",
        });
    }
    enforce_u32_limit(
        "role primary values",
        primary_count,
        limits.max_role_symbols,
    )?;
    enforce_u32_limit("role symbol entries", entry_count, limits.max_role_symbols)?;

    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "role symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_role_symbols),
    })?;
    let mut roles = Vec::new();
    reserve_exact(&mut roles, entry_count, budget, "role symbols")?;
    for _ in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let value = cursor.read_u32()?;
        let bound = if version >= POLICY_VERSION_BOUNDARY {
            nonzero(cursor.read_u32()?)
        } else {
            None
        };
        validate_symbol_value("role", value, primary_count)?;
        if bound.is_some_and(|bound| bound > primary_count) {
            return Err(ParseError::InvalidSymbolValue {
                table: "bound role",
                value: bound.unwrap_or_default(),
                primary_count,
            });
        }
        let name = read_symbol_name(cursor, name_length, limits, budget, "role symbol name")?;
        let dominates = read_bitmap_bits(cursor, limits, budget, "role dominance bitmap")?;
        let authorized_types =
            read_bitmap_bits(cursor, limits, budget, "role authorized type bitmap")?;
        roles.push(RoleSymbol {
            name,
            value,
            dominates,
            authorized_types,
            bound,
        });
    }

    roles.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    reject_duplicate_role_names(&roles)?;
    roles.sort_unstable_by_key(|role| role.value);
    reject_duplicate_role_values(&roles)?;
    for (index, role) in roles.iter().enumerate() {
        let expected = u32::try_from(index + 1).map_err(|_| ParseError::InvalidSymbolTable {
            table: "role",
            reason: "role index does not fit the binary format",
        })?;
        if role.value != expected {
            return Err(ParseError::InvalidSymbolTable {
                table: "role",
                reason: "role values are not dense and one-based",
            });
        }
        if role
            .dominates
            .iter()
            .any(|dominated| *dominated >= primary_count)
        {
            return Err(ParseError::InvalidSymbolTable {
                table: "role dominance bitmap",
                reason: "a role index is out of range",
            });
        }
    }
    if roles[0].name != "object_r" {
        return Err(ParseError::InvalidSymbolTable {
            table: "role",
            reason: "one-based role value 1 is not object_r",
        });
    }
    Ok(roles)
}

#[derive(Debug)]
struct RawTypeEntry {
    name: String,
    value: u32,
    primary: bool,
    kind: BinaryTypeKind,
    bound: Option<u32>,
    serialized_order: usize,
}

fn read_types(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    permissive_types: &[u32],
    neveraudit_types: &[u32],
) -> Result<(Vec<BinaryTypeSymbol>, u32), ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != 0 && primary_count == 0 {
        return Err(ParseError::InvalidSymbolTable {
            table: "type",
            reason: "entries exist without primary values",
        });
    }
    enforce_u32_limit(
        "type primary values",
        primary_count,
        limits.max_type_symbols,
    )?;
    enforce_u32_limit("type symbol entries", entry_count, limits.max_type_symbols)?;

    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "type symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_type_symbols),
    })?;
    let mut entries = Vec::new();
    reserve_exact(&mut entries, entry_count, budget, "type symbol entries")?;
    for serialized_order in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let value = cursor.read_u32()?;
        validate_symbol_value("type", value, primary_count)?;
        let (primary, kind, bound) = if version >= POLICY_VERSION_BOUNDARY {
            let properties = cursor.read_u32()?;
            if properties & !KERNEL_TYPE_PROPERTY_MASK != 0 {
                return Err(ParseError::InvalidSymbolTable {
                    table: "type",
                    reason: "kernel type properties contain userspace-only bits",
                });
            }
            (
                properties & TYPE_PROPERTY_PRIMARY != 0,
                if properties & TYPE_PROPERTY_ATTRIBUTE != 0 {
                    BinaryTypeKind::Attribute
                } else {
                    BinaryTypeKind::Type
                },
                nonzero(cursor.read_u32()?),
            )
        } else {
            let primary = cursor.read_u32()?;
            if primary > primary_count {
                return Err(ParseError::InvalidSymbolValue {
                    table: "type primary",
                    value: primary,
                    primary_count,
                });
            }
            (primary != 0, BinaryTypeKind::Type, None)
        };
        if !primary && kind == BinaryTypeKind::Attribute {
            return Err(ParseError::InvalidSymbolTable {
                table: "type",
                reason: "a non-primary entry is marked as an attribute",
            });
        }
        if bound.is_some_and(|bound| bound > primary_count) {
            return Err(ParseError::InvalidSymbolValue {
                table: "bound type",
                value: bound.unwrap_or_default(),
                primary_count,
            });
        }
        if kind == BinaryTypeKind::Attribute && bound.is_some() {
            return Err(ParseError::InvalidSymbolTable {
                table: "type",
                reason: "a type attribute has a bound",
            });
        }
        if !primary && bound.is_some() {
            return Err(ParseError::InvalidSymbolTable {
                table: "type",
                reason: "a type alias has a bound",
            });
        }
        let name = read_symbol_name(cursor, name_length, limits, budget, "type symbol name")?;
        entries.push(RawTypeEntry {
            name,
            value,
            primary,
            kind,
            bound,
            serialized_order,
        });
    }

    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    for pair in entries.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "type name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    entries.sort_unstable_by_key(|entry| (entry.value, !entry.primary, entry.serialized_order));

    let retained_count = usize::try_from(primary_count).map_err(|_| ParseError::LimitExceeded {
        resource: "type primary values",
        requested: u64::MAX,
        limit: u64::from(limits.max_type_symbols),
    })?;
    let mut types = Vec::new();
    reserve_exact(&mut types, retained_count, budget, "primary type symbols")?;
    let mut entries = entries.into_iter().peekable();
    while let Some(primary) = entries.next() {
        if !primary.primary {
            return Err(ParseError::InvalidSymbolTable {
                table: "type",
                reason: "an alias value has no primary symbol",
            });
        }
        if types
            .last()
            .is_some_and(|previous: &BinaryTypeSymbol| previous.value == primary.value)
        {
            return Err(ParseError::DuplicateSymbol {
                table: "primary type value",
                symbol: primary.value.to_string(),
            });
        }
        let value = primary.value;
        let mut aliases = Vec::new();
        while entries.peek().is_some_and(|entry| entry.value == value) {
            let alias = entries.next().expect("peeked type alias must be present");
            if alias.primary {
                return Err(ParseError::DuplicateSymbol {
                    table: "primary type value",
                    symbol: value.to_string(),
                });
            }
            reserve_additional(&mut aliases, 1, budget, "type aliases")?;
            aliases.push(alias.name);
        }
        if primary.kind == BinaryTypeKind::Attribute && !aliases.is_empty() {
            return Err(ParseError::InvalidSymbolTable {
                table: "type",
                reason: "a type attribute has aliases",
            });
        }
        types.push(BinaryTypeSymbol {
            name: primary.name,
            value,
            kind: primary.kind,
            aliases,
            permissive: permissive_types.binary_search(&value).is_ok(),
            bound: primary.bound,
            expanded_types: Vec::new(),
            attributes: Vec::new(),
        });
    }

    let gaps_are_implicit_attributes = (20..=POLICY_VERSION_PERMISSIVE).contains(&version);
    if !gaps_are_implicit_attributes && types.len() != retained_count {
        return Err(ParseError::InvalidSymbolTable {
            table: "type",
            reason: "primary type values are not dense",
        });
    }
    for (index, symbol) in types.iter().enumerate() {
        if !gaps_are_implicit_attributes {
            let expected =
                u32::try_from(index + 1).map_err(|_| ParseError::InvalidSymbolTable {
                    table: "type",
                    reason: "type index does not fit the binary format",
                })?;
            if symbol.value != expected {
                return Err(ParseError::InvalidSymbolTable {
                    table: "type",
                    reason: "primary type values are not dense and one-based",
                });
            }
        }
        if let Some(bound) = symbol.bound {
            let Ok(bound_index) = types.binary_search_by_key(&bound, |entry| entry.value) else {
                return Err(ParseError::InvalidSymbolTable {
                    table: "bound type",
                    reason: "the bound does not resolve to a primary type",
                });
            };
            if types[bound_index].kind != BinaryTypeKind::Type {
                return Err(ParseError::InvalidSymbolTable {
                    table: "bound type",
                    reason: "the bound resolves to a type attribute",
                });
            }
        }
    }
    validate_simple_type_bitmap("permissive type", permissive_types, primary_count, &types)?;
    validate_simple_type_bitmap("neveraudit type", neveraudit_types, primary_count, &types)?;

    Ok((types, primary_count))
}

fn validate_simple_type_bitmap(
    table: &'static str,
    values: &[u32],
    primary_count: u32,
    types: &[BinaryTypeSymbol],
) -> Result<(), ParseError> {
    for value in values {
        if *value == 0 || *value > primary_count {
            return Err(ParseError::InvalidSymbolValue {
                table,
                value: *value,
                primary_count,
            });
        }
        let Ok(index) = types.binary_search_by_key(value, |entry| entry.value) else {
            return Err(ParseError::InvalidSymbolTable {
                table,
                reason: "the bitmap value does not resolve to a primary type",
            });
        };
        if types[index].kind != BinaryTypeKind::Type {
            return Err(ParseError::InvalidSymbolTable {
                table,
                reason: "a type attribute occurs in a simple-type bitmap",
            });
        }
    }
    Ok(())
}

fn validate_role_type_references(
    roles: &[RoleSymbol],
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    version: u32,
) -> Result<(), ParseError> {
    let gaps_are_implicit_attributes = (20..=POLICY_VERSION_PERMISSIVE).contains(&version);
    for role in roles {
        for index in &role.authorized_types {
            if *index >= type_primary_count {
                return Err(ParseError::InvalidSymbolTable {
                    table: "role authorized type bitmap",
                    reason: "a type index is out of range",
                });
            }
            if !gaps_are_implicit_attributes
                && types
                    .binary_search_by_key(&(*index + 1), |entry| entry.value)
                    .is_err()
            {
                return Err(ParseError::InvalidSymbolTable {
                    table: "role authorized type bitmap",
                    reason: "a type index does not resolve to a primary symbol",
                });
            }
        }
    }
    Ok(())
}

fn read_users(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    mls: bool,
    roles: &[RoleSymbol],
) -> Result<Vec<UserSymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != primary_count {
        return Err(ParseError::InvalidSymbolTable {
            table: "user",
            reason: "kernel users must be dense primary values",
        });
    }
    enforce_u32_limit(
        "user primary values",
        primary_count,
        limits.max_user_symbols,
    )?;
    enforce_u32_limit("user symbol entries", entry_count, limits.max_user_symbols)?;

    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "user symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_user_symbols),
    })?;
    let mut users = Vec::new();
    reserve_exact(&mut users, entry_count, budget, "user symbols")?;
    for _ in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let value = cursor.read_u32()?;
        let bound = if version >= POLICY_VERSION_BOUNDARY {
            nonzero(cursor.read_u32()?)
        } else {
            None
        };
        validate_symbol_value("user", value, primary_count)?;
        if bound.is_some_and(|bound| bound > primary_count) {
            return Err(ParseError::InvalidSymbolValue {
                table: "bound user",
                value: bound.unwrap_or_default(),
                primary_count,
            });
        }
        let name = read_symbol_name(cursor, name_length, limits, budget, "user symbol name")?;
        let user_roles = read_bitmap_bits(cursor, limits, budget, "user role bitmap")?;
        if user_roles.iter().any(|role| *role >= roles.len() as u32) {
            return Err(ParseError::InvalidSymbolTable {
                table: "user role bitmap",
                reason: "a role index is out of range",
            });
        }
        let (range, default_level) = if version >= POLICY_VERSION_MLS {
            let range = read_mls_range(cursor, limits, budget, "user MLS range")?;
            let default_level = read_mls_level(cursor, limits, budget, "user default MLS level")?;
            if mls {
                (Some(range), Some(default_level))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };
        users.push(UserSymbol {
            name,
            value,
            roles: user_roles,
            bound,
            default_level,
            range,
        });
    }

    users.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    reject_duplicate_user_names(&users)?;
    users.sort_unstable_by_key(|user| user.value);
    reject_duplicate_user_values(&users)?;
    for (index, user) in users.iter().enumerate() {
        let expected = u32::try_from(index + 1).map_err(|_| ParseError::InvalidSymbolTable {
            table: "user",
            reason: "user index does not fit the binary format",
        })?;
        if user.value != expected {
            return Err(ParseError::InvalidSymbolTable {
                table: "user",
                reason: "user values are not dense and one-based",
            });
        }
    }
    Ok(users)
}

fn read_mls_range(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<BinaryMlsRange, ParseError> {
    let sensitivity_count = cursor.read_u32()?;
    if !(1..=2).contains(&sensitivity_count) {
        return Err(ParseError::InvalidSymbolTable {
            table: resource,
            reason: "an expanded MLS range must contain one or two sensitivities",
        });
    }
    let low_sensitivity = cursor.read_u32()?;
    let high_sensitivity = if sensitivity_count == 2 {
        cursor.read_u32()?
    } else {
        low_sensitivity
    };
    let low_categories = read_bitmap_bits(cursor, limits, budget, resource)?;
    let high_categories = if sensitivity_count == 2 {
        read_bitmap_bits(cursor, limits, budget, resource)?
    } else {
        clone_u32_vec(&low_categories, budget, resource)?
    };
    Ok(BinaryMlsRange {
        low: BinaryMlsLevel {
            sensitivity: low_sensitivity,
            categories: low_categories,
        },
        high: BinaryMlsLevel {
            sensitivity: high_sensitivity,
            categories: high_categories,
        },
    })
}

fn read_mls_level(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<BinaryMlsLevel, ParseError> {
    let sensitivity = cursor.read_u32()?;
    let categories = read_bitmap_bits(cursor, limits, budget, resource)?;
    Ok(BinaryMlsLevel {
        sensitivity,
        categories,
    })
}

fn clone_u32_vec(
    source: &[u32],
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<Vec<u32>, ParseError> {
    let mut output = Vec::new();
    reserve_exact(&mut output, source.len(), budget, resource)?;
    output.extend_from_slice(source);
    Ok(output)
}

fn read_booleans(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<Vec<BinaryBooleanSymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != primary_count {
        return Err(ParseError::InvalidSymbolTable {
            table: "Boolean",
            reason: "kernel Booleans must be dense primary values",
        });
    }
    enforce_u32_limit(
        "Boolean primary values",
        primary_count,
        limits.max_boolean_symbols,
    )?;
    enforce_u32_limit(
        "Boolean symbol entries",
        entry_count,
        limits.max_boolean_symbols,
    )?;
    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "Boolean symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_boolean_symbols),
    })?;
    let mut booleans = Vec::new();
    reserve_exact(&mut booleans, entry_count, budget, "Boolean symbols")?;
    for _ in 0..entry_count {
        let value = cursor.read_u32()?;
        let state = cursor.read_u32()?;
        let name_length = cursor.read_u32()?;
        validate_symbol_value("Boolean", value, primary_count)?;
        let state = match state {
            0 => false,
            1 => true,
            _ => {
                return Err(ParseError::InvalidSymbolTable {
                    table: "Boolean",
                    reason: "the default state is not zero or one",
                });
            }
        };
        let name = read_symbol_name(cursor, name_length, limits, budget, "Boolean symbol name")?;
        booleans.push(BinaryBooleanSymbol { name, value, state });
    }
    booleans.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    reject_duplicate_boolean_names(&booleans)?;
    booleans.sort_unstable_by_key(|boolean| boolean.value);
    reject_duplicate_boolean_values(&booleans)?;
    for (index, boolean) in booleans.iter().enumerate() {
        let expected = u32::try_from(index + 1).map_err(|_| ParseError::InvalidSymbolTable {
            table: "Boolean",
            reason: "Boolean index does not fit the binary format",
        })?;
        if boolean.value != expected {
            return Err(ParseError::InvalidSymbolTable {
                table: "Boolean",
                reason: "Boolean values are not dense and one-based",
            });
        }
    }
    Ok(booleans)
}

#[derive(Debug)]
struct RawSensitivityEntry {
    name: String,
    value: u32,
    alias: bool,
    categories: Vec<u32>,
    serialized_order: usize,
}

fn read_sensitivities(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<Vec<SensitivitySymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != 0 && primary_count == 0 {
        return Err(ParseError::InvalidSymbolTable {
            table: "sensitivity",
            reason: "entries exist without primary values",
        });
    }
    enforce_u32_limit(
        "sensitivity primary values",
        primary_count,
        limits.max_sensitivity_symbols,
    )?;
    enforce_u32_limit(
        "sensitivity symbol entries",
        entry_count,
        limits.max_sensitivity_symbols,
    )?;
    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "sensitivity symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_sensitivity_symbols),
    })?;
    let mut entries = Vec::new();
    reserve_exact(
        &mut entries,
        entry_count,
        budget,
        "sensitivity symbol entries",
    )?;
    for serialized_order in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let alias = cursor.read_u32()?;
        if alias > 1 {
            return Err(ParseError::InvalidSymbolTable {
                table: "sensitivity",
                reason: "the alias flag is not zero or one",
            });
        }
        let name = read_symbol_name(
            cursor,
            name_length,
            limits,
            budget,
            "sensitivity symbol name",
        )?;
        let value = cursor.read_u32()?;
        validate_symbol_value("sensitivity", value, primary_count)?;
        let categories = read_bitmap_bits(cursor, limits, budget, "sensitivity category bitmap")?;
        entries.push(RawSensitivityEntry {
            name,
            value,
            alias: alias != 0,
            categories,
            serialized_order,
        });
    }
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    for pair in entries.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "sensitivity name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    entries.sort_unstable_by_key(|entry| (entry.value, entry.alias, entry.serialized_order));
    // Kernel-policy expansion increments the serialized `nprim` field for
    // aliases too. Retain only canonical entries and validate their actual
    // values as the dense prefix used by libsepol's value-to-name index.
    let mut sensitivities = Vec::new();
    reserve_exact(
        &mut sensitivities,
        entry_count,
        budget,
        "primary sensitivity symbols",
    )?;
    let mut entries = entries.into_iter().peekable();
    while let Some(primary) = entries.next() {
        if primary.alias {
            return Err(ParseError::InvalidSymbolTable {
                table: "sensitivity",
                reason: "an alias value has no primary symbol",
            });
        }
        let value = primary.value;
        let mut aliases = Vec::new();
        while entries.peek().is_some_and(|entry| entry.value == value) {
            let alias = entries
                .next()
                .expect("peeked sensitivity alias must be present");
            if !alias.alias {
                return Err(ParseError::DuplicateSymbol {
                    table: "primary sensitivity value",
                    symbol: value.to_string(),
                });
            }
            if alias.categories != primary.categories {
                return Err(ParseError::InvalidSymbolTable {
                    table: "sensitivity",
                    reason: "an alias has different declared categories",
                });
            }
            reserve_additional(&mut aliases, 1, budget, "sensitivity aliases")?;
            aliases.push(alias.name);
        }
        sensitivities.push(SensitivitySymbol {
            name: primary.name,
            value,
            aliases,
            categories: primary.categories,
        });
    }
    validate_dense_sensitivity_values(&sensitivities)?;
    Ok(sensitivities)
}

#[derive(Debug)]
struct RawCategoryEntry {
    name: String,
    value: u32,
    alias: bool,
    serialized_order: usize,
}

fn read_categories(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<Vec<CategorySymbol>, ParseError> {
    let primary_count = cursor.read_u32()?;
    let entry_count = cursor.read_u32()?;
    if entry_count != 0 && primary_count == 0 {
        return Err(ParseError::InvalidSymbolTable {
            table: "category",
            reason: "entries exist without primary values",
        });
    }
    enforce_u32_limit(
        "category primary values",
        primary_count,
        limits.max_category_symbols,
    )?;
    enforce_u32_limit(
        "category symbol entries",
        entry_count,
        limits.max_category_symbols,
    )?;
    let entry_count = usize::try_from(entry_count).map_err(|_| ParseError::LimitExceeded {
        resource: "category symbol entries",
        requested: u64::MAX,
        limit: u64::from(limits.max_category_symbols),
    })?;
    let mut entries = Vec::new();
    reserve_exact(&mut entries, entry_count, budget, "category symbol entries")?;
    for serialized_order in 0..entry_count {
        let name_length = cursor.read_u32()?;
        let value = cursor.read_u32()?;
        let alias = cursor.read_u32()?;
        validate_symbol_value("category", value, primary_count)?;
        if alias > 1 {
            return Err(ParseError::InvalidSymbolTable {
                table: "category",
                reason: "the alias flag is not zero or one",
            });
        }
        let name = read_symbol_name(cursor, name_length, limits, budget, "category symbol name")?;
        entries.push(RawCategoryEntry {
            name,
            value,
            alias: alias != 0,
            serialized_order,
        });
    }
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    for pair in entries.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "category name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    entries.sort_unstable_by_key(|entry| (entry.value, entry.alias, entry.serialized_order));
    // As with sensitivities, kernel-policy `nprim` includes alias entries.
    let mut categories = Vec::new();
    reserve_exact(
        &mut categories,
        entry_count,
        budget,
        "primary category symbols",
    )?;
    let mut entries = entries.into_iter().peekable();
    while let Some(primary) = entries.next() {
        if primary.alias {
            return Err(ParseError::InvalidSymbolTable {
                table: "category",
                reason: "an alias value has no primary symbol",
            });
        }
        let value = primary.value;
        let mut aliases = Vec::new();
        while entries.peek().is_some_and(|entry| entry.value == value) {
            let alias = entries
                .next()
                .expect("peeked category alias must be present");
            if !alias.alias {
                return Err(ParseError::DuplicateSymbol {
                    table: "primary category value",
                    symbol: value.to_string(),
                });
            }
            reserve_additional(&mut aliases, 1, budget, "category aliases")?;
            aliases.push(alias.name);
        }
        categories.push(CategorySymbol {
            name: primary.name,
            value,
            aliases,
        });
    }
    validate_dense_category_values(&categories)?;
    Ok(categories)
}

fn validate_dense_sensitivity_values(
    sensitivities: &[SensitivitySymbol],
) -> Result<(), ParseError> {
    for (index, sensitivity) in sensitivities.iter().enumerate() {
        if sensitivity.value != (index + 1) as u32 {
            return Err(ParseError::InvalidSymbolTable {
                table: "sensitivity",
                reason: "primary sensitivity values are not dense and one-based",
            });
        }
    }
    Ok(())
}

fn validate_dense_category_values(categories: &[CategorySymbol]) -> Result<(), ParseError> {
    for (index, category) in categories.iter().enumerate() {
        if category.value != (index + 1) as u32 {
            return Err(ParseError::InvalidSymbolTable {
                table: "category",
                reason: "primary category values are not dense and one-based",
            });
        }
    }
    Ok(())
}

fn validate_mls_symbol_references(
    users: &[UserSymbol],
    sensitivities: &[SensitivitySymbol],
    categories: &[CategorySymbol],
    mls: bool,
) -> Result<(), ParseError> {
    let category_count = categories.len() as u32;
    for sensitivity in sensitivities {
        if sensitivity
            .categories
            .iter()
            .any(|category| *category >= category_count)
        {
            return Err(ParseError::InvalidSymbolTable {
                table: "sensitivity category bitmap",
                reason: "a category index is out of range",
            });
        }
    }
    if !mls {
        return Ok(());
    }
    let sensitivity_count = sensitivities.len() as u32;
    for user in users {
        let default_level = user
            .default_level
            .as_ref()
            .ok_or(ParseError::InvalidSymbolTable {
                table: "user MLS data",
                reason: "an MLS policy user has no default level",
            })?;
        let range = user.range.as_ref().ok_or(ParseError::InvalidSymbolTable {
            table: "user MLS data",
            reason: "an MLS policy user has no range",
        })?;
        for level in [default_level, &range.low, &range.high] {
            if level.sensitivity == 0 || level.sensitivity > sensitivity_count {
                return Err(ParseError::InvalidSymbolValue {
                    table: "user MLS sensitivity",
                    value: level.sensitivity,
                    primary_count: sensitivity_count,
                });
            }
            if level
                .categories
                .iter()
                .any(|category| *category >= category_count)
            {
                return Err(ParseError::InvalidSymbolTable {
                    table: "user MLS category bitmap",
                    reason: "a category index is out of range",
                });
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_avtab(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    conditional: bool,
    decoded_rule_count: &mut u64,
) -> Result<Vec<BinaryTeRule>, ParseError> {
    let record_count = cursor.read_u32()?;
    enforce_u32_limit(
        "access-vector table records",
        record_count,
        limits.max_te_rules,
    )?;
    read_avtab_records(
        cursor,
        record_count,
        limits,
        budget,
        version,
        target_platform,
        type_primary_count,
        types,
        classes,
        conditional,
        decoded_rule_count,
    )
}

#[allow(clippy::too_many_arguments)]
fn read_avtab_records(
    cursor: &mut Cursor<'_>,
    record_count: u32,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    conditional: bool,
    decoded_rule_count: &mut u64,
) -> Result<Vec<BinaryTeRule>, ParseError> {
    enforce_u32_limit(
        "access-vector rule-list records",
        record_count,
        limits.max_te_rules,
    )?;
    let retained_count = usize::try_from(record_count).map_err(|_| ParseError::LimitExceeded {
        resource: "access-vector rule-list records",
        requested: u64::MAX,
        limit: u64::from(limits.max_te_rules),
    })?;
    let minimum_decoded_count = decoded_rule_count
        .checked_add(u64::from(record_count))
        .ok_or(ParseError::LimitExceeded {
            resource: "decoded type-enforcement rules",
            requested: u64::MAX,
            limit: u64::from(limits.max_te_rules),
        })?;
    if minimum_decoded_count > u64::from(limits.max_te_rules) {
        return Err(ParseError::LimitExceeded {
            resource: "decoded type-enforcement rules",
            requested: minimum_decoded_count,
            limit: u64::from(limits.max_te_rules),
        });
    }
    let mut rules = Vec::new();
    reserve_exact(&mut rules, retained_count, budget, "type-enforcement rules")?;
    for _ in 0..record_count {
        if version < POLICY_VERSION_AVTAB {
            read_legacy_avtab_record(
                cursor,
                limits,
                budget,
                version,
                target_platform,
                type_primary_count,
                types,
                classes,
                conditional,
                decoded_rule_count,
                &mut rules,
            )?;
        } else {
            let rule = read_modern_avtab_record(
                cursor,
                budget,
                version,
                target_platform,
                type_primary_count,
                types,
                classes,
                conditional,
            )?;
            push_decoded_rule(&mut rules, rule, limits, budget, decoded_rule_count)?;
        }
    }
    Ok(rules)
}

#[allow(clippy::too_many_arguments)]
fn read_legacy_avtab_record(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    conditional: bool,
    decoded_rule_count: &mut u64,
    rules: &mut Vec<BinaryTeRule>,
) -> Result<(), ParseError> {
    let item_count = cursor.read_u32()?;
    if !(5..=8).contains(&item_count) {
        return Err(ParseError::InvalidAvtab(
            "legacy record item count is outside 5..=8",
        ));
    }
    let source = cursor.read_u32()?;
    let target = cursor.read_u32()?;
    let target_class = cursor.read_u32()?;
    if source > u32::from(u16::MAX)
        || target > u32::from(u16::MAX)
        || target_class > u32::from(u16::MAX)
    {
        return Err(ParseError::InvalidAvtab(
            "legacy rule key does not fit the kernel 16-bit fields",
        ));
    }
    let raw_specified = cursor.read_u32()?;
    let specified = raw_specified & !AVTAB_ENABLED_OLD;
    if specified & !(AVTAB_AV | AVTAB_TYPE) != 0 {
        return Err(ParseError::InvalidAvtab(
            "legacy record contains an unsupported rule specifier",
        ));
    }
    if specified & AVTAB_AV == 0 && specified & AVTAB_TYPE == 0 {
        return Err(ParseError::InvalidAvtab("legacy record has no rule kind"));
    }
    if specified & AVTAB_AV != 0 && specified & AVTAB_TYPE != 0 {
        return Err(ParseError::InvalidAvtab(
            "legacy record mixes access-vector and type rules",
        ));
    }
    let datum_count = specified.count_ones();
    if item_count != 4 + datum_count {
        return Err(ParseError::InvalidAvtab(
            "legacy record item count does not match its rule specifiers",
        ));
    }
    for raw_kind in [
        AVTAB_ALLOWED,
        AVTAB_AUDITDENY,
        AVTAB_AUDITALLOW,
        AVTAB_TRANSITION,
        AVTAB_CHANGE,
        AVTAB_MEMBER,
    ] {
        if specified & raw_kind == 0 {
            continue;
        }
        let datum = cursor.read_u32()?;
        let rule = build_avtab_rule(
            raw_kind,
            source,
            target,
            target_class,
            Some(datum),
            None,
            budget,
            version,
            target_platform,
            type_primary_count,
            types,
            classes,
            conditional,
        )?;
        push_decoded_rule(rules, rule, limits, budget, decoded_rule_count)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_modern_avtab_record(
    cursor: &mut Cursor<'_>,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    conditional: bool,
) -> Result<BinaryTeRule, ParseError> {
    let source = u32::from(cursor.read_u16()?);
    let target = u32::from(cursor.read_u16()?);
    let target_class = u32::from(cursor.read_u16()?);
    let raw_specified = u32::from(cursor.read_u16()?);
    if raw_specified & !(AVTAB_AV | AVTAB_TYPE | AVTAB_XPERMS | AVTAB_ENABLED) != 0 {
        return Err(ParseError::InvalidAvtab(
            "record contains an unsupported rule specifier",
        ));
    }
    let specified = raw_specified & !AVTAB_ENABLED;
    if specified.count_ones() != 1 {
        return Err(ParseError::InvalidAvtab(
            "record must contain exactly one rule specifier",
        ));
    }
    if specified & AVTAB_XPERMS != 0 {
        let xperm_kind = cursor.read_u8()?;
        let driver = cursor.read_u8()?;
        let mut permissions = [0_u32; 8];
        for word in &mut permissions {
            *word = cursor.read_u32()?;
        }
        build_avtab_rule(
            specified,
            source,
            target,
            target_class,
            None,
            Some((xperm_kind, driver, permissions)),
            budget,
            version,
            target_platform,
            type_primary_count,
            types,
            classes,
            conditional,
        )
    } else {
        let datum = cursor.read_u32()?;
        build_avtab_rule(
            specified,
            source,
            target,
            target_class,
            Some(datum),
            None,
            budget,
            version,
            target_platform,
            type_primary_count,
            types,
            classes,
            conditional,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn build_avtab_rule(
    raw_kind: u32,
    source: u32,
    target: u32,
    target_class: u32,
    datum: Option<u32>,
    xperms: Option<(u8, u8, [u32; 8])>,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    conditional: bool,
) -> Result<BinaryTeRule, ParseError> {
    validate_avtab_type_reference("source", source, version, type_primary_count, types, false)?;
    validate_avtab_type_reference("target", target, version, type_primary_count, types, false)?;
    validate_symbol_value("TE target class", target_class, classes.len() as u32)?;
    let target_class_record = &classes[(target_class - 1) as usize];
    let kind = parse_te_rule_kind(raw_kind)?;
    let data = if raw_kind & AVTAB_AV != 0 {
        let datum = datum.ok_or(ParseError::InvalidAvtab(
            "access-vector rule has no permission datum",
        ))?;
        let permission_mask = if raw_kind == AVTAB_AUDITDENY {
            !datum
        } else {
            datum
        };
        let valid_mask = permission_mask_for(target_class_record.permission_count);
        let permission_mask = permission_mask & valid_mask;
        if permission_mask == 0 {
            return Err(ParseError::InvalidAvtab(
                "access-vector rule has no valid target-class permissions",
            ));
        }
        BinaryTeRuleData::Permissions(bitmap_word_indices(
            permission_mask,
            budget,
            "type-enforcement permission IDs",
        )?)
    } else if raw_kind & AVTAB_TYPE != 0 {
        validate_avtab_type_reference("source", source, version, type_primary_count, types, true)?;
        validate_avtab_type_reference("target", target, version, type_primary_count, types, true)?;
        let default_type = datum.ok_or(ParseError::InvalidAvtab(
            "type rule has no default type datum",
        ))?;
        validate_avtab_type_reference(
            "default",
            default_type,
            version,
            type_primary_count,
            types,
            true,
        )?;
        BinaryTeRuleData::DefaultType(default_type)
    } else if raw_kind & AVTAB_XPERMS != 0 {
        if version < POLICY_VERSION_XPERMS_IOCTL {
            return Err(ParseError::InvalidAvtab(
                "extended permissions require policy version 30 or newer",
            ));
        }
        if target_platform != TargetPlatform::Selinux {
            return Err(ParseError::InvalidAvtab(
                "extended permissions are unsupported for this target",
            ));
        }
        if conditional && version < POLICY_VERSION_COND_XPERMS {
            return Err(ParseError::InvalidAvtab(
                "conditional extended permissions require policy version 34 or newer",
            ));
        }
        let (specified, driver, permissions) = xperms.ok_or(ParseError::InvalidAvtab(
            "extended-permission rule has no payload",
        ))?;
        let (kind, values) = decode_xperm_values(specified, driver, permissions, budget)?;
        BinaryTeRuleData::ExtendedPermissions { kind, values }
    } else {
        return Err(ParseError::InvalidAvtab("unsupported rule kind"));
    };
    Ok(BinaryTeRule {
        kind,
        source,
        target,
        target_class,
        data,
    })
}

fn validate_avtab_type_reference(
    relation: &'static str,
    value: u32,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    concrete: bool,
) -> Result<(), ParseError> {
    validate_symbol_value("TE type or attribute", value, type_primary_count)?;
    match types.binary_search_by_key(&value, |entry| entry.value) {
        Ok(index) if !concrete || types[index].kind == BinaryTypeKind::Type => Ok(()),
        Ok(_) => Err(ParseError::InvalidAvtab(match relation {
            "source" => "type rule source resolves to an attribute",
            "target" => "type rule target resolves to an attribute",
            _ => "type rule default resolves to an attribute",
        })),
        Err(_) if !concrete && (20..=POLICY_VERSION_PERMISSIVE).contains(&version) => Ok(()),
        Err(_) => Err(ParseError::InvalidAvtab(match relation {
            "source" => "rule source does not resolve to a symbol",
            "target" => "rule target does not resolve to a symbol",
            _ => "rule default does not resolve to a concrete type",
        })),
    }
}

const fn permission_mask_for(permission_count: u32) -> u32 {
    if permission_count >= 32 {
        u32::MAX
    } else if permission_count == 0 {
        0
    } else {
        (1_u32 << permission_count) - 1
    }
}

fn bitmap_word_indices(
    bitmap: u32,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<Vec<u32>, ParseError> {
    let count = bitmap.count_ones() as usize;
    let mut values = Vec::new();
    reserve_exact(&mut values, count, budget, resource)?;
    for bit in 0..32 {
        if bitmap & (1_u32 << bit) != 0 {
            values.push(bit);
        }
    }
    Ok(values)
}

fn parse_te_rule_kind(raw_kind: u32) -> Result<TeRuleKind, ParseError> {
    match raw_kind {
        AVTAB_ALLOWED => Ok(TeRuleKind::Allow),
        AVTAB_AUDITALLOW => Ok(TeRuleKind::AuditAllow),
        AVTAB_AUDITDENY => Ok(TeRuleKind::DontAudit),
        AVTAB_TRANSITION => Ok(TeRuleKind::TypeTransition),
        AVTAB_MEMBER => Ok(TeRuleKind::TypeMember),
        AVTAB_CHANGE => Ok(TeRuleKind::TypeChange),
        AVTAB_XPERMS_ALLOWED => Ok(TeRuleKind::AllowXperm),
        AVTAB_XPERMS_AUDITALLOW => Ok(TeRuleKind::AuditAllowXperm),
        AVTAB_XPERMS_DONTAUDIT => Ok(TeRuleKind::DontAuditXperm),
        _ => Err(ParseError::InvalidAvtab("unknown rule kind")),
    }
}

fn decode_xperm_values(
    specified: u8,
    driver: u8,
    permissions: [u32; 8],
    budget: &mut AllocationBudget,
) -> Result<(XpermKind, Vec<u16>), ParseError> {
    let kind = match specified {
        AVTAB_XPERMS_IOCTLFUNCTION | AVTAB_XPERMS_IOCTLDRIVER => XpermKind::Ioctl,
        AVTAB_XPERMS_NLMSG => XpermKind::NetlinkMessage,
        _ => {
            return Err(ParseError::InvalidAvtab(
                "extended-permission payload has an unknown namespace",
            ));
        }
    };
    let bit_count = permissions
        .iter()
        .map(|word| word.count_ones())
        .sum::<u32>();
    let value_count = if specified == AVTAB_XPERMS_IOCTLDRIVER {
        bit_count.checked_mul(256)
    } else {
        Some(bit_count)
    }
    .ok_or(ParseError::LimitExceeded {
        resource: "expanded extended-permission values",
        requested: u64::MAX,
        limit: u64::from(u16::MAX) + 1,
    })?;
    if value_count == 0 {
        return Err(ParseError::InvalidAvtab(
            "extended-permission rule has no values",
        ));
    }
    let value_count = usize::try_from(value_count).map_err(|_| ParseError::LimitExceeded {
        resource: "expanded extended-permission values",
        requested: u64::MAX,
        limit: u64::from(u16::MAX) + 1,
    })?;
    let mut values = Vec::new();
    reserve_exact(
        &mut values,
        value_count,
        budget,
        "expanded extended-permission values",
    )?;
    for bit in 0_u16..256 {
        if permissions[usize::from(bit / 32)] & (1_u32 << (bit % 32)) == 0 {
            continue;
        }
        if specified == AVTAB_XPERMS_IOCTLDRIVER {
            let base = bit << 8;
            values.extend(base..=base | 0x00ff);
        } else {
            values.push((u16::from(driver) << 8) | bit);
        }
    }
    Ok((kind, values))
}

fn push_decoded_rule(
    rules: &mut Vec<BinaryTeRule>,
    rule: BinaryTeRule,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    decoded_rule_count: &mut u64,
) -> Result<(), ParseError> {
    *decoded_rule_count = decoded_rule_count
        .checked_add(1)
        .ok_or(ParseError::LimitExceeded {
            resource: "decoded type-enforcement rules",
            requested: u64::MAX,
            limit: u64::from(limits.max_te_rules),
        })?;
    if *decoded_rule_count > u64::from(limits.max_te_rules) {
        return Err(ParseError::LimitExceeded {
            resource: "decoded type-enforcement rules",
            requested: *decoded_rule_count,
            limit: u64::from(limits.max_te_rules),
        });
    }
    if rules.len() == rules.capacity() {
        reserve_additional(rules, 1, budget, "type-enforcement rules")?;
    }
    rules.push(rule);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_conditionals(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    booleans: &[BinaryBooleanSymbol],
    decoded_rule_count: &mut u64,
) -> Result<Vec<BinaryConditional>, ParseError> {
    let count = cursor.read_u32()?;
    enforce_u32_limit("Boolean conditionals", count, limits.max_conditionals)?;
    let retained_count = usize::try_from(count).map_err(|_| ParseError::LimitExceeded {
        resource: "Boolean conditionals",
        requested: u64::MAX,
        limit: u64::from(limits.max_conditionals),
    })?;
    let mut conditionals = Vec::new();
    reserve_exact(
        &mut conditionals,
        retained_count,
        budget,
        "Boolean conditionals",
    )?;
    for _ in 0..count {
        let current_state = match cursor.read_u32()? {
            0 => false,
            1 => true,
            _ => {
                return Err(ParseError::InvalidConditional(
                    "current state is not zero or one",
                ));
            }
        };
        let tokens = read_conditional_tokens(cursor, limits, budget, booleans)?;
        let true_rules = read_avtab(
            cursor,
            limits,
            budget,
            version,
            target_platform,
            type_primary_count,
            types,
            classes,
            true,
            decoded_rule_count,
        )?;
        let false_rules = read_avtab(
            cursor,
            limits,
            budget,
            version,
            target_platform,
            type_primary_count,
            types,
            classes,
            true,
            decoded_rule_count,
        )?;
        conditionals.push(BinaryConditional {
            current_state,
            tokens,
            true_rules,
            false_rules,
        });
    }
    Ok(conditionals)
}

fn read_conditional_tokens(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    booleans: &[BinaryBooleanSymbol],
) -> Result<Vec<ConditionalToken>, ParseError> {
    let count = cursor.read_u32()?;
    if count == 0 {
        return Err(ParseError::InvalidConditional("expression is empty"));
    }
    enforce_u32_limit(
        "tokens per Boolean conditional",
        count,
        limits.max_conditional_tokens,
    )?;
    let retained_count = usize::try_from(count).map_err(|_| ParseError::LimitExceeded {
        resource: "tokens per Boolean conditional",
        requested: u64::MAX,
        limit: u64::from(limits.max_conditional_tokens),
    })?;
    let mut tokens = Vec::new();
    reserve_exact(
        &mut tokens,
        retained_count,
        budget,
        "Boolean conditional tokens",
    )?;
    let mut stack_depth = 0_u32;
    for _ in 0..count {
        let expression_kind = cursor.read_u32()?;
        let boolean = cursor.read_u32()?;
        let token = match expression_kind {
            1 => {
                validate_symbol_value("conditional Boolean", boolean, booleans.len() as u32)?;
                if stack_depth >= CONDITIONAL_EXPRESSION_MAX_DEPTH {
                    return Err(ParseError::InvalidConditional(
                        "expression exceeds the postfix stack depth",
                    ));
                }
                stack_depth += 1;
                ConditionalToken::Boolean(BooleanId::from_raw(boolean - 1))
            }
            2 => {
                validate_conditional_operator(boolean, stack_depth, false)?;
                ConditionalToken::Not
            }
            3 => {
                validate_conditional_operator(boolean, stack_depth, true)?;
                stack_depth -= 1;
                ConditionalToken::Or
            }
            4 => {
                validate_conditional_operator(boolean, stack_depth, true)?;
                stack_depth -= 1;
                ConditionalToken::And
            }
            5 => {
                validate_conditional_operator(boolean, stack_depth, true)?;
                stack_depth -= 1;
                ConditionalToken::Xor
            }
            6 => {
                validate_conditional_operator(boolean, stack_depth, true)?;
                stack_depth -= 1;
                ConditionalToken::Equal
            }
            7 => {
                validate_conditional_operator(boolean, stack_depth, true)?;
                stack_depth -= 1;
                ConditionalToken::NotEqual
            }
            _ => {
                return Err(ParseError::InvalidConditional(
                    "expression contains an unknown token kind",
                ));
            }
        };
        tokens.push(token);
    }
    if stack_depth != 1 {
        return Err(ParseError::InvalidConditional(
            "postfix expression does not produce exactly one value",
        ));
    }
    Ok(tokens)
}

fn validate_conditional_operator(
    boolean: u32,
    stack_depth: u32,
    binary: bool,
) -> Result<(), ParseError> {
    if boolean != 0 {
        return Err(ParseError::InvalidConditional(
            "operator token carries a Boolean value",
        ));
    }
    let required = if binary { 2 } else { 1 };
    if stack_depth < required {
        return Err(ParseError::InvalidConditional(
            "postfix operator has too few operands",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_rbac_rules(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    target_platform: TargetPlatform,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
    roles: &[RoleSymbol],
) -> Result<Vec<BinaryRbacRule>, ParseError> {
    let transition_count = cursor.read_u32()?;
    enforce_u32_limit(
        "role-transition rules",
        transition_count,
        limits.max_rbac_rules,
    )?;
    let retained_count =
        usize::try_from(transition_count).map_err(|_| ParseError::LimitExceeded {
            resource: "role-transition rules",
            requested: u64::MAX,
            limit: u64::from(limits.max_rbac_rules),
        })?;
    let mut rules = Vec::new();
    reserve_exact(&mut rules, retained_count, budget, "RBAC rules")?;
    let implicit_class = if version < POLICY_VERSION_ROLE_TRANSITION_CLASS && transition_count != 0
    {
        let name = match target_platform {
            TargetPlatform::Selinux => "process",
            TargetPlatform::Xen => "domain",
        };
        classes
            .iter()
            .find(|target_class| target_class.name == name)
            .map(|target_class| target_class.value)
            .ok_or(ParseError::InvalidRbac(
                "an old-format role transition has no implicit process class",
            ))?
    } else {
        0
    };
    for _ in 0..transition_count {
        let source = cursor.read_u32()?;
        let target = cursor.read_u32()?;
        let default = cursor.read_u32()?;
        let target_class = if version >= POLICY_VERSION_ROLE_TRANSITION_CLASS {
            cursor.read_u32()?
        } else {
            implicit_class
        };
        validate_symbol_value("RBAC source role", source, roles.len() as u32)?;
        validate_rbac_type_reference(target, version, type_primary_count, types)?;
        validate_symbol_value("RBAC target class", target_class, classes.len() as u32)?;
        validate_symbol_value("RBAC default role", default, roles.len() as u32)?;
        rules.push(BinaryRbacRule {
            source,
            data: BinaryRbacRuleData::RoleTransition {
                target,
                target_class,
                default,
            },
        });
    }

    let allow_count = cursor.read_u32()?;
    let total_count =
        transition_count
            .checked_add(allow_count)
            .ok_or(ParseError::LimitExceeded {
                resource: "RBAC rules",
                requested: u64::MAX,
                limit: u64::from(limits.max_rbac_rules),
            })?;
    enforce_u32_limit("RBAC rules", total_count, limits.max_rbac_rules)?;
    let allow_count = usize::try_from(allow_count).map_err(|_| ParseError::LimitExceeded {
        resource: "role-allow rules",
        requested: u64::MAX,
        limit: u64::from(limits.max_rbac_rules),
    })?;
    reserve_additional(&mut rules, allow_count, budget, "RBAC rules")?;
    for _ in 0..allow_count {
        let source = cursor.read_u32()?;
        let target = cursor.read_u32()?;
        validate_symbol_value("RBAC source role", source, roles.len() as u32)?;
        validate_symbol_value("RBAC target role", target, roles.len() as u32)?;
        rules.push(BinaryRbacRule {
            source,
            data: BinaryRbacRuleData::Allow { target },
        });
    }
    Ok(rules)
}

fn validate_rbac_type_reference(
    value: u32,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
) -> Result<(), ParseError> {
    validate_symbol_value("RBAC target type or attribute", value, type_primary_count)?;
    match types.binary_search_by_key(&value, |entry| entry.value) {
        Ok(_) => Ok(()),
        Err(_) if (20..=POLICY_VERSION_PERMISSIVE).contains(&version) => Ok(()),
        Err(_) => Err(ParseError::InvalidRbac(
            "target does not resolve to a type or attribute",
        )),
    }
}

#[derive(Debug)]
struct CompatFilenameTransition {
    serialized_order: u32,
    rule: BinaryFilenameTransition,
}

#[allow(clippy::too_many_arguments)]
fn read_filename_transitions(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
) -> Result<Vec<BinaryFilenameTransition>, ParseError> {
    if version < POLICY_VERSION_COMPRESSED_FILENAME_TRANSITION {
        read_compat_filename_transitions(
            cursor,
            limits,
            budget,
            version,
            type_primary_count,
            types,
            classes,
        )
    } else {
        read_compressed_filename_transitions(
            cursor,
            limits,
            budget,
            version,
            type_primary_count,
            types,
            classes,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn read_compat_filename_transitions(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
) -> Result<Vec<BinaryFilenameTransition>, ParseError> {
    let record_count = cursor.read_u32()?;
    enforce_u32_limit(
        "filename-transition records",
        record_count,
        limits.max_filename_transition_records,
    )?;
    enforce_u32_limit(
        "decoded filename transitions",
        record_count,
        limits.max_filename_transitions,
    )?;
    let count = usize::try_from(record_count).map_err(|_| ParseError::LimitExceeded {
        resource: "filename-transition records",
        requested: u64::MAX,
        limit: u64::from(limits.max_filename_transition_records),
    })?;
    let mut candidates = Vec::new();
    reserve_exact(
        &mut candidates,
        count,
        budget,
        "compat filename transitions",
    )?;
    for serialized_order in 0..record_count {
        let filename_length = cursor.read_u32()?;
        let filename = read_symbol_name(
            cursor,
            filename_length,
            limits,
            budget,
            "filename transition path component",
        )?;
        let source = cursor.read_u32()?;
        let target = cursor.read_u32()?;
        let target_class = cursor.read_u32()?;
        let default_type = cursor.read_u32()?;
        validate_filename_transition_references(
            source,
            target,
            target_class,
            default_type,
            version,
            type_primary_count,
            types,
            classes,
        )?;
        candidates.push(CompatFilenameTransition {
            serialized_order,
            rule: BinaryFilenameTransition {
                source,
                target,
                target_class,
                default_type,
                filename,
            },
        });
    }

    candidates.sort_unstable_by(|left, right| {
        filename_transition_identity_cmp(&left.rule, &right.rule)
            .then_with(|| left.serialized_order.cmp(&right.serialized_order))
    });
    candidates
        .dedup_by(|right, left| filename_transition_identity_cmp(&left.rule, &right.rule).is_eq());
    let mut rules = Vec::new();
    reserve_exact(
        &mut rules,
        candidates.len(),
        budget,
        "decoded filename transitions",
    )?;
    rules.extend(candidates.into_iter().map(|candidate| candidate.rule));
    Ok(rules)
}

#[allow(clippy::too_many_arguments)]
fn read_compressed_filename_transitions(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
) -> Result<Vec<BinaryFilenameTransition>, ParseError> {
    let record_count = cursor.read_u32()?;
    enforce_u32_limit(
        "compressed filename-transition records",
        record_count,
        limits.max_filename_transition_records,
    )?;
    let record_count_usize =
        usize::try_from(record_count).map_err(|_| ParseError::LimitExceeded {
            resource: "compressed filename-transition records",
            requested: u64::MAX,
            limit: u64::from(limits.max_filename_transition_records),
        })?;
    let mut group_keys = Vec::new();
    reserve_exact(
        &mut group_keys,
        record_count_usize,
        budget,
        "compressed filename-transition keys",
    )?;
    let mut rules = Vec::new();
    for _ in 0..record_count {
        let filename_length = cursor.read_u32()?;
        let filename = read_symbol_name(
            cursor,
            filename_length,
            limits,
            budget,
            "filename transition path component",
        )?;
        let target = cursor.read_u32()?;
        let target_class = cursor.read_u32()?;
        let datum_count = cursor.read_u32()?;
        if datum_count == 0 {
            return Err(ParseError::InvalidFilenameTransition(
                "a compressed record has no datum",
            ));
        }
        enforce_u32_limit(
            "filename-transition datums",
            datum_count,
            limits.max_filename_transition_datums,
        )?;
        validate_filename_type_reference(
            "target",
            target,
            version,
            type_primary_count,
            types,
            false,
        )?;
        validate_symbol_value(
            "filename-transition target class",
            target_class,
            classes.len() as u32,
        )?;
        let key_filename = clone_retained_string(
            &filename,
            budget,
            "compressed filename-transition key names",
        )?;
        group_keys.push((target, target_class, key_filename));

        let datum_count_usize =
            usize::try_from(datum_count).map_err(|_| ParseError::LimitExceeded {
                resource: "filename-transition datums",
                requested: u64::MAX,
                limit: u64::from(limits.max_filename_transition_datums),
            })?;
        let mut defaults = Vec::new();
        reserve_exact(
            &mut defaults,
            datum_count_usize,
            budget,
            "filename-transition datum defaults",
        )?;
        let record_start = rules.len();
        for _ in 0..datum_count {
            let sources =
                read_bitmap_bits(cursor, limits, budget, "filename-transition source bitmap")?;
            let default_type = cursor.read_u32()?;
            validate_filename_type_reference(
                "default",
                default_type,
                version,
                type_primary_count,
                types,
                true,
            )?;
            defaults.push(default_type);
            for source in sources {
                let source = source
                    .checked_add(1)
                    .ok_or(ParseError::InvalidFilenameTransition(
                        "a source bitmap value overflows",
                    ))?;
                validate_filename_type_reference(
                    "source",
                    source,
                    version,
                    type_primary_count,
                    types,
                    false,
                )?;
                push_filename_transition(
                    &mut rules,
                    BinaryFilenameTransition {
                        source,
                        target,
                        target_class,
                        default_type,
                        filename: clone_retained_string(
                            &filename,
                            budget,
                            "filename-transition names",
                        )?,
                    },
                    limits,
                    budget,
                )?;
            }
        }
        if datum_count > 1 {
            defaults.sort_unstable();
            if defaults.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(ParseError::InvalidFilenameTransition(
                    "compressed datums repeat a default type",
                ));
            }
            rules[record_start..].sort_unstable_by_key(|rule| rule.source);
            if rules[record_start..]
                .windows(2)
                .any(|pair| pair[0].source == pair[1].source)
            {
                return Err(ParseError::InvalidFilenameTransition(
                    "compressed datum source bitmaps overlap",
                ));
            }
        }
    }

    group_keys.sort_unstable();
    if group_keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ParseError::InvalidFilenameTransition(
            "compressed records repeat a filename/target/class key",
        ));
    }
    rules.sort_unstable_by(filename_transition_total_cmp);
    Ok(rules)
}

fn push_filename_transition(
    rules: &mut Vec<BinaryFilenameTransition>,
    rule: BinaryFilenameTransition,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<(), ParseError> {
    let requested = rules
        .len()
        .checked_add(1)
        .ok_or(ParseError::LimitExceeded {
            resource: "decoded filename transitions",
            requested: u64::MAX,
            limit: u64::from(limits.max_filename_transitions),
        })?;
    enforce_usize_limit(
        "decoded filename transitions",
        requested,
        limits.max_filename_transitions as usize,
    )?;
    if rules.len() == rules.capacity() {
        reserve_additional(rules, 1, budget, "decoded filename transitions")?;
    }
    rules.push(rule);
    Ok(())
}

fn clone_retained_string(
    value: &str,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<String, ParseError> {
    budget.charge(value.len(), resource)?;
    let mut cloned = String::new();
    cloned
        .try_reserve_exact(value.len())
        .map_err(|_| ParseError::AllocationFailed {
            resource,
            requested: value.len(),
        })?;
    cloned.push_str(value);
    Ok(cloned)
}

#[allow(clippy::too_many_arguments)]
fn validate_filename_transition_references(
    source: u32,
    target: u32,
    target_class: u32,
    default_type: u32,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    classes: &[ClassSymbol],
) -> Result<(), ParseError> {
    validate_filename_type_reference("source", source, version, type_primary_count, types, false)?;
    validate_filename_type_reference("target", target, version, type_primary_count, types, false)?;
    validate_symbol_value(
        "filename-transition target class",
        target_class,
        classes.len() as u32,
    )?;
    validate_filename_type_reference(
        "default",
        default_type,
        version,
        type_primary_count,
        types,
        true,
    )
}

fn validate_filename_type_reference(
    relation: &'static str,
    value: u32,
    version: u32,
    type_primary_count: u32,
    types: &[BinaryTypeSymbol],
    concrete: bool,
) -> Result<(), ParseError> {
    validate_symbol_value(
        "filename-transition type or attribute",
        value,
        type_primary_count,
    )?;
    match types.binary_search_by_key(&value, |entry| entry.value) {
        Ok(index) if !concrete || types[index].kind == BinaryTypeKind::Type => Ok(()),
        Ok(_) => Err(ParseError::InvalidFilenameTransition(
            "default resolves to an attribute",
        )),
        Err(_) if !concrete && (20..=POLICY_VERSION_PERMISSIVE).contains(&version) => Ok(()),
        Err(_) => Err(ParseError::InvalidFilenameTransition(match relation {
            "source" => "source does not resolve to a type or attribute",
            "target" => "target does not resolve to a type or attribute",
            _ => "default does not resolve to a concrete type",
        })),
    }
}

fn filename_transition_identity_cmp(
    left: &BinaryFilenameTransition,
    right: &BinaryFilenameTransition,
) -> std::cmp::Ordering {
    left.target
        .cmp(&right.target)
        .then_with(|| left.target_class.cmp(&right.target_class))
        .then_with(|| left.filename.cmp(&right.filename))
        .then_with(|| left.source.cmp(&right.source))
}

fn filename_transition_total_cmp(
    left: &BinaryFilenameTransition,
    right: &BinaryFilenameTransition,
) -> std::cmp::Ordering {
    filename_transition_identity_cmp(left, right)
        .then_with(|| left.default_type.cmp(&right.default_type))
}

struct ContextSymbols<'a> {
    version: u32,
    mls: bool,
    type_primary_count: u32,
    types: &'a [BinaryTypeSymbol],
    roles: &'a [RoleSymbol],
    users: &'a [UserSymbol],
    sensitivities: &'a [SensitivitySymbol],
    categories: &'a [CategorySymbol],
}

#[allow(clippy::too_many_arguments)]
fn read_object_contexts(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    target: TargetPlatform,
    family_count: u32,
    symbols: &ContextSymbols<'_>,
) -> Result<Vec<BinaryLabelingRule>, ParseError> {
    let mut rules = Vec::new();
    let mut decoded_count = 0_u32;
    for family in 0..family_count {
        let count = cursor.read_u32()?;
        decoded_count = decoded_count
            .checked_add(count)
            .ok_or(ParseError::LimitExceeded {
                resource: "object contexts",
                requested: u64::MAX,
                limit: u64::from(limits.max_object_contexts),
            })?;
        enforce_u32_limit("object contexts", decoded_count, limits.max_object_contexts)?;
        let count = usize::try_from(count).map_err(|_| ParseError::LimitExceeded {
            resource: "object contexts",
            requested: u64::MAX,
            limit: u64::from(limits.max_object_contexts),
        })?;
        reserve_additional(&mut rules, count, budget, "object contexts")?;
        for _ in 0..count {
            let rule = match target {
                TargetPlatform::Selinux => {
                    read_selinux_object_context(cursor, limits, budget, family, symbols)?
                }
                TargetPlatform::Xen => {
                    read_xen_object_context(cursor, limits, budget, family, symbols)?
                }
            };
            rules.push(rule);
        }
    }
    Ok(rules)
}

fn read_selinux_object_context(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    family: u32,
    symbols: &ContextSymbols<'_>,
) -> Result<BinaryLabelingRule, ParseError> {
    match family {
        0 => {
            let sid = cursor.read_u32()?;
            if !(1..28).contains(&sid) {
                return Err(ParseError::InvalidObjectContext(
                    "SELinux initial SID is outside the kernel namespace",
                ));
            }
            Ok(BinaryLabelingRule::InitialSid {
                sid,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        1 => {
            let filesystem =
                read_short_object_name(cursor, limits, budget, "filesystem context name")?;
            Ok(BinaryLabelingRule::FsContext {
                filesystem,
                filesystem_context: read_security_context(cursor, limits, budget, symbols)?,
                root_context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        2 => {
            let protocol = cursor.read_u32()?;
            if !matches!(protocol, 6 | 17 | 33 | 132) {
                return Err(ParseError::InvalidObjectContext(
                    "portcon uses an unsupported IP protocol",
                ));
            }
            let low = u16::try_from(cursor.read_u32()?).map_err(|_| {
                ParseError::InvalidObjectContext("portcon low port exceeds 16 bits")
            })?;
            let high = u16::try_from(cursor.read_u32()?).map_err(|_| {
                ParseError::InvalidObjectContext("portcon high port exceeds 16 bits")
            })?;
            if low > high {
                return Err(ParseError::InvalidObjectContext(
                    "portcon low port exceeds high port",
                ));
            }
            Ok(BinaryLabelingRule::Portcon {
                protocol,
                low,
                high,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        3 => {
            let interface =
                read_short_object_name(cursor, limits, budget, "network interface name")?;
            Ok(BinaryLabelingRule::Netifcon {
                interface,
                interface_context: read_security_context(cursor, limits, budget, symbols)?,
                packet_context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        4 => {
            let address = IpAddr::V4(read_ipv4(cursor)?);
            let mask = IpAddr::V4(read_ipv4(cursor)?);
            Ok(BinaryLabelingRule::Nodecon {
                address,
                mask,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        5 => {
            let behavior = cursor.read_u32()?;
            if !matches!(behavior, 1..=3) {
                return Err(ParseError::InvalidObjectContext(
                    "fs_use behavior is neither xattr, transition, nor task",
                ));
            }
            let length = cursor.read_u32()?;
            let filesystem =
                read_symbol_name(cursor, length, limits, budget, "fs_use filesystem name")?;
            Ok(BinaryLabelingRule::FsUse {
                behavior,
                filesystem,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        6 => {
            let address = IpAddr::V6(read_ipv6(cursor)?);
            let mask = IpAddr::V6(read_ipv6(cursor)?);
            Ok(BinaryLabelingRule::Nodecon {
                address,
                mask,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        7 => {
            let prefix = cursor.read_bytes(8)?;
            let mut address = [0_u8; 16];
            address[..8].copy_from_slice(prefix);
            let low = u16::try_from(cursor.read_u32()?).map_err(|_| {
                ParseError::InvalidObjectContext("ibpkeycon low key exceeds 16 bits")
            })?;
            let high = u16::try_from(cursor.read_u32()?).map_err(|_| {
                ParseError::InvalidObjectContext("ibpkeycon high key exceeds 16 bits")
            })?;
            if low > high {
                return Err(ParseError::InvalidObjectContext(
                    "ibpkeycon low key exceeds high key",
                ));
            }
            Ok(BinaryLabelingRule::Ibpkeycon {
                subnet_prefix: Ipv6Addr::from(address),
                low,
                high,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        8 => {
            let length = cursor.read_u32()?;
            let port = u8::try_from(cursor.read_u32()?).map_err(|_| {
                ParseError::InvalidObjectContext("ibendportcon port exceeds 8 bits")
            })?;
            if port == 0 {
                return Err(ParseError::InvalidObjectContext(
                    "ibendportcon port is zero",
                ));
            }
            if length == 0 || length > 63 {
                return Err(ParseError::InvalidObjectContext(
                    "InfiniBand device name length is outside 1..=63",
                ));
            }
            let device =
                read_symbol_name(cursor, length, limits, budget, "InfiniBand device name")?;
            Ok(BinaryLabelingRule::Ibendportcon {
                device,
                port,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        _ => Err(ParseError::InvalidObjectContext(
            "unknown SELinux object-context family",
        )),
    }
}

fn read_xen_object_context(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    family: u32,
    symbols: &ContextSymbols<'_>,
) -> Result<BinaryLabelingRule, ParseError> {
    match family {
        0 => {
            let sid = cursor.read_u32()?;
            if !(1..13).contains(&sid) {
                return Err(ParseError::InvalidObjectContext(
                    "Xen initial SID is outside the kernel namespace",
                ));
            }
            Ok(BinaryLabelingRule::InitialSid {
                sid,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        1 => {
            let irq = u16::try_from(cursor.read_u32()?)
                .map_err(|_| ParseError::InvalidObjectContext("Xen PIRQ value exceeds 16 bits"))?;
            Ok(BinaryLabelingRule::Pirqcon {
                irq,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        2 => {
            let low = cursor.read_u32()?;
            let high = cursor.read_u32()?;
            if low > high {
                return Err(ParseError::InvalidObjectContext(
                    "Xen I/O-port low value exceeds high value",
                ));
            }
            Ok(BinaryLabelingRule::Ioportcon {
                low,
                high,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        3 => {
            let (low, high) = if symbols.version >= POLICY_VERSION_XEN_DEVICETREE {
                (cursor.read_u64()?, cursor.read_u64()?)
            } else {
                (u64::from(cursor.read_u32()?), u64::from(cursor.read_u32()?))
            };
            if low > high {
                return Err(ParseError::InvalidObjectContext(
                    "Xen I/O-memory low value exceeds high value",
                ));
            }
            Ok(BinaryLabelingRule::Iomemcon {
                low,
                high,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        4 => Ok(BinaryLabelingRule::Pcidevicecon {
            device: cursor.read_u32()?,
            context: read_security_context(cursor, limits, budget, symbols)?,
        }),
        5 => {
            let length = cursor.read_u32()?;
            let path = read_symbol_name(cursor, length, limits, budget, "Xen device-tree path")?;
            Ok(BinaryLabelingRule::Devicetreecon {
                path,
                context: read_security_context(cursor, limits, budget, symbols)?,
            })
        }
        _ => Err(ParseError::InvalidObjectContext(
            "unknown Xen object-context family",
        )),
    }
}

fn read_short_object_name(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    field: &'static str,
) -> Result<String, ParseError> {
    let length = cursor.read_u32()?;
    if length > 63 {
        return Err(ParseError::InvalidObjectContext(
            "object name length exceeds its fixed 63-byte bound",
        ));
    }
    read_symbol_name(cursor, length, limits, budget, field)
}

fn read_ipv4(cursor: &mut Cursor<'_>) -> Result<Ipv4Addr, ParseError> {
    let bytes = cursor.read_bytes(4)?;
    Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn read_ipv6(cursor: &mut Cursor<'_>) -> Result<Ipv6Addr, ParseError> {
    let bytes = cursor.read_bytes(16)?;
    let mut address = [0_u8; 16];
    address.copy_from_slice(bytes);
    Ok(Ipv6Addr::from(address))
}

fn read_security_context(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    symbols: &ContextSymbols<'_>,
) -> Result<BinarySecurityContext, ParseError> {
    let user = cursor.read_u32()?;
    let role = cursor.read_u32()?;
    let type_id = cursor.read_u32()?;
    validate_symbol_value("security-context user", user, symbols.users.len() as u32)?;
    validate_symbol_value("security-context role", role, symbols.roles.len() as u32)?;
    validate_symbol_value("security-context type", type_id, symbols.type_primary_count)?;
    let Ok(type_index) = symbols
        .types
        .binary_search_by_key(&type_id, |entry| entry.value)
    else {
        return Err(ParseError::InvalidSecurityContext(
            "type does not resolve to a named concrete type",
        ));
    };
    if symbols.types[type_index].kind != BinaryTypeKind::Type {
        return Err(ParseError::InvalidSecurityContext(
            "type resolves to an attribute",
        ));
    }
    if role != 1 {
        let role_index = (role - 1) as usize;
        let authorized_types = &symbols.roles[role_index].authorized_types;
        let directly_authorized = authorized_types.binary_search(&(type_id - 1)).is_ok();
        // Attribute membership is serialized after this slice. An authorized
        // attribute can therefore make the context valid, but final proof is
        // deferred until type_attr_map is decoded.
        let may_be_authorized_by_attribute = authorized_types.iter().any(|index| {
            match symbols
                .types
                .binary_search_by_key(&(*index + 1), |entry| entry.value)
            {
                Ok(index) => symbols.types[index].kind == BinaryTypeKind::Attribute,
                Err(_) => (20..=POLICY_VERSION_PERMISSIVE).contains(&symbols.version),
            }
        });
        if !directly_authorized && !may_be_authorized_by_attribute {
            return Err(ParseError::InvalidSecurityContext(
                "role is not authorized for the type",
            ));
        }
        let user_index = (user - 1) as usize;
        if symbols.users[user_index]
            .roles
            .binary_search(&(role - 1))
            .is_err()
        {
            return Err(ParseError::InvalidSecurityContext(
                "user is not authorized for the role",
            ));
        }
    }

    let serialized_range = if symbols.version >= POLICY_VERSION_MLS {
        Some(read_mls_range(
            cursor,
            limits,
            budget,
            "security-context MLS range",
        )?)
    } else {
        None
    };
    let range = if symbols.mls {
        let range = serialized_range.ok_or(ParseError::InvalidSecurityContext(
            "MLS policy context has no serialized range",
        ))?;
        validate_security_context_range(&range, symbols, user, role)?;
        Some(range)
    } else {
        None
    };
    Ok(BinarySecurityContext {
        user,
        role,
        type_id,
        range,
    })
}

fn validate_security_context_range(
    range: &BinaryMlsRange,
    symbols: &ContextSymbols<'_>,
    user: u32,
    role: u32,
) -> Result<(), ParseError> {
    for level in [&range.low, &range.high] {
        if level.sensitivity == 0 || level.sensitivity > symbols.sensitivities.len() as u32 {
            return Err(ParseError::InvalidSecurityContext(
                "MLS sensitivity is outside the policy sensitivity table",
            ));
        }
        if level
            .categories
            .iter()
            .any(|category| *category >= symbols.categories.len() as u32)
        {
            return Err(ParseError::InvalidSecurityContext(
                "MLS category is outside the policy category table",
            ));
        }
        let sensitivity = &symbols.sensitivities[(level.sensitivity - 1) as usize];
        if level
            .categories
            .iter()
            .any(|category| sensitivity.categories.binary_search(category).is_err())
        {
            return Err(ParseError::InvalidSecurityContext(
                "MLS category is not authorized for its sensitivity",
            ));
        }
    }
    if !mls_level_dominates(&range.high, &range.low) {
        return Err(ParseError::InvalidSecurityContext(
            "MLS high level does not dominate low level",
        ));
    }
    if role != 1 {
        let user_range = symbols.users[(user - 1) as usize].range.as_ref().ok_or(
            ParseError::InvalidSecurityContext("MLS user has no authorized range"),
        )?;
        if !mls_level_dominates(&range.low, &user_range.low)
            || !mls_level_dominates(&user_range.high, &range.high)
        {
            return Err(ParseError::InvalidSecurityContext(
                "MLS range is outside the user's authorized range",
            ));
        }
    }
    Ok(())
}

fn mls_level_dominates(left: &BinaryMlsLevel, right: &BinaryMlsLevel) -> bool {
    left.sensitivity >= right.sensitivity
        && right
            .categories
            .iter()
            .all(|category| left.categories.binary_search(category).is_ok())
}

fn read_genfs_contexts(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    symbols: &ContextSymbols<'_>,
    classes: &[ClassSymbol],
    rules: &mut Vec<BinaryLabelingRule>,
) -> Result<(), ParseError> {
    let filesystem_count = cursor.read_u32()?;
    enforce_u32_limit(
        "genfs filesystems",
        filesystem_count,
        limits.max_genfs_filesystems,
    )?;
    let filesystem_count =
        usize::try_from(filesystem_count).map_err(|_| ParseError::LimitExceeded {
            resource: "genfs filesystems",
            requested: u64::MAX,
            limit: u64::from(limits.max_genfs_filesystems),
        })?;
    let mut filesystems = Vec::new();
    reserve_exact(
        &mut filesystems,
        filesystem_count,
        budget,
        "genfs filesystem names",
    )?;
    let mut decoded_contexts = 0_u32;
    for _ in 0..filesystem_count {
        let length = cursor.read_u32()?;
        let filesystem = read_symbol_name(cursor, length, limits, budget, "genfs filesystem name")?;
        if filesystems.iter().any(|name| name == &filesystem) {
            return Err(ParseError::InvalidGenfs("duplicate filesystem type"));
        }
        let context_count = cursor.read_u32()?;
        decoded_contexts =
            decoded_contexts
                .checked_add(context_count)
                .ok_or(ParseError::LimitExceeded {
                    resource: "genfs contexts",
                    requested: u64::MAX,
                    limit: u64::from(limits.max_genfs_contexts),
                })?;
        enforce_u32_limit(
            "genfs contexts",
            decoded_contexts,
            limits.max_genfs_contexts,
        )?;
        let context_count =
            usize::try_from(context_count).map_err(|_| ParseError::LimitExceeded {
                resource: "genfs contexts",
                requested: u64::MAX,
                limit: u64::from(limits.max_genfs_contexts),
            })?;
        reserve_additional(rules, context_count, budget, "genfs contexts")?;
        let first_rule = rules.len();
        for _ in 0..context_count {
            let path_length = cursor.read_u32()?;
            let path = read_symbol_name(cursor, path_length, limits, budget, "genfs path")?;
            let raw_class = cursor.read_u32()?;
            let target_class = nonzero(raw_class);
            if let Some(target_class) = target_class {
                validate_symbol_value("genfs target class", target_class, classes.len() as u32)?;
            }
            if rules[first_rule..].iter().any(|rule| {
                matches!(
                    rule,
                    BinaryLabelingRule::Genfscon {
                        path: existing_path,
                        target_class: existing_class,
                        ..
                    } if existing_path == &path
                        && (existing_class.is_none()
                            || target_class.is_none()
                            || *existing_class == target_class)
                )
            }) {
                return Err(ParseError::InvalidGenfs(
                    "duplicate path and overlapping object class",
                ));
            }
            rules.push(BinaryLabelingRule::Genfscon {
                filesystem: clone_retained_string(&filesystem, budget, "genfs filesystem names")?,
                path,
                target_class,
                context: read_security_context(cursor, limits, budget, symbols)?,
            });
        }
        filesystems.push(filesystem);
    }
    Ok(())
}

fn read_mls_range_transitions(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    symbols: &ContextSymbols<'_>,
    classes: &[ClassSymbol],
) -> Result<Vec<BinaryMlsRule>, ParseError> {
    let count = cursor.read_u32()?;
    enforce_u32_limit(
        "MLS range transitions",
        count,
        limits.max_mls_range_transitions,
    )?;
    if count != 0 && !symbols.mls {
        return Err(ParseError::InvalidMlsRule(
            "a non-MLS policy contains a range transition",
        ));
    }
    let implicit_class = if count != 0 && symbols.version < POLICY_VERSION_RANGE_TRANSITION_CLASS {
        Some(
            classes
                .iter()
                .find(|target_class| target_class.name == "process")
                .ok_or(ParseError::InvalidMlsRule(
                    "the legacy implicit process class is absent",
                ))?
                .value,
        )
    } else {
        None
    };
    let count = usize::try_from(count).map_err(|_| ParseError::LimitExceeded {
        resource: "MLS range transitions",
        requested: u64::MAX,
        limit: u64::from(limits.max_mls_range_transitions),
    })?;
    let mut rules = Vec::new();
    reserve_exact(&mut rules, count, budget, "MLS range transitions")?;
    for _ in 0..count {
        let source = cursor.read_u32()?;
        let target = cursor.read_u32()?;
        validate_mls_rule_type_reference(source, symbols)?;
        validate_mls_rule_type_reference(target, symbols)?;
        let target_class = if symbols.version >= POLICY_VERSION_RANGE_TRANSITION_CLASS {
            cursor.read_u32()?
        } else {
            implicit_class.expect("non-empty legacy range transitions have an implicit class")
        };
        validate_symbol_value(
            "MLS range-transition target class",
            target_class,
            classes.len() as u32,
        )?;
        let default = read_mls_range(cursor, limits, budget, "MLS range transition")?;
        validate_mls_rule_range(&default, symbols)?;
        if rules.iter().any(|rule: &BinaryMlsRule| {
            rule.source == source && rule.target == target && rule.target_class == target_class
        }) {
            return Err(ParseError::InvalidMlsRule(
                "duplicate source, target, and class key",
            ));
        }
        rules.push(BinaryMlsRule {
            source,
            target,
            target_class,
            default,
        });
    }
    Ok(rules)
}

fn validate_mls_rule_type_reference(
    value: u32,
    symbols: &ContextSymbols<'_>,
) -> Result<(), ParseError> {
    validate_symbol_value(
        "MLS range-transition type or attribute",
        value,
        symbols.type_primary_count,
    )?;
    match symbols
        .types
        .binary_search_by_key(&value, |entry| entry.value)
    {
        Ok(_) => Ok(()),
        Err(_) if (20..=POLICY_VERSION_PERMISSIVE).contains(&symbols.version) => Ok(()),
        Err(_) => Err(ParseError::InvalidMlsRule(
            "a type reference does not resolve to a primary symbol",
        )),
    }
}

fn validate_mls_rule_range(
    range: &BinaryMlsRange,
    symbols: &ContextSymbols<'_>,
) -> Result<(), ParseError> {
    for level in [&range.low, &range.high] {
        if level.sensitivity == 0 || level.sensitivity > symbols.sensitivities.len() as u32 {
            return Err(ParseError::InvalidMlsRule(
                "a sensitivity is outside the policy sensitivity table",
            ));
        }
        if level
            .categories
            .iter()
            .any(|category| *category >= symbols.categories.len() as u32)
        {
            return Err(ParseError::InvalidMlsRule(
                "a category is outside the policy category table",
            ));
        }
        let sensitivity = &symbols.sensitivities[(level.sensitivity - 1) as usize];
        if level
            .categories
            .iter()
            .any(|category| sensitivity.categories.binary_search(category).is_err())
        {
            return Err(ParseError::InvalidMlsRule(
                "a category is not authorized for its sensitivity",
            ));
        }
    }
    if !mls_level_dominates(&range.high, &range.low) {
        return Err(ParseError::InvalidMlsRule(
            "the high level does not dominate the low level",
        ));
    }
    Ok(())
}

fn read_type_attribute_maps(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    version: u32,
    type_primary_count: u32,
    types: &mut [BinaryTypeSymbol],
) -> Result<(), ParseError> {
    for symbol in types.iter_mut() {
        if symbol.kind == BinaryTypeKind::Type {
            reserve_additional(
                &mut symbol.expanded_types,
                1,
                budget,
                "concrete type expansions",
            )?;
            symbol.expanded_types.push(symbol.value - 1);
        }
    }
    if version < POLICY_VERSION_AVTAB {
        return Ok(());
    }

    let mut retained_memberships = 0_u32;
    for value_index in 0..type_primary_count {
        let mut attributes =
            read_bitmap_bits(cursor, limits, budget, "type-attribute membership bitmap")?;
        for attribute in &attributes {
            if *attribute >= type_primary_count {
                return Err(ParseError::InvalidTypeAttributeMap(
                    "an attribute index is out of range",
                ));
            }
            if *attribute == value_index {
                continue;
            }
            match types.binary_search_by_key(&(*attribute + 1), |entry| entry.value) {
                Ok(index) if types[index].kind == BinaryTypeKind::Attribute => {}
                Ok(_) => {
                    return Err(ParseError::InvalidTypeAttributeMap(
                        "a membership bit resolves to a concrete type",
                    ));
                }
                Err(_) if (20..=POLICY_VERSION_PERMISSIVE).contains(&version) => {}
                Err(_) => {
                    return Err(ParseError::InvalidTypeAttributeMap(
                        "a membership bit does not resolve to an attribute",
                    ));
                }
            }
        }
        attributes.retain(|attribute| *attribute != value_index);
        let additional =
            u32::try_from(attributes.len()).map_err(|_| ParseError::LimitExceeded {
                resource: "type-attribute memberships",
                requested: u64::MAX,
                limit: u64::from(limits.max_type_attribute_memberships),
            })?;
        retained_memberships =
            retained_memberships
                .checked_add(additional)
                .ok_or(ParseError::LimitExceeded {
                    resource: "type-attribute memberships",
                    requested: u64::MAX,
                    limit: u64::from(limits.max_type_attribute_memberships),
                })?;
        enforce_u32_limit(
            "type-attribute memberships",
            retained_memberships,
            limits.max_type_attribute_memberships,
        )?;

        let Ok(symbol_index) = types.binary_search_by_key(&(value_index + 1), |entry| entry.value)
        else {
            continue;
        };
        if types[symbol_index].kind == BinaryTypeKind::Type {
            for attribute in &attributes {
                let Ok(attribute_index) =
                    types.binary_search_by_key(&(*attribute + 1), |entry| entry.value)
                else {
                    continue;
                };
                reserve_additional(
                    &mut types[attribute_index].expanded_types,
                    1,
                    budget,
                    "attribute concrete type expansions",
                )?;
                types[attribute_index].expanded_types.push(value_index);
            }
        }
        types[symbol_index].attributes = attributes;
    }
    Ok(())
}

fn validate_labeling_role_authorization(
    rules: &[BinaryLabelingRule],
    roles: &[RoleSymbol],
    types: &[BinaryTypeSymbol],
) -> Result<(), ParseError> {
    for rule in rules {
        match rule {
            BinaryLabelingRule::FsContext {
                filesystem_context,
                root_context,
                ..
            } => {
                validate_context_role_authorization(filesystem_context, roles, types)?;
                validate_context_role_authorization(root_context, roles, types)?;
            }
            BinaryLabelingRule::Netifcon {
                interface_context,
                packet_context,
                ..
            } => {
                validate_context_role_authorization(interface_context, roles, types)?;
                validate_context_role_authorization(packet_context, roles, types)?;
            }
            BinaryLabelingRule::InitialSid { context, .. }
            | BinaryLabelingRule::Portcon { context, .. }
            | BinaryLabelingRule::Nodecon { context, .. }
            | BinaryLabelingRule::FsUse { context, .. }
            | BinaryLabelingRule::Ibpkeycon { context, .. }
            | BinaryLabelingRule::Ibendportcon { context, .. }
            | BinaryLabelingRule::Pirqcon { context, .. }
            | BinaryLabelingRule::Ioportcon { context, .. }
            | BinaryLabelingRule::Iomemcon { context, .. }
            | BinaryLabelingRule::Pcidevicecon { context, .. }
            | BinaryLabelingRule::Devicetreecon { context, .. }
            | BinaryLabelingRule::Genfscon { context, .. } => {
                validate_context_role_authorization(context, roles, types)?;
            }
        }
    }
    Ok(())
}

fn validate_context_role_authorization(
    context: &BinarySecurityContext,
    roles: &[RoleSymbol],
    types: &[BinaryTypeSymbol],
) -> Result<(), ParseError> {
    if context.role == 1 {
        return Ok(());
    }
    let role = &roles[(context.role - 1) as usize];
    let type_index = types
        .binary_search_by_key(&context.type_id, |entry| entry.value)
        .expect("security-context type references were validated while decoding");
    let concrete_index = context.type_id - 1;
    if role.authorized_types.binary_search(&concrete_index).is_ok()
        || types[type_index]
            .attributes
            .iter()
            .any(|attribute| role.authorized_types.binary_search(attribute).is_ok())
    {
        return Ok(());
    }
    Err(ParseError::InvalidSecurityContext(
        "role is not authorized for the type or any containing attribute",
    ))
}

const fn nonzero(value: u32) -> Option<u32> {
    if value == 0 { None } else { Some(value) }
}

#[allow(clippy::too_many_arguments)]
fn read_constraints(
    cursor: &mut Cursor<'_>,
    count: u32,
    validate_transition: bool,
    permission_count: u32,
    version: u32,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<Vec<BinaryConstraint>, ParseError> {
    let count = usize::try_from(count).map_err(|_| ParseError::LimitExceeded {
        resource: "constraints per object class",
        requested: u64::MAX,
        limit: u64::from(limits.max_constraints_per_class),
    })?;
    let mut constraints = Vec::new();
    reserve_exact(&mut constraints, count, budget, "object-class constraints")?;
    for _ in 0..count {
        let permissions = cursor.read_u32()?;
        let expression_count = cursor.read_u32()?;
        if validate_transition {
            if permissions != 0 {
                return Err(ParseError::InvalidConstraint(
                    "validation-transition permissions are not zero",
                ));
            }
        } else {
            if permission_count == 0 || permissions == 0 {
                return Err(ParseError::InvalidConstraint(
                    "ordinary constraints require class permissions",
                ));
            }
            if permission_count < PERMISSION_SYMBOL_LIMIT
                && permissions >= (1_u32 << permission_count)
            {
                return Err(ParseError::InvalidConstraint(
                    "permission mask exceeds the class permission width",
                ));
            }
        }
        enforce_u32_limit(
            "expressions per constraint",
            expression_count,
            limits.max_constraint_expressions,
        )?;
        let expression_count =
            usize::try_from(expression_count).map_err(|_| ParseError::LimitExceeded {
                resource: "expressions per constraint",
                requested: u64::MAX,
                limit: u64::from(limits.max_constraint_expressions),
            })?;
        let mut expressions = Vec::new();
        reserve_exact(
            &mut expressions,
            expression_count,
            budget,
            "constraint expressions",
        )?;
        let mut depth = -1_i32;
        for _ in 0..expression_count {
            let expression_type = cursor.read_u32()?;
            let attribute = cursor.read_u32()?;
            let operator = cursor.read_u32()?;
            let expression = match expression_type {
                1 => {
                    validate_logical_expression(attribute, operator)?;
                    if depth < 0 {
                        return Err(ParseError::InvalidConstraint(
                            "NOT has no preceding operand",
                        ));
                    }
                    BinaryConstraintExpression::Not
                }
                2 | 3 => {
                    validate_logical_expression(attribute, operator)?;
                    if depth < 1 {
                        return Err(ParseError::InvalidConstraint(
                            "binary operator has fewer than two operands",
                        ));
                    }
                    depth -= 1;
                    if expression_type == 2 {
                        BinaryConstraintExpression::And
                    } else {
                        BinaryConstraintExpression::Or
                    }
                }
                4 => {
                    push_constraint_operand(&mut depth)?;
                    let operator = parse_constraint_operator(operator)?;
                    validate_attribute_comparison(attribute, operator)?;
                    BinaryConstraintExpression::Attribute {
                        attribute,
                        operator,
                    }
                }
                5 => {
                    push_constraint_operand(&mut depth)?;
                    let operator = parse_constraint_operator(operator)?;
                    validate_names_comparison(attribute, operator, validate_transition)?;
                    let names = read_bitmap_bits(cursor, limits, budget, "constraint name bitmap")?;
                    let type_names = if version >= POLICY_VERSION_CONSTRAINT_NAMES {
                        Some(read_type_set(cursor, limits, budget)?)
                    } else {
                        None
                    };
                    if attribute & CONSTRAINT_TYPE == 0
                        && type_names.as_ref().is_some_and(|type_set| {
                            !type_set.types.is_empty()
                                || !type_set.negative_types.is_empty()
                                || type_set.flags != 0
                        })
                    {
                        return Err(ParseError::InvalidConstraint(
                            "a non-type named expression has a type-set payload",
                        ));
                    }
                    BinaryConstraintExpression::Names {
                        attribute,
                        operator,
                        names,
                        type_names,
                    }
                }
                _ => {
                    return Err(ParseError::InvalidConstraint(
                        "unknown postfix expression type",
                    ));
                }
            };
            expressions.push(expression);
        }
        if depth != 0 {
            return Err(ParseError::InvalidConstraint(
                "postfix expression does not reduce to one value",
            ));
        }
        constraints.push(BinaryConstraint {
            permissions,
            validate_transition,
            expressions,
        });
    }
    Ok(constraints)
}

fn read_type_set(
    cursor: &mut Cursor<'_>,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
) -> Result<BinaryTypeSet, ParseError> {
    let types = read_bitmap_bits(cursor, limits, budget, "constraint type-set bitmap")?;
    let negative_types = read_bitmap_bits(
        cursor,
        limits,
        budget,
        "constraint negative type-set bitmap",
    )?;
    let flags = cursor.read_u32()?;
    if !matches!(flags, 0..=2) {
        return Err(ParseError::InvalidConstraint(
            "type-set flags are neither empty, star, nor complement",
        ));
    }
    Ok(BinaryTypeSet {
        types,
        negative_types,
        flags,
    })
}

fn validate_logical_expression(attribute: u32, operator: u32) -> Result<(), ParseError> {
    if attribute != 0 || operator != 0 {
        Err(ParseError::InvalidConstraint(
            "logical expression carries an attribute or comparison operator",
        ))
    } else {
        Ok(())
    }
}

fn push_constraint_operand(depth: &mut i32) -> Result<(), ParseError> {
    if *depth == CONSTRAINT_MAX_DEPTH - 1 {
        Err(ParseError::InvalidConstraint(
            "postfix expression exceeds maximum stack depth",
        ))
    } else {
        *depth += 1;
        Ok(())
    }
}

fn parse_constraint_operator(value: u32) -> Result<ConstraintOperator, ParseError> {
    match value {
        1 => Ok(ConstraintOperator::Equal),
        2 => Ok(ConstraintOperator::NotEqual),
        3 => Ok(ConstraintOperator::Dominates),
        4 => Ok(ConstraintOperator::DominatedBy),
        5 => Ok(ConstraintOperator::Incomparable),
        _ => Err(ParseError::InvalidConstraint("unknown comparison operator")),
    }
}

fn validate_attribute_comparison(
    attribute: u32,
    operator: ConstraintOperator,
) -> Result<(), ParseError> {
    if !matches!(attribute, 1 | 2 | 4 | 32 | 64 | 128 | 256 | 512 | 1024) {
        return Err(ParseError::InvalidConstraint(
            "unknown attribute comparison selector",
        ));
    }
    if matches!(
        operator,
        ConstraintOperator::Dominates
            | ConstraintOperator::DominatedBy
            | ConstraintOperator::Incomparable
    ) && matches!(attribute, 1 | 4)
    {
        return Err(ParseError::InvalidConstraint(
            "user and type attributes only support equality operators",
        ));
    }
    Ok(())
}

fn validate_names_comparison(
    attribute: u32,
    operator: ConstraintOperator,
    validate_transition: bool,
) -> Result<(), ParseError> {
    if !matches!(attribute, 1 | 9 | 17 | 2 | 10 | 18 | 4 | 12 | 20) {
        return Err(ParseError::InvalidConstraint(
            "unknown named-symbol attribute selector",
        ));
    }
    if attribute & CONSTRAINT_XTARGET != 0 && !validate_transition {
        return Err(ParseError::InvalidConstraint(
            "ordinary constraints cannot select the third transition context",
        ));
    }
    if !matches!(
        operator,
        ConstraintOperator::Equal | ConstraintOperator::NotEqual
    ) {
        return Err(ParseError::InvalidConstraint(
            "named-symbol comparisons only support equality operators",
        ));
    }
    Ok(())
}

fn read_class_defaults(
    cursor: &mut Cursor<'_>,
    version: u32,
) -> Result<BinaryClassDefaults, ParseError> {
    let mut defaults = BinaryClassDefaults::default();
    if version >= POLICY_VERSION_NEW_OBJECT_DEFAULTS {
        defaults.user = parse_simple_default("default user", cursor.read_u32()?)?;
        defaults.role = parse_simple_default("default role", cursor.read_u32()?)?;
        defaults.range = parse_range_default(cursor.read_u32()?)?;
    }
    if version >= POLICY_VERSION_DEFAULT_TYPE {
        defaults.object_type = parse_simple_default("default type", cursor.read_u32()?)?;
    }
    Ok(defaults)
}

fn parse_simple_default(
    field: &'static str,
    value: u32,
) -> Result<Option<DefaultValue>, ParseError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(DefaultValue::Source)),
        2 => Ok(Some(DefaultValue::Target)),
        _ => Err(ParseError::InvalidDefault { field, value }),
    }
}

fn parse_range_default(
    value: u32,
) -> Result<Option<(DefaultValue, Option<DefaultRangePart>)>, ParseError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some((DefaultValue::Source, Some(DefaultRangePart::Low)))),
        2 => Ok(Some((DefaultValue::Source, Some(DefaultRangePart::High)))),
        3 => Ok(Some((
            DefaultValue::Source,
            Some(DefaultRangePart::LowHigh),
        ))),
        4 => Ok(Some((DefaultValue::Target, Some(DefaultRangePart::Low)))),
        5 => Ok(Some((DefaultValue::Target, Some(DefaultRangePart::High)))),
        6 => Ok(Some((
            DefaultValue::Target,
            Some(DefaultRangePart::LowHigh),
        ))),
        7 => Ok(Some((DefaultValue::GlbLub, None))),
        _ => Err(ParseError::InvalidDefault {
            field: "default range",
            value,
        }),
    }
}

fn read_symbol_name(
    cursor: &mut Cursor<'_>,
    serialized_length: u32,
    limits: &ParserLimits,
    budget: &mut AllocationBudget,
    field: &'static str,
) -> Result<String, ParseError> {
    let length = usize::try_from(serialized_length).map_err(|_| ParseError::LimitExceeded {
        resource: "symbol name bytes",
        requested: u64::from(serialized_length),
        limit: usize_to_u64(limits.max_string_bytes),
    })?;
    enforce_usize_limit("symbol name bytes", length, limits.max_string_bytes)?;
    let bytes = cursor.read_bytes(length)?;
    if bytes.contains(&0) {
        return Err(ParseError::EmbeddedNul { field });
    }
    let text = str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8 { field })?;
    budget.charge(length, "decoded strings")?;
    let mut result = String::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| ParseError::AllocationFailed {
            resource: "decoded string",
            requested: length,
        })?;
    result.push_str(text);
    Ok(result)
}

fn validate_symbol_value(
    table: &'static str,
    value: u32,
    primary_count: u32,
) -> Result<(), ParseError> {
    if value == 0 || value > primary_count {
        Err(ParseError::InvalidSymbolValue {
            table,
            value,
            primary_count,
        })
    } else {
        Ok(())
    }
}

fn reject_duplicate_common_values(commons: &[CommonSymbol]) -> Result<(), ParseError> {
    for pair in commons.windows(2) {
        if pair[0].value == pair[1].value {
            return Err(ParseError::DuplicateSymbol {
                table: "common value",
                symbol: pair[0].value.to_string(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_common_names(commons: &[CommonSymbol]) -> Result<(), ParseError> {
    for pair in commons.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "common name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_permission_values(permissions: &[PermissionSymbol]) -> Result<(), ParseError> {
    reject_duplicate_permission_values_for(permissions, "common permission value")
}

fn reject_duplicate_permission_values_for(
    permissions: &[PermissionSymbol],
    table: &'static str,
) -> Result<(), ParseError> {
    for pair in permissions.windows(2) {
        if pair[0].value == pair[1].value {
            return Err(ParseError::DuplicateSymbol {
                table,
                symbol: pair[0].value.to_string(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_permission_names(permissions: &[PermissionSymbol]) -> Result<(), ParseError> {
    reject_duplicate_permission_names_for(permissions, "common permission name")
}

fn reject_duplicate_permission_names_for(
    permissions: &[PermissionSymbol],
    table: &'static str,
) -> Result<(), ParseError> {
    for pair in permissions.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table,
                symbol: pair[0].name.clone(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_class_values(classes: &[ClassSymbol]) -> Result<(), ParseError> {
    for pair in classes.windows(2) {
        if pair[0].value == pair[1].value {
            return Err(ParseError::DuplicateSymbol {
                table: "object-class value",
                symbol: pair[0].value.to_string(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_class_names(classes: &[ClassSymbol]) -> Result<(), ParseError> {
    for pair in classes.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "object-class name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_role_values(roles: &[RoleSymbol]) -> Result<(), ParseError> {
    for pair in roles.windows(2) {
        if pair[0].value == pair[1].value {
            return Err(ParseError::DuplicateSymbol {
                table: "role value",
                symbol: pair[0].value.to_string(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_role_names(roles: &[RoleSymbol]) -> Result<(), ParseError> {
    for pair in roles.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "role name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_user_values(users: &[UserSymbol]) -> Result<(), ParseError> {
    for pair in users.windows(2) {
        if pair[0].value == pair[1].value {
            return Err(ParseError::DuplicateSymbol {
                table: "user value",
                symbol: pair[0].value.to_string(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_user_names(users: &[UserSymbol]) -> Result<(), ParseError> {
    for pair in users.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "user name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_boolean_values(booleans: &[BinaryBooleanSymbol]) -> Result<(), ParseError> {
    for pair in booleans.windows(2) {
        if pair[0].value == pair[1].value {
            return Err(ParseError::DuplicateSymbol {
                table: "Boolean value",
                symbol: pair[0].value.to_string(),
            });
        }
    }
    Ok(())
}

fn reject_duplicate_boolean_names(booleans: &[BinaryBooleanSymbol]) -> Result<(), ParseError> {
    for pair in booleans.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(ParseError::DuplicateSymbol {
                table: "Boolean name",
                symbol: pair[0].name.clone(),
            });
        }
    }
    Ok(())
}

fn enforce_u32_limit(resource: &'static str, requested: u32, limit: u32) -> Result<(), ParseError> {
    if requested > limit {
        Err(ParseError::LimitExceeded {
            resource,
            requested: u64::from(requested),
            limit: u64::from(limit),
        })
    } else {
        Ok(())
    }
}

fn enforce_usize_limit(
    resource: &'static str,
    requested: usize,
    limit: usize,
) -> Result<(), ParseError> {
    if requested > limit {
        Err(ParseError::LimitExceeded {
            resource,
            requested: usize_to_u64(requested),
            limit: usize_to_u64(limit),
        })
    } else {
        Ok(())
    }
}

fn reserve_exact<T>(
    values: &mut Vec<T>,
    count: usize,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<(), ParseError> {
    reserve_additional(values, count, budget, resource)
}

fn reserve_additional<T>(
    values: &mut Vec<T>,
    additional: usize,
    budget: &mut AllocationBudget,
    resource: &'static str,
) -> Result<(), ParseError> {
    let bytes = additional
        .checked_mul(size_of::<T>())
        .ok_or(ParseError::LimitExceeded {
            resource: "decoded allocation bytes",
            requested: u64::MAX,
            limit: usize_to_u64(budget.limit),
        })?;
    budget.charge(bytes, resource)?;
    values
        .try_reserve_exact(additional)
        .map_err(|_| ParseError::AllocationFailed {
            resource,
            requested: additional,
        })
}

struct AllocationBudget {
    used: usize,
    limit: usize,
}

impl AllocationBudget {
    const fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn with_used(limit: usize, used: usize) -> Result<Self, ParseError> {
        if used > limit {
            return Err(ParseError::LimitExceeded {
                resource: "decoded allocation bytes",
                requested: usize_to_u64(used),
                limit: usize_to_u64(limit),
            });
        }
        Ok(Self { used, limit })
    }

    fn charge(&mut self, bytes: usize, resource: &'static str) -> Result<(), ParseError> {
        let requested = self
            .used
            .checked_add(bytes)
            .ok_or(ParseError::LimitExceeded {
                resource: "decoded allocation bytes",
                requested: u64::MAX,
                limit: usize_to_u64(self.limit),
            })?;
        if requested > self.limit {
            return Err(ParseError::LimitExceeded {
                resource,
                requested: usize_to_u64(requested),
                limit: usize_to_u64(self.limit),
            });
        }
        self.used = requested;
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            max_offset: usize::MAX,
        }
    }

    const fn with_limit(bytes: &'a [u8], max_offset: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            max_offset,
        }
    }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, ParseError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let requested_end = self
            .offset
            .checked_add(length)
            .ok_or(ParseError::LimitExceeded {
                resource: "serialized prefix bytes",
                requested: u64::MAX,
                limit: usize_to_u64(self.max_offset),
            })?;
        if requested_end > self.max_offset {
            return Err(ParseError::LimitExceeded {
                resource: "serialized prefix bytes",
                requested: usize_to_u64(requested_end),
                limit: usize_to_u64(self.max_offset),
            });
        }
        let available = self.bytes.len().saturating_sub(self.offset);
        if available < length {
            return Err(ParseError::Truncated {
                offset: self.offset,
                needed: length,
                available,
            });
        }
        let start = self.offset;
        self.offset = requested_end;
        Ok(&self.bytes[start..self.offset])
    }
}

const fn usize_to_u64(value: usize) -> u64 {
    if size_of::<usize>() > size_of::<u64>() && value > u64::MAX as usize {
        u64::MAX
    } else {
        value as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY, AVTAB_CHANGE, AVTAB_ENABLED,
        AVTAB_ENABLED_OLD, AVTAB_MEMBER, AVTAB_TRANSITION, AVTAB_XPERMS_ALLOWED,
        AVTAB_XPERMS_IOCTLDRIVER, AllocationBudget, BinaryBooleanSymbol,
        BinaryConstraintExpression, BinaryLabelingRule, BinaryRbacRuleData, BinaryTeRuleData,
        BinaryTypeKind, ContextSymbols, Cursor, MetadataLoadError, POLICYDB_MAGIC,
        POLICYDB_MODULE_MAGIC, ParseError, ParserLimits, PureRustPolicyLoader,
        PureRustPrefixLoader, TYPE_PROPERTY_ATTRIBUTE, TYPE_PROPERTY_PRIMARY, decode_xperm_values,
        parse_policy_header, parse_policy_prefix, parse_policy_prefix_with_limits,
        read_conditional_tokens, read_filename_transitions, read_genfs_contexts,
        read_mls_range_transitions, read_object_contexts, read_rbac_rules,
    };
    use setools_policy::{
        BooleanId, ConditionalToken, ConstraintOperator, DefaultRangePart, DefaultValue,
        HandleUnknown, TargetPlatform, TeRuleKind, TypeId, XpermKind,
    };

    fn counts(target: &[u8], version: u32) -> (u32, u32) {
        match (target, version) {
            (b"SE Linux", 15) => (5, 6),
            (b"SE Linux", 16) => (6, 6),
            (b"SE Linux", 17..=18) => (6, 7),
            (b"SE Linux", 19..=30) => (8, 7),
            (b"SE Linux", 31..=35) => (8, 9),
            (b"XenFlask", 24) => (8, 5),
            (b"XenFlask", 30) => (8, 6),
            _ => (8, 7),
        }
    }

    fn header(target: &[u8], version: u32, config: u32) -> Vec<u8> {
        let (symbols, object_contexts) = counts(target, version);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&POLICYDB_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&(target.len() as u32).to_le_bytes());
        bytes.extend_from_slice(target);
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend_from_slice(&config.to_le_bytes());
        bytes.extend_from_slice(&symbols.to_le_bytes());
        bytes.extend_from_slice(&object_contexts.to_le_bytes());
        bytes
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_modern_avtab_key(
        bytes: &mut Vec<u8>,
        source: u16,
        target: u16,
        target_class: u16,
        specified: u16,
    ) {
        push_u16(bytes, source);
        push_u16(bytes, target);
        push_u16(bytes, target_class);
        push_u16(bytes, specified);
    }

    fn push_empty_bitmap(bytes: &mut Vec<u8>) {
        push_u32(bytes, 64);
        push_u32(bytes, 0);
        push_u32(bytes, 0);
    }

    fn push_bitmap(bytes: &mut Vec<u8>, map: u64) {
        push_u32(bytes, 64);
        push_u32(bytes, 64);
        push_u32(bytes, 1);
        push_u32(bytes, 0);
        bytes.extend_from_slice(&map.to_le_bytes());
    }

    fn push_test_security_context(bytes: &mut Vec<u8>) {
        for value in [1, 1, 1, 1, 1] {
            push_u32(bytes, value);
        }
        push_bitmap(bytes, 1);
    }

    fn context_symbols(prefix: &super::BinaryPolicyPrefix, version: u32) -> ContextSymbols<'_> {
        ContextSymbols {
            version,
            mls: true,
            type_primary_count: prefix.type_primary_count(),
            types: prefix.types(),
            roles: prefix.roles(),
            users: prefix.users(),
            sensitivities: prefix.sensitivities(),
            categories: prefix.categories(),
        }
    }

    fn policy_prefix() -> Vec<u8> {
        let mut bytes = header(b"SE Linux", 35, 3);
        push_bitmap(&mut bytes, (1_u64 << 0) | (1_u64 << 10) | (1_u64 << 14));
        push_bitmap(&mut bytes, 1_u64 << 3);
        push_empty_bitmap(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 2);
        bytes.extend_from_slice(b"infoflow");
        push_u32(&mut bytes, 5);
        push_u32(&mut bytes, 2);
        bytes.extend_from_slice(b"write");
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"read");

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 6);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"packet");
        bytes.extend_from_slice(b"infoflow");
        push_u32(&mut bytes, 10);
        push_u32(&mut bytes, 3);
        bytes.extend_from_slice(b"transition");

        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 5);
        push_u32(&mut bytes, 20);
        push_u32(&mut bytes, 1);
        push_bitmap(&mut bytes, 1_u64 << 2);
        push_bitmap(&mut bytes, 1_u64 << 1);
        push_empty_bitmap(&mut bytes);
        push_u32(&mut bytes, 0);

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 5);
        push_u32(&mut bytes, 1);

        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"object_r");
        push_empty_bitmap(&mut bytes);
        push_empty_bitmap(&mut bytes);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"system_r");
        push_bitmap(&mut bytes, 1);
        push_bitmap(&mut bytes, 1);

        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, TYPE_PROPERTY_PRIMARY);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"system_t");
        push_u32(&mut bytes, 12);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"system_alias");
        push_u32(&mut bytes, 6);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, TYPE_PROPERTY_PRIMARY | TYPE_PROPERTY_ATTRIBUTE);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"domain");
        push_u32(&mut bytes, 9);
        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, TYPE_PROPERTY_PRIMARY);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"bounded_t");

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 5);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"alice");
        push_bitmap(&mut bytes, 3);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_bitmap(&mut bytes, 1);
        push_bitmap(&mut bytes, 3);
        push_u32(&mut bytes, 1);
        push_bitmap(&mut bytes, 1);

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 7);
        bytes.extend_from_slice(b"enabled");

        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, 5);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"low_s");
        push_u32(&mut bytes, 1);
        push_bitmap(&mut bytes, 1);
        push_u32(&mut bytes, 6);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"high_s");
        push_u32(&mut bytes, 2);
        push_bitmap(&mut bytes, 3);
        push_u32(&mut bytes, 10);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"high_alias");
        push_u32(&mut bytes, 2);
        push_bitmap(&mut bytes, 3);

        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, 3);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"c0");
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"c1");
        push_u32(&mut bytes, 9);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"cat_alias");

        push_u32(&mut bytes, 4);
        push_modern_avtab_key(&mut bytes, 1, 2, 1, AVTAB_ALLOWED as u16);
        push_u32(&mut bytes, 1);
        push_modern_avtab_key(&mut bytes, 1, 1, 1, AVTAB_AUDITDENY as u16);
        push_u32(&mut bytes, !2_u32);
        push_modern_avtab_key(&mut bytes, 1, 3, 1, AVTAB_TRANSITION as u16);
        push_u32(&mut bytes, 1);
        push_modern_avtab_key(&mut bytes, 1, 1, 1, AVTAB_XPERMS_ALLOWED as u16);
        bytes.push(1);
        bytes.push(0x12);
        for word in [1_u32 << 0x14, 0, 0, 0, 0, 0, 0, 0] {
            push_u32(&mut bytes, word);
        }

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_modern_avtab_key(&mut bytes, 1, 1, 1, (AVTAB_ALLOWED | AVTAB_ENABLED) as u16);
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 1);
        push_modern_avtab_key(&mut bytes, 1, 1, 1, AVTAB_AUDITALLOW as u16);
        push_u32(&mut bytes, 2);

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 5);
        bytes.extend_from_slice(b"entry");
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_bitmap(&mut bytes, 1_u64 << 2);
        push_u32(&mut bytes, 1);
        push_bitmap(&mut bytes, 1);
        push_u32(&mut bytes, 3);
        for _ in 0..10 {
            push_u32(&mut bytes, 0);
        }
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_bitmap(&mut bytes, 1);
        push_bitmap(&mut bytes, 3);
        push_bitmap(&mut bytes, 0b011);
        push_bitmap(&mut bytes, 0b010);
        push_bitmap(&mut bytes, 0b110);
        bytes
    }

    fn version_15_class_prefix() -> Vec<u8> {
        let mut bytes = header(b"SE Linux", 15, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 7);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(b"process");
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"object_r");
        push_empty_bitmap(&mut bytes);
        push_empty_bitmap(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 6);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"system");
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 7);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(
            &mut bytes,
            AVTAB_TRANSITION | AVTAB_CHANGE | AVTAB_MEMBER | AVTAB_ENABLED_OLD,
        );
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        for _ in 0..7 {
            push_u32(&mut bytes, 0);
        }
        bytes
    }

    fn version_23_type_gap_prefix() -> Vec<u8> {
        let mut bytes = header(b"SE Linux", 23, 0);
        push_empty_bitmap(&mut bytes);
        push_bitmap(&mut bytes, 1_u64 << 1);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 8);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"object_r");
        push_empty_bitmap(&mut bytes);
        push_bitmap(&mut bytes, 1_u64 << 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 6);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(b"system");
        for _ in 0..4 {
            push_u32(&mut bytes, 0);
            push_u32(&mut bytes, 0);
        }
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        for _ in 0..8 {
            push_u32(&mut bytes, 0);
        }
        push_u32(&mut bytes, 0);
        push_bitmap(&mut bytes, 0b11);
        push_bitmap(&mut bytes, 0b10);
        bytes
    }

    #[test]
    fn parses_selinux_metadata() {
        let bytes = header(b"SE Linux", 35, 3);
        let parsed = parse_policy_header(&bytes).expect("header should parse");
        assert_eq!(parsed.metadata().version, 35);
        assert!(parsed.metadata().mls);
        assert_eq!(parsed.metadata().target, TargetPlatform::Selinux);
        assert_eq!(parsed.metadata().handle_unknown, HandleUnknown::Reject);
        assert_eq!(parsed.symbol_table_count(), 8);
        assert_eq!(parsed.object_context_count(), 9);
        assert_eq!(parsed.encoded_len(), bytes.len());
    }

    #[test]
    fn selects_target_version_compatibility_entries() {
        let xen = parse_policy_header(&header(b"XenFlask", 30, 4))
            .expect("Xen version 30 header should parse");
        assert_eq!(xen.metadata().target, TargetPlatform::Xen);
        assert_eq!(xen.object_context_count(), 6);
        assert_eq!(xen.metadata().handle_unknown, HandleUnknown::Allow);

        assert!(matches!(
            parse_policy_header(&header(b"XenFlask", 35, 0)),
            Err(ParseError::UnsupportedTargetVersion {
                target: TargetPlatform::Xen,
                version: 35
            })
        ));

        let mut incompatible = header(b"SE Linux", 30, 0);
        let final_byte = incompatible.len() - 1;
        incompatible[final_byte] = 9;
        assert!(matches!(
            parse_policy_header(&incompatible),
            Err(ParseError::IncompatibleTableCounts { .. })
        ));
    }

    #[test]
    fn parses_common_permission_symbols() {
        let bytes = policy_prefix();
        let parsed = parse_policy_prefix(&bytes).expect("policy prefix should parse");
        assert_eq!(parsed.encoded_len(), bytes.len());
        assert_eq!(parsed.policy_capabilities(), [0, 10, 14]);
        assert_eq!(parsed.commons().len(), 1);
        assert_eq!(parsed.commons()[0].name(), "infoflow");
        assert_eq!(parsed.commons()[0].value(), 1);
        assert_eq!(
            parsed.commons()[0]
                .permissions()
                .iter()
                .map(|permission| (permission.name(), permission.value()))
                .collect::<Vec<_>>(),
            [("read", 1), ("write", 2)]
        );
    }

    #[test]
    fn parses_object_class_constraints_and_defaults() {
        let bytes = policy_prefix();
        let parsed = parse_policy_prefix(&bytes).expect("policy prefix should parse");
        assert_eq!(parsed.encoded_len(), bytes.len());
        assert_eq!(parsed.classes().len(), 1);
        let target_class = &parsed.classes()[0];
        assert_eq!(target_class.name(), "packet");
        assert_eq!(target_class.value(), 1);
        assert_eq!(target_class.permission_count(), 3);
        assert_eq!(target_class.common(), Some("infoflow"));
        assert_eq!(
            target_class
                .local_permissions()
                .iter()
                .map(|permission| (permission.name(), permission.value()))
                .collect::<Vec<_>>(),
            [("transition", 3)]
        );
        assert_eq!(target_class.constraints().len(), 1);
        assert_eq!(target_class.constraints()[0].permissions(), 2);
        assert_eq!(
            target_class.constraints()[0].expressions(),
            [BinaryConstraintExpression::Attribute {
                attribute: 1,
                operator: ConstraintOperator::Equal,
            }]
        );
        assert_eq!(target_class.validation_constraints().len(), 1);
        assert_eq!(
            target_class.validation_constraints()[0].expressions()[0].effective_names(),
            Some([1_u32].as_slice())
        );
        assert_eq!(target_class.defaults().user(), Some(DefaultValue::Source));
        assert_eq!(target_class.defaults().role(), Some(DefaultValue::Target));
        assert_eq!(
            target_class.defaults().range(),
            Some((DefaultValue::Target, Some(DefaultRangePart::High)))
        );
        assert_eq!(
            target_class.defaults().object_type(),
            Some(DefaultValue::Source)
        );
        assert_eq!(parsed.roles().len(), 2);
        assert_eq!(parsed.roles()[0].name(), "object_r");
        assert_eq!(parsed.roles()[1].name(), "system_r");
        assert_eq!(parsed.roles()[1].bound(), Some(1));
        assert_eq!(parsed.roles()[1].dominates(), [0]);
        assert_eq!(parsed.roles()[1].authorized_types(), [0]);
        assert_eq!(parsed.type_primary_count(), 3);
        assert_eq!(parsed.types().len(), 3);
        assert_eq!(parsed.types()[0].name(), "system_t");
        assert_eq!(parsed.types()[0].aliases(), ["system_alias"]);
        assert_eq!(parsed.types()[1].kind(), BinaryTypeKind::Attribute);
        assert_eq!(parsed.types()[0].expanded_types(), [0]);
        assert_eq!(parsed.types()[0].attributes(), [1]);
        assert_eq!(parsed.types()[1].expanded_types(), [0, 2]);
        assert_eq!(parsed.types()[2].attributes(), [1]);
        assert_eq!(parsed.types()[2].bound(), Some(1));
        assert!(parsed.types()[2].is_permissive());
        assert_eq!(parsed.users().len(), 1);
        assert_eq!(parsed.users()[0].name(), "alice");
        assert_eq!(parsed.users()[0].roles(), [0, 1]);
        let default_level = parsed.users()[0]
            .default_level()
            .expect("MLS user must have a default level");
        assert_eq!(default_level.sensitivity(), 1);
        assert_eq!(default_level.categories(), [0]);
        let range = parsed.users()[0]
            .range()
            .expect("MLS user must have a range");
        assert_eq!(range.low().sensitivity(), 1);
        assert_eq!(range.high().sensitivity(), 2);
        assert_eq!(range.high().categories(), [0, 1]);
        assert_eq!(parsed.booleans().len(), 1);
        assert_eq!(parsed.booleans()[0].name(), "enabled");
        assert!(parsed.booleans()[0].state());
        assert_eq!(parsed.sensitivities().len(), 2);
        assert_eq!(parsed.sensitivities()[1].name(), "high_s");
        assert_eq!(parsed.sensitivities()[1].aliases(), ["high_alias"]);
        assert_eq!(parsed.sensitivities()[1].categories(), [0, 1]);
        assert_eq!(parsed.categories().len(), 2);
        assert_eq!(parsed.categories()[1].aliases(), ["cat_alias"]);
        assert_eq!(parsed.te_rules().len(), 4);
        assert_eq!(parsed.te_rules()[0].kind(), TeRuleKind::Allow);
        assert_eq!(parsed.te_rules()[0].source(), 1);
        assert_eq!(parsed.te_rules()[0].target(), 2);
        assert_eq!(parsed.te_rules()[0].target_class(), 1);
        assert_eq!(
            parsed.te_rules()[0].data(),
            &BinaryTeRuleData::Permissions(vec![0])
        );
        assert_eq!(parsed.te_rules()[1].kind(), TeRuleKind::DontAudit);
        assert_eq!(
            parsed.te_rules()[1].data(),
            &BinaryTeRuleData::Permissions(vec![1])
        );
        assert_eq!(
            parsed.te_rules()[2].data(),
            &BinaryTeRuleData::DefaultType(1)
        );
        assert_eq!(
            parsed.te_rules()[3].data(),
            &BinaryTeRuleData::ExtendedPermissions {
                kind: XpermKind::Ioctl,
                values: vec![0x1214],
            }
        );
        assert_eq!(parsed.conditionals().len(), 1);
        assert!(parsed.conditionals()[0].current_state());
        assert_eq!(
            parsed.conditionals()[0].tokens(),
            [ConditionalToken::Boolean(BooleanId::from_raw(0))]
        );
        assert_eq!(parsed.conditionals()[0].true_rules().len(), 1);
        assert_eq!(parsed.conditionals()[0].false_rules().len(), 1);
        assert_eq!(
            parsed.conditionals()[0].true_rules()[0].data(),
            &BinaryTeRuleData::Permissions(vec![2])
        );
        assert_eq!(
            parsed.conditionals()[0].false_rules()[0].kind(),
            TeRuleKind::AuditAllow
        );
        assert_eq!(parsed.rbac_rules().len(), 2);
        assert_eq!(parsed.rbac_rules()[0].source(), 2);
        assert_eq!(
            parsed.rbac_rules()[0].data(),
            &BinaryRbacRuleData::RoleTransition {
                target: 1,
                target_class: 1,
                default: 1,
            }
        );
        assert_eq!(
            parsed.rbac_rules()[1].data(),
            &BinaryRbacRuleData::Allow { target: 2 }
        );
        assert_eq!(parsed.filename_transitions().len(), 2);
        assert_eq!(parsed.filename_transitions()[0].source(), 1);
        assert_eq!(parsed.filename_transitions()[0].target(), 1);
        assert_eq!(parsed.filename_transitions()[0].target_class(), 1);
        assert_eq!(parsed.filename_transitions()[0].default_type(), 3);
        assert_eq!(parsed.filename_transitions()[0].filename(), "entry");
        assert_eq!(parsed.filename_transitions()[1].source(), 3);
        assert_eq!(parsed.filename_transitions()[1].default_type(), 1);
        assert_eq!(parsed.mls_rules().len(), 1);
        assert_eq!(parsed.mls_rules()[0].source(), 1);
        assert_eq!(parsed.mls_rules()[0].target(), 2);
        assert_eq!(parsed.mls_rules()[0].target_class(), 1);
        assert_eq!(parsed.mls_rules()[0].default().low().sensitivity(), 1);
        assert_eq!(parsed.mls_rules()[0].default().high().sensitivity(), 2);
        assert_eq!(parsed.mls_rules()[0].default().high().categories(), [0, 1]);
    }

    #[test]
    fn parses_version_15_class_without_newer_records() {
        let bytes = version_15_class_prefix();
        let parsed = parse_policy_prefix(&bytes).expect("version 15 prefix should parse");
        assert_eq!(parsed.encoded_len(), bytes.len());
        assert_eq!(parsed.classes().len(), 1);
        assert_eq!(parsed.classes()[0].name(), "process");
        assert!(parsed.classes()[0].constraints().is_empty());
        assert!(parsed.classes()[0].validation_constraints().is_empty());
        assert_eq!(parsed.classes()[0].defaults(), &Default::default());
        assert_eq!(parsed.roles().len(), 1);
        assert_eq!(parsed.roles()[0].name(), "object_r");
        assert_eq!(parsed.types().len(), 1);
        assert_eq!(parsed.types()[0].name(), "system");
        assert_eq!(parsed.types()[0].expanded_types(), [0]);
        assert!(parsed.types()[0].attributes().is_empty());
        assert!(parsed.users().is_empty());
        assert!(parsed.booleans().is_empty());
        assert!(parsed.sensitivities().is_empty());
        assert!(parsed.categories().is_empty());
        assert_eq!(parsed.te_rules().len(), 3);
        assert_eq!(parsed.te_rules()[0].kind(), TeRuleKind::TypeTransition);
        assert_eq!(parsed.te_rules()[1].kind(), TeRuleKind::TypeChange);
        assert_eq!(parsed.te_rules()[2].kind(), TeRuleKind::TypeMember);
        assert_eq!(
            parsed.te_rules()[0].data(),
            &BinaryTeRuleData::DefaultType(1)
        );
        assert!(parsed.conditionals().is_empty());
        assert_eq!(parsed.rbac_rules().len(), 2);
        assert_eq!(
            parsed.rbac_rules()[0].data(),
            &BinaryRbacRuleData::RoleTransition {
                target: 1,
                target_class: 1,
                default: 1,
            }
        );
        assert_eq!(
            parsed.rbac_rules()[1].data(),
            &BinaryRbacRuleData::Allow { target: 1 }
        );
        assert!(parsed.filename_transitions().is_empty());
    }

    #[test]
    fn parses_version_23_implicit_attribute_gap() {
        let bytes = version_23_type_gap_prefix();
        let parsed = parse_policy_prefix(&bytes).expect("version 23 prefix should parse");
        assert_eq!(parsed.encoded_len(), bytes.len());
        assert_eq!(parsed.type_primary_count(), 2);
        assert_eq!(parsed.types().len(), 1);
        assert_eq!(parsed.types()[0].value(), 1);
        assert!(parsed.types()[0].is_permissive());
        assert_eq!(parsed.types()[0].expanded_types(), [0]);
        assert_eq!(parsed.types()[0].attributes(), [1]);
        assert_eq!(parsed.roles()[0].authorized_types(), [1]);
        assert!(parsed.users().is_empty());
        assert!(parsed.booleans().is_empty());
        assert!(parsed.sensitivities().is_empty());
        assert!(parsed.categories().is_empty());
        assert!(parsed.te_rules().is_empty());
        assert!(parsed.conditionals().is_empty());
        assert!(parsed.rbac_rules().is_empty());
        assert!(parsed.filename_transitions().is_empty());

        let policy = parsed
            .to_policy("synthetic-v23.policy".into())
            .expect("the synthetic owned policy must fit the default budget");
        assert_eq!(policy.type_symbols().len(), 2);
        let unnamed = &policy.type_symbols()[1];
        assert_eq!(unnamed.name(), "@ttr0000000002");
        assert!(unnamed.is_attribute());
        assert_eq!(unnamed.expanded_types(), [TypeId::from_raw(0)]);
    }

    #[test]
    fn owned_reconstruction_shares_the_parser_allocation_budget() {
        let bytes = policy_prefix();
        let source = std::path::Path::new("budgeted.policy");
        let parsed = parse_policy_prefix(&bytes).expect("synthetic policy should parse");
        let parser_bytes = parsed.retained_allocation_bytes();
        let peak_bytes = parsed
            .estimated_peak_allocation_bytes(source)
            .expect("the allocation estimate should fit usize");
        assert!(peak_bytes > parser_bytes);

        let insufficient_limits = ParserLimits {
            max_total_allocation_bytes: peak_bytes - 1,
            ..ParserLimits::default()
        };
        let insufficient = parse_policy_prefix_with_limits(&bytes, insufficient_limits)
            .expect("the parser-owned model alone should fit");
        assert!(matches!(
            insufficient.to_policy(source.to_path_buf()),
            Err(ParseError::LimitExceeded {
                resource: "owned policy reconstruction",
                requested,
                limit,
            }) if requested > limit && limit == (peak_bytes - 1) as u64
        ));

        let exact_limits = ParserLimits {
            max_total_allocation_bytes: peak_bytes,
            ..ParserLimits::default()
        };
        let exact = parse_policy_prefix_with_limits(&bytes, exact_limits)
            .expect("the parser-owned model should fit the exact peak budget");
        exact
            .to_policy(source.to_path_buf())
            .expect("owned reconstruction should fit the exact estimated peak budget");
    }

    #[test]
    fn every_complete_policy_truncation_is_rejected() {
        let bytes = policy_prefix();
        for length in 0..bytes.len() {
            assert!(
                parse_policy_prefix(&bytes[..length]).is_err(),
                "truncation at byte {length} was accepted"
            );
        }
        assert!(parse_policy_prefix(&bytes).is_ok());
    }

    #[test]
    fn rejects_trailing_data_and_input_larger_than_the_byte_limit() {
        let mut bytes = policy_prefix();
        let complete_length = bytes.len();
        bytes.push(0xaa);
        assert_eq!(
            parse_policy_prefix(&bytes),
            Err(ParseError::TrailingData {
                offset: complete_length,
                remaining: 1,
            })
        );

        let limits = ParserLimits {
            max_serialized_prefix_bytes: complete_length,
            ..ParserLimits::default()
        };
        assert_eq!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "serialized prefix bytes",
                requested: complete_length as u64 + 1,
                limit: complete_length as u64,
            })
        );
    }

    #[test]
    fn prefix_loader_detects_a_file_larger_than_the_byte_limit() {
        let bytes = policy_prefix();
        let limit = bytes.len() - 1;
        let limits = ParserLimits {
            max_serialized_prefix_bytes: limit,
            ..ParserLimits::default()
        };
        let path = std::env::temp_dir().join(format!(
            "setools-policy-binary-oversize-{}.policy",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).expect("temporary policy should be writable");
        let result = PureRustPrefixLoader::with_limits(limits).load(&path);
        std::fs::remove_file(&path).expect("temporary policy should be removable");
        assert!(matches!(
            result,
            Err(MetadataLoadError::Parse {
                source: ParseError::LimitExceeded {
                    resource: "serialized prefix bytes",
                    requested,
                    limit: actual_limit,
                },
                ..
            }) if requested == bytes.len() as u64 && actual_limit == limit as u64
        ));
    }

    #[test]
    fn policy_loader_reports_an_owned_reconstruction_budget_error() {
        let bytes = policy_prefix();
        let path = std::env::temp_dir().join(format!(
            "setools-policy-binary-owned-budget-{}.policy",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).expect("temporary policy should be writable");
        let parsed = parse_policy_prefix(&bytes).expect("synthetic policy should parse");
        let peak_bytes = parsed
            .estimated_peak_allocation_bytes(&path)
            .expect("the allocation estimate should fit usize");
        let limits = ParserLimits {
            max_total_allocation_bytes: peak_bytes - 1,
            ..ParserLimits::default()
        };
        let result = PureRustPolicyLoader::with_limits(limits).load(&path);
        std::fs::remove_file(&path).expect("temporary policy should be removable");
        assert!(matches!(
            result,
            Err(MetadataLoadError::Parse {
                source: ParseError::LimitExceeded {
                    resource: "owned policy reconstruction",
                    requested,
                    limit,
                },
                ..
            }) if requested > limit && limit == (peak_bytes - 1) as u64
        ));
    }

    #[test]
    fn one_bit_policy_mutations_never_panic() {
        let original = policy_prefix();
        let limits = ParserLimits {
            max_serialized_prefix_bytes: original.len(),
            max_total_allocation_bytes: 256 * 1024,
            ..ParserLimits::default()
        };
        for byte in 0..original.len() {
            for bit in 0..u8::BITS {
                let mut mutated = original.clone();
                mutated[byte] ^= 1 << bit;
                if let Ok(prefix) = parse_policy_prefix_with_limits(&mutated, limits) {
                    let _ = prefix.to_policy("mutated.policy".into());
                }
            }
        }
    }

    #[test]
    fn parses_legacy_implicit_process_mls_range_transition() {
        let prefix = parse_policy_prefix(&policy_prefix()).expect("synthetic policy should parse");
        let symbols = context_symbols(&prefix, 20);
        let mut classes = prefix.classes().to_vec();
        classes[0].name = "process".to_owned();
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 2);
        push_bitmap(&mut bytes, 1);
        push_bitmap(&mut bytes, 3);
        let mut cursor = Cursor::new(&bytes);
        let rules = read_mls_range_transitions(
            &mut cursor,
            &ParserLimits::default(),
            &mut AllocationBudget::new(64 * 1024),
            &symbols,
            &classes,
        )
        .expect("version 20 range transition should infer process class");
        assert_eq!(cursor.offset, bytes.len());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].source(), 1);
        assert_eq!(rules[0].target(), 2);
        assert_eq!(rules[0].target_class(), 1);
        assert_eq!(rules[0].default().high().categories(), [0, 1]);
    }

    #[test]
    fn parses_versioned_xen_object_contexts_and_genfs() {
        let prefix = parse_policy_prefix(&policy_prefix()).expect("synthetic prefix should parse");
        let symbols = context_symbols(&prefix, 30);
        let mut bytes = Vec::new();

        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_test_security_context(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 40);
        push_test_security_context(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0x20);
        push_u32(&mut bytes, 0x22);
        push_test_security_context(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u64(&mut bytes, 0x1_0000_0010);
        push_u64(&mut bytes, 0x1_0000_0012);
        push_test_security_context(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 0x30);
        push_test_security_context(&mut bytes);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 11);
        bytes.extend_from_slice(b"/soc/device");
        push_test_security_context(&mut bytes);

        let mut cursor = Cursor::new(&bytes);
        let rules = read_object_contexts(
            &mut cursor,
            &ParserLimits::default(),
            &mut AllocationBudget::new(64 * 1024),
            TargetPlatform::Xen,
            6,
            &symbols,
        )
        .expect("Xen version 30 object contexts should parse");
        assert_eq!(cursor.offset, bytes.len());
        assert_eq!(rules.len(), 6);
        assert!(matches!(
            rules[0],
            BinaryLabelingRule::InitialSid { sid: 1, .. }
        ));
        assert!(matches!(
            rules[1],
            BinaryLabelingRule::Pirqcon { irq: 40, .. }
        ));
        assert!(matches!(
            rules[3],
            BinaryLabelingRule::Iomemcon {
                low: 0x1_0000_0010,
                high: 0x1_0000_0012,
                ..
            }
        ));
        assert!(matches!(
            &rules[5],
            BinaryLabelingRule::Devicetreecon { path, .. } if path == "/soc/device"
        ));

        let old_symbols = context_symbols(&prefix, 24);
        let mut old_bytes = Vec::new();
        for _ in 0..3 {
            push_u32(&mut old_bytes, 0);
        }
        push_u32(&mut old_bytes, 1);
        push_u32(&mut old_bytes, 0xffff_fff0);
        push_u32(&mut old_bytes, 0xffff_fff2);
        push_test_security_context(&mut old_bytes);
        push_u32(&mut old_bytes, 0);
        let old_rules = read_object_contexts(
            &mut Cursor::new(&old_bytes),
            &ParserLimits::default(),
            &mut AllocationBudget::new(16 * 1024),
            TargetPlatform::Xen,
            5,
            &old_symbols,
        )
        .expect("Xen version 24 must use 32-bit I/O-memory values");
        assert!(matches!(
            old_rules.as_slice(),
            [BinaryLabelingRule::Iomemcon {
                low: 0xffff_fff0,
                high: 0xffff_fff2,
                ..
            }]
        ));

        let mut genfs = Vec::new();
        push_u32(&mut genfs, 1);
        push_u32(&mut genfs, 4);
        genfs.extend_from_slice(b"proc");
        push_u32(&mut genfs, 1);
        push_u32(&mut genfs, 1);
        genfs.extend_from_slice(b"/");
        push_u32(&mut genfs, 1);
        push_test_security_context(&mut genfs);
        let mut genfs_rules = Vec::new();
        let mut genfs_cursor = Cursor::new(&genfs);
        read_genfs_contexts(
            &mut genfs_cursor,
            &ParserLimits::default(),
            &mut AllocationBudget::new(16 * 1024),
            &symbols,
            prefix.classes(),
            &mut genfs_rules,
        )
        .expect("genfs records should parse");
        assert_eq!(genfs_cursor.offset, genfs.len());
        assert!(matches!(
            genfs_rules.as_slice(),
            [BinaryLabelingRule::Genfscon {
                filesystem,
                path,
                target_class: Some(1),
                ..
            }] if filesystem == "proc" && path == "/"
        ));

        let mut duplicate_genfs = Vec::new();
        push_u32(&mut duplicate_genfs, 2);
        for _ in 0..2 {
            push_u32(&mut duplicate_genfs, 4);
            duplicate_genfs.extend_from_slice(b"proc");
            push_u32(&mut duplicate_genfs, 0);
        }
        assert_eq!(
            read_genfs_contexts(
                &mut Cursor::new(&duplicate_genfs),
                &ParserLimits::default(),
                &mut AllocationBudget::new(16 * 1024),
                &symbols,
                prefix.classes(),
                &mut Vec::new(),
            ),
            Err(ParseError::InvalidGenfs("duplicate filesystem type"))
        );

        let limits = ParserLimits {
            max_object_contexts: 0,
            ..ParserLimits::default()
        };
        assert!(matches!(
            read_object_contexts(
                &mut Cursor::new(&bytes),
                &limits,
                &mut AllocationBudget::new(64 * 1024),
                TargetPlatform::Xen,
                6,
                &symbols,
            ),
            Err(ParseError::LimitExceeded {
                resource: "object contexts",
                ..
            })
        ));

        let limits = ParserLimits {
            max_genfs_filesystems: 0,
            ..ParserLimits::default()
        };
        assert!(matches!(
            read_genfs_contexts(
                &mut Cursor::new(&genfs),
                &limits,
                &mut AllocationBudget::new(16 * 1024),
                &symbols,
                prefix.classes(),
                &mut Vec::new(),
            ),
            Err(ParseError::LimitExceeded {
                resource: "genfs filesystems",
                ..
            })
        ));
    }

    #[test]
    fn enforces_count_string_and_total_allocation_limits() {
        let bytes = policy_prefix();

        let mut limits = ParserLimits {
            max_common_symbols: 0,
            ..ParserLimits::default()
        };
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "common primary values",
                ..
            })
        ));

        limits.max_common_symbols = 1;
        limits.max_string_bytes = 4;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "symbol name bytes",
                ..
            })
        ));

        limits.max_string_bytes = 64;
        limits.max_class_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "object-class primary values",
                ..
            })
        ));

        limits.max_class_symbols = u32::from(u16::MAX);
        limits.max_constraints_per_class = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "constraints per object class",
                ..
            })
        ));

        limits.max_constraints_per_class = 65_536;
        limits.max_constraint_expressions = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "expressions per constraint",
                ..
            })
        ));

        limits.max_constraint_expressions = 4_096;
        limits.max_role_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "role primary values",
                ..
            })
        ));

        limits.max_role_symbols = 65_536;
        limits.max_type_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "type primary values",
                ..
            })
        ));

        limits.max_type_symbols = 1_048_576;
        limits.max_user_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "user primary values",
                ..
            })
        ));

        limits.max_user_symbols = 65_536;
        limits.max_boolean_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "Boolean primary values",
                ..
            })
        ));

        limits.max_boolean_symbols = 1_048_576;
        limits.max_sensitivity_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "sensitivity primary values",
                ..
            })
        ));

        limits.max_sensitivity_symbols = 65_536;
        limits.max_category_symbols = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "category primary values",
                ..
            })
        ));

        limits.max_category_symbols = 1_048_576;
        limits.max_te_rules = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "access-vector table records",
                ..
            })
        ));

        limits.max_te_rules = 16_777_216;
        limits.max_conditionals = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "Boolean conditionals",
                ..
            })
        ));

        limits.max_conditionals = 1_048_576;
        limits.max_conditional_tokens = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "tokens per Boolean conditional",
                ..
            })
        ));

        limits.max_conditional_tokens = 4_096;
        limits.max_rbac_rules = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "role-transition rules",
                ..
            })
        ));

        limits.max_rbac_rules = 4_194_304;
        limits.max_filename_transition_records = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "compressed filename-transition records",
                ..
            })
        ));

        limits.max_filename_transition_records = 4_194_304;
        limits.max_filename_transition_datums = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "filename-transition datums",
                ..
            })
        ));

        limits.max_filename_transition_datums = 1_048_576;
        limits.max_filename_transitions = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "decoded filename transitions",
                ..
            })
        ));

        limits.max_filename_transitions = 16_777_216;
        limits.max_mls_range_transitions = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "MLS range transitions",
                ..
            })
        ));

        limits.max_mls_range_transitions = 4_194_304;
        limits.max_type_attribute_memberships = 0;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "type-attribute memberships",
                ..
            })
        ));

        limits.max_type_attribute_memberships = 16_777_216;
        limits.max_total_allocation_bytes = 1;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded { .. })
        ));

        limits = ParserLimits::default();
        limits.max_serialized_prefix_bytes = bytes.len() - 1;
        assert!(matches!(
            parse_policy_prefix_with_limits(&bytes, limits),
            Err(ParseError::LimitExceeded {
                resource: "serialized prefix bytes",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_bitmap_and_permission_values() {
        let mut invalid_bitmap = policy_prefix();
        invalid_bitmap[32] = 32;
        assert!(matches!(
            parse_policy_prefix(&invalid_bitmap),
            Err(ParseError::InvalidBitmap(_))
        ));

        let mut unknown_capability = policy_prefix();
        unknown_capability[48..56].copy_from_slice(
            &((1_u64 << 0) | (1_u64 << 10) | (1_u64 << 14) | (1_u64 << 15)).to_le_bytes(),
        );
        assert!(matches!(
            parse_policy_prefix(&unknown_capability),
            Err(ParseError::InvalidSymbolTable {
                table: "policy capability bitmap",
                ..
            })
        ));

        let mut concrete_attribute_bit = policy_prefix();
        let first_type_map = concrete_attribute_bit.len() - 3 * 24;
        concrete_attribute_bit[first_type_map + 16..first_type_map + 24]
            .copy_from_slice(&0b111_u64.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&concrete_attribute_bit),
            Err(ParseError::InvalidTypeAttributeMap(
                "a membership bit resolves to a concrete type"
            ))
        ));

        let mut invalid_permission = policy_prefix();
        let read_offset = invalid_permission
            .windows(b"read".len())
            .position(|window| window == b"read")
            .expect("common read permission must be present");
        let permission_value_offset = read_offset - 4;
        invalid_permission[permission_value_offset..permission_value_offset + 4]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&invalid_permission),
            Err(ParseError::InvalidSymbolValue {
                table: "common permission",
                value: 3,
                primary_count: 2
            })
        ));

        let mut invalid_constraint = policy_prefix();
        let transition_offset = invalid_constraint
            .windows(b"transition".len())
            .position(|window| window == b"transition")
            .expect("class-local transition permission must be present");
        let operator_offset = transition_offset + b"transition".len() + 16;
        invalid_constraint[operator_offset..operator_offset + 4]
            .copy_from_slice(&6_u32.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&invalid_constraint),
            Err(ParseError::InvalidConstraint("unknown comparison operator"))
        ));
    }

    #[test]
    fn rejects_invalid_role_and_type_symbols() {
        let mut invalid_role = policy_prefix();
        let object_role = invalid_role
            .windows(b"object_r".len())
            .position(|window| window == b"object_r")
            .expect("object_r role must be present");
        invalid_role[object_role] = b'x';
        assert!(matches!(
            parse_policy_prefix(&invalid_role),
            Err(ParseError::InvalidSymbolTable {
                table: "role",
                reason: "one-based role value 1 is not object_r"
            })
        ));

        let mut invalid_type = policy_prefix();
        let domain = invalid_type
            .windows(b"domain".len())
            .position(|window| window == b"domain")
            .expect("domain attribute must be present");
        invalid_type[domain - 8..domain - 4]
            .copy_from_slice(&TYPE_PROPERTY_ATTRIBUTE.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&invalid_type),
            Err(ParseError::InvalidSymbolTable {
                table: "type",
                reason: "a non-primary entry is marked as an attribute"
            })
        ));
    }

    #[test]
    fn rejects_invalid_boolean_and_mls_symbols() {
        let mut invalid_boolean = policy_prefix();
        let enabled = invalid_boolean
            .windows(b"enabled".len())
            .position(|window| window == b"enabled")
            .expect("enabled Boolean must be present");
        invalid_boolean[enabled - 8..enabled - 4].copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&invalid_boolean),
            Err(ParseError::InvalidSymbolTable {
                table: "Boolean",
                reason: "the default state is not zero or one"
            })
        ));

        let mut invalid_category = policy_prefix();
        let alias = invalid_category
            .windows(b"cat_alias".len())
            .position(|window| window == b"cat_alias")
            .expect("category alias must be present");
        invalid_category[alias - 4..alias].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&invalid_category),
            Err(ParseError::DuplicateSymbol {
                table: "primary category value",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_avtab_and_conditional_records() {
        let mut invalid_source = policy_prefix();
        let source_offset = invalid_source
            .windows(8)
            .position(|window| window == [1, 0, 2, 0, 1, 0, 1, 0])
            .expect("the first modern AVTAB key must be present");
        invalid_source[source_offset..source_offset + 2].copy_from_slice(&0_u16.to_le_bytes());
        assert!(matches!(
            parse_policy_prefix(&invalid_source),
            Err(ParseError::InvalidSymbolValue {
                table: "TE type or attribute",
                value: 0,
                ..
            })
        ));

        let mut invalid_xperm = policy_prefix();
        let namespace_offset = invalid_xperm
            .windows(8)
            .position(|window| window == [1, 0, 1, 0, 1, 0, 0, 1])
            .expect("the xperm AVTAB key must be present")
            + 8;
        invalid_xperm[namespace_offset] = 9;
        assert_eq!(
            parse_policy_prefix(&invalid_xperm),
            Err(ParseError::InvalidAvtab(
                "extended-permission payload has an unknown namespace"
            ))
        );

        let mut driver_permissions = [0_u32; 8];
        driver_permissions[0] = 1 << 0x12;
        let (kind, values) = decode_xperm_values(
            AVTAB_XPERMS_IOCTLDRIVER,
            0,
            driver_permissions,
            &mut AllocationBudget::new(1024),
        )
        .expect("an ioctl driver bitmap should expand");
        assert_eq!(kind, XpermKind::Ioctl);
        assert_eq!(values.len(), 256);
        assert_eq!(values[0], 0x1200);
        assert_eq!(values[255], 0x12ff);

        let mut invalid_conditional = Vec::new();
        push_u32(&mut invalid_conditional, 1);
        push_u32(&mut invalid_conditional, 8);
        push_u32(&mut invalid_conditional, 0);
        assert_eq!(
            read_conditional_tokens(
                &mut Cursor::new(&invalid_conditional),
                &ParserLimits::default(),
                &mut AllocationBudget::new(1024),
                &[BinaryBooleanSymbol {
                    name: "enabled".to_owned(),
                    value: 1,
                    state: true,
                }],
            ),
            Err(ParseError::InvalidConditional(
                "expression contains an unknown token kind"
            ))
        );

        let booleans = [BinaryBooleanSymbol {
            name: "enabled".to_owned(),
            value: 1,
            state: true,
        }];
        let mut postfix = Vec::new();
        push_u32(&mut postfix, 4);
        for (kind, boolean) in [(1, 1), (1, 1), (4, 0), (2, 0)] {
            push_u32(&mut postfix, kind);
            push_u32(&mut postfix, boolean);
        }
        let tokens = read_conditional_tokens(
            &mut Cursor::new(&postfix),
            &ParserLimits::default(),
            &mut AllocationBudget::new(1024),
            &booleans,
        )
        .expect("a valid Boolean postfix expression should parse");
        assert_eq!(
            tokens,
            [
                ConditionalToken::Boolean(BooleanId::from_raw(0)),
                ConditionalToken::Boolean(BooleanId::from_raw(0)),
                ConditionalToken::And,
                ConditionalToken::Not,
            ]
        );

        let mut underflow = Vec::new();
        push_u32(&mut underflow, 1);
        push_u32(&mut underflow, 3);
        push_u32(&mut underflow, 0);
        assert_eq!(
            read_conditional_tokens(
                &mut Cursor::new(&underflow),
                &ParserLimits::default(),
                &mut AllocationBudget::new(1024),
                &booleans,
            ),
            Err(ParseError::InvalidConditional(
                "postfix operator has too few operands"
            ))
        );
    }

    #[test]
    fn validates_rbac_and_filename_transition_records() {
        let prefix = parse_policy_prefix(&policy_prefix()).expect("synthetic prefix should parse");
        let mut invalid_rbac = Vec::new();
        push_u32(&mut invalid_rbac, 1);
        for value in [0, 1, 1, 1] {
            push_u32(&mut invalid_rbac, value);
        }
        assert!(matches!(
            read_rbac_rules(
                &mut Cursor::new(&invalid_rbac),
                &ParserLimits::default(),
                &mut AllocationBudget::new(4096),
                35,
                TargetPlatform::Selinux,
                prefix.type_primary_count(),
                prefix.types(),
                prefix.classes(),
                prefix.roles(),
            ),
            Err(ParseError::InvalidSymbolValue {
                table: "RBAC source role",
                value: 0,
                ..
            })
        ));

        let mut duplicate_compat = Vec::new();
        push_u32(&mut duplicate_compat, 2);
        for default_type in [1, 3] {
            push_u32(&mut duplicate_compat, 5);
            duplicate_compat.extend_from_slice(b"entry");
            for value in [1, 1, 1, default_type] {
                push_u32(&mut duplicate_compat, value);
            }
        }
        let rules = read_filename_transitions(
            &mut Cursor::new(&duplicate_compat),
            &ParserLimits::default(),
            &mut AllocationBudget::new(16 * 1024),
            30,
            prefix.type_primary_count(),
            prefix.types(),
            prefix.classes(),
        )
        .expect("old-format duplicate filename transitions retain the first rule");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].default_type(), 1);

        let mut empty_compressed = Vec::new();
        push_u32(&mut empty_compressed, 1);
        push_u32(&mut empty_compressed, 5);
        empty_compressed.extend_from_slice(b"entry");
        push_u32(&mut empty_compressed, 1);
        push_u32(&mut empty_compressed, 1);
        push_u32(&mut empty_compressed, 0);
        assert_eq!(
            read_filename_transitions(
                &mut Cursor::new(&empty_compressed),
                &ParserLimits::default(),
                &mut AllocationBudget::new(16 * 1024),
                35,
                prefix.type_primary_count(),
                prefix.types(),
                prefix.classes(),
            ),
            Err(ParseError::InvalidFilenameTransition(
                "a compressed record has no datum"
            ))
        );

        let mut overlapping_compressed = Vec::new();
        push_u32(&mut overlapping_compressed, 1);
        push_u32(&mut overlapping_compressed, 5);
        overlapping_compressed.extend_from_slice(b"entry");
        push_u32(&mut overlapping_compressed, 1);
        push_u32(&mut overlapping_compressed, 1);
        push_u32(&mut overlapping_compressed, 2);
        push_bitmap(&mut overlapping_compressed, 1);
        push_u32(&mut overlapping_compressed, 1);
        push_bitmap(&mut overlapping_compressed, 1);
        push_u32(&mut overlapping_compressed, 3);
        assert_eq!(
            read_filename_transitions(
                &mut Cursor::new(&overlapping_compressed),
                &ParserLimits::default(),
                &mut AllocationBudget::new(16 * 1024),
                35,
                prefix.type_primary_count(),
                prefix.types(),
                prefix.classes(),
            ),
            Err(ParseError::InvalidFilenameTransition(
                "compressed datum source bitmaps overlap"
            ))
        );
    }

    #[test]
    fn rejects_truncated_and_unbounded_headers() {
        assert!(matches!(
            parse_policy_header(&[0x8c, 0xff]),
            Err(ParseError::Truncated { .. })
        ));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&POLICYDB_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&33_u32.to_le_bytes());
        assert_eq!(
            parse_policy_header(&bytes),
            Err(ParseError::InvalidIdentifierLength(33))
        );
    }

    #[test]
    fn distinguishes_modules_and_invalid_config() {
        let mut module = header(b"SE Linux", 35, 0);
        module[..4].copy_from_slice(&POLICYDB_MODULE_MAGIC.to_le_bytes());
        assert_eq!(
            parse_policy_header(&module),
            Err(ParseError::UnsupportedModulePolicy)
        );
        assert_eq!(
            parse_policy_header(&header(b"SE Linux", 35, 6)),
            Err(ParseError::InvalidUnknownHandling(6))
        );
    }
}
