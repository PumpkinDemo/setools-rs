//! Immutable, owned SELinux policy model and loader boundary.
//!
//! Native pointers and lifetimes never become part of these public types. All
//! names, memberships, permissions, and rules are copied before a loader
//! returns [`Policy`].

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

mod seinfo;

pub use seinfo::{
    CommonPermissionSet, ConstraintExpressionToken, ConstraintKind, ConstraintOperator,
    ConstraintRule, DefaultRangePart, DefaultRule, DefaultRuleKind, DefaultValue, FsUseKind,
    LabelingRule, PortProtocol, SecurityContext, SeinfoData, User,
};

macro_rules! policy_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u32);

        impl $name {
            /// Creates a policy-local ID from its dense zero-based value.
            #[must_use]
            pub const fn from_raw(raw: u32) -> Self {
                Self(raw)
            }

            /// Returns the dense zero-based value within its owning policy.
            #[must_use]
            pub const fn as_raw(self) -> u32 {
                self.0
            }
        }
    };
}

policy_id!(TypeId, "Policy-local type identifier.");
policy_id!(AttributeId, "Policy-local type-attribute identifier.");
policy_id!(ClassId, "Policy-local object-class identifier.");
policy_id!(PermissionId, "Policy-local class permission identifier.");
policy_id!(BooleanId, "Policy-local Boolean identifier.");
policy_id!(RoleId, "Policy-local role identifier.");
policy_id!(UserId, "Policy-local SELinux user identifier.");
policy_id!(SensitivityId, "Policy-local MLS sensitivity identifier.");
policy_id!(CategoryId, "Policy-local MLS category identifier.");
policy_id!(
    ConditionalId,
    "Policy-local conditional-expression identifier."
);

/// A policy-local symbol that is either a concrete type or an attribute.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypeOrAttributeId {
    /// Concrete type.
    Type(TypeId),
    /// Type attribute.
    Attribute(AttributeId),
}

impl TypeOrAttributeId {
    /// Returns the shared zero-based libsepol symbol value.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Type(id) => id.as_raw(),
            Self::Attribute(id) => id.as_raw(),
        }
    }
}

/// Policy target platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetPlatform {
    /// Linux SELinux policy.
    Selinux,
    /// Xen security policy.
    Xen,
}

/// Behavior requested for unknown object classes or permissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleUnknown {
    /// Deny unknown accesses.
    Deny,
    /// Reject policies containing unknown values.
    Reject,
    /// Allow unknown accesses.
    Allow,
}

/// Metadata read from a binary policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyMetadata {
    /// Binary policy format version.
    pub version: u32,
    /// Whether MLS is enabled.
    pub mls: bool,
    /// Policy target platform.
    pub target: TargetPlatform,
    /// Unknown class and permission behavior.
    pub handle_unknown: HandleUnknown,
}

/// An owned type or type-attribute record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeSymbol {
    id: TypeOrAttributeId,
    name: String,
    aliases: Vec<String>,
    expanded_types: Vec<TypeId>,
    permissive: bool,
    bound: Option<TypeId>,
}

/// An owned SELinux role record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    id: RoleId,
    name: String,
    expanded_roles: Vec<RoleId>,
    authorized_types: Vec<TypeId>,
}

impl Role {
    /// Creates a role and its indirect-match expansion.
    #[must_use]
    pub fn new(id: RoleId, name: String, expanded_roles: Vec<RoleId>) -> Self {
        Self {
            id,
            name,
            expanded_roles,
            authorized_types: Vec::new(),
        }
    }

    /// Returns the policy-local role ID.
    #[must_use]
    pub const fn id(&self) -> RoleId {
        self.id
    }

    /// Returns the role name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the concrete role expansion used by indirect matching.
    #[must_use]
    pub fn expanded_roles(&self) -> &[RoleId] {
        &self.expanded_roles
    }

    /// Adds the concrete types authorized for this role.
    #[must_use]
    pub fn with_authorized_types(mut self, mut authorized_types: Vec<TypeId>) -> Self {
        authorized_types.sort_unstable();
        authorized_types.dedup();
        self.authorized_types = authorized_types;
        self
    }

    /// Returns the concrete types authorized for this role.
    #[must_use]
    pub fn authorized_types(&self) -> &[TypeId] {
        &self.authorized_types
    }
}

impl TypeSymbol {
    /// Creates a concrete type record.
    #[must_use]
    pub fn new_type(id: TypeId, name: String) -> Self {
        Self {
            id: TypeOrAttributeId::Type(id),
            name,
            aliases: Vec::new(),
            expanded_types: vec![id],
            permissive: false,
            bound: None,
        }
    }

    /// Creates an attribute and its concrete member expansion.
    #[must_use]
    pub fn new_attribute(id: AttributeId, name: String, members: Vec<TypeId>) -> Self {
        Self {
            id: TypeOrAttributeId::Attribute(id),
            name,
            aliases: Vec::new(),
            expanded_types: members,
            permissive: false,
            bound: None,
        }
    }

    /// Returns this symbol's policy-local ID.
    #[must_use]
    pub const fn id(&self) -> TypeOrAttributeId {
        self.id
    }

    /// Returns the canonical symbol name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds aliases in the policy's declaration/hash-table order.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Returns aliases in the policy's native order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    /// Returns the concrete type expansion used by indirect matching.
    #[must_use]
    pub fn expanded_types(&self) -> &[TypeId] {
        &self.expanded_types
    }

    /// Returns whether this symbol is an attribute.
    #[must_use]
    pub const fn is_attribute(&self) -> bool {
        matches!(self.id, TypeOrAttributeId::Attribute(_))
    }

    /// Adds `seinfo` properties copied from the native type datum.
    #[must_use]
    pub const fn with_seinfo_properties(mut self, permissive: bool, bound: Option<TypeId>) -> Self {
        self.permissive = permissive;
        self.bound = bound;
        self
    }

    /// Returns whether this concrete type is permissive.
    #[must_use]
    pub const fn is_permissive(&self) -> bool {
        self.permissive
    }

    /// Returns this type's bound parent, when present.
    #[must_use]
    pub const fn bound(&self) -> Option<TypeId> {
        self.bound
    }
}

/// A class-local permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permission {
    id: PermissionId,
    name: String,
}

impl Permission {
    /// Creates a permission record.
    #[must_use]
    pub fn new(id: PermissionId, name: String) -> Self {
        Self { id, name }
    }

    /// Returns the class-local permission ID.
    #[must_use]
    pub const fn id(&self) -> PermissionId {
        self.id
    }

    /// Returns the permission name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// An SELinux object class and its complete inherited permission vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectClass {
    id: ClassId,
    name: String,
    permissions: Vec<Permission>,
    common: Option<String>,
    local_permissions: Vec<String>,
}

impl ObjectClass {
    /// Creates an object-class record.
    #[must_use]
    pub fn new(id: ClassId, name: String, permissions: Vec<Permission>) -> Self {
        Self {
            id,
            name,
            permissions,
            common: None,
            local_permissions: Vec::new(),
        }
    }

    /// Returns the policy-local class ID.
    #[must_use]
    pub const fn id(&self) -> ClassId {
        self.id
    }

    /// Returns the class name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns permissions in access-vector bit order.
    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// Adds declaration-only information used to expand this class.
    #[must_use]
    pub fn with_declaration(
        mut self,
        common: Option<String>,
        mut local_permissions: Vec<String>,
    ) -> Self {
        local_permissions.sort_unstable();
        local_permissions.dedup();
        self.common = common;
        self.local_permissions = local_permissions;
        self
    }

    /// Returns the inherited common permission-set name.
    #[must_use]
    pub fn common(&self) -> Option<&str> {
        self.common.as_deref()
    }

    /// Returns permissions declared directly on this class.
    #[must_use]
    pub fn local_permissions(&self) -> &[String] {
        &self.local_permissions
    }

    /// Looks up a permission by its class-local ID.
    #[must_use]
    pub fn permission(&self, id: PermissionId) -> Option<&Permission> {
        self.permissions.get(id.as_raw() as usize)
    }

    /// Looks up a permission name.
    #[must_use]
    pub fn permission_by_name(&self, name: &str) -> Option<&Permission> {
        self.permissions
            .iter()
            .find(|permission| permission.name() == name)
    }
}

/// Type-enforcement rule kind represented in the owned model.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TeRuleKind {
    /// Standard allow rule.
    Allow,
    /// Extended-permission allow rule.
    AllowXperm,
    /// Auditallow rule.
    AuditAllow,
    /// Extended-permission auditallow rule.
    AuditAllowXperm,
    /// Dontaudit rule.
    DontAudit,
    /// Extended-permission dontaudit rule.
    DontAuditXperm,
    /// Type transition rule.
    TypeTransition,
    /// Type change rule.
    TypeChange,
    /// Type member rule.
    TypeMember,
}

impl TeRuleKind {
    /// Returns the compatible policy-language keyword.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowXperm => "allowxperm",
            Self::AuditAllow => "auditallow",
            Self::AuditAllowXperm => "auditallowxperm",
            Self::DontAudit => "dontaudit",
            Self::DontAuditXperm => "dontauditxperm",
            Self::TypeTransition => "type_transition",
            Self::TypeChange => "type_change",
            Self::TypeMember => "type_member",
        }
    }
}

/// Extended-permission namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XpermKind {
    /// ioctl command number.
    Ioctl,
    /// Netlink message number.
    NetlinkMessage,
}

impl XpermKind {
    /// Returns the compatible policy-language name.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Ioctl => "ioctl",
            Self::NetlinkMessage => "nlmsg",
        }
    }
}

/// A named policy Boolean and its default state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Boolean {
    id: BooleanId,
    name: String,
    state: bool,
}

impl Boolean {
    /// Creates an owned Boolean record.
    #[must_use]
    pub fn new(id: BooleanId, name: String, state: bool) -> Self {
        Self { id, name, state }
    }

    /// Returns the policy-local Boolean ID.
    #[must_use]
    pub const fn id(&self) -> BooleanId {
        self.id
    }

    /// Returns the Boolean name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the default policy state.
    #[must_use]
    pub const fn state(&self) -> bool {
        self.state
    }
}

/// A postfix conditional-expression token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalToken {
    /// Boolean operand.
    Boolean(BooleanId),
    /// Logical negation.
    Not,
    /// Logical disjunction.
    Or,
    /// Logical conjunction.
    And,
    /// Exclusive disjunction.
    Xor,
    /// Equality comparison.
    Equal,
    /// Inequality comparison.
    NotEqual,
}

/// An owned conditional expression in libsepol postfix order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conditional {
    id: ConditionalId,
    tokens: Vec<ConditionalToken>,
    booleans: Vec<BooleanId>,
}

impl Conditional {
    /// Creates a conditional expression and derives its unique Boolean set.
    #[must_use]
    pub fn new(id: ConditionalId, tokens: Vec<ConditionalToken>) -> Self {
        let mut booleans = tokens
            .iter()
            .filter_map(|token| match token {
                ConditionalToken::Boolean(id) => Some(*id),
                _ => None,
            })
            .collect::<Vec<_>>();
        booleans.sort_unstable();
        booleans.dedup();
        Self {
            id,
            tokens,
            booleans,
        }
    }

    /// Returns the policy-local conditional ID.
    #[must_use]
    pub const fn id(&self) -> ConditionalId {
        self.id
    }

    /// Returns the postfix expression tokens.
    #[must_use]
    pub fn tokens(&self) -> &[ConditionalToken] {
        &self.tokens
    }

    /// Returns the sorted unique Boolean IDs referenced by the expression.
    #[must_use]
    pub fn booleans(&self) -> &[BooleanId] {
        &self.booleans
    }
}

/// A rule's association with one branch of a conditional expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleCondition {
    conditional: ConditionalId,
    block: bool,
}

impl RuleCondition {
    /// Creates a conditional branch reference.
    #[must_use]
    pub const fn new(conditional: ConditionalId, block: bool) -> Self {
        Self { conditional, block }
    }

    /// Returns the conditional expression ID.
    #[must_use]
    pub const fn conditional(self) -> ConditionalId {
        self.conditional
    }

    /// Returns `true` for the true block and `false` for the else block.
    #[must_use]
    pub const fn block(self) -> bool {
        self.block
    }
}

/// Rule-kind-specific payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeRuleData {
    /// Standard access-vector permission IDs.
    Permissions(Vec<PermissionId>),
    /// Extended permission values.
    ExtendedPermissions {
        /// Extended-permission namespace.
        kind: XpermKind,
        /// Sorted individual 16-bit values.
        values: Vec<u16>,
    },
    /// Default type for a type transition/change/member rule.
    DefaultType {
        /// Default concrete type.
        default: TypeId,
        /// Last path component for a filename type transition.
        filename: Option<String>,
    },
}

/// An owned type-enforcement rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeRule {
    kind: TeRuleKind,
    source: TypeOrAttributeId,
    target: TypeOrAttributeId,
    target_class: ClassId,
    data: TeRuleData,
    condition: Option<RuleCondition>,
}

/// RBAC rule kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RbacRuleKind {
    /// Permit a transition from one role to another.
    Allow,
    /// Select a default role for a type/class transition.
    RoleTransition,
}

impl RbacRuleKind {
    /// Returns the compatible policy-language keyword.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::RoleTransition => "role_transition",
        }
    }
}

/// Kind-specific RBAC rule payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RbacRuleData {
    /// Target role of an RBAC allow rule.
    Allow {
        /// Role which may be entered.
        target: RoleId,
    },
    /// Target type, object class, and default role of a role transition.
    RoleTransition {
        /// Executable or object type.
        target: TypeOrAttributeId,
        /// Object class selected by the rule.
        target_class: ClassId,
        /// New role.
        default: RoleId,
    },
}

/// An owned RBAC rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RbacRule {
    source: RoleId,
    data: RbacRuleData,
}

impl RbacRule {
    /// Creates an RBAC rule.
    #[must_use]
    pub const fn new(source: RoleId, data: RbacRuleData) -> Self {
        Self { source, data }
    }

    /// Returns the rule kind.
    #[must_use]
    pub const fn kind(&self) -> RbacRuleKind {
        match self.data {
            RbacRuleData::Allow { .. } => RbacRuleKind::Allow,
            RbacRuleData::RoleTransition { .. } => RbacRuleKind::RoleTransition,
        }
    }

    /// Returns the source role.
    #[must_use]
    pub const fn source(&self) -> RoleId {
        self.source
    }

    /// Returns the rule payload.
    #[must_use]
    pub const fn data(&self) -> &RbacRuleData {
        &self.data
    }
}

/// An MLS sensitivity in declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sensitivity {
    id: SensitivityId,
    name: String,
    aliases: Vec<String>,
}

impl Sensitivity {
    /// Creates a sensitivity record.
    #[must_use]
    pub fn new(id: SensitivityId, name: String) -> Self {
        Self {
            id,
            name,
            aliases: Vec::new(),
        }
    }

    /// Returns the policy-local ID.
    #[must_use]
    pub const fn id(&self) -> SensitivityId {
        self.id
    }

    /// Returns the canonical sensitivity name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds sensitivity aliases.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Returns aliases in the policy's native order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

/// An MLS category in declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Category {
    id: CategoryId,
    name: String,
    aliases: Vec<String>,
}

impl Category {
    /// Creates a category record.
    #[must_use]
    pub fn new(id: CategoryId, name: String) -> Self {
        Self {
            id,
            name,
            aliases: Vec::new(),
        }
    }

    /// Returns the policy-local ID.
    #[must_use]
    pub const fn id(&self) -> CategoryId {
        self.id
    }

    /// Returns the canonical category name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Adds category aliases.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Returns aliases in the policy's native order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

/// One MLS level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsLevel {
    sensitivity: SensitivityId,
    categories: Vec<CategoryId>,
}

impl MlsLevel {
    /// Creates an MLS level with categories in declaration order.
    #[must_use]
    pub fn new(sensitivity: SensitivityId, categories: Vec<CategoryId>) -> Self {
        Self {
            sensitivity,
            categories,
        }
    }

    /// Returns the sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> SensitivityId {
        self.sensitivity
    }

    /// Returns categories in declaration order.
    #[must_use]
    pub fn categories(&self) -> &[CategoryId] {
        &self.categories
    }
}

/// An inclusive low-to-high MLS range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsRange {
    low: MlsLevel,
    high: MlsLevel,
}

impl MlsRange {
    /// Creates an MLS range.
    #[must_use]
    pub const fn new(low: MlsLevel, high: MlsLevel) -> Self {
        Self { low, high }
    }

    /// Returns the low level.
    #[must_use]
    pub const fn low(&self) -> &MlsLevel {
        &self.low
    }

    /// Returns the high level.
    #[must_use]
    pub const fn high(&self) -> &MlsLevel {
        &self.high
    }
}

/// An owned MLS range transition rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsRule {
    source: TypeOrAttributeId,
    target: TypeOrAttributeId,
    target_class: ClassId,
    default: MlsRange,
}

impl MlsRule {
    /// Creates a range transition rule.
    #[must_use]
    pub const fn new(
        source: TypeOrAttributeId,
        target: TypeOrAttributeId,
        target_class: ClassId,
        default: MlsRange,
    ) -> Self {
        Self {
            source,
            target,
            target_class,
            default,
        }
    }

    /// Returns the source type.
    #[must_use]
    pub const fn source(&self) -> TypeOrAttributeId {
        self.source
    }

    /// Returns the target type.
    #[must_use]
    pub const fn target(&self) -> TypeOrAttributeId {
        self.target
    }

    /// Returns the object class.
    #[must_use]
    pub const fn target_class(&self) -> ClassId {
        self.target_class
    }

    /// Returns the default MLS range.
    #[must_use]
    pub const fn default(&self) -> &MlsRange {
        &self.default
    }
}

impl TeRule {
    /// Creates an unconditional rule copied from libsepol.
    #[must_use]
    pub const fn new(
        kind: TeRuleKind,
        source: TypeOrAttributeId,
        target: TypeOrAttributeId,
        target_class: ClassId,
        data: TeRuleData,
    ) -> Self {
        Self {
            kind,
            source,
            target,
            target_class,
            data,
            condition: None,
        }
    }

    /// Adds a conditional branch to a newly constructed rule.
    #[must_use]
    pub const fn with_condition(mut self, condition: RuleCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    /// Returns the rule kind.
    #[must_use]
    pub const fn kind(&self) -> TeRuleKind {
        self.kind
    }

    /// Returns the source type or attribute.
    #[must_use]
    pub const fn source(&self) -> TypeOrAttributeId {
        self.source
    }

    /// Returns the target type or attribute.
    #[must_use]
    pub const fn target(&self) -> TypeOrAttributeId {
        self.target
    }

    /// Returns the object class.
    #[must_use]
    pub const fn target_class(&self) -> ClassId {
        self.target_class
    }

    /// Returns the rule payload.
    #[must_use]
    pub const fn data(&self) -> &TeRuleData {
        &self.data
    }

    /// Returns the conditional branch, if this rule is conditional.
    #[must_use]
    pub const fn condition(&self) -> Option<RuleCondition> {
        self.condition
    }
}

/// An immutable policy owned entirely by Rust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    source: PathBuf,
    metadata: PolicyMetadata,
    type_symbols: Vec<TypeSymbol>,
    type_names: BTreeMap<String, TypeOrAttributeId>,
    roles: Vec<Role>,
    role_names: BTreeMap<String, RoleId>,
    object_classes: Vec<ObjectClass>,
    class_names: BTreeMap<String, ClassId>,
    booleans: Vec<Boolean>,
    boolean_names: BTreeMap<String, BooleanId>,
    conditionals: Vec<Conditional>,
    te_rules: Vec<TeRule>,
    rbac_rules: Vec<RbacRule>,
    sensitivities: Vec<Sensitivity>,
    sensitivity_names: BTreeMap<String, SensitivityId>,
    categories: Vec<Category>,
    category_names: BTreeMap<String, CategoryId>,
    mls_rules: Vec<MlsRule>,
    seinfo: SeinfoData,
}

impl Policy {
    /// Creates a metadata-only policy, primarily for model unit tests.
    #[must_use]
    pub fn new(source: PathBuf, metadata: PolicyMetadata) -> Self {
        Self::from_parts(source, metadata, Vec::new(), Vec::new(), Vec::new())
    }

    /// Creates a fully owned policy snapshot.
    #[must_use]
    pub fn from_parts(
        source: PathBuf,
        metadata: PolicyMetadata,
        type_symbols: Vec<TypeSymbol>,
        object_classes: Vec<ObjectClass>,
        te_rules: Vec<TeRule>,
    ) -> Self {
        Self::from_complete_parts(
            source,
            metadata,
            type_symbols,
            object_classes,
            Vec::new(),
            Vec::new(),
            te_rules,
        )
    }

    /// Creates a complete owned policy snapshot including conditionals.
    #[must_use]
    pub fn from_complete_parts(
        source: PathBuf,
        metadata: PolicyMetadata,
        type_symbols: Vec<TypeSymbol>,
        object_classes: Vec<ObjectClass>,
        booleans: Vec<Boolean>,
        conditionals: Vec<Conditional>,
        te_rules: Vec<TeRule>,
    ) -> Self {
        Self::from_sesearch_parts(
            source,
            metadata,
            type_symbols,
            object_classes,
            Vec::new(),
            booleans,
            conditionals,
            te_rules,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// Creates the complete owned snapshot required by `sesearch`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_sesearch_parts(
        source: PathBuf,
        metadata: PolicyMetadata,
        type_symbols: Vec<TypeSymbol>,
        object_classes: Vec<ObjectClass>,
        roles: Vec<Role>,
        booleans: Vec<Boolean>,
        conditionals: Vec<Conditional>,
        te_rules: Vec<TeRule>,
        rbac_rules: Vec<RbacRule>,
        sensitivities: Vec<Sensitivity>,
        categories: Vec<Category>,
        mls_rules: Vec<MlsRule>,
    ) -> Self {
        Self::from_all_parts(
            source,
            metadata,
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
            SeinfoData::default(),
        )
    }

    /// Creates the complete owned snapshot used by all implemented tools.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_all_parts(
        source: PathBuf,
        metadata: PolicyMetadata,
        type_symbols: Vec<TypeSymbol>,
        object_classes: Vec<ObjectClass>,
        roles: Vec<Role>,
        booleans: Vec<Boolean>,
        conditionals: Vec<Conditional>,
        te_rules: Vec<TeRule>,
        rbac_rules: Vec<RbacRule>,
        sensitivities: Vec<Sensitivity>,
        categories: Vec<Category>,
        mls_rules: Vec<MlsRule>,
        seinfo: SeinfoData,
    ) -> Self {
        let type_names = type_symbols
            .iter()
            .flat_map(|symbol| {
                std::iter::once(symbol.name())
                    .chain(symbol.aliases().iter().map(String::as_str))
                    .map(|name| (name.to_owned(), symbol.id()))
            })
            .collect();
        let class_names = object_classes
            .iter()
            .map(|target_class| (target_class.name().to_owned(), target_class.id()))
            .collect();
        let boolean_names = booleans
            .iter()
            .map(|boolean| (boolean.name().to_owned(), boolean.id()))
            .collect();
        let role_names = roles
            .iter()
            .map(|role| (role.name().to_owned(), role.id()))
            .collect();
        let sensitivity_names = sensitivities
            .iter()
            .flat_map(|sensitivity| {
                std::iter::once(sensitivity.name())
                    .chain(sensitivity.aliases().iter().map(String::as_str))
                    .map(|name| (name.to_owned(), sensitivity.id()))
            })
            .collect();
        let category_names = categories
            .iter()
            .flat_map(|category| {
                std::iter::once(category.name())
                    .chain(category.aliases().iter().map(String::as_str))
                    .map(|name| (name.to_owned(), category.id()))
            })
            .collect();
        Self {
            source,
            metadata,
            type_symbols,
            type_names,
            roles,
            role_names,
            object_classes,
            class_names,
            booleans,
            boolean_names,
            conditionals,
            te_rules,
            rbac_rules,
            sensitivities,
            sensitivity_names,
            categories,
            category_names,
            mls_rules,
            seinfo,
        }
    }

    /// Returns the source path used to load this policy.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Returns policy metadata.
    #[must_use]
    pub const fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }

    /// Returns all type and attribute records in symbol-value order.
    #[must_use]
    pub fn type_symbols(&self) -> &[TypeSymbol] {
        &self.type_symbols
    }

    /// Looks up a type or attribute by canonical name.
    #[must_use]
    pub fn type_symbol_by_name(&self, name: &str) -> Option<&TypeSymbol> {
        self.type_names
            .get(name)
            .and_then(|id| self.type_symbol(*id))
    }

    /// Looks up a type or attribute by policy-local ID.
    #[must_use]
    pub fn type_symbol(&self, id: TypeOrAttributeId) -> Option<&TypeSymbol> {
        self.type_symbols.get(id.as_raw() as usize)
    }

    /// Returns all roles in symbol-value order.
    #[must_use]
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    /// Looks up a role by name.
    #[must_use]
    pub fn role_by_name(&self, name: &str) -> Option<&Role> {
        self.role_names.get(name).and_then(|id| self.role(*id))
    }

    /// Looks up a role by ID.
    #[must_use]
    pub fn role(&self, id: RoleId) -> Option<&Role> {
        self.roles.get(id.as_raw() as usize)
    }

    /// Returns all object classes in symbol-value order.
    #[must_use]
    pub fn object_classes(&self) -> &[ObjectClass] {
        &self.object_classes
    }

    /// Looks up an object class by name.
    #[must_use]
    pub fn object_class_by_name(&self, name: &str) -> Option<&ObjectClass> {
        self.class_names
            .get(name)
            .and_then(|id| self.object_class(*id))
    }

    /// Looks up an object class by policy-local ID.
    #[must_use]
    pub fn object_class(&self, id: ClassId) -> Option<&ObjectClass> {
        self.object_classes.get(id.as_raw() as usize)
    }

    /// Returns all policy Booleans in symbol-value order.
    #[must_use]
    pub fn booleans(&self) -> &[Boolean] {
        &self.booleans
    }

    /// Looks up a Boolean by name.
    #[must_use]
    pub fn boolean_by_name(&self, name: &str) -> Option<&Boolean> {
        self.boolean_names
            .get(name)
            .and_then(|id| self.boolean(*id))
    }

    /// Looks up a Boolean by policy-local ID.
    #[must_use]
    pub fn boolean(&self, id: BooleanId) -> Option<&Boolean> {
        self.booleans.get(id.as_raw() as usize)
    }

    /// Returns all conditional expressions in policy order.
    #[must_use]
    pub fn conditionals(&self) -> &[Conditional] {
        &self.conditionals
    }

    /// Looks up a conditional expression by ID.
    #[must_use]
    pub fn conditional(&self, id: ConditionalId) -> Option<&Conditional> {
        self.conditionals.get(id.as_raw() as usize)
    }

    /// Returns all currently loaded type-enforcement rules.
    #[must_use]
    pub fn te_rules(&self) -> &[TeRule] {
        &self.te_rules
    }

    /// Returns all RBAC rules.
    #[must_use]
    pub fn rbac_rules(&self) -> &[RbacRule] {
        &self.rbac_rules
    }

    /// Returns all canonical sensitivities.
    #[must_use]
    pub fn sensitivities(&self) -> &[Sensitivity] {
        &self.sensitivities
    }

    /// Looks up a sensitivity by name.
    #[must_use]
    pub fn sensitivity_by_name(&self, name: &str) -> Option<&Sensitivity> {
        self.sensitivity_names
            .get(name)
            .and_then(|id| self.sensitivity(*id))
    }

    /// Looks up a sensitivity by ID.
    #[must_use]
    pub fn sensitivity(&self, id: SensitivityId) -> Option<&Sensitivity> {
        self.sensitivities.get(id.as_raw() as usize)
    }

    /// Returns all canonical MLS categories.
    #[must_use]
    pub fn categories(&self) -> &[Category] {
        &self.categories
    }

    /// Looks up a category by name.
    #[must_use]
    pub fn category_by_name(&self, name: &str) -> Option<&Category> {
        self.category_names
            .get(name)
            .and_then(|id| self.category(*id))
    }

    /// Looks up a category by ID.
    #[must_use]
    pub fn category(&self, id: CategoryId) -> Option<&Category> {
        self.categories.get(id.as_raw() as usize)
    }

    /// Returns all MLS range transition rules.
    #[must_use]
    pub fn mls_rules(&self) -> &[MlsRule] {
        &self.mls_rules
    }

    /// Returns the remaining owned components used by `seinfo`.
    #[must_use]
    pub const fn seinfo(&self) -> &SeinfoData {
        &self.seinfo
    }
}

/// Backend capable of producing an owned [`Policy`].
pub trait PolicyLoader {
    /// Loader-specific error type.
    type Error: Error + Send + Sync + 'static;

    /// Loads a policy from an explicit path.
    fn load(&self, path: &Path) -> Result<Policy, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::{
        HandleUnknown, Policy, PolicyMetadata, TargetPlatform, TypeId, TypeOrAttributeId,
        TypeSymbol,
    };
    use std::path::PathBuf;

    fn metadata() -> PolicyMetadata {
        PolicyMetadata {
            version: 35,
            mls: true,
            target: TargetPlatform::Selinux,
            handle_unknown: HandleUnknown::Reject,
        }
    }

    #[test]
    fn typed_id_round_trip() {
        assert_eq!(TypeId::from_raw(7).as_raw(), 7);
    }

    #[test]
    fn policy_owns_source_and_metadata() {
        let policy = Policy::new(PathBuf::from("policy.35"), metadata());

        assert_eq!(policy.source(), PathBuf::from("policy.35"));
        assert_eq!(policy.metadata(), &metadata());
    }

    #[test]
    fn type_lookup_uses_owned_name_index() {
        let symbol = TypeSymbol::new_type(TypeId::from_raw(0), "example_t".to_owned());
        let policy = Policy::from_parts(
            PathBuf::from("policy.35"),
            metadata(),
            vec![symbol],
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(
            policy.type_symbol_by_name("example_t").map(TypeSymbol::id),
            Some(TypeOrAttributeId::Type(TypeId::from_raw(0)))
        );
    }
}
