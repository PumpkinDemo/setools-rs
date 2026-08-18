//! Owned policy components used by `seinfo`.

#![allow(missing_docs)]

use crate::{ClassId, MlsLevel, MlsRange, PermissionId, RoleId, TypeId, UserId};
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonPermissionSet {
    name: String,
    permissions: Vec<String>,
}

impl CommonPermissionSet {
    pub fn new(name: String, mut permissions: Vec<String>) -> Self {
        permissions.sort_unstable();
        permissions.dedup();
        Self { name, permissions }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    id: UserId,
    name: String,
    roles: Vec<RoleId>,
    default_level: Option<MlsLevel>,
    range: Option<MlsRange>,
}

impl User {
    pub fn new(
        id: UserId,
        name: String,
        mut roles: Vec<RoleId>,
        default_level: Option<MlsLevel>,
        range: Option<MlsRange>,
    ) -> Self {
        roles.sort_unstable();
        roles.dedup();
        Self {
            id,
            name,
            roles,
            default_level,
            range,
        }
    }

    pub const fn id(&self) -> UserId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    pub const fn default_level(&self) -> Option<&MlsLevel> {
        self.default_level.as_ref()
    }

    pub const fn range(&self) -> Option<&MlsRange> {
        self.range.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConstraintKind {
    Constrain,
    MlsConstrain,
    ValidateTransition,
    MlsValidateTransition,
}

impl ConstraintKind {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Constrain => "constrain",
            Self::MlsConstrain => "mlsconstrain",
            Self::ValidateTransition => "validatetrans",
            Self::MlsValidateTransition => "mlsvalidatetrans",
        }
    }

    pub const fn is_validate_transition(self) -> bool {
        matches!(self, Self::ValidateTransition | Self::MlsValidateTransition)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstraintOperator {
    Not,
    And,
    Or,
    Equal,
    NotEqual,
    Dominates,
    DominatedBy,
    Incomparable,
}

impl ConstraintOperator {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Not => "not",
            Self::And => "and",
            Self::Or => "or",
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::Dominates => "dom",
            Self::DominatedBy => "domby",
            Self::Incomparable => "incomp",
        }
    }

    pub const fn precedence(self) -> u8 {
        match self {
            Self::Not => 4,
            Self::Equal
            | Self::NotEqual
            | Self::Dominates
            | Self::DominatedBy
            | Self::Incomparable => 3,
            Self::And => 2,
            Self::Or => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstraintExpressionToken {
    Operand(String),
    Names(Vec<String>),
    Operator(ConstraintOperator),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstraintRule {
    kind: ConstraintKind,
    target_class: ClassId,
    permissions: Vec<PermissionId>,
    expression: Vec<ConstraintExpressionToken>,
}

impl ConstraintRule {
    pub fn new(
        kind: ConstraintKind,
        target_class: ClassId,
        mut permissions: Vec<PermissionId>,
        expression: Vec<ConstraintExpressionToken>,
    ) -> Self {
        permissions.sort_unstable();
        permissions.dedup();
        Self {
            kind,
            target_class,
            permissions,
            expression,
        }
    }

    pub const fn kind(&self) -> ConstraintKind {
        self.kind
    }

    pub const fn target_class(&self) -> ClassId {
        self.target_class
    }

    pub fn permissions(&self) -> &[PermissionId] {
        &self.permissions
    }

    pub fn expression(&self) -> &[ConstraintExpressionToken] {
        &self.expression
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DefaultRuleKind {
    User,
    Role,
    Type,
    Range,
}

impl DefaultRuleKind {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::User => "default_user",
            Self::Role => "default_role",
            Self::Type => "default_type",
            Self::Range => "default_range",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultValue {
    Source,
    Target,
    GlbLub,
}

impl DefaultValue {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Target => "target",
            Self::GlbLub => "glblub",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultRangePart {
    Low,
    High,
    LowHigh,
}

impl DefaultRangePart {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
            Self::LowHigh => "low_high",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultRule {
    kind: DefaultRuleKind,
    target_class: ClassId,
    value: DefaultValue,
    range_part: Option<DefaultRangePart>,
}

impl DefaultRule {
    pub const fn new(
        kind: DefaultRuleKind,
        target_class: ClassId,
        value: DefaultValue,
        range_part: Option<DefaultRangePart>,
    ) -> Self {
        Self {
            kind,
            target_class,
            value,
            range_part,
        }
    }

    pub const fn kind(&self) -> DefaultRuleKind {
        self.kind
    }

    pub const fn target_class(&self) -> ClassId {
        self.target_class
    }

    pub const fn value(&self) -> DefaultValue {
        self.value
    }

    pub const fn range_part(&self) -> Option<DefaultRangePart> {
        self.range_part
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityContext {
    user: UserId,
    role: RoleId,
    type_id: TypeId,
    range: Option<MlsRange>,
}

impl SecurityContext {
    pub const fn new(user: UserId, role: RoleId, type_id: TypeId, range: Option<MlsRange>) -> Self {
        Self {
            user,
            role,
            type_id,
            range,
        }
    }

    pub const fn user(&self) -> UserId {
        self.user
    }

    pub const fn role(&self) -> RoleId {
        self.role
    }

    pub const fn type_id(&self) -> TypeId {
        self.type_id
    }

    pub const fn range(&self) -> Option<&MlsRange> {
        self.range.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsUseKind {
    Xattr,
    Transition,
    Task,
}

impl FsUseKind {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Xattr => "fs_use_xattr",
            Self::Transition => "fs_use_trans",
            Self::Task => "fs_use_task",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortProtocol {
    Tcp,
    Udp,
    Dccp,
    Sctp,
}

impl PortProtocol {
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Dccp => "dccp",
            Self::Sctp => "sctp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabelingRule {
    InitialSid {
        name: String,
        context: SecurityContext,
    },
    FsUse {
        kind: FsUseKind,
        filesystem: String,
        context: SecurityContext,
    },
    Genfscon {
        filesystem: String,
        path: String,
        target_class: Option<ClassId>,
        context: SecurityContext,
    },
    Portcon {
        protocol: PortProtocol,
        low: u16,
        high: u16,
        context: SecurityContext,
    },
    Netifcon {
        interface: String,
        interface_context: SecurityContext,
        packet_context: SecurityContext,
    },
    Nodecon {
        address: IpAddr,
        mask: IpAddr,
        context: SecurityContext,
    },
    Ibpkeycon {
        subnet_prefix: IpAddr,
        low: u16,
        high: u16,
        context: SecurityContext,
    },
    Ibendportcon {
        device: String,
        port: u8,
        context: SecurityContext,
    },
    Devicetreecon {
        path: String,
        context: SecurityContext,
    },
    Iomemcon {
        low: u64,
        high: u64,
        context: SecurityContext,
    },
    Ioportcon {
        low: u32,
        high: u32,
        context: SecurityContext,
    },
    Pcidevicecon {
        device: u32,
        context: SecurityContext,
    },
    Pirqcon {
        irq: u16,
        context: SecurityContext,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SeinfoData {
    commons: Vec<CommonPermissionSet>,
    users: Vec<User>,
    constraints: Vec<ConstraintRule>,
    defaults: Vec<DefaultRule>,
    policy_capabilities: Vec<String>,
    labeling_rules: Vec<LabelingRule>,
}

impl SeinfoData {
    pub fn new(
        commons: Vec<CommonPermissionSet>,
        users: Vec<User>,
        constraints: Vec<ConstraintRule>,
        defaults: Vec<DefaultRule>,
        mut policy_capabilities: Vec<String>,
        labeling_rules: Vec<LabelingRule>,
    ) -> Self {
        policy_capabilities.sort_unstable();
        policy_capabilities.dedup();
        Self {
            commons,
            users,
            constraints,
            defaults,
            policy_capabilities,
            labeling_rules,
        }
    }

    pub fn commons(&self) -> &[CommonPermissionSet] {
        &self.commons
    }

    pub fn users(&self) -> &[User] {
        &self.users
    }

    pub fn constraints(&self) -> &[ConstraintRule] {
        &self.constraints
    }

    pub fn defaults(&self) -> &[DefaultRule] {
        &self.defaults
    }

    pub fn policy_capabilities(&self) -> &[String] {
        &self.policy_capabilities
    }

    pub fn labeling_rules(&self) -> &[LabelingRule] {
        &self.labeling_rules
    }
}
