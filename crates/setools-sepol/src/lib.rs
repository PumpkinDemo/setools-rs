//! Safe ownership boundary for the project-owned libsepol C bridge.
//!
//! This crate is the only workspace crate permitted to contain FFI and
//! `unsafe` code. A native policy is thread-confined, copied into the owned
//! Rust model, and released before [`LibsepolLoader::load`] returns.

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
use std::error::Error;
use std::ffi::{CStr, CString, c_char, c_int};
use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;

const BRIDGE_ABI_VERSION: u32 = 4;
const INVALID_METADATA: i32 = 5;

/// libsepol-backed binary policy loader.
#[derive(Clone, Copy, Debug, Default)]
pub struct LibsepolLoader;

/// Restores the default `SIGPIPE` behavior used by the legacy CLI programs.
///
/// Returns whether the process signal disposition was changed successfully.
#[must_use]
pub fn use_default_sigpipe() -> bool {
    // SAFETY: this process-global bridge function has no pointer or ownership
    // requirements and is called during single-threaded CLI startup.
    unsafe { ffi::st_process_use_default_sigpipe() == 0 }
}

/// Paths and version limits used by libselinux/libsepol to find a running policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningPolicyInfo {
    /// Whether libselinux found a mounted SELinux filesystem.
    pub selinuxfs_exists: bool,
    /// Oldest binary policy version accepted by libsepol.
    pub minimum_version: u32,
    /// Newest binary policy version accepted by libsepol.
    pub maximum_version: u32,
    /// Path exported by SELinuxfs for the current policy, when available.
    pub current_policy_path: Option<PathBuf>,
    /// Base path for installed versioned binary policies, when available.
    pub binary_policy_path: Option<PathBuf>,
}

impl RunningPolicyInfo {
    /// Returns candidates in the order used by SETools 4.7.1.
    pub fn candidates(&self) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if let Some(path) = &self.current_policy_path {
            candidates.push(path.clone());
        }
        if let Some(base) = &self.binary_policy_path {
            for version in (self.minimum_version..=self.maximum_version).rev() {
                let mut path = base.as_os_str().to_os_string();
                path.push(format!(".{version}"));
                candidates.push(PathBuf::from(path));
            }
        }
        candidates
    }
}

/// Reads the running-policy discovery values supplied by libselinux/libsepol.
#[must_use]
pub fn running_policy_info() -> Option<RunningPolicyInfo> {
    let mut raw = ffi::StRunningPolicyInfo::default();
    // SAFETY: `raw` is a valid writable value and the returned string views
    // point at libselinux-owned static storage which is copied immediately.
    if unsafe { ffi::st_running_policy_info_get(&mut raw) } != 0 {
        return None;
    }
    Some(RunningPolicyInfo {
        selinuxfs_exists: raw.selinuxfs_exists != 0,
        minimum_version: raw.minimum_version,
        maximum_version: raw.maximum_version,
        current_policy_path: copy_os_path(raw.current_policy_path),
        binary_policy_path: copy_os_path(raw.binary_policy_path),
    })
}

/// Produces the local timestamp format used by Python's default logging formatter.
#[must_use]
pub fn local_log_timestamp() -> Option<String> {
    let mut buffer = [0_u8; 24];
    // SAFETY: the bridge receives a writable buffer with its exact capacity.
    if unsafe { ffi::st_local_log_timestamp(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    let length = buffer.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&buffer[..length])
        .ok()
        .map(str::to_owned)
}

/// Failure while loading or copying a native policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadError {
    path: PathBuf,
    code: i32,
    message: String,
}

impl LoadError {
    fn new(path: &Path, code: i32, message: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            code,
            message: message.into(),
        }
    }

    /// Returns the policy path associated with this error.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the bridge status code, or zero for a pre-FFI path error.
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.code
    }

    /// Returns the native or validation diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.message)
    }
}

impl Error for LoadError {}

impl PolicyLoader for LibsepolLoader {
    type Error = LoadError;

    fn load(&self, path: &Path) -> Result<Policy, Self::Error> {
        verify_bridge_abi(path)?;
        let native = NativePolicy::load(path)?;
        let metadata = native.metadata(path)?;
        let type_symbols = native.type_symbols(path)?;
        let object_classes = native.object_classes(path)?;
        let roles = native.roles(path)?;
        let booleans = native.booleans(path)?;
        let conditionals = native.conditionals(path, &booleans)?;
        let mut te_rules = native.te_rules(path, &type_symbols, &object_classes, &conditionals)?;
        te_rules.extend(native.filename_rules(path, &type_symbols, &object_classes)?);
        let rbac_rules = native.rbac_rules(path, &type_symbols, &object_classes, &roles)?;
        let sensitivities = native.sensitivities(path)?;
        let categories = native.categories(path)?;
        let mls_rules = native.mls_rules(
            path,
            &type_symbols,
            &object_classes,
            &sensitivities,
            &categories,
        )?;
        let seinfo = native.seinfo_data(
            path,
            &metadata,
            &type_symbols,
            &object_classes,
            &roles,
            &sensitivities,
            &categories,
        )?;

        // `native` is dropped here, before the owned policy can escape.
        Ok(Policy::from_all_parts(
            path.to_path_buf(),
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
            seinfo,
        ))
    }
}

struct NativePolicy {
    raw: NonNull<ffi::StPolicy>,
    _thread_confined: PhantomData<Rc<()>>,
}

impl NativePolicy {
    fn load(path: &Path) -> Result<Self, LoadError> {
        let c_path = path_to_c_string(path)?;
        let mut error = ffi::StError::default();

        // SAFETY: `c_path` is NUL-terminated and `error` is a valid writable
        // value. The returned pointer is either null or uniquely owned.
        let raw = unsafe { ffi::st_policy_load(c_path.as_ptr(), &mut error) };
        NonNull::new(raw)
            .map(|raw| Self {
                raw,
                _thread_confined: PhantomData,
            })
            .ok_or_else(|| take_native_error(path, &mut error, "libsepol policy load failed"))
    }

    fn metadata(&self, path: &Path) -> Result<PolicyMetadata, LoadError> {
        let mut metadata = ffi::StPolicyMetadata::default();
        let mut error = ffi::StError::default();

        // SAFETY: the RAII owner keeps the policy alive, and both output
        // pointers refer to initialized writable values for the duration of
        // the call.
        let status =
            unsafe { ffi::st_policy_metadata_get(self.raw.as_ptr(), &mut metadata, &mut error) };
        if status != 0 {
            return Err(take_native_error(
                path,
                &mut error,
                "could not read policy metadata",
            ));
        }

        let target = match metadata.target_platform {
            0 => TargetPlatform::Selinux,
            1 => TargetPlatform::Xen,
            value => {
                return Err(LoadError::new(
                    path,
                    INVALID_METADATA,
                    format!("unknown libsepol target platform value {value}"),
                ));
            }
        };
        let handle_unknown = match metadata.handle_unknown {
            0 => HandleUnknown::Deny,
            2 => HandleUnknown::Reject,
            4 => HandleUnknown::Allow,
            value => {
                return Err(LoadError::new(
                    path,
                    INVALID_METADATA,
                    format!("unknown libsepol handle-unknown value {value}"),
                ));
            }
        };

        Ok(PolicyMetadata {
            version: metadata.version,
            mls: metadata.mls != 0,
            target,
            handle_unknown,
        })
    }

    fn type_symbols(&self, path: &Path) -> Result<Vec<TypeSymbol>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_type_count(self.raw.as_ptr()) };
        let mut raw_types = Vec::with_capacity(count as usize);

        for index in 0..count {
            let mut view = ffi::StTypeView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and both output values are
            // writable for the duration of the call.
            let status =
                unsafe { ffi::st_policy_type_get(self.raw.as_ptr(), index, &mut view, &mut error) };
            check_status(path, status, &mut error, "could not copy type symbol")?;

            let name = if view.name.data.is_null() {
                if view.kind == 1 {
                    format!("@ttr{:010}", index + 1)
                } else {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        format!("type symbol {index} has no name"),
                    ));
                }
            } else {
                copy_string(path, view.name, "type symbol")?
            };
            raw_types.push((view.kind, name, view.permissive != 0, view.bound));
        }

        let mut symbols = Vec::with_capacity(raw_types.len());
        for (index, (kind, name, permissive, bound)) in raw_types.iter().enumerate() {
            let raw = u32::try_from(index)
                .map_err(|_| LoadError::new(path, INVALID_METADATA, "too many type symbols"))?;
            match kind {
                0 => {
                    let bound = if *bound == u32::MAX {
                        None
                    } else {
                        match raw_types.get(*bound as usize) {
                            Some((0, _, _, _)) => Some(TypeId::from_raw(*bound)),
                            _ => {
                                return Err(LoadError::new(
                                    path,
                                    INVALID_METADATA,
                                    format!("type {name} has invalid bound index {bound}"),
                                ));
                            }
                        }
                    };
                    symbols.push(
                        TypeSymbol::new_type(TypeId::from_raw(raw), name.clone())
                            .with_aliases(self.aliases(
                                path,
                                raw,
                                ffi::st_policy_type_alias_count,
                                ffi::st_policy_type_alias_get,
                                "type alias",
                            )?)
                            .with_seinfo_properties(*permissive, bound),
                    );
                }
                1 => {
                    let members = self.attribute_members(path, raw)?;
                    for member in &members {
                        match raw_types.get(member.as_raw() as usize) {
                            Some((0, _, _, _)) => {}
                            _ => {
                                return Err(LoadError::new(
                                    path,
                                    INVALID_METADATA,
                                    format!(
                                        "attribute {name} contains invalid type index {}",
                                        member.as_raw()
                                    ),
                                ));
                            }
                        }
                    }
                    symbols.push(TypeSymbol::new_attribute(
                        AttributeId::from_raw(raw),
                        name.clone(),
                        members,
                    ));
                }
                value => {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        format!("type symbol {index} has unknown kind {value}"),
                    ));
                }
            }
        }
        Ok(symbols)
    }

    fn attribute_members(&self, path: &Path, attribute: u32) -> Result<Vec<TypeId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: the policy is valid; a null member buffer requests the
        // required count and `count` is writable.
        let status = unsafe {
            ffi::st_policy_attribute_members_get(
                self.raw.as_ptr(),
                attribute,
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(
            path,
            status,
            &mut error,
            "could not count attribute members",
        )?;

        let mut members = vec![0_u32; count];
        let mut copied = count;
        let output = if members.is_empty() {
            std::ptr::null_mut()
        } else {
            members.as_mut_ptr()
        };
        let mut error = ffi::StError::default();
        // SAFETY: `output` has capacity `members.len()` when non-null, and the
        // other output values are writable.
        let status = unsafe {
            ffi::st_policy_attribute_members_get(
                self.raw.as_ptr(),
                attribute,
                output,
                members.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy attribute members")?;
        if copied != members.len() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                format!(
                    "attribute {attribute} member count changed from {} to {copied}",
                    members.len()
                ),
            ));
        }
        Ok(members.into_iter().map(TypeId::from_raw).collect())
    }

    fn aliases(
        &self,
        path: &Path,
        primary: u32,
        count_fn: unsafe extern "C" fn(*const ffi::StPolicy, u32) -> u32,
        get_fn: unsafe extern "C" fn(
            *const ffi::StPolicy,
            u32,
            u32,
            *mut ffi::StStringView,
            *mut ffi::StError,
        ) -> c_int,
        description: &str,
    ) -> Result<Vec<String>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { count_fn(self.raw.as_ptr(), primary) };
        let mut aliases = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut name = ffi::StStringView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status =
                unsafe { get_fn(self.raw.as_ptr(), primary, index, &mut name, &mut error) };
            check_status(path, status, &mut error, "could not copy symbol alias")?;
            aliases.push(copy_string(path, name, description)?);
        }
        Ok(aliases)
    }

    fn object_classes(&self, path: &Path) -> Result<Vec<ObjectClass>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_class_count(self.raw.as_ptr()) };
        let mut classes = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StClassView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and both output values are
            // writable for the duration of the call.
            let status = unsafe {
                ffi::st_policy_class_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy object class")?;
            let name = copy_string(path, view.name, "object class")?;
            let common = if view.common.data.is_null() {
                None
            } else {
                Some(copy_string(path, view.common, "class common")?)
            };

            let mut permissions = Vec::with_capacity(view.permission_count as usize);
            for permission in 0..view.permission_count {
                let mut permission_name = ffi::StStringView::default();
                let mut error = ffi::StError::default();
                // SAFETY: the policy remains alive and both output values are
                // writable for the duration of the call.
                let status = unsafe {
                    ffi::st_policy_permission_get(
                        self.raw.as_ptr(),
                        index,
                        permission,
                        &mut permission_name,
                        &mut error,
                    )
                };
                check_status(path, status, &mut error, "could not copy permission")?;
                permissions.push(Permission::new(
                    PermissionId::from_raw(permission),
                    copy_string(path, permission_name, "permission")?,
                ));
            }
            let mut local_permissions = Vec::with_capacity(view.local_permission_count as usize);
            for permission in 0..view.local_permission_count {
                let mut permission_name = ffi::StStringView::default();
                let mut error = ffi::StError::default();
                // SAFETY: the native policy remains alive and outputs are writable.
                let status = unsafe {
                    ffi::st_policy_class_local_permission_get(
                        self.raw.as_ptr(),
                        index,
                        permission,
                        &mut permission_name,
                        &mut error,
                    )
                };
                check_status(
                    path,
                    status,
                    &mut error,
                    "could not copy local class permission",
                )?;
                local_permissions.push(copy_string(
                    path,
                    permission_name,
                    "local class permission",
                )?);
            }
            classes.push(
                ObjectClass::new(ClassId::from_raw(index), name, permissions)
                    .with_declaration(common, local_permissions),
            );
        }
        Ok(classes)
    }

    fn booleans(&self, path: &Path) -> Result<Vec<Boolean>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_boolean_count(self.raw.as_ptr()) };
        let mut booleans = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StBooleanView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and both output values are
            // writable for the duration of the call.
            let status = unsafe {
                ffi::st_policy_boolean_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy Boolean")?;
            booleans.push(Boolean::new(
                BooleanId::from_raw(index),
                copy_string(path, view.name, "Boolean")?,
                view.state != 0,
            ));
        }
        Ok(booleans)
    }

    fn conditionals(
        &self,
        path: &Path,
        booleans: &[Boolean],
    ) -> Result<Vec<Conditional>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_conditional_count(self.raw.as_ptr()) };
        let mut conditionals = Vec::with_capacity(count as usize);
        for conditional in 0..count {
            // SAFETY: `conditional` is bounded by the count from this policy.
            let token_count =
                unsafe { ffi::st_policy_conditional_token_count(self.raw.as_ptr(), conditional) };
            if token_count == 0 {
                return Err(LoadError::new(
                    path,
                    INVALID_METADATA,
                    format!("conditional {conditional} has an empty expression"),
                ));
            }
            let mut tokens = Vec::with_capacity(token_count as usize);
            for index in 0..token_count {
                let mut view = ffi::StConditionalTokenView::default();
                let mut error = ffi::StError::default();
                // SAFETY: the policy remains alive and both output values are
                // writable for the duration of the call.
                let status = unsafe {
                    ffi::st_policy_conditional_token_get(
                        self.raw.as_ptr(),
                        conditional,
                        index,
                        &mut view,
                        &mut error,
                    )
                };
                check_status(path, status, &mut error, "could not copy conditional token")?;
                let token = match view.kind {
                    1 => {
                        if booleans.get(view.boolean as usize).is_none() {
                            return Err(LoadError::new(
                                path,
                                INVALID_METADATA,
                                format!(
                                    "conditional {conditional} token {index} has invalid Boolean index {}",
                                    view.boolean
                                ),
                            ));
                        }
                        ConditionalToken::Boolean(BooleanId::from_raw(view.boolean))
                    }
                    2 => ConditionalToken::Not,
                    3 => ConditionalToken::Or,
                    4 => ConditionalToken::And,
                    5 => ConditionalToken::Xor,
                    6 => ConditionalToken::Equal,
                    7 => ConditionalToken::NotEqual,
                    value => {
                        return Err(LoadError::new(
                            path,
                            INVALID_METADATA,
                            format!(
                                "conditional {conditional} token {index} has unknown kind {value}"
                            ),
                        ));
                    }
                };
                tokens.push(token);
            }
            conditionals.push(Conditional::new(
                ConditionalId::from_raw(conditional),
                tokens,
            ));
        }
        Ok(conditionals)
    }

    fn te_rules(
        &self,
        path: &Path,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
        conditionals: &[Conditional],
    ) -> Result<Vec<TeRule>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_te_rule_count(self.raw.as_ptr()) };
        let mut rules = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StTeRuleView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and both output values are
            // writable for the duration of the call.
            let status = unsafe {
                ffi::st_policy_te_rule_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy TE rule")?;

            let source = symbol_id(path, types, view.source, "source")?;
            let target = symbol_id(path, types, view.target, "target")?;
            let target_class = classes.get(view.target_class as usize).ok_or_else(|| {
                LoadError::new(
                    path,
                    INVALID_METADATA,
                    format!(
                        "TE rule {index} has invalid class index {}",
                        view.target_class
                    ),
                )
            })?;
            let kind = rule_kind(path, index, view.kind)?;
            let data = if matches!(
                kind,
                TeRuleKind::Allow | TeRuleKind::AuditAllow | TeRuleKind::DontAudit
            ) {
                let permissions = target_class
                    .permissions()
                    .iter()
                    .filter(|permission| {
                        view.permissions & (1_u32 << permission.id().as_raw()) != 0
                    })
                    .map(Permission::id)
                    .collect::<Vec<_>>();
                if permissions.is_empty() {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        format!("TE rule {index} has no permissions"),
                    ));
                }
                TeRuleData::Permissions(permissions)
            } else if matches!(
                kind,
                TeRuleKind::AllowXperm | TeRuleKind::AuditAllowXperm | TeRuleKind::DontAuditXperm
            ) {
                let (xperm_kind, values) = decode_xperms(path, index, &view)?;
                TeRuleData::ExtendedPermissions {
                    kind: xperm_kind,
                    values,
                }
            } else {
                let default = types
                    .get(view.default_type as usize)
                    .and_then(|symbol| match symbol.id() {
                        TypeOrAttributeId::Type(id) => Some(id),
                        TypeOrAttributeId::Attribute(_) => None,
                    })
                    .ok_or_else(|| {
                        LoadError::new(
                            path,
                            INVALID_METADATA,
                            format!(
                                "TE rule {index} has invalid default type index {}",
                                view.default_type
                            ),
                        )
                    })?;
                TeRuleData::DefaultType {
                    default,
                    filename: None,
                }
            };
            let mut rule = TeRule::new(kind, source, target, target_class.id(), data);
            if view.conditional != u32::MAX {
                if conditionals.get(view.conditional as usize).is_none()
                    || view.conditional_block > 1
                {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        format!(
                            "TE rule {index} has invalid conditional branch {}:{}",
                            view.conditional, view.conditional_block
                        ),
                    ));
                }
                rule = rule.with_condition(RuleCondition::new(
                    ConditionalId::from_raw(view.conditional),
                    view.conditional_block != 0,
                ));
            }
            rules.push(rule);
        }
        Ok(rules)
    }

    fn roles(&self, path: &Path) -> Result<Vec<Role>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_role_count(self.raw.as_ptr()) };
        let mut roles = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StRoleView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status =
                unsafe { ffi::st_policy_role_get(self.raw.as_ptr(), index, &mut view, &mut error) };
            check_status(path, status, &mut error, "could not copy role")?;
            let mut members = self.role_members(path, index)?;
            if members.is_empty() {
                members.push(RoleId::from_raw(index));
            }
            roles.push(
                Role::new(
                    RoleId::from_raw(index),
                    copy_string(path, view.name, "role")?,
                    members,
                )
                .with_authorized_types(self.role_types(path, index)?),
            );
        }
        Ok(roles)
    }

    fn role_members(&self, path: &Path, role: u32) -> Result<Vec<RoleId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_role_members_get(
                self.raw.as_ptr(),
                role,
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not count role members")?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let output = if raw.is_empty() {
            std::ptr::null_mut()
        } else {
            raw.as_mut_ptr()
        };
        let mut error = ffi::StError::default();
        // SAFETY: output has the declared capacity and outputs are writable.
        let status = unsafe {
            ffi::st_policy_role_members_get(
                self.raw.as_ptr(),
                role,
                output,
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy role members")?;
        if copied != raw.len() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                format!("role {role} member count changed while copying"),
            ));
        }
        Ok(raw.into_iter().map(RoleId::from_raw).collect())
    }

    fn role_types(&self, path: &Path, role: u32) -> Result<Vec<TypeId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_role_types_get(
                self.raw.as_ptr(),
                role,
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not count role types")?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let output = if raw.is_empty() {
            std::ptr::null_mut()
        } else {
            raw.as_mut_ptr()
        };
        let mut error = ffi::StError::default();
        // SAFETY: output has the declared capacity and outputs are writable.
        let status = unsafe {
            ffi::st_policy_role_types_get(
                self.raw.as_ptr(),
                role,
                output,
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy role types")?;
        if copied != raw.len() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                format!("role {role} type count changed while copying"),
            ));
        }
        Ok(raw.into_iter().map(TypeId::from_raw).collect())
    }

    fn filename_rules(
        &self,
        path: &Path,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
    ) -> Result<Vec<TeRule>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_filename_rule_count(self.raw.as_ptr()) };
        let mut rules = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StFilenameRuleView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_filename_rule_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(
                path,
                status,
                &mut error,
                "could not copy filename transition",
            )?;
            let source = symbol_id(path, types, view.source, "source")?;
            let target = symbol_id(path, types, view.target, "target")?;
            let target_class = classes.get(view.target_class as usize).ok_or_else(|| {
                LoadError::new(
                    path,
                    INVALID_METADATA,
                    "filename transition has invalid class",
                )
            })?;
            let default = concrete_type_id(path, types, view.default_type, "filename default")?;
            rules.push(TeRule::new(
                TeRuleKind::TypeTransition,
                source,
                target,
                target_class.id(),
                TeRuleData::DefaultType {
                    default,
                    filename: Some(copy_string(path, view.filename, "filename")?),
                },
            ));
        }
        Ok(rules)
    }

    fn rbac_rules(
        &self,
        path: &Path,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
        roles: &[Role],
    ) -> Result<Vec<RbacRule>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_rbac_rule_count(self.raw.as_ptr()) };
        let mut rules = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StRbacRuleView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_rbac_rule_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy RBAC rule")?;
            let source = role_id(path, roles, view.source, "source")?;
            let data = match view.kind {
                1 => RbacRuleData::Allow {
                    target: role_id(path, roles, view.target, "target")?,
                },
                2 => RbacRuleData::RoleTransition {
                    target: symbol_id(path, types, view.target, "target")?,
                    target_class: classes
                        .get(view.target_class as usize)
                        .ok_or_else(|| {
                            LoadError::new(
                                path,
                                INVALID_METADATA,
                                "role transition has invalid class",
                            )
                        })?
                        .id(),
                    default: role_id(path, roles, view.default_role, "default")?,
                },
                value => {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        format!("RBAC rule {index} has unknown kind {value}"),
                    ));
                }
            };
            rules.push(RbacRule::new(source, data));
        }
        Ok(rules)
    }

    fn sensitivities(&self, path: &Path) -> Result<Vec<Sensitivity>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_sensitivity_count(self.raw.as_ptr()) };
        let mut values = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut name = ffi::StStringView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_sensitivity_get(self.raw.as_ptr(), index, &mut name, &mut error)
            };
            check_status(path, status, &mut error, "could not copy sensitivity")?;
            values.push(
                Sensitivity::new(
                    SensitivityId::from_raw(index),
                    copy_string(path, name, "sensitivity")?,
                )
                .with_aliases(self.aliases(
                    path,
                    index,
                    ffi::st_policy_sensitivity_alias_count,
                    ffi::st_policy_sensitivity_alias_get,
                    "sensitivity alias",
                )?),
            );
        }
        Ok(values)
    }

    fn categories(&self, path: &Path) -> Result<Vec<Category>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_category_count(self.raw.as_ptr()) };
        let mut values = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut name = ffi::StStringView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_category_get(self.raw.as_ptr(), index, &mut name, &mut error)
            };
            check_status(path, status, &mut error, "could not copy category")?;
            values.push(
                Category::new(
                    CategoryId::from_raw(index),
                    copy_string(path, name, "category")?,
                )
                .with_aliases(self.aliases(
                    path,
                    index,
                    ffi::st_policy_category_alias_count,
                    ffi::st_policy_category_alias_get,
                    "category alias",
                )?),
            );
        }
        Ok(values)
    }

    fn mls_rules(
        &self,
        path: &Path,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
        sensitivities: &[Sensitivity],
        categories: &[Category],
    ) -> Result<Vec<MlsRule>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_mls_rule_count(self.raw.as_ptr()) };
        let mut rules = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StMlsRuleView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_mls_rule_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy MLS rule")?;
            if sensitivities.get(view.low_sensitivity as usize).is_none()
                || sensitivities.get(view.high_sensitivity as usize).is_none()
            {
                return Err(LoadError::new(
                    path,
                    INVALID_METADATA,
                    format!("MLS rule {index} has invalid sensitivity"),
                ));
            }
            let low_categories = self.mls_categories(path, index, false, categories.len())?;
            let high_categories = self.mls_categories(path, index, true, categories.len())?;
            rules.push(MlsRule::new(
                symbol_id(path, types, view.source, "source")?,
                symbol_id(path, types, view.target, "target")?,
                classes
                    .get(view.target_class as usize)
                    .ok_or_else(|| {
                        LoadError::new(path, INVALID_METADATA, "MLS rule has invalid class")
                    })?
                    .id(),
                MlsRange::new(
                    MlsLevel::new(
                        SensitivityId::from_raw(view.low_sensitivity),
                        low_categories,
                    ),
                    MlsLevel::new(
                        SensitivityId::from_raw(view.high_sensitivity),
                        high_categories,
                    ),
                ),
            ));
        }
        Ok(rules)
    }

    fn mls_categories(
        &self,
        path: &Path,
        rule: u32,
        high: bool,
        category_count: usize,
    ) -> Result<Vec<CategoryId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_mls_rule_categories_get(
                self.raw.as_ptr(),
                rule,
                u32::from(high),
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not count MLS categories")?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let output = if raw.is_empty() {
            std::ptr::null_mut()
        } else {
            raw.as_mut_ptr()
        };
        let mut error = ffi::StError::default();
        // SAFETY: output has the declared capacity and outputs are writable.
        let status = unsafe {
            ffi::st_policy_mls_rule_categories_get(
                self.raw.as_ptr(),
                rule,
                u32::from(high),
                output,
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy MLS categories")?;
        if copied != raw.len() || raw.iter().any(|value| *value as usize >= category_count) {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                format!("MLS rule {rule} has invalid categories"),
            ));
        }
        Ok(raw.into_iter().map(CategoryId::from_raw).collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn seinfo_data(
        &self,
        path: &Path,
        metadata: &PolicyMetadata,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
        roles: &[Role],
        sensitivities: &[Sensitivity],
        categories: &[Category],
    ) -> Result<SeinfoData, LoadError> {
        let commons = self.commons(path)?;
        let users = self.users(path, metadata, roles, sensitivities, categories)?;
        let constraints = self.constraints(path, types, classes, roles, &users)?;
        let defaults = self.defaults(path, classes)?;
        let policy_capabilities = self.policy_capabilities(path)?;
        let labeling_rules = self.labeling_rules(
            path,
            metadata,
            types,
            classes,
            roles,
            &users,
            sensitivities,
            categories,
        )?;
        Ok(SeinfoData::new(
            commons,
            users,
            constraints,
            defaults,
            policy_capabilities,
            labeling_rules,
        ))
    }

    fn commons(&self, path: &Path) -> Result<Vec<CommonPermissionSet>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_common_count(self.raw.as_ptr()) };
        let mut commons = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StCommonView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_common_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(
                path,
                status,
                &mut error,
                "could not copy common permission set",
            )?;
            let mut permissions = Vec::with_capacity(view.permission_count as usize);
            for permission in 0..view.permission_count {
                let mut name = ffi::StStringView::default();
                let mut error = ffi::StError::default();
                // SAFETY: indices are bounded by the view and outputs are writable.
                let status = unsafe {
                    ffi::st_policy_common_permission_get(
                        self.raw.as_ptr(),
                        index,
                        permission,
                        &mut name,
                        &mut error,
                    )
                };
                check_status(path, status, &mut error, "could not copy common permission")?;
                permissions.push(copy_string(path, name, "common permission")?);
            }
            commons.push(CommonPermissionSet::new(
                copy_string(path, view.name, "common permission set")?,
                permissions,
            ));
        }
        Ok(commons)
    }

    fn users(
        &self,
        path: &Path,
        metadata: &PolicyMetadata,
        roles: &[Role],
        sensitivities: &[Sensitivity],
        categories: &[Category],
    ) -> Result<Vec<User>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_user_count(self.raw.as_ptr()) };
        let mut users = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StUserView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status =
                unsafe { ffi::st_policy_user_get(self.raw.as_ptr(), index, &mut view, &mut error) };
            check_status(path, status, &mut error, "could not copy SELinux user")?;
            let mut user_roles = self.user_roles(path, index)?;
            for role in &user_roles {
                if roles.get(role.as_raw() as usize).is_none() {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        format!("user {index} has invalid role index {}", role.as_raw()),
                    ));
                }
            }
            user_roles.retain(|role| roles[role.as_raw() as usize].name() != "object_r");

            let (default_level, range) = if metadata.mls {
                let default_level = self.user_level(
                    path,
                    index,
                    view.default_sensitivity,
                    0,
                    sensitivities,
                    categories,
                )?;
                let low = self.user_level(
                    path,
                    index,
                    view.low_sensitivity,
                    1,
                    sensitivities,
                    categories,
                )?;
                let high = self.user_level(
                    path,
                    index,
                    view.high_sensitivity,
                    2,
                    sensitivities,
                    categories,
                )?;
                (Some(default_level), Some(MlsRange::new(low, high)))
            } else {
                (None, None)
            };
            users.push(User::new(
                UserId::from_raw(index),
                copy_string(path, view.name, "SELinux user")?,
                user_roles,
                default_level,
                range,
            ));
        }
        Ok(users)
    }

    fn user_roles(&self, path: &Path, user: u32) -> Result<Vec<RoleId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_user_roles_get(
                self.raw.as_ptr(),
                user,
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not count user roles")?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let mut error = ffi::StError::default();
        // SAFETY: the output buffer has the declared capacity.
        let status = unsafe {
            ffi::st_policy_user_roles_get(
                self.raw.as_ptr(),
                user,
                raw.as_mut_ptr(),
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy user roles")?;
        if copied != raw.len() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                "user role count changed",
            ));
        }
        Ok(raw.into_iter().map(RoleId::from_raw).collect())
    }

    fn user_level(
        &self,
        path: &Path,
        user: u32,
        sensitivity: u32,
        level: u32,
        sensitivities: &[Sensitivity],
        categories: &[Category],
    ) -> Result<MlsLevel, LoadError> {
        if sensitivities.get(sensitivity as usize).is_none() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                format!("user {user} has invalid sensitivity index {sensitivity}"),
            ));
        }
        Ok(MlsLevel::new(
            SensitivityId::from_raw(sensitivity),
            self.user_categories(path, user, level, categories.len())?,
        ))
    }

    fn user_categories(
        &self,
        path: &Path,
        user: u32,
        level: u32,
        category_count: usize,
    ) -> Result<Vec<CategoryId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_user_categories_get(
                self.raw.as_ptr(),
                user,
                level,
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not count user categories")?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let mut error = ffi::StError::default();
        // SAFETY: the output buffer has the declared capacity.
        let status = unsafe {
            ffi::st_policy_user_categories_get(
                self.raw.as_ptr(),
                user,
                level,
                raw.as_mut_ptr(),
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy user categories")?;
        if copied != raw.len() || raw.iter().any(|value| *value as usize >= category_count) {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                "user has invalid categories",
            ));
        }
        Ok(raw.into_iter().map(CategoryId::from_raw).collect())
    }

    fn defaults(
        &self,
        path: &Path,
        classes: &[ObjectClass],
    ) -> Result<Vec<DefaultRule>, LoadError> {
        let mut rules = Vec::new();
        for (index, target_class) in classes.iter().enumerate() {
            let index = u32::try_from(index)
                .map_err(|_| LoadError::new(path, INVALID_METADATA, "too many classes"))?;
            let mut view = ffi::StClassView::default();
            let mut error = ffi::StError::default();
            // SAFETY: class index is from the owned copy of this policy.
            let status = unsafe {
                ffi::st_policy_class_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy class defaults")?;
            for (kind, raw) in [
                (DefaultRuleKind::User, view.default_user),
                (DefaultRuleKind::Role, view.default_role),
                (DefaultRuleKind::Type, view.default_type),
            ] {
                let value = match raw {
                    0 => continue,
                    1 => DefaultValue::Source,
                    2 => DefaultValue::Target,
                    value => {
                        return Err(LoadError::new(
                            path,
                            INVALID_METADATA,
                            format!("class {index} has invalid default value {value}"),
                        ));
                    }
                };
                rules.push(DefaultRule::new(kind, target_class.id(), value, None));
            }
            if view.default_range != 0 {
                let (value, part) = match view.default_range {
                    1 => (DefaultValue::Source, Some(DefaultRangePart::Low)),
                    2 => (DefaultValue::Source, Some(DefaultRangePart::High)),
                    3 => (DefaultValue::Source, Some(DefaultRangePart::LowHigh)),
                    4 => (DefaultValue::Target, Some(DefaultRangePart::Low)),
                    5 => (DefaultValue::Target, Some(DefaultRangePart::High)),
                    6 => (DefaultValue::Target, Some(DefaultRangePart::LowHigh)),
                    7 => (DefaultValue::GlbLub, None),
                    raw => {
                        return Err(LoadError::new(
                            path,
                            INVALID_METADATA,
                            format!("class {index} has invalid default range {raw}"),
                        ));
                    }
                };
                rules.push(DefaultRule::new(
                    DefaultRuleKind::Range,
                    target_class.id(),
                    value,
                    part,
                ));
            }
        }
        Ok(rules)
    }

    fn constraints(
        &self,
        path: &Path,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
        roles: &[Role],
        users: &[User],
    ) -> Result<Vec<ConstraintRule>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_constraint_count(self.raw.as_ptr()) };
        let mut rules = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut view = ffi::StConstraintView::default();
            let mut error = ffi::StError::default();
            // SAFETY: the policy remains alive and outputs are writable.
            let status = unsafe {
                ffi::st_policy_constraint_get(self.raw.as_ptr(), index, &mut view, &mut error)
            };
            check_status(path, status, &mut error, "could not copy constraint")?;
            let target_class = classes.get(view.target_class as usize).ok_or_else(|| {
                LoadError::new(path, INVALID_METADATA, "constraint has invalid class")
            })?;
            let permissions = target_class
                .permissions()
                .iter()
                .filter(|permission| view.permissions & (1_u32 << permission.id().as_raw()) != 0)
                .map(Permission::id)
                .collect();
            let mut expression = Vec::new();
            for expression_index in 0..view.expression_count {
                let mut native = ffi::StConstraintExpressionView::default();
                let mut error = ffi::StError::default();
                // SAFETY: expression index is bounded by the native view.
                let status = unsafe {
                    ffi::st_policy_constraint_expression_get(
                        self.raw.as_ptr(),
                        index,
                        expression_index,
                        &mut native,
                        &mut error,
                    )
                };
                check_status(
                    path,
                    status,
                    &mut error,
                    "could not copy constraint expression",
                )?;
                match native.expression_type {
                    1 => expression
                        .push(ConstraintExpressionToken::Operator(ConstraintOperator::Not)),
                    2 => expression
                        .push(ConstraintExpressionToken::Operator(ConstraintOperator::And)),
                    3 => {
                        expression.push(ConstraintExpressionToken::Operator(ConstraintOperator::Or))
                    }
                    4 | 5 => {
                        let (left, right) = constraint_operands(path, native.attribute)?;
                        expression.push(ConstraintExpressionToken::Operand(left.to_owned()));
                        if native.expression_type == 4 {
                            let right = right.ok_or_else(|| {
                                LoadError::new(
                                    path,
                                    INVALID_METADATA,
                                    "attribute constraint has no right operand",
                                )
                            })?;
                            expression.push(ConstraintExpressionToken::Operand(right.to_owned()));
                        } else {
                            expression.push(ConstraintExpressionToken::Names(
                                self.constraint_names(
                                    path,
                                    index,
                                    expression_index,
                                    native.names_kind,
                                    types,
                                    roles,
                                    users,
                                )?,
                            ));
                        }
                        expression.push(ConstraintExpressionToken::Operator(constraint_operator(
                            path,
                            native.operator,
                        )?));
                    }
                    value => {
                        return Err(LoadError::new(
                            path,
                            INVALID_METADATA,
                            format!("constraint expression has unknown type {value}"),
                        ));
                    }
                }
            }
            let kind = match (view.validate_transition != 0, view.mls != 0) {
                (false, false) => ConstraintKind::Constrain,
                (false, true) => ConstraintKind::MlsConstrain,
                (true, false) => ConstraintKind::ValidateTransition,
                (true, true) => ConstraintKind::MlsValidateTransition,
            };
            rules.push(ConstraintRule::new(
                kind,
                target_class.id(),
                permissions,
                expression,
            ));
        }
        Ok(rules)
    }

    #[allow(clippy::too_many_arguments)]
    fn constraint_names(
        &self,
        path: &Path,
        constraint: u32,
        expression: u32,
        kind: u32,
        types: &[TypeSymbol],
        roles: &[Role],
        users: &[User],
    ) -> Result<Vec<String>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_constraint_expression_names_get(
                self.raw.as_ptr(),
                constraint,
                expression,
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not count constraint names")?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let mut error = ffi::StError::default();
        // SAFETY: the output buffer has the declared capacity.
        let status = unsafe {
            ffi::st_policy_constraint_expression_names_get(
                self.raw.as_ptr(),
                constraint,
                expression,
                raw.as_mut_ptr(),
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(path, status, &mut error, "could not copy constraint names")?;
        if copied != raw.len() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                "constraint name count changed",
            ));
        }
        raw.into_iter()
            .map(|value| match kind {
                1 => users.get(value as usize).map(User::name),
                2 => roles.get(value as usize).map(Role::name),
                3 => types.get(value as usize).map(TypeSymbol::name),
                _ => None,
            })
            .map(|name| {
                name.map(str::to_owned).ok_or_else(|| {
                    LoadError::new(path, INVALID_METADATA, "constraint has invalid name index")
                })
            })
            .collect()
    }

    fn policy_capabilities(&self, path: &Path) -> Result<Vec<String>, LoadError> {
        // SAFETY: the native policy handle is valid for this method call.
        let count = unsafe { ffi::st_policy_capability_count(self.raw.as_ptr()) };
        let mut capabilities = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut name = ffi::StStringView::default();
            let mut error = ffi::StError::default();
            // SAFETY: index is bounded by the native count and outputs are writable.
            let status = unsafe {
                ffi::st_policy_capability_get(self.raw.as_ptr(), index, &mut name, &mut error)
            };
            check_status(path, status, &mut error, "could not copy policy capability")?;
            capabilities.push(copy_string(path, name, "policy capability")?);
        }
        Ok(capabilities)
    }

    #[allow(clippy::too_many_arguments)]
    fn labeling_rules(
        &self,
        path: &Path,
        metadata: &PolicyMetadata,
        types: &[TypeSymbol],
        classes: &[ObjectClass],
        roles: &[Role],
        users: &[User],
        sensitivities: &[Sensitivity],
        categories: &[Category],
    ) -> Result<Vec<LabelingRule>, LoadError> {
        let mut rules = Vec::new();
        for kind in 0..=12_u32 {
            // SAFETY: the native policy handle is valid for this method call.
            let count = unsafe { ffi::st_policy_labeling_count(self.raw.as_ptr(), kind) };
            for index in 0..count {
                let mut view = ffi::StLabelingView::default();
                let mut error = ffi::StError::default();
                // SAFETY: index is bounded by the native count and outputs are writable.
                let status = unsafe {
                    ffi::st_policy_labeling_get(
                        self.raw.as_ptr(),
                        kind,
                        index,
                        &mut view,
                        &mut error,
                    )
                };
                check_status(path, status, &mut error, "could not copy labeling rule")?;
                let context = self.security_context(
                    path,
                    metadata,
                    kind,
                    index,
                    0,
                    &view.contexts[0],
                    types,
                    roles,
                    users,
                    sensitivities,
                    categories,
                )?;
                let name = |description| copy_string(path, view.name, description);
                let rule = match kind {
                    0 => LabelingRule::InitialSid {
                        name: name("initial SID")?,
                        context,
                    },
                    1 => LabelingRule::FsUse {
                        kind: match view.subtype {
                            1 => FsUseKind::Xattr,
                            2 => FsUseKind::Transition,
                            3 => FsUseKind::Task,
                            value => {
                                return Err(LoadError::new(
                                    path,
                                    INVALID_METADATA,
                                    format!("fs_use rule has unknown behavior {value}"),
                                ));
                            }
                        },
                        filesystem: name("filesystem")?,
                        context,
                    },
                    2 => LabelingRule::Genfscon {
                        filesystem: name("filesystem")?,
                        path: copy_string(path, view.secondary, "genfs path")?,
                        target_class: if view.subtype == u32::MAX {
                            None
                        } else {
                            Some(
                                classes
                                    .get(view.subtype as usize)
                                    .ok_or_else(|| {
                                        LoadError::new(
                                            path,
                                            INVALID_METADATA,
                                            "genfscon has invalid class",
                                        )
                                    })?
                                    .id(),
                            )
                        },
                        context,
                    },
                    3 => LabelingRule::Portcon {
                        protocol: match view.subtype {
                            6 => PortProtocol::Tcp,
                            17 => PortProtocol::Udp,
                            33 => PortProtocol::Dccp,
                            132 => PortProtocol::Sctp,
                            value => {
                                return Err(LoadError::new(
                                    path,
                                    INVALID_METADATA,
                                    format!("portcon has unknown protocol {value}"),
                                ));
                            }
                        },
                        low: u16::try_from(view.low).map_err(|_| {
                            LoadError::new(path, INVALID_METADATA, "portcon low port is too large")
                        })?,
                        high: u16::try_from(view.high).map_err(|_| {
                            LoadError::new(path, INVALID_METADATA, "portcon high port is too large")
                        })?,
                        context,
                    },
                    4 => LabelingRule::Netifcon {
                        interface: name("network interface")?,
                        interface_context: context,
                        packet_context: self.security_context(
                            path,
                            metadata,
                            kind,
                            index,
                            1,
                            &view.contexts[1],
                            types,
                            roles,
                            users,
                            sensitivities,
                            categories,
                        )?,
                    },
                    5 => LabelingRule::Nodecon {
                        address: labeling_address(path, view.subtype, view.address)?,
                        mask: labeling_address(path, view.subtype, view.mask)?,
                        context,
                    },
                    6 => LabelingRule::Ibpkeycon {
                        subnet_prefix: IpAddr::V6(Ipv6Addr::from(view.address)),
                        low: u16::try_from(view.low).map_err(|_| {
                            LoadError::new(path, INVALID_METADATA, "ibpkeycon low key is too large")
                        })?,
                        high: u16::try_from(view.high).map_err(|_| {
                            LoadError::new(
                                path,
                                INVALID_METADATA,
                                "ibpkeycon high key is too large",
                            )
                        })?,
                        context,
                    },
                    7 => LabelingRule::Ibendportcon {
                        device: name("InfiniBand device")?,
                        port: u8::try_from(view.low).map_err(|_| {
                            LoadError::new(path, INVALID_METADATA, "ibendportcon port is too large")
                        })?,
                        context,
                    },
                    8 => LabelingRule::Devicetreecon {
                        path: name("device tree path")?,
                        context,
                    },
                    9 => LabelingRule::Iomemcon {
                        low: view.low,
                        high: view.high,
                        context,
                    },
                    10 => LabelingRule::Ioportcon {
                        low: u32::try_from(view.low).map_err(|_| {
                            LoadError::new(
                                path,
                                INVALID_METADATA,
                                "ioportcon low port is too large",
                            )
                        })?,
                        high: u32::try_from(view.high).map_err(|_| {
                            LoadError::new(
                                path,
                                INVALID_METADATA,
                                "ioportcon high port is too large",
                            )
                        })?,
                        context,
                    },
                    11 => LabelingRule::Pcidevicecon {
                        device: u32::try_from(view.low).map_err(|_| {
                            LoadError::new(path, INVALID_METADATA, "PCI device value is too large")
                        })?,
                        context,
                    },
                    12 => LabelingRule::Pirqcon {
                        irq: u16::try_from(view.low).map_err(|_| {
                            LoadError::new(path, INVALID_METADATA, "PIRQ value is too large")
                        })?,
                        context,
                    },
                    _ => unreachable!("bounded labeling kind"),
                };
                rules.push(rule);
            }
        }
        Ok(rules)
    }

    #[allow(clippy::too_many_arguments)]
    fn security_context(
        &self,
        path: &Path,
        metadata: &PolicyMetadata,
        kind: u32,
        index: u32,
        context_index: u32,
        view: &ffi::StContextView,
        types: &[TypeSymbol],
        roles: &[Role],
        users: &[User],
        sensitivities: &[Sensitivity],
        categories: &[Category],
    ) -> Result<SecurityContext, LoadError> {
        if users.get(view.user as usize).is_none() || roles.get(view.role as usize).is_none() {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                "security context has invalid user or role",
            ));
        }
        let type_id = concrete_type_id(path, types, view.type_id, "security context")?;
        let range = if metadata.mls {
            for sensitivity in [view.low_sensitivity, view.high_sensitivity] {
                if sensitivities.get(sensitivity as usize).is_none() {
                    return Err(LoadError::new(
                        path,
                        INVALID_METADATA,
                        "security context has invalid sensitivity",
                    ));
                }
            }
            Some(MlsRange::new(
                MlsLevel::new(
                    SensitivityId::from_raw(view.low_sensitivity),
                    self.labeling_categories(
                        path,
                        kind,
                        index,
                        context_index,
                        false,
                        categories.len(),
                    )?,
                ),
                MlsLevel::new(
                    SensitivityId::from_raw(view.high_sensitivity),
                    self.labeling_categories(
                        path,
                        kind,
                        index,
                        context_index,
                        true,
                        categories.len(),
                    )?,
                ),
            ))
        } else {
            None
        };
        Ok(SecurityContext::new(
            UserId::from_raw(view.user),
            RoleId::from_raw(view.role),
            type_id,
            range,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn labeling_categories(
        &self,
        path: &Path,
        kind: u32,
        index: u32,
        context_index: u32,
        high: bool,
        category_count: usize,
    ) -> Result<Vec<CategoryId>, LoadError> {
        let mut count = 0_usize;
        let mut error = ffi::StError::default();
        // SAFETY: a null buffer requests the required count.
        let status = unsafe {
            ffi::st_policy_labeling_context_categories_get(
                self.raw.as_ptr(),
                kind,
                index,
                context_index,
                u32::from(high),
                std::ptr::null_mut(),
                0,
                &mut count,
                &mut error,
            )
        };
        check_status(
            path,
            status,
            &mut error,
            "could not count labeling categories",
        )?;
        let mut raw = vec![0_u32; count];
        let mut copied = count;
        let mut error = ffi::StError::default();
        // SAFETY: the output buffer has the declared capacity.
        let status = unsafe {
            ffi::st_policy_labeling_context_categories_get(
                self.raw.as_ptr(),
                kind,
                index,
                context_index,
                u32::from(high),
                raw.as_mut_ptr(),
                raw.len(),
                &mut copied,
                &mut error,
            )
        };
        check_status(
            path,
            status,
            &mut error,
            "could not copy labeling categories",
        )?;
        if copied != raw.len() || raw.iter().any(|value| *value as usize >= category_count) {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                "labeling context has invalid categories",
            ));
        }
        Ok(raw.into_iter().map(CategoryId::from_raw).collect())
    }
}

fn constraint_operands(
    path: &Path,
    attribute: u32,
) -> Result<(&'static str, Option<&'static str>), LoadError> {
    match attribute {
        1 => Ok(("u1", Some("u2"))),
        9 => Ok(("u2", None)),
        17 => Ok(("u3", None)),
        2 => Ok(("r1", Some("r2"))),
        10 => Ok(("r2", None)),
        18 => Ok(("r3", None)),
        4 => Ok(("t1", Some("t2"))),
        12 => Ok(("t2", None)),
        20 => Ok(("t3", None)),
        32 => Ok(("l1", Some("l2"))),
        64 => Ok(("l1", Some("h2"))),
        128 => Ok(("h1", Some("l2"))),
        256 => Ok(("h1", Some("h2"))),
        512 => Ok(("l1", Some("h1"))),
        1024 => Ok(("l2", Some("h2"))),
        value => Err(LoadError::new(
            path,
            INVALID_METADATA,
            format!("constraint has unknown attribute {value}"),
        )),
    }
}

fn constraint_operator(path: &Path, operator: u32) -> Result<ConstraintOperator, LoadError> {
    match operator {
        1 => Ok(ConstraintOperator::Equal),
        2 => Ok(ConstraintOperator::NotEqual),
        3 => Ok(ConstraintOperator::Dominates),
        4 => Ok(ConstraintOperator::DominatedBy),
        5 => Ok(ConstraintOperator::Incomparable),
        value => Err(LoadError::new(
            path,
            INVALID_METADATA,
            format!("constraint has unknown operator {value}"),
        )),
    }
}

fn labeling_address(path: &Path, family: u32, bytes: [u8; 16]) -> Result<IpAddr, LoadError> {
    match family {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        6 => Ok(IpAddr::V6(Ipv6Addr::from(bytes))),
        value => Err(LoadError::new(
            path,
            INVALID_METADATA,
            format!("nodecon has unknown address family {value}"),
        )),
    }
}

fn concrete_type_id(
    path: &Path,
    types: &[TypeSymbol],
    raw: u32,
    relation: &str,
) -> Result<TypeId, LoadError> {
    types
        .get(raw as usize)
        .and_then(|symbol| match symbol.id() {
            TypeOrAttributeId::Type(id) => Some(id),
            TypeOrAttributeId::Attribute(_) => None,
        })
        .ok_or_else(|| {
            LoadError::new(
                path,
                INVALID_METADATA,
                format!("rule has invalid {relation} type index {raw}"),
            )
        })
}

fn role_id(path: &Path, roles: &[Role], raw: u32, relation: &str) -> Result<RoleId, LoadError> {
    roles.get(raw as usize).map(Role::id).ok_or_else(|| {
        LoadError::new(
            path,
            INVALID_METADATA,
            format!("RBAC rule has invalid {relation} role index {raw}"),
        )
    })
}

fn symbol_id(
    path: &Path,
    types: &[TypeSymbol],
    raw: u32,
    relation: &str,
) -> Result<TypeOrAttributeId, LoadError> {
    types.get(raw as usize).map(TypeSymbol::id).ok_or_else(|| {
        LoadError::new(
            path,
            INVALID_METADATA,
            format!("TE rule has invalid {relation} symbol index {raw}"),
        )
    })
}

fn rule_kind(path: &Path, index: u32, raw: u32) -> Result<TeRuleKind, LoadError> {
    match raw {
        0x0001 => Ok(TeRuleKind::Allow),
        0x0002 => Ok(TeRuleKind::AuditAllow),
        0x0004 => Ok(TeRuleKind::DontAudit),
        0x0010 => Ok(TeRuleKind::TypeTransition),
        0x0020 => Ok(TeRuleKind::TypeMember),
        0x0040 => Ok(TeRuleKind::TypeChange),
        0x0100 => Ok(TeRuleKind::AllowXperm),
        0x0200 => Ok(TeRuleKind::AuditAllowXperm),
        0x0400 => Ok(TeRuleKind::DontAuditXperm),
        value => Err(LoadError::new(
            path,
            INVALID_METADATA,
            format!("TE rule {index} has unknown kind {value:#x}"),
        )),
    }
}

fn decode_xperms(
    path: &Path,
    index: u32,
    view: &ffi::StTeRuleView,
) -> Result<(XpermKind, Vec<u16>), LoadError> {
    let kind = match view.xperm_kind {
        1 | 2 => XpermKind::Ioctl,
        3 => XpermKind::NetlinkMessage,
        value => {
            return Err(LoadError::new(
                path,
                INVALID_METADATA,
                format!("TE rule {index} has unknown xperm kind {value}"),
            ));
        }
    };
    let mut values = Vec::new();
    for bit in 0_u16..256 {
        if view.xperms[usize::from(bit / 32)] & (1_u32 << (bit % 32)) == 0 {
            continue;
        }
        if view.xperm_kind == 2 {
            let base = bit << 8;
            values.extend(base..=base | 0x00ff);
        } else {
            values.push((view.xperm_driver as u16) << 8 | bit);
        }
    }
    if values.is_empty() {
        return Err(LoadError::new(
            path,
            INVALID_METADATA,
            format!("TE rule {index} has no extended permissions"),
        ));
    }
    Ok((kind, values))
}

impl Drop for NativePolicy {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `st_policy_load`, remains uniquely owned,
        // and this destructor runs exactly once.
        unsafe { ffi::st_policy_free(self.raw.as_ptr()) };
    }
}

fn verify_bridge_abi(path: &Path) -> Result<(), LoadError> {
    // SAFETY: this function has no arguments or ownership requirements.
    let actual = unsafe { ffi::st_bridge_abi_version() };
    if actual == BRIDGE_ABI_VERSION {
        Ok(())
    } else {
        Err(LoadError::new(
            path,
            0,
            format!("libsepol bridge ABI mismatch: expected {BRIDGE_ABI_VERSION}, found {actual}"),
        ))
    }
}

fn path_to_c_string(path: &Path) -> Result<CString, LoadError> {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    };

    #[cfg(not(unix))]
    let bytes = path
        .as_os_str()
        .to_str()
        .ok_or_else(|| LoadError::new(path, 0, "policy path cannot be represented as UTF-8"))?;

    CString::new(bytes)
        .map_err(|_| LoadError::new(path, 0, "policy path contains an interior NUL byte"))
}

fn take_native_error(path: &Path, error: &mut ffi::StError, fallback: &str) -> LoadError {
    let message = if error.message.is_null() {
        fallback.to_owned()
    } else {
        // SAFETY: bridge diagnostics are owned, NUL-terminated C strings that
        // remain valid until `st_error_clear` below.
        unsafe { CStr::from_ptr(error.message) }
            .to_string_lossy()
            .into_owned()
    };
    let result = LoadError::new(path, error.code, message);

    // SAFETY: the bridge allocated this error message and accepts an empty
    // value; clearing transfers no pointer back to Rust.
    unsafe { ffi::st_error_clear(error) };
    result
}

fn check_status(
    path: &Path,
    status: c_int,
    error: &mut ffi::StError,
    fallback: &str,
) -> Result<(), LoadError> {
    if status == 0 {
        Ok(())
    } else {
        Err(take_native_error(path, error, fallback))
    }
}

fn copy_string(
    path: &Path,
    view: ffi::StStringView,
    description: &str,
) -> Result<String, LoadError> {
    if view.data.is_null() {
        return Err(LoadError::new(
            path,
            INVALID_METADATA,
            format!("{description} has a null name"),
        ));
    }
    // SAFETY: the bridge guarantees the view is readable for `length` bytes
    // while the native owner remains alive, which it does for this copy.
    let bytes = unsafe { std::slice::from_raw_parts(view.data.cast::<u8>(), view.length) };
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
        LoadError::new(
            path,
            INVALID_METADATA,
            format!("{description} is not UTF-8"),
        )
    })
}

fn copy_os_path(view: ffi::StStringView) -> Option<PathBuf> {
    if view.data.is_null() {
        return None;
    }
    // SAFETY: libselinux owns this static string and guarantees it remains
    // readable; only an immediate owned copy is retained.
    let bytes = unsafe { std::slice::from_raw_parts(view.data.cast::<u8>(), view.length) };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes).ok().map(PathBuf::from)
    }
}

mod ffi {
    use super::{c_char, c_int};

    #[repr(C)]
    pub struct StPolicy {
        _private: [u8; 0],
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StError {
        pub code: i32,
        pub message: *mut c_char,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StPolicyMetadata {
        pub version: u32,
        pub mls: u32,
        pub target_platform: u32,
        pub handle_unknown: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct StStringView {
        pub data: *const c_char,
        pub length: usize,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StRunningPolicyInfo {
        pub selinuxfs_exists: u32,
        pub minimum_version: u32,
        pub maximum_version: u32,
        pub current_policy_path: StStringView,
        pub binary_policy_path: StStringView,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StTypeView {
        pub kind: u32,
        pub name: StStringView,
        pub permissive: u32,
        pub bound: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StClassView {
        pub name: StStringView,
        pub common: StStringView,
        pub permission_count: u32,
        pub local_permission_count: u32,
        pub default_user: u32,
        pub default_role: u32,
        pub default_type: u32,
        pub default_range: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StTeRuleView {
        pub kind: u32,
        pub source: u32,
        pub target: u32,
        pub target_class: u32,
        pub permissions: u32,
        pub default_type: u32,
        pub xperm_kind: u32,
        pub xperm_driver: u32,
        pub xperms: [u32; 8],
        pub conditional: u32,
        pub conditional_block: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StBooleanView {
        pub name: StStringView,
        pub state: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StConditionalTokenView {
        pub kind: u32,
        pub boolean: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StRoleView {
        pub name: StStringView,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StRbacRuleView {
        pub kind: u32,
        pub source: u32,
        pub target: u32,
        pub target_class: u32,
        pub default_role: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StFilenameRuleView {
        pub source: u32,
        pub target: u32,
        pub target_class: u32,
        pub default_type: u32,
        pub filename: StStringView,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StMlsRuleView {
        pub source: u32,
        pub target: u32,
        pub target_class: u32,
        pub low_sensitivity: u32,
        pub high_sensitivity: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StCommonView {
        pub name: StStringView,
        pub permission_count: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StUserView {
        pub name: StStringView,
        pub low_sensitivity: u32,
        pub high_sensitivity: u32,
        pub default_sensitivity: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StConstraintView {
        pub target_class: u32,
        pub permissions: u32,
        pub validate_transition: u32,
        pub mls: u32,
        pub expression_count: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StConstraintExpressionView {
        pub expression_type: u32,
        pub attribute: u32,
        pub operator: u32,
        pub names_kind: u32,
        pub names_count: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct StContextView {
        pub user: u32,
        pub role: u32,
        pub type_id: u32,
        pub low_sensitivity: u32,
        pub high_sensitivity: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StLabelingView {
        pub subtype: u32,
        pub name: StStringView,
        pub secondary: StStringView,
        pub low: u64,
        pub high: u64,
        pub address: [u8; 16],
        pub mask: [u8; 16],
        pub contexts: [StContextView; 2],
    }

    unsafe extern "C" {
        pub fn st_bridge_abi_version() -> u32;
        pub fn st_process_use_default_sigpipe() -> c_int;
        pub fn st_running_policy_info_get(info: *mut StRunningPolicyInfo) -> c_int;
        pub fn st_local_log_timestamp(buffer: *mut c_char, capacity: usize) -> c_int;
        pub fn st_policy_load(path: *const c_char, error: *mut StError) -> *mut StPolicy;
        pub fn st_policy_free(policy: *mut StPolicy);
        pub fn st_policy_metadata_get(
            policy: *const StPolicy,
            metadata: *mut StPolicyMetadata,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_type_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_type_get(
            policy: *const StPolicy,
            index: u32,
            symbol: *mut StTypeView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_type_alias_count(policy: *const StPolicy, symbol: u32) -> u32;
        pub fn st_policy_type_alias_get(
            policy: *const StPolicy,
            symbol: u32,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_attribute_members_get(
            policy: *const StPolicy,
            attribute: u32,
            members: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_class_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_class_get(
            policy: *const StPolicy,
            index: u32,
            target_class: *mut StClassView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_permission_get(
            policy: *const StPolicy,
            target_class: u32,
            permission: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_class_local_permission_get(
            policy: *const StPolicy,
            target_class: u32,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_te_rule_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_te_rule_get(
            policy: *const StPolicy,
            index: u32,
            rule: *mut StTeRuleView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_boolean_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_boolean_get(
            policy: *const StPolicy,
            index: u32,
            boolean: *mut StBooleanView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_conditional_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_conditional_token_count(policy: *const StPolicy, conditional: u32) -> u32;
        pub fn st_policy_conditional_token_get(
            policy: *const StPolicy,
            conditional: u32,
            index: u32,
            token: *mut StConditionalTokenView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_role_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_role_get(
            policy: *const StPolicy,
            index: u32,
            role: *mut StRoleView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_role_members_get(
            policy: *const StPolicy,
            role: u32,
            members: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_role_types_get(
            policy: *const StPolicy,
            role: u32,
            types: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_rbac_rule_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_rbac_rule_get(
            policy: *const StPolicy,
            index: u32,
            rule: *mut StRbacRuleView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_filename_rule_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_filename_rule_get(
            policy: *const StPolicy,
            index: u32,
            rule: *mut StFilenameRuleView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_sensitivity_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_sensitivity_get(
            policy: *const StPolicy,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_sensitivity_alias_count(policy: *const StPolicy, sensitivity: u32) -> u32;
        pub fn st_policy_sensitivity_alias_get(
            policy: *const StPolicy,
            sensitivity: u32,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_category_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_category_get(
            policy: *const StPolicy,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_category_alias_count(policy: *const StPolicy, category: u32) -> u32;
        pub fn st_policy_category_alias_get(
            policy: *const StPolicy,
            category: u32,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_mls_rule_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_mls_rule_get(
            policy: *const StPolicy,
            index: u32,
            rule: *mut StMlsRuleView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_mls_rule_categories_get(
            policy: *const StPolicy,
            index: u32,
            high: u32,
            categories: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_common_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_common_get(
            policy: *const StPolicy,
            index: u32,
            common: *mut StCommonView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_common_permission_get(
            policy: *const StPolicy,
            common: u32,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_user_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_user_get(
            policy: *const StPolicy,
            index: u32,
            user: *mut StUserView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_user_roles_get(
            policy: *const StPolicy,
            user: u32,
            roles: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_user_categories_get(
            policy: *const StPolicy,
            user: u32,
            level: u32,
            categories: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_constraint_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_constraint_get(
            policy: *const StPolicy,
            index: u32,
            constraint: *mut StConstraintView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_constraint_expression_get(
            policy: *const StPolicy,
            constraint: u32,
            index: u32,
            expression: *mut StConstraintExpressionView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_constraint_expression_names_get(
            policy: *const StPolicy,
            constraint: u32,
            expression: u32,
            names: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_capability_count(policy: *const StPolicy) -> u32;
        pub fn st_policy_capability_get(
            policy: *const StPolicy,
            index: u32,
            name: *mut StStringView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_labeling_count(policy: *const StPolicy, kind: u32) -> u32;
        pub fn st_policy_labeling_get(
            policy: *const StPolicy,
            kind: u32,
            index: u32,
            labeling: *mut StLabelingView,
            error: *mut StError,
        ) -> c_int;
        pub fn st_policy_labeling_context_categories_get(
            policy: *const StPolicy,
            kind: u32,
            index: u32,
            context_index: u32,
            high: u32,
            categories: *mut u32,
            capacity: usize,
            count: *mut usize,
            error: *mut StError,
        ) -> c_int;
        pub fn st_error_clear(error: *mut StError);
    }
}

#[cfg(test)]
mod tests {
    use super::{LibsepolLoader, RunningPolicyInfo, local_log_timestamp};
    use setools_policy::PolicyLoader;
    use std::path::{Path, PathBuf};

    #[test]
    fn missing_policy_reports_native_open_error() {
        let path = Path::new("definitely-missing-policy.35");
        let error = LibsepolLoader.load(path).unwrap_err();

        assert_eq!(error.path(), path);
        assert_eq!(error.code(), 3);
        assert!(error.message().contains("could not open binary policy"));
    }

    #[test]
    fn running_policy_candidates_match_legacy_order() {
        let info = RunningPolicyInfo {
            selinuxfs_exists: true,
            minimum_version: 32,
            maximum_version: 35,
            current_policy_path: Some(PathBuf::from("/sys/fs/selinux/policy")),
            binary_policy_path: Some(PathBuf::from("/etc/selinux/policy/policy")),
        };

        assert_eq!(
            info.candidates(),
            [
                "/sys/fs/selinux/policy",
                "/etc/selinux/policy/policy.35",
                "/etc/selinux/policy/policy.34",
                "/etc/selinux/policy/policy.33",
                "/etc/selinux/policy/policy.32",
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn local_log_timestamp_has_python_logging_shape() {
        let value = local_log_timestamp().expect("local timestamp should be available");
        let bytes = value.as_bytes();

        assert_eq!(bytes.len(), 23);
        for index in [4, 7] {
            assert_eq!(bytes[index], b'-');
        }
        assert_eq!(bytes[10], b' ');
        for index in [13, 16] {
            assert_eq!(bytes[index], b':');
        }
        assert_eq!(bytes[19], b',');
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| [4, 7, 10, 13, 16, 19].contains(&index)
                    || byte.is_ascii_digit())
        );
    }
}
