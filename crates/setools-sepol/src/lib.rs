//! Safe ownership boundary for the project-owned libsepol C bridge.
//!
//! This crate is the only workspace crate permitted to contain FFI and
//! `unsafe` code. A native policy is thread-confined, copied into the owned
//! Rust model, and released before [`LibsepolLoader::load`] returns.

use setools_policy::{
    AttributeId, Boolean, BooleanId, Category, CategoryId, ClassId, Conditional, ConditionalId,
    ConditionalToken, HandleUnknown, MlsLevel, MlsRange, MlsRule, ObjectClass, Permission,
    PermissionId, Policy, PolicyLoader, PolicyMetadata, RbacRule, RbacRuleData, Role, RoleId,
    RuleCondition, Sensitivity, SensitivityId, TargetPlatform, TeRule, TeRuleData, TeRuleKind,
    TypeId, TypeOrAttributeId, TypeSymbol, XpermKind,
};
use std::error::Error;
use std::ffi::{CStr, CString, c_char, c_int};
use std::fmt;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;

const BRIDGE_ABI_VERSION: u32 = 3;
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

        // `native` is dropped here, before the owned policy can escape.
        Ok(Policy::from_sesearch_parts(
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
            raw_types.push((view.kind, name));
        }

        let mut symbols = Vec::with_capacity(raw_types.len());
        for (index, (kind, name)) in raw_types.iter().enumerate() {
            let raw = u32::try_from(index)
                .map_err(|_| LoadError::new(path, INVALID_METADATA, "too many type symbols"))?;
            match kind {
                0 => symbols.push(
                    TypeSymbol::new_type(TypeId::from_raw(raw), name.clone()).with_aliases(
                        self.aliases(
                            path,
                            raw,
                            ffi::st_policy_type_alias_count,
                            ffi::st_policy_type_alias_get,
                            "type alias",
                        )?,
                    ),
                ),
                1 => {
                    let members = self.attribute_members(path, raw)?;
                    for member in &members {
                        match raw_types.get(member.as_raw() as usize) {
                            Some((0, _)) => {}
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
            classes.push(ObjectClass::new(
                ClassId::from_raw(index),
                name,
                permissions,
            ));
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
            roles.push(Role::new(
                RoleId::from_raw(index),
                copy_string(path, view.name, "role")?,
                members,
            ));
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
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct StClassView {
        pub name: StStringView,
        pub permission_count: u32,
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
