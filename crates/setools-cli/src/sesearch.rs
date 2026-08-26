//! `sesearch` argument parsing and compatibility text/versioned JSON rendering.

use crate::json;
use setools_policy::{
    ConditionalToken, MlsRule, Policy, PolicyLoader, RbacRule, RbacRuleData, RbacRuleKind, TeRule,
    TeRuleData, TeRuleKind, TypeOrAttributeId,
};
use setools_query::{MlsRuleQuery, RbacRuleQuery, TeRuleQuery, format_mls_range};
use setools_sepol::{
    LibsepolLoader, LoadError, local_log_timestamp, running_policy_info, use_default_sigpipe,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = include_str!("../assets/sesearch-help.txt");

const USAGE: &str = r"usage: sesearch [-h] [--version] [-v] [--debug] [-A] [--allow] [--allowxperm]
                [--auditallow] [--auditallowxperm] [--dontaudit]
                [--dontauditxperm] [-T] [--type_change] [--type_member]
                [--role_allow] [--role_transition] [--range_transition]
                [-s SOURCE] [-t TARGET] [-c TCLASS] [-p PERMS] [-x XPERMS]
                [-D DEFAULT] [-b BOOL] [-eb] [-ep] [-ex] [-Sp] [-ds] [-dt]
                [-rs] [-rt] [-rc] [-rd] [-rb]
                [policy]
";

#[derive(Debug, Default)]
struct Options {
    policy: Option<PathBuf>,
    te_kinds: BTreeSet<TeRuleKind>,
    role_allow: bool,
    role_transition: bool,
    range_transition: bool,
    source: Option<String>,
    target: Option<String>,
    target_class: Option<String>,
    permissions: Option<String>,
    xpermissions: Option<String>,
    default_type: Option<String>,
    boolean: Option<String>,
    boolean_equal: bool,
    permissions_equal: bool,
    xpermissions_equal: bool,
    permissions_subset: bool,
    source_indirect: bool,
    target_indirect: bool,
    source_regex: bool,
    target_regex: bool,
    target_class_regex: bool,
    default_regex: bool,
    boolean_regex: bool,
    verbose: bool,
    debug: bool,
    json: bool,
}

impl Options {
    fn new() -> Self {
        Self {
            source_indirect: true,
            target_indirect: true,
            ..Self::default()
        }
    }

    fn has_rbac_or_mls(&self) -> bool {
        self.role_allow || self.role_transition || self.range_transition
    }

    fn has_any_rule_kind(&self) -> bool {
        !self.te_kinds.is_empty() || self.has_rbac_or_mls()
    }
}

enum ParseAction {
    Run(Box<Options>),
    Help,
    Version,
}

#[derive(Debug, Eq, PartialEq)]
struct SearchResult {
    family: &'static str,
    rule_type: &'static str,
    statement: String,
}

impl SearchResult {
    fn new(family: &'static str, rule_type: &'static str, statement: String) -> Self {
        Self {
            family,
            rule_type,
            statement,
        }
    }
}

/// Runs `sesearch` with already separated process arguments.
pub(crate) fn run(arguments: Vec<OsString>) -> ExitCode {
    let _ = use_default_sigpipe();
    let action = match parse(arguments) {
        Ok(action) => action,
        Err(message) => return usage_error(&message),
    };
    let options = match action {
        ParseAction::Help => return write_stdout(HELP),
        ParseAction::Version => return write_stdout(concat!(env!("CARGO_PKG_VERSION"), "\n")),
        ParseAction::Run(options) => *options,
    };

    if !options.has_any_rule_kind() {
        return usage_error("At least one rule type must be specified.");
    }
    if (options.permissions.is_some()
        || options.xpermissions.is_some()
        || options.boolean.is_some())
        && options.has_rbac_or_mls()
    {
        return usage_error(
            "-p/--perms, -x/--xperms, and -b/--bool options are only supported with TE rule searches.",
        );
    }
    let (policy, policy_path) = match load_policy(&options) {
        Ok(loaded) => loaded,
        Err(message) => return analysis_error(&message),
    };
    let mut results = Vec::new();
    if !options.te_kinds.is_empty() {
        log_message(
            &options,
            "INFO",
            "setools.terulequery",
            &format!("Generating TE rule results from {}", policy_path.display()),
        );
        let query = match prepare_te_query(&policy, &options) {
            Ok(query) => query,
            Err(error) => return analysis_error(&error.to_string()),
        };
        log_te_query(&options, &policy, &policy_path);
        let mut family_results = match query
            .results()
            .into_iter()
            .map(|rule| {
                render_rule(&policy, rule)
                    .map(|statement| SearchResult::new("te", rule.kind().keyword(), statement))
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(results) => results,
            Err(message) => return analysis_error(&message),
        };
        family_results.sort_unstable_by(|left, right| left.statement.cmp(&right.statement));
        results.extend(family_results);
    }
    if options.role_allow || options.role_transition {
        log_message(
            &options,
            "INFO",
            "setools.rbacrulequery",
            &format!(
                "Generating RBAC rule results from {}",
                policy_path.display()
            ),
        );
        let query = match prepare_rbac_query(&policy, &options) {
            Ok(query) => query,
            Err(error) => return analysis_error(&error.to_string()),
        };
        log_rbac_query(&options, &policy, &policy_path);
        let mut family_results = match query
            .results()
            .into_iter()
            .map(|rule| {
                render_rbac_rule(&policy, rule)
                    .map(|statement| SearchResult::new("rbac", rule.kind().keyword(), statement))
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(results) => results,
            Err(message) => return analysis_error(&message),
        };
        family_results.sort_unstable_by(|left, right| left.statement.cmp(&right.statement));
        results.extend(family_results);
    }
    if options.range_transition {
        log_message(
            &options,
            "INFO",
            "setools.mlsrulequery",
            &format!("Generating MLS rule results from {}", policy_path.display()),
        );
        let query = match prepare_mls_query(&policy, &options) {
            Ok(query) => query,
            Err(error) => return analysis_error(&error.to_string()),
        };
        log_mls_query(&options, &policy, &policy_path);
        let mut family_results = match query
            .results()
            .into_iter()
            .map(|rule| {
                render_mls_rule(&policy, rule)
                    .map(|statement| SearchResult::new("mls", "range_transition", statement))
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(results) => results,
            Err(message) => return analysis_error(&message),
        };
        family_results.sort_unstable_by(|left, right| left.statement.cmp(&right.statement));
        results.extend(family_results);
    }
    if options.json {
        write_stdout(&render_json(&options, &policy_path, &results))
    } else if results.is_empty() {
        ExitCode::SUCCESS
    } else {
        write_stdout(&format!(
            "{}\n",
            results
                .iter()
                .map(|result| result.statement.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

fn render_json(options: &Options, policy_path: &Path, results: &[SearchResult]) -> String {
    let mut output = String::new();
    output.push_str(
        "{\"schema\":\"setools-rs.sesearch\",\"schema_version\":1,\"tool\":{\"name\":\"sesearch\",\"version\":",
    );
    json::push_string(&mut output, env!("CARGO_PKG_VERSION"));
    output.push_str("},\"policy\":{\"path\":");
    json::push_string(&mut output, &policy_path.to_string_lossy());
    output.push_str("},\"query\":{\"rule_types\":[");
    push_json_rule_types(&mut output, options);
    output.push_str("],\"source\":");
    push_json_symbol_criterion(
        &mut output,
        options.source.as_deref(),
        options.source_indirect,
        options.source_regex,
    );
    output.push_str(",\"target\":");
    push_json_symbol_criterion(
        &mut output,
        options.target.as_deref(),
        options.target_indirect,
        options.target_regex,
    );
    output.push_str(",\"class\":");
    push_json_regex_criterion(
        &mut output,
        options.target_class.as_deref(),
        options.target_class_regex,
    );
    output.push_str(",\"permissions\":");
    push_json_permission_criterion(
        &mut output,
        options.permissions.as_deref(),
        options.permissions_equal,
        options.permissions_subset,
    );
    output.push_str(",\"xpermissions\":");
    push_json_equal_criterion(
        &mut output,
        options.xpermissions.as_deref(),
        options.xpermissions_equal,
    );
    output.push_str(",\"default\":");
    push_json_regex_criterion(
        &mut output,
        options.default_type.as_deref(),
        options.default_regex,
    );
    output.push_str(",\"boolean\":");
    push_json_boolean_criterion(
        &mut output,
        options.boolean.as_deref(),
        options.boolean_equal,
        options.boolean_regex,
    );
    output.push_str("},\"result_count\":");
    output.push_str(&results.len().to_string());
    output.push_str(",\"results\":[");
    for (index, result) in results.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"family\":");
        json::push_string(&mut output, result.family);
        output.push_str(",\"rule_type\":");
        json::push_string(&mut output, result.rule_type);
        output.push_str(",\"statement\":");
        json::push_string(&mut output, &result.statement);
        output.push('}');
    }
    output.push_str("]}\n");
    output
}

fn push_json_rule_types(output: &mut String, options: &Options) {
    let mut first = true;
    for kind in &options.te_kinds {
        push_json_rule_type(output, &mut first, "te", kind.keyword());
    }
    if options.role_allow {
        push_json_rule_type(output, &mut first, "rbac", RbacRuleKind::Allow.keyword());
    }
    if options.role_transition {
        push_json_rule_type(
            output,
            &mut first,
            "rbac",
            RbacRuleKind::RoleTransition.keyword(),
        );
    }
    if options.range_transition {
        push_json_rule_type(output, &mut first, "mls", "range_transition");
    }
}

fn push_json_rule_type(output: &mut String, first: &mut bool, family: &str, rule_type: &str) {
    if !*first {
        output.push(',');
    }
    *first = false;
    output.push_str("{\"family\":");
    json::push_string(output, family);
    output.push_str(",\"rule_type\":");
    json::push_string(output, rule_type);
    output.push('}');
}

fn push_json_symbol_criterion(
    output: &mut String,
    value: Option<&str>,
    indirect: bool,
    regex: bool,
) {
    let Some(value) = value else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"value\":");
    json::push_string(output, value);
    output.push_str(",\"indirect\":");
    output.push_str(json_boolean(indirect));
    output.push_str(",\"regex\":");
    output.push_str(json_boolean(regex));
    output.push('}');
}

fn push_json_regex_criterion(output: &mut String, value: Option<&str>, regex: bool) {
    let Some(value) = value else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"value\":");
    json::push_string(output, value);
    output.push_str(",\"regex\":");
    output.push_str(json_boolean(regex));
    output.push('}');
}

fn push_json_permission_criterion(
    output: &mut String,
    value: Option<&str>,
    equal: bool,
    subset: bool,
) {
    let Some(value) = value else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"value\":");
    json::push_string(output, value);
    output.push_str(",\"equal\":");
    output.push_str(json_boolean(equal));
    output.push_str(",\"subset\":");
    output.push_str(json_boolean(subset));
    output.push('}');
}

fn push_json_equal_criterion(output: &mut String, value: Option<&str>, equal: bool) {
    let Some(value) = value else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"value\":");
    json::push_string(output, value);
    output.push_str(",\"equal\":");
    output.push_str(json_boolean(equal));
    output.push('}');
}

fn push_json_boolean_criterion(output: &mut String, value: Option<&str>, equal: bool, regex: bool) {
    let Some(value) = value else {
        output.push_str("null");
        return;
    };
    output.push_str("{\"value\":");
    json::push_string(output, value);
    output.push_str(",\"equal\":");
    output.push_str(json_boolean(equal));
    output.push_str(",\"regex\":");
    output.push_str(json_boolean(regex));
    output.push('}');
}

const fn json_boolean(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn parse(arguments: Vec<OsString>) -> Result<ParseAction, String> {
    let arguments = arguments
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "command-line arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut options = Options::new();
    let mut index = 0_usize;
    let mut positional_only = false;

    while index < arguments.len() {
        let argument = &arguments[index];
        if positional_only {
            set_policy(&mut options, argument)?;
            index += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        match argument.as_str() {
            "-h" | "--help" => return Ok(ParseAction::Help),
            "--version" => return Ok(ParseAction::Version),
            "-v" | "--verbose" => options.verbose = true,
            "--debug" => options.debug = true,
            "--json" => options.json = true,
            "-A" => {
                options.te_kinds.insert(TeRuleKind::Allow);
                options.te_kinds.insert(TeRuleKind::AllowXperm);
            }
            "--allow" => select(&mut options, TeRuleKind::Allow),
            "--allowxperm" => select(&mut options, TeRuleKind::AllowXperm),
            "--auditallow" => select(&mut options, TeRuleKind::AuditAllow),
            "--auditallowxperm" => select(&mut options, TeRuleKind::AuditAllowXperm),
            "--dontaudit" => select(&mut options, TeRuleKind::DontAudit),
            "--dontauditxperm" => select(&mut options, TeRuleKind::DontAuditXperm),
            "-T" | "--type_transition" => select(&mut options, TeRuleKind::TypeTransition),
            "--type_change" => select(&mut options, TeRuleKind::TypeChange),
            "--type_member" => select(&mut options, TeRuleKind::TypeMember),
            "--role_allow" => options.role_allow = true,
            "--role_transition" => options.role_transition = true,
            "--range_transition" => options.range_transition = true,
            "-eb" => options.boolean_equal = true,
            "-ep" => options.permissions_equal = true,
            "-ex" => options.xpermissions_equal = true,
            "-Sp" => options.permissions_subset = true,
            "-ds" => options.source_indirect = false,
            "-dt" => options.target_indirect = false,
            "-rs" => options.source_regex = true,
            "-rt" => options.target_regex = true,
            "-rc" => options.target_class_regex = true,
            "-rd" => options.default_regex = true,
            "-rb" => options.boolean_regex = true,
            "-s" | "--source" => {
                options.source = Some(take_value(&arguments, &mut index, argument)?);
            }
            "-t" | "--target" => {
                options.target = Some(take_value(&arguments, &mut index, argument)?);
            }
            "-c" | "--class" => {
                options.target_class = Some(take_value(&arguments, &mut index, argument)?);
            }
            "-p" | "--perms" => {
                options.permissions = Some(take_value(&arguments, &mut index, argument)?);
            }
            "-x" | "--xperms" => {
                options.xpermissions = Some(take_value(&arguments, &mut index, argument)?);
            }
            "-D" | "--default" => {
                options.default_type = Some(take_value(&arguments, &mut index, argument)?);
            }
            "-b" | "--bool" => {
                options.boolean = Some(take_value(&arguments, &mut index, argument)?);
            }
            _ if argument.starts_with("--") && argument.contains('=') => {
                let (option, value) = argument
                    .split_once('=')
                    .expect("contains check guarantees split");
                set_long_value(&mut options, option, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unrecognized arguments: {argument}"));
            }
            _ => set_policy(&mut options, argument)?,
        }
        index += 1;
    }
    Ok(ParseAction::Run(Box::new(options)))
}

fn select(options: &mut Options, kind: TeRuleKind) {
    options.te_kinds.insert(kind);
}

fn take_value(arguments: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("argument {option}: expected one argument"))
}

fn set_long_value(options: &mut Options, option: &str, value: &str) -> Result<(), String> {
    match option {
        "--source" => options.source = Some(value.to_owned()),
        "--target" => options.target = Some(value.to_owned()),
        "--class" => options.target_class = Some(value.to_owned()),
        "--perms" => options.permissions = Some(value.to_owned()),
        "--xperms" => options.xpermissions = Some(value.to_owned()),
        "--default" => options.default_type = Some(value.to_owned()),
        "--bool" => options.boolean = Some(value.to_owned()),
        _ => return Err(format!("unrecognized arguments: {option}={value}")),
    }
    Ok(())
}

fn set_policy(options: &mut Options, value: &str) -> Result<(), String> {
    if options.policy.is_some() {
        return Err(format!("unrecognized arguments: {value}"));
    }
    options.policy = Some(PathBuf::from(value));
    Ok(())
}

fn prepare_te_query<'policy>(
    policy: &'policy Policy,
    options: &Options,
) -> Result<TeRuleQuery<'policy>, Box<dyn std::error::Error>> {
    let mut query = TeRuleQuery::new(policy);
    for kind in &options.te_kinds {
        query.select_kind(*kind);
    }
    if let Some(source) = &options.source {
        query.set_source(source, options.source_indirect, options.source_regex)?;
    }
    if let Some(target) = &options.target {
        query.set_target(target, options.target_indirect, options.target_regex)?;
    }
    if let Some(target_class) = &options.target_class {
        if options.target_class_regex {
            query.set_class_regex(target_class)?;
        } else {
            query.set_classes(target_class.split(','))?;
        }
    }
    if let Some(permissions) = &options.permissions {
        query.set_permissions(
            permissions.split(','),
            options.permissions_equal,
            options.permissions_subset,
        )?;
    }
    if let Some(xpermissions) = &options.xpermissions {
        query.set_xpermissions(
            parse_xpermissions(xpermissions)?,
            options.xpermissions_equal,
        );
    }
    if let Some(default_type) = &options.default_type {
        query.set_default(default_type, options.default_regex)?;
    }
    if let Some(boolean) = &options.boolean {
        if options.boolean_regex {
            query.set_boolean_regex(boolean)?;
        } else {
            query.set_booleans(boolean.split(','), options.boolean_equal)?;
        }
    }
    Ok(query)
}

fn prepare_rbac_query<'policy>(
    policy: &'policy Policy,
    options: &Options,
) -> Result<RbacRuleQuery<'policy>, Box<dyn std::error::Error>> {
    let mut query = RbacRuleQuery::new(policy);
    if options.role_allow {
        query.select_kind(RbacRuleKind::Allow);
    }
    if options.role_transition {
        query.select_kind(RbacRuleKind::RoleTransition);
    }
    if let Some(source) = &options.source {
        query.set_source(source, options.source_indirect, options.source_regex)?;
    }
    if let Some(target) = &options.target {
        query.set_target(target, options.target_indirect, options.target_regex)?;
    }
    if let Some(target_class) = &options.target_class {
        if options.target_class_regex {
            query.set_class_regex(target_class)?;
        } else {
            query.set_classes(target_class.split(','))?;
        }
    }
    if let Some(default_role) = &options.default_type {
        query.set_default(default_role, options.default_regex)?;
    }
    Ok(query)
}

fn prepare_mls_query<'policy>(
    policy: &'policy Policy,
    options: &Options,
) -> Result<MlsRuleQuery<'policy>, Box<dyn std::error::Error>> {
    let mut query = MlsRuleQuery::new(policy);
    if let Some(source) = &options.source {
        query.set_source(source, options.source_indirect, options.source_regex)?;
    }
    if let Some(target) = &options.target {
        query.set_target(target, options.target_indirect, options.target_regex)?;
    }
    if let Some(target_class) = &options.target_class {
        if options.target_class_regex {
            query.set_class_regex(target_class)?;
        } else {
            query.set_classes(target_class.split(','))?;
        }
    }
    if let Some(default_range) = &options.default_type {
        query.set_default(default_range)?;
    }
    Ok(query)
}

fn parse_xpermissions(value: &str) -> Result<BTreeSet<u16>, String> {
    let mut result = BTreeSet::new();
    for item in value.split(',') {
        let pieces = item.split('-').collect::<Vec<_>>();
        let (mut low, mut high) = match pieces.as_slice() {
            [single] => {
                let parsed = parse_hex(single)?;
                (parsed, parsed)
            }
            [low, high] => (parse_hex(low)?, parse_hex(high)?),
            _ => return Err(format!("Unable to parse \"{item}\" for xperms.")),
        };
        if high < low {
            std::mem::swap(&mut low, &mut high);
        }
        result.extend(low..=high);
    }
    Ok(result)
}

fn parse_hex(value: &str) -> Result<u16, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let parsed = u32::from_str_radix(digits, 16)
        .map_err(|_| format!("invalid literal for int() with base 16: '{value}'"))?;
    u16::try_from(parsed).map_err(|_| format!("{parsed:#07x} is not a valid ioctl."))
}

fn load_policy(options: &Options) -> Result<(Policy, PathBuf), String> {
    let explicit = options.policy.is_some();
    let candidates = if let Some(path) = &options.policy {
        vec![path.clone()]
    } else {
        log_message(
            options,
            "INFO",
            "setools.policyrep",
            "Attempting to locate current running policy.",
        );
        let Some(info) = running_policy_info() else {
            return Err("Unable to locate an SELinux policy to load.".to_owned());
        };
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            &format!(
                "SELinuxfs exists: {}",
                if info.selinuxfs_exists {
                    "True"
                } else {
                    "False"
                }
            ),
        );
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            &format!(
                "Sepol version range: {}-{}",
                info.minimum_version, info.maximum_version
            ),
        );
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            &format!(
                "Current policy path: {}",
                optional_path(&info.current_policy_path)
            ),
        );
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            &format!(
                "Binary policy path: {}",
                optional_path(&info.binary_policy_path)
            ),
        );
        let candidates = info.candidates();
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            &format!("Potential policies: {}", python_path_list(&candidates)),
        );
        candidates
    };

    for path in candidates {
        log_message(
            options,
            "INFO",
            "setools.policyrep",
            &format!("Opening SELinux policy \"{}\"", path.display()),
        );
        match LibsepolLoader.load(&path) {
            Ok(policy) => {
                log_policy_load_debug(options, &policy);
                log_message(
                    options,
                    "INFO",
                    "setools.policyrep",
                    &format!("Successfully opened SELinux policy \"{}\"", path.display()),
                );
                return Ok((policy, path));
            }
            Err(error) if !explicit && error.code() == 3 && !path.exists() => continue,
            Err(error) => return Err(compat_load_error(&path, &error)),
        }
    }
    Err("Unable to locate an SELinux policy to load.".to_owned())
}

fn optional_path(path: &Option<PathBuf>) -> String {
    path.as_ref()
        .map_or_else(|| "None".to_owned(), |path| path.display().to_string())
}

fn python_path_list(paths: &[PathBuf]) -> String {
    format!(
        "[{}]",
        paths
            .iter()
            .map(|path| format!("'{}'", path.display()))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn log_policy_load_debug(options: &Options, policy: &Policy) {
    log_message(
        options,
        "DEBUG",
        "setools.policyrep",
        "Rebuilding attributes.",
    );
    log_message(
        options,
        "DEBUG",
        "setools.policyrep",
        "Setting permissive flags in type datums.",
    );
    if policy.metadata().mls {
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            "Creating cat_val_to_struct.",
        );
        log_message(
            options,
            "DEBUG",
            "setools.policyrep",
            "Creating level_val_to_struct.",
        );
    }
}

fn compat_load_error(path: &Path, error: &LoadError) -> String {
    if error.code() == 3 && !path.exists() {
        format!("[Errno 2] No such file or directory: '{}'", path.display())
    } else {
        error.to_string()
    }
}

fn log_message(options: &Options, level: &str, module: &str, message: &str) {
    if options.debug {
        if let Some(timestamp) = local_log_timestamp() {
            eprintln!("{timestamp}|{level}|{module}|{message}");
        } else {
            eprintln!("{level}|{module}|{message}");
        }
    } else if options.verbose && level == "INFO" {
        eprintln!("{message}");
    }
}

fn log_te_query(options: &Options, policy: &Policy, path: &Path) {
    if !options.debug {
        return;
    }
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!("self.ruletype={}", te_kind_repr(&options.te_kinds)),
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.source={}, self.source_indirect={}, self.source_regex={}",
            symbol_criterion_repr(
                policy,
                path,
                options.source.as_deref(),
                options.source_regex
            ),
            python_bool(options.source_indirect),
            python_bool(options.source_regex)
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.target={}, self.target_indirect={}, self.target_regex={}",
            symbol_criterion_repr(
                policy,
                path,
                options.target.as_deref(),
                options.target_regex
            ),
            python_bool(options.target_indirect),
            python_bool(options.target_regex)
        ),
    );
    log_common_query(options, policy, path, "setools.terulequery");
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.xperms={}, self.xperms_equal={}",
            xpermission_criterion_repr(options.xpermissions.as_deref()),
            python_bool(options.xpermissions_equal)
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.default={}, self.default_regex={}",
            symbol_criterion_repr(
                policy,
                path,
                options.default_type.as_deref(),
                options.default_regex
            ),
            python_bool(options.default_regex)
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.boolean={}, self.boolean_equal={}, self.boolean_regex={}",
            boolean_criterion_repr(
                policy,
                path,
                options.boolean.as_deref(),
                options.boolean_regex
            ),
            python_bool(options.boolean_equal),
            python_bool(options.boolean_regex)
        ),
    );
}

fn log_rbac_query(options: &Options, policy: &Policy, path: &Path) {
    if !options.debug {
        return;
    }
    let mut kinds = Vec::new();
    if options.role_allow {
        kinds.push("<RBACRuletype.allow: 1>");
    }
    if options.role_transition {
        kinds.push("<RBACRuletype.role_transition: 2>");
    }
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        &format!("self.ruletype=frozenset({{{}}})", kinds.join(", ")),
    );
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        &format!(
            "self.source={}, self.source_indirect={}, self.source_regex={}",
            role_criterion_repr(
                policy,
                path,
                options.source.as_deref(),
                options.source_regex
            ),
            python_bool(options.source_indirect),
            python_bool(options.source_regex)
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        &format!(
            "self.target={}, self.target_indirect={}, self.target_regex={}",
            rbac_target_repr(
                policy,
                path,
                options.target.as_deref(),
                options.target_regex
            ),
            python_bool(options.target_indirect),
            python_bool(options.target_regex)
        ),
    );
    log_class_query(options, policy, path, "setools.rbacrulequery");
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        &format!(
            "self.default={}, self.default_regex={}",
            role_criterion_repr(
                policy,
                path,
                options.default_type.as_deref(),
                options.default_regex
            ),
            python_bool(options.default_regex)
        ),
    );
}

fn log_mls_query(options: &Options, policy: &Policy, path: &Path) {
    if !options.debug {
        return;
    }
    log_message(
        options,
        "DEBUG",
        "setools.mlsrulequery",
        "self.ruletype=frozenset({<MLSRuletype.range_transition: 1>})",
    );
    log_message(
        options,
        "DEBUG",
        "setools.mlsrulequery",
        &format!(
            "self.source={}, self.source_indirect={}, self.source_regex={}",
            symbol_criterion_repr(
                policy,
                path,
                options.source.as_deref(),
                options.source_regex
            ),
            python_bool(options.source_indirect),
            python_bool(options.source_regex)
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.mlsrulequery",
        &format!(
            "self.target={}, self.target_indirect={}, self.target_regex={}",
            symbol_criterion_repr(
                policy,
                path,
                options.target.as_deref(),
                options.target_regex
            ),
            python_bool(options.target_indirect),
            python_bool(options.target_regex)
        ),
    );
    log_class_query(options, policy, path, "setools.mlsrulequery");
    log_message(
        options,
        "DEBUG",
        "setools.mlsrulequery",
        &format!(
            "self.default={}, self.default_overlap=False, self.default_subset=False, self.default_superset=False, self.default_proper=False",
            range_criterion_repr(path, options.default_type.as_deref())
        ),
    );
}

fn log_common_query(options: &Options, policy: &Policy, path: &Path, module: &str) {
    log_class_query(options, policy, path, module);
    log_message(
        options,
        "DEBUG",
        module,
        &format!(
            "self.perms={}, self.perms_regex=False, self.perms_equal={}, self.perms_subset={}",
            string_set_repr(options.permissions.as_deref()),
            python_bool(options.permissions_equal),
            python_bool(options.permissions_subset)
        ),
    );
}

fn string_set_repr(value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |value| {
            format!(
                "frozenset({{{}}})",
                value
                    .split(',')
                    .map(|item| format!("'{item}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    )
}

fn boolean_criterion_repr(
    policy: &Policy,
    path: &Path,
    value: Option<&str>,
    regex: bool,
) -> String {
    let Some(value) = value else {
        return "None".to_owned();
    };
    if regex {
        return format!("re.compile('{value}')");
    }
    let values = value
        .split(',')
        .map(|name| {
            let name = policy
                .boolean_by_name(name)
                .map_or(name, |boolean| boolean.name());
            format!(
                "<Boolean(<SELinuxPolicy(\"{}\")>, \"{name}\")>",
                path.display()
            )
        })
        .collect::<Vec<_>>();
    format!("frozenset({{{}}})", values.join(", "))
}

fn xpermission_criterion_repr(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "None".to_owned();
    };
    let Ok(values) = parse_xpermissions(value) else {
        return value.to_owned();
    };
    format!(
        "{{ {} }}",
        xpermission_ranges(&values.into_iter().collect::<Vec<_>>()).join(", ")
    )
}

fn log_class_query(options: &Options, policy: &Policy, path: &Path, module: &str) {
    log_message(
        options,
        "DEBUG",
        module,
        &format!(
            "self.tclass={}, self.tclass_regex={}",
            class_criterion_repr(
                policy,
                path,
                options.target_class.as_deref(),
                options.target_class_regex
            ),
            python_bool(options.target_class_regex)
        ),
    );
}

fn class_criterion_repr(policy: &Policy, path: &Path, value: Option<&str>, regex: bool) -> String {
    let Some(value) = value else {
        return "None".to_owned();
    };
    if regex {
        return format!("re.compile('{value}')");
    }
    let classes = value
        .split(',')
        .filter_map(|name| policy.object_class_by_name(name))
        .map(|target_class| {
            format!(
                "<ObjClass(<SELinuxPolicy(\"{}\")>, \"{}\")>",
                path.display(),
                target_class.name()
            )
        })
        .collect::<Vec<_>>();
    format!("frozenset({{{}}})", classes.join(", "))
}

fn role_criterion_repr(policy: &Policy, path: &Path, value: Option<&str>, regex: bool) -> String {
    let Some(value) = value else {
        return "None".to_owned();
    };
    if regex {
        return format!("re.compile('{value}')");
    }
    let name = policy.role_by_name(value).map_or(value, |role| role.name());
    format!(
        "<Role(<SELinuxPolicy(\"{}\")>, \"{name}\")>",
        path.display()
    )
}

fn rbac_target_repr(policy: &Policy, path: &Path, value: Option<&str>, regex: bool) -> String {
    let Some(value) = value else {
        return "None".to_owned();
    };
    if regex {
        return format!("re.compile('{value}')");
    }
    if policy.type_symbol_by_name(value).is_some() {
        symbol_criterion_repr(policy, path, Some(value), false)
    } else {
        role_criterion_repr(policy, path, Some(value), false)
    }
}

fn range_criterion_repr(path: &Path, value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |value| {
            format!(
                "<Range(<SELinuxPolicy(\"{}\")>, \"{value}\")>",
                path.display()
            )
        },
    )
}

fn symbol_criterion_repr(policy: &Policy, path: &Path, value: Option<&str>, regex: bool) -> String {
    let Some(value) = value else {
        return "None".to_owned();
    };
    if regex {
        return format!("re.compile('{value}')");
    }
    let Some(symbol) = policy.type_symbol_by_name(value) else {
        return value.to_owned();
    };
    let kind = match symbol.id() {
        TypeOrAttributeId::Type(_) => "Type",
        TypeOrAttributeId::Attribute(_) => "TypeAttribute",
    };
    format!(
        "<{kind}(<SELinuxPolicy(\"{}\")>, \"{}\")>",
        path.display(),
        symbol.name()
    )
}

fn te_kind_repr(kinds: &BTreeSet<TeRuleKind>) -> String {
    let values = kinds
        .iter()
        .map(|kind| match kind {
            TeRuleKind::Allow => "<TERuletype.allow: 1>",
            TeRuleKind::AuditAllow => "<TERuletype.auditallow: 4>",
            TeRuleKind::DontAudit => "<TERuletype.dontaudit: 8>",
            TeRuleKind::TypeTransition => "<TERuletype.type_transition: 16>",
            TeRuleKind::TypeChange => "<TERuletype.type_change: 32>",
            TeRuleKind::TypeMember => "<TERuletype.type_member: 64>",
            TeRuleKind::AllowXperm => "<TERuletype.allowxperm: 256>",
            TeRuleKind::AuditAllowXperm => "<TERuletype.auditallowxperm: 1024>",
            TeRuleKind::DontAuditXperm => "<TERuletype.dontauditxperm: 2048>",
        })
        .collect::<Vec<_>>();
    format!("frozenset({{{}}})", values.join(", "))
}

const fn python_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

pub(crate) fn render_rule(policy: &Policy, rule: &TeRule) -> Result<String, String> {
    let source = symbol_name(policy, rule.source())?;
    let target = symbol_name(policy, rule.target())?;
    let target_class = policy
        .object_class(rule.target_class())
        .ok_or_else(|| "rule refers to a missing object class".to_owned())?;
    let prefix = format!(
        "{} {source} {target}:{} ",
        rule.kind().keyword(),
        target_class.name()
    );
    let mut statement = match rule.data() {
        TeRuleData::Permissions(ids) => {
            let mut names = ids
                .iter()
                .map(|id| {
                    target_class
                        .permission(*id)
                        .map(|permission| permission.name().to_owned())
                        .ok_or_else(|| "rule refers to a missing permission".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort_unstable();
            if names.len() == 1 {
                format!("{prefix}{};", names[0])
            } else {
                format!("{prefix}{{ {} }};", names.join(" "))
            }
        }
        TeRuleData::ExtendedPermissions { kind, values } => {
            let ranges = xpermission_ranges(values);
            let rendered = if ranges.len() == 1 {
                ranges[0].clone()
            } else {
                format!("{{ {} }}", ranges.join(" "))
            };
            format!("{prefix}{} {rendered};", kind.keyword())
        }
        TeRuleData::DefaultType { default, filename } => {
            let name = symbol_name(policy, TypeOrAttributeId::Type(*default))?;
            if let Some(filename) = filename {
                format!("{prefix}{name} {filename};")
            } else {
                format!("{prefix}{name};")
            }
        }
    };
    if let Some(rule_condition) = rule.condition() {
        let conditional = policy
            .conditional(rule_condition.conditional())
            .ok_or_else(|| "rule refers to a missing conditional expression".to_owned())?;
        let expression = render_conditional(policy, conditional.tokens())?;
        let block = if rule_condition.block() {
            "True"
        } else {
            "False"
        };
        statement.push_str(&format!(" [ {expression} ]:{block}"));
    }
    Ok(statement)
}

#[derive(Debug)]
struct ConditionalOperand {
    tokens: Vec<String>,
    compound: bool,
}

fn render_conditional(policy: &Policy, tokens: &[ConditionalToken]) -> Result<String, String> {
    let mut stack = Vec::<ConditionalOperand>::new();
    let mut previous_precedence = 5_u8;

    for token in tokens {
        if let ConditionalToken::Boolean(id) = token {
            let boolean = policy
                .boolean(*id)
                .ok_or_else(|| "conditional refers to a missing Boolean".to_owned())?;
            stack.push(ConditionalOperand {
                tokens: vec![boolean.name().to_owned()],
                compound: false,
            });
            continue;
        }

        if *token == ConditionalToken::Not {
            let operand = stack
                .pop()
                .ok_or_else(|| "conditional expression has a missing operand".to_owned())?;
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
        // This pop order deliberately follows SETools' historical renderer.
        let operand1 = stack
            .pop()
            .ok_or_else(|| "conditional expression has a missing operand".to_owned())?;
        let operand2 = stack
            .pop()
            .ok_or_else(|| "conditional expression has a missing operand".to_owned())?;
        let mut rendered = Vec::new();
        let parenthesized = previous_precedence <= precedence;
        if parenthesized {
            rendered.push("(".to_owned());
        }
        rendered.extend(operand1.tokens);
        rendered.push(operator.to_owned());
        rendered.extend(operand2.tokens);
        if parenthesized {
            rendered.push(")".to_owned());
        }
        stack.push(ConditionalOperand {
            tokens: rendered,
            compound: true,
        });
        previous_precedence = precedence;
    }

    if stack.len() != 1 {
        return Err("conditional expression has extra operands".to_owned());
    }
    Ok(stack.pop().expect("length checked").tokens.join(" "))
}

fn symbol_name(policy: &Policy, id: TypeOrAttributeId) -> Result<&str, String> {
    policy
        .type_symbol(id)
        .map(|symbol| symbol.name())
        .ok_or_else(|| "rule refers to a missing type symbol".to_owned())
}

pub(crate) fn render_rbac_rule(policy: &Policy, rule: &RbacRule) -> Result<String, String> {
    let source = policy
        .role(rule.source())
        .ok_or_else(|| "RBAC rule refers to a missing source role".to_owned())?
        .name();
    match rule.data() {
        RbacRuleData::Allow { target } => {
            let target = policy
                .role(*target)
                .ok_or_else(|| "RBAC rule refers to a missing target role".to_owned())?
                .name();
            Ok(format!("allow {source} {target};"))
        }
        RbacRuleData::RoleTransition {
            target,
            target_class,
            default,
        } => {
            let target = symbol_name(policy, *target)?;
            let target_class = policy
                .object_class(*target_class)
                .ok_or_else(|| "RBAC rule refers to a missing object class".to_owned())?
                .name();
            let default = policy
                .role(*default)
                .ok_or_else(|| "RBAC rule refers to a missing default role".to_owned())?
                .name();
            Ok(format!(
                "role_transition {source} {target}:{target_class} {default};"
            ))
        }
    }
}

fn render_mls_rule(policy: &Policy, rule: &MlsRule) -> Result<String, String> {
    let source = symbol_name(policy, rule.source())?;
    let target = symbol_name(policy, rule.target())?;
    let target_class = policy
        .object_class(rule.target_class())
        .ok_or_else(|| "MLS rule refers to a missing object class".to_owned())?
        .name();
    let default = format_mls_range(policy, rule.default())
        .ok_or_else(|| "MLS rule refers to a missing sensitivity or category".to_owned())?;
    Ok(format!(
        "range_transition {source} {target}:{target_class} {default};"
    ))
}

fn xpermission_ranges(values: &[u16]) -> Vec<String> {
    let mut ranges = Vec::new();
    let Some(&first) = values.first() else {
        return ranges;
    };
    let mut low = first;
    let mut high = first;
    for &value in &values[1..] {
        if value == high.saturating_add(1) {
            high = value;
        } else {
            ranges.push(format_xpermission_range(low, high));
            low = value;
            high = value;
        }
    }
    ranges.push(format_xpermission_range(low, high));
    ranges
}

fn format_xpermission_range(low: u16, high: u16) -> String {
    if low == high {
        format!("{low:#06x}")
    } else {
        format!("{low:#06x}-{high:#06x}")
    }
}

fn usage_error(message: &str) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{USAGE}sesearch: error: {message}");
    ExitCode::from(2)
}

fn analysis_error(message: &str) -> ExitCode {
    write_stdout(&format!("{message}\n")).then_failure()
}

fn write_stdout(value: &str) -> ExitCode {
    let mut stdout = io::stdout().lock();
    match stdout.write_all(value.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

trait ExitCodeExt {
    fn then_failure(self) -> ExitCode;
}

impl ExitCodeExt for ExitCode {
    fn then_failure(self) -> ExitCode {
        if self == ExitCode::SUCCESS {
            ExitCode::from(1)
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Options, ParseAction, SearchResult, format_xpermission_range, parse, parse_xpermissions,
        render_json,
    };
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_direct_allow_source() {
        let ParseAction::Run(options) =
            parse(args(&["--allow", "-s", "example_t", "-ds", "policy.35"]))
                .expect("arguments must parse")
        else {
            panic!("expected query action");
        };
        assert!(
            options
                .te_kinds
                .contains(&setools_policy::TeRuleKind::Allow)
        );
        assert_eq!(options.source.as_deref(), Some("example_t"));
        assert!(!options.source_indirect);
        assert_eq!(
            options.policy.as_deref(),
            Some(std::path::Path::new("policy.35"))
        );
    }

    #[test]
    fn parses_json_as_an_additive_output_mode() {
        let ParseAction::Run(options) =
            parse(args(&["--json", "--allow", "policy.35"])).expect("arguments must parse")
        else {
            panic!("expected query action");
        };
        assert!(options.json);
        assert!(
            options
                .te_kinds
                .contains(&setools_policy::TeRuleKind::Allow)
        );
    }

    #[test]
    fn json_query_records_active_criteria_and_escapes_results() {
        let mut options = Options::new();
        options.te_kinds.insert(setools_policy::TeRuleKind::Allow);
        options.source = Some("source.*".to_owned());
        options.source_indirect = false;
        options.source_regex = true;
        options.target = Some("target_t".to_owned());
        options.target_class = Some("file,dir".to_owned());
        options.target_class_regex = true;
        options.permissions = Some("read,write".to_owned());
        options.permissions_equal = true;
        options.permissions_subset = true;
        options.xpermissions = Some("0x0001-0x0002".to_owned());
        options.xpermissions_equal = true;
        options.default_type = Some("default.*".to_owned());
        options.default_regex = true;
        options.boolean = Some("enabled,debug".to_owned());
        options.boolean_equal = true;
        options.boolean_regex = true;
        let results = [SearchResult::new(
            "te",
            "allow",
            "allow source target:file \"quoted\";\n".to_owned(),
        )];

        let rendered = render_json(&options, std::path::Path::new("policy\"name"), &results);
        for expected in [
            "\"path\":\"policy\\\"name\"",
            "\"source\":{\"value\":\"source.*\",\"indirect\":false,\"regex\":true}",
            "\"target\":{\"value\":\"target_t\",\"indirect\":true,\"regex\":false}",
            "\"class\":{\"value\":\"file,dir\",\"regex\":true}",
            "\"permissions\":{\"value\":\"read,write\",\"equal\":true,\"subset\":true}",
            "\"xpermissions\":{\"value\":\"0x0001-0x0002\",\"equal\":true}",
            "\"default\":{\"value\":\"default.*\",\"regex\":true}",
            "\"boolean\":{\"value\":\"enabled,debug\",\"equal\":true,\"regex\":true}",
            "\"statement\":\"allow source target:file \\\"quoted\\\";\\n\"",
        ] {
            assert!(
                rendered.contains(expected),
                "missing JSON fragment: {expected}"
            );
        }
    }

    #[test]
    fn parses_xpermission_ranges() {
        assert_eq!(
            parse_xpermissions("0x0001,0x0010-0x0012").expect("range must parse"),
            BTreeSet::from([0x0001, 0x0010, 0x0011, 0x0012])
        );
        assert_eq!(format_xpermission_range(1, 3), "0x0001-0x0003");
    }
}
