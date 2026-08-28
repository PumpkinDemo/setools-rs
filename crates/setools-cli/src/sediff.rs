//! `sediff` argument parsing and compatibility rendering.

use crate::{
    json, policy_loader,
    runtime::{local_log_timestamp, use_default_sigpipe},
};
use setools_diff::{
    CompatibilityDifference, ComponentDifference, ModifiedAliases, ModifiedBoolean,
    ModifiedTypeAttribute, NameSetDifference, PolicyDiff, PropertyChange, PropertyValue,
};
use setools_policy::{ConstraintKind, HandleUnknown, Policy, TeRuleKind};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = include_str!("../assets/sediff-help.txt");

const USAGE: &str = r"usage: sediff [-h] [--version] [--stats] [-v] [--debug] [--common] [-c] [-t]
              [-a] [-r] [-u] [-b] [--sensitivity] [--category] [--level] [-A]
              [--allow] [--auditallow] [--dontaudit] [--allowxperm]
              [--auditallowxperm] [--dontauditxperm] [-T] [--type_change]
              [--type_member] [--role_allow] [--role_trans] [--range_trans]
              [--constrain] [--mlsconstrain] [--validatetrans]
              [--mlsvalidatetrans] [--ibendportcon] [--ibpkeycon]
              [--initialsid] [--fs_use] [--genfscon] [--netifcon] [--nodecon]
              [--portcon] [--default] [--property] [--polcap] [--typebounds]
              POLICY1 POLICY2
";

#[derive(Debug, Default)]
struct Options {
    policies: Vec<PathBuf>,
    json: bool,
    stats: bool,
    verbose: bool,
    debug: bool,
    property: bool,
    polcap: bool,
    boolean: bool,
    attribute: bool,
    category: bool,
    sensitivity: bool,
    common: bool,
    class: bool,
    type_: bool,
    role: bool,
    user: bool,
    level: bool,
    allow: bool,
    auditallow: bool,
    dontaudit: bool,
    allowxperm: bool,
    auditallowxperm: bool,
    dontauditxperm: bool,
    type_trans: bool,
    type_change: bool,
    type_member: bool,
    role_allow: bool,
    role_trans: bool,
    range_trans: bool,
    constrain: bool,
    mlsconstrain: bool,
    validatetrans: bool,
    mlsvalidatetrans: bool,
    ibendportcon: bool,
    ibpkeycon: bool,
    initialsid: bool,
    fs_use: bool,
    genfscon: bool,
    netifcon: bool,
    nodecon: bool,
    portcon: bool,
    default_: bool,
    typebounds: bool,
}

impl Options {
    fn has_component_selection(&self) -> bool {
        self.property
            || self.polcap
            || self.boolean
            || self.attribute
            || self.category
            || self.sensitivity
            || self.common
            || self.class
            || self.type_
            || self.role
            || self.user
            || self.level
            || self.allow
            || self.auditallow
            || self.dontaudit
            || self.allowxperm
            || self.auditallowxperm
            || self.dontauditxperm
            || self.type_trans
            || self.type_change
            || self.type_member
            || self.role_allow
            || self.role_trans
            || self.range_trans
            || self.constrain
            || self.mlsconstrain
            || self.validatetrans
            || self.mlsvalidatetrans
            || self.ibendportcon
            || self.ibpkeycon
            || self.initialsid
            || self.fs_use
            || self.genfscon
            || self.netifcon
            || self.nodecon
            || self.portcon
            || self.default_
            || self.typebounds
    }
}

enum ParseAction {
    Run(Options),
    Help,
    Version,
}

/// Runs `sediff` with already separated process arguments.
pub(crate) fn run(arguments: Vec<OsString>) -> ExitCode {
    let _ = use_default_sigpipe();
    let options = match parse(arguments) {
        Ok(ParseAction::Help) => return write_stdout(HELP),
        Ok(ParseAction::Version) => {
            return write_stdout(concat!(env!("CARGO_PKG_VERSION"), "\n"));
        }
        Ok(ParseAction::Run(options)) => options,
        Err(message) => return usage_error(&message),
    };

    let left_path = &options.policies[0];
    let right_path = &options.policies[1];
    let left = match load_policy(left_path, &options) {
        Ok(policy) => policy,
        Err(message) => return analysis_error(&message),
    };
    let right = match load_policy(right_path, &options) {
        Ok(policy) => policy,
        Err(message) => return analysis_error(&message),
    };

    log_message(
        &options,
        "INFO",
        "setools.diff.difference",
        &format!("Policy diff left policy set to {}", left_path.display()),
    );
    log_diff_resets(&options);
    log_message(
        &options,
        "INFO",
        "setools.diff.difference",
        &format!("Policy diff right policy set to {}", right_path.display()),
    );
    log_diff_resets(&options);

    let diff = PolicyDiff::new(&left, &right);
    let output = if options.json {
        render_selected_json(&diff, left_path, right_path, &options)
    } else {
        render_selected(&diff, left_path, right_path, &options)
    };
    write_stdout(&output)
}

#[derive(Debug)]
struct JsonModifiedItem {
    summary: String,
    details: Vec<String>,
}

#[derive(Debug)]
struct JsonDifference {
    component: &'static str,
    description: &'static str,
    added: Vec<String>,
    removed: Vec<String>,
    modified: Vec<JsonModifiedItem>,
}

impl JsonDifference {
    fn count(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }

    fn is_empty(&self) -> bool {
        self.count() == 0
    }
}

fn render_selected_json(
    diff: &PolicyDiff<'_>,
    left_path: &Path,
    right_path: &Path,
    options: &Options,
) -> String {
    let differences = collect_json_differences(diff, left_path, right_path, options);
    render_json(options, left_path, right_path, &differences)
}

fn collect_json_differences(
    diff: &PolicyDiff<'_>,
    left_path: &Path,
    right_path: &Path,
    options: &Options,
) -> Vec<JsonDifference> {
    let mut differences = Vec::new();
    let all = !options.has_component_selection();

    if all || options.property {
        let difference = json_property_difference(diff.properties());
        push_json_difference(&mut differences, all, options.property, difference);
    }
    if all || options.polcap {
        log_generation(options, "policy cap", left_path, right_path);
        let difference =
            json_name_set_difference("polcap", "Policy Capabilities", diff.policy_capabilities());
        push_json_difference(&mut differences, all, options.polcap, difference);
    }
    collect_json_compatibility(
        &mut differences,
        all,
        options.common,
        options,
        left_path,
        right_path,
        "common",
        "common",
        "Commons",
        || diff.commons(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.class,
        options,
        left_path,
        right_path,
        "class",
        "class",
        "Classes",
        || diff.classes(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.default_,
        options,
        left_path,
        right_path,
        "default_*",
        "default",
        "Defaults",
        || diff.defaults(),
    );
    if all || options.boolean {
        log_generation(options, "Boolean", left_path, right_path);
        let difference = json_boolean_difference(diff.booleans());
        push_json_difference(&mut differences, all, options.boolean, difference);
    }
    collect_json_compatibility(
        &mut differences,
        all,
        options.role,
        options,
        left_path,
        right_path,
        "role",
        "role",
        "Roles",
        || diff.roles(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.type_,
        options,
        left_path,
        right_path,
        "type",
        "type",
        "Types",
        || diff.types(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.typebounds,
        options,
        left_path,
        right_path,
        "typebounds",
        "typebounds",
        "Typebounds",
        || diff.typebounds(),
    );
    if all || options.attribute {
        log_generation(options, "type attribute", left_path, right_path);
        let difference = json_attribute_difference(diff.type_attributes());
        push_json_difference(&mut differences, all, options.attribute, difference);
    }
    collect_json_compatibility(
        &mut differences,
        all,
        options.user,
        options,
        left_path,
        right_path,
        "user",
        "user",
        "Users",
        || diff.users(),
    );
    if all || options.category {
        log_generation(options, "category", left_path, right_path);
        let difference = json_alias_difference("category", "Categories", diff.categories());
        push_json_difference(&mut differences, all, options.category, difference);
    }
    if all || options.sensitivity {
        log_generation(options, "sensitivity", left_path, right_path);
        let difference =
            json_alias_difference("sensitivity", "Sensitivities", diff.sensitivities());
        push_json_difference(&mut differences, all, options.sensitivity, difference);
    }
    collect_json_compatibility(
        &mut differences,
        all,
        options.level,
        options,
        left_path,
        right_path,
        "level decl",
        "level",
        "Levels",
        || diff.levels(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.allow,
        options,
        left_path,
        right_path,
        "allow",
        "allow",
        "Allow Rules",
        || diff.av_rules(TeRuleKind::Allow),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.allowxperm,
        options,
        left_path,
        right_path,
        "allowxperm",
        "allowxperm",
        "Allowxperm Rules",
        || diff.xperm_rules(TeRuleKind::AllowXperm),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.auditallow,
        options,
        left_path,
        right_path,
        "auditallow",
        "auditallow",
        "Auditallow Rules",
        || diff.av_rules(TeRuleKind::AuditAllow),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.auditallowxperm,
        options,
        left_path,
        right_path,
        "auditallowxperm",
        "auditallowxperm",
        "Auditallowxperm Rules",
        || diff.xperm_rules(TeRuleKind::AuditAllowXperm),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.dontaudit,
        options,
        left_path,
        right_path,
        "dontaudit",
        "dontaudit",
        "Dontaudit Rules",
        || diff.av_rules(TeRuleKind::DontAudit),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.dontauditxperm,
        options,
        left_path,
        right_path,
        "dontauditxperm",
        "dontauditxperm",
        "Dontauditxperm Rules",
        || diff.xperm_rules(TeRuleKind::DontAuditXperm),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.type_trans,
        options,
        left_path,
        right_path,
        "type_transition",
        "type_transition",
        "Type_transition Rules",
        || diff.type_rules(TeRuleKind::TypeTransition),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.type_change,
        options,
        left_path,
        right_path,
        "type_change",
        "type_change",
        "Type_change Rules",
        || diff.type_rules(TeRuleKind::TypeChange),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.type_member,
        options,
        left_path,
        right_path,
        "type_member",
        "type_member",
        "Type_member Rules",
        || diff.type_rules(TeRuleKind::TypeMember),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.role_allow,
        options,
        left_path,
        right_path,
        "role allow",
        "role_allow",
        "Role allow Rules",
        || diff.role_allows(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.role_trans,
        options,
        left_path,
        right_path,
        "role_transition",
        "role_transition",
        "Role_transition Rules",
        || diff.role_transitions(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.range_trans,
        options,
        left_path,
        right_path,
        "range_transition",
        "range_transition",
        "Range_transition Rules",
        || diff.range_transitions(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.constrain,
        options,
        left_path,
        right_path,
        "constraint",
        "constrain",
        "Constraints",
        || diff.constraints(ConstraintKind::Constrain),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.mlsconstrain,
        options,
        left_path,
        right_path,
        "MLS constraint",
        "mlsconstrain",
        "MLS Constraints",
        || diff.constraints(ConstraintKind::MlsConstrain),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.validatetrans,
        options,
        left_path,
        right_path,
        "validatetrans",
        "validatetrans",
        "Validatetrans",
        || diff.constraints(ConstraintKind::ValidateTransition),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.mlsvalidatetrans,
        options,
        left_path,
        right_path,
        "mlsvalidatetrans",
        "mlsvalidatetrans",
        "MLS Validatetrans",
        || diff.constraints(ConstraintKind::MlsValidateTransition),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.initialsid,
        options,
        left_path,
        right_path,
        "initial SID",
        "initialsid",
        "Initial SIDs",
        || diff.initial_sids(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.ibendportcon,
        options,
        left_path,
        right_path,
        "ibendportcon",
        "ibendportcon",
        "Ibendportcons",
        || diff.ibendportcons(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.ibpkeycon,
        options,
        left_path,
        right_path,
        "ibpkeycon",
        "ibpkeycon",
        "Ibpkeycons",
        || diff.ibpkeycons(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.fs_use,
        options,
        left_path,
        right_path,
        "fs_use_*",
        "fs_use",
        "Fs_use",
        || diff.fs_uses(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.genfscon,
        options,
        left_path,
        right_path,
        "genfscon",
        "genfscon",
        "Genfscons",
        || diff.genfscons(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.netifcon,
        options,
        left_path,
        right_path,
        "netifcon",
        "netifcon",
        "Netifcons",
        || diff.netifcons(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.nodecon,
        options,
        left_path,
        right_path,
        "nodecon",
        "nodecon",
        "Nodecons",
        || diff.nodecons(),
    );
    collect_json_compatibility(
        &mut differences,
        all,
        options.portcon,
        options,
        left_path,
        right_path,
        "portcon",
        "portcon",
        "Portcons",
        || diff.portcons(),
    );

    differences
}

fn push_json_difference(
    differences: &mut Vec<JsonDifference>,
    all: bool,
    selected: bool,
    difference: JsonDifference,
) {
    if selected || (all && !difference.is_empty()) {
        differences.push(difference);
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_json_compatibility<Build>(
    differences: &mut Vec<JsonDifference>,
    all: bool,
    selected: bool,
    options: &Options,
    left_path: &Path,
    right_path: &Path,
    generation_name: &str,
    component: &'static str,
    description: &'static str,
    build: Build,
) where
    Build: FnOnce() -> CompatibilityDifference,
{
    if !all && !selected {
        return;
    }
    log_generation(options, generation_name, left_path, right_path);
    log_av_expansion(options, generation_name, left_path, right_path);
    let difference = json_compatibility_difference(component, description, build());
    push_json_difference(differences, all, selected, difference);
}

fn json_property_difference(changes: Vec<PropertyChange>) -> JsonDifference {
    JsonDifference {
        component: "property",
        description: "Policy Properties",
        added: Vec::new(),
        removed: Vec::new(),
        modified: changes
            .into_iter()
            .map(|change| JsonModifiedItem {
                summary: change.property().to_owned(),
                details: vec![
                    format!("+{}", render_property_value(change.added())),
                    format!("-{}", render_property_value(change.removed())),
                ],
            })
            .collect(),
    }
}

fn json_name_set_difference(
    component: &'static str,
    description: &'static str,
    difference: NameSetDifference,
) -> JsonDifference {
    JsonDifference {
        component,
        description,
        added: difference.added().to_vec(),
        removed: difference.removed().to_vec(),
        modified: Vec::new(),
    }
}

fn json_compatibility_difference(
    component: &'static str,
    description: &'static str,
    difference: CompatibilityDifference,
) -> JsonDifference {
    JsonDifference {
        component,
        description,
        added: difference.added().to_vec(),
        removed: difference.removed().to_vec(),
        modified: difference
            .modified()
            .iter()
            .map(|item| JsonModifiedItem {
                summary: item.summary().to_owned(),
                details: item
                    .detail_lines()
                    .iter()
                    .map(|line| line.trim_start().to_owned())
                    .collect(),
            })
            .collect(),
    }
}

fn json_boolean_difference(difference: ComponentDifference<ModifiedBoolean>) -> JsonDifference {
    JsonDifference {
        component: "boolean",
        description: "Booleans",
        added: difference.added().to_vec(),
        removed: difference.removed().to_vec(),
        modified: difference
            .modified()
            .iter()
            .map(|item| JsonModifiedItem {
                summary: format!("{} (Modified default state)", item.name()),
                details: vec![
                    format!("+ {}", python_boolean(item.added_state())),
                    format!("- {}", python_boolean(item.removed_state())),
                ],
            })
            .collect(),
    }
}

fn json_attribute_difference(
    difference: ComponentDifference<ModifiedTypeAttribute>,
) -> JsonDifference {
    JsonDifference {
        component: "attribute",
        description: "Type Attributes",
        added: difference.added().to_vec(),
        removed: difference.removed().to_vec(),
        modified: difference
            .modified()
            .iter()
            .map(|item| {
                let mut changes = Vec::new();
                if !item.added_types().is_empty() {
                    changes.push(format!("{} Added types", item.added_types().len()));
                }
                if !item.removed_types().is_empty() {
                    changes.push(format!("{} Removed types", item.removed_types().len()));
                }
                JsonModifiedItem {
                    summary: format!("{} ({})", item.name(), changes.join(", ")),
                    details: item
                        .added_types()
                        .iter()
                        .map(|name| format!("+ {name}"))
                        .chain(item.removed_types().iter().map(|name| format!("- {name}")))
                        .collect(),
                }
            })
            .collect(),
    }
}

fn json_alias_difference(
    component: &'static str,
    description: &'static str,
    difference: ComponentDifference<ModifiedAliases>,
) -> JsonDifference {
    JsonDifference {
        component,
        description,
        added: difference.added().to_vec(),
        removed: difference.removed().to_vec(),
        modified: difference
            .modified()
            .iter()
            .map(|item| {
                let mut changes = Vec::new();
                if !item.added_aliases().is_empty() {
                    changes.push(format!("{} Added Aliases", item.added_aliases().len()));
                }
                if !item.removed_aliases().is_empty() {
                    changes.push(format!("{} Removed Aliases", item.removed_aliases().len()));
                }
                JsonModifiedItem {
                    summary: format!("{} ({})", item.name(), changes.join(", ")),
                    details: std::iter::once("Aliases:".to_owned())
                        .chain(
                            item.added_aliases()
                                .iter()
                                .map(|alias| format!("+ {alias}")),
                        )
                        .chain(
                            item.removed_aliases()
                                .iter()
                                .map(|alias| format!("- {alias}")),
                        )
                        .collect(),
                }
            })
            .collect(),
    }
}

fn render_json(
    options: &Options,
    left_path: &Path,
    right_path: &Path,
    differences: &[JsonDifference],
) -> String {
    let mut output = String::new();
    output.push_str(
        "{\"schema\":\"setools-rs.sediff\",\"schema_version\":1,\"tool\":{\"name\":\"sediff\",\"version\":",
    );
    json::push_string(&mut output, env!("CARGO_PKG_VERSION"));
    output.push_str("},\"policy\":{\"left_path\":");
    json::push_string(&mut output, &left_path.to_string_lossy());
    output.push_str(",\"right_path\":");
    json::push_string(&mut output, &right_path.to_string_lossy());
    output.push_str("},\"query\":{\"all\":");
    output.push_str(json_boolean(!options.has_component_selection()));
    output.push_str(",\"stats\":");
    output.push_str(json_boolean(options.stats));
    output.push_str(",\"components\":[");
    push_json_query_components(&mut output, options);
    output.push_str("]},\"result_count\":");
    output.push_str(
        &differences
            .iter()
            .map(JsonDifference::count)
            .sum::<usize>()
            .to_string(),
    );
    output.push_str(",\"results\":[");
    for (index, difference) in differences.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"component\":");
        json::push_string(&mut output, difference.component);
        output.push_str(",\"description\":");
        json::push_string(&mut output, difference.description);
        output.push_str(",\"counts\":{\"added\":");
        output.push_str(&difference.added.len().to_string());
        output.push_str(",\"removed\":");
        output.push_str(&difference.removed.len().to_string());
        output.push_str(",\"modified\":");
        output.push_str(&difference.modified.len().to_string());
        output.push_str("},\"added\":[");
        if !options.stats {
            push_json_strings(&mut output, &difference.added);
        }
        output.push_str("],\"removed\":[");
        if !options.stats {
            push_json_strings(&mut output, &difference.removed);
        }
        output.push_str("],\"modified\":[");
        if !options.stats {
            for (modified_index, modified) in difference.modified.iter().enumerate() {
                if modified_index > 0 {
                    output.push(',');
                }
                output.push_str("{\"summary\":");
                json::push_string(&mut output, &modified.summary);
                output.push_str(",\"details\":[");
                push_json_strings(&mut output, &modified.details);
                output.push_str("]}");
            }
        }
        output.push_str("]}");
    }
    output.push_str("]}\n");
    output
}

fn push_json_query_components(output: &mut String, options: &Options) {
    let mut first = true;
    for (component, selected) in [
        ("property", options.property),
        ("polcap", options.polcap),
        ("common", options.common),
        ("class", options.class),
        ("default", options.default_),
        ("boolean", options.boolean),
        ("role", options.role),
        ("type", options.type_),
        ("typebounds", options.typebounds),
        ("attribute", options.attribute),
        ("user", options.user),
        ("category", options.category),
        ("sensitivity", options.sensitivity),
        ("level", options.level),
        ("allow", options.allow),
        ("allowxperm", options.allowxperm),
        ("auditallow", options.auditallow),
        ("auditallowxperm", options.auditallowxperm),
        ("dontaudit", options.dontaudit),
        ("dontauditxperm", options.dontauditxperm),
        ("type_transition", options.type_trans),
        ("type_change", options.type_change),
        ("type_member", options.type_member),
        ("role_allow", options.role_allow),
        ("role_transition", options.role_trans),
        ("range_transition", options.range_trans),
        ("constrain", options.constrain),
        ("mlsconstrain", options.mlsconstrain),
        ("validatetrans", options.validatetrans),
        ("mlsvalidatetrans", options.mlsvalidatetrans),
        ("initialsid", options.initialsid),
        ("ibendportcon", options.ibendportcon),
        ("ibpkeycon", options.ibpkeycon),
        ("fs_use", options.fs_use),
        ("genfscon", options.genfscon),
        ("netifcon", options.netifcon),
        ("nodecon", options.nodecon),
        ("portcon", options.portcon),
    ] {
        if selected {
            if !first {
                output.push(',');
            }
            first = false;
            json::push_string(output, component);
        }
    }
}

fn push_json_strings(output: &mut String, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        json::push_string(output, value);
    }
}

const fn json_boolean(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn render_selected(
    diff: &PolicyDiff<'_>,
    left_path: &Path,
    right_path: &Path,
    options: &Options,
) -> String {
    let mut output = String::new();
    let all = !options.has_component_selection();
    if all || options.property {
        let changes = diff.properties();
        if options.property || !changes.is_empty() {
            render_property_changes(&mut output, changes, options.stats);
        }
    }
    if all || options.polcap {
        log_generation(options, "policy cap", left_path, right_path);
        let difference = diff.policy_capabilities();
        if options.polcap || !difference.is_empty() {
            render_name_set(
                &mut output,
                "Policy Capabilities",
                "Policy Capabilities",
                &difference,
                options.stats,
            );
        }
    }
    compat_section(
        &mut output,
        all,
        options.common,
        options,
        left_path,
        right_path,
        "common",
        "Commons",
        "Commons",
        || diff.commons(),
    );
    compat_section(
        &mut output,
        all,
        options.class,
        options,
        left_path,
        right_path,
        "class",
        "Classes",
        "Classes",
        || diff.classes(),
    );
    compat_section(
        &mut output,
        all,
        options.default_,
        options,
        left_path,
        right_path,
        "default_*",
        "Defaults",
        "Defaults",
        || diff.defaults(),
    );
    if all || options.boolean {
        log_generation(options, "Boolean", left_path, right_path);
        let difference = diff.booleans();
        if options.boolean || !difference.is_empty() {
            render_boolean_difference(&mut output, &difference, options.stats);
        }
    }
    compat_section(
        &mut output,
        all,
        options.role,
        options,
        left_path,
        right_path,
        "role",
        "Roles",
        "Roles",
        || diff.roles(),
    );
    compat_section(
        &mut output,
        all,
        options.type_,
        options,
        left_path,
        right_path,
        "type",
        "Types",
        "Types",
        || diff.types(),
    );
    compat_section(
        &mut output,
        all,
        options.typebounds,
        options,
        left_path,
        right_path,
        "typebounds",
        "Typebounds",
        "Typebounds",
        || diff.typebounds(),
    );
    if all || options.attribute {
        log_generation(options, "type attribute", left_path, right_path);
        let difference = diff.type_attributes();
        if options.attribute || !difference.is_empty() {
            render_attribute_difference(&mut output, &difference, options.stats);
        }
    }
    compat_section(
        &mut output,
        all,
        options.user,
        options,
        left_path,
        right_path,
        "user",
        "Users",
        "Users",
        || diff.users(),
    );
    if all || options.category {
        log_generation(options, "category", left_path, right_path);
        let difference = diff.categories();
        if options.category || !difference.is_empty() {
            render_alias_component(
                &mut output,
                "Categories",
                "Categories",
                &difference,
                options.stats,
            );
        }
    }
    if all || options.sensitivity {
        log_generation(options, "sensitivity", left_path, right_path);
        let difference = diff.sensitivities();
        if options.sensitivity || !difference.is_empty() {
            render_alias_component(
                &mut output,
                "Sensitivities",
                "Sensitivities",
                &difference,
                options.stats,
            );
        }
    }
    compat_section(
        &mut output,
        all,
        options.level,
        options,
        left_path,
        right_path,
        "level decl",
        "Levels",
        "Levels",
        || diff.levels(),
    );
    compat_section(
        &mut output,
        all,
        options.allow,
        options,
        left_path,
        right_path,
        "allow",
        "Allow Rules",
        "Allow Rules",
        || diff.av_rules(TeRuleKind::Allow),
    );
    compat_section(
        &mut output,
        all,
        options.allowxperm,
        options,
        left_path,
        right_path,
        "allowxperm",
        "Allowxperm Rules",
        "Allowxperm Rules",
        || diff.xperm_rules(TeRuleKind::AllowXperm),
    );
    compat_section(
        &mut output,
        all,
        options.auditallow,
        options,
        left_path,
        right_path,
        "auditallow",
        "Auditallow Rules",
        "Auditallow Rules",
        || diff.av_rules(TeRuleKind::AuditAllow),
    );
    compat_section(
        &mut output,
        all,
        options.auditallowxperm,
        options,
        left_path,
        right_path,
        "auditallowxperm",
        "Auditallowxperm Rules",
        "Auditallowxperm Rules",
        || diff.xperm_rules(TeRuleKind::AuditAllowXperm),
    );
    compat_section(
        &mut output,
        all,
        options.dontaudit,
        options,
        left_path,
        right_path,
        "dontaudit",
        "Dontaudit Rules",
        "Dontaudit Rules",
        || diff.av_rules(TeRuleKind::DontAudit),
    );
    compat_section(
        &mut output,
        all,
        options.dontauditxperm,
        options,
        left_path,
        right_path,
        "dontauditxperm",
        "Dontauditxperm Rules",
        "Dontauditxperm Rules",
        || diff.xperm_rules(TeRuleKind::DontAuditXperm),
    );
    compat_section(
        &mut output,
        all,
        options.type_trans,
        options,
        left_path,
        right_path,
        "type_transition",
        "Type_transition Rules",
        "Type_transition Rules",
        || diff.type_rules(TeRuleKind::TypeTransition),
    );
    compat_section(
        &mut output,
        all,
        options.type_change,
        options,
        left_path,
        right_path,
        "type_change",
        "Type_change Rules",
        "Type_change Rules",
        || diff.type_rules(TeRuleKind::TypeChange),
    );
    compat_section(
        &mut output,
        all,
        options.type_member,
        options,
        left_path,
        right_path,
        "type_member",
        "Type_member Rules",
        "Type_member Rules",
        || diff.type_rules(TeRuleKind::TypeMember),
    );
    compat_section(
        &mut output,
        all,
        options.role_allow,
        options,
        left_path,
        right_path,
        "role allow",
        "Role allow Rules",
        "Role Allow Rules",
        || diff.role_allows(),
    );
    compat_section(
        &mut output,
        all,
        options.role_trans,
        options,
        left_path,
        right_path,
        "role_transition",
        "Role_transition Rules",
        "Role_transition Rules",
        || diff.role_transitions(),
    );
    compat_section(
        &mut output,
        all,
        options.range_trans,
        options,
        left_path,
        right_path,
        "range_transition",
        "Range_transition Rules",
        "Range_transition Rules",
        || diff.range_transitions(),
    );
    compat_section(
        &mut output,
        all,
        options.constrain,
        options,
        left_path,
        right_path,
        "constraint",
        "Constraints",
        "Constraints",
        || diff.constraints(ConstraintKind::Constrain),
    );
    compat_section(
        &mut output,
        all,
        options.mlsconstrain,
        options,
        left_path,
        right_path,
        "MLS constraint",
        "MLS Constraints",
        "MLS Constraints",
        || diff.constraints(ConstraintKind::MlsConstrain),
    );
    compat_section(
        &mut output,
        all,
        options.validatetrans,
        options,
        left_path,
        right_path,
        "validatetrans",
        "Validatetrans",
        "Validatetrans",
        || diff.constraints(ConstraintKind::ValidateTransition),
    );
    compat_section(
        &mut output,
        all,
        options.mlsvalidatetrans,
        options,
        left_path,
        right_path,
        "mlsvalidatetrans",
        "MLS Validatetrans",
        "MLS Validatetrans",
        || diff.constraints(ConstraintKind::MlsValidateTransition),
    );
    compat_section(
        &mut output,
        all,
        options.initialsid,
        options,
        left_path,
        right_path,
        "initial SID",
        "Initial SIDs",
        "Initial SIDs",
        || diff.initial_sids(),
    );
    compat_section(
        &mut output,
        all,
        options.ibendportcon,
        options,
        left_path,
        right_path,
        "ibendportcon",
        "Ibendportcons",
        "Ibendportcons",
        || diff.ibendportcons(),
    );
    compat_section(
        &mut output,
        all,
        options.ibpkeycon,
        options,
        left_path,
        right_path,
        "ibpkeycon",
        "Ibpkeycons",
        "Ibpkeycons",
        || diff.ibpkeycons(),
    );
    compat_section(
        &mut output,
        all,
        options.fs_use,
        options,
        left_path,
        right_path,
        "fs_use_*",
        "Fs_use",
        "Fs_use",
        || diff.fs_uses(),
    );
    compat_section(
        &mut output,
        all,
        options.genfscon,
        options,
        left_path,
        right_path,
        "genfscon",
        "Genfscons",
        "Genfscons",
        || diff.genfscons(),
    );
    compat_section(
        &mut output,
        all,
        options.netifcon,
        options,
        left_path,
        right_path,
        "netifcon",
        "Netifcons",
        "Netifcons",
        || diff.netifcons(),
    );
    compat_section(
        &mut output,
        all,
        options.nodecon,
        options,
        left_path,
        right_path,
        "nodecon",
        "Nodecons",
        "Nodecons",
        || diff.nodecons(),
    );
    compat_section(
        &mut output,
        all,
        options.portcon,
        options,
        left_path,
        right_path,
        "portcon",
        "Portcons",
        "Portcons",
        || diff.portcons(),
    );
    output
}

#[allow(clippy::too_many_arguments)]
fn compat_section<Build>(
    output: &mut String,
    all: bool,
    selected: bool,
    options: &Options,
    left_path: &Path,
    right_path: &Path,
    generation_name: &str,
    heading: &str,
    item_name: &str,
    build: Build,
) where
    Build: FnOnce() -> CompatibilityDifference,
{
    if !all && !selected {
        return;
    }
    log_generation(options, generation_name, left_path, right_path);
    log_av_expansion(options, generation_name, left_path, right_path);
    let difference = build();
    if selected || !difference.is_empty() {
        render_compatibility_difference(output, heading, item_name, &difference, options.stats);
    }
}

fn render_compatibility_difference(
    output: &mut String,
    heading: &str,
    item_name: &str,
    difference: &CompatibilityDifference,
    stats: bool,
) {
    let set_only = matches!(
        heading,
        "Role allow Rules"
            | "Constraints"
            | "MLS Constraints"
            | "Validatetrans"
            | "MLS Validatetrans"
    );
    if set_only {
        let _ = writeln!(
            output,
            "{heading} ({} Added, {} Removed)",
            difference.added().len(),
            difference.removed().len()
        );
    } else {
        let _ = writeln!(
            output,
            "{heading} ({} Added, {} Removed, {} Modified)",
            difference.added().len(),
            difference.removed().len(),
            difference.modified().len()
        );
    }
    if !stats && !difference.added().is_empty() {
        let _ = writeln!(output, "   Added {item_name}: {}", difference.added().len());
        for statement in difference.added() {
            let _ = writeln!(output, "      + {statement}");
        }
    }
    if !stats && !difference.removed().is_empty() {
        let _ = writeln!(
            output,
            "   Removed {item_name}: {}",
            difference.removed().len()
        );
        for statement in difference.removed() {
            let _ = writeln!(output, "      - {statement}");
        }
    }
    if !stats && !difference.modified().is_empty() {
        let _ = writeln!(
            output,
            "   Modified {item_name}: {}",
            difference.modified().len()
        );
        for item in difference.modified() {
            let _ = writeln!(output, "      * {}", item.summary());
            for line in item.detail_lines() {
                let _ = writeln!(output, "{line}");
            }
        }
    }
    output.push('\n');
}

fn render_property_changes(
    output: &mut String,
    changes: Vec<setools_diff::PropertyChange>,
    stats: bool,
) {
    let _ = writeln!(output, "Policy Properties ({} Modified)", changes.len());
    if !stats {
        for change in changes {
            let _ = writeln!(
                output,
                "      * {} +{} -{}",
                change.property(),
                render_property_value(change.added()),
                render_property_value(change.removed())
            );
        }
    }
    output.push('\n');
}

fn render_property_value(value: PropertyValue) -> String {
    match value {
        PropertyValue::HandleUnknown(value) => match value {
            HandleUnknown::Deny => "deny".to_owned(),
            HandleUnknown::Reject => "reject".to_owned(),
            HandleUnknown::Allow => "allow".to_owned(),
        },
        PropertyValue::Boolean(value) => python_boolean(value).to_owned(),
        PropertyValue::Version(value) => value.to_string(),
    }
}

fn render_name_set(
    output: &mut String,
    heading: &str,
    item_name: &str,
    difference: &NameSetDifference,
    stats: bool,
) {
    let _ = writeln!(
        output,
        "{heading} ({} Added, {} Removed)",
        difference.added().len(),
        difference.removed().len()
    );
    if !stats && !difference.added().is_empty() {
        let _ = writeln!(output, "   Added {item_name}: {}", difference.added().len());
        for name in difference.added() {
            let _ = writeln!(output, "      + {name}");
        }
    }
    if !stats && !difference.removed().is_empty() {
        let _ = writeln!(
            output,
            "   Removed {item_name}: {}",
            difference.removed().len()
        );
        for name in difference.removed() {
            let _ = writeln!(output, "      - {name}");
        }
    }
    output.push('\n');
}

fn render_boolean_difference(
    output: &mut String,
    difference: &ComponentDifference<setools_diff::ModifiedBoolean>,
    stats: bool,
) {
    render_component_heading(output, "Booleans", difference);
    if !stats {
        render_added_removed(output, "Booleans", difference);
        if !difference.modified().is_empty() {
            let _ = writeln!(
                output,
                "   Modified Booleans: {}",
                difference.modified().len()
            );
            for modified in difference.modified() {
                let _ = writeln!(
                    output,
                    "      * {} (Modified default state)",
                    modified.name()
                );
                let _ = writeln!(
                    output,
                    "          + {}",
                    python_boolean(modified.added_state())
                );
                let _ = writeln!(
                    output,
                    "          - {}",
                    python_boolean(modified.removed_state())
                );
            }
        }
    }
    output.push('\n');
}

fn render_attribute_difference(
    output: &mut String,
    difference: &ComponentDifference<setools_diff::ModifiedTypeAttribute>,
    stats: bool,
) {
    render_component_heading(output, "Type Attributes", difference);
    if !stats {
        render_added_removed(output, "Type Attributes", difference);
        if !difference.modified().is_empty() {
            let _ = writeln!(
                output,
                "   Modified Type Attributes: {}",
                difference.modified().len()
            );
            for modified in difference.modified() {
                let mut changes = Vec::new();
                if !modified.added_types().is_empty() {
                    changes.push(format!("{} Added types", modified.added_types().len()));
                }
                if !modified.removed_types().is_empty() {
                    changes.push(format!("{} Removed types", modified.removed_types().len()));
                }
                let _ = writeln!(
                    output,
                    "      * {} ({})",
                    modified.name(),
                    changes.join(", ")
                );
                for name in modified.added_types() {
                    let _ = writeln!(output, "          + {name}");
                }
                for name in modified.removed_types() {
                    let _ = writeln!(output, "          - {name}");
                }
            }
        }
    }
    output.push('\n');
}

fn render_alias_component(
    output: &mut String,
    heading: &str,
    item_name: &str,
    difference: &ComponentDifference<ModifiedAliases>,
    stats: bool,
) {
    render_component_heading(output, heading, difference);
    if !stats {
        render_added_removed(output, item_name, difference);
        if !difference.modified().is_empty() {
            let _ = writeln!(
                output,
                "   Modified {item_name}: {}",
                difference.modified().len()
            );
            for modified in difference.modified() {
                let mut changes = Vec::new();
                if !modified.added_aliases().is_empty() {
                    changes.push(format!("{} Added Aliases", modified.added_aliases().len()));
                }
                if !modified.removed_aliases().is_empty() {
                    changes.push(format!(
                        "{} Removed Aliases",
                        modified.removed_aliases().len()
                    ));
                }
                let _ = writeln!(
                    output,
                    "      * {} ({})",
                    modified.name(),
                    changes.join(", ")
                );
                output.push_str("          Aliases:\n");
                for alias in modified.added_aliases() {
                    let _ = writeln!(output, "          + {alias}");
                }
                for alias in modified.removed_aliases() {
                    let _ = writeln!(output, "          - {alias}");
                }
            }
        }
    }
    output.push('\n');
}

fn render_component_heading<Modified>(
    output: &mut String,
    heading: &str,
    difference: &ComponentDifference<Modified>,
) {
    let _ = writeln!(
        output,
        "{heading} ({} Added, {} Removed, {} Modified)",
        difference.added().len(),
        difference.removed().len(),
        difference.modified().len()
    );
}

fn render_added_removed<Modified>(
    output: &mut String,
    item_name: &str,
    difference: &ComponentDifference<Modified>,
) {
    if !difference.added().is_empty() {
        let _ = writeln!(output, "   Added {item_name}: {}", difference.added().len());
        for name in difference.added() {
            let _ = writeln!(output, "      + {name}");
        }
    }
    if !difference.removed().is_empty() {
        let _ = writeln!(
            output,
            "   Removed {item_name}: {}",
            difference.removed().len()
        );
        for name in difference.removed() {
            let _ = writeln!(output, "      - {name}");
        }
    }
}

const fn python_boolean(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

fn load_policy(path: &Path, options: &Options) -> Result<Policy, String> {
    log_message(
        options,
        "INFO",
        "setools.policyrep",
        &format!("Opening SELinux policy \"{}\"", path.display()),
    );
    match policy_loader::load(path) {
        Ok(policy) => {
            log_policy_load_debug(options, &policy);
            log_message(
                options,
                "INFO",
                "setools.policyrep",
                &format!("Successfully opened SELinux policy \"{}\"", path.display()),
            );
            Ok(policy)
        }
        Err(error) => Err(policy_loader::format_error(path, &error)),
    }
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

fn log_diff_resets(options: &Options) {
    const RESETS: &[&str] = &[
        "Resetting Boolean differences",
        "Resetting all *bounds differences",
        "Resetting category differences",
        "Resetting common differences",
        "Resetting all constraints differences",
        "Resetting default_* differences",
        "Resetting fs_use_* rule differences",
        "Resetting genfscon rule differences",
        "Resetting ibendportcon differences",
        "Resetting ibpkeycon differences",
        "Resetting initialsid differences",
        "Resetting sensitivity differences",
        "Resetting MLS rule differences",
        "Resetting netifcon differences",
        "Resetting nodecon differences",
        "Resetting object class differences",
        "Resetting policy capability differences",
        "Resetting portcon differences",
        "Resetting property differences",
        "Resetting RBAC rule differences",
        "Resetting role differences",
        "Resetting sensitivity differences",
        "Resetting TE rule differences",
        "Resetting type attribute differences",
        "Resetting type differences",
        "Resetting user differences",
    ];
    for message in RESETS {
        log_message(options, "DEBUG", "setools.diff.difference", message);
    }
}

fn log_generation(options: &Options, component: &str, left: &Path, right: &Path) {
    log_message(
        options,
        "INFO",
        "setools.diff.difference",
        &format!(
            "Generating {component} differences from {} to {}",
            left.display(),
            right.display()
        ),
    );
}

fn log_av_expansion(options: &Options, component: &str, left: &Path, right: &Path) {
    if !matches!(component, "allow" | "auditallow" | "dontaudit") {
        return;
    }
    log_message(
        options,
        "INFO",
        "setools.diff.terules",
        &format!("Expanding AV rules from {}.", left.display()),
    );
    log_message(
        options,
        "INFO",
        "setools.diff.terules",
        &format!("Expanding AV rules from {}.", right.display()),
    );
    log_message(
        options,
        "INFO",
        "setools.diff.terules",
        "Removing redundant AV rules.",
    );
    log_message(
        options,
        "INFO",
        "setools.diff.terules",
        "Generating AV rule diff.",
    );
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

fn parse(arguments: Vec<OsString>) -> Result<ParseAction, String> {
    let mut options = Options::default();
    let mut positional_only = false;
    for argument in arguments {
        let value = argument
            .to_str()
            .ok_or_else(|| "command-line arguments must be valid UTF-8".to_owned())?;
        if !positional_only {
            match value {
                "-h" | "--help" => return Ok(ParseAction::Help),
                "--version" => return Ok(ParseAction::Version),
                "--" => {
                    positional_only = true;
                    continue;
                }
                "--stats" => options.stats = true,
                "--json" => options.json = true,
                "-v" | "--verbose" => options.verbose = true,
                "--debug" => options.debug = true,
                "--property" => options.property = true,
                "--polcap" => options.polcap = true,
                "-b" | "--bool" => options.boolean = true,
                "-a" | "--attribute" => options.attribute = true,
                "--category" => options.category = true,
                "--sensitivity" => options.sensitivity = true,
                "--common" => options.common = true,
                "-c" | "--class" => options.class = true,
                "-t" | "--type" => options.type_ = true,
                "-r" | "--role" => options.role = true,
                "-u" | "--user" => options.user = true,
                "--level" => options.level = true,
                "-A" => {
                    options.allow = true;
                    options.allowxperm = true;
                }
                "--allow" => options.allow = true,
                "--auditallow" => options.auditallow = true,
                "--dontaudit" => options.dontaudit = true,
                "--allowxperm" => options.allowxperm = true,
                "--auditallowxperm" => options.auditallowxperm = true,
                "--dontauditxperm" => options.dontauditxperm = true,
                "-T" | "--type_trans" => options.type_trans = true,
                "--type_change" => options.type_change = true,
                "--type_member" => options.type_member = true,
                "--role_allow" => options.role_allow = true,
                "--role_trans" => options.role_trans = true,
                "--range_trans" => options.range_trans = true,
                "--constrain" => options.constrain = true,
                "--mlsconstrain" => options.mlsconstrain = true,
                "--validatetrans" => options.validatetrans = true,
                "--mlsvalidatetrans" => options.mlsvalidatetrans = true,
                "--ibendportcon" => options.ibendportcon = true,
                "--ibpkeycon" => options.ibpkeycon = true,
                "--initialsid" => options.initialsid = true,
                "--fs_use" => options.fs_use = true,
                "--genfscon" => options.genfscon = true,
                "--netifcon" => options.netifcon = true,
                "--nodecon" => options.nodecon = true,
                "--portcon" => options.portcon = true,
                "--default" => options.default_ = true,
                "--typebounds" => options.typebounds = true,
                _ if value.starts_with('-') => {
                    return Err(format!("unrecognized arguments: {value}"));
                }
                _ => options.policies.push(PathBuf::from(argument)),
            }
        } else {
            options.policies.push(PathBuf::from(argument));
        }
    }

    match options.policies.len() {
        0 => Err("the following arguments are required: POLICY1, POLICY2".to_owned()),
        1 => Err("the following arguments are required: POLICY2".to_owned()),
        2 => Ok(ParseAction::Run(options)),
        _ => Err(format!(
            "unrecognized arguments: {}",
            options.policies[2..]
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )),
    }
}

fn usage_error(message: &str) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{USAGE}sediff: error: {message}");
    ExitCode::from(2)
}

fn analysis_error(message: &str) -> ExitCode {
    let status = write_stdout(&format!("{message}\n"));
    if status == ExitCode::SUCCESS {
        ExitCode::from(1)
    } else {
        status
    }
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

#[cfg(test)]
mod tests {
    use super::{ParseAction, parse};
    use std::ffi::OsString;

    #[test]
    fn parses_implemented_component_selection() {
        let action = parse(
            ["--stats", "--bool", "--attribute", "left", "right"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        )
        .expect("arguments should parse");
        let ParseAction::Run(options) = action else {
            panic!("expected runnable options");
        };
        assert!(options.stats);
        assert!(!options.json);
        assert!(options.boolean);
        assert!(options.attribute);
        assert_eq!(options.policies.len(), 2);
    }

    #[test]
    fn parses_hidden_json_option() {
        let action = parse(
            ["--json", "--property", "left", "right"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        )
        .expect("arguments should parse");
        let ParseAction::Run(options) = action else {
            panic!("expected runnable options");
        };
        assert!(options.json);
        assert!(options.property);
    }

    #[test]
    fn requires_both_policy_paths() {
        let error = match parse(vec![OsString::from("left")]) {
            Ok(_) => panic!("one path must not parse"),
            Err(error) => error,
        };
        assert_eq!(error, "the following arguments are required: POLICY2");
    }
}
