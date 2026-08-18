//! `seinfo` argument parsing, component queries, and compatibility rendering.

use setools_policy::{
    Boolean, Category, ConstraintExpressionToken, ConstraintKind, ConstraintOperator,
    ConstraintRule, DefaultRule, HandleUnknown, LabelingRule, MlsLevel, MlsRange, ObjectClass,
    Policy, PolicyLoader, RbacRuleKind, Role, SecurityContext, Sensitivity, TargetPlatform,
    TeRuleKind, TypeOrAttributeId, TypeSymbol, User,
};
use setools_query::{BoolQuery, ObjClassQuery, RoleQuery, TypeAttributeQuery, TypeQuery};
use setools_sepol::{
    LibsepolLoader, LoadError, local_log_timestamp, running_policy_info, use_default_sigpipe,
};
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = include_str!("../assets/seinfo-help.txt");

const USAGE: &str = r"usage: seinfo [-h] [--version] [-x] [--flat] [-v] [--debug] [-a [ATTR]]
              [-b [BOOL]] [-c [CLASS]] [-r [ROLE]] [-t [TYPE]] [-u [USER]]
              [--category [CAT]] [--common [COMMON]] [--constrain [CLASS]]
              [--default [CLASS]] [--permissive [TYPE]] [--polcap [NAME]]
              [--role_types TYPE] [--sensitivity [SENS]]
              [--typebounds [BOUND_TYPE]] [--validatetrans [CLASS]] [--all]
              [--fs_use [FS_TYPE]] [--genfscon [FS_TYPE]]
              [--ibpkeycon [PKEY[-PKEY]]] [--ibendportcon [NAME]]
              [--initialsid [NAME]] [--netifcon [DEVICE]] [--nodecon [ADDR]]
              [--portcon [PORTNUM[-PORTNUM]]] [--devicetreecon [PATH]]
              [--iomemcon [ADDR[-ADDR]]] [--ioportcon [PORTNUM[-PORTNUM]]]
              [--pcidevicecon [DEVICE]] [--pirqcon [IRQ]]
              [policy]
";

#[derive(Clone, Debug, Eq, PartialEq)]
enum Selection {
    All,
    Named(String),
}

impl Selection {
    fn name(&self) -> Option<&str> {
        match self {
            Self::All => None,
            Self::Named(name) => Some(name),
        }
    }
}

#[derive(Debug, Default)]
struct Options {
    policy: Option<PathBuf>,
    boolean: Option<Selection>,
    category: Option<Selection>,
    target_class: Option<Selection>,
    common: Option<Selection>,
    constrain: Option<Selection>,
    default_rule: Option<Selection>,
    permissive: Option<Selection>,
    polcap: Option<Selection>,
    role: Option<Selection>,
    role_types: Option<String>,
    sensitivity: Option<Selection>,
    typebounds: Option<Selection>,
    target_type: Option<Selection>,
    attribute: Option<Selection>,
    user: Option<Selection>,
    validatetrans: Option<Selection>,
    fs_use: Option<Selection>,
    genfscon: Option<Selection>,
    ibpkeycon: Option<Selection>,
    ibendportcon: Option<Selection>,
    initialsid: Option<Selection>,
    netifcon: Option<Selection>,
    nodecon: Option<Selection>,
    portcon: Option<Selection>,
    devicetreecon: Option<Selection>,
    iomemcon: Option<Selection>,
    ioportcon: Option<Selection>,
    pcidevicecon: Option<Selection>,
    pirqcon: Option<Selection>,
    all: bool,
    expand: bool,
    flat: bool,
    verbose: bool,
    debug: bool,
}

impl Options {
    fn has_component_query(&self) -> bool {
        self.boolean.is_some()
            || self.category.is_some()
            || self.target_class.is_some()
            || self.common.is_some()
            || self.constrain.is_some()
            || self.default_rule.is_some()
            || self.permissive.is_some()
            || self.polcap.is_some()
            || self.role.is_some()
            || self.role_types.is_some()
            || self.sensitivity.is_some()
            || self.typebounds.is_some()
            || self.target_type.is_some()
            || self.attribute.is_some()
            || self.user.is_some()
            || self.validatetrans.is_some()
            || self.has_selinux_query()
            || self.has_xen_query()
            || self.all
    }

    fn has_selinux_query(&self) -> bool {
        self.fs_use.is_some()
            || self.genfscon.is_some()
            || self.ibpkeycon.is_some()
            || self.ibendportcon.is_some()
            || self.initialsid.is_some()
            || self.netifcon.is_some()
            || self.nodecon.is_some()
            || self.portcon.is_some()
    }

    fn has_xen_query(&self) -> bool {
        self.devicetreecon.is_some()
            || self.iomemcon.is_some()
            || self.ioportcon.is_some()
            || self.pcidevicecon.is_some()
            || self.pirqcon.is_some()
    }

    fn selinux_arguments(&self) -> Vec<&'static str> {
        [
            (self.fs_use.is_some(), "--fs_use"),
            (self.genfscon.is_some(), "--genfscon"),
            (self.ibpkeycon.is_some(), "--ibpkeycon"),
            (self.ibendportcon.is_some(), "--ibendportcon"),
            (self.initialsid.is_some(), "--initialsid"),
            (self.netifcon.is_some(), "--netifcon"),
            (self.nodecon.is_some(), "--nodecon"),
            (self.portcon.is_some(), "--portcon"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect()
    }

    fn xen_arguments(&self) -> Vec<&'static str> {
        [
            (self.devicetreecon.is_some(), "--devicetreecon"),
            (self.iomemcon.is_some(), "--iomemcon"),
            (self.ioportcon.is_some(), "--ioportcon"),
            (self.pcidevicecon.is_some(), "--pcidevicecon"),
            (self.pirqcon.is_some(), "--pirqcon"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect()
    }
}

enum ParseAction {
    Run(Box<Options>),
    Help,
    Version,
}

struct Section {
    description: &'static str,
    items: Vec<String>,
}

enum BuildError {
    Usage(String),
    Analysis(String),
}

impl From<String> for BuildError {
    fn from(message: String) -> Self {
        Self::Analysis(message)
    }
}

/// Runs `seinfo` with already separated process arguments.
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

    let selinux_arguments = options.selinux_arguments();
    let xen_arguments = options.xen_arguments();
    if !selinux_arguments.is_empty() && !xen_arguments.is_empty() {
        return usage_error(&format!(
            "SELinux arguments ({}) cannot be combined with Xen arguments ({}).",
            selinux_arguments.join(", "),
            xen_arguments.join(", ")
        ));
    }

    let (policy, policy_path) = match load_policy(&options) {
        Ok(loaded) => loaded,
        Err(message) => return analysis_error(&message),
    };
    if policy.metadata().target == TargetPlatform::Selinux && !xen_arguments.is_empty() {
        return analysis_error(&format!(
            "error: Xen queries specified ({}), but {} is an SELinux policy.",
            xen_arguments.join(", "),
            policy_path.display()
        ));
    }
    if policy.metadata().target == TargetPlatform::Xen && !selinux_arguments.is_empty() {
        return analysis_error(&format!(
            "error: SELinux queries specified ({}), but {} is a Xen policy.",
            selinux_arguments.join(", "),
            policy_path.display()
        ));
    }

    let sections = match build_sections(&policy, &policy_path, &options) {
        Ok(sections) => sections,
        Err(BuildError::Usage(message)) => return usage_error(&message),
        Err(BuildError::Analysis(message)) => return analysis_error(&message),
    };
    let statistics = ((!options.has_component_query() || options.all) && !options.flat)
        .then(|| render_statistics(&policy, &policy_path));
    render_output(statistics.as_deref(), &sections, options.flat)
}

fn build_sections(
    policy: &Policy,
    policy_path: &Path,
    options: &Options,
) -> Result<Vec<Section>, BuildError> {
    let mut sections = Vec::new();

    if let Some(selection) = selected(&options.boolean, options.all) {
        log_query(options, "setools.boolquery", "Boolean", policy_path);
        let mut query = BoolQuery::new(policy);
        if let Some(name) = selection.name() {
            query.set_name(name);
        }
        let mut results = query.results().collect::<Vec<_>>();
        results.sort_unstable_by(|left, right| left.name().cmp(right.name()));
        sections.push(Section {
            description: "Booleans",
            items: results
                .into_iter()
                .map(|value| render_boolean(value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.category, options.all) {
        log_query(options, "setools.categoryquery", "category", policy_path);
        let name = selection.name();
        sections.push(Section {
            description: "Categories",
            items: policy
                .categories()
                .iter()
                .filter(|value| symbol_or_alias_matches(value.name(), value.aliases(), name))
                .map(|value| render_category(value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.target_class, options.all) {
        log_query(
            options,
            "setools.objclassquery",
            "object class",
            policy_path,
        );
        let mut query = ObjClassQuery::new(policy);
        if let Some(name) = selection.name() {
            query.set_name(name);
        }
        let mut results = query.results().collect::<Vec<_>>();
        results.sort_unstable_by(|left, right| left.name().cmp(right.name()));
        sections.push(Section {
            description: "Classes",
            items: results
                .into_iter()
                .map(|value| render_class(value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.common, options.all) {
        log_query(options, "setools.commonquery", "common", policy_path);
        let mut items = policy
            .seinfo()
            .commons()
            .iter()
            .filter(|value| name_matches(value.name(), selection.name()))
            .map(|value| {
                if options.expand {
                    format!(
                        "common {}\n{{\n\t{}\n}}",
                        value.name(),
                        value.permissions().join("\n\t")
                    )
                } else {
                    value.name().to_owned()
                }
            })
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Commons",
            items,
        });
    }
    if let Some(selection) = selected(&options.constrain, options.all) {
        log_query(
            options,
            "setools.constraintquery",
            "constraint",
            policy_path,
        );
        validate_class_selection(policy, selection)?;
        sections.push(constraint_section(policy, selection, false, "Constraints"));
    }
    if let Some(selection) = selected(&options.default_rule, options.all) {
        log_query(options, "setools.defaultquery", "default_*", policy_path);
        validate_class_selection(policy, selection)?;
        let mut items = policy
            .seinfo()
            .defaults()
            .iter()
            .filter(|rule| class_selection_matches(policy, rule.target_class(), selection))
            .map(|rule| render_default(policy, rule))
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Default rules",
            items,
        });
    }
    if let Some(selection) = selected(&options.permissive, options.all) {
        log_query(options, "setools.typequery", "type", policy_path);
        let mut results = policy
            .type_symbols()
            .iter()
            .filter(|value| !value.is_attribute() && value.is_permissive())
            .filter(|value| type_selection_matches(value, selection))
            .collect::<Vec<_>>();
        results.sort_unstable_by(|left, right| left.name().cmp(right.name()));
        sections.push(Section {
            description: "Permissive Types",
            items: results
                .into_iter()
                .map(|value| render_type(policy, value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.polcap, options.all) {
        log_query(
            options,
            "setools.polcapquery",
            "policy capability",
            policy_path,
        );
        let mut items = policy
            .seinfo()
            .policy_capabilities()
            .iter()
            .filter(|name| name_matches(name, selection.name()))
            .map(|name| {
                if options.expand {
                    format!("policycap {name};")
                } else {
                    name.clone()
                }
            })
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Polcap",
            items,
        });
    }
    if let Some(selection) = selected(&options.role, options.all) {
        log_query(options, "setools.rolequery", "role", policy_path);
        let mut query = RoleQuery::new(policy);
        if let Some(name) = selection.name() {
            query.set_name(name);
        }
        let mut results = query.results().collect::<Vec<_>>();
        results.sort_unstable_by(|left, right| left.name().cmp(right.name()));
        sections.push(Section {
            description: "Roles",
            items: results
                .into_iter()
                .map(|value| render_role(policy, value, options.expand))
                .collect(),
        });
    }
    if let Some(name) = &options.role_types {
        log_query(options, "setools.roletypesquery", "role-types", policy_path);
        let mut items = policy
            .roles()
            .iter()
            .filter(|role| {
                role.authorized_types().iter().any(|id| {
                    policy
                        .type_symbol(TypeOrAttributeId::Type(*id))
                        .is_some_and(|value| value.name() == name)
                })
            })
            .map(|value| render_role(policy, value, options.expand))
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Roles",
            items,
        });
    }
    if let Some(selection) = selected(&options.sensitivity, options.all) {
        log_query(
            options,
            "setools.sensitivityquery",
            "sensitivity",
            policy_path,
        );
        let name = selection.name();
        sections.push(Section {
            description: "Sensitivities",
            items: policy
                .sensitivities()
                .iter()
                .filter(|value| symbol_or_alias_matches(value.name(), value.aliases(), name))
                .map(|value| render_sensitivity(value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.typebounds, options.all) {
        log_query(options, "setools.boundsquery", "bounds", policy_path);
        let mut items = policy
            .type_symbols()
            .iter()
            .filter_map(|child| child.bound().map(|parent| (child, parent)))
            .filter(|(child, _)| name_matches(child.name(), selection.name()))
            .filter_map(|(child, parent)| {
                policy
                    .type_symbol(TypeOrAttributeId::Type(parent))
                    .map(|parent| format!("typebounds {} {};", parent.name(), child.name()))
            })
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Typebounds",
            items,
        });
    }
    if let Some(selection) = selected(&options.target_type, options.all) {
        log_query(options, "setools.typequery", "type", policy_path);
        let mut query = TypeQuery::new(policy);
        if let Some(name) = selection
            .name()
            .and_then(|name| canonical_type_name(policy, name))
        {
            query.set_name(name);
        } else if let Some(name) = selection.name() {
            query.set_name(name);
        }
        let mut results = query.results().collect::<Vec<_>>();
        results.sort_unstable_by(|left, right| left.name().cmp(right.name()));
        sections.push(Section {
            description: "Types",
            items: results
                .into_iter()
                .map(|value| render_type(policy, value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.attribute, options.all) {
        log_query(
            options,
            "setools.typeattrquery",
            "type attribute",
            policy_path,
        );
        let mut query = TypeAttributeQuery::new(policy);
        if let Some(name) = selection.name() {
            query.set_name(name);
        }
        let mut results = query.results().collect::<Vec<_>>();
        results.sort_unstable_by(|left, right| left.name().cmp(right.name()));
        sections.push(Section {
            description: "Type Attributes",
            items: results
                .into_iter()
                .map(|value| render_attribute(policy, value, options.expand))
                .collect(),
        });
    }
    if let Some(selection) = selected(&options.user, options.all) {
        log_query(options, "setools.userquery", "user", policy_path);
        let mut items = policy
            .seinfo()
            .users()
            .iter()
            .filter(|value| name_matches(value.name(), selection.name()))
            .map(|value| render_user(policy, value, options.expand))
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Users",
            items,
        });
    }
    if let Some(selection) = selected(&options.validatetrans, options.all) {
        log_query(
            options,
            "setools.constraintquery",
            "constraint",
            policy_path,
        );
        validate_class_selection(policy, selection)?;
        sections.push(constraint_section(policy, selection, true, "Validatetrans"));
    }

    match policy.metadata().target {
        TargetPlatform::Selinux => {
            build_selinux_sections(policy, policy_path, options, &mut sections)?
        }
        TargetPlatform::Xen => build_xen_sections(policy, policy_path, options, &mut sections)?,
    }
    Ok(sections)
}

fn build_selinux_sections(
    policy: &Policy,
    policy_path: &Path,
    options: &Options,
    sections: &mut Vec<Section>,
) -> Result<(), BuildError> {
    if let Some(selection) = selected(&options.fs_use, options.all) {
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Fs_use",
            "fs_use_*",
            |rule| matches!(rule, LabelingRule::FsUse { filesystem, .. } if name_matches(filesystem, selection.name())),
        );
    }
    if let Some(selection) = selected(&options.genfscon, options.all) {
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Genfscon",
            "genfscon",
            |rule| matches!(rule, LabelingRule::Genfscon { filesystem, .. } if name_matches(filesystem, selection.name())),
        );
    }
    if let Some(selection) = selected(&options.ibendportcon, options.all) {
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Ibendportcon",
            "ibendportcon",
            |rule| matches!(rule, LabelingRule::Ibendportcon { device, .. } if name_matches(device, selection.name())),
        );
    }
    if let Some(selection) = selected(&options.ibpkeycon, options.all) {
        let range = selection.name().map(parse_pkey_range).transpose()?;
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Ibpkeycon",
            "ibpkeycon",
            |rule| matches!(rule, LabelingRule::Ibpkeycon { low, high, .. } if range.is_none_or(|(query_low, query_high)| *low == query_low && *high == query_high)),
        );
    }
    if let Some(selection) = selected(&options.initialsid, options.all) {
        log_query(
            options,
            "setools.initialsidquery",
            "initial SID",
            policy_path,
        );
        let mut items = policy
            .seinfo()
            .labeling_rules()
            .iter()
            .filter_map(|rule| match rule {
                LabelingRule::InitialSid { name, context }
                    if name_matches(name, selection.name()) =>
                {
                    Some(if options.expand {
                        format!("sid {name} {}", render_context(policy, context))
                    } else {
                        name.clone()
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        items.sort_unstable();
        sections.push(Section {
            description: "Initial SIDs",
            items,
        });
    }
    if let Some(selection) = selected(&options.netifcon, options.all) {
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Netifcon",
            "netifcon",
            |rule| matches!(rule, LabelingRule::Netifcon { interface, .. } if name_matches(interface, selection.name())),
        );
    }
    if let Some(selection) = selected(&options.nodecon, options.all) {
        let network = selection.name().map(parse_network).transpose()?;
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Nodecon",
            "nodecon",
            |rule| matches!(rule, LabelingRule::Nodecon { address, mask, .. } if network.as_ref().is_none_or(|query| network_from_address_mask(*address, *mask) == *query)),
        );
    }
    if let Some(selection) = selected(&options.portcon, options.all) {
        let range = selection.name().map(parse_port_range).transpose()?;
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Portcon",
            "portcon",
            |rule| matches!(rule, LabelingRule::Portcon { low, high, .. } if range.is_none_or(|(query_low, query_high)| *low <= query_low && query_high <= *high)),
        );
    }
    Ok(())
}

fn build_xen_sections(
    policy: &Policy,
    policy_path: &Path,
    options: &Options,
    sections: &mut Vec<Section>,
) -> Result<(), BuildError> {
    if let Some(selection) = selected(&options.devicetreecon, options.all) {
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Devicetreecon",
            "",
            |rule| matches!(rule, LabelingRule::Devicetreecon { path, .. } if name_matches(path, selection.name())),
        );
    }
    if let Some(selection) = selected(&options.iomemcon, options.all) {
        let range = selection.name().map(parse_iomem_range).transpose()?;
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Iomemcon",
            "",
            |rule| matches!(rule, LabelingRule::Iomemcon { low, high, .. } if range.is_none_or(|(query_low, query_high)| *low == query_low && *high == query_high)),
        );
    }
    if let Some(selection) = selected(&options.ioportcon, options.all) {
        let range = selection.name().map(parse_ioport_range).transpose()?;
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Ioportcon",
            "",
            |rule| matches!(rule, LabelingRule::Ioportcon { low, high, .. } if range.is_none_or(|(query_low, query_high)| *low <= query_low && query_high <= *high)),
        );
    }
    if let Some(selection) = selected(&options.pcidevicecon, options.all) {
        let device = selection
            .name()
            .map(|value| parse_python_int(value, 16))
            .transpose()?
            .filter(|value| *value != 0);
        if device.is_some_and(|value| value < 0) {
            return Err(BuildError::Analysis(format!(
                "PCI device ID must be positive: {}",
                device.expect("checked present")
            )));
        }
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Pcidevicecon",
            "",
            |rule| matches!(rule, LabelingRule::Pcidevicecon { device: value, .. } if device.is_none_or(|device| i128::from(*value) == device)),
        );
    }
    if let Some(selection) = selected(&options.pirqcon, options.all) {
        let irq = selection
            .name()
            .map(|value| parse_python_int(value, 10))
            .transpose()?
            .filter(|value| *value != 0);
        if irq.is_some_and(|value| value < 0) {
            return Err(BuildError::Analysis(format!(
                "The IRQ must be positive: {}",
                irq.expect("checked present")
            )));
        }
        push_labeling_section(
            policy,
            options,
            policy_path,
            sections,
            "Pirqcon",
            "",
            |rule| matches!(rule, LabelingRule::Pirqcon { irq: value, .. } if irq.is_none_or(|irq| i128::from(*value) == irq)),
        );
    }
    Ok(())
}

fn push_labeling_section(
    policy: &Policy,
    options: &Options,
    policy_path: &Path,
    sections: &mut Vec<Section>,
    description: &'static str,
    query_name: &str,
    predicate: impl Fn(&LabelingRule) -> bool,
) {
    log_query(options, "setools.policyrep", query_name, policy_path);
    let mut items = policy
        .seinfo()
        .labeling_rules()
        .iter()
        .filter(|rule| predicate(rule))
        .map(|rule| render_labeling(policy, rule))
        .collect::<Vec<_>>();
    items.sort_unstable();
    sections.push(Section { description, items });
}

fn selected(selection: &Option<Selection>, all: bool) -> Option<&Selection> {
    static ALL: Selection = Selection::All;
    selection.as_ref().or_else(|| all.then_some(&ALL))
}

fn constraint_section(
    policy: &Policy,
    selection: &Selection,
    validate_transition: bool,
    description: &'static str,
) -> Section {
    let mut items = policy
        .seinfo()
        .constraints()
        .iter()
        .filter(|rule| rule.kind().is_validate_transition() == validate_transition)
        .filter(|rule| class_selection_matches(policy, rule.target_class(), selection))
        .map(|rule| render_constraint(policy, rule))
        .collect::<Vec<_>>();
    items.sort_unstable();
    Section { description, items }
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
    let mut options = Options::default();
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
            "-x" | "--expand" => options.expand = true,
            "--flat" => options.flat = true,
            "-v" | "--verbose" => options.verbose = true,
            "--debug" => options.debug = true,
            "--all" => options.all = true,
            "--role_types" => {
                options.role_types = Some(take_value(&arguments, &mut index, argument)?)
            }
            _ if optional_option(
                &mut options,
                argument,
                take_optional(&arguments, &mut index),
            ) => {}
            _ if argument.starts_with("--") && argument.contains('=') => {
                let (option, value) = argument.split_once('=').expect("checked split");
                set_long_value(&mut options, option, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unrecognized arguments: {argument}"));
            }
            _ => set_policy(&mut options, argument)?,
        }
        index += 1;
    }
    repair_consumed_policy(&mut options);
    Ok(ParseAction::Run(Box::new(options)))
}

fn optional_option(options: &mut Options, option: &str, selection: Selection) -> bool {
    let target = match option {
        "-a" | "--attribute" => &mut options.attribute,
        "-b" | "--bool" => &mut options.boolean,
        "-c" | "--class" => &mut options.target_class,
        "-r" | "--role" => &mut options.role,
        "-t" | "--type" => &mut options.target_type,
        "-u" | "--user" => &mut options.user,
        "--category" => &mut options.category,
        "--common" => &mut options.common,
        "--constrain" => &mut options.constrain,
        "--default" => &mut options.default_rule,
        "--permissive" => &mut options.permissive,
        "--polcap" => &mut options.polcap,
        "--sensitivity" => &mut options.sensitivity,
        "--typebounds" => &mut options.typebounds,
        "--validatetrans" => &mut options.validatetrans,
        "--fs_use" => &mut options.fs_use,
        "--genfscon" => &mut options.genfscon,
        "--ibpkeycon" => &mut options.ibpkeycon,
        "--ibendportcon" => &mut options.ibendportcon,
        "--initialsid" => &mut options.initialsid,
        "--netifcon" => &mut options.netifcon,
        "--nodecon" => &mut options.nodecon,
        "--portcon" => &mut options.portcon,
        "--devicetreecon" => &mut options.devicetreecon,
        "--iomemcon" => &mut options.iomemcon,
        "--ioportcon" => &mut options.ioportcon,
        "--pcidevicecon" => &mut options.pcidevicecon,
        "--pirqcon" => &mut options.pirqcon,
        _ => return false,
    };
    *target = Some(selection);
    true
}

fn take_optional(arguments: &[String], index: &mut usize) -> Selection {
    match arguments.get(*index + 1) {
        Some(value) if !value.starts_with('-') => {
            *index += 1;
            Selection::Named(value.clone())
        }
        _ => Selection::All,
    }
}

fn take_value(arguments: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("argument {option}: expected one argument"))
}

fn set_long_value(options: &mut Options, option: &str, value: &str) -> Result<(), String> {
    if option == "--role_types" {
        options.role_types = Some(value.to_owned());
    } else if !optional_option(options, option, Selection::Named(value.to_owned())) {
        return Err(format!("unrecognized arguments: {option}={value}"));
    }
    Ok(())
}

fn set_policy(options: &mut Options, value: &str) -> Result<(), String> {
    if options.policy.is_some() {
        Err(format!("unrecognized arguments: {value}"))
    } else {
        options.policy = Some(PathBuf::from(value));
        Ok(())
    }
}

fn repair_consumed_policy(options: &mut Options) {
    if options.policy.is_some() {
        return;
    }
    let selections = [
        &mut options.attribute,
        &mut options.boolean,
        &mut options.target_class,
        &mut options.role,
        &mut options.target_type,
        &mut options.user,
        &mut options.category,
        &mut options.common,
        &mut options.constrain,
        &mut options.default_rule,
        &mut options.permissive,
        &mut options.polcap,
        &mut options.sensitivity,
        &mut options.typebounds,
        &mut options.validatetrans,
        &mut options.fs_use,
        &mut options.genfscon,
        &mut options.ibpkeycon,
        &mut options.ibendportcon,
        &mut options.initialsid,
        &mut options.netifcon,
        &mut options.nodecon,
        &mut options.portcon,
        &mut options.devicetreecon,
        &mut options.iomemcon,
        &mut options.ioportcon,
        &mut options.pcidevicecon,
        &mut options.pirqcon,
    ];
    for selection in selections {
        let Some(Selection::Named(value)) = selection else {
            continue;
        };
        if Path::new(value).exists() {
            options.policy = Some(PathBuf::from(value.as_str()));
            *selection = Some(Selection::All);
            break;
        }
    }
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

fn log_query(options: &Options, module: &str, description: &str, path: &Path) {
    let message = if description.is_empty() {
        format!("Generating results from {}", path.display())
    } else {
        format!("Generating {description} results from {}", path.display())
    };
    log_message(options, "INFO", module, &message);
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

fn render_boolean(value: &Boolean, expand: bool) -> String {
    if expand {
        format!(
            "bool {} {};",
            value.name(),
            if value.state() { "true" } else { "false" }
        )
    } else {
        value.name().to_owned()
    }
}

fn render_category(value: &Category, expand: bool) -> String {
    if expand {
        render_aliased_statement("category", value.name(), value.aliases())
    } else {
        value.name().to_owned()
    }
}

fn render_sensitivity(value: &Sensitivity, expand: bool) -> String {
    if expand {
        render_aliased_statement("sensitivity", value.name(), value.aliases())
    } else {
        value.name().to_owned()
    }
}

fn render_aliased_statement(keyword: &str, name: &str, aliases: &[String]) -> String {
    let alias = match aliases {
        [] => String::new(),
        [alias] => format!(" alias {alias}"),
        aliases => format!(" alias {{ {} }}", aliases.join(" ")),
    };
    format!("{keyword} {name}{alias};")
}

fn render_class(value: &ObjectClass, expand: bool) -> String {
    if !expand {
        return value.name().to_owned();
    }
    let mut statement = format!("class {}\n", value.name());
    if let Some(common) = value.common() {
        statement.push_str(&format!("inherits {common}\n"));
    }
    if !value.local_permissions().is_empty() {
        statement.push_str("{\n\t");
        statement.push_str(&value.local_permissions().join("\n\t"));
        statement.push_str("\n}");
    }
    statement
}

fn render_role(policy: &Policy, value: &Role, expand: bool) -> String {
    if !expand {
        return value.name().to_owned();
    }
    let mut types = value
        .authorized_types()
        .iter()
        .filter_map(|id| policy.type_symbol(TypeOrAttributeId::Type(*id)))
        .map(TypeSymbol::name)
        .collect::<Vec<_>>();
    types.sort_unstable();
    match types.as_slice() {
        [] => format!("role {};", value.name()),
        [target_type] => format!("role {} types {target_type};", value.name()),
        _ => format!("role {} types {{ {} }};", value.name(), types.join(" ")),
    }
}

fn render_type(policy: &Policy, value: &TypeSymbol, expand: bool) -> String {
    if !expand {
        return value.name().to_owned();
    }
    let TypeOrAttributeId::Type(type_id) = value.id() else {
        return value.name().to_owned();
    };
    let mut statement = format!("type {}", value.name());
    match value.aliases() {
        [] => {}
        [alias] => statement.push_str(&format!(" alias {alias}")),
        aliases => statement.push_str(&format!(" alias {{ {} }}", aliases.join(" "))),
    }
    let mut attributes = policy
        .type_symbols()
        .iter()
        .filter(|symbol| {
            symbol.is_attribute() && symbol.expanded_types().binary_search(&type_id).is_ok()
        })
        .map(TypeSymbol::name)
        .collect::<Vec<_>>();
    attributes.sort_unstable();
    if !attributes.is_empty() {
        statement.push_str(", ");
        statement.push_str(&attributes.join(", "));
    }
    statement.push(';');
    statement
}

fn render_attribute(policy: &Policy, value: &TypeSymbol, expand: bool) -> String {
    if !expand {
        return value.name().to_owned();
    }
    let mut members = value
        .expanded_types()
        .iter()
        .filter_map(|id| policy.type_symbol(TypeOrAttributeId::Type(*id)))
        .map(TypeSymbol::name)
        .collect::<Vec<_>>();
    members.sort_unstable();
    let contents = if members.is_empty() {
        "<empty attribute>".to_owned()
    } else {
        members.join("\n\t")
    };
    format!("attribute {};\n\t{contents}", value.name())
}

fn render_user(policy: &Policy, value: &User, expand: bool) -> String {
    if !expand {
        return value.name().to_owned();
    }
    let mut roles = value
        .roles()
        .iter()
        .filter_map(|id| policy.role(*id))
        .map(Role::name)
        .collect::<Vec<_>>();
    roles.sort_unstable();
    let roles = match roles.as_slice() {
        [role] => (*role).to_owned(),
        _ => format!("{{ {} }}", roles.join(" ")),
    };
    let mut statement = format!("user {} roles {roles}", value.name());
    if let (Some(level), Some(range)) = (value.default_level(), value.range()) {
        statement.push_str(&format!(
            " level {} range {}",
            render_level(policy, level),
            render_range(policy, range)
        ));
    }
    statement.push(';');
    statement
}

fn render_default(policy: &Policy, rule: &DefaultRule) -> String {
    let target_class = policy
        .object_class(rule.target_class())
        .expect("validated default class");
    let mut statement = format!(
        "{} {} {}",
        rule.kind().keyword(),
        target_class.name(),
        rule.value().keyword()
    );
    if let Some(part) = rule.range_part() {
        statement.push(' ');
        statement.push_str(part.keyword());
    }
    statement.push(';');
    statement
}

fn render_constraint(policy: &Policy, rule: &ConstraintRule) -> String {
    let target_class = policy
        .object_class(rule.target_class())
        .expect("validated constraint class");
    let expression = render_constraint_expression(rule.expression());
    if rule.kind().is_validate_transition() {
        format!(
            "{} {} ({expression});",
            rule.kind().keyword(),
            target_class.name()
        )
    } else {
        let mut permissions = rule
            .permissions()
            .iter()
            .filter_map(|id| target_class.permission(*id))
            .map(|value| value.name())
            .collect::<Vec<_>>();
        permissions.sort_unstable();
        let permissions = match permissions.as_slice() {
            [permission] => (*permission).to_owned(),
            _ => format!("{{ {} }}", permissions.join(" ")),
        };
        format!(
            "{} {} {permissions} ({expression});",
            rule.kind().keyword(),
            target_class.name()
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
                let value = if values.len() > 1 {
                    format!("{{ {} }}", values.join(" "))
                } else {
                    values.join(" ")
                };
                stack.push((4, value));
            }
            ConstraintExpressionToken::Operator(operator) => {
                let precedence = operator.precedence();
                if *operator == ConstraintOperator::Not {
                    let Some((operand_precedence, operand)) = stack.pop() else {
                        return "<invalid expression>".to_owned();
                    };
                    let operand = parenthesize(operand_precedence, precedence, operand);
                    stack.push((precedence, format!("not {operand}")));
                } else {
                    let Some((right_precedence, right)) = stack.pop() else {
                        return "<invalid expression>".to_owned();
                    };
                    let Some((left_precedence, left)) = stack.pop() else {
                        return "<invalid expression>".to_owned();
                    };
                    stack.push((
                        precedence,
                        format!(
                            "{} {} {}",
                            parenthesize(left_precedence, precedence, left),
                            operator.keyword(),
                            parenthesize(right_precedence, precedence, right)
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

fn render_labeling(policy: &Policy, rule: &LabelingRule) -> String {
    match rule {
        LabelingRule::InitialSid { name, context } => {
            format!("sid {name} {}", render_context(policy, context))
        }
        LabelingRule::FsUse {
            kind,
            filesystem,
            context,
        } => format!(
            "{} {filesystem} {};",
            kind.keyword(),
            render_context(policy, context)
        ),
        LabelingRule::Genfscon {
            filesystem,
            path,
            target_class,
            context,
        } => {
            let filetype =
                target_class
                    .and_then(|id| policy.object_class(id))
                    .map_or("", |class| match class.name() {
                        "blk_file" => "-b",
                        "chr_file" => "-c",
                        "dir" => "-d",
                        "fifo_file" => "-p",
                        "file" => "--",
                        "lnk_file" => "-l",
                        "sock_file" => "-s",
                        _ => "",
                    });
            format!(
                "genfscon {filesystem} {path} {filetype} {}",
                render_context(policy, context)
            )
        }
        LabelingRule::Portcon {
            protocol,
            low,
            high,
            context,
        } => format!(
            "portcon {} {} {}",
            protocol.keyword(),
            decimal_range(*low, *high),
            render_context(policy, context)
        ),
        LabelingRule::Netifcon {
            interface,
            interface_context,
            packet_context,
        } => format!(
            "netifcon {interface} {} {}",
            render_context(policy, interface_context),
            render_context(policy, packet_context)
        ),
        LabelingRule::Nodecon {
            address,
            mask,
            context,
        } => format!(
            "nodecon {} {} {}",
            normalized_network_address(*address, *mask),
            mask,
            render_context(policy, context)
        ),
        LabelingRule::Ibpkeycon {
            subnet_prefix,
            low,
            high,
            context,
        } => format!(
            "ibpkeycon {subnet_prefix} {} {}",
            hex_range(u64::from(*low), u64::from(*high)),
            render_context(policy, context)
        ),
        LabelingRule::Ibendportcon {
            device,
            port,
            context,
        } => format!(
            "ibendportcon {device} {port} {}",
            render_context(policy, context)
        ),
        LabelingRule::Devicetreecon { path, context } => {
            format!("devicetreecon {path} {}", render_context(policy, context))
        }
        LabelingRule::Iomemcon { low, high, context } => format!(
            "iomemcon {} {}",
            hex_range(*low, *high),
            render_context(policy, context)
        ),
        LabelingRule::Ioportcon { low, high, context } => format!(
            "ioportcon {} {}",
            hex_range(u64::from(*low), u64::from(*high)),
            render_context(policy, context)
        ),
        LabelingRule::Pcidevicecon { device, context } => format!(
            "pcidevicecon {device:#06x} {}",
            render_context(policy, context)
        ),
        LabelingRule::Pirqcon { irq, context } => {
            format!("pirqcon {irq} {}", render_context(policy, context))
        }
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

fn render_range(policy: &Policy, range: &MlsRange) -> String {
    let low = render_level(policy, range.low());
    let high = render_level(policy, range.high());
    if low == high {
        low
    } else {
        format!("{low} - {high}")
    }
}

fn render_level(policy: &Policy, level: &MlsLevel) -> String {
    let sensitivity = policy
        .sensitivity(level.sensitivity())
        .expect("validated sensitivity");
    let mut value = sensitivity.name().to_owned();
    let categories = level.categories();
    if !categories.is_empty() {
        let mut runs = Vec::new();
        let mut start = 0_usize;
        while start < categories.len() {
            let mut end = start;
            while end + 1 < categories.len()
                && categories[end + 1].as_raw() == categories[end].as_raw() + 1
            {
                end += 1;
            }
            let first = policy
                .category(categories[start])
                .expect("validated category")
                .name();
            if end == start {
                runs.push(first.to_owned());
            } else {
                let last = policy
                    .category(categories[end])
                    .expect("validated category")
                    .name();
                runs.push(format!("{first}.{last}"));
            }
            start = end + 1;
        }
        value.push(':');
        value.push_str(&runs.join(","));
    }
    value
}

fn render_statistics(policy: &Policy, path: &Path) -> String {
    let metadata = policy.metadata();
    let type_count = policy
        .type_symbols()
        .iter()
        .filter(|value| !value.is_attribute())
        .count();
    let attribute_count = policy.type_symbols().len() - type_count;
    let permission_count = policy
        .object_classes()
        .iter()
        .map(|target_class| target_class.local_permissions().len())
        .sum::<usize>()
        + policy
            .seinfo()
            .commons()
            .iter()
            .map(|common| common.permissions().len())
            .sum::<usize>();
    let te_count = |kind| {
        policy
            .te_rules()
            .iter()
            .filter(|rule| rule.kind() == kind)
            .count()
    };
    let rbac_count = |kind| {
        policy
            .rbac_rules()
            .iter()
            .filter(|rule| rule.kind() == kind)
            .count()
    };
    let constraint_count = |kind| {
        policy
            .seinfo()
            .constraints()
            .iter()
            .filter(|rule| rule.kind() == kind)
            .count()
    };
    let label_count = |predicate: fn(&LabelingRule) -> bool| {
        policy
            .seinfo()
            .labeling_rules()
            .iter()
            .filter(|rule| predicate(rule))
            .count()
    };
    let mut output = String::new();
    output.push_str(&format!("Statistics for policy file: {}\n", path.display()));
    output.push_str(&format!(
        "Policy Version:             {} (MLS {})\n",
        metadata.version,
        if metadata.mls { "enabled" } else { "disabled" }
    ));
    output.push_str(&format!(
        "Target Policy:              {}\n",
        match metadata.target {
            TargetPlatform::Selinux => "selinux",
            TargetPlatform::Xen => "xen",
        }
    ));
    output.push_str(&format!(
        "Handle unknown classes:     {}\n",
        match metadata.handle_unknown {
            HandleUnknown::Deny => "deny",
            HandleUnknown::Reject => "reject",
            HandleUnknown::Allow => "allow",
        }
    ));
    stats_line(
        &mut output,
        "Classes:",
        policy.object_classes().len(),
        "Permissions:",
        permission_count,
    );
    stats_line(
        &mut output,
        "Sensitivities:",
        policy.sensitivities().len(),
        "Categories:",
        policy.categories().len(),
    );
    stats_line(
        &mut output,
        "Types:",
        type_count,
        "Attributes:",
        attribute_count,
    );
    stats_line(
        &mut output,
        "Users:",
        policy.seinfo().users().len(),
        "Roles:",
        policy.roles().len(),
    );
    stats_line(
        &mut output,
        "Booleans:",
        policy.booleans().len(),
        "Cond. Expr.:",
        policy.conditionals().len(),
    );
    stats_line(
        &mut output,
        "Allow:",
        te_count(TeRuleKind::Allow),
        "Neverallow:",
        0,
    );
    stats_line(
        &mut output,
        "Auditallow:",
        te_count(TeRuleKind::AuditAllow),
        "Dontaudit:",
        te_count(TeRuleKind::DontAudit),
    );
    stats_line(
        &mut output,
        "Type_trans:",
        te_count(TeRuleKind::TypeTransition),
        "Type_change:",
        te_count(TeRuleKind::TypeChange),
    );
    stats_line(
        &mut output,
        "Type_member:",
        te_count(TeRuleKind::TypeMember),
        "Range_trans:",
        policy.mls_rules().len(),
    );
    stats_line(
        &mut output,
        "Role allow:",
        rbac_count(RbacRuleKind::Allow),
        "Role_trans:",
        rbac_count(RbacRuleKind::RoleTransition),
    );
    stats_line(
        &mut output,
        "Constraints:",
        constraint_count(ConstraintKind::Constrain),
        "Validatetrans:",
        constraint_count(ConstraintKind::ValidateTransition),
    );
    stats_line(
        &mut output,
        "MLS Constrain:",
        constraint_count(ConstraintKind::MlsConstrain),
        "MLS Val. Tran:",
        constraint_count(ConstraintKind::MlsValidateTransition),
    );
    stats_line(
        &mut output,
        "Permissives:",
        policy
            .type_symbols()
            .iter()
            .filter(|value| value.is_permissive())
            .count(),
        "Polcap:",
        policy.seinfo().policy_capabilities().len(),
    );
    stats_line(
        &mut output,
        "Defaults:",
        policy.seinfo().defaults().len(),
        "Typebounds:",
        policy
            .type_symbols()
            .iter()
            .filter(|value| value.bound().is_some())
            .count(),
    );
    match metadata.target {
        TargetPlatform::Selinux => {
            stats_line(
                &mut output,
                "Allowxperm:",
                te_count(TeRuleKind::AllowXperm),
                "Neverallowxperm:",
                0,
            );
            stats_line(
                &mut output,
                "Auditallowxperm:",
                te_count(TeRuleKind::AuditAllowXperm),
                "Dontauditxperm:",
                te_count(TeRuleKind::DontAuditXperm),
            );
            stats_line(
                &mut output,
                "Ibendportcon:",
                label_count(|rule| matches!(rule, LabelingRule::Ibendportcon { .. })),
                "Ibpkeycon:",
                label_count(|rule| matches!(rule, LabelingRule::Ibpkeycon { .. })),
            );
            stats_line(
                &mut output,
                "Initial SIDs:",
                label_count(|rule| matches!(rule, LabelingRule::InitialSid { .. })),
                "Fs_use:",
                label_count(|rule| matches!(rule, LabelingRule::FsUse { .. })),
            );
            stats_line(
                &mut output,
                "Genfscon:",
                label_count(|rule| matches!(rule, LabelingRule::Genfscon { .. })),
                "Portcon:",
                label_count(|rule| matches!(rule, LabelingRule::Portcon { .. })),
            );
            stats_line(
                &mut output,
                "Netifcon:",
                label_count(|rule| matches!(rule, LabelingRule::Netifcon { .. })),
                "Nodecon:",
                label_count(|rule| matches!(rule, LabelingRule::Nodecon { .. })),
            );
        }
        TargetPlatform::Xen => {
            stats_line(
                &mut output,
                "Initial SIDs:",
                label_count(|rule| matches!(rule, LabelingRule::InitialSid { .. })),
                "Devicetreecon:",
                label_count(|rule| matches!(rule, LabelingRule::Devicetreecon { .. })),
            );
            stats_line(
                &mut output,
                "Iomemcon:",
                label_count(|rule| matches!(rule, LabelingRule::Iomemcon { .. })),
                "Ioportcon:",
                label_count(|rule| matches!(rule, LabelingRule::Ioportcon { .. })),
            );
            stats_line(
                &mut output,
                "Pcidevicecon:",
                label_count(|rule| matches!(rule, LabelingRule::Pcidevicecon { .. })),
                "Pirqcon:",
                label_count(|rule| matches!(rule, LabelingRule::Pirqcon { .. })),
            );
        }
    }
    output
}

fn stats_line(output: &mut String, left_label: &str, left: usize, right_label: &str, right: usize) {
    output.push_str(&format!(
        "  {left_label:<17}{left:7}    {right_label:<17}{right:7}\n"
    ));
}

fn render_output(statistics: Option<&str>, sections: &[Section], flat: bool) -> ExitCode {
    let mut output = statistics.unwrap_or_default().to_owned();
    for section in sections {
        if flat {
            for item in &section.items {
                output.push_str(item);
                output.push('\n');
            }
        } else {
            output.push('\n');
            output.push_str(section.description);
            output.push_str(": ");
            output.push_str(&section.items.len().to_string());
            output.push('\n');
            for item in &section.items {
                output.push_str("   ");
                output.push_str(item);
                output.push('\n');
            }
        }
    }
    write_stdout(&output)
}

fn name_matches(name: &str, criterion: Option<&str>) -> bool {
    criterion.is_none_or(|criterion| name == criterion)
}

fn symbol_or_alias_matches(name: &str, aliases: &[String], criterion: Option<&str>) -> bool {
    criterion
        .is_none_or(|criterion| name == criterion || aliases.iter().any(|alias| alias == criterion))
}

fn type_selection_matches(value: &TypeSymbol, selection: &Selection) -> bool {
    symbol_or_alias_matches(value.name(), value.aliases(), selection.name())
}

fn canonical_type_name<'policy>(policy: &'policy Policy, name: &str) -> Option<&'policy str> {
    policy
        .type_symbol_by_name(name)
        .filter(|value| !value.is_attribute())
        .map(TypeSymbol::name)
}

fn class_selection_matches(
    policy: &Policy,
    id: setools_policy::ClassId,
    selection: &Selection,
) -> bool {
    policy
        .object_class(id)
        .is_some_and(|value| name_matches(value.name(), selection.name()))
}

fn validate_class_selection(policy: &Policy, selection: &Selection) -> Result<(), BuildError> {
    if let Some(name) = selection.name()
        && policy.object_class_by_name(name).is_none()
    {
        return Err(BuildError::Analysis(format!("{name} is not a valid class")));
    }
    Ok(())
}

fn decimal_range(low: u16, high: u16) -> String {
    if low == high {
        low.to_string()
    } else {
        format!("{low}-{high}")
    }
}

fn hex_range(low: u64, high: u64) -> String {
    if low == high {
        format!("{low:#06x}")
    } else {
        format!("{low:#06x}-{high:#06x}")
    }
}

fn parse_port_range(value: &str) -> Result<(u16, u16), BuildError> {
    let (low, high) = parse_integer_range(
        value,
        10,
        "Enter a port number or range, e.g. 22 or 6000-6020",
    )?;
    if low < 1 || high < 1 {
        return Err(BuildError::Analysis(format!(
            "Port numbers must be >= 1: {}",
            decimal_i128_range(low, high)
        )));
    }
    if low > i128::from(u16::MAX) || high > i128::from(u16::MAX) {
        return Err(BuildError::Analysis(format!(
            "Port numbers must be <= 65535: {}",
            decimal_i128_range(low, high)
        )));
    }
    if low > high {
        return Err(BuildError::Analysis(format!(
            "The low port must be <= the high port: {}",
            decimal_i128_range(low, high)
        )));
    }
    Ok((low as u16, high as u16))
}

fn parse_pkey_range(value: &str) -> Result<(u16, u16), BuildError> {
    let (low, high) = parse_integer_range(
        value,
        16,
        "Enter a pkey number or range, e.g. 0x22 or 0x6000-0x6020",
    )?;
    if low < 1 || high < 1 {
        return Err(BuildError::Analysis(format!(
            "Partition keys must be >= 0x0001: {}",
            hex_i128_range(low, high)
        )));
    }
    if low > i128::from(u16::MAX) || high > i128::from(u16::MAX) {
        return Err(BuildError::Analysis(format!(
            "Partition keys must be <= 0xffff: {}",
            hex_i128_range(low, high)
        )));
    }
    if low > high {
        return Err(BuildError::Analysis(format!(
            "The low partition key must be <= the high partition key: {}",
            hex_i128_range(low, high)
        )));
    }
    Ok((low as u16, high as u16))
}

fn parse_iomem_range(value: &str) -> Result<(u64, u64), BuildError> {
    let (low, high) = parse_integer_range(
        value,
        16,
        "Enter an IO memory address or range, e.g. 0x22 or 0x6000-0x6020",
    )?;
    if low < 1 || high < 1 {
        return Err(BuildError::Analysis(format!(
            "Memory address must be >= 0x0001: {}",
            hex_i128_range(low, high)
        )));
    }
    if low > 0xffff || high > 0xffff {
        return Err(BuildError::Analysis(format!(
            "Memory address must be <= 0xffff: {}",
            hex_i128_range(low, high)
        )));
    }
    if low > high {
        return Err(BuildError::Analysis(format!(
            "The low mem addr must be smaller than the high mem addr: {}",
            hex_i128_range(low, high)
        )));
    }
    Ok((low as u64, high as u64))
}

fn parse_ioport_range(value: &str) -> Result<(u32, u32), BuildError> {
    let (low, high) = parse_integer_range(
        value,
        16,
        "Enter an IO port number or range, e.g. 0x22 or 0x6000-0x6020",
    )?;
    if low < 1 || high < 1 {
        return Err(BuildError::Analysis(format!(
            "Port numbers must be >= 0x0001: {}",
            hex_i128_range(low, high)
        )));
    }
    if low > 0xffff || high > 0xffff {
        return Err(BuildError::Analysis(format!(
            "Port numbers must be <= 0xffff: {}",
            hex_i128_range(low, high)
        )));
    }
    if low > high {
        return Err(BuildError::Analysis(format!(
            "The low port must be smaller than the high port: {}",
            hex_i128_range(low, high)
        )));
    }
    Ok((low as u32, high as u32))
}

fn parse_integer_range(
    value: &str,
    radix: u32,
    usage_message: &str,
) -> Result<(i128, i128), BuildError> {
    let parts = value.split('-').collect::<Vec<_>>();
    let parsed = match parts.as_slice() {
        [single] => parse_python_int(single, radix)
            .ok()
            .map(|value| (value, value)),
        [low, high] => parse_python_int(low, radix)
            .ok()
            .zip(parse_python_int(high, radix).ok()),
        _ => None,
    };
    parsed.ok_or_else(|| BuildError::Usage(usage_message.to_owned()))
}

fn parse_python_int(value: &str, radix: u32) -> Result<i128, String> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |digits| (true, digits));
    let digits = if radix == 16 {
        digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
            .unwrap_or(digits)
    } else {
        digits
    };
    let parsed = i128::from_str_radix(digits, radix)
        .map_err(|_| format!("invalid literal for int() with base {radix}: '{value}'"))?;
    Ok(if negative { -parsed } else { parsed })
}

fn decimal_i128_range(low: i128, high: i128) -> String {
    if low == high {
        low.to_string()
    } else {
        format!("{low}-{high}")
    }
}

fn hex_i128_range(low: i128, high: i128) -> String {
    let render = |value: i128| {
        if value < 0 {
            format!("-0x{:03x}", value.unsigned_abs())
        } else {
            format!("0x{value:04x}")
        }
    };
    if low == high {
        render(low)
    } else {
        format!("{}-{}", render(low), render(high))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Network {
    address: IpAddr,
    prefix: u8,
}

fn parse_network(value: &str) -> Result<Network, String> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("'{value}' does not appear to be an IPv4 or IPv6 network"))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix
        .map_or(Ok(maximum), |prefix| prefix.parse::<u8>())
        .map_err(|_| format!("'{value}' does not appear to be an IPv4 or IPv6 network"))?;
    if prefix > maximum || normalize_address(address, prefix) != address {
        return Err(format!("{address}/{prefix} has host bits set"));
    }
    Ok(Network { address, prefix })
}

fn network_from_address_mask(address: IpAddr, mask: IpAddr) -> Network {
    let prefix = match mask {
        IpAddr::V4(mask) => u8::try_from(u32::from(mask).count_ones()).expect("IPv4 prefix fits"),
        IpAddr::V6(mask) => u8::try_from(u128::from(mask).count_ones()).expect("IPv6 prefix fits"),
    };
    Network {
        address: normalize_address(address, prefix),
        prefix,
    }
}

fn normalized_network_address(address: IpAddr, mask: IpAddr) -> IpAddr {
    network_from_address_mask(address, mask).address
}

fn normalize_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

fn usage_error(message: &str) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{USAGE}seinfo: error: {message}");
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
    use super::{ParseAction, Selection, parse};
    use std::ffi::OsString;
    use std::path::Path;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_named_type_and_policy() {
        let ParseAction::Run(options) =
            parse(args(&["--type", "example_t", "policy.35"])).expect("arguments must parse")
        else {
            panic!("expected query action");
        };
        assert_eq!(
            options.target_type,
            Some(Selection::Named("example_t".to_owned()))
        );
        assert_eq!(options.policy.as_deref(), Some(Path::new("policy.35")));
    }

    #[test]
    fn parses_all_boolean_query_without_value() {
        let ParseAction::Run(options) = parse(args(&["--bool"])).expect("arguments must parse")
        else {
            panic!("expected query action");
        };
        assert_eq!(options.boolean, Some(Selection::All));
    }
}
