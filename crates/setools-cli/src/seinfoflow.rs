//! `seinfoflow` argument parsing, information-flow queries, and rendering.

use crate::sesearch::render_rule;
use setools_graph::{
    InformationFlowGraph, InformationFlowStats, InformationFlowStep, PermissionDirection,
    PermissionMap,
};
use setools_policy::{Policy, PolicyLoader, TypeId, TypeOrAttributeId};
use setools_sepol::{
    LibsepolLoader, LoadError, local_log_timestamp, running_policy_info, use_default_sigpipe,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const HELP: &str = include_str!("../assets/seinfoflow-help.txt");

const USAGE: &str = r"usage: seinfoflow [-h] [--full] [--version] [--stats] [-v] [--debug]
                  [-p POLICY] [-m MAP] -s SOURCE [-t TARGET] [-S]
                  [-A MAX_STEPS] [-r] [-w MIN_WEIGHT] [-l LIMIT_FLOWS]
                  [-b BOOLEANS] [-o OUTPUT_FILE]
                  [exclude ...]
";

#[derive(Debug)]
struct Options {
    policy: Option<PathBuf>,
    permission_map: Option<PathBuf>,
    source: Option<String>,
    target: Option<String>,
    full: bool,
    stats: bool,
    verbose: bool,
    debug: bool,
    shortest_path: bool,
    all_paths: Option<i32>,
    reverse: bool,
    minimum_weight: i32,
    limit_flows: i32,
    booleans: Option<BTreeMap<String, bool>>,
    output_file: Option<PathBuf>,
    exclude: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: None,
            permission_map: None,
            source: None,
            target: None,
            full: false,
            stats: false,
            verbose: false,
            debug: false,
            shortest_path: false,
            all_paths: None,
            reverse: false,
            minimum_weight: 3,
            limit_flows: 0,
            booleans: None,
            output_file: None,
            exclude: Vec::new(),
        }
    }
}

enum ParseAction {
    Run(Options),
    Help,
    Version,
}

enum Results<'policy> {
    Flows(Vec<InformationFlowStep<'policy>>),
    Paths(Vec<Vec<InformationFlowStep<'policy>>>),
}

/// Runs `seinfoflow` with already separated process arguments.
pub(crate) fn run(arguments: Vec<OsString>) -> ExitCode {
    let _ = use_default_sigpipe();
    let action = match parse(arguments) {
        Ok(action) => action,
        Err(message) => return usage_error(&message),
    };
    let options = match action {
        ParseAction::Help => return write_stdout(HELP),
        ParseAction::Version => return write_stdout(concat!(env!("CARGO_PKG_VERSION"), "\n")),
        ParseAction::Run(options) => options,
    };

    let has_all_paths = options.all_paths.is_some_and(|depth| depth != 0);
    if options.target.is_none() && (options.shortest_path || has_all_paths) {
        return usage_error("The target type must be specified to determine a path.");
    }
    if options.target.is_some() && !(options.shortest_path || has_all_paths) {
        return usage_error("A target type is not used for flows in/out of a type.");
    }
    if options.limit_flows < 0 {
        return usage_error("Limit on information flows cannot be negative.");
    }

    let (policy, policy_path) = match load_policy(&options) {
        Ok(loaded) => loaded,
        Err(message) => return analysis_error(&message),
    };
    let permission_map = match load_permission_map(&options) {
        Ok(map) => map,
        Err(message) => return analysis_error(&message),
    };
    if !(1..=10).contains(&options.minimum_weight) {
        return analysis_error("Min information flow weight must be an integer 1-10.");
    }
    if let Err(message) = validate_types(&policy, &options) {
        return analysis_error(&message);
    }
    if has_all_paths && options.all_paths.is_some_and(|depth| depth < 1) {
        return analysis_error("Information flow max depth must be positive.");
    }

    log_message(
        &options,
        "INFO",
        "setools.infoflow",
        &format!(
            "Building information flow graph from {}...",
            policy_path.display()
        ),
    );
    log_message(
        &options,
        "DEBUG",
        "setools.infoflow",
        &format!(
            "self.perm_map=<setools.permmap.PermissionMap object at {:p}>",
            &permission_map
        ),
    );
    let graph = InformationFlowGraph::new(&policy, &permission_map);
    let stats = graph.stats();
    log_message(
        &options,
        "INFO",
        "setools.infoflow",
        "Completed building information flow graph.",
    );
    log_message(
        &options,
        "DEBUG",
        "setools.infoflow",
        &format!(
            "Graph stats: nodes: {}, edges: {}.",
            stats.nodes, stats.edges
        ),
    );
    log_message(
        &options,
        "INFO",
        "setools.infoflow",
        "Building information flow subgraph...",
    );
    log_message(
        &options,
        "DEBUG",
        "setools.infoflow",
        &format!("self.min_weight={}", options.minimum_weight),
    );
    log_message(
        &options,
        "DEBUG",
        "setools.infoflow",
        &format!("self.exclude={}", python_string_list(&options.exclude)),
    );
    log_message(
        &options,
        "DEBUG",
        "setools.infoflow",
        &format!(
            "self.booleans={}",
            python_boolean_map(options.booleans.as_ref())
        ),
    );

    let source = options.source.as_deref().expect("parser requires source");
    let result = if options.shortest_path || has_all_paths {
        let target = options.target.as_deref().expect("validated target");
        if options.shortest_path {
            graph.shortest_paths(
                source,
                target,
                options.minimum_weight,
                &options.exclude,
                options.booleans.as_ref(),
            )
        } else {
            graph.all_paths(
                source,
                target,
                options.all_paths.expect("all-path mode has a depth"),
                options.minimum_weight,
                &options.exclude,
                options.booleans.as_ref(),
            )
        }
        .map(Results::Paths)
    } else if options.reverse {
        graph
            .flows_in(
                source,
                options.minimum_weight,
                &options.exclude,
                options.booleans.as_ref(),
            )
            .map(Results::Flows)
    } else {
        graph
            .flows_out(
                source,
                options.minimum_weight,
                &options.exclude,
                options.booleans.as_ref(),
            )
            .map(Results::Flows)
    };
    let results = match result {
        Ok(results) => results,
        Err(error) => return analysis_error(&error.to_string()),
    };

    log_message(
        &options,
        "INFO",
        "setools.infoflow",
        "Completed building information flow subgraph.",
    );
    let subgraph_stats = graph
        .subgraph_stats(
            options.minimum_weight,
            &options.exclude,
            options.booleans.as_ref(),
        )
        .unwrap_or(stats);
    log_message(
        &options,
        "DEBUG",
        "setools.infoflow",
        &format!(
            "Subgraph stats: nodes: {}, edges: {}.",
            subgraph_stats.nodes, subgraph_stats.edges
        ),
    );
    log_message(
        &options,
        "INFO",
        "setools.infoflow",
        &format!(
            "Generating information flow results from {}",
            policy_path.display()
        ),
    );
    log_query_debug(&policy, &policy_path, &options);
    log_mode(&options);

    if let Some(output_file) = &options.output_file {
        if let Err(message) = write_graphical_results(&policy, &results, output_file) {
            return analysis_error(&message);
        }
        return write_stdout(&render_stats(options.stats, stats));
    }

    match render_results(&policy, &options, results, stats) {
        Ok(output) => write_stdout(&output),
        Err(message) => analysis_error(&message),
    }
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
    let mut boolean_argument = None::<String>;
    let mut index = 0_usize;
    let mut positional_only = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if positional_only {
            options.exclude.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if let Some((name, value)) = argument.split_once('=') {
            match name {
                "--policy" => options.policy = Some(PathBuf::from(value)),
                "--map" => options.permission_map = Some(PathBuf::from(value)),
                "--source" => options.source = Some(value.to_owned()),
                "--target" => options.target = nonempty(value),
                "--all_paths" => options.all_paths = Some(parse_int(name, value)?),
                "--min_weight" => options.minimum_weight = parse_int(name, value)?,
                "--limit_flows" => options.limit_flows = parse_int(name, value)?,
                "--booleans" => boolean_argument = Some(value.to_owned()),
                "--output_file" => options.output_file = Some(PathBuf::from(value)),
                _ => return Err(format!("unrecognized arguments: {argument}")),
            }
            index += 1;
            continue;
        }
        match argument.as_str() {
            "-h" | "--help" => return Ok(ParseAction::Help),
            "--version" => return Ok(ParseAction::Version),
            "--full" => options.full = true,
            "--stats" => options.stats = true,
            "-v" | "--verbose" => options.verbose = true,
            "--debug" => options.debug = true,
            "-p" | "--policy" => {
                options.policy = Some(PathBuf::from(take_value(
                    &arguments,
                    &mut index,
                    "-p/--policy",
                )?));
            }
            "-m" | "--map" => {
                options.permission_map = Some(PathBuf::from(take_value(
                    &arguments, &mut index, "-m/--map",
                )?));
            }
            "-s" | "--source" => {
                options.source = Some(take_value(&arguments, &mut index, "-s/--source")?);
            }
            "-t" | "--target" => {
                let value = take_value(&arguments, &mut index, "-t/--target")?;
                options.target = nonempty(&value);
            }
            "-S" | "--shortest_path" => options.shortest_path = true,
            "-A" | "--all_paths" => {
                let value = take_value(&arguments, &mut index, "-A/--all_paths")?;
                options.all_paths = Some(parse_int("-A/--all_paths", &value)?);
            }
            "-r" | "--reverse" => options.reverse = true,
            "-w" | "--min_weight" => {
                let value = take_value(&arguments, &mut index, "-w/--min_weight")?;
                options.minimum_weight = parse_int("-w/--min_weight", &value)?;
            }
            "-l" | "--limit_flows" => {
                let value = take_value(&arguments, &mut index, "-l/--limit_flows")?;
                options.limit_flows = parse_int("-l/--limit_flows", &value)?;
            }
            "-b" | "--booleans" => {
                boolean_argument = Some(take_value(&arguments, &mut index, "-b/--booleans")?);
            }
            "-o" | "--output_file" => {
                options.output_file = Some(PathBuf::from(take_value(
                    &arguments,
                    &mut index,
                    "-o/--output_file",
                )?));
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unrecognized arguments: {argument}"));
            }
            _ => options.exclude.push(argument.clone()),
        }
        index += 1;
    }
    if options.source.is_none() {
        return Err("the following arguments are required: -s/--source".to_owned());
    }
    options.booleans = parse_booleans(boolean_argument.as_deref())?;
    Ok(ParseAction::Run(options))
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_booleans(value: Option<&str>) -> Result<Option<BTreeMap<String, bool>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value == "default" {
        return Ok(Some(BTreeMap::new()));
    }
    let mut output = BTreeMap::new();
    for assignment in value.split(',') {
        let parts = assignment.split(':').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err("Expected boolean format foo:true,bar:false".to_owned());
        }
        let state = if parts[1].eq_ignore_ascii_case("true") {
            true
        } else if parts[1].eq_ignore_ascii_case("false") {
            false
        } else {
            return Err("Conditional value must be true or false.".to_owned());
        };
        output.insert(parts[0].to_owned(), state);
    }
    Ok(Some(output))
}

fn take_value(arguments: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("argument {option}: expected one argument"))
}

fn parse_int(option: &str, value: &str) -> Result<i32, String> {
    value
        .parse()
        .map_err(|_| format!("argument {option}: invalid int value: '{value}'"))
}

fn load_permission_map(options: &Options) -> Result<PermissionMap, String> {
    let source = options
        .permission_map
        .as_ref()
        .map_or("<built-in permission map>".to_owned(), |path| {
            path.display().to_string()
        });
    log_message(
        options,
        "INFO",
        "setools.permmap",
        &format!("Opening permission map \"{source}\""),
    );
    let map = if let Some(path) = &options.permission_map {
        PermissionMap::from_file(path)
    } else {
        PermissionMap::built_in()
    }
    .map_err(|error| error.to_string())?;
    for mapping in map.mappings() {
        log_message(
            options,
            "DEBUG",
            "setools.permmap",
            &format!(
                "Read {}:{} {} {}",
                mapping.class(),
                mapping.permission(),
                mapping.direction().code(),
                mapping.weight()
            ),
        );
        if mapping.direction() == PermissionDirection::Unmapped {
            log_message(
                options,
                "INFO",
                "setools.permmap",
                &format!(
                    "Permission {}:{} is unmapped.",
                    mapping.class(),
                    mapping.permission()
                ),
            );
        }
    }
    log_message(
        options,
        "INFO",
        "setools.permmap",
        &format!("Successfully opened permission map \"{source}\""),
    );
    log_message(
        options,
        "DEBUG",
        "setools.permmap",
        &format!(
            "Read {} classes and {} total permissions.",
            map.class_count(),
            map.mappings().len()
        ),
    );
    Ok(map)
}

fn render_results(
    policy: &Policy,
    options: &Options,
    results: Results<'_>,
    stats: InformationFlowStats,
) -> Result<String, String> {
    let mut output = String::new();
    match results {
        Results::Flows(flows) => {
            let mut count = 0_usize;
            for flow in flows {
                count += 1;
                output.push_str(&format!(
                    "Flow {count}: {}",
                    render_step(policy, &flow, options.full)?
                ));
                output.push('\n');
                if options.full {
                    output.push('\n');
                }
                if options.limit_flows != 0 && count as i32 >= options.limit_flows {
                    break;
                }
            }
            output.push_str(&format!("\n{count} information flow(s) found.\n"));
        }
        Results::Paths(paths) => {
            let mut count = 0_usize;
            for path in paths {
                count += 1;
                output.push_str(&format!("Flow {count}:\n"));
                for (number, step) in path.iter().enumerate() {
                    output.push_str(&format!(
                        "  Step {}: {}\n",
                        number + 1,
                        render_step(policy, step, options.full)?
                    ));
                    if options.full {
                        output.push('\n');
                    }
                }
                if options.limit_flows != 0 && count as i32 >= options.limit_flows {
                    break;
                }
            }
            output.push_str(&format!("\n{count} information flow(s) found.\n"));
        }
    }
    output.push_str(&render_stats(options.stats, stats));
    Ok(output)
}

fn render_step(
    policy: &Policy,
    step: &InformationFlowStep<'_>,
    full: bool,
) -> Result<String, String> {
    let source = type_name(policy, step.source())?;
    let target = type_name(policy, step.target())?;
    if !full {
        return Ok(format!("{source} -> {target}"));
    }
    let mut rules = step
        .rules()
        .iter()
        .map(|rule| render_rule(policy, rule))
        .collect::<Result<Vec<_>, _>>()?;
    rules.sort_unstable();
    Ok(format!(
        "{source} -> {target}\n{}",
        rules
            .into_iter()
            .map(|rule| format!("   {rule}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

fn render_stats(enabled: bool, stats: InformationFlowStats) -> String {
    if !enabled {
        return String::new();
    }
    format!(
        "\nGraph statistics:\n\
         nx.number_of_nodes(self.G)={}\n\
         nx.number_of_edges(self.G)={}\n\
         len(self.G)={}\n\n",
        stats.nodes, stats.edges, stats.nodes
    )
}

fn validate_types(policy: &Policy, options: &Options) -> Result<(), String> {
    for name in options
        .exclude
        .iter()
        .chain(options.source.iter())
        .chain(options.target.iter())
    {
        let Some(symbol) = policy.type_symbol_by_name(name) else {
            return Err(format!("{name} is not a valid type"));
        };
        if !matches!(symbol.id(), TypeOrAttributeId::Type(_)) {
            return Err(format!("{name} is not a valid type"));
        }
    }
    Ok(())
}

fn write_graphical_results(
    policy: &Policy,
    results: &Results<'_>,
    output_file: &Path,
) -> Result<(), String> {
    let steps = match results {
        Results::Flows(flows) => flows.iter().collect::<Vec<_>>(),
        Results::Paths(paths) => paths.iter().flatten().collect::<Vec<_>>(),
    };
    let mut edges = Vec::<(String, String)>::new();
    for step in steps {
        let pair = (
            type_name(policy, step.source())?.to_owned(),
            type_name(policy, step.target())?.to_owned(),
        );
        if !edges.contains(&pair) {
            edges.push(pair);
        }
    }
    let mut dot = String::from("digraph seinfoflow {\n");
    for (source, target) in edges {
        dot.push_str(&format!(
            "    \"{}\" -> \"{}\";\n",
            escape_dot(&source),
            escape_dot(&target)
        ));
    }
    dot.push_str("}\n");

    let mut child = Command::new("dot")
        .arg("-Tpng")
        .arg("-o")
        .arg(output_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                "requires pygraphviz http://pygraphviz.github.io/".to_owned()
            } else {
                error.to_string()
            }
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| "could not open Graphviz input".to_owned())?
        .write_all(dot.as_bytes())
        .map_err(|error| error.to_string())?;
    let result = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if result.status.success() {
        Ok(())
    } else {
        let message = String::from_utf8_lossy(&result.stderr).trim().to_owned();
        Err(if message.is_empty() {
            "Graphviz failed to render the information flow graph.".to_owned()
        } else {
            message
        })
    }
}

fn escape_dot(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn type_name(policy: &Policy, id: TypeId) -> Result<&str, String> {
    policy
        .type_symbol(TypeOrAttributeId::Type(id))
        .map(|symbol| symbol.name())
        .ok_or_else(|| "information flow refers to a missing type".to_owned())
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
            &format!("SELinuxfs exists: {}", python_bool(info.selinuxfs_exists)),
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

fn python_string_list(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn python_boolean_map(values: Option<&BTreeMap<String, bool>>) -> String {
    values.map_or_else(
        || "None".to_owned(),
        |values| {
            format!(
                "{{{}}}",
                values
                    .iter()
                    .map(|(name, state)| format!("'{name}': {}", python_bool(*state)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    )
}

const fn python_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
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

fn log_mode(options: &Options) {
    let source = options.source.as_deref().expect("parser requires source");
    if options.shortest_path {
        log_message(
            options,
            "INFO",
            "setools.infoflow",
            &format!(
                "Generating all shortest information flow paths from {source} to {}...",
                options.target.as_deref().expect("validated target")
            ),
        );
    } else if let Some(depth) = options.all_paths.filter(|depth| *depth != 0) {
        log_message(
            options,
            "INFO",
            "setools.infoflow",
            &format!(
                "Generating all information flow paths from {source} to {}, max length {depth}...",
                options.target.as_deref().expect("validated target")
            ),
        );
    } else if options.reverse {
        log_message(
            options,
            "INFO",
            "setools.infoflow",
            &format!("Generating all information flows into {source} "),
        );
    } else {
        log_message(
            options,
            "INFO",
            "setools.infoflow",
            &format!("Generating all information flows out of {source}, max depth 1"),
        );
    }
}

fn log_query_debug(policy: &Policy, policy_path: &Path, options: &Options) {
    if !options.debug {
        return;
    }
    let path_mode = options.shortest_path || options.all_paths.is_some_and(|depth| depth != 0);
    let (source, target) = if path_mode {
        (
            type_debug_repr(policy, policy_path, options.source.as_deref()),
            type_debug_repr(policy, policy_path, options.target.as_deref()),
        )
    } else if options.reverse {
        (
            "None".to_owned(),
            type_debug_repr(policy, policy_path, options.source.as_deref()),
        )
    } else {
        (
            type_debug_repr(policy, policy_path, options.source.as_deref()),
            "None".to_owned(),
        )
    };
    log_message(
        options,
        "DEBUG",
        "setools.infoflow",
        &format!("self.source={source}"),
    );
    log_message(
        options,
        "DEBUG",
        "setools.infoflow",
        &format!("self.target={target}"),
    );
    let (mode, depth) = if options.shortest_path {
        ("<Mode.ShortestPaths: 'All shortest paths'>", 1)
    } else if let Some(depth) = options.all_paths.filter(|depth| *depth != 0) {
        ("<Mode.AllPaths: 'All paths up to'>", depth)
    } else if options.reverse {
        ("<Mode.FlowsIn: 'Flows into the target type.'>", 1)
    } else {
        ("<Mode.FlowsOut: 'Flows out of the source type.'>", 1)
    };
    log_message(
        options,
        "DEBUG",
        "setools.infoflow",
        &format!("self.mode={mode}, self.depth_limit={depth}"),
    );
}

fn type_debug_repr(policy: &Policy, policy_path: &Path, name: Option<&str>) -> String {
    let Some(name) = name else {
        return "None".to_owned();
    };
    let canonical = policy
        .type_symbol_by_name(name)
        .map_or(name, |symbol| symbol.name());
    format!(
        "<Type(<SELinuxPolicy(\"{}\")>, \"{canonical}\")>",
        policy_path.display()
    )
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

fn usage_error(message: &str) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{USAGE}seinfoflow: error: {message}");
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
