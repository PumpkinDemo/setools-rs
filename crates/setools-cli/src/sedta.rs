//! `sedta` argument parsing, graph queries, and compatibility text rendering.

use crate::sesearch::render_rule;
use setools_graph::{DomainEntrypoint, DomainTransition, DomainTransitionGraph};
use setools_policy::{Policy, PolicyLoader, TypeId, TypeOrAttributeId};
use setools_sepol::{
    LibsepolLoader, LoadError, local_log_timestamp, running_policy_info, use_default_sigpipe,
};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const HELP: &str = include_str!("../assets/sedta-help.txt");

const USAGE: &str = r"usage: sedta [-h] [--version] [-p POLICY] -s SOURCE [-t TARGET] [--full]
             [--stats] [-v] [--debug] [-S] [-A MAX_STEPS] [-r]
             [-l LIMIT_TRANS] [-o OUTPUT_FILE]
             [exclude ...]
";

#[derive(Debug, Default)]
struct Options {
    policy: Option<PathBuf>,
    source: Option<String>,
    target: Option<String>,
    full: bool,
    stats: bool,
    verbose: bool,
    debug: bool,
    shortest_path: bool,
    all_paths: Option<i32>,
    reverse: bool,
    limit_trans: i32,
    output_file: Option<PathBuf>,
    exclude: Vec<String>,
}

enum ParseAction {
    Run(Options),
    Help,
    Version,
}

/// Runs `sedta` with already separated process arguments.
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
        return usage_error("An algorithm must be specified to determine a path.");
    }

    let (policy, policy_path) = match load_policy(&options) {
        Ok(loaded) => loaded,
        Err(message) => return analysis_error(&message),
    };
    if let Err(message) = validate_types(&policy, &options) {
        return analysis_error(&message);
    }
    if has_all_paths && options.all_paths.is_some_and(|depth| depth < 1) {
        return analysis_error("Domain transition max depth must be positive.");
    }
    let query_reverse = (options.shortest_path || has_all_paths) && options.reverse;
    log_message(
        &options,
        "INFO",
        "setools.dta",
        &format!(
            "Building domain transition graph from {}...",
            policy_path.display()
        ),
    );
    let graph = DomainTransitionGraph::new(&policy);
    log_message(
        &options,
        "INFO",
        "setools.dta",
        "Completed building domain transition graph.",
    );
    let stats = graph.stats();
    log_message(
        &options,
        "DEBUG",
        "setools.dta",
        &format!(
            "Graph stats: nodes: {}, edges: {}.",
            stats.nodes, stats.edges
        ),
    );
    log_message(
        &options,
        "INFO",
        "setools.dta",
        "Building domain transition subgraph.",
    );
    log_message(
        &options,
        "DEBUG",
        "setools.dta",
        &format!(
            "self.reverse={} self.exclude={}",
            python_bool(query_reverse),
            python_string_list(&options.exclude)
        ),
    );

    let source = options.source.as_deref().expect("parser requires source");
    let result = if options.shortest_path || has_all_paths {
        let target = options.target.as_deref().expect("validated target");
        if options.shortest_path {
            graph.shortest_paths(source, target, options.reverse, &options.exclude)
        } else {
            graph.all_paths(
                source,
                target,
                options.all_paths.expect("all-path mode has a depth"),
                options.reverse,
                &options.exclude,
            )
        }
        .map(Results::Paths)
    } else if options.reverse {
        graph
            .transitions_in(source, &options.exclude)
            .map(Results::Transitions)
    } else {
        graph
            .transitions_out(source, &options.exclude)
            .map(Results::Transitions)
    };
    let results = match result {
        Ok(results) => results,
        Err(error) => return analysis_error(&error.to_string()),
    };
    log_message(
        &options,
        "INFO",
        "setools.dta",
        "Completed building domain transition subgraph.",
    );
    log_message(
        &options,
        "DEBUG",
        "setools.dta",
        &match graph.subgraph_stats(&options.exclude) {
            Ok(subgraph) => format!(
                "Subgraph stats: nodes: {}, edges: {}.",
                subgraph.nodes, subgraph.edges
            ),
            Err(_) => format!(
                "Subgraph stats: nodes: {}, edges: {}.",
                stats.nodes, stats.edges
            ),
        },
    );
    log_message(
        &options,
        "INFO",
        "setools.dta",
        &format!(
            "Generating domain transition results from {}",
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

    let output = match render_results(&policy, &options, results, stats) {
        Ok(output) => output,
        Err(message) => return analysis_error(&message),
    };
    write_stdout(&output)
}

enum Results<'policy> {
    Transitions(Vec<DomainTransition<'policy>>),
    Paths(Vec<Vec<DomainTransition<'policy>>>),
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
                "--source" => options.source = Some(value.to_owned()),
                "--target" => options.target = Some(value.to_owned()),
                "--all_paths" => options.all_paths = Some(parse_int(name, value)?),
                "--limit_trans" => options.limit_trans = parse_int(name, value)?,
                "--output_file" => options.output_file = Some(PathBuf::from(value)),
                _ => return Err(format!("unrecognized arguments: {argument}")),
            }
            index += 1;
            continue;
        }
        match argument.as_str() {
            "-h" | "--help" => return Ok(ParseAction::Help),
            "--version" => return Ok(ParseAction::Version),
            "-p" | "--policy" => {
                options.policy = Some(PathBuf::from(take_value(
                    &arguments,
                    &mut index,
                    "-p/--policy",
                )?));
            }
            "-s" | "--source" => {
                options.source = Some(take_value(&arguments, &mut index, "-s/--source")?);
            }
            "-t" | "--target" => {
                options.target = Some(take_value(&arguments, &mut index, "-t/--target")?);
            }
            "--full" => options.full = true,
            "--stats" => options.stats = true,
            "-v" | "--verbose" => options.verbose = true,
            "--debug" => options.debug = true,
            "-S" | "--shortest_path" => options.shortest_path = true,
            "-A" | "--all_paths" => {
                let value = take_value(&arguments, &mut index, "-A/--all_paths")?;
                options.all_paths = Some(parse_int("-A/--all_paths", &value)?);
            }
            "-r" | "--reverse" => options.reverse = true,
            "-l" | "--limit_trans" => {
                let value = take_value(&arguments, &mut index, "-l/--limit_trans")?;
                options.limit_trans = parse_int("-l/--limit_trans", &value)?;
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
    Ok(ParseAction::Run(options))
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

fn render_results(
    policy: &Policy,
    options: &Options,
    results: Results<'_>,
    stats: setools_graph::DomainTransitionStats,
) -> Result<String, String> {
    let mut output = String::new();
    match results {
        Results::Transitions(transitions) => {
            let mut count = 0_usize;
            for transition in transitions {
                count += 1;
                if options.full {
                    output.push_str(&format!(
                        "Transition {count}: {}\n\n",
                        render_transition(policy, &transition, true)?
                    ));
                } else {
                    output.push_str(&format!(
                        "Transition {count}: {}\n",
                        render_transition(policy, &transition, false)?
                    ));
                }
                if options.limit_trans != 0 && count as i32 >= options.limit_trans {
                    break;
                }
            }
            output.push_str(&format!("\n{count} domain transition(s) found.\n"));
        }
        Results::Paths(paths) => {
            let mut count = 0_usize;
            for path in paths {
                count += 1;
                output.push_str(&format!("Domain transition path {count}:\n"));
                for (step, transition) in path.iter().enumerate() {
                    if options.full {
                        output.push_str(&format!(
                            "Step {}: {}\n\n",
                            step + 1,
                            render_transition(policy, transition, true)?
                        ));
                    } else {
                        output.push_str(&format!(
                            "Step {}: {}\n",
                            step + 1,
                            render_transition(policy, transition, false)?
                        ));
                    }
                }
                if options.limit_trans != 0 && count as i32 >= options.limit_trans {
                    break;
                }
                output.push('\n');
            }
            output.push_str(&format!("\n{count} domain transition path(s) found.\n"));
        }
    }
    output.push_str(&render_stats(options.stats, stats));
    Ok(output)
}

fn render_stats(enabled: bool, stats: setools_graph::DomainTransitionStats) -> String {
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
    let transitions = match results {
        Results::Transitions(transitions) => transitions.iter().collect::<Vec<_>>(),
        Results::Paths(paths) => paths.iter().flatten().collect::<Vec<_>>(),
    };
    let mut edges = Vec::<(String, String)>::new();
    for transition in transitions {
        let pair = (
            type_name(policy, transition.source())?.to_owned(),
            type_name(policy, transition.target())?.to_owned(),
        );
        if !edges.contains(&pair) {
            edges.push(pair);
        }
    }
    let mut dot = String::from("digraph sedta {\n");
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
            "Graphviz failed to render the domain transition graph.".to_owned()
        } else {
            message
        })
    }
}

fn escape_dot(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_transition(
    policy: &Policy,
    transition: &DomainTransition<'_>,
    full: bool,
) -> Result<String, String> {
    let source = type_name(policy, transition.source())?;
    let target = type_name(policy, transition.target())?;
    if !full {
        return Ok(format!("{source} -> {target}\n"));
    }

    let mut lines = vec![format!("{source} -> {target}\n")];
    if !transition.transition_rules().is_empty() {
        lines.push("Domain transition rule(s):".to_owned());
        lines.extend(render_rules(policy, transition.transition_rules())?);
        if !transition.setexec_rules().is_empty() {
            lines.push("\nSet execution context rule(s):".to_owned());
            lines.extend(render_rules(policy, transition.setexec_rules())?);
        }
        for entrypoint in transition.entrypoints() {
            lines.push(format!("{}\n", render_entrypoint(policy, entrypoint)?));
        }
    }
    if !transition.dyntransition_rules().is_empty() {
        lines.push("Dynamic transition rule(s):".to_owned());
        lines.extend(render_rules(policy, transition.dyntransition_rules())?);
        lines.push("\nSet current process context rule(s):".to_owned());
        lines.extend(render_rules(policy, transition.setcurrent_rules())?);
        lines.push(String::new());
    }
    Ok(lines.join("\n"))
}

fn render_entrypoint(policy: &Policy, entrypoint: &DomainEntrypoint<'_>) -> Result<String, String> {
    let name = type_name(policy, entrypoint.name())?;
    let mut lines = vec![
        format!("\nEntrypoint {name}:"),
        "\tDomain entrypoint rule(s):".to_owned(),
    ];
    lines.extend(
        render_rules(policy, entrypoint.entrypoint_rules())?
            .into_iter()
            .map(|rule| format!("\t{rule}")),
    );
    lines.push("\n\tFile execute rule(s):".to_owned());
    lines.extend(
        render_rules(policy, entrypoint.execute_rules())?
            .into_iter()
            .map(|rule| format!("\t{rule}")),
    );
    if !entrypoint.type_transition_rules().is_empty() {
        lines.push("\n\tType transition rule(s):".to_owned());
        lines.extend(
            render_rules(policy, entrypoint.type_transition_rules())?
                .into_iter()
                .map(|rule| format!("\t{rule}")),
        );
    }
    Ok(lines.join("\n"))
}

fn render_rules(policy: &Policy, rules: &[&setools_policy::TeRule]) -> Result<Vec<String>, String> {
    let mut rendered = rules
        .iter()
        .map(|rule| render_rule(policy, rule))
        .collect::<Result<Vec<_>, _>>()?;
    rendered.sort_unstable();
    Ok(rendered)
}

fn type_name(policy: &Policy, id: TypeId) -> Result<&str, String> {
    policy
        .type_symbol(TypeOrAttributeId::Type(id))
        .map(|symbol| symbol.name())
        .ok_or_else(|| "domain transition refers to a missing type".to_owned())
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
            "setools.dta",
            &format!(
                "Generating all shortest domain transition paths from {source} to {}...",
                options.target.as_deref().expect("validated target")
            ),
        );
    } else if options.all_paths.is_some_and(|depth| depth != 0) {
        log_message(
            options,
            "INFO",
            "setools.dta",
            &format!(
                "Generating all domain transition paths from {source} to {}, max length {}...",
                options.target.as_deref().expect("validated target"),
                options.all_paths.expect("mode checked")
            ),
        );
    } else if options.reverse {
        log_message(
            options,
            "INFO",
            "setools.dta",
            &format!("Generating all domain transitions into {source}"),
        );
    } else {
        log_message(
            options,
            "INFO",
            "setools.dta",
            &format!("Generating all domain transitions out of {source}"),
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
        "setools.dta",
        &format!("self.source={source}"),
    );
    log_message(
        options,
        "DEBUG",
        "setools.dta",
        &format!("self.target={target}"),
    );
    let (mode, depth) = if options.shortest_path {
        ("<Mode.ShortestPaths: 'All shortest paths'>", 1)
    } else if let Some(depth) = options.all_paths.filter(|depth| *depth != 0) {
        ("<Mode.AllPaths: 'All paths up to'>", depth)
    } else if options.reverse {
        (
            "<Mode.TransitionsIn: 'Transitions into the target domain.'>",
            1,
        )
    } else {
        (
            "<Mode.TransitionsOut: 'Transitions out of the source domain.'>",
            1,
        )
    };
    log_message(
        options,
        "DEBUG",
        "setools.dta",
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
    let _ = writeln!(stderr, "{USAGE}sedta: error: {message}");
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
