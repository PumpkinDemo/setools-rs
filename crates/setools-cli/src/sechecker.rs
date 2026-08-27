//! `sechecker` argument parsing and compatibility report rendering.

use crate::json;
use crate::sesearch::{render_rbac_rule, render_rule};
use setools_checker::{
    CheckDebug, CheckOutcome, CheckResult, CheckType, Checker, NoticeLevel, RbacQuerySettings,
    ReadOnlyKind, TeQuerySettings,
};
use setools_policy::{Policy, PolicyLoader};
use setools_sepol::{
    LibsepolLoader, LoadError, local_log_timestamp, running_policy_info, use_default_sigpipe,
};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const HELP: &str = include_str!("../assets/sechecker-help.txt");
const USAGE: &str = "usage: sechecker [-h] [--version] [-o OUTPUT_FILE] [-v] [--debug]\n                 config [policy]\n";
const SECTION_SEPARATOR: &str = "---------------------------------------------------------\n\n";

#[derive(Debug, Default)]
struct Options {
    config: Option<PathBuf>,
    policy: Option<PathBuf>,
    output_file: Option<PathBuf>,
    json: bool,
    verbose: bool,
    debug: bool,
}

enum ParseAction {
    Run(Options),
    Help,
    Version,
}

/// Runs `sechecker` with already separated process arguments.
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
    if options.json && options.output_file.is_some() {
        return usage_error("--json cannot be used with --output_file.");
    }
    let config_path = options
        .config
        .as_ref()
        .expect("validated parser must set config");
    let (policy, policy_path) = match load_policy(&options) {
        Ok(value) => value,
        Err(message) => return operational_error(&options, &message),
    };
    log_message(
        &options,
        "INFO",
        "setools.checker.checker",
        &format!("Opening policy checker config {}.", config_path.display()),
    );
    let contents = match fs::read_to_string(config_path) {
        Ok(value) => value,
        Err(error) => {
            let cause = compat_io_error(config_path, &error);
            return config_error(
                &options,
                &format!(
                    "Unable to parse checker config {}: {cause}",
                    config_path.display()
                ),
            );
        }
    };
    log_message(
        &options,
        "INFO",
        "setools.checker.checker",
        "Validating configuration settings.",
    );
    let checker = match Checker::from_config(&policy, &config_path.display().to_string(), &contents)
    {
        Ok(checker) => checker,
        Err(error) => return config_error(&options, &error.to_string()),
    };
    for notice in checker.notices() {
        let level = match notice.level {
            NoticeLevel::Info => "INFO",
            NoticeLevel::Debug => "DEBUG",
        };
        log_message(&options, level, notice.module, &notice.message);
    }
    log_message(
        &options,
        "INFO",
        "setools.checker.checker",
        &format!(
            "Successfully opened policy checker config {}.",
            config_path.display()
        ),
    );

    let start_time = utc_now();
    let results = checker.run();
    for result in &results {
        if matches!(result.outcome, CheckOutcome::Disabled { .. }) {
            if let CheckOutcome::Disabled { reason } = &result.outcome {
                log_message(
                    &options,
                    "DEBUG",
                    "setools.checker.checker",
                    &format!("Skipping disabled check {}: {reason}", result.name),
                );
            }
            continue;
        }
        log_message(
            &options,
            "DEBUG",
            "setools.checker.checker",
            &format!(
                "Running check {}, type {}.",
                result.name,
                result.check_type.name()
            ),
        );
        let message = match (&result.check_type, &result.outcome) {
            (CheckType::EmptyTypeAttribute, CheckOutcome::EmptyTypeAttribute { attribute, .. }) => {
                format!("Checking type attribute {attribute} is empty.")
            }
            _ => result.check_type.run_message().to_owned(),
        };
        log_message(&options, "INFO", result.check_type.logger(), &message);
        log_check_trace(&options, &policy, &policy_path, result);
    }
    let end_time = utc_now();
    let report = match if options.json {
        render_json(&policy, config_path, &policy_path, &results)
    } else {
        render_report(
            &policy,
            config_path,
            &policy_path,
            &start_time,
            &end_time,
            &results,
        )
    } {
        Ok(value) => value,
        Err(message) => return operational_error(&options, &message),
    };
    let failures = results
        .iter()
        .map(CheckResult::failure_count)
        .sum::<usize>();
    log_message(
        &options,
        "INFO",
        "setools.checker.checker",
        &format!("{failures} failures found in {} checks.", checker.len()),
    );
    let output_status = if let Some(path) = &options.output_file {
        match fs::write(path, report) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => return operational_error(&options, &compat_io_error(path, &error)),
        }
    } else {
        write_stdout(&report)
    };
    if output_status != ExitCode::SUCCESS {
        output_status
    } else if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
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
    let mut index = 0_usize;
    let mut positional_only = false;
    let mut unrecognized = Vec::new();
    while index < arguments.len() {
        let argument = &arguments[index];
        if positional_only {
            set_positional(&mut options, argument)?;
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
            "--json" => options.json = true,
            "-v" | "--verbose" => options.verbose = true,
            "--debug" => options.debug = true,
            "-o" | "--output_file" => {
                options.output_file =
                    Some(PathBuf::from(take_value(&arguments, &mut index, argument)?));
            }
            _ if argument.starts_with("--output_file=") => {
                let value = argument
                    .split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or_default();
                if value.is_empty() {
                    return Err("argument -o/--output_file: expected one argument".to_owned());
                }
                options.output_file = Some(PathBuf::from(value));
            }
            _ if argument.starts_with('-') => {
                unrecognized.push(argument.clone());
            }
            _ => set_positional(&mut options, argument)?,
        }
        index += 1;
    }
    if options.config.is_none() {
        return Err("the following arguments are required: config".to_owned());
    }
    if !unrecognized.is_empty() {
        return Err(format!(
            "unrecognized arguments: {}",
            unrecognized.join(" ")
        ));
    }
    Ok(ParseAction::Run(options))
}

fn take_value(arguments: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    arguments.get(*index).cloned().ok_or_else(|| {
        if option == "-o" || option == "--output_file" {
            "argument -o/--output_file: expected one argument".to_owned()
        } else {
            format!("argument {option}: expected one argument")
        }
    })
}

fn set_positional(options: &mut Options, value: &str) -> Result<(), String> {
    if options.config.is_none() {
        options.config = Some(PathBuf::from(value));
    } else if options.policy.is_none() {
        options.policy = Some(PathBuf::from(value));
    } else {
        return Err(format!("unrecognized arguments: {value}"));
    }
    Ok(())
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

fn render_report(
    policy: &Policy,
    config_path: &Path,
    policy_path: &Path,
    start_time: &str,
    end_time: &str,
    results: &[CheckResult<'_>],
) -> Result<String, String> {
    let mut output = String::new();
    output.push_str(SECTION_SEPARATOR);
    output.push_str(&format!(
        "Policy check configuration: {}\nPolicy being checked: {}\nStart time: {start_time}\n\n",
        config_path.display(),
        policy_path.display()
    ));
    let mut summary = Vec::new();
    let mut failures = 0_usize;
    for result in results {
        output.push_str(SECTION_SEPARATOR);
        output.push_str(&format!("Check name: {}\n\n", result.name));
        if let Some(description) = &result.description {
            output.push_str(&format!("Description: {description}\n\n"));
        }
        if let CheckOutcome::Disabled { reason } = &result.outcome {
            output.push_str(&format!("Check DISABLED.  Reason: {reason}\n\n"));
            summary.push((result.name.clone(), format!("DISABLED ({reason})")));
            continue;
        }
        render_outcome(policy, &result.outcome, &mut output)?;
        output.push('\n');
        let count = result.failure_count();
        if count == 0 {
            output.push_str("Check PASSED\n\n");
            summary.push((result.name.clone(), "PASSED".to_owned()));
        } else {
            output.push_str("Check FAILED\n\n");
            summary.push((result.name.clone(), format!("FAILED ({count} failures)")));
        }
        failures += count;
    }
    output.push_str(SECTION_SEPARATOR);
    output.push_str("Result Summary:\n\n");
    for (name, result) in summary {
        output.push_str(&format!("{name:<39} {result}\n"));
    }
    output.push_str(&format!(
        "\n{failures} failure(s) found.\n\nPolicy check configuration: {}\nPolicy being checked: {}\nEnd time: {end_time}\n",
        config_path.display(),
        policy_path.display()
    ));
    Ok(output)
}

fn render_outcome(
    policy: &Policy,
    outcome: &CheckOutcome<'_>,
    output: &mut String,
) -> Result<(), String> {
    match outcome {
        CheckOutcome::Disabled { .. } => {}
        CheckOutcome::EmptyTypeAttribute {
            attribute,
            missing,
            members,
        } => {
            if *missing {
                output.push_str(&format!("    {attribute} does not exist.\n"));
            } else {
                output.push_str(&format!("Member types of {attribute}:\n"));
                for member in members {
                    output.push_str(&format!("    * {member}\n"));
                }
            }
        }
        CheckOutcome::AssertTe {
            rules,
            missing_sources,
            missing_targets,
        } => {
            let mut rendered = rules
                .iter()
                .map(|rule| render_rule(policy, rule))
                .collect::<Result<Vec<_>, _>>()?;
            rendered.sort_unstable();
            for rule in rendered {
                output.push_str(&format!("    * {rule}\n"));
            }
            for source in missing_sources {
                output.push_str(&format!(
                    "    * Expected rule with source \"{source}\" not found.\n"
                ));
            }
            for target in missing_targets {
                output.push_str(&format!(
                    "    * Expected rule with target \"{target}\" not found.\n"
                ));
            }
        }
        CheckOutcome::AssertRbac {
            rules,
            missing_sources,
            missing_targets,
        } => {
            let mut rendered = rules
                .iter()
                .map(|rule| render_rbac_rule(policy, rule))
                .collect::<Result<Vec<_>, _>>()?;
            rendered.sort_unstable();
            for rule in rendered {
                output.push_str(&format!("    * {rule}\n"));
            }
            for source in missing_sources {
                output.push_str(&format!(
                    "    * Expected rule with source \"{source}\" not found.\n"
                ));
            }
            for target in missing_targets {
                output.push_str(&format!(
                    "    * Expected rule with target \"{target}\" not found.\n"
                ));
            }
        }
        CheckOutcome::ReadOnly { kind, files, .. } => {
            for file in files {
                output.push_str("\n------------\n\n");
                match kind {
                    ReadOnlyKind::Executable => output.push_str(&format!(
                        "Executable type {} is writable.\n\nExecute rules:\n",
                        file.type_name
                    )),
                    ReadOnlyKind::KernelModule => output.push_str(&format!(
                        "Kernel module type {} is writable.\n\nModule load rules:\n",
                        file.type_name
                    )),
                }
                let mut use_rules = file
                    .use_rules
                    .iter()
                    .map(|rule| render_rule(policy, rule))
                    .collect::<Result<Vec<_>, _>>()?;
                use_rules.sort_unstable();
                use_rules.dedup();
                for rule in use_rules {
                    output.push_str(&format!("    * {rule}\n"));
                }
                output.push_str("\nWrite rules:\n");
                let mut write_rules = file
                    .write_rules
                    .iter()
                    .map(|rule| render_rule(policy, rule))
                    .collect::<Result<Vec<_>, _>>()?;
                write_rules.sort_unstable();
                write_rules.dedup();
                for rule in write_rules {
                    output.push_str(&format!("    * {rule}\n"));
                }
            }
        }
        CheckOutcome::Unexpected { message } => {
            output.push_str(&format!("Unexpected error: {message}.  Failing check.\n\n"));
        }
    }
    Ok(())
}

fn render_json(
    policy: &Policy,
    config_path: &Path,
    policy_path: &Path,
    results: &[CheckResult<'_>],
) -> Result<String, String> {
    let failure_count = results
        .iter()
        .map(CheckResult::failure_count)
        .sum::<usize>();
    let mut passed_check_count = 0_usize;
    let mut failed_check_count = 0_usize;
    let mut disabled_check_count = 0_usize;
    for result in results {
        match result_status(result) {
            "passed" => passed_check_count += 1,
            "failed" => failed_check_count += 1,
            "disabled" => disabled_check_count += 1,
            _ => unreachable!("result status is a closed set"),
        }
    }

    let mut output = String::new();
    output.push_str(
        "{\"schema\":\"setools-rs.sechecker\",\"schema_version\":1,\"tool\":{\"name\":\"sechecker\",\"version\":",
    );
    json::push_string(&mut output, env!("CARGO_PKG_VERSION"));
    output.push_str("},\"policy\":{\"path\":");
    json::push_string(&mut output, &policy_path.to_string_lossy());
    output.push_str("},\"query\":{\"configuration_path\":");
    json::push_string(&mut output, &config_path.to_string_lossy());
    output.push_str("},\"summary\":{\"check_count\":");
    output.push_str(&results.len().to_string());
    output.push_str(",\"passed_check_count\":");
    output.push_str(&passed_check_count.to_string());
    output.push_str(",\"failed_check_count\":");
    output.push_str(&failed_check_count.to_string());
    output.push_str(",\"disabled_check_count\":");
    output.push_str(&disabled_check_count.to_string());
    output.push_str(",\"failure_count\":");
    output.push_str(&failure_count.to_string());
    output.push_str("},\"result_count\":");
    output.push_str(&results.len().to_string());
    output.push_str(",\"results\":[");
    for (index, result) in results.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_result(&mut output, policy, result)?;
    }
    output.push_str("]}\n");
    Ok(output)
}

fn push_json_result(
    output: &mut String,
    policy: &Policy,
    result: &CheckResult<'_>,
) -> Result<(), String> {
    output.push_str("{\"name\":");
    json::push_string(output, &result.name);
    output.push_str(",\"description\":");
    push_json_optional_string(output, result.description.as_deref());
    output.push_str(",\"check_type\":");
    json::push_string(output, result.check_type.name());
    output.push_str(",\"status\":");
    json::push_string(output, result_status(result));
    output.push_str(",\"failure_count\":");
    output.push_str(&result.failure_count().to_string());
    output.push_str(",\"details\":");
    push_json_outcome(output, policy, &result.outcome)?;
    output.push('}');
    Ok(())
}

fn push_json_outcome(
    output: &mut String,
    policy: &Policy,
    outcome: &CheckOutcome<'_>,
) -> Result<(), String> {
    match outcome {
        CheckOutcome::Disabled { reason } => {
            output.push_str("{\"kind\":\"disabled\",\"reason\":");
            json::push_string(output, reason);
            output.push('}');
        }
        CheckOutcome::EmptyTypeAttribute {
            attribute,
            missing,
            members,
        } => {
            output.push_str("{\"kind\":\"empty_typeattr\",\"attribute\":");
            json::push_string(output, attribute);
            output.push_str(",\"missing\":");
            output.push_str(json_boolean(*missing));
            output.push_str(",\"members\":[");
            push_json_strings(output, members);
            output.push_str("]}");
        }
        CheckOutcome::AssertTe {
            rules,
            missing_sources,
            missing_targets,
        } => {
            let mut rules = rules
                .iter()
                .map(|rule| render_rule(policy, rule))
                .collect::<Result<Vec<_>, _>>()?;
            rules.sort_unstable();
            output.push_str("{\"kind\":\"assert_te\",\"rules\":[");
            push_json_strings(output, &rules);
            output.push_str("],\"missing_sources\":[");
            push_json_strings(output, missing_sources);
            output.push_str("],\"missing_targets\":[");
            push_json_strings(output, missing_targets);
            output.push_str("]}");
        }
        CheckOutcome::AssertRbac {
            rules,
            missing_sources,
            missing_targets,
        } => {
            let mut rules = rules
                .iter()
                .map(|rule| render_rbac_rule(policy, rule))
                .collect::<Result<Vec<_>, _>>()?;
            rules.sort_unstable();
            output.push_str("{\"kind\":\"assert_rbac\",\"rules\":[");
            push_json_strings(output, &rules);
            output.push_str("],\"missing_sources\":[");
            push_json_strings(output, missing_sources);
            output.push_str("],\"missing_targets\":[");
            push_json_strings(output, missing_targets);
            output.push_str("]}");
        }
        CheckOutcome::ReadOnly {
            kind,
            checked_types,
            files,
        } => {
            output.push_str("{\"kind\":\"read_only\",\"category\":");
            json::push_string(
                output,
                match kind {
                    ReadOnlyKind::Executable => "executable",
                    ReadOnlyKind::KernelModule => "kernel_module",
                },
            );
            output.push_str(",\"checked_types\":[");
            push_json_strings(output, checked_types);
            output.push_str("],\"files\":[");
            for (index, file) in files.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                let mut use_rules = file
                    .use_rules
                    .iter()
                    .map(|rule| render_rule(policy, rule))
                    .collect::<Result<Vec<_>, _>>()?;
                use_rules.sort_unstable();
                use_rules.dedup();
                let mut write_rules = file
                    .write_rules
                    .iter()
                    .map(|rule| render_rule(policy, rule))
                    .collect::<Result<Vec<_>, _>>()?;
                write_rules.sort_unstable();
                write_rules.dedup();
                output.push_str("{\"type_name\":");
                json::push_string(output, &file.type_name);
                output.push_str(",\"use_rules\":[");
                push_json_strings(output, &use_rules);
                output.push_str("],\"write_rules\":[");
                push_json_strings(output, &write_rules);
                output.push_str("]}");
            }
            output.push_str("]}");
        }
        CheckOutcome::Unexpected { message } => {
            output.push_str("{\"kind\":\"unexpected\",\"message\":");
            json::push_string(output, message);
            output.push('}');
        }
    }
    Ok(())
}

fn result_status(result: &CheckResult<'_>) -> &'static str {
    if matches!(&result.outcome, CheckOutcome::Disabled { .. }) {
        "disabled"
    } else if result.failure_count() == 0 {
        "passed"
    } else {
        "failed"
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

fn push_json_optional_string(output: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        json::push_string(output, value);
    } else {
        output.push_str("null");
    }
}

const fn json_boolean(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn utc_now() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{:06}+00:00",
        duration.subsec_micros()
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u64, day as u64)
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

fn compat_io_error(path: &Path, error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::NotFound {
        format!("[Errno 2] No such file or directory: '{}'", path.display())
    } else if error.kind() == io::ErrorKind::PermissionDenied {
        format!("[Errno 13] Permission denied: '{}'", path.display())
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

fn log_check_trace(
    options: &Options,
    policy: &Policy,
    policy_path: &Path,
    result: &CheckResult<'_>,
) {
    match &result.debug {
        CheckDebug::None => {}
        CheckDebug::EmptyTypeAttribute => {
            if !options.debug {
                return;
            }
            let CheckOutcome::EmptyTypeAttribute {
                attribute,
                missing,
                members,
            } = &result.outcome
            else {
                return;
            };
            if *missing {
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    &format!("    {attribute} does not exist."),
                );
            } else if members.is_empty() {
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    "P   *     <empty>",
                );
            } else {
                for member in members {
                    log_message(
                        options,
                        "DEBUG",
                        result.check_type.logger(),
                        &format!("F   * {member}"),
                    );
                }
            }
            let failures = if members.is_empty() {
                "[]".to_owned()
            } else {
                format!(
                    "[{}]",
                    members
                        .iter()
                        .map(|name| type_repr(policy, policy_path, name))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            log_message(
                options,
                "DEBUG",
                result.check_type.logger(),
                &format!("{failures} failure(s)"),
            );
        }
        CheckDebug::AssertTe { query, evaluated } => {
            log_te_query(options, policy, policy_path, query);
            if !options.debug {
                return;
            }
            let mut evaluated = evaluated
                .iter()
                .filter_map(|item| {
                    render_rule(policy, item.rule)
                        .ok()
                        .map(|rule| (rule, item.failed))
                })
                .collect::<Vec<_>>();
            evaluated.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            for (rule, failed) in evaluated {
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    &format!("{}   * {rule}", if failed { "F" } else { "P" }),
                );
            }
            if let CheckOutcome::AssertTe {
                missing_sources,
                missing_targets,
                ..
            } = &result.outcome
            {
                log_missing_expectations(
                    options,
                    result.check_type.logger(),
                    missing_sources,
                    missing_targets,
                );
            }
            log_te_failure_list(options, policy, policy_path, result);
        }
        CheckDebug::AssertRbac { query, evaluated } => {
            log_rbac_query(options, policy, policy_path, query);
            if !options.debug {
                return;
            }
            let mut evaluated = evaluated
                .iter()
                .filter_map(|item| {
                    render_rbac_rule(policy, item.rule)
                        .ok()
                        .map(|rule| (rule, item.failed))
                })
                .collect::<Vec<_>>();
            evaluated.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            for (rule, failed) in evaluated {
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    &format!("{}   * {rule}", if failed { "F" } else { "P" }),
                );
            }
            if let CheckOutcome::AssertRbac {
                missing_sources,
                missing_targets,
                ..
            } = &result.outcome
            {
                log_missing_expectations(
                    options,
                    result.check_type.logger(),
                    missing_sources,
                    missing_targets,
                );
            }
            log_rbac_failure_list(options, policy, policy_path, result);
        }
        CheckDebug::ReadOnly {
            exempt_users,
            use_rules,
        } => {
            let CheckOutcome::ReadOnly {
                kind,
                checked_types,
                files,
            } = &result.outcome
            else {
                return;
            };
            let (noun, user_option, use_class, use_permissions) = match kind {
                ReadOnlyKind::Executable => (
                    "executable file types",
                    "exempt_exec_domain",
                    "file",
                    &["execute", "execute_no_trans"][..],
                ),
                ReadOnlyKind::KernelModule => (
                    "kernel module types",
                    "exempt_load_domain",
                    "system",
                    &["module_load"][..],
                ),
            };
            if options.debug {
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    &format!("Collecting list of {noun}."),
                );
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    &format!(
                        "self.{user_option}={}",
                        type_set_repr(policy, policy_path, exempt_users)
                    ),
                );
            }
            log_fixed_te_query(
                options,
                policy,
                policy_path,
                None,
                use_class,
                use_permissions,
            );
            if options.debug {
                for item in use_rules {
                    let Ok(rule) = render_rule(policy, item.rule) else {
                        continue;
                    };
                    if item.targets.is_empty() {
                        let description = match kind {
                            ReadOnlyKind::Executable => "Ignoring execute rule",
                            ReadOnlyKind::KernelModule => "Ignoring empty module_load rule",
                        };
                        log_message(
                            options,
                            "DEBUG",
                            result.check_type.logger(),
                            &format!("{description}: {rule}"),
                        );
                    } else {
                        for target in &item.targets {
                            let description = match kind {
                                ReadOnlyKind::Executable => {
                                    format!("Determined {target} is executable by")
                                }
                                ReadOnlyKind::KernelModule => {
                                    format!("Determined {target} is a kernel module by")
                                }
                            };
                            log_message(
                                options,
                                "DEBUG",
                                result.check_type.logger(),
                                &format!("{description}: {rule}"),
                            );
                        }
                    }
                }
            }
            for type_name in checked_types {
                if options.debug {
                    let description = match kind {
                        ReadOnlyKind::Executable => "executable type",
                        ReadOnlyKind::KernelModule => "kernel module type",
                    };
                    log_message(
                        options,
                        "DEBUG",
                        result.check_type.logger(),
                        &format!("Checking if {description} {type_name} is writable."),
                    );
                }
                log_fixed_te_query(
                    options,
                    policy,
                    policy_path,
                    Some(type_name),
                    "file",
                    &["write", "append"],
                );
            }
            if options.debug {
                for file in files {
                    let mut rules = file
                        .write_rules
                        .iter()
                        .filter_map(|rule| render_rule(policy, rule).ok())
                        .collect::<Vec<_>>();
                    rules.sort_unstable();
                    rules.dedup();
                    for rule in rules {
                        log_message(
                            options,
                            "DEBUG",
                            result.check_type.logger(),
                            &format!("F   * {rule}"),
                        );
                    }
                }
                log_message(
                    options,
                    "DEBUG",
                    result.check_type.logger(),
                    &format!("{} failure(s)", files.len()),
                );
            }
        }
    }
}

fn log_missing_expectations(
    options: &Options,
    module: &str,
    missing_sources: &[String],
    missing_targets: &[String],
) {
    for source in missing_sources {
        log_message(
            options,
            "DEBUG",
            module,
            &format!("F   * Expected rule with source \"{source}\" not found."),
        );
    }
    for target in missing_targets {
        log_message(
            options,
            "DEBUG",
            module,
            &format!("F   * Expected rule with target \"{target}\" not found."),
        );
    }
}

fn log_te_failure_list(
    options: &Options,
    policy: &Policy,
    policy_path: &Path,
    result: &CheckResult<'_>,
) {
    let CheckOutcome::AssertTe {
        rules,
        missing_sources,
        missing_targets,
    } = &result.outcome
    else {
        return;
    };
    let mut rendered_rules = rules
        .iter()
        .filter_map(|rule| render_rule(policy, rule).ok())
        .collect::<Vec<_>>();
    rendered_rules.sort_unstable();
    let mut values = rendered_rules
        .into_iter()
        .map(|rule| {
            format!(
                "<AVRule(<SELinuxPolicy(\"{}\")>, \"{rule}\")>",
                policy_path.display()
            )
        })
        .collect::<Vec<_>>();
    values.extend(missing_sources.iter().map(|source| {
        python_string_repr(&format!(
            "Expected rule with source \"{source}\" not found."
        ))
    }));
    values.extend(missing_targets.iter().map(|target| {
        python_string_repr(&format!(
            "Expected rule with target \"{target}\" not found."
        ))
    }));
    log_assertion_failure_values(options, result, &values);
}

fn log_rbac_failure_list(
    options: &Options,
    policy: &Policy,
    policy_path: &Path,
    result: &CheckResult<'_>,
) {
    let CheckOutcome::AssertRbac {
        rules,
        missing_sources,
        missing_targets,
    } = &result.outcome
    else {
        return;
    };
    let mut rendered_rules = rules
        .iter()
        .filter_map(|rule| render_rbac_rule(policy, rule).ok())
        .collect::<Vec<_>>();
    rendered_rules.sort_unstable();
    let mut values = rendered_rules
        .into_iter()
        .map(|rule| {
            format!(
                "<RoleAllow(<SELinuxPolicy(\"{}\")>, \"{rule}\")>",
                policy_path.display()
            )
        })
        .collect::<Vec<_>>();
    values.extend(missing_sources.iter().map(|source| {
        python_string_repr(&format!(
            "Expected rule with source \"{source}\" not found."
        ))
    }));
    values.extend(missing_targets.iter().map(|target| {
        python_string_repr(&format!(
            "Expected rule with target \"{target}\" not found."
        ))
    }));
    log_assertion_failure_values(options, result, &values);
}

fn log_assertion_failure_values(options: &Options, result: &CheckResult<'_>, values: &[String]) {
    log_message(
        options,
        "DEBUG",
        result.check_type.logger(),
        &format!("[{}] failure(s)", values.join(", ")),
    );
}

fn python_string_repr(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn log_te_query(options: &Options, policy: &Policy, policy_path: &Path, query: &TeQuerySettings) {
    log_query_generation(options, "TE", "setools.terulequery", policy_path);
    if !options.debug {
        return;
    }
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        "self.ruletype=frozenset({<TERuletype.allow: 1>})",
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.source={}, self.source_indirect=True, self.source_regex=False",
            optional_type_repr(policy, policy_path, query.source.as_deref())
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.target={}, self.target_indirect=True, self.target_regex=False",
            optional_type_repr(policy, policy_path, query.target.as_deref())
        ),
    );
    log_te_query_tail(
        options,
        policy,
        policy_path,
        &query.classes,
        &query.permissions,
    );
}

fn log_fixed_te_query(
    options: &Options,
    policy: &Policy,
    policy_path: &Path,
    target: Option<&str>,
    target_class: &str,
    permissions: &[&str],
) {
    log_query_generation(options, "TE", "setools.terulequery", policy_path);
    if !options.debug {
        return;
    }
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        "self.ruletype=frozenset({<TERuletype.allow: 1>})",
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        "self.source=None, self.source_indirect=True, self.source_regex=False",
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.target={}, self.target_indirect=True, self.target_regex=False",
            optional_type_repr(policy, policy_path, target)
        ),
    );
    let classes = vec![target_class.to_owned()];
    let permissions = permissions
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    log_te_query_tail(options, policy, policy_path, &classes, &permissions);
}

fn log_te_query_tail(
    options: &Options,
    policy: &Policy,
    policy_path: &Path,
    classes: &[String],
    permissions: &[String],
) {
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.tclass={}, self.tclass_regex=False",
            class_set_repr(policy, policy_path, classes)
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.terulequery",
        &format!(
            "self.perms={}, self.perms_regex=False, self.perms_equal=False, self.perms_subset=False",
            string_set_repr(permissions)
        ),
    );
    for message in [
        "self.xperms=None, self.xperms_equal=False",
        "self.default=None, self.default_regex=False",
        "self.boolean=None, self.boolean_equal=False, self.boolean_regex=False",
    ] {
        log_message(options, "DEBUG", "setools.terulequery", message);
    }
}

fn log_rbac_query(
    options: &Options,
    policy: &Policy,
    policy_path: &Path,
    query: &RbacQuerySettings,
) {
    log_query_generation(options, "RBAC", "setools.rbacrulequery", policy_path);
    if !options.debug {
        return;
    }
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        "self.ruletype=frozenset({<RBACRuletype.allow: 1>})",
    );
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        &format!(
            "self.source={}, self.source_indirect=True, self.source_regex=False",
            optional_role_repr(policy, policy_path, query.source.as_deref())
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        &format!(
            "self.target={}, self.target_indirect=True, self.target_regex=False",
            optional_role_repr(policy, policy_path, query.target.as_deref())
        ),
    );
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        "self.tclass=None, self.tclass_regex=False",
    );
    log_message(
        options,
        "DEBUG",
        "setools.rbacrulequery",
        "self.default=None, self.default_regex=False",
    );
}

fn optional_type_repr(policy: &Policy, path: &Path, value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |name| {
            policy.type_symbol_by_name(name).map_or_else(
                || name.to_owned(),
                |symbol| type_repr(policy, path, symbol.name()),
            )
        },
    )
}

fn type_repr(policy: &Policy, path: &Path, name: &str) -> String {
    let kind = policy.type_symbol_by_name(name).map_or("Type", |symbol| {
        if symbol.is_attribute() {
            "TypeAttribute"
        } else {
            "Type"
        }
    });
    format!(
        "<{kind}(<SELinuxPolicy(\"{}\")>, \"{name}\")>",
        path.display()
    )
}

fn optional_role_repr(policy: &Policy, path: &Path, value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |name| {
            let name = policy.role_by_name(name).map_or(name, |role| role.name());
            format!(
                "<Role(<SELinuxPolicy(\"{}\")>, \"{name}\")>",
                path.display()
            )
        },
    )
}

fn class_set_repr(policy: &Policy, path: &Path, classes: &[String]) -> String {
    if classes.is_empty() {
        return "None".to_owned();
    }
    let values = classes
        .iter()
        .filter_map(|name| policy.object_class_by_name(name))
        .map(|class| {
            format!(
                "<ObjClass(<SELinuxPolicy(\"{}\")>, \"{}\")>",
                path.display(),
                class.name()
            )
        })
        .collect::<Vec<_>>();
    format!("frozenset({{{}}})", values.join(", "))
}

fn string_set_repr(values: &[String]) -> String {
    if values.is_empty() {
        return "None".to_owned();
    }
    format!(
        "frozenset({{{}}})",
        values
            .iter()
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn type_set_repr(policy: &Policy, path: &Path, values: &[String]) -> String {
    if values.is_empty() {
        return "frozenset()".to_owned();
    }
    format!(
        "frozenset({{{}}})",
        values
            .iter()
            .map(|value| type_repr(policy, path, value))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn log_query_generation(options: &Options, kind: &str, module: &str, policy_path: &Path) {
    log_message(
        options,
        "INFO",
        module,
        &format!(
            "Generating {kind} rule results from {}",
            policy_path.display()
        ),
    );
}

fn usage_error(message: &str) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{USAGE}sechecker: error: {message}");
    ExitCode::from(2)
}

fn config_error(options: &Options, message: &str) -> ExitCode {
    if let Some((_, detail)) = message.split_once(": ")
        && detail.starts_with("Invalid _internal_")
        && detail.contains(" item: ")
    {
        if options.debug {
            log_message(options, "ERROR", "setools.checker", detail);
        } else {
            eprintln!("{detail}");
        }
    }
    if options.debug {
        eprintln!("{message}");
        ExitCode::from(1)
    } else {
        let _ = write_stdout(&format!("{message}\n"));
        ExitCode::from(2)
    }
}

fn operational_error(options: &Options, message: &str) -> ExitCode {
    if options.debug {
        eprintln!("{message}");
        ExitCode::from(1)
    } else {
        let _ = write_stdout(&format!("{message}\n"));
        ExitCode::from(3)
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
    use super::{civil_from_days, parse};
    use std::ffi::OsString;

    #[test]
    fn unix_epoch_has_expected_civil_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_686), (2026, 8, 21));
    }

    #[test]
    fn config_is_required() {
        let error = parse(Vec::new()).err().expect("missing config should fail");
        assert_eq!(error, "the following arguments are required: config");
    }

    #[test]
    fn accepts_output_file_equals_form() {
        let action = parse(vec![
            OsString::from("--output_file=report.txt"),
            OsString::from("checks.ini"),
        ])
        .expect("options should parse");
        assert!(matches!(action, super::ParseAction::Run(_)));
    }

    #[test]
    fn parses_hidden_json_option() {
        let action = parse(vec![
            OsString::from("--json"),
            OsString::from("checks.ini"),
            OsString::from("policy.bin"),
        ])
        .expect("options should parse");
        let super::ParseAction::Run(options) = action else {
            panic!("expected runnable options");
        };
        assert!(options.json);
        assert_eq!(options.config, Some("checks.ini".into()));
        assert_eq!(options.policy, Some("policy.bin".into()));
    }
}
