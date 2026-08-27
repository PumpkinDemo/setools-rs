// SPDX-License-Identifier: GPL-2.0-only

//! Generates and verifies release man pages and shell completions.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const TOOLS: &[&str] = &[
    "sesearch",
    "seinfo",
    "sediff",
    "sedta",
    "seinfoflow",
    "sechecker",
];

#[derive(Debug, Eq, PartialEq)]
struct HelpDocument {
    usage: Vec<String>,
    summary: String,
    sections: Vec<HelpSection>,
    epilogue: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct HelpSection {
    title: String,
    entries: Vec<HelpEntry>,
}

#[derive(Debug, Eq, PartialEq)]
struct HelpEntry {
    signature: String,
    description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OptionSpec {
    aliases: Vec<String>,
    value: Option<String>,
    optional_value: bool,
    description: String,
}

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(action) = arguments.next() else {
        eprintln!("usage: cargo run -p setools-xtask -- <generate|check>");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("setools-xtask: unexpected extra arguments");
        return ExitCode::from(2);
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be inside the repository");
    let assets = match generated_assets(root) {
        Ok(assets) => assets,
        Err(message) => {
            eprintln!("setools-xtask: {message}");
            return ExitCode::FAILURE;
        }
    };
    let result = match action.as_str() {
        "generate" => write_assets(root, &assets),
        "check" => check_assets(root, &assets),
        _ => {
            eprintln!("setools-xtask: unknown action {action:?}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("setools-xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

fn generated_assets(root: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let mut assets = Vec::new();
    for tool in TOOLS {
        let help_path = root.join(format!("crates/setools-cli/assets/{tool}-help.txt"));
        let help = fs::read_to_string(&help_path)
            .map_err(|error| format!("unable to read {}: {error}", help_path.display()))?;
        let document = parse_help(&help)?;
        let options = options_with_json(&document)?;
        assets.push((
            PathBuf::from(format!("man/man1/{tool}.1")),
            render_man(tool, &document),
        ));
        assets.push((
            PathBuf::from(format!("completions/bash/{tool}")),
            render_bash(tool, &options),
        ));
        assets.push((
            PathBuf::from(format!("completions/zsh/_{tool}")),
            render_zsh(tool, &options),
        ));
        assets.push((
            PathBuf::from(format!("completions/fish/{tool}.fish")),
            render_fish(tool, &options),
        ));
    }
    Ok(assets)
}

fn write_assets(root: &Path, assets: &[(PathBuf, String)]) -> Result<(), String> {
    for (relative, contents) in assets {
        let path = root.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("unable to create {}: {error}", parent.display()))?;
        fs::write(&path, contents)
            .map_err(|error| format!("unable to write {}: {error}", path.display()))?;
    }
    println!("generated {} CLI release assets", assets.len());
    Ok(())
}

fn check_assets(root: &Path, assets: &[(PathBuf, String)]) -> Result<(), String> {
    let expected = assets
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    let mut failures = Vec::new();
    for (relative, contents) in assets {
        let path = root.join(relative);
        match fs::read_to_string(&path) {
            Ok(current) if current == *contents => {}
            Ok(_) => failures.push(format!(
                "{} is stale; run `cargo run -p setools-xtask -- generate`",
                relative.display()
            )),
            Err(error) => failures.push(format!("unable to read {}: {error}", relative.display())),
        }
    }
    for directory in [
        "man/man1",
        "completions/bash",
        "completions/zsh",
        "completions/fish",
    ] {
        let path = root.join(directory);
        let entries = fs::read_dir(&path)
            .map_err(|error| format!("unable to read {}: {error}", path.display()))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("unable to read directory entry: {error}"))?;
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("generated path must be below the repository")
                .to_path_buf();
            if entry
                .file_type()
                .map_err(|error| format!("unable to inspect {}: {error}", relative.display()))?
                .is_file()
                && !expected.contains(&relative)
            {
                failures.push(format!("unexpected generated asset {}", relative.display()));
            }
        }
    }
    if failures.is_empty() {
        println!("verified {} generated CLI release assets", assets.len());
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn parse_help(help: &str) -> Result<HelpDocument, String> {
    let lines = help.lines().collect::<Vec<_>>();
    let Some(first) = lines.first() else {
        return Err("empty help asset".to_owned());
    };
    if !first.starts_with("usage: ") {
        return Err("help asset does not start with usage".to_owned());
    }
    let mut index = 0_usize;
    let mut usage = Vec::new();
    while lines.get(index).is_some_and(|line| !line.is_empty()) {
        usage.push(lines[index].to_owned());
        index += 1;
    }
    while lines.get(index).is_some_and(|line| line.is_empty()) {
        index += 1;
    }
    let summary = lines
        .get(index)
        .ok_or_else(|| "help asset is missing a summary".to_owned())?
        .to_string();
    index += 1;
    while lines.get(index).is_some_and(|line| line.is_empty()) {
        index += 1;
    }

    let mut sections = Vec::new();
    let mut epilogue = Vec::new();
    let mut current_section: Option<HelpSection> = None;
    let mut current_entry: Option<HelpEntry> = None;
    while let Some(line) = lines.get(index) {
        if !line.starts_with(char::is_whitespace) && line.ends_with(':') {
            finish_entry(&mut current_section, &mut current_entry)?;
            if let Some(section) = current_section.take() {
                sections.push(section);
            }
            current_section = Some(HelpSection {
                title: line.trim_end_matches(':').to_owned(),
                entries: Vec::new(),
            });
        } else if starts_entry(line) {
            finish_entry(&mut current_section, &mut current_entry)?;
            let (signature, description) = split_entry(line.trim_start());
            current_entry = Some(HelpEntry {
                signature,
                description,
            });
        } else if line.starts_with(char::is_whitespace) && !line.trim().is_empty() {
            let entry = current_entry
                .as_mut()
                .ok_or_else(|| format!("orphaned help continuation: {line}"))?;
            if !entry.description.is_empty() {
                entry.description.push(' ');
            }
            entry.description.push_str(line.trim());
        } else if !line.trim().is_empty() {
            finish_entry(&mut current_section, &mut current_entry)?;
            if let Some(section) = current_section.take() {
                sections.push(section);
            }
            epilogue.push(line.trim().to_owned());
        } else if !epilogue.is_empty() {
            epilogue.push(String::new());
        }
        index += 1;
    }
    finish_entry(&mut current_section, &mut current_entry)?;
    if let Some(section) = current_section {
        sections.push(section);
    }
    if sections.is_empty() {
        return Err("help asset has no sections".to_owned());
    }
    Ok(HelpDocument {
        usage,
        summary,
        sections,
        epilogue,
    })
}

fn starts_entry(line: &str) -> bool {
    line.starts_with("  ") && !line.as_bytes().get(2).is_none_or(u8::is_ascii_whitespace)
}

fn split_entry(line: &str) -> (String, String) {
    let bytes = line.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index - start >= 2 {
                return (
                    line[..start].trim_end().to_owned(),
                    line[index..].trim().to_owned(),
                );
            }
        } else {
            index += 1;
        }
    }
    (line.trim().to_owned(), String::new())
}

fn finish_entry(
    section: &mut Option<HelpSection>,
    entry: &mut Option<HelpEntry>,
) -> Result<(), String> {
    let Some(entry) = entry.take() else {
        return Ok(());
    };
    section
        .as_mut()
        .ok_or_else(|| format!("help entry outside a section: {}", entry.signature))?
        .entries
        .push(entry);
    Ok(())
}

fn options_with_json(document: &HelpDocument) -> Result<Vec<OptionSpec>, String> {
    let mut options = document
        .sections
        .iter()
        .flat_map(|section| &section.entries)
        .filter(|entry| entry.signature.starts_with('-'))
        .map(parse_option)
        .collect::<Result<Vec<_>, _>>()?;
    if options
        .iter()
        .any(|option| option.aliases.iter().any(|alias| alias == "--json"))
    {
        return Err("compatibility help unexpectedly exposes --json".to_owned());
    }
    options.push(OptionSpec {
        aliases: vec!["--json".to_owned()],
        value: None,
        optional_value: false,
        description: "Emit command-specific versioned JSON output.".to_owned(),
    });
    Ok(options)
}

fn parse_option(entry: &HelpEntry) -> Result<OptionSpec, String> {
    let mut aliases = Vec::new();
    let mut values = Vec::new();
    for token in entry.signature.split_whitespace() {
        let token = token.trim_end_matches(',');
        if token.starts_with('-') {
            aliases.push(token.to_owned());
        } else {
            values.push(token.to_owned());
        }
    }
    if aliases.is_empty() {
        return Err(format!("option has no aliases: {}", entry.signature));
    }
    let value = (!values.is_empty()).then(|| values.join(" "));
    let optional_value = value
        .as_ref()
        .is_some_and(|value| value.starts_with('[') && value.ends_with(']'));
    Ok(OptionSpec {
        aliases,
        value,
        optional_value,
        description: entry.description.clone(),
    })
}

fn render_man(tool: &str, document: &HelpDocument) -> String {
    let mut output = String::new();
    output.push_str(".\\\" Generated by `cargo run -p setools-xtask -- generate`; do not edit.\n");
    output.push_str(&format!(
        ".TH \"{}\" \"1\" \"setools-rs {}\" \"SETools Rust Rewrite\"\n",
        tool.to_ascii_uppercase(),
        env!("CARGO_PKG_VERSION")
    ));
    output.push_str(".SH NAME\n");
    output.push_str(&roff(&format!(
        "{tool} - {}",
        document.summary.trim_end_matches('.')
    )));
    output.push('\n');
    output.push_str(".SH SYNOPSIS\n.nf\n");
    for (index, line) in document.usage.iter().enumerate() {
        let line = if index == 0 {
            line.strip_prefix("usage: ").unwrap_or(line)
        } else {
            line
        };
        output.push_str(&roff(line));
        output.push('\n');
    }
    output.push_str(".fi\n.SH DESCRIPTION\n");
    output.push_str(&roff(&document.summary));
    output.push('\n');
    for section in &document.sections {
        output.push_str(&format!(
            ".SH \"{}\"\n",
            roff(&section.title.to_ascii_uppercase())
        ));
        for entry in &section.entries {
            output.push_str(".TP\n.B \"");
            output.push_str(&roff(&entry.signature));
            output.push_str("\"\n");
            if entry.description.is_empty() {
                output.push_str("\\&\n");
            } else {
                output.push_str(&roff(&entry.description));
                output.push('\n');
            }
        }
    }
    if !document.epilogue.is_empty() {
        output.push_str(".SH NOTES\n");
        for line in &document.epilogue {
            if line.is_empty() {
                output.push_str(".PP\n");
            } else {
                output.push_str(&roff(line));
                output.push('\n');
            }
        }
    }
    output.push_str(".SH STRUCTURED OUTPUT\n.TP\n.B \"\\-\\-json\"\n");
    output.push_str(&roff(json_man_description(tool)));
    output.push('\n');
    output.push_str("This additive option is intentionally absent from the SETools 4.7.1 compatibility help text.\n");
    output.push_str(".SH SEE ALSO\n");
    let related = TOOLS
        .iter()
        .filter(|candidate| **candidate != tool)
        .map(|candidate| format!("{candidate}(1)"))
        .collect::<Vec<_>>()
        .join(", ");
    output.push_str(&roff(&related));
    output.push('\n');
    output.push_str(".SH LICENSE\nGPL-2.0-only.\n");
    output
}

fn json_man_description(tool: &str) -> &'static str {
    match tool {
        "sedta" | "seinfoflow" => {
            "Emit one compact command-specific JSON v1 document. This option cannot be combined with --output_file."
        }
        "sechecker" => {
            "Emit one compact command-specific JSON v1 document. A completed run exits 0 when clean or 1 when findings exist. This option cannot be combined with --output_file."
        }
        _ => "Emit one compact command-specific JSON v1 document.",
    }
}

fn render_bash(tool: &str, options: &[OptionSpec]) -> String {
    let function = format!("_setools_rs_{tool}");
    let words = options
        .iter()
        .flat_map(|option| &option.aliases)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let mut file_patterns = Vec::new();
    let mut value_patterns = Vec::new();
    for option in options
        .iter()
        .filter(|option| option.value.is_some() && !option.optional_value)
    {
        let target = if option.value.as_deref().is_some_and(is_path_value) {
            &mut file_patterns
        } else {
            &mut value_patterns
        };
        target.extend(option.aliases.iter().cloned());
    }
    let mut output = format!(
        "# Generated by `cargo run -p setools-xtask -- generate`; do not edit.\n{function}()\n{{\n    local cur prev\n    COMPREPLY=()\n    cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n    prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n"
    );
    if !file_patterns.is_empty() || !value_patterns.is_empty() {
        output.push_str("\n    case \"$prev\" in\n");
        if !file_patterns.is_empty() {
            output.push_str(&format!(
                "        {}) COMPREPLY=( $(compgen -f -- \"$cur\") ); return 0 ;;\n",
                file_patterns.join("|")
            ));
        }
        if !value_patterns.is_empty() {
            output.push_str(&format!(
                "        {}) return 0 ;;\n",
                value_patterns.join("|")
            ));
        }
        output.push_str("    esac\n");
    }
    output.push_str(&format!(
        "\n    if [[ \"$cur\" == -* ]]; then\n        COMPREPLY=( $(compgen -W {} -- \"$cur\") )\n",
        shell_single(&words)
    ));
    if has_path_positionals(tool) {
        output.push_str("    else\n        COMPREPLY=( $(compgen -f -- \"$cur\") )\n");
    } else {
        output.push_str("    else\n        COMPREPLY=()\n");
    }
    output.push_str(&format!("    fi\n}}\ncomplete -F {function} {tool}\n"));
    output
}

fn render_zsh(tool: &str, options: &[OptionSpec]) -> String {
    let mut output = format!(
        "#compdef {tool}\n# Generated by `cargo run -p setools-xtask -- generate`; do not edit.\n\n_arguments -s -S \\\n"
    );
    let mut specifications = options.iter().map(zsh_option).collect::<Vec<_>>();
    specifications.push(if has_path_positionals(tool) {
        "'*:file:_files'".to_owned()
    } else {
        "'*:policy type:'".to_owned()
    });
    for (index, specification) in specifications.iter().enumerate() {
        output.push_str("  ");
        output.push_str(specification);
        if index + 1 != specifications.len() {
            output.push_str(" \\");
        }
        output.push('\n');
    }
    output
}

fn zsh_option(option: &OptionSpec) -> String {
    let aliases = if option.aliases.len() == 1 {
        option.aliases[0].clone()
    } else {
        format!("{{{}}}", option.aliases.join(","))
    };
    let exclusions = if option.aliases.len() > 1 {
        format!("({})", option.aliases.join(" "))
    } else {
        String::new()
    };
    let description = zsh_escape(&option.description);
    let value = option.value.as_ref().map_or_else(String::new, |value| {
        let name = value.trim_matches(['[', ']']);
        let separator = if option.optional_value { "::" } else { ":" };
        if is_path_value(value) {
            format!("{separator}{name}:_files")
        } else {
            format!("{separator}{name}:")
        }
    });
    shell_single(&format!("{exclusions}{aliases}[{description}]{value}"))
}

fn render_fish(tool: &str, options: &[OptionSpec]) -> String {
    let mut output =
        "# Generated by `cargo run -p setools-xtask -- generate`; do not edit.\n".to_owned();
    if !has_path_positionals(tool) {
        output.push_str(&format!("complete -c {tool} -f\n"));
    }
    for option in options {
        output.push_str("complete -c ");
        output.push_str(tool);
        for alias in &option.aliases {
            if let Some(short) = alias.strip_prefix("--") {
                output.push_str(" -l ");
                output.push_str(short);
            } else if let Some(short) = alias.strip_prefix('-') {
                if short.chars().count() == 1 {
                    output.push_str(" -s ");
                } else {
                    output.push_str(" -o ");
                }
                output.push_str(short);
            }
        }
        match option.value.as_deref() {
            Some(value) if !option.optional_value && is_path_value(value) => {
                output.push_str(" -r -F")
            }
            Some(_) if !option.optional_value => output.push_str(" -r -f"),
            _ => output.push_str(" -f"),
        }
        output.push_str(" -d ");
        output.push_str(&fish_single(&option.description));
        output.push('\n');
    }
    output
}

fn is_path_value(value: &str) -> bool {
    let value = value.trim_matches(['[', ']']);
    matches!(
        value,
        "POLICY" | "POLICY1" | "POLICY2" | "MAP" | "OUTPUT_FILE" | "PATH"
    )
}

fn has_path_positionals(tool: &str) -> bool {
    !matches!(tool, "sedta" | "seinfoflow")
}

fn roff(value: &str) -> String {
    let mut escaped = value.replace('\\', "\\e").replace('-', "\\-");
    if escaped.starts_with('.') || escaped.starts_with('\'') {
        escaped.insert_str(0, "\\&");
    }
    escaped
}

fn shell_single(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn fish_single(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn zsh_escape(value: &str) -> String {
    value.replace('[', "\\[").replace(']', "\\]")
}

#[cfg(test)]
mod tests {
    use super::{options_with_json, parse_help, render_bash, render_man, render_zsh};

    #[test]
    fn parses_compatibility_help_and_adds_json_metadata() {
        let help = include_str!("../../crates/setools-cli/assets/sesearch-help.txt");
        let document = parse_help(help).expect("sesearch help should parse");
        assert_eq!(document.summary, "SELinux policy rule search tool.");
        assert_eq!(document.usage.len(), 8);
        assert!(
            document
                .sections
                .iter()
                .any(|section| section.title == "TE Rule Types")
        );
        let options = options_with_json(&document).expect("options should parse");
        assert!(
            options
                .iter()
                .any(|option| option.aliases == ["-s", "--source"])
        );
        assert!(options.iter().any(|option| option.aliases == ["--json"]));
    }

    #[test]
    fn generated_formats_include_public_and_additive_options() {
        let help = include_str!("../../crates/setools-cli/assets/sechecker-help.txt");
        let document = parse_help(help).expect("sechecker help should parse");
        let options = options_with_json(&document).expect("options should parse");
        let man = render_man("sechecker", &document);
        assert!(man.contains(".TH \"SECHECKER\" \"1\""));
        assert!(man.contains("\\-\\-output_file"));
        assert!(man.contains("\\-\\-json"));
        let bash = render_bash("sechecker", &options);
        assert!(bash.contains("\n_setools_rs_sechecker()\n"));
        assert!(bash.contains("complete -F _setools_rs_sechecker sechecker"));
        assert!(bash.contains("--output_file"));
        assert!(bash.contains("--json"));
        let zsh = render_zsh("sechecker", &options);
        assert!(zsh.contains("--output_file"));
        assert!(zsh.contains("--json"));
    }
}
