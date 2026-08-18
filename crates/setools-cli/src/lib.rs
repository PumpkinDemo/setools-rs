//! Shared command-line entry point and compatibility rendering boundary.

use std::env;
use std::fmt;
use std::process::ExitCode;

mod seinfo;
mod sesearch;

/// Executable provided by the workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tool {
    /// Policy rule search.
    Sesearch,
    /// Policy component information.
    Seinfo,
    /// Semantic policy difference.
    Sediff,
    /// Domain-transition analysis.
    Sedta,
    /// Information-flow analysis.
    Seinfoflow,
    /// Automated policy checks.
    Sechecker,
}

impl fmt::Display for Tool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Sesearch => "sesearch",
            Self::Seinfo => "seinfo",
            Self::Sediff => "sediff",
            Self::Sedta => "sedta",
            Self::Seinfoflow => "seinfoflow",
            Self::Sechecker => "sechecker",
        };
        formatter.write_str(name)
    }
}

/// Runs one of the installed command-line programs.
#[must_use]
pub fn run(tool: Tool) -> ExitCode {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    match tool {
        Tool::Sesearch => return sesearch::run(arguments),
        Tool::Seinfo => return seinfo::run(arguments),
        _ => {}
    }
    if arguments.len() == 1 && arguments[0] == "--version" {
        println!("{}", env!("CARGO_PKG_VERSION"));
        ExitCode::SUCCESS
    } else {
        eprintln!("{tool}: Rust rewrite scaffold; command is not implemented yet");
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::Tool;

    #[test]
    fn tool_names_match_installed_binaries() {
        assert_eq!(Tool::Sesearch.to_string(), "sesearch");
        assert_eq!(Tool::Seinfo.to_string(), "seinfo");
        assert_eq!(Tool::Sediff.to_string(), "sediff");
        assert_eq!(Tool::Sedta.to_string(), "sedta");
        assert_eq!(Tool::Seinfoflow.to_string(), "seinfoflow");
        assert_eq!(Tool::Sechecker.to_string(), "sechecker");
    }
}
