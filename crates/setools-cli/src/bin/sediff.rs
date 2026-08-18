//! `sediff` executable entry point.

use setools_cli::{Tool, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    run(Tool::Sediff)
}
