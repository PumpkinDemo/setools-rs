// SPDX-License-Identifier: LGPL-2.1-only
//! Prints the bounded metadata slice parsed without libsepol.

use setools_policy_binary::PureRustMetadataLoader;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: policy-header BINARY_POLICY");
        return ExitCode::from(2);
    };
    let path = Path::new(&path);
    let header = match PureRustMetadataLoader.load(path) {
        Ok(header) => header,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let metadata = header.metadata();
    println!("path: {}", path.display());
    println!("version: {}", metadata.version);
    println!("target: {:?}", metadata.target);
    println!("mls: {}", metadata.mls);
    println!("handle_unknown: {:?}", metadata.handle_unknown);
    println!("symbol_table_families: {}", header.symbol_table_count());
    println!("object_context_families: {}", header.object_context_count());
    println!("header_bytes: {}", header.encoded_len());
    ExitCode::SUCCESS
}
