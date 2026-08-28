// SPDX-License-Identifier: LGPL-2.1-only
//! Prints every symbol-table family parsed without libsepol.

use setools_policy_binary::PureRustPrefixLoader;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: policy-prefix BINARY_POLICY");
        return ExitCode::from(2);
    };
    let path = Path::new(&path);
    let prefix = match PureRustPrefixLoader::default().load(path) {
        Ok(prefix) => prefix,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    println!("path: {}", path.display());
    println!("version: {}", prefix.header().metadata().version);
    println!(
        "policy_capabilities: {}",
        prefix.policy_capabilities().len()
    );
    println!("common_permission_sets: {}", prefix.commons().len());
    for common in prefix.commons() {
        let permissions = common
            .permissions()
            .iter()
            .map(|permission| permission.name())
            .collect::<Vec<_>>()
            .join(" ");
        println!("{}: {permissions}", common.name());
    }
    println!("object_classes: {}", prefix.classes().len());
    println!("roles: {}", prefix.roles().len());
    println!("type_primary_values: {}", prefix.type_primary_count());
    println!("named_types_and_attributes: {}", prefix.types().len());
    println!(
        "type_attributes: {}",
        prefix
            .types()
            .iter()
            .filter(|symbol| { symbol.kind() == setools_policy_binary::BinaryTypeKind::Attribute })
            .count()
    );
    println!(
        "type_aliases: {}",
        prefix
            .types()
            .iter()
            .map(|symbol| symbol.aliases().len())
            .sum::<usize>()
    );
    println!(
        "permissive_types: {}",
        prefix
            .types()
            .iter()
            .filter(|symbol| symbol.is_permissive())
            .count()
    );
    println!(
        "type_bounds: {}",
        prefix
            .types()
            .iter()
            .filter(|symbol| symbol.bound().is_some())
            .count()
    );
    println!("users: {}", prefix.users().len());
    println!("booleans: {}", prefix.booleans().len());
    println!("sensitivities: {}", prefix.sensitivities().len());
    println!(
        "sensitivity_aliases: {}",
        prefix
            .sensitivities()
            .iter()
            .map(|symbol| symbol.aliases().len())
            .sum::<usize>()
    );
    println!("categories: {}", prefix.categories().len());
    println!(
        "category_aliases: {}",
        prefix
            .categories()
            .iter()
            .map(|symbol| symbol.aliases().len())
            .sum::<usize>()
    );
    println!("unconditional_te_rules: {}", prefix.te_rules().len());
    println!("conditionals: {}", prefix.conditionals().len());
    println!(
        "conditional_te_rules: {}",
        prefix
            .conditionals()
            .iter()
            .map(|conditional| conditional.true_rules().len() + conditional.false_rules().len())
            .sum::<usize>()
    );
    println!("rbac_rules: {}", prefix.rbac_rules().len());
    println!(
        "filename_transitions: {}",
        prefix.filename_transitions().len()
    );
    println!("labeling_rules: {}", prefix.labeling_rules().len());
    println!("mls_range_transitions: {}", prefix.mls_rules().len());
    println!(
        "type_attribute_memberships: {}",
        prefix
            .types()
            .iter()
            .map(|symbol| symbol.attributes().len())
            .sum::<usize>()
    );
    println!(
        "declared_permissions: {}",
        prefix
            .commons()
            .iter()
            .map(|common| common.permissions().len())
            .sum::<usize>()
            + prefix
                .classes()
                .iter()
                .map(|target_class| target_class.local_permissions().len())
                .sum::<usize>()
    );
    println!(
        "constraints: {}",
        prefix
            .classes()
            .iter()
            .map(|target_class| {
                target_class.constraints().len() + target_class.validation_constraints().len()
            })
            .sum::<usize>()
    );
    println!(
        "defaults: {}",
        prefix
            .classes()
            .iter()
            .map(|target_class| {
                let defaults = target_class.defaults();
                usize::from(defaults.user().is_some())
                    + usize::from(defaults.role().is_some())
                    + usize::from(defaults.object_type().is_some())
                    + usize::from(defaults.range().is_some())
            })
            .sum::<usize>()
    );
    println!("policy_bytes: {}", prefix.encoded_len());
    println!(
        "parser_retained_allocation_bytes: {}",
        prefix.retained_allocation_bytes()
    );
    match prefix.estimated_peak_allocation_bytes(path) {
        Ok(bytes) => println!("estimated_peak_allocation_bytes: {bytes}"),
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
