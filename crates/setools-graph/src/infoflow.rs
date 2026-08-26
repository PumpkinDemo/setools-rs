//! Permission-map parsing and information-flow graph analysis.

use setools_policy::{
    ConditionalToken, Policy, TeRule, TeRuleData, TeRuleKind, TypeId, TypeOrAttributeId,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

const DEFAULT_PERMISSION_MAP: &str = include_str!("../assets/perm_map");

/// Information-flow direction assigned to one object-class permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionDirection {
    /// Information flows from object to subject.
    Read,
    /// Information flows from subject to object.
    Write,
    /// Information flows in both directions.
    Both,
    /// The permission does not carry information.
    None,
    /// The permission has not been classified.
    Unmapped,
}

impl PermissionDirection {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "r" => Some(Self::Read),
            "w" => Some(Self::Write),
            "b" => Some(Self::Both),
            "n" => Some(Self::None),
            "u" => Some(Self::Unmapped),
            _ => None,
        }
    }

    /// Returns the permission-map format character.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Read => "r",
            Self::Write => "w",
            Self::Both => "b",
            Self::None => "n",
            Self::Unmapped => "u",
        }
    }
}

/// One permission-map entry in file declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionMapping {
    class: String,
    permission: String,
    direction: PermissionDirection,
    weight: u8,
}

impl PermissionMapping {
    /// Returns the object-class name.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Returns the permission name.
    #[must_use]
    pub fn permission(&self) -> &str {
        &self.permission
    }

    /// Returns the information-flow direction.
    #[must_use]
    pub const fn direction(&self) -> PermissionDirection {
        self.direction
    }

    /// Returns the permission weight, in the inclusive range 1-10.
    #[must_use]
    pub const fn weight(&self) -> u8 {
        self.weight
    }
}

/// A permission-map load or syntax error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionMapError(String);

impl fmt::Display for PermissionMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PermissionMapError {}

/// Parsed object-class permission flow mappings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionMap {
    source: String,
    mappings: Vec<PermissionMapping>,
    indexes: BTreeMap<String, BTreeMap<String, usize>>,
    declared_classes: usize,
    parsed_classes: usize,
}

impl PermissionMap {
    /// Loads the project-owned default permission map.
    pub fn built_in() -> Result<Self, PermissionMapError> {
        Self::parse(DEFAULT_PERMISSION_MAP, "<built-in permission map>")
    }

    /// Loads a permission map from an explicit path.
    pub fn from_file(path: &Path) -> Result<Self, PermissionMapError> {
        let contents = fs::read_to_string(path).map_err(|error| {
            let message = if error.kind() == std::io::ErrorKind::NotFound {
                format!("[Errno 2] No such file or directory: '{}'", path.display())
            } else {
                format!("{}: {error}", path.display())
            };
            PermissionMapError(message)
        })?;
        Self::parse(&contents, &path.display().to_string())
    }

    /// Parses a complete permission-map document.
    pub fn parse(contents: &str, source: &str) -> Result<Self, PermissionMapError> {
        enum State {
            ClassCount,
            Class,
            Permissions {
                class: String,
                expected: usize,
                parsed: usize,
            },
        }

        let mut state = State::ClassCount;
        let mut declared_classes = 0_usize;
        let mut parsed_classes = 0_usize;
        let mut mappings = Vec::new();
        let mut indexes = BTreeMap::<String, BTreeMap<String, usize>>::new();

        for (offset, line) in contents.lines().enumerate() {
            let line_number = offset + 1;
            let entry = line.split_whitespace().collect::<Vec<_>>();
            if entry.is_empty() || entry[0].starts_with('#') {
                continue;
            }

            match &mut state {
                State::ClassCount => {
                    let count = entry[0].parse::<i64>().map_err(|_| {
                        PermissionMapError(format!(
                            "{source}:{line_number}:Invalid number of classes: {}",
                            entry[0]
                        ))
                    })?;
                    if count < 1 {
                        return Err(PermissionMapError(format!(
                            "{source}:{line_number}:Number of classes must be positive: {count}"
                        )));
                    }
                    declared_classes = usize::try_from(count).map_err(|_| {
                        PermissionMapError(format!(
                            "{source}:{line_number}:Invalid number of classes: {}",
                            entry[0]
                        ))
                    })?;
                    state = State::Class;
                }
                State::Class => {
                    if entry.len() != 3 || entry[0] != "class" {
                        return Err(PermissionMapError(format!(
                            "{source}:{line_number}:Invalid class declaration: {}",
                            python_list(&entry)
                        )));
                    }
                    let class = entry[1].to_owned();
                    let permission_count = entry[2].parse::<i64>().map_err(|_| {
                        PermissionMapError(format!(
                            "{source}:{line_number}:Invalid number of permissions: {}",
                            entry[2]
                        ))
                    })?;
                    if permission_count < 1 {
                        return Err(PermissionMapError(format!(
                            "{source}:{line_number}:Number of permissions must be positive: {permission_count}"
                        )));
                    }
                    let expected = usize::try_from(permission_count).map_err(|_| {
                        PermissionMapError(format!(
                            "{source}:{line_number}:Invalid number of permissions: {}",
                            entry[2]
                        ))
                    })?;
                    parsed_classes += 1;
                    if parsed_classes > declared_classes {
                        return Err(PermissionMapError(format!(
                            "{source}:{line_number}:Extra class found: {class}"
                        )));
                    }
                    indexes.insert(class.clone(), BTreeMap::new());
                    state = State::Permissions {
                        class,
                        expected,
                        parsed: 0,
                    };
                }
                State::Permissions {
                    class,
                    expected,
                    parsed,
                } => {
                    if entry.len() < 3 {
                        return Err(PermissionMapError(format!(
                            "{source}:{line_number}:Invalid permission declaration: {}",
                            python_list(&entry)
                        )));
                    }
                    let direction = PermissionDirection::parse(entry[1]).ok_or_else(|| {
                        PermissionMapError(format!(
                            "{source}:{line_number}:Invalid information flow direction: {}",
                            entry[1]
                        ))
                    })?;
                    let weight = entry[2].parse::<i64>().map_err(|_| {
                        PermissionMapError(format!(
                            "{source}:{line_number}:Invalid permission weight: {}",
                            entry[2]
                        ))
                    })?;
                    if !(1..=10).contains(&weight) {
                        return Err(PermissionMapError(format!(
                            "{source}:{line_number}:Permission weight must be 1-10: {weight}"
                        )));
                    }
                    let weight = u8::try_from(weight).expect("validated permission weight");
                    let mapping = PermissionMapping {
                        class: class.clone(),
                        permission: entry[0].to_owned(),
                        direction,
                        weight,
                    };
                    indexes
                        .entry(mapping.class.clone())
                        .or_default()
                        .insert(mapping.permission.clone(), mappings.len());
                    mappings.push(mapping);
                    *parsed += 1;
                    if *parsed >= *expected {
                        state = State::Class;
                    }
                }
            }
        }

        Ok(Self {
            source: source.to_owned(),
            mappings,
            indexes,
            declared_classes,
            parsed_classes,
        })
    }

    /// Returns the source label or explicit path.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns entries in file declaration order.
    #[must_use]
    pub fn mappings(&self) -> &[PermissionMapping] {
        &self.mappings
    }

    /// Returns the number of parsed class declarations.
    #[must_use]
    pub const fn class_count(&self) -> usize {
        self.parsed_classes
    }

    /// Returns the number of declared classes in the header.
    #[must_use]
    pub const fn declared_class_count(&self) -> usize {
        self.declared_classes
    }

    /// Looks up one mapped permission.
    #[must_use]
    pub fn mapping(&self, class: &str, permission: &str) -> Option<&PermissionMapping> {
        self.indexes
            .get(class)
            .and_then(|permissions| permissions.get(permission))
            .and_then(|index| self.mappings.get(*index))
    }
}

fn python_list(values: &[&str]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// An invalid information-flow graph criterion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InformationFlowError {
    /// A concrete type could not be resolved.
    UnknownType(String),
    /// The minimum edge weight is outside 1-10.
    InvalidWeight,
    /// The path depth is zero or negative.
    InvalidDepth,
}

impl fmt::Display for InformationFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(name) => write!(formatter, "{name} is not a valid type"),
            Self::InvalidWeight => {
                formatter.write_str("Min information flow weight must be an integer 1-10.")
            }
            Self::InvalidDepth => {
                formatter.write_str("Information flow max depth must be positive.")
            }
        }
    }
}

impl Error for InformationFlowError {}

/// One directed information-flow edge and its contributing allow rules.
#[derive(Clone, Debug)]
pub struct InformationFlowStep<'policy> {
    source: TypeId,
    target: TypeId,
    rules: Vec<&'policy TeRule>,
    weight: u8,
}

impl<'policy> InformationFlowStep<'policy> {
    /// Returns the source type of the information flow.
    #[must_use]
    pub const fn source(&self) -> TypeId {
        self.source
    }

    /// Returns the target type of the information flow.
    #[must_use]
    pub const fn target(&self) -> TypeId {
        self.target
    }

    /// Returns all allow rules which contribute to this direction.
    #[must_use]
    pub fn rules(&self) -> &[&'policy TeRule] {
        &self.rules
    }

    /// Returns the maximum contributing permission weight.
    #[must_use]
    pub const fn weight(&self) -> u8 {
        self.weight
    }
}

/// Counts from the complete, unfiltered information-flow graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InformationFlowStats {
    /// Types incident to at least one information-flow edge.
    pub nodes: usize,
    /// Directed information-flow edges.
    pub edges: usize,
}

#[derive(Clone, Debug)]
struct Edge<'policy> {
    source: TypeId,
    target: TypeId,
    rules: Vec<&'policy TeRule>,
    weight: u8,
}

impl<'policy> Edge<'policy> {
    fn public(&self) -> InformationFlowStep<'policy> {
        InformationFlowStep {
            source: self.source,
            target: self.target,
            rules: self.rules.clone(),
            weight: self.weight,
        }
    }
}

/// A complete information-flow graph built from allow rules and a permission map.
#[derive(Debug)]
pub struct InformationFlowGraph<'policy> {
    policy: &'policy Policy,
    edges: Vec<Edge<'policy>>,
    nodes: BTreeSet<TypeId>,
}

impl<'policy> InformationFlowGraph<'policy> {
    /// Builds every non-self directed flow, before query filtering.
    #[must_use]
    pub fn new(policy: &'policy Policy, permission_map: &PermissionMap) -> Self {
        let mut edges = Vec::<Edge<'policy>>::new();
        let mut indexes = BTreeMap::<(TypeId, TypeId), usize>::new();
        let mut nodes = BTreeSet::new();

        for rule in policy
            .te_rules()
            .iter()
            .filter(|rule| rule.kind() == TeRuleKind::Allow)
        {
            let (read, write) = rule_weight(policy, permission_map, rule);
            for (source, target) in expanded_pairs(policy, rule) {
                if source == target {
                    continue;
                }
                if write > 0 {
                    add_flow(
                        &mut edges,
                        &mut indexes,
                        &mut nodes,
                        source,
                        target,
                        write,
                        rule,
                    );
                }
                if read > 0 {
                    add_flow(
                        &mut edges,
                        &mut indexes,
                        &mut nodes,
                        target,
                        source,
                        read,
                        rule,
                    );
                }
            }
        }
        Self {
            policy,
            edges,
            nodes,
        }
    }

    /// Returns complete graph counts.
    #[must_use]
    pub fn stats(&self) -> InformationFlowStats {
        InformationFlowStats {
            nodes: self.nodes.len(),
            edges: self.edges.len(),
        }
    }

    /// Returns filtered graph counts, retaining isolated non-excluded nodes.
    pub fn subgraph_stats(
        &self,
        minimum_weight: i32,
        exclude: &[String],
        booleans: Option<&BTreeMap<String, bool>>,
    ) -> Result<InformationFlowStats, InformationFlowError> {
        let (excluded, edges) = self.filtered_edges(minimum_weight, exclude, booleans)?;
        Ok(InformationFlowStats {
            nodes: self
                .nodes
                .iter()
                .filter(|node| !excluded.contains(node))
                .count(),
            edges: edges.len(),
        })
    }

    /// Returns immediate flows out of a source type.
    pub fn flows_out(
        &self,
        source: &str,
        minimum_weight: i32,
        exclude: &[String],
        booleans: Option<&BTreeMap<String, bool>>,
    ) -> Result<Vec<InformationFlowStep<'policy>>, InformationFlowError> {
        let source = self.resolve_type(source)?;
        let (_, edges) = self.filtered_edges(minimum_weight, exclude, booleans)?;
        Ok(edges
            .into_iter()
            .filter(|edge| edge.source == source)
            .map(|edge| edge.public())
            .collect())
    }

    /// Returns immediate flows into a target type.
    pub fn flows_in(
        &self,
        target: &str,
        minimum_weight: i32,
        exclude: &[String],
        booleans: Option<&BTreeMap<String, bool>>,
    ) -> Result<Vec<InformationFlowStep<'policy>>, InformationFlowError> {
        let target = self.resolve_type(target)?;
        let (_, edges) = self.filtered_edges(minimum_weight, exclude, booleans)?;
        Ok(edges
            .into_iter()
            .filter(|edge| edge.target == target)
            .map(|edge| edge.public())
            .collect())
    }

    /// Returns all shortest directed information-flow paths.
    pub fn shortest_paths(
        &self,
        source: &str,
        target: &str,
        minimum_weight: i32,
        exclude: &[String],
        booleans: Option<&BTreeMap<String, bool>>,
    ) -> Result<Vec<Vec<InformationFlowStep<'policy>>>, InformationFlowError> {
        let source = self.resolve_type(source)?;
        let target = self.resolve_type(target)?;
        let (excluded, edges) = self.filtered_edges(minimum_weight, exclude, booleans)?;
        if excluded.contains(&source) || excluded.contains(&target) {
            return Ok(Vec::new());
        }
        let mut distances = BTreeMap::from([(source, 0_usize)]);
        let mut predecessors = BTreeMap::<TypeId, Vec<TypeId>>::new();
        let mut pending = VecDeque::from([source]);
        while let Some(node) = pending.pop_front() {
            let distance = distances[&node];
            for neighbor in neighbors(&edges, node) {
                match distances.get(&neighbor).copied() {
                    None => {
                        distances.insert(neighbor, distance + 1);
                        predecessors.insert(neighbor, vec![node]);
                        pending.push_back(neighbor);
                    }
                    Some(existing) if existing == distance + 1 => {
                        predecessors.entry(neighbor).or_default().push(node);
                    }
                    _ => {}
                }
            }
        }
        if !distances.contains_key(&target) {
            return Ok(Vec::new());
        }
        let mut node_paths = Vec::new();
        let mut reversed = vec![target];
        collect_shortest_paths(
            source,
            target,
            &predecessors,
            &mut reversed,
            &mut node_paths,
        );
        Ok(node_paths
            .into_iter()
            .map(|path| path_to_steps(&edges, &path))
            .collect())
    }

    /// Returns every directed simple path up to `depth_limit` edges.
    pub fn all_paths(
        &self,
        source: &str,
        target: &str,
        depth_limit: i32,
        minimum_weight: i32,
        exclude: &[String],
        booleans: Option<&BTreeMap<String, bool>>,
    ) -> Result<Vec<Vec<InformationFlowStep<'policy>>>, InformationFlowError> {
        if depth_limit < 1 {
            return Err(InformationFlowError::InvalidDepth);
        }
        let source = self.resolve_type(source)?;
        let target = self.resolve_type(target)?;
        let (excluded, edges) = self.filtered_edges(minimum_weight, exclude, booleans)?;
        if excluded.contains(&source) || excluded.contains(&target) {
            return Ok(Vec::new());
        }
        let mut node_paths = Vec::new();
        let mut current = vec![source];
        collect_all_paths(
            &edges,
            target,
            depth_limit as usize,
            &mut current,
            &mut node_paths,
        );
        Ok(node_paths
            .into_iter()
            .map(|path| path_to_steps(&edges, &path))
            .collect())
    }

    fn resolve_type(&self, name: &str) -> Result<TypeId, InformationFlowError> {
        let Some(symbol) = self.policy.type_symbol_by_name(name) else {
            return Err(InformationFlowError::UnknownType(name.to_owned()));
        };
        match symbol.id() {
            TypeOrAttributeId::Type(id) => Ok(id),
            TypeOrAttributeId::Attribute(_) => {
                Err(InformationFlowError::UnknownType(name.to_owned()))
            }
        }
    }

    fn filtered_edges(
        &self,
        minimum_weight: i32,
        exclude: &[String],
        booleans: Option<&BTreeMap<String, bool>>,
    ) -> Result<(BTreeSet<TypeId>, Vec<Edge<'policy>>), InformationFlowError> {
        if !(1..=10).contains(&minimum_weight) {
            return Err(InformationFlowError::InvalidWeight);
        }
        let excluded = exclude
            .iter()
            .map(|name| self.resolve_type(name))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let edges = self
            .edges
            .iter()
            .filter(|edge| {
                !excluded.contains(&edge.source)
                    && !excluded.contains(&edge.target)
                    && i32::from(edge.weight) >= minimum_weight
            })
            .filter_map(|edge| {
                let mut edge = edge.clone();
                if let Some(overrides) = booleans {
                    edge.rules
                        .retain(|rule| rule_enabled(self.policy, rule, overrides));
                }
                (!edge.rules.is_empty()).then_some(edge)
            })
            .collect();
        Ok((excluded, edges))
    }
}

fn add_flow<'policy>(
    edges: &mut Vec<Edge<'policy>>,
    indexes: &mut BTreeMap<(TypeId, TypeId), usize>,
    nodes: &mut BTreeSet<TypeId>,
    source: TypeId,
    target: TypeId,
    weight: u8,
    rule: &'policy TeRule,
) {
    let index = *indexes.entry((source, target)).or_insert_with(|| {
        nodes.insert(source);
        nodes.insert(target);
        edges.push(Edge {
            source,
            target,
            rules: Vec::new(),
            weight: 0,
        });
        edges.len() - 1
    });
    let edge = &mut edges[index];
    edge.rules.push(rule);
    edge.weight = edge.weight.max(weight);
}

fn rule_weight(policy: &Policy, map: &PermissionMap, rule: &TeRule) -> (u8, u8) {
    let TeRuleData::Permissions(permissions) = rule.data() else {
        return (0, 0);
    };
    let Some(target_class) = policy.object_class(rule.target_class()) else {
        return (0, 0);
    };
    let mut read = 0_u8;
    let mut write = 0_u8;
    for permission in permissions {
        let Some(permission) = target_class.permission(*permission) else {
            continue;
        };
        let Some(mapping) = map.mapping(target_class.name(), permission.name()) else {
            continue;
        };
        match mapping.direction {
            PermissionDirection::Read => read = read.max(mapping.weight),
            PermissionDirection::Write => write = write.max(mapping.weight),
            PermissionDirection::Both => {
                read = read.max(mapping.weight);
                write = write.max(mapping.weight);
            }
            PermissionDirection::None | PermissionDirection::Unmapped => {}
        }
    }
    (read, write)
}

fn expanded_pairs(policy: &Policy, rule: &TeRule) -> Vec<(TypeId, TypeId)> {
    let sources = expand(policy, rule.source());
    let targets = expand(policy, rule.target());
    sources
        .into_iter()
        .flat_map(|source| targets.iter().copied().map(move |target| (source, target)))
        .collect()
}

fn expand(policy: &Policy, symbol: TypeOrAttributeId) -> Vec<TypeId> {
    policy
        .type_symbol(symbol)
        .map_or_else(Vec::new, |symbol| symbol.expanded_types().to_vec())
}

fn rule_enabled(policy: &Policy, rule: &TeRule, overrides: &BTreeMap<String, bool>) -> bool {
    let Some(condition) = rule.condition() else {
        return true;
    };
    let Some(expression) = policy.conditional(condition.conditional()) else {
        return false;
    };
    let mut stack = Vec::<bool>::new();
    for token in expression.tokens() {
        match token {
            ConditionalToken::Boolean(id) => {
                let Some(boolean) = policy.boolean(*id) else {
                    return false;
                };
                stack.push(
                    overrides
                        .get(boolean.name())
                        .copied()
                        .unwrap_or_else(|| boolean.state()),
                );
            }
            ConditionalToken::Not => {
                let Some(value) = stack.pop() else {
                    return false;
                };
                stack.push(!value);
            }
            operator => {
                let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
                    return false;
                };
                stack.push(match operator {
                    ConditionalToken::Or => left || right,
                    ConditionalToken::And => left && right,
                    ConditionalToken::Xor => left ^ right,
                    ConditionalToken::Equal => left == right,
                    ConditionalToken::NotEqual => left != right,
                    ConditionalToken::Boolean(_) | ConditionalToken::Not => unreachable!(),
                });
            }
        }
    }
    stack
        .pop()
        .is_some_and(|value| stack.is_empty() && value == condition.block())
}

fn neighbors(edges: &[Edge<'_>], node: TypeId) -> Vec<TypeId> {
    edges
        .iter()
        .filter_map(|edge| (edge.source == node).then_some(edge.target))
        .collect()
}

fn collect_shortest_paths(
    source: TypeId,
    node: TypeId,
    predecessors: &BTreeMap<TypeId, Vec<TypeId>>,
    reversed: &mut Vec<TypeId>,
    output: &mut Vec<Vec<TypeId>>,
) {
    if node == source {
        output.push(reversed.iter().rev().copied().collect());
        return;
    }
    if let Some(previous) = predecessors.get(&node) {
        for predecessor in previous {
            reversed.push(*predecessor);
            collect_shortest_paths(source, *predecessor, predecessors, reversed, output);
            reversed.pop();
        }
    }
}

fn collect_all_paths(
    edges: &[Edge<'_>],
    target: TypeId,
    depth_limit: usize,
    current: &mut Vec<TypeId>,
    output: &mut Vec<Vec<TypeId>>,
) {
    let node = *current.last().expect("path is never empty");
    if node == target {
        output.push(current.clone());
        return;
    }
    if current.len() - 1 == depth_limit {
        return;
    }
    for neighbor in neighbors(edges, node) {
        if current.contains(&neighbor) {
            continue;
        }
        current.push(neighbor);
        collect_all_paths(edges, target, depth_limit, current, output);
        current.pop();
    }
}

fn path_to_steps<'policy>(
    edges: &[Edge<'policy>],
    path: &[TypeId],
) -> Vec<InformationFlowStep<'policy>> {
    path.windows(2)
        .filter_map(|pair| {
            edges
                .iter()
                .find(|edge| edge.source == pair[0] && edge.target == pair[1])
                .map(Edge::public)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{InformationFlowError, InformationFlowGraph, PermissionDirection, PermissionMap};
    use setools_policy::{
        AttributeId, Boolean, BooleanId, ClassId, Conditional, ConditionalId, ConditionalToken,
        HandleUnknown, ObjectClass, Permission, PermissionId, Policy, PolicyMetadata,
        RuleCondition, TargetPlatform, TeRule, TeRuleData, TeRuleKind, TypeId, TypeOrAttributeId,
        TypeSymbol,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const CHANNEL: ClassId = ClassId::from_raw(0);

    fn type_id(raw: u32) -> TypeId {
        TypeId::from_raw(raw)
    }

    fn allow(source: TypeOrAttributeId, target: TypeOrAttributeId, permission: u32) -> TeRule {
        TeRule::new(
            TeRuleKind::Allow,
            source,
            target,
            CHANNEL,
            TeRuleData::Permissions(vec![PermissionId::from_raw(permission)]),
        )
    }

    fn flow_policy() -> Policy {
        let mut types = [
            "alpha",
            "beta",
            "gamma",
            "low",
            "inbound",
            "flow_true",
            "flow_false",
        ]
        .into_iter()
        .enumerate()
        .map(|(id, name)| TypeSymbol::new_type(type_id(id as u32), name.to_owned()))
        .collect::<Vec<_>>();
        types.push(TypeSymbol::new_attribute(
            AttributeId::from_raw(7),
            "writers".to_owned(),
            vec![type_id(0), type_id(4)],
        ));
        let class = ObjectClass::new(
            CHANNEL,
            "channel".to_owned(),
            ["read_low", "read_medium", "write_low", "write_high"]
                .into_iter()
                .enumerate()
                .map(|(id, name)| Permission::new(PermissionId::from_raw(id as u32), name.into()))
                .collect(),
        );
        let condition = ConditionalId::from_raw(0);
        let rules = vec![
            allow(
                TypeOrAttributeId::Type(type_id(0)),
                TypeOrAttributeId::Type(type_id(1)),
                2,
            ),
            allow(
                TypeOrAttributeId::Type(type_id(1)),
                TypeOrAttributeId::Type(type_id(0)),
                1,
            ),
            allow(
                TypeOrAttributeId::Type(type_id(1)),
                TypeOrAttributeId::Type(type_id(2)),
                3,
            ),
            allow(
                TypeOrAttributeId::Type(type_id(0)),
                TypeOrAttributeId::Type(type_id(3)),
                2,
            ),
            allow(
                TypeOrAttributeId::Type(type_id(4)),
                TypeOrAttributeId::Type(type_id(0)),
                3,
            ),
            allow(
                TypeOrAttributeId::Type(type_id(0)),
                TypeOrAttributeId::Type(type_id(5)),
                3,
            )
            .with_condition(RuleCondition::new(condition, true)),
            allow(
                TypeOrAttributeId::Type(type_id(0)),
                TypeOrAttributeId::Type(type_id(6)),
                3,
            )
            .with_condition(RuleCondition::new(condition, false)),
            allow(
                TypeOrAttributeId::Attribute(AttributeId::from_raw(7)),
                TypeOrAttributeId::Type(type_id(3)),
                2,
            ),
        ];
        Policy::from_complete_parts(
            PathBuf::from("infoflow-test.policy"),
            PolicyMetadata {
                version: 35,
                mls: false,
                target: TargetPlatform::Selinux,
                handle_unknown: HandleUnknown::Reject,
            },
            types,
            vec![class],
            vec![Boolean::new(
                BooleanId::from_raw(0),
                "enabled".to_owned(),
                false,
            )],
            vec![Conditional::new(
                condition,
                vec![ConditionalToken::Boolean(BooleanId::from_raw(0))],
            )],
            rules,
        )
    }

    fn flow_map() -> PermissionMap {
        PermissionMap::parse(
            concat!(
                "1\n",
                "class channel 4\n",
                "read_low r 1\n",
                "read_medium r 5\n",
                "write_low w 1\n",
                "write_high w 10\n",
            ),
            "test.map",
        )
        .unwrap()
    }

    #[test]
    fn parses_permission_map_entries_and_built_in_data() {
        let map =
            PermissionMap::parse("1\nclass file 2\nread r 10\nwrite w 7\n", "test.map").unwrap();
        assert_eq!(map.class_count(), 1);
        assert_eq!(map.mappings().len(), 2);
        assert_eq!(
            map.mapping("file", "read").unwrap().direction(),
            PermissionDirection::Read
        );
        assert_eq!(map.mapping("file", "write").unwrap().weight(), 7);

        let built_in = PermissionMap::built_in().unwrap();
        assert_eq!(built_in.class_count(), 134);
        assert!(!built_in.mappings().is_empty());

        let replaced = PermissionMap::parse(
            "2\nclass file 1\nold r 1\nclass file 1\nnew w 2\n",
            "replace.map",
        )
        .unwrap();
        assert!(replaced.mapping("file", "old").is_none());
        assert_eq!(replaced.mapping("file", "new").unwrap().weight(), 2);
    }

    #[test]
    fn reports_compatible_permission_map_errors() {
        let error = PermissionMap::parse("zero\n", "bad.map").unwrap_err();
        assert_eq!(
            error.to_string(),
            "bad.map:1:Invalid number of classes: zero"
        );
        let error =
            PermissionMap::parse("1\nclass file 1\nread sideways 3\n", "bad.map").unwrap_err();
        assert_eq!(
            error.to_string(),
            "bad.map:3:Invalid information flow direction: sideways"
        );
        let error = PermissionMap::parse("-1\n", "bad.map").unwrap_err();
        assert_eq!(
            error.to_string(),
            "bad.map:1:Number of classes must be positive: -1"
        );
        let error = PermissionMap::parse("1\nclass file 1\nread r -1\n", "bad.map").unwrap_err();
        assert_eq!(
            error.to_string(),
            "bad.map:3:Permission weight must be 1-10: -1"
        );
    }

    #[test]
    fn builds_weighted_edges_and_expands_attributes() {
        let policy = flow_policy();
        let graph = InformationFlowGraph::new(&policy, &flow_map());
        assert_eq!(graph.stats().nodes, 7);
        assert_eq!(graph.stats().edges, 7);

        let flows = graph.flows_out("alpha", 1, &[], None).unwrap();
        assert_eq!(flows.len(), 4);
        assert_eq!(flows[0].target(), type_id(1));
        assert_eq!(flows[0].weight(), 5);
        assert_eq!(flows[0].rules().len(), 2);
        assert_eq!(flows[1].target(), type_id(3));
        assert_eq!(flows[1].rules().len(), 2);

        let expanded = graph.flows_out("inbound", 1, &[], None).unwrap();
        assert_eq!(expanded.len(), 2);
        assert!(expanded.iter().any(|flow| flow.target() == type_id(3)));
    }

    #[test]
    fn filters_weights_exclusions_and_conditional_branches() {
        let policy = flow_policy();
        let graph = InformationFlowGraph::new(&policy, &flow_map());
        let weighted = graph.flows_out("alpha", 3, &[], None).unwrap();
        assert_eq!(weighted.len(), 3);
        assert!(weighted.iter().all(|flow| flow.weight() >= 3));

        let defaults = BTreeMap::new();
        let filtered = graph.flows_out("alpha", 1, &[], Some(&defaults)).unwrap();
        assert!(filtered.iter().any(|flow| flow.target() == type_id(6)));
        assert!(!filtered.iter().any(|flow| flow.target() == type_id(5)));

        let enabled = BTreeMap::from([("enabled".to_owned(), true)]);
        let filtered = graph.flows_out("alpha", 1, &[], Some(&enabled)).unwrap();
        assert!(filtered.iter().any(|flow| flow.target() == type_id(5)));
        assert!(!filtered.iter().any(|flow| flow.target() == type_id(6)));

        let excluded = graph
            .flows_out("alpha", 1, &["beta".to_owned()], None)
            .unwrap();
        assert!(!excluded.iter().any(|flow| flow.target() == type_id(1)));
    }

    #[test]
    fn enumerates_paths_reverse_flows_and_errors() {
        let policy = flow_policy();
        let graph = InformationFlowGraph::new(&policy, &flow_map());
        let shortest = graph
            .shortest_paths("alpha", "gamma", 1, &[], None)
            .unwrap();
        assert_eq!(shortest.len(), 1);
        assert_eq!(shortest[0].len(), 2);
        assert_eq!(shortest[0][1].target(), type_id(2));

        let paths = graph.all_paths("alpha", "gamma", 2, 1, &[], None).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 2);
        let reverse = graph.flows_in("alpha", 1, &[], None).unwrap();
        assert_eq!(reverse.len(), 1);
        assert_eq!(reverse[0].source(), type_id(4));

        assert_eq!(
            graph.flows_out("missing", 1, &[], None).unwrap_err(),
            InformationFlowError::UnknownType("missing".to_owned())
        );
        assert_eq!(
            graph.flows_out("alpha", 0, &[], None).unwrap_err(),
            InformationFlowError::InvalidWeight
        );
        assert_eq!(
            graph
                .all_paths("alpha", "gamma", 0, 1, &[], None)
                .unwrap_err(),
            InformationFlowError::InvalidDepth
        );
    }
}
