//! Domain-transition and information-flow graph analysis.

mod infoflow;

pub use infoflow::{
    InformationFlowError, InformationFlowGraph, InformationFlowStats, InformationFlowStep,
    PermissionDirection, PermissionMap, PermissionMapError, PermissionMapping,
};

use setools_policy::{Policy, TeRule, TeRuleData, TeRuleKind, TypeId, TypeOrAttributeId};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

/// An invalid graph-analysis criterion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphError {
    /// A concrete policy type could not be resolved.
    UnknownType(String),
    /// An all-paths depth limit was zero or negative.
    InvalidDepth,
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(name) => write!(formatter, "{name} is not a valid type"),
            Self::InvalidDepth => {
                formatter.write_str("Domain transition max depth must be positive.")
            }
        }
    }
}

impl Error for GraphError {}

/// The rules which make one executable type a domain entrypoint.
#[derive(Clone, Debug)]
pub struct DomainEntrypoint<'policy> {
    name: TypeId,
    entrypoint: Vec<&'policy TeRule>,
    execute: Vec<&'policy TeRule>,
    type_transition: Vec<&'policy TeRule>,
}

impl<'policy> DomainEntrypoint<'policy> {
    /// Returns the concrete executable type.
    #[must_use]
    pub const fn name(&self) -> TypeId {
        self.name
    }

    /// Returns the target domain's `entrypoint` rules.
    #[must_use]
    pub fn entrypoint_rules(&self) -> &[&'policy TeRule] {
        &self.entrypoint
    }

    /// Returns the source domain's `execute` rules.
    #[must_use]
    pub fn execute_rules(&self) -> &[&'policy TeRule] {
        &self.execute
    }

    /// Returns matching automatic `type_transition` rules.
    #[must_use]
    pub fn type_transition_rules(&self) -> &[&'policy TeRule] {
        &self.type_transition
    }
}

/// One valid standard and/or dynamic domain-transition edge.
#[derive(Clone, Debug)]
pub struct DomainTransition<'policy> {
    source: TypeId,
    target: TypeId,
    transition: Vec<&'policy TeRule>,
    entrypoints: Vec<DomainEntrypoint<'policy>>,
    setexec: Vec<&'policy TeRule>,
    dyntransition: Vec<&'policy TeRule>,
    setcurrent: Vec<&'policy TeRule>,
}

impl<'policy> DomainTransition<'policy> {
    /// Returns the source domain.
    #[must_use]
    pub const fn source(&self) -> TypeId {
        self.source
    }

    /// Returns the target domain.
    #[must_use]
    pub const fn target(&self) -> TypeId {
        self.target
    }

    /// Returns standard `process transition` rules.
    #[must_use]
    pub fn transition_rules(&self) -> &[&'policy TeRule] {
        &self.transition
    }

    /// Returns executable entrypoint details in canonical-name order.
    #[must_use]
    pub fn entrypoints(&self) -> &[DomainEntrypoint<'policy>] {
        &self.entrypoints
    }

    /// Returns source-domain `setexec` rules.
    #[must_use]
    pub fn setexec_rules(&self) -> &[&'policy TeRule] {
        &self.setexec
    }

    /// Returns `process dyntransition` rules.
    #[must_use]
    pub fn dyntransition_rules(&self) -> &[&'policy TeRule] {
        &self.dyntransition
    }

    /// Returns source-domain `setcurrent` rules.
    #[must_use]
    pub fn setcurrent_rules(&self) -> &[&'policy TeRule] {
        &self.setcurrent
    }
}

/// Counts from the unfiltered domain-transition graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainTransitionStats {
    /// Nodes introduced by candidate transition/dyntransition rules.
    pub nodes: usize,
    /// Valid standard and/or dynamic transition edges.
    pub edges: usize,
}

#[derive(Clone, Debug)]
struct Edge<'policy> {
    source: TypeId,
    target: TypeId,
    transition: Vec<&'policy TeRule>,
    entrypoints: Vec<DomainEntrypoint<'policy>>,
    setexec: Vec<&'policy TeRule>,
    dyntransition: Vec<&'policy TeRule>,
    setcurrent: Vec<&'policy TeRule>,
}

impl<'policy> Edge<'policy> {
    fn public(&self) -> DomainTransition<'policy> {
        DomainTransition {
            source: self.source,
            target: self.target,
            transition: self.transition.clone(),
            entrypoints: self.entrypoints.clone(),
            setexec: self.setexec.clone(),
            dyntransition: self.dyntransition.clone(),
            setcurrent: self.setcurrent.clone(),
        }
    }
}

type RuleMap<'policy> = BTreeMap<TypeId, Vec<&'policy TeRule>>;
type EntryRuleMap<'policy> = BTreeMap<TypeId, RuleMap<'policy>>;
type TransitionRuleMap<'policy> = BTreeMap<TypeId, BTreeMap<TypeId, RuleMap<'policy>>>;

/// A complete, immutable domain-transition graph built from an owned policy.
///
/// Edge order follows the policy rule snapshot, matching the legacy graph's
/// breadth-first and path enumeration order while remaining deterministic.
#[derive(Debug)]
pub struct DomainTransitionGraph<'policy> {
    policy: &'policy Policy,
    edges: Vec<Edge<'policy>>,
    nodes: BTreeSet<TypeId>,
}

impl<'policy> DomainTransitionGraph<'policy> {
    /// Builds and validates all standard and dynamic domain-transition edges.
    #[must_use]
    pub fn new(policy: &'policy Policy) -> Self {
        let process = policy
            .object_class_by_name("process")
            .map(|class| class.id());
        let file = policy.object_class_by_name("file").map(|class| class.id());
        let mut edges = Vec::<Edge<'policy>>::new();
        let mut edge_indexes = BTreeMap::<(TypeId, TypeId), usize>::new();
        let mut nodes = BTreeSet::new();
        let mut setexec = RuleMap::new();
        let mut setcurrent = RuleMap::new();
        let mut execute = EntryRuleMap::new();
        let mut entrypoint = EntryRuleMap::new();
        let mut type_trans = TransitionRuleMap::new();

        for rule in policy.te_rules() {
            match rule.kind() {
                TeRuleKind::Allow if Some(rule.target_class()) == process => {
                    if has_permission(policy, rule, "transition") {
                        for (source, target) in expanded_pairs(policy, rule) {
                            if source != target {
                                let edge = edge_mut(
                                    &mut edges,
                                    &mut edge_indexes,
                                    &mut nodes,
                                    source,
                                    target,
                                );
                                edge.transition.push(rule);
                            }
                        }
                    }
                    if has_permission(policy, rule, "dyntransition") {
                        for (source, target) in expanded_pairs(policy, rule) {
                            if source != target {
                                let edge = edge_mut(
                                    &mut edges,
                                    &mut edge_indexes,
                                    &mut nodes,
                                    source,
                                    target,
                                );
                                edge.dyntransition.push(rule);
                            }
                        }
                    }
                    if has_permission(policy, rule, "setexec") {
                        for source in expand(policy, rule.source()) {
                            setexec.entry(source).or_default().push(rule);
                        }
                    }
                    if has_permission(policy, rule, "setcurrent") {
                        for source in expand(policy, rule.source()) {
                            setcurrent.entry(source).or_default().push(rule);
                        }
                    }
                }
                TeRuleKind::Allow if Some(rule.target_class()) == file => {
                    if has_permission(policy, rule, "execute") {
                        add_pair_rules(policy, rule, &mut execute);
                    }
                    if has_permission(policy, rule, "entrypoint") {
                        add_pair_rules(policy, rule, &mut entrypoint);
                    }
                }
                TeRuleKind::TypeTransition if Some(rule.target_class()) == process => {
                    let TeRuleData::DefaultType { default, .. } = rule.data() else {
                        continue;
                    };
                    for (source, executable) in expanded_pairs(policy, rule) {
                        type_trans
                            .entry(source)
                            .or_default()
                            .entry(executable)
                            .or_default()
                            .entry(*default)
                            .or_default()
                            .push(rule);
                    }
                }
                _ => {}
            }
        }

        for edge in &mut edges {
            let mut standard_valid = false;
            if !edge.transition.is_empty() {
                let source_execute = execute.get(&edge.source);
                let target_entrypoint = entrypoint.get(&edge.target);
                if let (Some(source_execute), Some(target_entrypoint)) =
                    (source_execute, target_entrypoint)
                {
                    let source_setexec = setexec.get(&edge.source);
                    for executable in source_execute
                        .keys()
                        .filter(|executable| target_entrypoint.contains_key(executable))
                    {
                        let automatic = type_trans
                            .get(&edge.source)
                            .and_then(|by_executable| by_executable.get(executable));
                        if source_setexec.is_some() || automatic.is_some() {
                            let mut type_transition = automatic
                                .and_then(|by_target| by_target.get(&edge.target))
                                .cloned()
                                .unwrap_or_default();
                            sort_rules(policy, &mut type_transition);
                            edge.entrypoints.push(DomainEntrypoint {
                                name: *executable,
                                entrypoint: target_entrypoint[executable].clone(),
                                execute: source_execute[executable].clone(),
                                type_transition,
                            });
                        }
                    }
                    edge.entrypoints.sort_by(|left, right| {
                        type_name(policy, left.name).cmp(type_name(policy, right.name))
                    });
                    if let Some(rules) = source_setexec {
                        edge.setexec.clone_from(rules);
                    }
                    standard_valid = !edge.setexec.is_empty()
                        || edge
                            .entrypoints
                            .iter()
                            .any(|entry| !entry.type_transition.is_empty());
                }
            }

            let dynamic_valid = !edge.dyntransition.is_empty()
                && setcurrent
                    .get(&edge.source)
                    .is_some_and(|rules| !rules.is_empty());
            if dynamic_valid {
                edge.setcurrent = setcurrent[&edge.source].clone();
            }
            if !standard_valid {
                edge.transition.clear();
                edge.entrypoints.clear();
                edge.setexec.clear();
            }
            if !dynamic_valid {
                edge.dyntransition.clear();
                edge.setcurrent.clear();
            }
        }
        edges.retain(|edge| !edge.transition.is_empty() || !edge.dyntransition.is_empty());

        Self {
            policy,
            edges,
            nodes,
        }
    }

    /// Returns the source policy.
    #[must_use]
    pub const fn policy(&self) -> &'policy Policy {
        self.policy
    }

    /// Returns counts for the unfiltered graph.
    #[must_use]
    pub fn stats(&self) -> DomainTransitionStats {
        DomainTransitionStats {
            nodes: self.nodes.len(),
            edges: self.edges.len(),
        }
    }

    /// Returns counts after excluding domain and entrypoint types.
    pub fn subgraph_stats(&self, exclude: &[String]) -> Result<DomainTransitionStats, GraphError> {
        let excluded = self.resolve_excluded(exclude)?;
        Ok(DomainTransitionStats {
            nodes: self
                .nodes
                .iter()
                .filter(|node| !excluded.contains(node))
                .count(),
            edges: self.filtered_edges(&excluded).len(),
        })
    }

    /// Returns immediate valid transitions out of a source domain.
    pub fn transitions_out(
        &self,
        source: &str,
        exclude: &[String],
    ) -> Result<Vec<DomainTransition<'policy>>, GraphError> {
        let source = self.resolve_type(source)?;
        let excluded = self.resolve_excluded(exclude)?;
        Ok(self
            .filtered_edges(&excluded)
            .into_iter()
            .filter(|edge| edge.source == source)
            .map(|edge| edge.public())
            .collect())
    }

    /// Returns immediate valid transitions into a target domain.
    pub fn transitions_in(
        &self,
        target: &str,
        exclude: &[String],
    ) -> Result<Vec<DomainTransition<'policy>>, GraphError> {
        let target = self.resolve_type(target)?;
        let excluded = self.resolve_excluded(exclude)?;
        Ok(self
            .filtered_edges(&excluded)
            .into_iter()
            .filter(|edge| edge.target == target)
            .map(|edge| edge.public())
            .collect())
    }

    /// Returns every shortest path between two query-perspective domains.
    pub fn shortest_paths(
        &self,
        source: &str,
        target: &str,
        reverse: bool,
        exclude: &[String],
    ) -> Result<Vec<Vec<DomainTransition<'policy>>>, GraphError> {
        let source = self.resolve_type(source)?;
        let target = self.resolve_type(target)?;
        let excluded = self.resolve_excluded(exclude)?;
        let edges = self.filtered_edges(&excluded);
        if excluded.contains(&source) || excluded.contains(&target) {
            return Ok(Vec::new());
        }

        let mut distances = BTreeMap::from([(source, 0_usize)]);
        let mut predecessors = BTreeMap::<TypeId, Vec<TypeId>>::new();
        let mut pending = VecDeque::from([source]);
        while let Some(node) = pending.pop_front() {
            let distance = distances[&node];
            for neighbor in neighbors(&edges, node, reverse) {
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
        let mut reversed_path = vec![target];
        collect_shortest_paths(
            source,
            target,
            &predecessors,
            &mut reversed_path,
            &mut node_paths,
        );
        Ok(node_paths
            .into_iter()
            .map(|path| path_to_steps(&edges, &path, reverse))
            .collect())
    }

    /// Returns every simple path up to `depth_limit` edges.
    pub fn all_paths(
        &self,
        source: &str,
        target: &str,
        depth_limit: i32,
        reverse: bool,
        exclude: &[String],
    ) -> Result<Vec<Vec<DomainTransition<'policy>>>, GraphError> {
        if depth_limit < 1 {
            return Err(GraphError::InvalidDepth);
        }
        let source = self.resolve_type(source)?;
        let target = self.resolve_type(target)?;
        let excluded = self.resolve_excluded(exclude)?;
        if excluded.contains(&source) || excluded.contains(&target) {
            return Ok(Vec::new());
        }
        let edges = self.filtered_edges(&excluded);
        let mut node_paths = Vec::new();
        let mut current = vec![source];
        collect_all_paths(
            &edges,
            target,
            depth_limit as usize,
            reverse,
            &mut current,
            &mut node_paths,
        );
        Ok(node_paths
            .into_iter()
            .map(|path| path_to_steps(&edges, &path, reverse))
            .collect())
    }

    fn resolve_type(&self, name: &str) -> Result<TypeId, GraphError> {
        let Some(symbol) = self.policy.type_symbol_by_name(name) else {
            return Err(GraphError::UnknownType(name.to_owned()));
        };
        match symbol.id() {
            TypeOrAttributeId::Type(id) => Ok(id),
            TypeOrAttributeId::Attribute(_) => Err(GraphError::UnknownType(name.to_owned())),
        }
    }

    fn resolve_excluded(&self, names: &[String]) -> Result<BTreeSet<TypeId>, GraphError> {
        names.iter().map(|name| self.resolve_type(name)).collect()
    }

    fn filtered_edges(&self, excluded: &BTreeSet<TypeId>) -> Vec<Edge<'policy>> {
        self.edges
            .iter()
            .filter(|edge| !excluded.contains(&edge.source) && !excluded.contains(&edge.target))
            .filter_map(|edge| {
                let mut edge = edge.clone();
                edge.entrypoints
                    .retain(|entrypoint| !excluded.contains(&entrypoint.name));
                if edge.entrypoints.is_empty() && edge.dyntransition.is_empty() {
                    None
                } else {
                    Some(edge)
                }
            })
            .collect()
    }
}

fn edge_mut<'graph, 'policy>(
    edges: &'graph mut Vec<Edge<'policy>>,
    indexes: &mut BTreeMap<(TypeId, TypeId), usize>,
    nodes: &mut BTreeSet<TypeId>,
    source: TypeId,
    target: TypeId,
) -> &'graph mut Edge<'policy> {
    let index = *indexes.entry((source, target)).or_insert_with(|| {
        nodes.insert(source);
        nodes.insert(target);
        edges.push(Edge {
            source,
            target,
            transition: Vec::new(),
            entrypoints: Vec::new(),
            setexec: Vec::new(),
            dyntransition: Vec::new(),
            setcurrent: Vec::new(),
        });
        edges.len() - 1
    });
    &mut edges[index]
}

fn add_pair_rules<'policy>(
    policy: &'policy Policy,
    rule: &'policy TeRule,
    output: &mut EntryRuleMap<'policy>,
) {
    for (source, target) in expanded_pairs(policy, rule) {
        output
            .entry(source)
            .or_default()
            .entry(target)
            .or_default()
            .push(rule);
    }
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

fn has_permission(policy: &Policy, rule: &TeRule, expected: &str) -> bool {
    let TeRuleData::Permissions(permissions) = rule.data() else {
        return false;
    };
    let Some(target_class) = policy.object_class(rule.target_class()) else {
        return false;
    };
    permissions.iter().any(|permission| {
        target_class
            .permission(*permission)
            .is_some_and(|permission| permission.name() == expected)
    })
}

fn type_name(policy: &Policy, id: TypeId) -> &str {
    policy
        .type_symbol(TypeOrAttributeId::Type(id))
        .map_or("", |symbol| symbol.name())
}

fn sort_rules(policy: &Policy, rules: &mut Vec<&TeRule>) {
    rules.sort_by_key(|rule| rule_sort_key(policy, rule));
}

fn rule_sort_key(policy: &Policy, rule: &TeRule) -> (String, String, String, String) {
    let source = policy
        .type_symbol(rule.source())
        .map_or_else(String::new, |symbol| symbol.name().to_owned());
    let target = policy
        .type_symbol(rule.target())
        .map_or_else(String::new, |symbol| symbol.name().to_owned());
    let target_class = policy
        .object_class(rule.target_class())
        .map_or_else(String::new, |class| class.name().to_owned());
    (
        rule.kind().keyword().to_owned(),
        source,
        target,
        target_class,
    )
}

fn neighbors(edges: &[Edge<'_>], node: TypeId, reverse: bool) -> Vec<TypeId> {
    edges
        .iter()
        .filter_map(|edge| {
            let (source, target) = if reverse {
                (edge.target, edge.source)
            } else {
                (edge.source, edge.target)
            };
            (source == node).then_some(target)
        })
        .collect()
}

fn collect_shortest_paths(
    source: TypeId,
    node: TypeId,
    predecessors: &BTreeMap<TypeId, Vec<TypeId>>,
    reversed_path: &mut Vec<TypeId>,
    output: &mut Vec<Vec<TypeId>>,
) {
    if node == source {
        output.push(reversed_path.iter().rev().copied().collect());
        return;
    }
    if let Some(previous) = predecessors.get(&node) {
        for predecessor in previous {
            reversed_path.push(*predecessor);
            collect_shortest_paths(source, *predecessor, predecessors, reversed_path, output);
            reversed_path.pop();
        }
    }
}

fn collect_all_paths(
    edges: &[Edge<'_>],
    target: TypeId,
    depth_limit: usize,
    reverse: bool,
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
    for neighbor in neighbors(edges, node, reverse) {
        if current.contains(&neighbor) {
            continue;
        }
        current.push(neighbor);
        collect_all_paths(edges, target, depth_limit, reverse, current, output);
        current.pop();
    }
}

fn path_to_steps<'policy>(
    edges: &[Edge<'policy>],
    path: &[TypeId],
    reverse: bool,
) -> Vec<DomainTransition<'policy>> {
    path.windows(2)
        .filter_map(|pair| {
            let (source, target) = if reverse {
                (pair[1], pair[0])
            } else {
                (pair[0], pair[1])
            };
            edges
                .iter()
                .find(|edge| edge.source == source && edge.target == target)
                .map(Edge::public)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DomainTransitionGraph, GraphError};
    use setools_policy::{
        AttributeId, ClassId, HandleUnknown, ObjectClass, Permission, PermissionId, Policy,
        PolicyMetadata, TargetPlatform, TeRule, TeRuleData, TeRuleKind, TypeId, TypeOrAttributeId,
        TypeSymbol,
    };
    use std::path::PathBuf;

    const PROCESS: ClassId = ClassId::from_raw(0);
    const FILE: ClassId = ClassId::from_raw(1);

    fn type_id(raw: u32) -> TypeId {
        TypeId::from_raw(raw)
    }

    fn symbol(raw: u32, name: &str) -> TypeSymbol {
        TypeSymbol::new_type(type_id(raw), name.to_owned())
    }

    fn allow(source: u32, target: u32, class: ClassId, permissions: &[u32]) -> TeRule {
        TeRule::new(
            TeRuleKind::Allow,
            TypeOrAttributeId::Type(type_id(source)),
            TypeOrAttributeId::Type(type_id(target)),
            class,
            TeRuleData::Permissions(
                permissions
                    .iter()
                    .copied()
                    .map(PermissionId::from_raw)
                    .collect(),
            ),
        )
    }

    fn type_transition(source: u32, executable: u32, target: u32) -> TeRule {
        TeRule::new(
            TeRuleKind::TypeTransition,
            TypeOrAttributeId::Type(type_id(source)),
            TypeOrAttributeId::Type(type_id(executable)),
            PROCESS,
            TeRuleData::DefaultType {
                default: type_id(target),
                filename: None,
            },
        )
    }

    fn policy() -> Policy {
        let mut types = [
            "alpha",
            "beta",
            "beta_exec",
            "gamma",
            "gamma_exec",
            "dynamic",
            "invalid",
        ]
        .into_iter()
        .enumerate()
        .map(|(id, name)| symbol(id as u32, name))
        .collect::<Vec<_>>();
        types.push(TypeSymbol::new_attribute(
            AttributeId::from_raw(7),
            "source_domains".to_owned(),
            vec![type_id(0), type_id(5)],
        ));
        let process = ObjectClass::new(
            PROCESS,
            "process".to_owned(),
            ["transition", "dyntransition", "setexec", "setcurrent"]
                .into_iter()
                .enumerate()
                .map(|(id, name)| Permission::new(PermissionId::from_raw(id as u32), name.into()))
                .collect(),
        );
        let file = ObjectClass::new(
            FILE,
            "file".to_owned(),
            ["execute", "entrypoint"]
                .into_iter()
                .enumerate()
                .map(|(id, name)| Permission::new(PermissionId::from_raw(id as u32), name.into()))
                .collect(),
        );
        let rules = vec![
            allow(0, 1, PROCESS, &[0]),
            allow(0, 2, FILE, &[0]),
            allow(1, 2, FILE, &[1]),
            type_transition(0, 2, 1),
            allow(1, 3, PROCESS, &[0]),
            allow(1, 1, PROCESS, &[2]),
            allow(1, 4, FILE, &[0]),
            allow(3, 4, FILE, &[1]),
            allow(0, 5, PROCESS, &[1]),
            allow(0, 0, PROCESS, &[3]),
            allow(0, 6, PROCESS, &[0]),
            allow(5, 3, PROCESS, &[1]),
            allow(5, 5, PROCESS, &[3]),
            TeRule::new(
                TeRuleKind::Allow,
                TypeOrAttributeId::Attribute(AttributeId::from_raw(7)),
                TypeOrAttributeId::Type(type_id(1)),
                PROCESS,
                TeRuleData::Permissions(vec![PermissionId::from_raw(0)]),
            ),
            TeRule::new(
                TeRuleKind::Allow,
                TypeOrAttributeId::Attribute(AttributeId::from_raw(7)),
                TypeOrAttributeId::Type(type_id(2)),
                FILE,
                TeRuleData::Permissions(vec![PermissionId::from_raw(0)]),
            ),
            TeRule::new(
                TeRuleKind::TypeTransition,
                TypeOrAttributeId::Attribute(AttributeId::from_raw(7)),
                TypeOrAttributeId::Type(type_id(2)),
                PROCESS,
                TeRuleData::DefaultType {
                    default: type_id(1),
                    filename: None,
                },
            ),
        ];
        Policy::from_parts(
            PathBuf::from("graph-test.policy"),
            PolicyMetadata {
                version: 35,
                mls: false,
                target: TargetPlatform::Selinux,
                handle_unknown: HandleUnknown::Reject,
            },
            types,
            vec![process, file],
            rules,
        )
    }

    #[test]
    fn builds_only_complete_standard_and_dynamic_transitions() {
        let policy = policy();
        let graph = DomainTransitionGraph::new(&policy);
        assert_eq!(graph.stats().nodes, 5);
        assert_eq!(graph.stats().edges, 5);

        let transitions = graph.transitions_out("alpha", &[]).unwrap();
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].target(), type_id(1));
        assert_eq!(transitions[0].entrypoints()[0].name(), type_id(2));
        assert_eq!(transitions[1].target(), type_id(5));
        assert!(transitions[1].transition_rules().is_empty());
        assert_eq!(transitions[1].dyntransition_rules().len(), 1);
    }

    #[test]
    fn enumerates_forward_and_reverse_paths() {
        let policy = policy();
        let graph = DomainTransitionGraph::new(&policy);
        let paths = graph.shortest_paths("alpha", "gamma", false, &[]).unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].len(), 2);
        assert_eq!(paths[0][0].source(), type_id(0));
        assert_eq!(paths[0][1].target(), type_id(3));
        assert_eq!(paths[1][0].target(), type_id(5));
        assert_eq!(paths[1][1].source(), type_id(5));

        let reverse = graph.shortest_paths("gamma", "alpha", true, &[]).unwrap();
        assert_eq!(reverse.len(), 2);
        assert_eq!(reverse[0][0].source(), type_id(1));
        assert_eq!(reverse[0][0].target(), type_id(3));
        assert_eq!(reverse[0][1].source(), type_id(0));

        let expanded = graph.transitions_out("dynamic", &[]).unwrap();
        assert!(expanded.iter().any(|transition| {
            transition.target() == type_id(1) && !transition.transition_rules().is_empty()
        }));
    }

    #[test]
    fn excludes_domains_and_entrypoints_and_validates_names() {
        let policy = policy();
        let graph = DomainTransitionGraph::new(&policy);
        assert!(
            graph
                .transitions_out("alpha", &["beta_exec".to_owned()])
                .unwrap()
                .iter()
                .all(|transition| transition.target() != type_id(1))
        );
        assert_eq!(
            graph.transitions_out("missing", &[]).unwrap_err(),
            GraphError::UnknownType("missing".to_owned())
        );
        assert!(matches!(
            graph.all_paths("alpha", "gamma", 0, false, &[]),
            Err(GraphError::InvalidDepth)
        ));
    }
}
