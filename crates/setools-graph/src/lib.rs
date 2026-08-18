//! Domain-transition and information-flow graph analysis.

use setools_policy::Policy;

/// Shared graph-analysis context.
#[derive(Debug)]
pub struct AnalysisGraph<'policy> {
    policy: &'policy Policy,
}

impl<'policy> AnalysisGraph<'policy> {
    /// Creates an empty graph context for a policy.
    #[must_use]
    pub const fn new(policy: &'policy Policy) -> Self {
        Self { policy }
    }

    /// Returns the policy from which the graph will be built.
    #[must_use]
    pub const fn policy(&self) -> &'policy Policy {
        self.policy
    }
}
