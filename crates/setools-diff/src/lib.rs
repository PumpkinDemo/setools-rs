//! Semantic comparison of two owned SELinux policies.

use setools_policy::Policy;

/// A lazily evaluated semantic policy comparison.
#[derive(Debug)]
pub struct PolicyDiff<'policy> {
    left: &'policy Policy,
    right: &'policy Policy,
}

impl<'policy> PolicyDiff<'policy> {
    /// Creates a comparison without computing any components.
    #[must_use]
    pub const fn new(left: &'policy Policy, right: &'policy Policy) -> Self {
        Self { left, right }
    }

    /// Returns the left policy.
    #[must_use]
    pub const fn left(&self) -> &'policy Policy {
        self.left
    }

    /// Returns the right policy.
    #[must_use]
    pub const fn right(&self) -> &'policy Policy {
        self.right
    }
}
