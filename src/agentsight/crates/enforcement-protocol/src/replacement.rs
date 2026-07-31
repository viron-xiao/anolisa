//! Typed compare-and-replace contract for policy ownership handoff.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{ApplyCredentialPolicy, ApplyPolicy, Binding, BindingState, PolicyValidationError};

/// Policy request that replaces one currently enforced binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "request", rename_all = "snake_case")]
pub enum ReplacementPolicy {
    /// Applies an already compiled product policy expressed as ActPlane DSL.
    Generic(ApplyPolicy),
    /// Compiles a product-level credential policy inside the privileged adapter.
    Credential(ApplyCredentialPolicy),
}

impl ReplacementPolicy {
    /// Returns the stable identifier of the replacement binding.
    pub fn binding_id(&self) -> Uuid {
        match self {
            Self::Generic(request) => request.binding_id,
            Self::Credential(request) => request.binding_id,
        }
    }
}

/// Compare-and-replace request for one exact active binding snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacePolicy {
    /// Complete source acknowledgement that must still own the runtime.
    pub expected: Binding,
    /// Desired policy that receives ownership after a successful handoff.
    pub replacement: ReplacementPolicy,
}

impl ReplacePolicy {
    /// Validates invariants required before privileged runtime mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed error when source and target identities overlap, the
    /// source is not an enforced acknowledgement, or a credential target is
    /// not a valid bounded product policy.
    pub fn validate(&self) -> Result<(), ReplaceValidationError> {
        if self.expected.request.binding_id == self.replacement.binding_id() {
            return Err(ReplaceValidationError::SameBindingId);
        }
        if self.expected.state != BindingState::Enforced {
            return Err(ReplaceValidationError::SourceNotEnforced);
        }
        if let ReplacementPolicy::Credential(request) = &self.replacement {
            request.policy.validate()?;
        }
        Ok(())
    }
}

/// Stable replacement validation failure safe to expose across the UDS boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ReplaceValidationError {
    /// Source and target bindings must be different immutable identities.
    #[error("source and replacement binding IDs must differ")]
    SameBindingId,
    /// A handoff may replace only a binding acknowledged as enforced.
    #[error("source binding must be enforced")]
    SourceNotEnforced,
    /// The product-level credential target is invalid.
    #[error("replacement credential policy is invalid: {0}")]
    CredentialPolicy(#[from] PolicyValidationError),
}

/// Stable failure category returned for a replacement that did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaceFailureCode {
    /// Actual runtime ownership did not match the expected source.
    BindingConflict,
    /// The replacement process identity was stale or reused.
    StaleProcess,
    /// The replacement or source policy could not be compiled.
    CompileFailure,
    /// Kernel attachment or runtime state management failed.
    KernelFailure,
}

/// Result of a serialized replacement attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub enum ReplaceOutcome {
    /// Replacement was acknowledged and now owns the runtime.
    Applied(Binding),
    /// Replacement was rejected before detachment and the source remained active.
    SourceRetained {
        /// Source binding that still owns the runtime.
        binding: Binding,
        /// Stable reason the replacement was not attempted.
        code: ReplaceFailureCode,
    },
    /// Replacement failed after detachment and the source was restored.
    SourceRestored {
        /// Source binding acknowledged after rollback.
        binding: Binding,
        /// Stable reason the replacement failed.
        code: ReplaceFailureCode,
    },
    /// A different binding owned the runtime and was left untouched.
    Conflict {
        /// Stable ownership-conflict category.
        code: ReplaceFailureCode,
    },
    /// Neither replacement nor source ownership could be proven.
    Indeterminate {
        /// Stable category for the failed runtime operation.
        code: ReplaceFailureCode,
    },
}
