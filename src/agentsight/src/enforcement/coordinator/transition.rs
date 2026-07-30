//! Coordinator boundary for durable policy ownership replacement.

use agentsight_enforcement_protocol::{ReplaceOutcome, ReplacePolicy, ReplacementPolicy};

use super::{
    EnforcementClient, EnforcementCoordinator, EnforcementCoordinatorError, EnforcementError,
    EnforcementStore,
};
use crate::enforcement::{PolicyTransition, TransitionKey, TransitionPhase};

/// Replacement operation used by live and scripted reconciliation clients.
pub(super) trait ReplacementClient {
    fn replace(&self, request: ReplacePolicy) -> Result<ReplaceOutcome, EnforcementError>;
}

impl ReplacementClient for EnforcementClient {
    fn replace(&self, request: ReplacePolicy) -> Result<ReplaceOutcome, EnforcementError> {
        EnforcementClient::replace(self, request)
    }
}

impl EnforcementCoordinator {
    /// Persists a new transition before asking the enforcer to replace policy ownership.
    ///
    /// # Errors
    ///
    /// Returns when ingestion is unavailable, persistence fails, transport is
    /// lost, or the enforcer cannot prove one exact owner.
    pub fn begin_transition(
        &self,
        key: TransitionKey,
        request: ReplacePolicy,
    ) -> Result<PolicyTransition, EnforcementCoordinatorError> {
        let _lifecycle = self.lifecycle();
        if !self.ingestion_readiness.is_ready() {
            return Err(EnforcementCoordinatorError::IngestionUnavailable);
        }
        let transition = self
            .store
            .begin_transition(&PolicyTransition::pending(key, request))?;
        execute_transition(&self.client, &self.store, transition)
    }

    /// Resumes the exact persisted transition without accepting new desired state.
    ///
    /// # Errors
    ///
    /// Returns a missing-transition, persistence, transport, or ownership error.
    pub fn resume_transition(
        &self,
        key: &TransitionKey,
    ) -> Result<PolicyTransition, EnforcementCoordinatorError> {
        let _lifecycle = self.lifecycle();
        let transition =
            self.store
                .transition(key)?
                .ok_or(super::EnforcementStoreError::MissingTransition(
                    key.action_id,
                ))?;
        execute_transition(&self.client, &self.store, transition)
    }

    /// Restores the source audit policy recorded by a completed forward transition.
    ///
    /// # Errors
    ///
    /// Returns when the forward transition is missing or incomplete, ingestion
    /// is unavailable, persistence fails, or runtime ownership cannot be proved.
    pub fn begin_reverse_transition(
        &self,
        action_id: uuid::Uuid,
    ) -> Result<PolicyTransition, EnforcementCoordinatorError> {
        let _lifecycle = self.lifecycle();
        if !self.ingestion_readiness.is_ready() {
            return Err(EnforcementCoordinatorError::IngestionUnavailable);
        }
        let forward_key = TransitionKey {
            action_id,
            direction: crate::enforcement::TransitionDirection::Forward,
        };
        let forward = self
            .store
            .transition(&forward_key)?
            .ok_or(super::EnforcementStoreError::MissingTransition(action_id))?;
        if forward.phase != TransitionPhase::Completed {
            return Err(super::EnforcementStoreError::TransitionConflict(action_id).into());
        }
        let expected = forward.acknowledgement.ok_or_else(|| {
            super::EnforcementStoreError::InvalidTransitionState {
                field: "acknowledgement",
                value: "missing completed forward acknowledgement".into(),
            }
        })?;
        let reverse = PolicyTransition::pending(
            TransitionKey {
                action_id,
                direction: crate::enforcement::TransitionDirection::Reverse,
            },
            ReplacePolicy {
                expected,
                replacement: ReplacementPolicy::Generic(forward.request.expected.request),
            },
        );
        let transition = self.store.begin_transition(&reverse)?;
        execute_transition(&self.client, &self.store, transition)
    }
}

pub(super) fn execute_transition<C: ReplacementClient + ?Sized>(
    client: &C,
    store: &EnforcementStore,
    transition: PolicyTransition,
) -> Result<PolicyTransition, EnforcementCoordinatorError> {
    if matches!(
        transition.phase,
        TransitionPhase::Completed | TransitionPhase::SourceRestored
    ) {
        return Ok(transition);
    }
    let key = transition.key.clone();
    match client.replace(transition.request.clone())? {
        ReplaceOutcome::Applied(binding) => store.complete_transition(&key, &binding)?,
        ReplaceOutcome::SourceRetained { binding, code }
        | ReplaceOutcome::SourceRestored { binding, code } => {
            store.restore_transition(&key, &binding, code)?;
        }
        ReplaceOutcome::Conflict { code } | ReplaceOutcome::Indeterminate { code } => {
            store.mark_transition_indeterminate(&key, code)?;
            return Err(EnforcementCoordinatorError::TransitionUnavailable);
        }
    }
    store
        .transition(&key)?
        .ok_or_else(|| super::EnforcementStoreError::MissingTransition(key.action_id).into())
}
