//! SQLite operations for durable policy ownership transitions.

use agentsight_enforcement_protocol::{
    ApplyPolicy, Binding, BindingState, ReplaceFailureCode, ReplacementPolicy,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::{EnforcementStore, EnforcementStoreError, now_ns, sqlite_i64, upsert_binding_on};
use crate::enforcement::{PolicyTransition, TransitionDirection, TransitionKey, TransitionPhase};

impl EnforcementStore {
    /// Persists transition intent before the privileged replacement call.
    ///
    /// Reusing the key with the exact request is idempotent; different desired
    /// state is rejected.
    ///
    /// # Errors
    ///
    /// Returns a persistence, decoding, or immutable-request conflict error.
    pub fn begin_transition(
        &self,
        transition: &PolicyTransition,
    ) -> Result<PolicyTransition, EnforcementStoreError> {
        let connection = self.connection()?;
        if let Some(existing) = transition_on(&connection, &transition.key)? {
            if existing.request == transition.request {
                return Ok(existing);
            }
            return Err(EnforcementStoreError::TransitionConflict(
                transition.key.action_id,
            ));
        }
        connection.execute(
            "INSERT INTO enforcement_transitions
               (action_id, direction, request_json, phase,
                acknowledgement_json, failure_code, updated_at_ns)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
            params![
                transition.key.action_id.to_string(),
                transition.key.direction.as_str(),
                serde_json::to_string(&transition.request)?,
                TransitionPhase::Pending.as_str(),
                sqlite_i64(transition.updated_at_ns),
            ],
        )?;
        transition_on(&connection, &transition.key)?.ok_or(
            EnforcementStoreError::MissingTransition(transition.key.action_id),
        )
    }

    /// Reads one transition by stable action and direction.
    ///
    /// # Errors
    ///
    /// Returns a persistence or decoding error.
    pub fn transition(
        &self,
        key: &TransitionKey,
    ) -> Result<Option<PolicyTransition>, EnforcementStoreError> {
        let connection = self.connection()?;
        transition_on(&connection, key)
    }

    /// Lists transitions that require a replacement retry.
    ///
    /// # Errors
    ///
    /// Returns a persistence or decoding error.
    pub fn pending_transitions(&self) -> Result<Vec<PolicyTransition>, EnforcementStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT action_id, direction, request_json, phase,
                    acknowledgement_json, failure_code, updated_at_ns
             FROM enforcement_transitions
             WHERE phase IN ('pending', 'indeterminate')
             ORDER BY updated_at_ns ASC, action_id ASC, direction ASC",
        )?;
        let rows = statement.query_map([], transition_row)?;
        let mut transitions = Vec::new();
        for row in rows {
            transitions.push(decode_transition(row?)?);
        }
        Ok(transitions)
    }

    /// Atomically transfers desired binding ownership to the target.
    ///
    /// # Errors
    ///
    /// Returns a persistence, phase compare-and-swap, or binding conflict error.
    pub fn complete_transition(
        &self,
        key: &TransitionKey,
        target: &Binding,
    ) -> Result<(), EnforcementStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let transition = required_transition(&transaction, key)?;
        if transition.phase == TransitionPhase::Completed
            && transition.acknowledgement.as_ref() == Some(target)
        {
            transaction.commit()?;
            return Ok(());
        }
        require_retryable_phase(&transition)?;
        if target.state != BindingState::Enforced
            || !replacement_matches(&transition.request.replacement, &target.request)
        {
            return Err(EnforcementStoreError::TransitionConflict(key.action_id));
        }

        let mut source = transition.request.expected;
        source.state = BindingState::Detached;
        source.message = None;
        source.domain_id = None;
        let updated_at_ns = now_ns();
        upsert_binding_on(&transaction, &source, updated_at_ns)?;
        upsert_binding_on(&transaction, target, updated_at_ns)?;
        update_transition(
            &transaction,
            key,
            TransitionPhase::Completed,
            Some(target),
            None,
            updated_at_ns,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically records that the exact source policy owns the runtime again.
    ///
    /// # Errors
    ///
    /// Returns a persistence, phase compare-and-swap, or binding conflict error.
    pub fn restore_transition(
        &self,
        key: &TransitionKey,
        source: &Binding,
        code: ReplaceFailureCode,
    ) -> Result<(), EnforcementStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let transition = required_transition(&transaction, key)?;
        if transition.phase == TransitionPhase::SourceRestored
            && transition.acknowledgement.as_ref() == Some(source)
            && transition.failure_code == Some(code)
        {
            transaction.commit()?;
            return Ok(());
        }
        require_retryable_phase(&transition)?;
        if source.state != BindingState::Enforced
            || source.request != transition.request.expected.request
        {
            return Err(EnforcementStoreError::TransitionConflict(key.action_id));
        }

        let updated_at_ns = now_ns();
        upsert_binding_on(&transaction, source, updated_at_ns)?;
        update_transition(
            &transaction,
            key,
            TransitionPhase::SourceRestored,
            Some(source),
            Some(code),
            updated_at_ns,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Marks runtime ownership unknown so reconnect reconciliation retries it.
    ///
    /// # Errors
    ///
    /// Returns a persistence or missing-transition error.
    pub fn mark_transition_indeterminate(
        &self,
        key: &TransitionKey,
        code: ReplaceFailureCode,
    ) -> Result<(), EnforcementStoreError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE enforcement_transitions
             SET phase = 'indeterminate', acknowledgement_json = NULL,
                 failure_code = ?1, updated_at_ns = ?2
             WHERE action_id = ?3 AND direction = ?4
               AND phase IN ('pending', 'indeterminate')",
            params![
                failure_code_name(code),
                sqlite_i64(now_ns()),
                key.action_id.to_string(),
                key.direction.as_str(),
            ],
        )?;
        if changed == 0 {
            return if transition_on(&connection, key)?.is_none() {
                Err(EnforcementStoreError::MissingTransition(key.action_id))
            } else {
                Err(EnforcementStoreError::TransitionConflict(key.action_id))
            };
        }
        Ok(())
    }
}

type TransitionRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
);

fn transition_on(
    connection: &Connection,
    key: &TransitionKey,
) -> Result<Option<PolicyTransition>, EnforcementStoreError> {
    let row = connection
        .query_row(
            "SELECT action_id, direction, request_json, phase,
                    acknowledgement_json, failure_code, updated_at_ns
             FROM enforcement_transitions
             WHERE action_id = ?1 AND direction = ?2",
            params![key.action_id.to_string(), key.direction.as_str()],
            transition_row,
        )
        .optional()?;
    row.map(decode_transition).transpose()
}

fn transition_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransitionRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn decode_transition(row: TransitionRow) -> Result<PolicyTransition, EnforcementStoreError> {
    let action_id = uuid::Uuid::parse_str(&row.0).map_err(|_| {
        EnforcementStoreError::InvalidTransitionState {
            field: "action_id",
            value: row.0.clone(),
        }
    })?;
    let direction = parse_direction(&row.1)?;
    let phase = parse_phase(&row.3)?;
    Ok(PolicyTransition {
        key: TransitionKey {
            action_id,
            direction,
        },
        request: serde_json::from_str(&row.2)?,
        phase,
        acknowledgement: row.4.map(|json| serde_json::from_str(&json)).transpose()?,
        failure_code: row.5.map(|value| parse_failure_code(&value)).transpose()?,
        updated_at_ns: u64::try_from(row.6).map_err(|_| {
            EnforcementStoreError::InvalidTransitionState {
                field: "updated_at_ns",
                value: row.6.to_string(),
            }
        })?,
    })
}

fn required_transition(
    connection: &Connection,
    key: &TransitionKey,
) -> Result<PolicyTransition, EnforcementStoreError> {
    transition_on(connection, key)?.ok_or(EnforcementStoreError::MissingTransition(key.action_id))
}

fn require_retryable_phase(transition: &PolicyTransition) -> Result<(), EnforcementStoreError> {
    if matches!(
        transition.phase,
        TransitionPhase::Pending | TransitionPhase::Indeterminate
    ) {
        Ok(())
    } else {
        Err(EnforcementStoreError::TransitionConflict(
            transition.key.action_id,
        ))
    }
}

fn update_transition(
    connection: &Connection,
    key: &TransitionKey,
    phase: TransitionPhase,
    acknowledgement: Option<&Binding>,
    failure_code: Option<ReplaceFailureCode>,
    updated_at_ns: u64,
) -> Result<(), EnforcementStoreError> {
    let changed = connection.execute(
        "UPDATE enforcement_transitions
         SET phase = ?1, acknowledgement_json = ?2,
             failure_code = ?3, updated_at_ns = ?4
         WHERE action_id = ?5 AND direction = ?6
           AND phase IN ('pending', 'indeterminate')",
        params![
            phase.as_str(),
            acknowledgement.map(serde_json::to_string).transpose()?,
            failure_code.map(failure_code_name),
            sqlite_i64(updated_at_ns),
            key.action_id.to_string(),
            key.direction.as_str(),
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(EnforcementStoreError::TransitionConflict(key.action_id))
    }
}

fn parse_direction(value: &str) -> Result<TransitionDirection, EnforcementStoreError> {
    TransitionDirection::parse(value).ok_or_else(|| EnforcementStoreError::InvalidTransitionState {
        field: "direction",
        value: value.into(),
    })
}

fn parse_phase(value: &str) -> Result<TransitionPhase, EnforcementStoreError> {
    TransitionPhase::parse(value).ok_or_else(|| EnforcementStoreError::InvalidTransitionState {
        field: "phase",
        value: value.into(),
    })
}

fn failure_code_name(code: ReplaceFailureCode) -> &'static str {
    match code {
        ReplaceFailureCode::BindingConflict => "binding_conflict",
        ReplaceFailureCode::StaleProcess => "stale_process",
        ReplaceFailureCode::CompileFailure => "compile_failure",
        ReplaceFailureCode::KernelFailure => "kernel_failure",
    }
}

fn parse_failure_code(value: &str) -> Result<ReplaceFailureCode, EnforcementStoreError> {
    match value {
        "binding_conflict" => Ok(ReplaceFailureCode::BindingConflict),
        "stale_process" => Ok(ReplaceFailureCode::StaleProcess),
        "compile_failure" => Ok(ReplaceFailureCode::CompileFailure),
        "kernel_failure" => Ok(ReplaceFailureCode::KernelFailure),
        _ => Err(EnforcementStoreError::InvalidTransitionState {
            field: "failure_code",
            value: value.into(),
        }),
    }
}

fn replacement_matches(replacement: &ReplacementPolicy, acknowledged: &ApplyPolicy) -> bool {
    match replacement {
        ReplacementPolicy::Generic(request) => request == acknowledged,
        ReplacementPolicy::Credential(request) => {
            request.binding_id == acknowledged.binding_id
                && request.agent_id == acknowledged.agent_id
                && request.session_id == acknowledged.session_id
                && request.root_pid == acknowledged.root_pid
                && request.process_start_time == acknowledged.process_start_time
                && request.policy.policy_id == acknowledged.policy_id
                && request.policy.revision.to_string() == acknowledged.policy_revision
        }
    }
}
