use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use super::broker;
use super::command_risk::CommandShape;
use super::command_risk_parser::{parse_command, SegmentConnector};
use super::readonly_pipeline::{
    cleanup_paths, error, read_limited_clean, temp_path, wait_child_with_deadline,
    ReadonlyPipelineConfig, ReadonlyPipelineError, ReadonlyPipelineOutput,
};

/// Execution plan for a fully-whitelisted compound command (issue #1882).
/// The plan carries parser tokens verbatim: steps are spawned directly
/// with `std::process::Command`, so no shell parsing layer ever touches
/// the assessed text and every expansion mechanism (history, glob,
/// tilde, parameter, alias, ...) is structurally inert — the assessed
/// token sequence *is* the executed argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadonlyCompoundPlan {
    pub(crate) steps: Vec<ReadonlyCompoundStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadonlyCompoundStep {
    /// Connector between this step and the previous one; ignored on the
    /// first step, which always runs.
    pub(crate) connector: SegmentConnector,
    pub(crate) argv: Vec<String>,
}

/// Builds an execution plan when — and only when — a compound command is
/// eligible for auto-execution. Eligibility is exactly "a plan exists",
/// so the assessment path and the execution path can never disagree
/// about what would run. Returns `None` for every ineligible shape, in
/// which case the caller keeps the pre-existing AskUser flow untouched.
///
/// Eligibility rules (design §2):
/// 1. shape is `AndOrList` or `Sequence` (all other shapes fail closed);
/// 2. no null-redirections were stripped by the parser (stripping loses
///    the user's output-suppression intent);
/// 3. at least two segments, and no empty segment was swallowed
///    (connector count must equal the gap count);
/// 4. every segment is exactly one stage (no pipeline segments);
/// 5. every token is free of `$` and backtick (the executor does not
///    expand, so expansion intent would diverge from execution);
/// 6. every segment's token sequence passes the readonly allowlist via
///    the same token-level predicate the broker uses (single source of
///    truth; no text re-splitting, so quoted arguments keep their
///    boundaries).
pub(crate) fn build_readonly_compound_plan(command: &str) -> Option<ReadonlyCompoundPlan> {
    let parsed = parse_command(command);
    if !matches!(
        parsed.shape,
        CommandShape::AndOrList | CommandShape::Sequence
    ) {
        return None;
    }
    if parsed.null_redirections > 0 {
        return None;
    }
    if parsed.segments.len() < 2 {
        return None;
    }
    if parsed.segment_connectors.len() != parsed.segments.len() - 1 {
        // A doubled separator (`pwd && && df`) swallows an empty segment;
        // bash would reject the line outright, so fail closed instead of
        // executing a re-interpretation.
        return None;
    }

    let mut steps = Vec::with_capacity(parsed.segments.len());
    for (index, segment) in parsed.segments.iter().enumerate() {
        if segment.len() != 1 {
            return None;
        }
        let argv = &segment[0];
        if argv.is_empty()
            || argv.iter().any(|token| token.contains(['$', '`']))
            || !broker::configured_readonly_command(argv)
        {
            return None;
        }
        steps.push(ReadonlyCompoundStep {
            connector: if index == 0 {
                SegmentConnector::Seq
            } else {
                parsed.segment_connectors[index - 1]
            },
            argv: argv.clone(),
        });
    }
    Some(ReadonlyCompoundPlan { steps })
}

/// Runs a compound plan with bash list semantics: `&&` runs the next
/// step only when the previous executed step exited 0, `||` only when it
/// exited non-zero, `;`/newline always; the overall exit code is the
/// last executed step's code. Per-step stdout/stderr are concatenated in
/// execution order with no annotations, matching what a terminal would
/// have shown; each stream is bounded by the shared config budget and
/// carries a single `<truncated>` marker once its budget is exhausted.
/// Timeouts and spawn/io failures fail the whole run with the same
/// error contract as the readonly pipeline.
pub(crate) fn run_readonly_compound(
    plan: &ReadonlyCompoundPlan,
    config: &ReadonlyPipelineConfig,
) -> Result<ReadonlyPipelineOutput, ReadonlyPipelineError> {
    if plan.steps.is_empty() {
        return Err(error(
            "empty-plan",
            "readonly compound requires at least one step",
        ));
    }
    let deadline = Instant::now() + config.total_timeout;
    let mut cleanup = Vec::new();
    let mut final_exit_code = None;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut stdout_exhausted = false;
    let mut stderr_exhausted = false;

    for (index, step) in plan.steps.iter().enumerate() {
        if index > 0 {
            let previous_code = final_exit_code.unwrap_or(0);
            let should_run = match step.connector {
                SegmentConnector::Seq => true,
                SegmentConnector::And => previous_code == 0,
                SegmentConnector::Or => previous_code != 0,
            };
            if !should_run {
                continue;
            }
        }
        if Instant::now() >= deadline {
            cleanup_paths(&cleanup);
            return Err(error("compound-timeout", "readonly compound timed out"));
        }

        let stdout_path = temp_path("stdout", index);
        let stderr_path = temp_path("stderr", index);
        cleanup.push(stdout_path.clone());
        cleanup.push(stderr_path.clone());

        let stdout_file = File::create(&stdout_path)
            .map_err(|err| error("executor-io", format!("create stdout: {err}")))?;
        let stderr_file = File::create(&stderr_path)
            .map_err(|err| error("executor-io", format!("create stderr: {err}")))?;

        let mut command = Command::new(&step.argv[0]);
        command
            .args(&step.argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                cleanup_paths(&cleanup);
                return Err(error("executor-spawn", format!("{}: {err}", step.argv[0])));
            }
        };
        let stage_deadline = Instant::now()
            + config
                .stage_timeout
                .min(deadline.saturating_duration_since(Instant::now()));
        match wait_child_with_deadline(&mut child, stage_deadline, step.argv.join(" ")) {
            Ok(code) => final_exit_code = code,
            Err(err) => {
                cleanup_paths(&cleanup);
                return Err(err);
            }
        }

        append_step_output(&mut stdout, &stdout_path, config, &mut stdout_exhausted)?;
        append_step_output(&mut stderr, &stderr_path, config, &mut stderr_exhausted)?;
    }

    cleanup_paths(&cleanup);
    Ok(ReadonlyPipelineOutput {
        exit_code: final_exit_code,
        stdout,
        stderr,
    })
}

/// Appends one step's captured stream to the aggregate under the
/// remaining budget; once a step overflows the remaining budget the
/// `<truncated>` marker from `read_limited_clean` terminates the
/// aggregate and later steps are skipped for that stream.
fn append_step_output(
    aggregate: &mut String,
    path: &Path,
    config: &ReadonlyPipelineConfig,
    exhausted: &mut bool,
) -> Result<(), ReadonlyPipelineError> {
    if *exhausted {
        return Ok(());
    }
    let remaining_bytes = config.output_limit_bytes.saturating_sub(aggregate.len());
    let remaining_lines = config
        .output_limit_lines
        .saturating_sub(aggregate.lines().count());
    let chunk = read_limited_clean(path, remaining_bytes, remaining_lines)?;
    if chunk.ends_with("<truncated>") {
        *exhausted = true;
    }
    aggregate.push_str(&chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(command: &str) -> ReadonlyCompoundPlan {
        build_readonly_compound_plan(command).expect("eligible compound")
    }

    /// Builds a plan directly, bypassing eligibility: executor-mechanism
    /// tests need `true`/`false`/free-form argv that the readonly
    /// allowlist (correctly) never grants.
    fn raw_plan(steps: &[(&[&str], SegmentConnector)]) -> ReadonlyCompoundPlan {
        ReadonlyCompoundPlan {
            steps: steps
                .iter()
                .map(|(argv, connector)| ReadonlyCompoundStep {
                    connector: *connector,
                    argv: argv.iter().map(ToString::to_string).collect(),
                })
                .collect(),
        }
    }

    fn run_plan(plan: &ReadonlyCompoundPlan) -> ReadonlyPipelineOutput {
        run_readonly_compound(plan, &ReadonlyPipelineConfig::default()).expect("compound run")
    }

    use SegmentConnector::{And, Or, Seq};

    #[test]
    fn build_plan_keeps_connector_sequence() {
        let plan = plan("pwd && df -h; git status --short || pwd");
        assert_eq!(plan.steps.len(), 4);
        let connectors: Vec<SegmentConnector> =
            plan.steps.iter().map(|step| step.connector).collect();
        assert_eq!(
            connectors,
            vec![
                SegmentConnector::Seq,
                SegmentConnector::And,
                SegmentConnector::Seq,
                SegmentConnector::Or,
            ]
        );
        assert_eq!(plan.steps[1].argv, vec!["df", "-h"]);
    }

    #[test]
    fn build_plan_accepts_quoted_and_newline_forms() {
        let quoted = plan("ls 'my dir' && pwd");
        assert_eq!(quoted.steps[0].argv, vec!["ls", "my dir"]);
        let multiline = plan("pwd\ndf -h");
        assert_eq!(multiline.steps.len(), 2);
        assert_eq!(multiline.steps[1].connector, SegmentConnector::Seq);
    }

    #[test]
    fn build_plan_fails_closed_for_ineligible_shapes() {
        for command in [
            // non-allowlisted segment
            "cd /tmp && git status",
            "touch /tmp/a && pwd",
            // pipeline segment
            "ps aux | head -5 && pwd",
            // null redirection stripped by the parser
            "pwd && df -h 2>/dev/null",
            // read redirection
            "wc -l < notes.txt && pwd",
            // write redirection / command substitution (dominant shapes)
            "pwd && echo x > f",
            "pwd && echo $(id)",
            "pwd && echo `id`",
            // expansion intent the executor would not honor
            "pwd && echo $HOME",
            // complex shapes
            "(pwd) && df -h",
            "pwd & df -h",
            // doubled separator swallows an empty segment
            "pwd && && df -h",
            // trailing separator leaves a single segment
            "pwd &&",
            // not a compound at all
            "pwd",
        ] {
            assert!(
                build_readonly_compound_plan(command).is_none(),
                "{command} must stay ineligible"
            );
        }
    }

    #[test]
    fn executor_short_circuits_like_bash() {
        // `&&` after success runs the next step.
        let output = run_plan(&raw_plan(&[
            (&["echo", "first"], Seq),
            (&["echo", "second"], And),
        ]));
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "first\nsecond\n");
        // `&&` after failure skips it; the failing code is preserved.
        let output = run_plan(&raw_plan(&[(&["false"], Seq), (&["echo", "second"], And)]));
        assert_eq!(output.exit_code, Some(1));
        assert_eq!(output.stdout, "");
        // `||` after success skips the next step.
        let output = run_plan(&raw_plan(&[(&["true"], Seq), (&["echo", "second"], Or)]));
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "");
        // `||` after failure runs it.
        let output = run_plan(&raw_plan(&[(&["false"], Seq), (&["echo", "second"], Or)]));
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "second\n");
        // `;` always runs the next step.
        let output = run_plan(&raw_plan(&[(&["false"], Seq), (&["echo", "second"], Seq)]));
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "second\n");
        // Left-associative chain: `false || false && echo ok` runs nothing
        // after the first failure pair, exit code is the last executed step.
        let output = run_plan(&raw_plan(&[
            (&["false"], Seq),
            (&["false"], Or),
            (&["echo", "ok"], And),
        ]));
        assert_eq!(output.exit_code, Some(1));
        assert_eq!(output.stdout, "");
        // `true && false || echo x` matches bash left-associativity.
        let output = run_plan(&raw_plan(&[
            (&["true"], Seq),
            (&["false"], And),
            (&["echo", "x"], Or),
        ]));
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "x\n");
    }

    #[test]
    fn executor_passes_tokens_verbatim() {
        // Every character class that a shell would expand (history
        // expansion trigger, glob, tilde, comment lead, spaces inside
        // quotes) reaches the process argv untouched.
        let output = run_plan(&raw_plan(&[(
            &["echo", "a b", "!-2", "*.log", "~", "#x"],
            Seq,
        )]));
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "a b !-2 *.log ~ #x\n");
    }

    // The shell control group for the no-parsing-layer evidence lives in
    // the integration layer (`tests/logic/tools.rs`): check-layout.sh
    // forbids new subprocess spawns in `src` test code, and
    // `executor_passes_tokens_verbatim` above covers the executor half.

    #[test]
    fn executor_bounds_aggregate_output() {
        let plan = raw_plan(&[
            (&["echo", "first"], Seq),
            (&["echo", "second"], Seq),
            (&["echo", "third"], Seq),
        ]);
        let output = run_readonly_compound(
            &plan,
            &ReadonlyPipelineConfig {
                output_limit_bytes: 12,
                ..ReadonlyPipelineConfig::default()
            },
        )
        .expect("bounded run");
        assert!(output.stdout.contains("<truncated>"), "{}", output.stdout);
        assert!(output.stdout.len() <= 32, "{}", output.stdout);
    }

    #[test]
    fn executor_enforces_stage_timeout() {
        let plan = raw_plan(&[(&["sleep", "2"], Seq), (&["echo", "second"], Seq)]);
        let err = run_readonly_compound(
            &plan,
            &ReadonlyPipelineConfig {
                stage_timeout: std::time::Duration::from_millis(20),
                total_timeout: std::time::Duration::from_secs(10),
                ..ReadonlyPipelineConfig::default()
            },
        )
        .expect_err("stage must time out");
        assert_eq!(err.reason, "stage-timeout");
    }
}
