use super::*;

const CAPTURE_QUARANTINE_MAX_BYTES: usize = 64 * 1024;

/// Submit-window deadline before an unacknowledged capture chain expires.
/// Tests shrink it so expiry paths stay testable without real waits, while
/// leaving enough headroom for the ack helper threads on loaded CI hosts.
fn capture_submit_drain_deadline() -> Duration {
    if cfg!(test) {
        Duration::from_millis(250)
    } else {
        Duration::from_secs(5)
    }
}

/// Bounded buffer for bytes that arrive while a submitted capture chain is
/// still draining. The bytes are retained (not just counted) so a cleanly
/// finished chain can replay them into the main-prompt owner instead of
/// silently dropping type-ahead (#1913); unsafe terminal states reject them
/// with user-visible feedback instead.
#[derive(Default)]
pub(super) struct CaptureOwnedInput {
    bytes: Vec<u8>,
    overflowed: bool,
}

impl CaptureOwnedInput {
    pub(super) fn observe(&mut self, bytes: &[u8]) -> bool {
        if self.overflowed {
            return false;
        }
        if self.bytes.len().saturating_add(bytes.len()) > CAPTURE_QUARANTINE_MAX_BYTES {
            // Past the cap nothing can be replayed faithfully anymore:
            // discard the whole batch and report the overflow edge once.
            self.bytes.clear();
            self.overflowed = true;
            return true;
        }
        self.bytes.extend_from_slice(bytes);
        false
    }

    fn take_bytes(&mut self) -> Vec<u8> {
        self.overflowed = false;
        std::mem::take(&mut self.bytes)
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

pub(super) fn capture_owns_input(mode: &RawInputMode) -> bool {
    matches!(
        mode,
        RawInputMode::Capture { .. }
            | RawInputMode::Submitted { .. }
            | RawInputMode::Draining { .. }
            | RawInputMode::Terminal { .. }
    )
}

pub(super) fn capture_generation(mode: &RawInputMode) -> Option<u64> {
    match mode {
        RawInputMode::Capture { generation, .. }
        | RawInputMode::Submitted { generation, .. }
        | RawInputMode::Draining { generation, .. } => Some(*generation),
        _ => None,
    }
}

pub(super) fn capture_quarantine_generation(
    observed_generation: Option<u64>,
    mode: &RawInputMode,
) -> Option<u64> {
    match observed_generation {
        Some(observed)
            if matches!(
                mode,
                RawInputMode::Capture { generation, .. } if *generation == observed
            ) =>
        {
            None
        }
        Some(observed) => Some(observed),
        None => None,
    }
}

pub(super) fn relay_input_chunk(
    bytes: &[u8],
    mut mode: RawInputMode,
    card_state: &mut CardInputState,
    capture_owned_input: &mut CaptureOwnedInput,
    deferred_input: &mut Option<InputRead>,
    read_ahead: Option<&Receiver<InputRead>>,
    expected_capture_generation: Option<u64>,
    relay: &mut InputRelayContext<'_>,
) -> io::Result<()> {
    loop {
        match mode {
            RawInputMode::Capture {
                capture,
                generation,
                ..
            } => {
                if let Some(expected_generation) = expected_capture_generation {
                    if expected_generation != generation {
                        relay_late_capture_bytes(
                            bytes,
                            expected_generation,
                            card_state,
                            capture_owned_input,
                            relay,
                        )?;
                        return Ok(());
                    }
                }
                let result = consume_captured_input(
                    card_state,
                    &capture,
                    generation,
                    bytes,
                    relay.input_events,
                    relay.input_mode,
                );
                if result.retry {
                    if let Some(expected_generation) = expected_capture_generation {
                        relay_late_capture_bytes(
                            bytes,
                            expected_generation,
                            card_state,
                            capture_owned_input,
                            relay,
                        )?;
                        return Ok(());
                    }
                    mode = current_raw_input_mode(relay.input_mode);
                    continue;
                }
                if result.generation.is_some() {
                    relay.line_buffer.clear();
                    relay.native_line_state.clear();
                    drain_capture_submission(
                        result,
                        card_state,
                        capture_owned_input,
                        deferred_input,
                        read_ahead,
                        relay,
                    )?;
                }
                return Ok(());
            }
            RawInputMode::Submitted { .. } => {
                thread::sleep(Duration::from_millis(1));
                mode = current_raw_input_mode(relay.input_mode);
            }
            RawInputMode::Draining { .. } => {
                card_state.reset();
                drain_abandoned_capture(card_state, capture_owned_input, relay)?;
                mode = current_raw_input_mode(relay.input_mode);
            }
            RawInputMode::Hold => {
                card_state.reset();
                send_held_input_events(bytes, relay.input_events);
                return Ok(());
            }
            RawInputMode::Delay { .. } => {
                card_state.reset();
                relay_delayed_input(bytes, relay)?;
                return Ok(());
            }
            RawInputMode::Passthrough | RawInputMode::Terminal { .. } => {
                card_state.reset();
                relay_passthrough_input(bytes, relay)?;
                return Ok(());
            }
            RawInputMode::PromptGhost {
                text: ghost_text,
                route,
            } => {
                card_state.reset();
                relay_prompt_ghost_input(bytes, &ghost_text, &route, relay)?;
                return Ok(());
            }
            RawInputMode::RawPassthrough => {
                card_state.reset();
                relay.line_buffer.clear();
                send_raw_input_events(bytes, relay.input_events);
                relay.native_line_state.observe_shell_bytes(bytes);
                relay.exit_tracker.observe_shell_bytes(bytes);
                write_user_bytes_to_pty(
                    relay.master,
                    relay.input_generation,
                    relay.line_submits,
                    relay.input_events,
                    relay.main_prompt_gate,
                    bytes,
                )?;
                return Ok(());
            }
        }
    }
}

pub(super) fn drain_capture_submission(
    result: CaptureConsumeResult,
    card_state: &mut CardInputState,
    capture_owned_input: &mut CaptureOwnedInput,
    deferred_input: &mut Option<InputRead>,
    read_ahead: Option<&Receiver<InputRead>>,
    relay: &mut InputRelayContext<'_>,
) -> io::Result<()> {
    let Some(generation) = result.generation else {
        return Ok(());
    };
    let mut overflow = capture_owned_input.observe(&result.remainder);
    if overflow {
        let _ = relay
            .input_events
            .send(RawInputEvent::CaptureOverflow { generation });
        expire_capture_submission(relay.input_mode, generation);
    }

    let chain_invalidated;
    let deadline = Instant::now() + capture_submit_drain_deadline();
    loop {
        match current_raw_input_mode(relay.input_mode) {
            RawInputMode::Draining {
                generation: active,
                invalidated,
                ..
            } if active == generation => {
                chain_invalidated = invalidated;
                if !overflow {
                    overflow = drain_capture_read_ahead(
                        generation,
                        capture_owned_input,
                        deferred_input,
                        read_ahead,
                        relay,
                    );
                }
                break;
            }
            RawInputMode::Submitted {
                generation: active, ..
            } if active == generation && Instant::now() < deadline => {
                let wait = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5));
                let Some(receiver) = read_ahead else {
                    thread::sleep(wait);
                    continue;
                };
                match receiver.recv_timeout(wait) {
                    Ok(InputRead::Bytes { bytes, .. }) => {
                        if !overflow && capture_owned_input.observe(&bytes) {
                            overflow = true;
                            let _ = relay
                                .input_events
                                .send(RawInputEvent::CaptureOverflow { generation });
                            expire_capture_submission(relay.input_mode, generation);
                        }
                    }
                    Ok(input @ (InputRead::Eof | InputRead::Error(_))) => {
                        *deferred_input = Some(input);
                        expire_capture_submission(relay.input_mode, generation);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        *deferred_input = Some(InputRead::Eof);
                        expire_capture_submission(relay.input_mode, generation);
                    }
                }
            }
            RawInputMode::Submitted {
                generation: active, ..
            } if active == generation => {
                let _ = relay
                    .input_events
                    .send(RawInputEvent::CaptureExpired { generation });
                expire_capture_submission(relay.input_mode, generation);
            }
            _ => return Ok(()),
        }
    }
    if !overflow && complete_capture_chain_if_pending(relay.input_mode, generation) {
        // T2: a follow-up card armed; the no-leak invariant outranks
        // delivery, so the quarantined bytes are rejected visibly (#1913 D5).
        reject_quarantined_input(capture_owned_input, generation, relay);
        let _ = relay
            .input_events
            .send(RawInputEvent::CaptureDrained { generation });
        return Ok(());
    }

    complete_capture_replay(relay.input_mode, generation);
    let _ = relay
        .input_events
        .send(RawInputEvent::CaptureDrained { generation });
    if overflow || chain_invalidated {
        // T3/T4: expired or overflowed chains never replay (#1913 D6).
        reject_quarantined_input(capture_owned_input, generation, relay);
        return Ok(());
    }
    replay_or_reject_after_drain(card_state, capture_owned_input, generation, relay)
}

/// Deliver the quarantined bytes when the chain landed back at the
/// main-prompt owner for this generation; the bytes re-enter the relay
/// exactly like live input read under a Terminal snapshot (no PTY bypass,
/// #1913 D4). Any other landing rejects visibly (fail-safe C4).
fn replay_or_reject_after_drain(
    card_state: &mut CardInputState,
    capture_owned_input: &mut CaptureOwnedInput,
    generation: u64,
    relay: &mut InputRelayContext<'_>,
) -> io::Result<()> {
    let bytes = capture_owned_input.take_bytes();
    if bytes.is_empty() {
        return Ok(());
    }
    let mode = current_raw_input_mode(relay.input_mode);
    if matches!(
        mode,
        RawInputMode::Terminal { generation: active, .. } if active == generation
    ) {
        let mut deferred_input = None;
        return relay_input_chunk(
            &bytes,
            mode,
            card_state,
            capture_owned_input,
            &mut deferred_input,
            None,
            None,
            relay,
        );
    }
    let _ = relay
        .input_events
        .send(RawInputEvent::CaptureInputRejected {
            generation,
            byte_len: bytes.len(),
        });
    Ok(())
}

/// Discard the quarantined bytes with user-visible feedback; an empty
/// buffer stays silent (nothing was lost).
fn reject_quarantined_input(
    capture_owned_input: &mut CaptureOwnedInput,
    generation: u64,
    relay: &mut InputRelayContext<'_>,
) {
    let bytes = capture_owned_input.take_bytes();
    if !bytes.is_empty() {
        let _ = relay
            .input_events
            .send(RawInputEvent::CaptureInputRejected {
                generation,
                byte_len: bytes.len(),
            });
    }
}

pub(in super::super) fn relay_late_capture_input(
    bytes: &[u8],
    generation: u64,
    master: &mut File,
    input_events: &Sender<RawInputEvent>,
    input_classifier: &InputClassifier,
    input_mode: &Arc<Mutex<RawInputMode>>,
    state: &mut RawInputRelayState,
) -> io::Result<()> {
    let RawInputRelayState {
        card_state,
        line_buffer,
        native_line_state,
        exit_tracker,
        capture_owned_input,
        input_generation,
        line_submits,
        main_prompt_gate,
        slash_route_enabled,
        ..
    } = state;
    let mut relay = InputRelayContext {
        master,
        input_classifier,
        input_events,
        input_mode,
        input_generation,
        line_submits,
        line_buffer,
        native_line_state,
        exit_tracker,
        main_prompt_gate,
        slash_route_enabled: *slash_route_enabled,
    };
    relay_late_capture_bytes(
        bytes,
        generation,
        card_state,
        capture_owned_input,
        &mut relay,
    )
}

fn relay_late_capture_bytes(
    bytes: &[u8],
    generation: u64,
    card_state: &mut CardInputState,
    capture_owned_input: &mut CaptureOwnedInput,
    relay: &mut InputRelayContext<'_>,
) -> io::Result<()> {
    let active_generation = match current_raw_input_mode(relay.input_mode) {
        RawInputMode::Capture {
            generation: active, ..
        }
        | RawInputMode::Submitted {
            generation: active, ..
        }
        | RawInputMode::Draining {
            generation: active, ..
        } => Some(active),
        _ => None,
    };
    if active_generation != Some(generation) {
        // The chain these bytes were typed against is gone; delivering them
        // to whatever owns input now would be a leak, so reject visibly
        // instead of the pre-#1913 silent discard.
        capture_owned_input.clear();
        if !bytes.is_empty() {
            let _ = relay
                .input_events
                .send(RawInputEvent::CaptureInputRejected {
                    generation,
                    byte_len: bytes.len(),
                });
        }
        return Ok(());
    }

    let overflow = capture_owned_input.observe(bytes);
    if overflow {
        let _ = relay
            .input_events
            .send(RawInputEvent::CaptureOverflow { generation });
        match current_raw_input_mode(relay.input_mode) {
            RawInputMode::Capture {
                generation: active, ..
            } if active == generation => abandon_active_capture(relay.input_mode),
            RawInputMode::Submitted {
                generation: active, ..
            }
            | RawInputMode::Draining {
                generation: active, ..
            } if active == generation => expire_capture_submission(relay.input_mode, active),
            _ => {}
        }
    }

    match current_raw_input_mode(relay.input_mode) {
        RawInputMode::Capture { .. } | RawInputMode::Submitted { .. } if !overflow => Ok(()),
        RawInputMode::Draining { .. } => {
            drain_abandoned_capture(card_state, capture_owned_input, relay)
        }
        _ => {
            reject_quarantined_input(capture_owned_input, generation, relay);
            Ok(())
        }
    }
}

fn drain_capture_read_ahead(
    generation: u64,
    capture_owned_input: &mut CaptureOwnedInput,
    deferred_input: &mut Option<InputRead>,
    read_ahead: Option<&Receiver<InputRead>>,
    relay: &mut InputRelayContext<'_>,
) -> bool {
    let Some(receiver) = read_ahead else {
        return false;
    };
    loop {
        match receiver.try_recv() {
            Ok(InputRead::Bytes { bytes, .. }) => {
                if capture_owned_input.observe(&bytes) {
                    let _ = relay
                        .input_events
                        .send(RawInputEvent::CaptureOverflow { generation });
                    expire_capture_submission(relay.input_mode, generation);
                    return true;
                }
            }
            Ok(input @ (InputRead::Eof | InputRead::Error(_))) => {
                *deferred_input = Some(input);
                return false;
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => return false,
        }
    }
}

pub(super) fn drain_abandoned_capture(
    card_state: &mut CardInputState,
    capture_owned_input: &mut CaptureOwnedInput,
    relay: &mut InputRelayContext<'_>,
) -> io::Result<()> {
    let RawInputMode::Draining {
        generation,
        invalidated,
        ..
    } = current_raw_input_mode(relay.input_mode)
    else {
        return Ok(());
    };
    complete_capture_replay(relay.input_mode, generation);
    let _ = relay
        .input_events
        .send(RawInputEvent::CaptureDrained { generation });
    if invalidated {
        // T3/T6: an invalidated chain never replays (#1913 D6).
        reject_quarantined_input(capture_owned_input, generation, relay);
        return Ok(());
    }
    // T8: the buffered bytes replay before whatever live input triggered
    // this drain, preserving arrival order (#1913 C3).
    replay_or_reject_after_drain(card_state, capture_owned_input, generation, relay)
}

pub(in super::super) fn finish_input_relay(
    master: &mut File,
    input_events: &Sender<RawInputEvent>,
    input_classifier: &InputClassifier,
    input_mode: &Arc<Mutex<RawInputMode>>,
    state: &mut RawInputRelayState,
) -> io::Result<()> {
    flush_pending_prompt_ghost_escape(
        true,
        Instant::now(),
        master,
        input_events,
        input_classifier,
        input_mode,
        state,
    )?;
    super::action::flush_pending_delay_escape(
        true,
        Instant::now(),
        master,
        input_events,
        input_classifier,
        input_mode,
        state,
    )?;
    let mode = current_raw_input_mode(input_mode);
    flush_pending_replaced_prompt_ghost_suffix(
        true,
        Instant::now(),
        &mode,
        master,
        input_events,
        input_classifier,
        input_mode,
        state,
    )?;
    if let RawInputMode::Submitted { generation, .. } = current_raw_input_mode(input_mode) {
        expire_capture_submission(input_mode, generation);
    }
    abandon_active_capture(input_mode);
    if matches!(
        current_raw_input_mode(input_mode),
        RawInputMode::Draining { .. }
    ) {
        let RawInputRelayState {
            card_state,
            line_buffer,
            native_line_state,
            exit_tracker,
            capture_owned_input,
            input_generation,
            line_submits,
            main_prompt_gate,
            ..
        } = state;
        let mut relay = InputRelayContext {
            master,
            input_classifier,
            input_events,
            input_mode,
            input_generation,
            line_submits,
            line_buffer,
            native_line_state,
            exit_tracker,
            main_prompt_gate,
            slash_route_enabled: false,
        };
        drain_abandoned_capture(card_state, capture_owned_input, &mut relay)?;
    }
    // Bytes held as a possible split paste delimiter never got a routing
    // verdict: forward them byte-identically before the trailing exit
    // (#1721; keeps partial CSI passthrough guarantees at EOF).
    let held_partial = state.line_buffer.take_pending_partial();
    if !held_partial.is_empty() {
        write_user_bytes_to_pty(
            master,
            &state.input_generation,
            &mut state.line_submits,
            input_events,
            &state.main_prompt_gate,
            &held_partial,
        )?;
    }
    if !state.exit_tracker.saw_explicit_exit() {
        write_user_bytes_to_pty(
            master,
            &state.input_generation,
            &mut state.line_submits,
            input_events,
            &state.main_prompt_gate,
            b"exit\n",
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "capture_matrix_tests.rs"]
mod matrix_tests;

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
