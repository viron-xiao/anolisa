use crate::runtime::prelude::*;
use crate::slash::panel::render_notice_panel;
use crate::slash::prompt::{clear_shell_prompt_line, write_shell_prompt};
use crate::types::ShellCaptureLifecycle;

/// Visible feedback when quarantined submit-window input was discarded
/// (#1913 G2): every rejected/overflowed capture chain renders one notice
/// so the product keeps no silent input-drop path.
pub(crate) fn render_capture_input_rejected<W: Write>(
    events: &[ShellEvent],
    state: &mut InlineState,
    output: &mut W,
    event_index_base: usize,
) -> std::io::Result<()> {
    for (idx, event) in events.iter().enumerate() {
        let Some(capture) = event.capture.as_ref() else {
            continue;
        };
        if !matches!(
            capture.lifecycle,
            ShellCaptureLifecycle::InputRejected | ShellCaptureLifecycle::Overflow
        ) {
            continue;
        }
        let key = stable_event_key("capture-input-rejected", event_index_base + idx, event);
        if !state.control.claim_config_action(key) {
            continue;
        }
        clear_shell_prompt_line(output)?;
        let i18n = state.i18n();
        render_notice_panel(
            output,
            i18n.t(MessageId::CaptureInputRejectedTitle),
            vec![i18n.t(MessageId::CaptureInputRejectedBody).to_string()],
            None,
        )?;
        write_shell_prompt(state, output)?;
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ShellCaptureMetadata, ShellEventKind};

    fn rejected_event(lifecycle: ShellCaptureLifecycle) -> ShellEvent {
        let mut event = ShellEvent::user_input_intercepted("session", "");
        event.kind = ShellEventKind::UserInputIntercepted;
        event.capture = Some(ShellCaptureMetadata {
            kind: None,
            target_id: None,
            generation: 42,
            lifecycle,
        });
        event
    }

    #[test]
    fn rejected_lifecycle_renders_notice_once() {
        let mut state = InlineState {
            language: Language::ZhCn,
            ..InlineState::default()
        };
        let event = rejected_event(ShellCaptureLifecycle::InputRejected);
        let mut output = Vec::new();

        render_capture_input_rejected(std::slice::from_ref(&event), &mut state, &mut output, 0)
            .expect("render rejected notice");
        let rendered = String::from_utf8(output).expect("utf8 output");
        assert!(rendered.contains("输入未投递"), "{rendered}");
        assert!(rendered.contains("请重新输入"), "{rendered}");

        let mut second = Vec::new();
        render_capture_input_rejected(&[event], &mut state, &mut second, 0)
            .expect("render duplicate");
        assert!(second.is_empty(), "duplicate event must not re-render");
    }

    #[test]
    fn drained_lifecycle_stays_silent() {
        let mut state = InlineState::default();
        let event = rejected_event(ShellCaptureLifecycle::Drained);
        let mut output = Vec::new();

        render_capture_input_rejected(&[event], &mut state, &mut output, 0)
            .expect("render drained lifecycle");

        assert!(output.is_empty());
    }
}
