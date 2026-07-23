// Rule 2: after any MNPI data has entered the session, block calls to
// communication tools (Slack, email, public channels) to prevent leakage.
forbid (
  principal,
  action,
  resource == Resource::"communication.send"
)
when {
  context.session_max_sensitivity == "mnpi"
};
