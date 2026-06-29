// Rule 3: block calls to uncovered (non-BAA) external services when
// session has touched PHI data, prevents HIPAA cross-boundary violations.
forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource
)
when {
  context.session_max_sensitivity == "hipaa_phi" &&
  !resource.baa_covered
};
