// Rule 3: block calls to uncovered (non-BAA) external services when
// session has touched PHI data, prevents HIPAA cross-boundary violations.
forbid (
  principal,
  action,
  resource
)
when {
  context.session_max_sensitivity == "hipaa_phi" &&
  !context.baa_covered
};
