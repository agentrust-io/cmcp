// A forbid overrides permits elsewhere in the same bundle.
forbid (principal, action, resource)
when {
  (["pii", "hipaa_phi", "mnpi"].contains(context.session_max_sensitivity) &&
   !context.baa_covered) ||
  context.compliance_domain == "external"
};
