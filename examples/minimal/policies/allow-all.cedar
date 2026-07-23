// Minimal policy: allow every call to a catalogued tool.
// The catalog is the primary allowlist; this permit adds nothing beyond it.
permit (
  principal,
  action,
  resource
);
