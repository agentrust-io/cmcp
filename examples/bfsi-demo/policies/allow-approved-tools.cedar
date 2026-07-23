// Rule 1: allow calls to tools in the approved catalog
// (the catalog itself is the primary allowlist; this policy adds workflow scope)
permit (
  principal,
  action,
  resource
);
