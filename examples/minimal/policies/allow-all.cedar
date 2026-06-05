// Minimal policy: allow all calls to catalog tools
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
);
