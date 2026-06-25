// approved policy v1.0.0: allow EHR tool access for authorized principals
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource == cMCP::Resource::"ehr.get_patient"
);
