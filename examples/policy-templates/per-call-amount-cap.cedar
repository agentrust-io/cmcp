// Example cap: 1000 integer minor units per call, not a running total.
forbid (principal, action, resource)
when {
  context.arguments has amount && context.arguments.amount > 1000
};
