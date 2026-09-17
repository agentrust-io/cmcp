# Optional sensitivity ceilings for tool and response sinks

`sink_policy` adds hard admission ceilings to the actual gateway call path.
It is supplied by the operator at startup, independent of tool arguments and
Cedar advisory/silent modes. Omit the block to preserve existing behavior.

```yaml
sink_policy:
  tool_max_sensitivity:
    records.read: confidential
    internal.summarize: confidential
    public.search: public
  response_max_sensitivity: confidential
```

Both keys are required. An empty tool map denies all tools. An absent tool,
unknown sensitivity label, malformed block, or misspelled ceiling fails closed.
Custom ceilings use the configured additive sensitivity vocabulary. Ceilings
compare ranks: labels at the same rank are equivalent for this check. They do
not provide compartment, purpose, recipient identity, or jurisdiction rules.

Before dispatch, every applicable label must fit the tool's ceiling: the
accumulated session class, the approved catalog's class, and any caller-declared
class. A caller can increase classification but cannot lower an existing floor.
After inspection and session-state update, the same rule controls release to
the caller using `response_max_sensitivity`. The class observed at call entry
is retained for that call even if an operator resets the session in flight.
Refusals use `sink_policy:tool_denied` or `sink_policy:response_denied` in the
ordinary terminal audit path. A response refusal does not undo a tool operation
that has already executed.

For example, once a session has read a catalogued confidential record, a
subsequent public-search call is denied even if it contains a clean-looking
summary and declares itself public. There is no automatic declassification or
model-generated approval. A session reset is an operator action; it must not be
used to carry the same secret into a fresh public session.

## Logging boundary

When this policy is configured, gateway-created stdio servers suppress captured
stderr content and log its byte count only. Ordinary upstream error logs retain
the error code rather than the upstream's potentially private message. Proxy
Cedar exception logs retain the exception class without a traceback or message.
These changes constrain these specific log sites, not every diagnostic sink.

The audit chain still includes payload hashes and metadata. Hashes of predictable
inputs can support guessing attacks, and tool names, identifiers, timing, and
external evidence can be sensitive. Protect audit exports and application logs
with deployment access policy; this feature does not encrypt them or make them
safe for publication. Application, runtime, third-party, and agent-host logs
remain outside the stderr control.

## Assurance limits

- This is a conservative session-label gate, not semantic information-flow
  tracking. It relies on accurate catalog/input classification. It does not
  discover unlabelled secrets or prove a derived output contains none.
- The gateway cannot mediate an agent's direct sockets, files, remote model
  calls, or other paths that bypass it. A permitted remote tool still needs its
  own confidentiality protections. A catalog entry is not remote attestation.
- The response ceiling is an operator authorization for this gateway's callers,
  not per-user clearance negotiation. Run separate deployments where callers
  require different ceilings.
- The immutable policy is captured when a proxy is created. Treat configuration
  and catalog changes as deployment changes; this feature does not add their
  digest to an attestation claim or implement a remotely verified policy update.
- Cross-session classification, durable session state, trusted operator resets,
  and protection of the process/configuration remain deployment obligations.
  This gate does not establish a distributed total order over simultaneous
  calls or independently operated gateways.
