# How cMCP works

cMCP sits between an MCP client and its tool servers. It evaluates routed calls against a Cedar policy, records decisions, and signs a session record when the session closes.

[Run the local allow/deny example](https://cmcp.agentrust-io.com/quickstart/index.md) [Read the verification guide](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md)

## Where enforcement runs

```
flowchart TB
    agent[Agent and MCP client]
    subgraph runtime[cMCP runtime]
        policy[Catalog lookup and Cedar policy]
        decision{Decision}
        audit[Audit entries]
        claim[Signed session claim]
        response[Response inspection and egress policy]
        policy --> decision
        decision -->|record decision| audit
        audit -->|session closes| claim
    end
    agent -->|tool request| policy
    decision -->|allow| tool[Upstream MCP tool server]
    decision -->|deny: return error| agent
    tool -->|tool response| response
    response -->|response or egress denial| agent
    claim -->|evidence| verifier[Independent verifier]
```

The runtime box is a **process boundary in software mode**. With a supported confidential-computing deployment, it can also be a hardware isolation boundary. The agent, model inference, and upstream tool server do not automatically move inside that boundary. A TPM can provide measured-state evidence; it does not by itself isolate the runtime's memory from the host.

Only calls routed through cMCP are governed. The deployment must prevent an agent from bypassing the gateway. In `enforcing` mode, a policy denial stops forwarding; in `advisory` mode, the same decision is logged while the call proceeds. See the [component model](https://cmcp.agentrust-io.com/spec/component-model/index.md), [enforcement modes](https://cmcp.agentrust-io.com/configuration/index.md), and [provider limitations](https://cmcp.agentrust-io.com/limitations/index.md).

## What the signed record tells you

A cMCP `GatewayClaim` contains an inner TRACE Trust Record plus session summaries and audit-chain information. The signature binds the claim's contents. Whether those contents establish hardware provenance depends on the attestation evidence and the verifier's trust policy.

| Question                   | Evidence to inspect                                 | Additional check                                                                         |
| -------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Which identity signed?     | Subject and signing public key                      | Authenticate the key; a self-declared identity is insufficient                           |
| Which policy was loaded?   | `trace.policy.bundle_hash` and enforcement mode     | Compare with the verifier's independently approved bundle hash                           |
| Which tools were approved? | `gateway.catalog.hash`                              | Compare with an independently approved catalog hash                                      |
| What calls were recorded?  | Session summary and signed transcript commitment    | Verify the exported audit entries when individual calls matter                           |
| Where did the runtime run? | Platform, measurement, and raw attestation evidence | Verify the platform's signature chain, key binding, freshness, and required measurements |

In the [software quickstart](https://cmcp.agentrust-io.com/quickstart/index.md), the signature and consistency checks pass, but hardware attestation does not. The expected result is `partially_verified`, with CLI exit code 1. A consumer that requires hardware provenance must reject that result.

## Policy approval is a separate input

The verifier needs to know what your organization approved **before** inspecting a claim. Compute the bundle and catalog hashes from reviewed build artifacts, then deliver them through a verifier-controlled channel.

Copying the hashes out of the claim and comparing them with that same claim does not establish approval. It only repeats the producer's assertion. The [quickstart](https://cmcp.agentrust-io.com/quickstart/#confirm-your-setup) computes expected hashes from local input files before starting the runtime; a production deployment should obtain them from its approved build artifacts.

Cedar rules decide authorization using the context supplied by the runtime. A catalog tag such as `pii` describes the configured tool; it is not a scan of the agent's request. Session sensitivity can rise after inspected responses, but the runtime cannot see the model's internal context or prove which earlier response influenced a later call. See [Cedar policy](https://cmcp.agentrust-io.com/spec/cedar-policy/index.md) and [call graph and tag propagation](https://cmcp.agentrust-io.com/spec/call-graph/index.md).

## Audit entries and their limits

The runtime hashes canonical audit entries that include the previous entry's hash. A verifier with the entries can recompute the chain and compare it with the signed commitment. Modification, deletion, or reordering can then be detected relative to that commitment.

A signed chain tip alone does not replay or inspect every entry. It also does not prove that every real-world action was routed through the runtime. Use the exported audit bundle when you need transcript verification, and retain the approved signed record separately from the logs it commits to.

See the [audit implementation](https://github.com/agentrust-io/cmcp/blob/main/src/cmcp_runtime/audit/chain.py) and [verification library](https://cmcp.agentrust-io.com/spec/verification-library/index.md) for the exact serialized fields and checks. Hash formats and platform measurement rules are implementation-specific; the diagram above does not define their wire format.

## Hardware verification is platform-specific

Hardware provenance requires more than changing `provider` or moving a process to a confidential VM. A verifier must check the evidence chain, bind the signing key to the attested environment, and apply its expected measurements and freshness policy. Provider support and trust anchors differ.

- [Attestation specification](https://cmcp.agentrust-io.com/spec/attestation/index.md): provider evidence and binding rules.
- [Hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/index.md): recorded platform validation.
- [Limitations](https://cmcp.agentrust-io.com/limitations/index.md): supported checks and remaining assumptions.
- [Verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md): approved hashes and consumer acceptance.

## Choose the next step

- **First local result:** [allow and deny a tool call](https://cmcp.agentrust-io.com/quickstart/index.md).
- **Connect an application:** [use an existing MCP client](https://cmcp.agentrust-io.com/tutorials/existing-mcp-clients/index.md).
- **Write policy:** [Cedar walkthrough](https://cmcp.agentrust-io.com/tutorials/cedar-policy-walkthrough/index.md).
- **Consume evidence:** [verify a signed session record](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md).
