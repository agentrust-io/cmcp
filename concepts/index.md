# How cMCP works

This page explains, in plain terms, what cMCP checks, what its signed receipt can and cannot tell you, and where hardware comes in. Read it before you rely on cMCP for anything real.

An AI agent uses tools by sending requests (tool calls) through an MCP client, the part of the agent that speaks the Model Context Protocol. cMCP sits between that client and the tool servers. It checks each call it receives against your rules, written in the Cedar policy language, writes down every decision, and signs a record of the session when the session ends.

[Run the local allow/deny example](https://cmcp.agentrust-io.com/quickstart/index.md) [Read the verification guide](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md)

## Where enforcement runs

A request goes from the agent to cMCP. cMCP looks the tool up in its list of approved tools (the catalog), applies your rules, and either forwards the call or sends back an error. Replies from the tool are checked on the way back too. Scroll the diagram sideways on small screens; the text below says the same thing.

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

On an ordinary computer (**software mode**), the cMCP box in the diagram is just a separate program. On supported confidential-computing hardware, which keeps a program's memory sealed off from the machine's owner, the box can also be a hardware wall. The agent, the AI model and the tool servers do not move inside that wall on their own. A TPM (a security chip that records what software started) can report the machine's state, but it does not by itself hide the gateway's memory from the host.

cMCP only checks calls that go through it. Your setup has to stop the agent from reaching tools some other way. In `enforcing` mode a call the rules deny is not forwarded; in `advisory` mode the same decision is written down but the call goes ahead. See the [component model](https://cmcp.agentrust-io.com/spec/component-model/index.md), [enforcement modes](https://cmcp.agentrust-io.com/configuration/index.md), and [provider limitations](https://cmcp.agentrust-io.com/limitations/index.md).

## What the signed record tells you

The signed receipt cMCP produces is called a `GatewayClaim`. Inside it is a TRACE Trust Record (the shared AgenTrust receipt format), a summary of the session and a fingerprint of the full log. The signature proves the contents were not changed after signing. Whether they also prove *where* the gateway ran depends on the hardware report (attestation) attached to it and on what the person checking it is willing to trust.

Each row below is a question you might ask of a receipt, where to look, and what you must check on your own.

| Question                   | Evidence to inspect                                 | Additional check                                                                         |
| -------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Which identity signed?     | Subject and signing public key                      | Authenticate the key; a self-declared identity is insufficient                           |
| Which policy was loaded?   | `trace.policy.bundle_hash` and enforcement mode     | Compare with the verifier's independently approved bundle hash                           |
| Which tools were approved? | `gateway.catalog.hash`                              | Compare with an independently approved catalog hash                                      |
| What calls were recorded?  | Session summary and signed transcript commitment    | Verify the exported audit entries when individual calls matter                           |
| Where did the runtime run? | Platform, measurement, and raw attestation evidence | Verify the platform's signature chain, key binding, freshness, and required measurements |

In the [software quickstart](https://cmcp.agentrust-io.com/quickstart/index.md), the signature and consistency checks pass, but there is no hardware report to check. The expected result is `partially_verified`, with CLI exit code 1. Anyone who needs proof of hardware must reject that result.

## Policy approval is a separate input

A receipt says which rules and which tool list were loaded, as hashes (short fingerprints of the files). That only means something if the person checking it already knows which fingerprints your organization approved. Work out the policy bundle and catalog hashes from reviewed files, then hand them to the checker through a channel the checker controls.

Copying the hashes out of the receipt and comparing them with the same receipt proves nothing. It only repeats what the gateway said about itself. The [quickstart](https://cmcp.agentrust-io.com/quickstart/#confirm-your-setup) computes expected hashes from local input files before starting the runtime; a production deployment should obtain them from its approved build artifacts.

Cedar rules decide using the facts the gateway gives them. A catalog tag such as `pii` (personal data) is a label you put on a tool; cMCP does not scan the agent's request for personal data. A session can be marked more sensitive after cMCP inspects a reply, but cMCP cannot see what is inside the AI model or prove which earlier reply led to a later call. See [Cedar policy](https://cmcp.agentrust-io.com/spec/cedar-policy/index.md) and [call graph and tag propagation](https://cmcp.agentrust-io.com/spec/call-graph/index.md).

## Audit entries and their limits

Every log entry includes a fingerprint (hash) of the entry before it, so the entries form a chain, and the receipt signs the last link. Someone with the full log can rebuild the chain and compare it with the signed value. If any entry was changed, deleted or moved, the values will not match.

The signed last link on its own does not show what each entry said. It also cannot prove that every real-world action went through cMCP. When individual calls matter, check the exported log (the audit bundle), and keep the signed receipt somewhere separate from the logs it covers.

See the [audit implementation](https://github.com/agentrust-io/cmcp/blob/main/src/cmcp_runtime/audit/chain.py) and [verification library](https://cmcp.agentrust-io.com/spec/verification-library/index.md) for the exact serialized fields and checks. Hash formats and platform measurement rules are implementation-specific; the diagram above does not define their wire format.

## Hardware verification is platform-specific

Proving that the gateway ran on protected hardware takes more than changing the `provider` setting or starting it on a confidential virtual machine. The checker has to verify the hardware maker's signatures on the report, confirm the receipt's signing key belongs to that protected machine, check the software fingerprints (measurements) it expects, and make sure the report is recent. Each cloud supports this differently and roots trust in different keys.

- [Attestation specification](https://cmcp.agentrust-io.com/spec/attestation/index.md): provider evidence and binding rules.
- [Hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/index.md): recorded platform validation.
- [Limitations](https://cmcp.agentrust-io.com/limitations/index.md): supported checks and remaining assumptions.
- [Verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md): approved hashes and consumer acceptance.

## Choose the next step

- **First local result:** [allow and deny a tool call](https://cmcp.agentrust-io.com/quickstart/index.md).
- **Connect an application:** [use an existing MCP client](https://cmcp.agentrust-io.com/tutorials/existing-mcp-clients/index.md).
- **Write policy:** [Cedar walkthrough](https://cmcp.agentrust-io.com/tutorials/cedar-policy-walkthrough/index.md).
- **Consume evidence:** [verify a signed session record](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md).
