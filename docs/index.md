---
title: The secure, confidential way to run MCP
description: cMCP is a hardware-attested MCP runtime. Every tool call an agent makes passes through a TEE-isolated gateway that evaluates it against a Cedar policy and emits a signed TRACE receipt a verifier can check without trusting the operator.
---

# cMCP

cMCP (Confidential MCP) is a hardware-attested runtime for the Model Context Protocol. Every MCP tool call an agent makes passes through a TEE-isolated gateway that evaluates it against a Cedar policy bundle and produces a TRACE claim: a signed, hardware-attested artifact a verifier can check without trusting the operator.

**Prove that the policy you describe in documents is the policy that actually ran on your traffic.**

!!! tip "TL;DR"
    - MCP authenticates the caller. It does not constrain what a tool call may do, and it leaves no evidence of what it did.
    - cMCP runs the tool call inside a TEE, decides it against Cedar, and emits a signed receipt for every call.
    - Install with `pip install cmcp-runtime`, or follow the [guided quickstart](https://agentrust-io.com/quickstart/) and watch a policy block a real data leak in about ten minutes.
    - Two bounds worth stating up front: the plaintext guarantee holds where the egress policy denies telemetry and APM endpoints, and the receipt is hardware-attested when the gateway runs in a TEE and signed-only in software mode.

```bash
pip install cmcp-runtime
```

## The gap it closes

An agent calling a tool over MCP presents a token. The token says who is calling. It does not say what the call is allowed to touch, and once the call returns there is no artifact proving what actually happened.

Software-only enforcement does not close this. A privileged operator can change a policy between the approval that was reviewed and the traffic that ran, and then write the log that describes it. The log is authored by the system being audited.

cMCP moves the decision and the evidence inside a TEE. The policy bundle is measured, the decision happens where the operator cannot reach it, and the receipt is signed by a key that never leaves the enclave. Phase 1 attests the agent-to-tool boundary on the consumer side, in the runtime. Phase 2 attests it on the provider side, in the server.

## Where to start

<div class="grid cards" markdown>

-   __Run it__

    ---

    Write one policy, watch it block a tool call, and verify the receipt it produced.

    [Quick Start](quickstart.md)

-   __Understand it__

    ---

    The component model, trust boundaries, and how a tool call becomes a signed claim.

    [How It Works](concepts.md)

-   __Read the spec__

    ---

    Problem taxonomy, the thirteen threat shapes, and the Phase 1 and Phase 2 coverage matrix.

    [SPEC.md](SPEC.md)

-   __Check the bounds__

    ---

    What is attested against real silicon, what is parsed, and what is not appraised at all.

    [Limitations](limitations.md)

</div>

## How it fits the rest of the stack

cMCP is the enforcement layer of the AgenTrust chain. [Agent Manifest](https://manifest.agentrust-io.com) declares what an agent is and what it may do before it runs. cMCP enforces that at the tool-call boundary. [TRACE](https://trace.agentrust-io.com) is the evidence format the receipts are written in, and [cA2A](https://ca2a.agentrust-io.com) carries the same guarantees across agent-to-agent hops.

Issues in this repository track specification decisions rather than implementation bugs. To propose a change, open an issue describing the problem with the current spec, then submit a pull request. See [Contributing](https://github.com/agentrust-io/cmcp/blob/main/CONTRIBUTING.md).
