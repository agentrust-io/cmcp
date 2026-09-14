---
hide:
  - navigation
  - toc
title: "cMCP: policy-checked MCP tool calls with signed evidence"
description: cMCP checks routed MCP tool calls against Cedar policy and signs session records. Run a local allow/deny example, then evaluate hardware-backed deployment.
---

[03 · Actions: was each tool call checked inside attested hardware?](https://agentrust-io.com/#chain)

# Check routed MCP tool calls and sign the evidence

cMCP is an MCP gateway that evaluates each routed tool call against Cedar policy, blocks denied calls in enforcing mode, and signs a TRACE session record a verifier can check offline.

[Block a call in 10 minutes](https://agentrust-io.com/quickstart/){ .md-button .md-button--primary }
[What this proves, and what it does not](limitations.md){ .md-button }

!!! tip "TL;DR"
    Install [cmcp-runtime](https://pypi.org/project/cmcp-runtime/) 0.5.0 (MIT; the PyPI name `cmcp` belongs to an unrelated project) and see `403 POLICY_DENY` locally, reported as `partially_verified` because software mode carries no hardware attestation. The SEV-SNP and Intel TDX verifiers are validated on real Azure and GCP evidence, and calls that bypass the gateway, along with NVIDIA GPU confidential computing, are outside what it proves today.

<div class="grid cards" markdown>

-   __Run it__

    ---

    A blocked request and a signed session record on your laptop, with a mock tool and software attestation.

    [Guided first demo](https://agentrust-io.com/quickstart/)

-   __What it proves, and what it does not__

    ---

    Software mode has no hardware isolation, and the upstream tool server stays outside the TEE.

    [Limitations](limitations.md)

-   __Hardware evidence__

    ---

    SEV-SNP on an Azure confidential VM and Intel TDX on GCP C3, validated 2026-07-27. NVIDIA GPU CC is not implemented.

    [Hardware validation](testing/hardware-validation.md)

-   __The chain__

    ---

    Before it: [Agent Manifest](https://manifest.agentrust-io.com) declares the agent. Alongside: [cA2A](https://ca2a.agentrust-io.com) covers delegation. After it: records in [TRACE](https://trace.agentrust-io.com). Check a real TDX quote at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

    [See the chain](https://agentrust-io.com/#chain)

</div>

## Choose your next step

| You want to… | Start here | Result |
|---|---|---|
| Understand a policy denial | [Guided first demo](https://agentrust-io.com/quickstart/) | A blocked request and a signed session record |
| Exercise a real local upstream | [Allow/deny quickstart](quickstart.md) | One denied tool call and one forwarded call |
| Connect an existing agent | [MCP client integration](tutorials/existing-mcp-clients.md) | Your client sends requests through the gateway |
| Evaluate the trust boundary | [How it works](concepts.md) | Distinguish policy enforcement, signing, and hardware provenance |
| Deploy with hardware evidence | [TEE attestation](tutorials/tee-attestation.md) | Provider prerequisites and verification requirements |
| Implement against the protocol | [Specification index](spec-index.md) | The relevant component, transport, and policy contracts |

## What changes at the tool boundary

Authentication identifies a caller; your Cedar policy decides what a routed call may do. The gateway records the decision and binds the session's evidence into a signed claim when the session closes.

A hardware deployment can protect the runtime from its host, subject to the provider's threat model and verification support. The agent, model, and upstream tool server remain separate components. Calls that bypass the gateway are outside its enforcement. Host confidentiality also depends on the configured egress policy.

Read the [architecture](concepts.md), [enforcement modes](configuration.md), and [limitations](limitations.md) before treating a successful software demo as evidence of hardware isolation.

## Get involved

For implementation bugs or specification feedback, include the failing command, runtime version, and expected behavior in an [issue](https://github.com/agentrust-io/cmcp/issues). See [Contributing](https://github.com/agentrust-io/cmcp/blob/main/CONTRIBUTING.md).

**Status:** cmcp-runtime 0.5.0 · MIT · hosting at the Agentic AI Foundation proposed, not accepted · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
