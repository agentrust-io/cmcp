---
title: Govern MCP tool calls and verify the evidence
description: cMCP checks routed MCP tool calls against Cedar policy and signs session records. Run a local allow/deny example, then explore hardware-backed deployment.
---

# Govern tool calls. Verify the evidence.

cMCP (Confidential MCP) is an open-source gateway between your AI agent's MCP client and its tool servers. It checks routed calls against Cedar policy, blocks denied calls in enforcing mode, and produces a signed TRACE session record.

[Block a call in 10 minutes](https://agentrust-io.com/quickstart/){ .md-button .md-button--primary }
[See the architecture](concepts.md){ .md-button }

The first demo runs on your laptop with a mock tool and software attestation. You will see `403 POLICY_DENY`, then the expected `partially_verified` result because no hardware attestation is present. It needs Python 3.11+ and no cloud account.

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

## How it fits AgenTrust

[Agent Manifest](https://manifest.agentrust-io.com) declares identity and intended authority. cMCP governs the MCP tool-call path. [TRACE](https://trace.agentrust-io.com) defines signed runtime evidence, and [cA2A](https://ca2a.agentrust-io.com) addresses delegation between agents. Use the components required by your application's trust boundaries.

For implementation bugs or specification feedback, include the failing command, runtime version, and expected behavior in an [issue](https://github.com/agentrust-io/cmcp/issues). See [Contributing](https://github.com/agentrust-io/cmcp/blob/main/CONTRIBUTING.md).
