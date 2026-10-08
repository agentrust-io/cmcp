[03 · Actions: was each tool call checked inside attested hardware?](https://agentrust-io.com/#chain)

# Check routed MCP tool calls and sign the evidence

When an AI agent uses a tool (looks up a customer, sends an email, queries a database), it sends a request called a tool call, usually over MCP, the Model Context Protocol. cMCP is a gateway that sits in the path of those calls: it checks each one against rules you write in the Cedar policy language, blocks the ones the rules forbid, and at the end of the session signs a receipt (a TRACE record) that anyone can check later without network access. New to these terms? See [the terms, in plain English](https://agentrust-io.com/#plain-terms).

[Block a call in 10 minutes](https://agentrust-io.com/quickstart/) [What this proves, and what it does not](https://cmcp.agentrust-io.com/limitations/index.md)

TL;DR

Install [cmcp-runtime](https://pypi.org/project/cmcp-runtime/) 0.7.0 (MIT; the PyPI name `cmcp` belongs to an unrelated project) and watch it block a call with `403 POLICY_DENY` on your own computer; the receipt reads `partially_verified` because a laptop gives no hardware proof of where the gateway ran. On sealed-off cloud hardware (AMD SEV-SNP on Azure, Intel TDX on GCP) the hardware checks pass on real evidence, while calls that go around the gateway, and NVIDIA GPU confidential computing, are outside what it proves today.

- **Run it**

  ______________________________________________________________________

  See a request blocked and get a signed receipt on your laptop, using a stand-in tool and no special hardware.

  [Guided first demo](https://agentrust-io.com/quickstart/)

- **What it proves, and what it does not**

  ______________________________________________________________________

  On a laptop nothing shields the gateway from the computer it runs on, and the tool server it forwards to always sits outside the sealed-off hardware (the TEE, trusted execution environment).

  [Limitations](https://cmcp.agentrust-io.com/limitations/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  Real hardware reports checked on AMD SEV-SNP (an Azure confidential VM) and Intel TDX (GCP C3), validated 2026-07-27. NVIDIA GPU confidential computing is not implemented.

  [Hardware validation](https://cmcp.agentrust-io.com/testing/hardware-validation/index.md)

- **The chain**

  ______________________________________________________________________

  Before it: [Agent Manifest](https://manifest.agentrust-io.com) describes the agent. Alongside: [cA2A](https://ca2a.agentrust-io.com) covers one agent handing work to another. After it: receipts in [TRACE](https://trace.agentrust-io.com). Check a real Intel TDX hardware report at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [See the chain](https://agentrust-io.com/#chain)

## Choose your next step

| You want to…                                   | Start here                                                                                      | Result                                                |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| See a rule block a call                        | [Guided first demo](https://agentrust-io.com/quickstart/)                                       | A blocked request and a signed receipt                |
| Try it with a real tool server on your machine | [Allow/deny quickstart](https://cmcp.agentrust-io.com/quickstart/index.md)                      | One denied tool call and one forwarded call           |
| Connect an existing agent                      | [MCP client integration](https://cmcp.agentrust-io.com/tutorials/existing-mcp-clients/index.md) | Your client sends requests through the gateway        |
| Understand what it protects                    | [How it works](https://cmcp.agentrust-io.com/concepts/index.md)                                 | Tell apart rule checking, signing, and hardware proof |
| Deploy with hardware evidence                  | [TEE attestation](https://cmcp.agentrust-io.com/tutorials/tee-attestation/index.md)             | What each cloud needs and what a checker must verify  |
| Build your own implementation                  | [Specification index](https://cmcp.agentrust-io.com/spec-index/index.md)                        | The exact rules for each part                         |

## What changes at the tool boundary

Logging in tells the gateway who is calling. Your Cedar rules decide what that caller's tool call is allowed to do. The gateway writes down every decision, and when the session ends it signs a record of all of them.

On confidential-computing hardware (machines that keep running code sealed off from the cloud operator), the gateway can also be protected from the computer it runs on, within what each cloud provider supports and lets you verify. The agent, the AI model and the tool servers are still separate programs outside that protection. Calls that do not go through the gateway are not checked. Whether data can leak to the host also depends on the outbound-traffic (egress) rules you configure.

A working laptop demo is not proof of hardware isolation. Read [how it works](https://cmcp.agentrust-io.com/concepts/index.md), [enforcement modes](https://cmcp.agentrust-io.com/configuration/index.md) and [limitations](https://cmcp.agentrust-io.com/limitations/index.md) first.

## Get involved

Found a bug or have feedback on the specification? Open an [issue](https://github.com/agentrust-io/cmcp/issues) with the command that failed, the runtime version, and what you expected to happen. See [Contributing](https://github.com/agentrust-io/cmcp/blob/main/CONTRIBUTING.md).

**Status:** cmcp-runtime 0.7.0 · MIT · hosting at the Agentic AI Foundation proposed, not accepted · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
