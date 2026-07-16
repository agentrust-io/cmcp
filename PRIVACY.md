# Privacy

cMCP is a self-hosted gateway that you deploy and operate. agentrust-io and OPAQUE run no service on your behalf and receive no data from your deployment: cMCP sends no telemetry, analytics, or usage data to us.

What cMCP processes: as an MCP gateway, cMCP handles the MCP requests and responses that pass through it in order to enforce policy and produce attestation. This traffic is processed inside the trusted execution environment (TEE) you run and is governed by your own configuration and your privacy commitments to your users. cMCP is designed so that a privileged operator cannot silently exfiltrate this data.

What cMCP records: cMCP can emit signed TRACE records (metadata such as model, policy hash, data class, and tool-call digests) to the destinations you configure. It writes only what your policy specifies, where you specify.

As the operator, you are the data controller for traffic through your cMCP deployment. This notice describes the software's behavior, not a hosted service.

Questions or corrections: https://github.com/agentrust-io/cmcp/issues
