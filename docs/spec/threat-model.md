# Threat Model

This document captures the cMCP Gateway threat model with precision corrections required before handoff to a security architect, plus the H3 security investigation into tool identity integrity threats.

## Precision Corrections to SPEC.md

### Correction 1: APM Payload Capture and SDK Telemetry

**Status: Mitigated (default-deny egress, operator-dependent)**

The protection is structural only when the egress policy denies the APM/telemetry endpoint. The TEE prevents plaintext from leaving the enclave, but if the operator allowlists the APM endpoint in the egress policy, the protection is not active. This threat is mitigated by correct configuration, not eliminated structurally.

Verifiers must confirm that the egress policy hash excludes APM and telemetry endpoints. A TRACE Claim with an egress policy that permits APM endpoints does not provide this protection, and the verifier should flag it.

### Correction 2: Server Swap / Tool Identity (T.1)

**Status: Closes (requires agent-side verification)**

The gateway produces an attestation report. T.1 is only closed if the agent (or the agent's gateway) verifies the attestation report before sending traffic. Without verification, the attestation exists as post-hoc evidence but provides no runtime protection against server swap at the moment of the call.

The verification library (`cmcp-verify`, see [verification-library.md](verification-library.md)) is required to close this threat. Deployments that do not run `cmcp-verify` (or an equivalent) treat attestation as audit evidence only, not as a runtime gate.

### Correction 3: P4.1 Supply Chain

**Status: Prevented (binary-level only)**

Hardware measurement at launch time proves the binary is what it should be. Runtime configuration injection (environment variables, mounted secrets, configuration files loaded after startup) happens after the measurement. A supply chain attack that operates via runtime configuration changes the server's behavior without changing the binary measurement.

The binary-level protection is real and valuable. The runtime config gap must be stated explicitly in any compliance claim referencing this control.

---

## H3 Investigation: Tool Identity Integrity Threats

### Shape 1: Typosquatted MCP Packages (P4.1)

**Attack vector.** Malicious packages are seeded in MCP registries (npm, PyPI) with names visually similar to legitimate packages. LLM coding assistants suggest install commands with incorrect spelling, and developers copy-paste without verifying.

**Documented precedent.** CVE-2025-54136 (MCPoison) is a documented instance of MCP package typosquatting. This is not a theoretical threat.

**Phase 1 gateway coverage.** The Phase 1 gateway refuses to route to any server not present in its attested catalog. A typosquatted package cannot receive traffic unless it has been added to the catalog. If a developer mistakenly adds the typosquatted package to the catalog, Phase 1 does not detect it. Catalog entries are human-approved; the gateway trusts the catalog.

**Phase 2 coverage.** Server-side attestation proves the binary running inside the TEE matches the approved image. A typosquatted package running a different binary produces a measurement mismatch and fails attestation.

**Investigation framework.** To validate whether this is a live customer threat versus theoretical, check:

1. Are there reported incidents of MCP package typosquatting beyond CVE-2025-54136?
2. Do design partner developers use LLM coding assistants to install MCP packages? If yes, this is a real near-term vector that Phase 2 closes structurally.

### Shape 2: Rug-Pull via Tool-Definition Mutation (P4.2)

**Attack vector.** A previously-approved MCP server uses `notifications/tools/list_changed` to silently modify tool definitions after security review has concluded. The description field is the primary target because the LLM reads it as authoritative context and the change is not visible to a human reviewer watching traffic.

**Phase 1 gateway coverage.** Catalog hash pinning detects this. The approved tool definition hash is stored in the catalog. When the server sends a changed definition, the gateway computes the new `definition_hash` and compares it against the catalog entry. A mismatch triggers fail-closed behavior: calls to the affected tool are denied until the catalog is explicitly updated by a human approver. This is strong coverage for the rug-pull vector.

**Phase 2 coverage.** Server-side attestation proves the tool surface at startup matches the approved catalog. A server that has drifted from its approved tool surface produces a measurement mismatch and fails attestation before any traffic is routed.
