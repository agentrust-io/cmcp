# cMCP — current status

This file is the single source of truth for what ships today versus what is on the roadmap.
Other docs (README, SPEC, quickstart) should link here rather than restate status, so the
picture is stated once. Developer Preview: interfaces may change before v1.0.

## Defaults (from `cmcp_runtime.config`)

| Setting | Default |
|---|---|
| `attestation.provider` | `auto` (probe order `tpm -> sev-snp -> tdx`) |
| `attestation.enforcement_mode` | `enforcing` |
| `attestation.staleness_policy` | `fail_closed` |
| `attestation.validity_seconds` | `86400` |
| `policy_reload_interval_seconds` | `0` (disabled; policy change requires an enclave restart) |

## Capabilities

| Capability | Status | Notes |
|---|---|---|
| MCP interception + Cedar policy evaluation inside the TEE | Shipped | HTTP/SSE transport. `stdio` is not yet supported (bridge planned, Phase 2). |
| Enforcement modes (`enforcing` / `advisory` / `silent`) | Shipped | Default is `enforcing`. |
| Hash-chained audit log, TEE-sealed signing key | Shipped | |
| `GatewayClaim` (TRACE Claim) generation + signing | Shipped | Normative schema: [`schemas/trace-claim.schema.json`](schemas/trace-claim.schema.json). |
| Offline verification (`cmcp_verify`) | Shipped | No operator trust required when the verifier independently checks the attestation report. |
| Agent Manifest identity binding | Shipped | Optional; trust in the issuer key is an out-of-band PKI concern. |
| Attestation verifiers: `tpm`, `sev-snp`, `tdx` | Partial | Report parsing + certificate-chain verification against real vendor roots; report-signature paths validated with synthetic vectors. End-to-end validation against a real hardware quote on a confidential VM is pending — do not describe as fully hardware-attested until then. |
| `opaque` provider | Not implemented | Opt-in placeholder; excluded from auto-detect. Selecting it explicitly raises `ATTESTATION_PROVIDER_NOT_IMPLEMENTED` rather than falling through silently. |
| `gpu-cc` (NVIDIA H100/H200/Blackwell, via NRAS) | Planned (v0.2) | |
| Transparency-log anchoring for TRACE Claims | v0.2 | Write and lookup. |
| Server-side (provider) attestation | Not yet (Phase 2) | Phase 1 attests the gateway boundary only. |
| Real-time policy update without enclave restart | Not yet | `policy_reload_interval_seconds` is `0`; a policy change requires a restart. |
| Full RATS/EAT conformance | v1.0 target | Claims are EAT-shaped today; full conformance is tracked for v1.0. |

See [ROADMAP.md](ROADMAP.md) for version sequencing and [LIMITATIONS.md](LIMITATIONS.md) for
what cMCP does not prevent.
