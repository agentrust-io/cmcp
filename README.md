<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="cMCP"/>
</p>

# cMCP: Confidential MCP Runtime

### Enforce MCP tool policy where it cannot be tampered with

<p align="center">
  <a href="https://agentrust-io.github.io/cmcp">
    <img src="https://img.shields.io/badge/Documentation-agentrust--io.github.io%2Fcmcp-7c3aed?style=for-the-badge" alt="Documentation" height="36">
  </a>
</p>

<p align="center">
  <strong>
    <a href="#quick-start">Quick Start</a> ·
    <a href="#how-it-works">Architecture</a> ·
    <a href="#configuration">Configuration</a> ·
    <a href="#cli-reference">CLI</a> ·
    <a href="CHANGELOG.md">Changelog</a>
  </strong>
</p>

[![CI](https://github.com/agentrust-io/cmcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agentrust-io/cmcp/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![PyPI](https://img.shields.io/pypi/v/cmcp-runtime)](https://pypi.org/project/cmcp-runtime/) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/agentrust-io/cmcp/badge)](https://scorecard.dev/viewer/?uri=github.com/agentrust-io/cmcp) [![Discord](https://dcbadge.limes.pink/api/server/9JWNpH7E?style=flat)](https://discord.gg/9JWNpH7E)

> **Developer Preview** - launching at Confidential Computing Summit, June 23 2026. May have breaking changes before v1.0.

Your agent calls Snowflake, Salesforce, a dozen APIs. What stops it from leaking a customer's data on one of those calls? If a regulator asks, could you prove it didn't?

---

## The problem

An agent calls a tool. The policy engine says allow. The tool call goes through.

None of that proves the policy engine itself was not compromised. Software-only MCP governance cannot guarantee:

- The Cedar policy on disk is the one that ran. A rogue admin can swap the bundle after approval; the hash check runs inside the same OS the admin controls.
- The allow/deny decision was not flipped in memory. A supply chain CVE in the evaluator runs in the same address space as the attacker.
- The audit log reflects what actually happened. Any party holding the software signing key can reconstruct a valid audit chain after the fact.

The control plane that governs tool calls must run where it cannot be reached by the process it governs.

Hardware-attested policy enforcement for MCP tool calls. Every tool call is intercepted, evaluated against a Cedar policy bundle, and enforced by a policy engine running inside a Trusted Execution Environment (TEE). The policy bundle hash is measured into the hardware attestation report before any code runs.

Unlike tunnel-based connectivity solutions, the cMCP Runtime processes tool-call payloads inside the TEE. The connectivity provider sees ciphertext, not plaintext. The only thing that leaves the enclave is the signed TRACE claim.

---

## Quick Start

```bash
pip install cmcp-runtime
```

Create `cmcp-config.yaml`:

```yaml
attestation:
  provider: auto
  enforcement_mode: advisory
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
```

Start the gateway:

```bash
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

Make a tool call:

```bash
curl -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"salesforce.contacts","arguments":{"query":"Acme Corp"},"_cmcp":{"session_id":"s1","workflow_id":"demo-agent"}}}'
```

See [docs/quickstart.md](docs/quickstart.md) for the full walkthrough: Cedar policy, tool catalog, first TRACE Claim, and verification (no hardware TEE required).

---

## How it works

1. The agent sends every tool call to the cMCP Gateway instead of directly to MCP servers.
2. At startup the gateway measures the Cedar policy bundle hash into the hardware attestation report. No code runs before this measurement.
3. Each incoming tool call is evaluated by the Cedar policy engine running inside the TEE. The result is allow, deny, or redact. The call and its decision are appended to the hardware-sealed audit chain.
4. At the end of the session the gateway produces a TRACE Claim: a signed, hardware-attested artifact that records which tools ran, which policy decided each call, and the full audit chain. A verifier checks this without trusting the operator.

```
Agent -> cMCP Runtime -> Cedar Policy Engine (TEE) -> Tool
                     |
               GatewayClaim (TRACE Profile)
               +-- trace.eat_profile
               +-- trace.runtime.platform + measurement
               +-- trace.policy.bundle_hash
               +-- trace.cnf.jwk  (Ed25519 confirmation key)
               +-- gateway.audit_chain (root/tip/length)
               +-- signature (Ed25519 over canonical JSON)
```

---

## Hardware providers

| Provider | Platform | Assurance | Notes |
|---|---|---|---|
| `tpm` | TPM 2.0 / vTPM (Azure, AWS, GCP Trusted Launch) | Medium | Local TPM quote |
| `sev-snp` | AMD SEV-SNP (Azure DCasv5, AWS C6a Nitro) | High | AMD KDS |
| `tdx` | Intel TDX (Azure DCedsv5, GCP C3) | High | Intel PCS |
| `gpu-cc` _(v0.2)_ | NVIDIA H100/H200/Blackwell (CC mode) | High | NVIDIA Remote Attestation Service (NRAS) |
| `opaque` _(explicit opt-in)_ | OPAQUE Confidential Runtime | High | Set `OPAQUE_ATTESTATION_URL`; not in auto-detect chain (stub: detect() returns False, not yet implemented) |

Provider auto-detects: `SEV-SNP -> TDX -> TPM -> software`. `opaque` is explicit opt-in via `OPAQUE_ATTESTATION_URL` and is never selected automatically.

```python
from cmcp_gateway.config import TEEProvider

# Auto-detect (default)
# attestation.provider: auto  ->  sev-snp -> tdx -> tpm -> software

# Explicit hardware selection
# attestation.provider: sev-snp

# Opaque Managed Runtime (explicit opt-in only)
# OPAQUE_ATTESTATION_URL=https://... cmcp start --config cmcp-config.yaml
```

---

## Enforcement modes

| Mode | Behavior | Use case |
|---|---|---|
| `enforcing` | Policy denies return HTTP 403; call is not forwarded | Production |
| `advisory` | Policy denies are logged; call proceeds | First deployment, policy tuning |
| `silent` | Policy is evaluated but nothing is logged or blocked | Baselining |

Default is `enforcing`. Set `enforcement_mode: advisory` in `cmcp-config.yaml` to use advisory mode.

---

## Configuration

`cmcp-config.yaml` full reference:

```yaml
attestation:
  provider: auto                    # auto | tpm | sev-snp | tdx | opaque | software-only
  enforcement_mode: enforcing       # enforcing | advisory | silent
  validity_seconds: 86400           # attestation freshness window (default: 24 hours)
  staleness_policy: fail_closed     # fail_closed | warn_only
  expected_measurement: ~           # pin a specific PCR/measurement (optional)

policy_bundle_path: policy/         # directory containing .cedar files and manifest.json
catalog_path: catalog.json          # approved tool catalog

listen_addr: "0.0.0.0:8443"
max_response_size_bytes: 2097152    # 2 MB default
policy_reload_interval_seconds: 0   # 0 = disabled; restart required to update policy
```

Environment variables:

| Variable | Effect |
|---|---|
| `CMCP_DEV_MODE=1` | Use software-only TEE provider; no hardware required |
| `CMCP_BEARER_TOKEN` | Require this bearer token on all inbound requests |
| `OPAQUE_ATTESTATION_URL` | Enable Opaque Managed Runtime attestation (explicit opt-in) |

---

## CLI reference

| Command | Flags | Description |
|---|---|---|
| `cmcp start` | `--config PATH` (required) | Start the gateway |
| `cmcp validate-config` | `--config PATH` (required) | Validate `cmcp-config.yaml` without starting |
| `cmcp validate-bundle` | `--bundle-path PATH` (required), `--expected-hash sha256:<hex>` (required) | Verify a Cedar bundle hash before deployment |

---

## TRACE Claims

A `GatewayClaim` is the unit of proof handed to an auditor, regulator, or downstream verifier. It is produced per session (or per call, configurable) and signed with a key that never leaves the TEE.

| Field | Description |
|---|---|
| `trace.eat_profile` | EAT profile URI: `tag:agentrust.io,2026:trace-v0.1` |
| `trace.runtime` | TEE platform and hardware measurement recorded at enclave boot |
| `trace.policy.bundle_hash` | SHA-256 of the Cedar bundle loaded at startup; changing any policy file changes this value |
| `trace.cnf.jwk` | Ed25519 public key bound to the TEE signing key |
| `gateway.audit_chain` | Hash-chained audit log root and tip; verifiable without replaying individual entries |
| `signature` | Ed25519 over canonical JSON of the full claim body (RFC 8785) |

Verification with the `cmcp_verify` library does not require trusting the operator. The verifier checks the signature against the TEE-bound key, the policy bundle hash against the approved value, and the audit chain for internal consistency.

See [docs/spec/verification-library.md](docs/spec/verification-library.md) and the [TRACE specification](https://agentrust.io/trace-spec) for the full verification protocol.

---

## Standards alignment

| Standard | Coverage |
|---|---|
| OWASP Agentic AI Top 10 | MCP10 (data leakage via tool calls), MCP02 (unsanctioned tools), MCP08 (provable governance), MCP04 (supply chain) |
| NIST SP 800-207 | Policy decision point inside TEE; no implicit trust in workload identity |
| EU AI Act Art. 12, 15 | Per-decision audit records (Art. 12); TEE-backed cybersecurity controls (Art. 15) |
| DORA Art. 9 | Attestation chain; audit log retention via `gateway.audit_chain` |
| RATS/EAT RFC 9711 | `GatewayClaim` is an EAT; `eat_profile` field identifies the TRACE profile |

---

## Security

| Tool | What it checks |
|---|---|
| ruff | Style and import linting on every PR |
| bandit | Python security linting on every PR |
| pip-audit | Dependency vulnerability scan on every PR |
| mypy | Static type checking on every PR |
| CodeQL | Python SAST, security-extended queries, weekly |
| OpenSSF Scorecard | Weekly scoring, SARIF upload |

See [SECURITY.md](SECURITY.md) for vulnerability reporting and response SLAs. See [LIMITATIONS.md](LIMITATIONS.md) for explicit scope boundaries, including residual risks for APM payload capture, runtime config injection, and P4.1 supply chain (typosquat) that Phase 1 does not close.

---

## Documentation

| Page | Description |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | From zero to first TRACE Claim in under 30 minutes |
| [docs/configuration.md](docs/configuration.md) | Full config reference with all fields and defaults |
| [docs/SPEC.md](docs/SPEC.md) | Product specification: problem taxonomy, architecture, coverage matrix |
| [docs/spec/threat-model.md](docs/spec/threat-model.md) | STRIDE analysis, adversary model, residual risks |
| [docs/spec/cedar-policy.md](docs/spec/cedar-policy.md) | Cedar policy language reference and schema |
| [docs/testing/benchmarks.md](docs/testing/benchmarks.md) | Latency and throughput benchmarks per TEE provider |

---

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) · [GOVERNANCE.md](GOVERNANCE.md) · [Discussions](https://github.com/agentrust-io/cmcp/discussions)

Join the community on [Discord](https://discord.gg/9JWNpH7E).

Using cMCP in production? Add your organization to [ADOPTERS.md](ADOPTERS.md).

---

## License

MIT - see [LICENSE](LICENSE).
