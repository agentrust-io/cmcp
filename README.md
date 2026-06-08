<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="cMCP"/>
</p>

# cMCP: Confidential MCP Gateway

[![CI](https://github.com/agentrust-io/cmcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agentrust-io/cmcp/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![PyPI](https://img.shields.io/pypi/v/cmcp-gateway)](https://pypi.org/project/cmcp-gateway/) [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/agentrust-io/cmcp/badge)](https://scorecard.dev/viewer/?uri=github.com/agentrust-io/cmcp)

Hardware-attested policy enforcement for MCP tool calls. Every tool call is intercepted, evaluated against a Cedar policy bundle, and enforced by a policy engine running inside a Trusted Execution Environment (TEE). The policy bundle hash is measured into the hardware attestation report before any code runs.

```yaml
pip install cmcp-gateway
```

```yaml
# cmcp-config.yaml
attestation:
  provider: tpm           # auto-detects: sev-snp -> tdx -> tpm -> software  (opaque is explicit opt-in via OPAQUE_ATTESTATION_URL)
  enforcement_mode: advisory
cmcp start --config cmcp-config.yaml
```

## Quick Start

```bash
pip install cmcp-gateway
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

See [docs/quickstart.md](docs/quickstart.md) for a full walkthrough: Cedar policy, tool catalog, first TRACE Claim, and verification (no hardware TEE required).

## Why TEE

| Threat | Software Governance | cMCP |
|--------|--------------------|----|
| Rogue admin replaces Cedar policy on disk | Undetected: hash chain runs in compromised OS | Policy hash measured by hardware before code runs |
| Supply chain CVE flips allow/deny signal | Undetected: evaluator in attacker's address space | Evaluator in isolated enclave memory |
| Admin regenerates audit log post-breach | Undetected: any party with signing key can reconstruct | Signing key hardware-sealed; new valid signatures are impossible |
| Permissive policy loaded at evaluation time | Undetected: comparator runs in mutable process | Policy bundle measured at enclave startup |

## Architecture

```
Agent -> cMCP Gateway -> Cedar Policy Engine (TEE) -> Tool
                     |
               GatewayClaim (TRACE Profile)
               +-- trace.eat_profile
               +-- trace.runtime.platform + measurement
               +-- trace.policy.bundle_hash
               +-- trace.cnf.jwk  (Ed25519 confirmation key)
               +-- gateway.audit_chain (root/tip/length)
               +-- signature (Ed25519 over canonical JSON)
```

## Hardware Providers

| Provider | Hardware | Assurance | Attestation Service |
|----------|----------|-----------|---------------------|
| `tpm` | TPM 2.0 / vTPM (any Azure/AWS/GCP VM with Trusted Launch) | Medium | Local TPM quote |
| `sev-snp` | AMD SEV-SNP (Azure DCasv5, AWS C6a Nitro) | High | AMD KDS |
| `tdx` | Intel TDX (Azure DCedsv5, GCP C3) | High | Intel PCS |
| `gpu-cc` _(v0.2)_ | NVIDIA H100/H200/Blackwell (CC mode) | High | NVIDIA Remote Attestation Service (NRAS) |
| `opaque` _(explicit opt-in)_ | Opaque Managed Runtime | High (explicit opt-in) | Opaque KMS |

## Status

Developer preview. Launching at CC Summit, June 23 2026. See [ROADMAP.md](ROADMAP.md) for what is planned.

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
