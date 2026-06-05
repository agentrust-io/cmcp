<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="cMCP"/>
</p>

# cMCP — Confidential MCP Gateway

Hardware-attested policy enforcement for MCP tool calls. Every tool call is intercepted, evaluated against a Cedar policy bundle, and enforced by a policy engine running inside a Trusted Execution Environment (TEE). The policy bundle hash is measured into the hardware attestation report before any code runs.

```yaml
pip install cmcp-gateway
```

```yaml
# cmcp-config.yaml
attestation:
  provider: tpm           # auto-detects: tpm -> sev-snp -> tdx -> opaque
  enforcement_mode: advisory
cmcp start --config cmcp-config.yaml
```

## Why TEE

| Threat | Software Governance | cMCP |
|--------|--------------------|----|
| Rogue admin replaces Cedar policy on disk | Undetected — hash chain runs in compromised OS | Policy hash measured by hardware before code runs |
| Supply chain CVE flips allow/deny signal | Undetected — evaluator in attacker's address space | Evaluator in isolated enclave memory |
| Admin regenerates audit log post-breach | Undetected — any party with signing key can reconstruct | Signing key hardware-sealed — new valid signatures are impossible |
| Permissive policy loaded at evaluation time | Undetected — comparator runs in mutable process | Policy bundle measured at enclave startup |

## Architecture

```
Agent → cMCP Gateway → Cedar Policy Engine (TEE) → Tool
                    ↓
              TRACE Claim Output
              - policy_bundle_hash
              - enforcement_mode
              - audit_chain_root
              - trust_score
              - tee_public_key
```

## Hardware Providers

| Provider | Hardware | Assurance |
|----------|----------|-----------|
| `tpm` | TPM 2.0 / vTPM (any Azure/AWS/GCP VM with Trusted Launch) | Medium |
| `sev-snp` | AMD SEV-SNP (Azure DCasv5, AWS C6a Nitro) | High |
| `tdx` | Intel TDX (Azure DCedsv5, GCP C3) | High |
| `opaque` | Opaque Managed Runtime | Highest |

## Status

Private. Launching at CC Summit June 23, 2026. See [agentrust-io](https://github.com/agentrust-io) for release timeline.

## License

MIT