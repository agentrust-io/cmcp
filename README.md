<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="cMCP"/>
</p>

# cMCP: Confidential MCP Runtime

### Enforce MCP tool policy where it cannot be tampered with

<p align="center">
  <a href="https://cmcp.agentrust-io.com">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_Full_Documentation-cmcp.agentrust--io.com-7c3aed?style=for-the-badge&logoColor=white" alt="Full Documentation" height="40">
  </a>
</p>

<p align="center">
  <a href="docs/quickstart.md">Quick Start</a> &nbsp;|&nbsp;
  <a href="docs/spec/architecture.md">Architecture</a> &nbsp;|&nbsp;
  <a href="docs/spec/">Specification</a> &nbsp;|&nbsp;
  <a href="CHANGELOG.md">Changelog</a>
</p>

[![CI](https://github.com/agentrust-io/cmcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agentrust-io/cmcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/cmcp-runtime)](https://pypi.org/project/cmcp-runtime/)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white&style=flat)](https://discord.gg/9JWNpH7E)

> **Developer Preview** — launching at Confidential Computing Summit, June 23 2026.

Hardware-attested policy enforcement for MCP tool calls. cMCP intercepts every tool call, evaluates it against a Cedar policy bundle, and enforces the decision inside a Trusted Execution Environment (TEE). The policy bundle hash is measured into the hardware attestation report before any code runs — the control plane governing tool calls runs where it cannot be reached by the process it governs.

Every tool call produces a signed [TRACE](https://github.com/agentrust-io/trace-spec) record: cryptographic proof of what ran, under which policy, in which TEE.

## Quick start

```bash
pip install cmcp-runtime
```

```yaml
# cmcp-config.yaml
attestation:
  platform: amd-sev-snp
policy:
  bundle: ./policy.tar.gz
  enforcement_mode: enforce
```

```bash
cmcp start --config cmcp-config.yaml
```

## Resources

| | |
|---|---|
| 📖 Full documentation | [cmcp.agentrust-io.com](https://cmcp.agentrust-io.com) |
| 📄 Specification | [docs/spec/](docs/spec/) |
| 🔑 Cedar policies | [examples/policies/](examples/policies/) |
| 🔗 TRACE attestation | [trace-spec](https://github.com/agentrust-io/trace-spec) |
| 🐳 Docker | [Dockerfile](Dockerfile) |
| 💬 Discussions | [GitHub Discussions](https://github.com/orgs/agentrust-io/discussions) |
| 📋 Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md).
