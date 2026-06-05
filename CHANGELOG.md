# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-23

### Added

- Initial TEE gateway with provider support for TPM, SEV-SNP, TDX, and Opaque
- Cedar policy enforcement for request authorization at the gateway layer
- TRACE Claim generation using the `GatewayClaim` envelope from `agentrust-trace`
- `cmcp-verify` standalone verifier for validating TRACE Claims offline
- Audit chain with Ed25519 signing for tamper-evident log integrity

[Unreleased]: https://github.com/agentic-ai-foundation/cmcp-agentrust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentic-ai-foundation/cmcp-agentrust/releases/tag/v0.1.0
