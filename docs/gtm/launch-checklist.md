# CC Summit Launch Checklist

**Target date:** June 23, 2026

---

## Technical Readiness

All items must be green before launch.

- [ ] Gateway intercepts a real MCP tool call in a demo environment (not mocked)
- [ ] Cedar policy evaluation runs inside a TEE (TPM baseline minimum, SEV-SNP preferred for demo)
- [ ] TRACE Claim is generated and signed with the TEE-sealed key
- [ ] Verification demo works: a third party verifies the TRACE Claim using `cmcp-verify` without operator involvement
- [ ] Advisory mode demo: same flow with `enforcement_mode=advisory`, no calls blocked, all logged
- [ ] Fail-closed demo: attempt a call not in the catalog; confirm it is denied and a structured error is returned
- [ ] 72-hour soak test completed on at least one TEE provider with all success criteria met (docs/testing/soak-test.md)
- [ ] Latency benchmarks collected and within targets (docs/testing/benchmarks.md)
- [ ] docs/SPEC.md merged and linked from README
- [ ] `cmcp-gateway` Python package installable via pip
- [ ] `cmcp-verify` Python package installable via pip
- [ ] Quickstart guide tested: time-to-first-TRACE-Claim under 30 minutes on a fresh cloud VM

---

## Recommended Demo Scenario

An agent calls a data tool with PII in the arguments. The gateway enforces a Cedar policy that redacts the SSN field before the call reaches the tool.

Show:
1. The TRACE Claim that a compliance officer would receive
2. The `cmcp-verify` output confirming: `policy_bundle` verified, `enforcement_mode=enforcing`, audit chain intact

---

## Business Readiness

- [ ] Qualifying question validated (see docs/research/qualifying-question-validation.md)
- [ ] Regulated buyer entry point playbook finalized (docs/gtm/regulated-buyer-playbook.md)
- [ ] Design partner term sheet template ready (docs/partners/design-partner-template.md)
- [ ] Two design partner conversations confirmed for post-event follow-up

---

*Closes #16*
