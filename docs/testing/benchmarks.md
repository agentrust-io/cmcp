# cMCP Runtime: Latency Targets and Benchmarks

This page says how much delay cMCP aims to add to each tool call, and how to measure it.
It is for anyone sizing a deployment or checking performance. The numbers here are goals
and estimates; no measured results are published yet.

## Latest results

The benchmark that runs in CI (our automated build) on the main branch uses `software-only` mode, with no secure hardware, on a standard Ubuntu runner. It uploads a `benchmark-results` workflow artifact; it does not commit nightly hardware measurements to the repository. See the [CI workflow](https://github.com/agentrust-io/cmcp/blob/main/.github/workflows/ci.yml).

The committed `benchmarks/` directory currently contains only its placeholder. The latency figures below are targets and estimates, not measured results or service guarantees. For recorded hardware validation, see [hardware runs](hardware-validation.md); those reports have their own scope and do not establish these latency targets.

---

## Overview

Latency is the extra time cMCP adds between an agent sending a tool call and the call reaching the tool. The targets come in two phases:

- **Phase 1**: the gateway checks the call against the Cedar policy (the rule file), writes an audit entry, and passes the call on. It does not look inside the data.
- **Phase 2**: the gateway also inspects the data in each request and response, using pattern matching or a classifier model.

---

## Phase 1 Targets

### Attestation Handshake (one-time, at runtime startup)

Attestation is the step where the secure hardware proves what software it is running. It happens once when the gateway starts, so it is not counted in the time per call.

| TEE Provider    | Target     | Notes                                              |
|-----------------|------------|----------------------------------------------------|
| TPM             | < 500ms    | Hardware I/O bound; TPM attestation is slow        |
| SEV-SNP         | < 100ms    | Provider-specific deployment; verify the actual attestation profile                        |
| TDX             | < 100ms    | Azure DCedsv5, GCP C3                              |

### Per-Call Runtime Overhead

This covers the policy check, the audit entry and passing the call on. It leaves out the time the tool itself takes to do the work.

| Percentile | Target  |
|------------|---------|
| p50        | < 1ms   |
| p95        | < 3ms   |
| p99        | < 5ms   |

Expected breakdown for a 10-rule policy bundle:

| Component                      | Estimated cost     |
|--------------------------------|--------------------|
| Cedar evaluation (10 rules)    | 0.2 to 0.5ms        |
| Audit entry hash computation   | ~0.1ms             |
| Network routing overhead       | 0.5 to 2ms          |

---

## Phase 2 Targets

Phase 2 adds a look inside the data after the gateway receives a call and before it passes the call to the tool.

| Path                                           | p50     | p95     | p99     |
|------------------------------------------------|---------|---------|---------|
| Pattern-based classification (regex + schema)  | < 2ms   | < 8ms   | < 10ms  |
| Model-based classification (semantic ML)       | < 30ms  | < 80ms  | < 100ms |
| Full proxy path (Cedar + pattern)              | < 5ms   | < 12ms  | < 15ms  |

**Notes:**
- Pattern classification is measured against a 1KB JSON payload with 20 patterns.
- Model-based classification is Phase 2+ and not required for Phase 1.

---

## Benchmark Methodology

### Hardware

Run one set of benchmarks per TEE provider (a TEE, or trusted execution environment, is the hardware-isolated area the gateway runs in), on the same kind of hardware you would use in production. Numbers from ordinary hardware without a TEE do not represent a real deployment, so do not report them as if they did.

### Representative Policy Bundle

A 12-rule Cedar bundle:
- 10 tool allowlist rules
- 2 field-redaction rules
- 1 cross-boundary rule

### Representative Payloads

**Tool call (request):**
```json
{
  "tool_name": "salesforce.query",
  "arguments": {
    "soql": "SELECT Id, Name, Email FROM Contact WHERE AccountId = '001x000001'",
    "max_records": 100
  }
}
```
Approximately 200 bytes.

**Tool response:** 1KB JSON with 10 fields, 2 of which are PII-tagged.

### Warmup

Run 1000 calls before you start measuring, so that one-off startup costs (code compilation and empty caches) do not show up in the numbers.

### Measurement

- 10,000 calls per benchmark run
- Report p50, p95, p99 per run
- Run 5 times and average across runs

### Metrics

Collect the following per run, in microseconds unless noted:

| Metric                    | Unit  | Description                                                                   |
|---------------------------|-------|-------------------------------------------------------------------------------|
| `cedar_eval_latency_us`   | µs    | Cedar policy evaluation time                                                  |
| `audit_entry_latency_us`  | µs    | Time to hash and append audit chain entry                                     |
| `routing_latency_us`      | µs    | Time from runtime receive to first byte sent to upstream                      |
| `end_to_end_latency_us`   | µs    | Time from agent request received to response returned (excludes upstream)     |
| `attestation_handshake_ms`| ms    | Measured once at startup, not per-call                                        |

---

## Reporting Format

Benchmark results are committed as JSON to the `benchmarks/` directory in CI after each run, in this format. (As noted at the top, the directory holds only a placeholder today.)

```json
{
  "provider": "sev-snp",
  "timestamp": "2026-06-04T00:00:00Z",
  "policy_rules_count": 12,
  "payload_bytes": 200,
  "calls_measured": 10000,
  "cedar_eval_us": {"p50": 210, "p95": 450, "p99": 890},
  "audit_entry_us": {"p50": 95, "p95": 180, "p99": 350},
  "end_to_end_us": {"p50": 850, "p95": 2100, "p99": 4200}
}
```

File naming: `benchmarks/<provider>-YYYY-MM-DD.json`. One file per provider per run.
