# cMCP Runtime - Latency Targets and Benchmark Specification

Closes #27.

## Overview

This document defines latency targets and the benchmark methodology for the cMCP Runtime. Targets are split by phase:

- **Phase 1**: Runtime intercept path only (Cedar policy evaluation, audit entry creation, routing). No payload inspection.
- **Phase 2**: Full proxy path with payload inspection (pattern-based and model-based classification).

---

## Phase 1 Targets

### Attestation Handshake (one-time, at runtime startup)

Attestation is a startup cost, not a per-call cost. It is not included in the per-call latency budget.

| TEE Provider    | Target     | Notes                                              |
|-----------------|------------|----------------------------------------------------|
| TPM             | < 500ms    | Hardware I/O bound; TPM attestation is slow        |
| SEV-SNP         | < 100ms    | Azure DCasv5, AWS C6a Nitro                        |
| TDX             | < 100ms    | Azure DCedsv5, GCP C3                              |
| Opaque Managed  | < 50ms     | Opaque Managed Runtime, highest assurance          |

### Per-Call Runtime Overhead

Covers Cedar policy evaluation + audit entry creation + routing. Excludes upstream tool execution time.

| Percentile | Target  |
|------------|---------|
| p50        | < 1ms   |
| p95        | < 3ms   |
| p99        | < 5ms   |

Expected breakdown for a 10-rule policy bundle:

| Component                      | Estimated cost     |
|--------------------------------|--------------------|
| Cedar evaluation (10 rules)    | 0.2 – 0.5ms        |
| Audit entry hash computation   | ~0.1ms             |
| Network routing overhead       | 0.5 – 2ms          |

---

## Phase 2 Targets

Phase 2 adds payload inspection between runtime receive and upstream forward.

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

Run one benchmark suite per TEE provider, on TEE-enabled hardware matching production targets. Do not run benchmarks on non-TEE hardware and report results as representative.

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

Run 1000 calls before measurement starts. This eliminates JIT compilation and cache cold-start effects from reported numbers.

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

Benchmark results are committed as JSON to the `benchmarks/` directory in CI after each run.

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
