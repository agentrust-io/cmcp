# cMCP Runtime - 72-Hour Soak Test Plan

A soak test runs the gateway for a long stretch, here 72 hours, to find problems that only show up over time, such as slowly growing memory or connections that quietly drop. This page is the plan for that test: how to set it up, what to check, and what counts as a pass. It is for anyone running or reviewing a long-running deployment. (Plan written for issue #31.)

## Purpose

Find stability failures that only appear after hours of use. Short integration tests and unit tests will not catch:

- Attestation expiration mid-session (attestation is the hardware's signed proof of what software is running, and it is only trusted for a set time)
- Audit chain memory growth (the audit chain is the gateway's tamper-evident log of every call)
- SSE connection drops through an HTTP proxy (SSE, server-sent events, is how streamed responses travel)
- Cloud networking idle timeout behavior
- Signing key consistency across the enclave lifetime (the enclave is the hardware-isolated area the gateway runs in)

---

## Test Setup

| Parameter           | Value                                                                 |
|---------------------|-----------------------------------------------------------------------|
| Duration            | 72 hours continuous                                                   |
| Load pattern        | Alternating blocks: 1 hour active (100 calls/hour), 1 hour idle (0 calls). Repeat 36 times. |
| HTTP proxy          | nginx as reverse proxy between test client and runtime (simulates corporate firewall) |
| TEE providers       | TPM (mandatory); one of SEV-SNP or TDX (mandatory if available in CI) |
| Cedar policy        | 10-rule allowlist, enforcing mode                                     |
| Session type        | Long-running: session_id persists for 4 hours, then a new session starts |

### Reference MCP Server

A test MCP server (the tool server the gateway sits in front of) that offers 3 tools:

| Tool       | Behavior                                                        |
|------------|-----------------------------------------------------------------|
| `echo`     | Returns input unchanged                                         |
| `get_data` | Returns 1KB of synthetic PII-tagged data                        |
| `delay`    | Sleeps for a specified number of milliseconds, then returns     |

---

## Edge Cases

These are the five situations most likely to break over a long run. Each edge case must be explicitly tested and logged. A soak run does not pass if any edge case is skipped.

### 1. Attestation Expiration During Active Session

**Setup:** Set `attestation_validity_seconds = 14400` (4 hours). Sessions are 4 hours long, so expiration coincides with session boundary.

**What to check:** When attestation expires, the runtime must either:
- Re-attest without service interruption, or
- Terminate the session with a clean error and issue a new attestation for the next session.

**Success:**
- No orphaned sessions (sessions that continue past attestation expiry without a clean state transition).
- No TRACE Claims where `attestation_generated_at` is stale and `attestation_stale` is not set to `true`.

---

### 2. SSE Connection Stability Through HTTP Proxy

**Setup:** nginx `keepalive_timeout` defaults to 65 seconds. Run 10 SSE streaming calls of 30-second duration with nginx in the path.

**What to monitor:**
- Silent connection termination (drop without error)
- nginx proxy timeouts
- Incomplete SSE event streams

**Success:** All 10 streaming calls complete without silent disconnection.

---

### 3. Memory Growth from Audit Chain

**Setup:** At 100 calls/hour over 72 hours, the audit chain accumulates approximately 4,800 entries. Measure enclave memory usage at T=0h, T=24h, T=48h, T=72h.

**Success:** Memory grows in step with the number of audit entries (O(n) with n = audit entries) and no faster.

Absolute threshold: enclave memory at T=72h must be less than:

```
(2 × enclave_memory_at_T0) + (4800 × average_entry_size_bytes)
```

---

### 4. TEE Networking Idle Timeout

**Setup:** During the 1-hour idle periods, confirm that MCP connections are handled correctly. Cloud networks may close a network connection that has carried no traffic for 10 minutes.

**What to check:**
- Does the runtime maintain idle upstream connections?
- Does it detect and re-establish connections after a cloud NAT timeout?

**Success:** After a 1-hour idle period, the first active-period call succeeds within 2x normal p99 latency (to account for connection re-establishment).

---

### 5. Signing Key Stability

**Setup:** Collect `tee_public_key` from one TRACE Claim at T=0h, T=24h, T=48h, and T=72h (four samples total, one per 24-hour window).

**Expected:** All four values are identical. The signing key is created fresh inside the TEE (trusted execution environment) when it starts, and it must not change during the enclave's lifetime.

**Success:**
- All 4 `tee_public_key` values are identical.
- If they differ (indicating an unexpected enclave restart), the soak log records the timestamp of the restart.

---

## Success Criteria

All items must pass for the soak run to be marked successful.

- [ ] 0 runtime crashes over 72 hours
- [ ] 0 TRACE Claims with attestation gaps (every call in the active period appears in the audit chain)
- [ ] Memory growth bounded (within the threshold defined above)
- [ ] All 10 SSE streaming calls complete without silent disconnection
- [ ] Idle-to-active transitions succeed within 2x normal latency
- [ ] Signing key stable across all 72 hours (unless restart, which is logged)
- [ ] No session orphaning after attestation expiry

---

## Output

After each run, commit results to `benchmarks/soak-YYYY-MM-DD.json`.

```json
{
  "run_date": "2026-06-04",
  "duration_hours": 72,
  "provider": "sev-snp",
  "total_calls": 4800,
  "crashes": 0,
  "attestation_gaps": 0,
  "memory_t0_bytes": 0,
  "memory_t24_bytes": 0,
  "memory_t48_bytes": 0,
  "memory_t72_bytes": 0,
  "sse_calls_completed": 10,
  "sse_silent_drops": 0,
  "idle_transition_within_2x": true,
  "signing_key_stable": true,
  "signing_key_restart_timestamps": [],
  "session_orphans": 0,
  "passed": true
}
```
