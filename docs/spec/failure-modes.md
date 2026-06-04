# Failure Mode Specification

Documents exact gateway behavior for every failure scenario.

Closes #22.

---

## Decision Table

| Failure | Default Behavior | Configurable? | TRACE Claim Status | Log Format |
|---------|-----------------|---------------|-------------------|------------|
| Attestation failure at startup | Fail-closed. Gateway does not start. No traffic processed. | No | Not produced | `FATAL attestation_failure` + provider + error code |
| Attestation staleness mid-session | Fail-closed. Active sessions terminated. | Yes (see FM-2) | `attestation_stale: true` on claims produced at or after deadline | `WARN attestation_stale` + session_id + expiry_utc |
| TEE fault mid-invocation | Fail-closed on in-flight call. Structured error returned to agent. Session continues if TEE recovers. | No | `status: fault` | `ERROR tee_fault` + call_id + timestamp |
| Policy bundle hash mismatch at startup | Fail-closed. Gateway does not start. | No | Not produced | `FATAL policy_hash_mismatch` + expected_hash + actual_hash |
| MCP protocol parse failure | Fail-closed on the specific call. Structured error returned. Session continues. | No | `status: parse_error` | `WARN parse_failure` + call_id + payload_hash |

---

## FM-1: Attestation Failure at Startup

**Trigger**: The TEE cannot produce a valid attestation report at gateway startup. Causes include: TPM not present or disabled in firmware, SEV-SNP or TDX not enabled on the host, firmware version not matching a known-good measurement, or the attestation service is unreachable.

**Decision**: Fail-closed. The gateway does not start. No MCP traffic is processed. No TRACE Claims are produced (there is no attested identity to sign with).

**Behavior**:
1. Gateway startup sequence attempts attestation as the first step, before binding any network port.
2. If attestation fails, the gateway writes a structured log entry and exits with a non-zero status code.
3. The orchestrator (Kubernetes, systemd, ECS) observes the non-zero exit and does not route traffic to the pod/service.

**Log entry format**:
```json
{
  "level": "FATAL",
  "event": "attestation_failure",
  "timestamp_utc": "2025-10-01T12:00:00.000Z",
  "tee_provider": "sev-snp",
  "error_code": "ATTESTATION_REPORT_UNAVAILABLE",
  "error_detail": "AMD PSP did not return a report within 5000ms",
  "gateway_version": "0.3.0",
  "action": "startup_aborted"
}
```

**Operator notification**: The orchestration platform health check fails (no process listening on the health port). Alerting on pod restart loops or task failure is the operator responsibility. The gateway does not attempt to send an outbound notification from a failed-attestation state, as there is no attested channel to send it on.

---

## FM-2: Attestation Staleness Mid-Session

**Trigger**: The attestation report has a validity period (typically 1-24 hours depending on provider). An active session is in progress when the attestation validity deadline passes.

**Decision**: Configurable. Default is fail-closed: terminate the session. The session max duration is bounded by the attestation validity period. A new session requires a fresh attestation report.

**Configurable option**: `attestation_staleness_policy: warn_only` allows sessions to continue past the validity deadline. This is not recommended for production. TRACE Claims produced after the deadline are marked `attestation_stale: true` to alert downstream verifiers.

**Behavior (default, fail-closed)**:
1. Gateway tracks the attestation validity deadline per session.
2. At the deadline, the gateway closes the session: sends a structured close notification to the agent, writes a log entry, and marks the session closed in the audit chain.
3. In-flight tool calls at the moment of termination are treated as FM-3 (TEE fault mid-invocation): fail-closed, structured error returned.
4. No new sessions are accepted until attestation is renewed (gateway restarts with a fresh report, or a re-attestation flow completes if supported by the provider).

**TRACE Claim field** (when `warn_only` is configured):
```json
"attestation_report": {
  "provider": "tpm",
  "measurement": "...",
  "report_data": "...",
  "attestation_stale": true,
  "validity_expired_utc": "2025-10-01T13:00:00.000Z"
}
```

**Log entry format**:
```json
{
  "level": "WARN",
  "event": "attestation_stale",
  "timestamp_utc": "2025-10-01T13:00:01.000Z",
  "session_id": "sess_01JABCDE",
  "expiry_utc": "2025-10-01T13:00:00.000Z",
  "staleness_policy": "fail_closed",
  "action": "session_terminated"
}
```

---

## FM-3: TEE Fault Mid-Invocation

**Trigger**: The TEE process (the gateway enclave context) crashes, becomes unresponsive, or returns an internal fault during an active tool call. This covers: enclave exception, out-of-memory inside the TEE, watchdog timeout, or unhandled panic in the gateway process.

**Decision**: Fail-closed on the in-flight call. The agent receives a structured error, not the tool response (which was never obtained or cannot be trusted). The audit chain records the fault. If the TEE recovers (e.g., the gateway process restarts and re-attests), subsequent calls in a new session may proceed.

**Behavior**:
1. In-flight call is abandoned. No tool response is forwarded to the agent.
2. A structured error is returned to the agent over the existing HTTP/SSE connection (if the connection is still alive). If the connection is also lost, the agent MCP client receives a connection error.
3. An audit chain entry is written for the failed call (see TRACE Claim structure below).
4. The gateway process exits if the TEE fault is unrecoverable. The orchestrator restarts it; a new attestation report is obtained on restart.

**Structured error returned to agent**:
```json
{
  "jsonrpc": "2.0",
  "id": "call-42",
  "error": {
    "code": -32099,
    "message": "Gateway internal fault",
    "data": {
      "call_id": "call-42",
      "fault_type": "tee_fault",
      "timestamp_utc": "2025-10-01T12:05:00.000Z",
      "trace_claim_available": false
    }
  }
}
```

**Audit chain entry for the failed call**:
```json
{
  "call_id": "call-42",
  "session_id": "sess_01JABCDE",
  "timestamp_utc": "2025-10-01T12:05:00.000Z",
  "tool_name": "database_query",
  "status": "fault",
  "fault_type": "tee_fault",
  "tool_response_logged": false,
  "note": "In-flight call abandoned due to TEE fault. No tool response was received or forwarded."
}
```

**Log entry format**:
```json
{
  "level": "ERROR",
  "event": "tee_fault",
  "timestamp_utc": "2025-10-01T12:05:00.000Z",
  "call_id": "call-42",
  "session_id": "sess_01JABCDE",
  "fault_detail": "Enclave watchdog timeout after 30000ms",
  "action": "call_abandoned_gateway_restarting"
}
```

---

## FM-4: Policy Bundle Hash Mismatch at Startup

**Trigger**: The gateway loads its Cedar policy bundle at startup and measures its hash. If the measured hash does not match the expected hash in the deployment manifest (set at deploy time, part of the TEE measurement or a separate signed manifest), the gateway refuses to start.

**Decision**: Fail-closed. Gateway does not start. This prevents a swapped or tampered policy bundle from being used. A silently different policy would undermine the governance guarantee: the TRACE Claim asserts a specific policy bundle hash, and if that hash is wrong, every claim produced would be a lie.

**Behavior**:
1. At startup, before binding any port, the gateway reads the policy bundle from disk and computes its SHA-256 hash.
2. The gateway compares the computed hash against the expected hash from the signed deployment manifest.
3. If they do not match, the gateway writes a log entry and exits with a non-zero status code.
4. No TRACE Claims are produced.

**Log entry format**:
```json
{
  "level": "FATAL",
  "event": "policy_hash_mismatch",
  "timestamp_utc": "2025-10-01T12:00:00.000Z",
  "expected_hash": "sha256:abc123...",
  "actual_hash": "sha256:def456...",
  "policy_bundle_path": "/etc/cmcp/policies/bundle.cedar",
  "action": "startup_aborted"
}
```

**Operator notification**: Same as FM-1. Orchestrator health check fails. The log entry provides the expected and actual hashes for forensic comparison.

**Note on deployment**: The expected hash must be set at deploy time and must be part of the TEE measurement or a signed manifest that the TEE verifies before trusting. If the expected hash itself can be tampered with, this check provides no protection. The deployment pipeline is responsible for ensuring the expected hash is authoritative.

---

## FM-5: MCP Protocol Parse Failure

**Trigger**: The gateway receives a message from the agent MCP client that is malformed JSON-RPC, uses an unsupported JSON-RPC version, violates the MCP protocol schema, or is crafted to exploit a parser (e.g., deeply nested structures, oversized payloads, binary data in a text field).

**Decision**: Fail-closed on the specific call. The session continues; only the failing call is rejected. A structured parse error is returned to the agent. The raw payload hash (not the content) is logged for forensics. The full payload is not logged to avoid storing attacker-controlled data.

**Behavior**:
1. Parser rejects the message before any tool lookup or policy evaluation.
2. Structured error is returned to the agent MCP client.
3. Log entry records the call_id (if parseable), session_id, error type, and a SHA-256 hash of the raw payload bytes.
4. The session remains open. Subsequent well-formed calls are processed normally.
5. Rate limiting: if a session sends more than N parse failures within a configurable window, the gateway closes the session (configurable threshold, default: 10 failures in 60 seconds).

**Structured error returned to agent**:
```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32700,
    "message": "Parse error",
    "data": {
      "fault_type": "mcp_parse_failure",
      "timestamp_utc": "2025-10-01T12:10:00.000Z"
    }
  }
}
```

**Log entry format**:
```json
{
  "level": "WARN",
  "event": "parse_failure",
  "timestamp_utc": "2025-10-01T12:10:00.000Z",
  "session_id": "sess_01JABCDE",
  "call_id": null,
  "parse_error": "invalid JSON: unexpected token at position 42",
  "payload_hash": "sha256:789abc...",
  "payload_size_bytes": 1024,
  "action": "call_rejected_session_continues"
}
```

---

## Failed-Call TRACE Claim JSON Structure

For calls that are rejected or faulted (FM-3, FM-5), the TRACE Claim records the failure without including the tool response. The claim is still signed by the TEE if the TEE is operational; for FM-3 (TEE fault), the claim may be unsigned if the signing key is unavailable.

```json
{
  "trace_version": "0.1",
  "session_id": "sess_01JABCDE",
  "timestamp_utc": "2025-10-01T12:05:00.000Z",
  "tee_public_key": "...",
  "attestation_report": {
    "provider": "sev-snp",
    "measurement": "...",
    "report_data": "...",
    "attestation_stale": false
  },
  "policy_bundle": {
    "hash": "sha256:abc123...",
    "enforcement_mode": "enforcing",
    "policy_version": "1.2.0"
  },
  "tool_catalog": {
    "hash": "sha256:def456..."
  },
  "call_summary": {
    "total": 1,
    "allowed": 0,
    "denied": 0,
    "faulted": 1,
    "tools_invoked": []
  },
  "failed_call": {
    "call_id": "call-42",
    "tool_name": "database_query",
    "status": "fault",
    "fault_type": "tee_fault",
    "timestamp_utc": "2025-10-01T12:05:00.000Z",
    "tool_response_logged": false,
    "policy_evaluated": false
  },
  "audit_chain_root": "...",
  "audit_chain_tip": "...",
  "signature": null,
  "signature_note": "TEE fault prevented signing. This claim is for audit record only and must not be treated as an attested proof."
}
```