# stdio Transport: the Gateway as Parent

---
Status: Implemented; design rationale retained below
Written: 2026-08-09
Supersedes: the original stdio exclusion in [transport.md](transport.md)
Implementation: `src/cmcp_runtime/mcp/stdio.py` and `mcp/proxy.py`
---

## Current behavior

The gateway starts a configured stdio server on first use within a session. A child is reused within that session by execution identity, and session close terminates it. An expected digest mismatch refuses the spawn; a missing digest requires explicit `allow_unmeasured_spawn`. In software-only mode this creates no enclave assurance.

Stderr content is kept out of the shareable audit chain but can reach gateway logs. Framing errors fail the session. The gateway process and child share their deployment isolation domain; a VM boundary does not isolate the gateway from its child.

## Cache identity

Spawned children are pooled per session by executable, arguments, measurement
target, and pinned digest—not by the server's human-readable display name.
Display names need not be unique and are not security identities. Provenance
verdicts additionally bind the configured record and publisher key.

## Why revisit a settled decision

[`transport.md`](transport.md) records that stdio is out of scope, and its reasoning is
sound as far as it goes:

> A subprocess cannot cross the TEE boundary: the agent process lives outside the enclave
> and cannot fork a child that executes inside isolated TEE memory.

It then evaluates two bridging options, both of which put a translating component *outside*
the enclave, and rejects both — correctly. An untrusted segment at the trust boundary can
inject or suppress tool calls before the gateway ever sees them, and the attestation report
does not cover it.

**Both options share an assumption that does not hold in this architecture: that the agent
spawns the MCP server.** That is how stdio works in a default MCP deployment. It is not how
anything works once cMCP is in the path. `transport.md` says so itself, in the agent
configuration section:

> The agent does not list individual MCP servers here. The runtime tool catalog is the
> authoritative list of available tools.

The agent already does not spawn, address, or reach servers. It reaches the gateway.

## The proposal

**The gateway spawns the stdio server, as its own child, inside the TEE.**

```
Agent  (outside)
  │  HTTP/SSE, unchanged
  ▼
cMCP Gateway  (inside TEE)
  ├── spawns MCP server as a child process, inside the same enclave
  └── speaks JSON-RPC 2.0 over the child's stdin/stdout
```

Nothing crosses the boundary that does not cross it today. The child is a child of a
process already inside the enclave, so it is inside the enclave: SEV-SNP and TDX isolate a
VM, and a process tree does not leave the VM by forking. The objection in `transport.md`
is about a process *outside* the enclave forking a child *inside* it, which is indeed
impossible and is not what this does.

### What this gets that HTTP/SSE does not

**The binary is measurable before it runs.** The gateway chooses when to exec, so it can
digest the executable and its arguments first and refuse to spawn on a mismatch. For an
HTTP upstream, the best available binding is a pinned TLS fingerprint, which identifies an
endpoint rather than the code behind it. This is a stronger claim than the one Phase 1
currently makes about any upstream, and it is the natural identity for the server
provenance record: a package digest the gateway verified rather than a URL it trusted.

**No network hop.** No TLS to pin, no MITM window, no `hash-only` evidence class for
upstreams that never got a certificate.

## What it costs, stated plainly

**A subprocess inside the enclave is a subprocess inside the enclave.** The MCP server's
code now runs in the same isolation domain as the policy evaluator and the audit chain. A
compromised server is inside the boundary, and the memory isolation that protects the
gateway from the host does not protect the gateway from its own child. This is a real
weakening relative to a network upstream, where the server is isolated by the network.

Mitigations, in order of how much they actually buy:

1. **Refuse to spawn what is not measured.** No digest match, no exec. This is the control
   that matters; everything else is depth.
2. Drop privileges and apply seccomp/landlock to the child before exec.
3. Separate enclave per server for high-sensitivity catalogs, at the cost of an internal
   network hop and much of the simplicity above.

**The measurement problem is real.** The gateway's own attestation is taken at startup and
covers the gateway image. A child spawned later is not in the launch measurement. The
honest position is that the child's digest is recorded in the audit chain and in the
GatewayClaim, sealed by the gateway's key, which makes it operator-evident and
hardware-rooted only to the extent that the gateway itself is. That is a weaker claim than
the launch measurement and must be reported as a distinct evidence class, not folded into
`hardware_attestation`.

## Evidence classes, extending the existing pair

`LIMITATIONS.md` records `tls-pinned` and `hash-only` for upstream responses. stdio adds:

| Class | Meaning |
|---|---|
| `spawn-measured` | The gateway digested the executable, matched it against the catalog, spawned it, and recorded the digest in the audit chain. The response came from that process. |
| `spawn-unmeasured` | The gateway spawned a child with no digest in the catalog to check against. Recorded, never silently treated as measured. Configuration should be able to refuse this. |

## Original design questions and current answers

1. **Lifecycle.** Implemented as children scoped to a session, reused by execution identity within it, and closed with that session. The original alternative was a pool across sessions. A pool is
   faster and leaks state between sessions, which is exactly the kind of cross-session
   contamination the audit chain cannot see. "Closed with that session" covers every way a
   session ends: an explicit `POST /sessions/{id}/close`, the gateway process exiting
   with a session still live during graceful shutdown, and `POST /sessions/{id}/reset`,
   which also retires a session id and opens a successor. Reset drains admitted calls
   and releases the same session-scoped resources before it records the boundary, so
   the successor never inherits a child, a pooled client, or a provenance entry from
   the session it replaced. If a child fails to close, the current session ID and
   audit boundary remain unchanged, admission stays sealed, and a retry closes the
   retained child before recording the reset.
   A call that arrives during a transition waits for it and is admitted to the
   successor, but that wait is bounded: a transition that has already failed is
   lifted only by a close retry or operator action, so a call waiting past the
   bound is answered with the reason rather than held on an open socket.
   Close blocks new calls,
   waits up to `CMCP_SESSION_CLOSE_DRAIN_SECONDS` (default 30 seconds), then
   requests cancellation and allows a further five seconds for calls to unwind.
   If calls remain, close fails with `SessionDrainIncomplete` and admission stays
   sealed; a retry must drain them before signing and rebinding. Partial claim
   failure also seals admission and requires operator investigation. Successful
   task completion alone does not prove audit completeness: a failed terminal
   audit write prevents signing, rotation, reset, and further call admission.
   Hydration failures and cancellations are included in terminal finalization.
   Shutdown can still release resources without signing an incomplete claim.
   Successful cleanup precedes rebinding; a child that fails to close is retained
   for retry. Pooled HTTP clients are closed on a best-effort basis instead: an
   `AsyncClient` marks itself closed and HTTPcore empties its pool before the
   underlying streams are released, so a failed close leaves connections no retry
   reaches through any public API. Such a client is dropped and the failure logged
   rather than sealing the session, because it is reuse by the successor, not the
   socket, that this lifecycle rule exists to prevent.
   Graceful shutdown permanently rejects new work and resource acquisition,
   drains active calls, and serializes spawning with cleanup. An incomplete
   drain, or a child that could not be closed, is reported as shutdown failure
   rather than success; a pooled client that could not be closed is logged and
   does not fail the shutdown, for the reason given above. Hard
   process termination cannot run this cleanup, and a shutdown that waits out an
   in-flight close can need twice the drain budget before cleanup begins, so a
   deployment's termination grace period has to exceed it or the cleanup is cut
   short by the kill. These drain deadlines do not
   bound arbitrary signing or transport cleanup time.
2. **stderr.** The implementation logs diagnostics through the gateway logger and records a byte count in evidence. MCP servers write diagnostics there. Capturing it into the audit chain risks
   payload leakage into an artifact meant to be shareable; discarding it loses the only
   signal when a child misbehaves.
3. **Framing.** Implemented as fail-closed newline-delimited JSON-RPC. A child that writes an unframed
   blob, or writes to stdout for logging, desynchronizes the stream. The reader must treat
   a parse failure as a fatal session error rather than resynchronizing, because
   resynchronizing means guessing which bytes were a response.
4. **Does this change the Phase 1 / Phase 2 line?** Phase 2 attests the server from inside
   its own TEE. A spawn-measured stdio child is a third position between "unattested
   network upstream" and "server attests itself", and the phase model does not currently
   have a place for it.

## Original recommendation

Adopt the gateway-as-parent model and retire both bridging options, which exist only to
serve an assumption this architecture already discarded. Implement behind configuration,
default off, with `spawn-measured` required and `spawn-unmeasured` refused unless
explicitly enabled.

The gateway-as-parent implementation now ships in the runtime. The proposed privilege and sandboxing mitigations above should not be read as a claim that all have been implemented.
