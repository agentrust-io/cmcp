# stdio Transport: the Gateway as Parent

---
Status: Proposal
Written: 2026-08-09
Supersedes: the stdio section of [transport.md](transport.md), if accepted
Stability: Unstable, no code written
---

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

## Open questions

1. **Lifecycle.** One child per session, or a pool reused across sessions? A pool is
   faster and leaks state between sessions, which is exactly the kind of cross-session
   contamination the audit chain cannot see.
2. **stderr.** MCP servers write diagnostics there. Capturing it into the audit chain risks
   payload leakage into an artifact meant to be shareable; discarding it loses the only
   signal when a child misbehaves.
3. **Framing.** MCP stdio uses newline-delimited JSON-RPC. A child that writes an unframed
   blob, or writes to stdout for logging, desynchronizes the stream. The reader must treat
   a parse failure as a fatal session error rather than resynchronizing, because
   resynchronizing means guessing which bytes were a response.
4. **Does this change the Phase 1 / Phase 2 line?** Phase 2 attests the server from inside
   its own TEE. A spawn-measured stdio child is a third position between "unattested
   network upstream" and "server attests itself", and the phase model does not currently
   have a place for it.

## Recommendation

Adopt the gateway-as-parent model and retire both bridging options, which exist only to
serve an assumption this architecture already discarded. Implement behind configuration,
default off, with `spawn-measured` required and `spawn-unmeasured` refused unless
explicitly enabled.

No code has been written against this proposal.
