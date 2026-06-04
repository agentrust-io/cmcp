# MCP Component Model and Trust Boundaries

Defines the full component model, trust levels per phase, and the hardware vs. software trust boundary.

Closes #43.

---

## Components

### Agent Host / AI Application

**Definition**: The container or process that hosts the agent and its MCP clients. Typically an enterprise application, a SaaS product, or a developer workstation running an AI assistant.

**Owned by**: Enterprise deployer or application vendor.

**Trust level**: Software-rooted. The agent host identity is established by TLS certificates or SPIFFE SVIDs provisioned at deploy time, not by hardware measurement. Its behavior is not isolated from the underlying OS.

**Responsibilities**:
- Provisions MCP client(s) with the gateway endpoint.
- Holds the SPIFFE SVID (issued by SPIRE, conditioned on gateway attestation -- see transport spec).
- Does not connect directly to any MCP server. All MCP traffic goes through the gateway.

---

### Agent (LLM + Control Loop)

**Definition**: The model inference process plus the orchestration logic (tool selection, chain-of-thought, re-prompting). The agent decides which tools to call and constructs the input payloads.

**Owned by**: Model provider (for hosted models) or enterprise (for self-hosted models).

**Trust level**: Untrusted from the gateway perspective. Tool choices and payloads are outputs of a probabilistic model, not deterministic code. The gateway assumes the agent may produce any tool call at any time, including calls that violate policy. The gateway enforces policy on every call regardless of agent intent.

**Note**: The agent being "untrusted" does not mean it is assumed to be malicious. It means the gateway does not rely on the agent good behavior as a security control.

---

### MCP Client

**Definition**: The in-process library, embedded in the agent host, that speaks JSON-RPC 2.0 over HTTP/SSE (or stdio, subject to transport limitations). One client instance connects to one endpoint.

**Owned by**: Agent host vendor or the open-source MCP SDK.

**Trust level**: Software-rooted. The client is a library in the agent host process; it has the same trust level as the agent host.

**Phase 1 configuration**: The MCP client is configured with a single endpoint -- the cMCP Gateway. It does not maintain connections to individual MCP servers. The gateway presents itself as a single MCP server to the client; internally it routes calls to the appropriate upstream MCP server.

---

### cMCP Gateway

**Definition**: The governance proxy. Every MCP tool call from the agent passes through the gateway. The gateway evaluates each call against a Cedar policy bundle, produces a TRACE Claim, and forwards allowed calls to the upstream MCP server.

**Owned by**: Enterprise deployer (Phase 1) or SaaS vendor (Phase 2, provider-side).

**Trust level**: Hardware-rooted. The gateway runs inside a TEE (TPM, SEV-SNP, TDX, or Opaque). Its identity is a SPIFFE SVID issued only after TEE attestation succeeds. Its signing key is sealed to the TEE and never exported. Its behavior is covered by the hardware measurement.

**Responsibilities**:
- Terminates mTLS connections from agent hosts (verifying SPIFFE SVIDs).
- Evaluates Cedar policies for every tool call.
- Produces signed, hardware-attested TRACE Claims.
- Maintains the append-only audit chain.
- Forwards allowed calls to upstream MCP servers over a separate internal connection.

---

### MCP Server

**Definition**: The process that wraps a backend system and exposes it as MCP tools. May be first-party (built and operated by the enterprise), third-party (SaaS vendor MCP server), or local (stdio on the user machine, Phase 1 unsupported).

**Owned by**: Varies.

**Trust level**:
- **Phase 1**: Software-rooted. The MCP server runs outside the TEE. Its responses are received by the gateway but are not hardware-attested. The gateway trusts that the server returns what it claims to return, but this is not verifiable beyond TLS.
- **Phase 2**: Hardware-rooted. The SaaS vendor runs the MCP server inside its own TEE. The gateway can verify the server attestation report before routing calls to it. Both ends of the call are hardware-attested.

---

### Backend Systems

**Definition**: Databases, REST APIs, filesystems, and other systems that the MCP server wraps. Not MCP-aware.

**Owned by**: Enterprise or SaaS vendor.

**Trust level**: Varies. Backend systems are outside the scope of the MCP governance model. Their access controls are independent of cMCP.

---

## Trust Boundary Diagrams

### Phase 1: Gateway Inside TEE

```
+-------------------------------------------------------------+
|  Agent Host (software-rooted)                               |
|                                                             |
|  +------------------+    +-----------------------------+   |
|  |  Agent           |    |  MCP Client                 |   |
|  |  (LLM + loop)    |--->|  (JSON-RPC 2.0 / HTTP+SSE) |   |
|  |  [untrusted]     |    |  [software-rooted]          |   |
|  +------------------+    +---------------+-------------+   |
|                                          | mTLS (SPIFFE)    |
+------------------------------------------+------------------+
                                           |
                          #================+=================#
                          #  TEE BOUNDARY (Phase 1)         #
                          #                                 #
                          #  +-----------------------+      #
                          #  |  cMCP Gateway         |      #
                          #  |  [hardware-rooted]    |      #
                          #  |                       |      #
                          #  |  Cedar policy engine  |      #
                          #  |  TRACE Claim signer   |      #
                          #  |  Audit chain          |      #
                          #  +-----------+-----------+      #
                          #              | TLS              #
                          #=============+===================#
                                         |
                          +--------------+------------------+
                          |  MCP Server (software-rooted)   |
                          |  [Phase 1: outside TEE]         |
                          +--------------+------------------+
                                         |
                          +--------------+------------------+
                          |  Backend System                 |
                          |  (DB, API, filesystem)          |
                          +---------------------------------+

Verification points:
  [A] Agent-side: SPIFFE SVID confirms gateway identity before sending any call
  [B] External auditor: verifies TRACE Claim signature against TEE public key
                        and checks attestation report against known-good measurement
```

### Phase 2: Server Also Inside TEE

```
+-------------------------------------------------------------+
|  Agent Host (software-rooted)                               |
|  MCP Client ---- mTLS (SPIFFE SVID) ---------------------- |
+----------------------------------------------+--------------+
                                               |
                      #========================+================#
                      #  TEE BOUNDARY -- Gateway               #
                      #  cMCP Gateway [hardware-rooted]        #
                      #========================+================#
                                               | mTLS (mutual SPIFFE SVIDs)
                      #========================+================#
                      #  TEE BOUNDARY -- Server                #
                      #  MCP Server   [hardware-rooted]        #
                      #========================+================#
                                               |
                      +------------------------+-----------------+
                      |  Backend System                         |
                      +-----------------------------------------+

Both ends of the call are hardware-attested.
The TRACE Claim can include the server attestation measurement.
```

---

## Hardware-Rooted vs. Software-Rooted per Component per Phase

| Component | Phase 1 | Phase 2 |
|-----------|---------|---------|
| Agent Host | Software-rooted | Software-rooted |
| Agent (LLM + loop) | Untrusted | Untrusted |
| MCP Client | Software-rooted | Software-rooted |
| cMCP Gateway | **Hardware-rooted** (inside TEE) | **Hardware-rooted** (inside TEE) |
| MCP Server (first-party) | Software-rooted | **Hardware-rooted** (inside TEE) |
| MCP Server (third-party SaaS) | Software-rooted | **Hardware-rooted** (vendor TEE) |
| MCP Server (local/stdio) | Out of scope | Out of scope |
| Backend Systems | Varies | Varies |

---

## Component Interaction Table

| Caller | Callee | Protocol | Authentication Method |
|--------|--------|----------|-----------------------|
| Agent | MCP Client | In-process API | N/A (same process) |
| MCP Client | cMCP Gateway | JSON-RPC 2.0 over HTTP/SSE | mTLS with SPIFFE SVID |
| cMCP Gateway | MCP Server | JSON-RPC 2.0 over HTTP/SSE | mTLS with TLS client cert (Phase 1); mTLS with SPIFFE SVID (Phase 2) |
| MCP Server | Backend System | REST, SQL, gRPC, or other | Backend-native credentials (API key, IAM role, DB password) |
| External Auditor | TRACE Claim | Offline verification | TEE public key (from attestation report); no live connection to gateway required |
| SPIRE | cMCP Gateway | SPIFFE workload API | TEE attestation (node attestation plugin) |

---

## Verification Points

**Agent-side verification**: Before routing any tool call, the agent MCP client verifies the gateway TLS certificate against the expected SPIFFE SVID. This confirms the agent is talking to an attested gateway, not an impersonator. The SPIFFE SVID is the agent-side trust anchor.

**External auditor verification**: The auditor receives TRACE Claims (out-of-band, from a log store or delivered by the enterprise). The auditor verifies:
1. The TRACE Claim signature against the TEE public key embedded in the claim.
2. The TEE public key against the attestation report (the key is bound to the TEE measurement).
3. The attestation report against the known-good measurement for the gateway version (obtained from the build pipeline or a public transparency log).
4. The policy bundle hash against the expected hash for the declared policy version.

This verification requires no live connection to the gateway. It can be done weeks or months after the fact, satisfying P3.1 (regulatory proof requests) and P3.2 (customer pre-renewal questionnaires).