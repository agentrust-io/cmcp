# Bounded comparison, as of September 27, 2026

Method: primary documentation and original research selected across process shutdown,
gateway shutdown, session withdrawal and behavioral off-switch research. Search terms
included MCP gateway kill switch revoke sessions, OpenShell sandbox stop/delete,
Off-Switch Game and AI Kill Switch for malicious agents. Five comparison sources
were read on September 19, 2026 and each was reopened on September 27, 2026. No
competitor runtime was executed and the search is not exhaustive.

| Source | Documented scope | Evidence level in this comparison | September 27 recheck |
|---|---|---|---|
| [NVIDIA OpenShell](https://docs.nvidia.com/openshell/how-it-works/sandboxes/overview) | Stop/start compute while retaining the persistent workspace, policies, provider attachments and settings; separate deletion lifecycle where "deletion accepted" means the gateway started deletion | Product documentation; no execution here | Statement still holds. The September 19 address (/openshell/dev/sandboxes/manage-sandboxes) now returns 404; the "Manage Sandboxes" page moved to the address linked here |
| [GitHub Agentic Workflows](https://github.github.com/gh-aw/reference/mcp-gateway/) | Section 5.1.3: reject new requests with HTTP 503, let in-flight requests complete within a timeout, SIGTERM then SIGKILL for server containers | Draft specification, version 1.17.0; no execution here | Statement still holds; version now cited |
| [Microsoft AGT](https://microsoft.github.io/agent-governance-toolkit/specs/MCP-SECURITY-GATEWAY-1.0/) | Section 8.4 Session Lifecycle: revoke_session and revoke_all_sessions(agent_id), marked Pure Specification | Draft specification, version 1.0 dated 2025-07-28; the author created and has contributed to this project | Statement still holds; draft status and date now cited |
| [Off-Switch Game](https://arxiv.org/abs/1611.08219) | Incentives to preserve human shutdown authority | Original research, abstract reviewed | Title and four authors unchanged |
| [KILLBENCH](https://arxiv.org/abs/2511.13725v5) | External prompt-style interruption of malicious web agents without access to internal parameters | Original research, v5 abstract reviewed; no benchmark rerun | v5 (September 12, 2026) is still the latest revision |

KILLBENCH's current title is Can We Stop Malicious AI? KILLBENCH: A Benchmark for
External AI Kill Switch Feasibility (Lee, Kim and Park, revision September 12, 2026).
An initial search returned an older title and abstract. The paper uses the current
record rather than copying that stale description, and cites the pinned v5 URL.

Decision: no priority, uniqueness or superiority language. The sample already shows
several shutdown and control approaches. No claim is made that a capability is
absent from another project merely because the selected page does not describe it.
Our supportable contribution is the observed cMCP behavior, its signed refusal
relationships and executable counterexamples to stronger shutdown interpretations.
