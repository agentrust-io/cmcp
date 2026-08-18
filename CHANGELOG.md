# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **TDX read both of the fields it attests from the wrong offsets, and enforced neither (#371).** `REPORTDATA` was read at `0x08`, inside REPORTMACSTRUCT's leading RESERVED block, and a mismatch was advisory: the binding between the report and the confirmation key was neither checked in the right place nor enforced where it was checked. `MRTD` was read at `0x90`, which is inside `REPORTMACSTRUCT.report_data`, the 64 bytes the guest itself supplies. The producer wrote the nonce there and then hashed 48 bytes of it back out as the "TD measurement", so two attestations of the same TD with different nonces produced different measurements. A measurement that moves with the nonce is not a measurement.

  Both offsets now come from `cmcp_runtime.tee.tdreport`, one ctypes definition of TDREPORT_STRUCT imported by the producer and the verifier, with the ABI offsets asserted at import: `REPORTDATA` at `0x80`, `MRTD` at `0x210`. Producer and verifier having their own copies is how two wrong offsets agreed with each other for this long. A `report_data` mismatch is now fatal on TDX, matching the SEV-SNP rule from #390.

- **A TDX claim could be reported as fully `verified` with the quote signature unverified (#370).** `LIMITATIONS.md` already said a claim whose report signature or chain is unverified stays `partially_verified` and is never presented as hardware-backed. That was true of SEV-SNP, which #390 gated on the VCEK chain, and not of TDX, where a TDREPORT alone was enough. A TDREPORT is an unsigned buffer the host could have written. TDX is now gated on `dcap_quote_signature` exactly as SNP is gated on `vcek_cert_chain`, so the documentation and the code agree.

- **`initialize` answered every handshake with a revision that has no `initialize` (#509).** Third on the to-do list in #496 was "stop hardcoding the downstream protocol version", and #509 did it by replacing the hardcoded `2024-11-05` in the `initialize` result with `PROTOCOL_VERSION`. That constant is `2026-07-28`: the revision that **removed** the handshake. So the gateway answered every `initialize` by naming a protocol in which the request just made does not exist, and in which each later request must carry `_meta` plus the mirrored `MCP-Protocol-Version` / `Mcp-Method` headers a handshake-era client has no way to know it should send. Confirmed against every revision a real client offers: asked `2025-06-18`, `2025-03-26` or `2024-11-05`, the gateway answered `2026-07-28` in all three cases.

  The direction of the swap is the whole defect. `PROTOCOL_VERSION` is correct on the **outbound** leg, where the gateway is the client and #509 got it right; it is wrong on the **inbound** one, where reaching `initialize` at all is proof the caller is handshake-era. `initialize` now negotiates over `_LEGACY_PROTOCOL_VERSIONS` only, echoing the client's request when the gateway speaks it and otherwise answering with the newest handshake-era revision. A client that asks for `2026-07-28` at a handshake is deliberately not humoured: it cannot be speaking a revision with no handshake, so confirming it would agree on a protocol neither side is using. `server.py` no longer imports `PROTOCOL_VERSION`; #509 introduced that import solely for this misuse.

  That set now leads with **`2025-11-25`**, the newest revision that still defines `initialize`. It had been omitted, so a client offering the latest handshake revision was answered `2025-06-18` instead. The lifecycle spec requires a server to echo a version it supports and says a client that does not support the server's answer SHOULD disconnect, which makes a needless downgrade the same class of defect as the one above, one revision over.

  Non-object `initialize` params are now rejected with `-32600` rather than treated as an empty object. `InitializeRequestParams` is an object with required members, so answering a malformed handshake with a successful negotiation blessed a validation gap. This matches how #500 already rejects non-object `tools/call` params. Absent `params` remains legal and negotiates the newest revision.

  `tests/unit/test_initialize_protocol_version.py` pins the negotiation and asserts the outbound constant is untouched. Verified by mutation: reverting only the `initialize` line while keeping the new constant fails 9 of its 10 tests.

### Security

- The MCP ingress now rejects non-object JSON-RPC messages, non-string methods, and non-object `tools/call` parameters with a bounded `MCP_INVALID_REQUEST` response. Structurally invalid attacker input no longer reaches attribute errors, HTTP 500 responses, or exception trace logging.
- The unauthenticated health/readiness rate limiter now expires inactive source-address entries and caps tracked clients at 10,000. Source-address churn can no longer grow the in-memory limiter map for the lifetime of the gateway.
- Upstream stdio children and provenance verdicts are now cached by complete execution and trust identity rather than the non-unique human-readable `display_name`. Distinct catalog servers sharing a label can no longer reuse another server's process or provenance result.
- Built wheels now include the catalog-entry JSON Schema, and catalog loading fails closed if that schema is absent or unreadable. Previously source-tree tests validated catalog structure, but installed wheels omitted the schema and silently skipped that validation.
- PyPI publication now installs and smoke-tests the exact wheel and source distribution before upload, including release-tag/version agreement, import provenance, runtime configuration, and the packaged CLI.
- The runtime container now uses a patch-pinned Python slim base, builds a non-editable production wheelhouse in a separate stage, excludes development dependencies and build tooling from the final image, and runs as an unprivileged numeric UID/GID.

### Changed

- **`STATUS.md` understated the attestation default in two ways.** It gave the probe order as `tpm -> sev-snp -> tdx`, missing `azure-cvm`, which is probed *first* and exists precisely so an Azure confidential VM is not mistaken for a plain TPM host. And it said nothing about what happens when no hardware is found, which is the question an evaluator is actually asking.

  The answer is better than the omission implied and is now stated: **auto never degrades to software.** With no hardware detected the gateway refuses to start unless `CMCP_DEV_MODE=1`, and `provider: software-only` requires that flag as well, so a software-mode gateway is always a deployment that asked for one rather than a silent downgrade. `tests/unit/test_tee.py` pins both, including that setting `CMCP_DEV_MODE` in the environment *after* config load does not bypass it.

  Documentation only. No behaviour changed; the behaviour was already correct and the defaults table was selling it short.

### Added

- **Configurable sensitivity vocabulary (#479).** The six built in sensitivity labels (`public`, `pii`, `confidential`, `hipaa_phi`, `mnpi`, `trade_secret`) were the only ones a catalog entry could ever declare, so a regulated deployment whose own scheme names a tier above `trade_secret`, an Open/Confidential/Secret/Top Secret ladder for example, had no way to catalogue it truthfully.

  `sensitivity.vocabulary` in config now lets a deployment add new labels at any rank. It is additive only and enforced at two layers: config parsing rejects a vocabulary key that names a built in label outright, and `session/state.py`'s `effective_sensitivity_order()` merges the built in table in last regardless, so a built in name can never be shadowed even by a bug elsewhere in the chain. That guarantee is not cosmetic: response inspection's content pattern detectors emit the built in tags `pii` and `hipaa_phi` directly when they spot an SSN, an email, a diagnosis code and so on, and if either name had silently dropped out of the effective vocabulary those detections would have ranked at 0, the same fail open hole #478 closed for the catalog schema.

  `SessionManager` and `PolicyEvaluator` each derive the effective vocabulary once from the same `Config`, so a session's `max_sensitivity` string and the `sensitivity_level` integer Cedar evaluates can never disagree about what a custom label ranks as. The catalog schema's `sensitivity_level` enum moved from the static JSON schema into a Python level check at load time against this same effective set, so the vocabulary stays closed, just not hardcoded.

  Per call classification, letting a single call declare a class narrower than its tool's catalogued default, is the second half of #479 and is left for a follow up change.

- **Per call sensitivity classification (#479).** One catalogued tool can serve many classes of data, a model call tool catalogued at `pii` might, on a specific call, actually carry `confidential` data (agentrust-io/demos#36 is the motivating example). The signed transcript could only ever show the tool's single catalogued value, and the session's own sensitivity tracking never rose past what the catalog alone said either, an enforcement gap for later calls in the session, not only a record keeping one.

  A call may now declare a class for itself via `_cmcp.data_class` on the request. It composes with the vocabulary work above: a deployment adds a label in config, a call declares it per call. The declared value needs no separate validation, `_max_sensitivity` already is the validator: it returns whichever of two labels ranks higher and ties favour the catalog value, so an unrecognised or lower declared value is harmless by construction, and a legitimately higher one raises both the session's `max_sensitivity` and, independently, that specific call's own row in the signed transcript, without inheriting whatever the session had already accumulated from earlier calls.

  `AuditEntry` gained one new field, `effective_data_class`, `None` on every call that never declares one, so nothing changes for a caller that does not use `_cmcp.data_class`.

- **Server provenance checking (step 3).** The gateway consumes [`server-provenance-v1`](https://github.com/agentrust-io/trace-spec/blob/main/spec/server-provenance-v1.md) records via `agentrust-trace>=0.8`: it verifies the record against a **configured** publisher key, then compares the record's tool-catalog hash against the tools the server advertises to this gateway.

  It never falls back to the catalog's own approved definitions for that comparison. Comparing a record against our approval instead of against the server is the substitution that turns the whole check into theatre.

  Five outcomes reach the audit chain and none is silent. `verified`; `catalog-mismatch`, which means the document is fine and the *server* is not; `invalid`; `unchecked`, which means the record verified but the tool list was unavailable so the comparison that catches a substituted server never ran; and `absent`. `unchecked` exists because reporting a signature check alone as `verified` is a document checking itself.

  **Absence is recorded and non-fatal by default.** Almost no MCP server has a record, and a gateway that refuses to route without one is a gateway that gets turned off on first contact and never turned back on. `attestation.required_provenance_kind` sets a floor per deployment; a `catalog-mismatch` satisfies no floor, including the weakest.

  A record with no configured publisher key is `invalid`, not `verified`: the key embedded in a record cannot be used to check that record, because a forgery supplies its own.

### Added

- **stdio transport: the gateway spawns the MCP server as its own child, inside the enclave (#484).** `docs/spec/transport.md` ruled stdio out and rejected two bridging options, correctly, because both put a translating component *outside* the TEE where it can inject or suppress calls before the gateway sees them. Both options assumed the agent spawns the server. It does not: that same document states the agent reaches only the gateway and that the runtime catalog is authoritative. So the child is a child of a process already inside the enclave, and nothing crosses the boundary that does not cross it today.

  **This buys a binding no network upstream can have.** The gateway chooses when to `exec`, so it digests the entrypoint first and refuses to spawn on a mismatch. A pinned TLS fingerprint identifies an endpoint; a verified digest identifies code.

  **And it costs something, which is in the spec rather than the footnotes.** The server then runs in the same isolation domain as the policy evaluator and the audit chain, and the gateway's launch measurement does not cover a process spawned later. The child's digest is therefore reported as its own evidence class, `spawn-measured` or `spawn-unmeasured`, never folded into `hardware_attestation`.

  Defaults: `attestation.allow_unmeasured_spawn` is `false`, so a server the catalog does not pin is not spawned at all. Turning it on does not make the spawn silent; every such call is recorded as `spawn-unmeasured`.

  Two design corrections came out of writing the tests. **Pinning the executable is nearly useless for an interpreted server** — the executable is the interpreter, so every Python MCP server on a host shares one digest and the pin would match a completely different server; `measure_target` pins the entrypoint instead. And **executable and readable are different properties**: a Windows Store Python is an App Execution Alias that runs fine and cannot be opened for reading, so an unmeasurable target is a refusal with an explanation rather than a crash.

  Framing errors are fatal by design. A child that logs to stdout has desynchronized the JSON-RPC stream, and skipping to the next parsable line means guessing which bytes answered which call; a response whose id does not match its request is fatal for the same reason. stderr never enters the audit chain, because diagnostics carry payloads and the chain is meant to be shareable: content goes to the logger, only the byte count is exposed.

  The catalog schema conditions its requirements on transport rather than relaxing them, so a network transport still requires `url` and `tls_fingerprint` while stdio requires `spawn`.

### Fixed

- **The AIA chain walk for a TPM attestation key had no margin above the one depth it was measured against (#514).** `TPMProvider._chain_from_leaf` stops walking the certificate chain at `_AIA_MAX_DEPTH`, and that constant was `4`, exactly the length of the one real Azure hierarchy measured so far: leaf, Azure Cloud Virtual TPM CA - 11, Azure Cloud Virtual TPM CA 2025, root. Split out of #453, whose own investigation found a second real hierarchy, `Global Virtual TPM CA - 03`, that reaches the same root in only 3 certificates. Two different depths already exist on real fleet hardware, so a cap sized to match one of them exactly leaves zero room for a future or differently configured hierarchy that needs one more hop: the walk would stop one certificate short of the root, and the resulting chain would ship without it.

  Not a loop logic bug: the walk correctly builds any chain up to the cap, including one where the root arrives on the last allowed certificate. The cap is now `6`, two hops above the deeper of the two known depths rather than matching either exactly, and the walk logs a warning when it stops without reaching a self signed root, so a future truncation is visible in the logs immediately rather than only surfacing later as a chain verification failure that looks identical to a chain that legitimately reaches an untrusted root.

## [0.4.0] - 2026-08-08

**Anyone running 0.3.0 should upgrade.** On 0.3.0 a forged TPM quote was reported as hardware-attested: the `tpm2` branch of `verify_trace_claim` called only `verify_tpm_measurement`, which takes no signature parameter, so a `TPMS_ATTEST` with the correct magic and matching `qualifying_data` passed with no signature and no certificate chain (#370). The authenticated path existed and was tested; nothing in production called it. This release makes the quote signature and the AK certificate chain the gate on `hardware_attestation`, so evidence that does not chain to a pinned root can no longer report as verified.

### Changed

- **BREAKING for verifiers: claims now carry `gateway.attestation_evidence` (#469, #370).** Signed platform
  evidence (`raw_evidence`, `quote_signature`, `cert_chain`, `ek_cert_chain`) travels inside the claim so the
  verifier has something to check the TPM quote against. It could not live under `trace.runtime`, because
  agentrust-trace's `RuntimeInfo` is `extra="forbid"` and rejected the claim as `CLAIM_MALFORMED` before the
  platform branch ran, which is precisely what kept the chain verifiers unreachable.

  The break is one-directional, and only for verifiers:

  | | result |
  |---|---|
  | this verifier reading an older claim with no evidence | fine, the fields are optional and `trace.runtime` is still read as a fallback |
  | a verifier older than 0.4.0 reading a claim from this gateway | `CLAIM_MALFORMED` on `gateway.attestation_evidence` |

  `GatewayAddenda` and `RuntimeClaim` are both `extra="forbid"`, so any additive field anywhere in the claim is
  rejected by a verifier built before it, and `verify_trace_claim` never reads `cmcp_version`. There is no
  negotiation path, so "evidence travels with the claim" and "older verifiers keep working" cannot both hold.
  Evidence transport won, since without it the TPM quote is unauthenticated. Anyone verifying claims from a
  0.4.0 gateway must upgrade `cmcp-runtime` to 0.4.0, which is what ships `cmcp_verify`. Claims with no
  evidence serialize byte-identically to 0.3.0, so software-only deployments are unaffected.

  Minor rather than patch under SemVer: the wire format gained a field that older readers reject.

### Security

Five changes below the headline TPM fix, each one a case where cMCP reported more assurance than it held. Collected here rather than scattered through Fixed, because an operator deciding whether to upgrade should be able to read them in one place.

- **Tokenless development mode may now only bind a loopback address.** `CMCP_DEV_MODE=1` skips the bearer-token requirement, and the default `listen_addr` is `0.0.0.0:8443`, so the documented quickstart stood up an unauthenticated gateway on every interface of the host. Configuration is now refused unless the bind is loopback or `CMCP_BEARER_TOKEN` is set. The default bind is unchanged; what changed is that the unsafe combination no longer starts.

- **A claim is no longer issued when the per-session TEE attestation call fails (#426).** `close_session` fell back to the shared startup report and signed a claim anyway. That report carries no chain-root commitment, so a strict verifier rejects it, but the runtime handed it out as if nothing were wrong. On a hardware platform this now raises `TeeFault` instead of issuing an unbound claim. Software-only dev mode keeps the previous fallback, where the binding was already best-effort.

- **Unsigned PCR reads were labelled hardware-attested (#441).** A PCR read carries no signature and nothing binds it to a TPM, but the provider still reported `provider=tpm` when the quote failed, and the subprocess path never produces a quote at all. Both cases now downgrade to software-only with the note `tpm-pcr-read-unsigned`. Related: a PCR hex-parsing defect that corrupted the measurement itself (#437).

- **SNP `report_data` mismatch is now fatal (#371, #390),** since that field carries the confirmation-key binding and the freshness nonce, and the dispatcher no longer reports `hardware_attestation` as verified while the VCEK chain is unverified (#370, #372); such a claim stays `PARTIALLY_VERIFIED`. Same defect class as the TPM headline, on the AMD path, fixed first.

- **TCG event logs are replayed against the reported PCR values (#443)**, so a log that does not reproduce the quoted digests is detected rather than trusted as narrative.
- **`gateway.agent_identity.agent_key_thumbprint` scaffold (#425).** SAGE (via l33tdawg, agentrust-io/.github discussion #15) wanted an offline check that a downstream signature came from the agent a TRACE Claim describes. Investigating turned up that the issue's own premise did not hold: `AgentManifestBinding` carries no agent public key anywhere, and `subject_source` is a static config value today, not a live-authenticated credential (`svid` is a valid value but nothing produces it). So there was no key material anywhere in the runtime to hash.

  Landed as a nullable, additive field instead: `agent_key_thumbprint` (RFC 7638 JWK thumbprint, `sha256:<hex>`) on `AgentIdentityInfo`/`AgentIdentityOut`, always `None` today since no code path supplies agent key bytes. The real, non-speculative piece is on the verifier side: `cmcp_verify.verify_trace_claim` now fails closed (`AGENT_KEY_THUMBPRINT_UNBOUND_SUBJECT`) on any claim that carries the field while `subject_source` is not live-authenticated, so a future producer cannot launder a config-supplied identity into something that looks like a hardware-attested key binding.

  Populating the field for real needs either an `agent_manifest_sdk` schema change carrying the agent's public key, or a live mTLS/challenge-response credential wired into `AgentManifestBinding` - both explicitly out of scope here, tracked in the issue thread.

### Fixed

- **`TPM2_NV_Certify` could never have worked as shipped in #459 (hardware, 2026-08-01).** Two defects, both found by running it against a real Azure Trusted Launch vTPM and neither catchable by the unit tests as written:

  1. `ESAPI.nv_certify` takes `in_scheme` (a `TPMT_SIG_SCHEME`) and `size` as **required positional** arguments. The shipped call omitted both, so it raised `TypeError` before the TPM was ever reached. The fake in the unit tests accepted any signature, so the tests passed against code that could not run.
  2. A freshly defined `TPM_NT_EXTEND` index is **uninitialised**, and `TPM2_NV_Certify` on it fails with `TPM_RC_NV_UNINITIALIZED`. On a first gateway start there was therefore no pre-value to certify. Fixed by seeding the index once at provision time, which keeps the verifier's `post == H(pre || digest)` check free of a first-boot special case.

  The fake now enforces both constraints, so each defect has a regression test that fails without its fix (verified by mutation).

  What the run then established: the platform AK at `0x81000003` **can** sign an NV certify, which was an open question for a restricted signing key; `parse_nv_certify`'s field offsets are correct against a real blob, which was the highest-risk item since they came from the TCG spec and had never met real bytes; the extend relation holds across two consecutive starts with run 2's `pre` equal to run 1's `post`; and `verify_gateway_measurement` passes all seven steps while rejecting a wrong digest and a replayed nonce on genuine evidence. The chain was anchored on the leaf because that host presented the no-AIA hierarchy, so key provenance remains unproven on Azure (#453).

### Added

- **The gateway measurement is now signed evidence (#432, second half).** The NV index value previously travelled as an ordinary NV read that no signature covers, so it was a local integrity control: a compromised gateway could report any value. `certify_and_extend_gateway_measurement` now certifies the index, extends it, and certifies again, giving two TPM-signed values. `cmcp_verify.nv_certify.verify_gateway_measurement` appraises the pair, checking `post == H(pre || expected_gateway_digest)` with nothing collector-asserted and no verifier-side state.

  Two certifies rather than one because `TPM2_NV_Certify` signs only the index's *current* value and cannot attest to a previous one, while extends accumulate across reboots so there is no absolute value a verifier could expect. The two calls commit different qualifying data (`pre` / `post`) so each blob's role is signed rather than inferred from position. The shortcut that looks equivalent and is not: reading the index and committing the result into a quote's qualifying data means the collector asserts the value it read, and a compromised gateway is the adversary.

  Only the platform attestation key certifies. A transient key would produce a verifiable signature with no provenance, which is worse than an honest absence because it looks like evidence, so a platform without a certified key falls back to the unsigned extend and ships no evidence at all. `TPMProvider.platform_attestation_key` exposes that distinction explicitly instead of leaving callers to read a transient-key side channel.

  `agent_manifest.verify_tpm_quote` cannot appraise an NV certify: it rejects any attest type that is not `TPM_ST_ATTEST_QUOTE`, and its parser assumes a `TPML_PCR_SELECTION` union. The certificate chain is still delegated to `agent_manifest.verify_cert_chain`; only the `TPM_ST_ATTEST_NV` and `TPMT_SIGNATURE` wire formats are local, tracked upstream as agentrust-io/agent-manifest#255.

### Changed

- **Startup generates the signing key before measuring the gateway.** The measurement's certify calls commit the attestation nonce, which is derived from that key, so the key now comes first. It has no dependencies of its own, so this is ordering only and not a behaviour change. The documented sequence in `run_startup` is updated: detect provider, signing key and nonce, measure and certify, produce the report.
- `mypy src` is clean for the first time. The five pre-existing errors in `cmcp_verify/tpm.py` were a `type[HashAlgorithm]` inference that made `hash_cls()` read as instantiating the abstract base; typing the lookup as a factory fixes it, and `padding.PSS.DIGEST_LENGTH` replaces `hash_cls.digest_size` for the same salt length with a correct type.

### Fixed

- **The Azure vTPM certificate hierarchy is fleet variance, not a migration (hardware, 2026-08-01).** `docs/testing/hardware-validation.md` recorded on 2026-07-31 that "Azure has changed its vTPM PKI", after finding the AK certificate at NV `0x01C101D0` issued by `Azure Cloud Virtual TPM CA - 11` with a walkable AIA chain, superseding an earlier no-AIA observation. A VM provisioned 2026-08-01 (`Standard_D2s_v7`, eastus2) presented the older form again: 994 bytes, issued by `Global Virtual TPM CA - 03`, **no AIA extension at all**, and `tpm2_getcap handles-nv-index` confirmed no intermediates stored in NV as a fallback. Both hierarchies are live concurrently, so the planning assumption must be that a host may present either and **AIA cannot be relied on**. The practical consequence, now stated in the doc and in `cmcp_verify/tpm_roots.py`: pinning the 2023 root does not make Azure verify everywhere, and chained verification is impossible on a host presenting the no-AIA hierarchy. This is worth re-reading against #431, which was closed on the basis that chains ship with the evidence.

### Added

- **Hardware validation for the gateway measurement NV extend index (#432, #451).** The TPM calls in `cmcp_runtime.tee.measurement` were written against the documented tpm2-pytss API without ever executing against a TPM. All of them work on a real Azure Trusted Launch vTPM: `nv_define_space` with `TPMA_NV.parse(...) | (TPM2_NT.EXTEND << 4)` created a genuine extend index (`TPM_NT = 4` read back from the public area), `nv_extend` accumulated as `H(old || data)` across calls, an existing index was reused rather than redefined, and **a plain `nv_write` to the index was refused by the TPM**, which is the check the tamper-evidence argument actually rests on. Recorded in `docs/testing/hardware-validation.md`.

- **The gateway is now measured into a TPM NV extend index at startup (#432).** PCRs 0 through 7 cover firmware, option ROMs, boot configuration, and the bootloader, and there was no `PCR_Extend` anywhere in the codebase, so replacing the policy bundle or the gateway itself produced an identical measurement and the TPM enforced nothing about the thing the TPM path exists to protect. `cmcp_runtime.tee.measurement` digests the installed distributions' recorded per-file hashes (pip's `RECORD`), the policy bundle bytes, and the resolved configuration with secrets excluded, then extends that digest into NV `0x01500432` before the gateway serves traffic. `RuntimeContext` carries the result.

  An NV index with `TPM_NT_EXTEND` rather than an application PCR, per the decision on #432: PCR 23 and PCR 16 are both resettable from locality 0, so an adversary with local code execution could reset and re-extend a chosen value, which is exactly the adversary this tier addresses. Extend writes are one-way (`new = H(old || data)`), so forgery needs a preimage, which is what carries the security argument rather than the write policy the original proposal called for.

  Scope is deliberately honest about two things. Measuring dependencies means an editable install, which has no `RECORD`, cannot be measured: that is fatal in production and a warning under `CMCP_DEV_MODE`, rather than a confident digest over an unknown subset of code. And because extends accumulate across reboots, the index is a hash chain over every start rather than a predictable absolute value, so the collector reports the value both before and after the extend and continuity is what a relying party checks.

### Changed

- **RFC section 5 P2 (`docs/spec/tpm-security-model.md`) rewritten** to record the NV-extend decision instead of leading with the application PCR it rejected, along with the residual-risk analysis: `TPM2_NV_UndefineSpace` with owner auth can erase the measurement, which guest root holds on Azure, so the property is tamper-evident rather than tamper-proof. Section 4.3 now separates what landed from what has not: the index value travels as an ordinary NV read, which the quote signature does not cover, so it is a local integrity control and not yet remote-verifiable evidence. `TPM2_NV_Certify` is the primitive that closes it; committing an NV read into the quote's qualifying data is not sound, because the collector would be asserting the value it read.

### Changed

- **BREAKING: TRACE Claims now carry the v0.2 profile** `tag:agentrust-io.com,2026:trace-v0.2`, and `agentrust-trace` is pinned to `>=0.5`. The v0.1 URI named `agentrust.io`, a domain this project never controlled, which RFC 4151 does not permit for a tag URI (agentrust-io/trace-spec#107). A verifier on the v0.2 suite rejects a v0.1 claim, so producers and verifiers move together. Nothing else about the claim format changed.

### Changed

- Moved every `agentrust.io` identifier to `agentrust-io.com`: the JSON Schema `$id` values for `trace-claim`, `audit-entry`, and `catalog-entry`, the `@context` URL in test fixtures, and the maintainer email. `agentrust.io` is not ours and resolves to parked AWS addresses, so these identifiers pointed at a domain we do not control. They never resolved, so nothing that worked stops working. The `tag:agentrust-io.com,2026:trace-v0.2` EAT profile identifier is deliberately unchanged; it is a cross-repo identifier inside signed payloads and needs a transition decision, not a rename.

### Fixed

- README no longer claims hardware attestation unconditionally. "Each session produces a signed, hardware-attested TRACE Claim" contradicted the TL;DR two paragraphs below it, which tells you to `pip install cmcp-runtime` and start in software mode with no hardware. It now reads "hardware-attested when the gateway runs in a TEE and signed-only in software mode", which is what the runtime actually does.

### Fixed

- Raised the `agent-manifest` floor to `>=0.6.1` and made an unappraisable manifest fail closed with a diagnostic message. `verify_agent_manifest_binding` runs the SDK verifier over a peer-supplied manifest, and before 0.6.1 a manifest declaring `ML-DSA-65` or `hybrid-Ed25519-ML-DSA-65` crashed the SDK with an uncaught `RuntimeError` on any install without the optional `[pq]` extra, so this path answered a crash instead of a rejection. The SDK now returns `UNVERIFIABLE`, which cMCP already rejects; the `UNVERIFIABLE` message now distinguishes "could not be verified" (missing trusted key or unavailable algorithm) from "verification failed" (a bad signature) and surfaces the verifier's own reason, because those call for different operator responses.
- **The TDX verifier rejected every genuine DCAP v4 quote.** Real quotes nest the Quoting Enclave material: the bytes after the attestation key are a certification-data header of type 6 (`QE_REPORT_CERTIFICATION_DATA`) wrapping the QE report, its PCK signature, the auth data and the type-5 PCK chain. `parse_td_quote` read the QE report directly after the attestation key, six bytes early, so a real GCP C3 quote failed with `attestation_key_not_bound_to_qe`. The synthetic test fixture emitted the same flat layout, so CI validated the defect. Failure was closed, so this was a false negative rather than an unsound accept, but the TDX path had never worked against real evidence. The parser now handles the nested layout, the fixture builds the real shape, and a new test rejects the flat layout outright.

### Added

- **Real-hardware validation for SEV-SNP and TDX**, recorded in [`docs/testing/hardware-validation.md`](docs/testing/hardware-validation.md). `cmcp_verify` now verifies a genuine Azure CVM SEV-SNP report (VCEK chain to the AMD ARK-Milan root, ECDSA-P384 report signature, paravisor `REPORT_DATA` binding) and a genuine GCP C3 Intel TDX DCAP v4 quote (PCK chain to the pinned Intel SGX Root CA, QE binding, quote signature) end to end. Both are env-gated (`CMCP_AZURE_FIXTURE_DIR`, `CMCP_TDX_FIXTURE_DIR`) because the evidence embeds per-CPU identifiers and cannot be committed. `test_real_tdx_quote_agrees_with_agent_manifest` pins cMCP's verdict to the shared verifier so the two cannot drift apart silently. STATUS and ROADMAP now say which platforms have been validated against real evidence and which have not (TPM has not).

### Changed

- Attestation crypto now delegates to agent-manifest's shared verification library (`agent-manifest>=0.5`) instead of cMCP's own copies: the SEV-SNP report signature (`verify_snp_signature`) and the VCEK/PCK certificate-chain verification (the generic `verify_cert_chain`) are shared across the org rather than duplicated. cMCP keeps its own DCAP quote parser, `*VerificationResult` shapes, TR-field semantics, and report_data/qualifying-data bindings; behavior is unchanged (all tests pass unchanged). cMCP's TPM verifier stays local (Phase-1 parse-only: no AK signature/chain to share).

### Added

- Azure confidential-VM attestation (`cmcp_runtime.tee.azure_cvm.AzureCVMProvider` + `cmcp_verify.azure_cvm`), **hardware-validated on live Azure SEV-SNP silicon**. Azure runs SNP behind a Hyper-V paravisor with no `/dev/sev-guest`; the SNP report is read from the vTPM NV index `0x01400001` and the guest cannot control `REPORT_DATA` (the paravisor binds the vTPM AK there). cMCP's nonce (`jwk_thumbprint || audit-root`) is therefore committed into an AK-signed TPM quote's qualifying data, with the AK rooted in silicon via the SNP report (`REPORT_DATA == sha256(runtime_data)`) and the VCEK→ASK→ARK chain (reusing `cmcp_verify.sev_snp`). Auto-detected first (before TPM/SEV-SNP) since Azure exposes no `/dev/sev-guest`. Carries its own `runtime.platform` value `azure-cvm-sev-snp` (requires `agentrust-trace>=0.4`) so a consumer keying on `runtime.platform` knows the root of trust is vTPM-rooted, not a guest-controlled SNP `report_data`.
- `tool_transcript.entries`: privacy-preserving per-call view in the TRACE Claim (one entry per tool call with `tool_name`, `data_class` from the catalog, and the policy `decision`), derived from the audit chain so no raw parameters or response bodies are exposed. `tool_transcript.hash` continues to bind the full transcript to the audit-chain tip. Adds `transcript_entries_hash()` for offline recomputation. (#126)

### Fixed

- Bare-metal `SEVSNPProvider` now obtains the SNP report via the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`) instead of a `/dev/sev-guest` ioctl. The previous ioctl number and inline request ABI were incorrect and failed on real hardware with `ENOTTY` ("inappropriate ioctl for device"). **Hardware-validated on a non-paravisor SEV-SNP guest (GCP N2D, AMD Milan):** the guest-supplied nonce lands in the report's `REPORT_DATA` and the report verifies against the AMD VCEK.
- SNP report-version check in `cmcp_verify.sev_snp` now accepts version `>= 2` (was `(2, 3)` only). Real Milan hardware emits report version 5, which the old allowlist wrongly rejected as `invalid_snp_report_version`; the field offsets read are layout-stable across v2..v5 and the VCEK signature is the real gate.

## [0.3.0] - 2026-06-30

### Security

- Software-only (non-hardware-backed) claims now return `partially_verified` instead of `verified` (fail-closed); a real verification failure is never downgraded.
- An external-execution receipt whose `linked_call_id` does not match the entry is no longer reported signature-valid (short-circuits).

## [0.2.0] - 2026-06-12

### Added

- Bearer-token auth (`Authorization: Bearer`) wired into the live gateway server
- Upstream MCP forwarding: AGT pre-call interception, JSON-RPC forward to the attested catalog server, response size guard, injection/credential/PII response scanning
- Durable SQLite audit store (WAL mode, synchronous) with TEE-anchored hash chains and orphaned-session detection
- `POST /sessions/{id}/close` issues the signed TRACE Trust Record and rotates the session
- Cedar `@annotation` metadata returned as structured advice on deny decisions (HITL payloads)
- `cmcp-verify`: one-command verification of claims and signed audit bundles, tamper-evident
- Fail-closed hardware verifiers (TPM, SEV-SNP, TDX, OPAQUE): no attestation evidence means no verification
- Dev-mode records carry `platform: software-only`, never `tpm2` (requires `agentrust-trace>=0.1.1`)
- Silent mode contract: operational logs quiet, audit evidence always recorded

## [0.1.0] - 2026-06-09

### Added

- Initial TEE gateway with provider support for TPM, SEV-SNP, TDX, and OPAQUE
- Cedar policy enforcement for request authorization at the gateway layer
- TRACE Claim generation using the `GatewayClaim` envelope from `agentrust-trace`
- `cmcp-verify` standalone verifier for validating TRACE Claims offline
- Audit chain with Ed25519 signing for tamper-evident log integrity

[Unreleased]: https://github.com/agentrust-io/cmcp/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/agentrust-io/cmcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/agentrust-io/cmcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/agentrust-io/cmcp/releases/tag/v0.1.0
