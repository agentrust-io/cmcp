# Exact-output disclosure authorization

This reference contract addresses #660. A recipient outside the approved
confidential boundary requires independently authorized disclosure. A model's
claim that a summary is public is not release authority. The existing gateway
sink ceilings continue to deny that call; this opt-in library adapter is a
separate operator-controlled release path, not a new MCP request parameter.

## Contract and trusted inputs

The trusted controller supplies the accumulated labels, source/derivation scope,
authenticated workload identity and intended purpose. Derived outputs inherit
all source restrictions; caller-declared labels can add restrictions, never
replace the accumulated ones. Classification and provenance discovery are not
implemented by this adapter. It cannot detect a controller omitting a source.

An operator registry binds each opaque recipient ID to a delivery adapter, its
sensitivity ceiling and whether its boundary is accepted, external or unknown.
The adapter must authenticate that recipient and deliver the exact byte string
without alternate URLs, redirects, transformations or implicit extra sinks.
Registry assertions are trusted inputs, not hardware-appraisal evidence.

A release-authority registry pins Ed25519 public keys to principal IDs and
their allowed source scopes, audiences and purposes. Keys establish signing
authority only within those configured scopes. Workload identity, represented
user, delegated authority and runtime attestation remain separate as in #568.
This profile supplies direct owner authority; it does not invent a represented
user or implement token exchange, delegation chains or proof of possession.
Existing catalog approvals and Cedar step-up advice do not confer disclosure
authority. Reuse of a reviewer key requires a separate explicit release grant.

An approval signs a domain-separated, canonical record binding the principal,
one-use request ID, workload, source scope, all inherited labels, recipient,
purpose, policy version, exact output SHA-256 and validity interval. The signer
must review the exact candidate bytes and scope. No wildcard, regular expression,
model verdict or named summarization transform substitutes for those bytes.
Changing even one byte requires another approval. The approval record is private:
its digest may permit guessing low-entropy content. Never put it in public logs.

## Decisions and delivery

| Condition | Disposition | Delivery |
|---|---|---|
| Accepted boundary and every known label fits its ceiling | `unchanged` | Exact bytes to the registered adapter; no broader confidentiality claim. |
| Known external recipient, or release lowers its ceiling | `authorized_disclosure` only with valid scoped approval | Exact approved bytes; source/session restrictions remain unchanged. |
| Unknown label, source scope or recipient boundary; absent approval/key | `unavailable` | No delivery. |
| Known contradictory signature, scope, bytes, policy, validity or replay | `denied` | No delivery. |

The configured policy version is checked even for unchanged-boundary releases.
Versions must identify immutable policy/registry inputs. To update policy or
revoke authority, stop admission on the old gate, replace it under controller
serialization, and use the same protected replay database. Reconstructing a
gate does not stop already admitted delivery on another live gate.

After validation, a durable SQLite transaction consumes the request ID **before**
the delivery callback. A crash, callback exception or lost acknowledgement leaves
delivery unknown; the ID stays consumed. Never automatically retry or assign a
fresh ID to an unknown attempt. A normal callback return is an acknowledgement,
not proof of recipient installation, processing or downstream confidentiality.

All gates for a release authority must use the same trusted replay store.
Deletion, snapshot rollback, database substitution or separate clones defeat
that store; deployments must prevent them externally. System UTC seconds are
the default validity clock, with exclusive expiry. The caller must protect time;
this library does not supply a trusted clock or revoke disclosed plaintext.

The returned minimized record contains only disposition, reason, an independent
random event ID and a delivery outcome (`not_attempted`, `unknown`, or
`acknowledged`). It contains no output digest, payload, principal, purpose,
recipient or approval. Keep the private correlation record access-controlled.
Even event timing and random IDs can expose activity or linkage. The record is
not a signed TRACE claim or proof of complete audit coverage.

## Library use and reproduction

The API lives in `cmcp_runtime.disclosure`. A trusted controller constructs a
`ReleaseRequest` from immutable candidate bytes and its retained source labels.
The owner-side `approve_exact_output` signs that request after review using a
private key held outside the model/runtime. `DisclosureGate` receives only pinned
public `ReleaseAuthority` grants, `ReleaseRecipient` adapters and a `ReplayStore`.
Calling `release(request, approval)` validates and consumes the attempt before
calling the pinned adapter. The returned `ReleaseObservation` must not be
interpreted as attested execution or used to authorize another release.

The scope and purpose strings are exact identifiers, not patterns. Purpose
checking authorizes sending for that declared purpose; it cannot enforce the
recipient's subsequent use. The gate is synchronous and has no callback timeout
or cancellation watchdog. Delivery adapters must supply their own bounded I/O.
Use admission/rate limits and protected retention for the replay ledger; pruning
consumed IDs can make old approvals replayable while still valid.

From an editable `.[dev]` installation, run:

```sh
python -m pytest -q tests/unit/test_disclosure.py tests/unit/test_sink_policy.py
```

Tests use generated software keys and a recording callback, not external
recipients or real confidential content. The independent serialization control
constructs one ASCII canonical approval without the signing helper; this is not
a second protocol implementation. Concurrent attempts use separate SQLite
connections in threads. Restart is modeled by reopening the store; process-kill,
filesystem durability faults and rollback-resistant hardware are not tested.

## Scope

This is a synchronous exact-byte reference adapter. It is not wired into
`CMCPProxy` and grants no exception to its existing sink policy. An integration
must mediate every actual egress path, preserve classifications, authenticate
recipients and serialize policy changes. The confinement work in #659 remains
a separate prerequisite for a deployment-wide claim.

Prompt-injection tests must request relabeling, summarization and forged model
approval at a lower-clearance sink. Paired positive controls use an independent
owner key; substitutions cover bytes, recipient, workload, purpose, source,
labels, policy, signer and time. Replay must fail after reopening the database,
concurrently, and after a delivery exception. Deliberately removing a tested
gate must turn its test red.

No semantic declassification, differential-privacy budget, downstream-use
restriction, secure erasure, protected signing key, independent-operator run or
hardware confidentiality is established. An authorized disclosure deliberately
changes the confidentiality boundary and cannot be undone.
