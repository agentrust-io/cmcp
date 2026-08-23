# Verifiable catalog-approval provenance

The active catalog hash proves that the gateway is using the approved bytes at
runtime. It does not prove how those bytes reached the approved state. The
detached record defined by `schemas/catalog-approval.schema.json` supplies that
missing history without putting mutable approval status into the catalog or
TRACE claim.

Each record identifies a catalog, sequence, previous record, previous and new
catalog hashes, a change-set digest, an automated-checks digest, and an
approval policy. Every approval is an Ed25519 signature over the record body and
its own principal, issuer, role, validity interval, and key identifier. The
verifier resolves keys from trusted configuration; no record-embedded key can
bootstrap trust.

The same rule applies to the policy. A record states which policy it followed,
but the verifier is given the expected policy hash and catalog identifier from
its own configuration, and rejects any record citing a different policy. The
record's `policy_hash` must also cover its own policy body, computed over the
policy object with the `policy_hash` field removed. Without this pinning a
single reviewer key could issue a record declaring a threshold of one, so the
M-of-N property depends on the policy being verifier-supplied rather than
record-supplied.

The verifier rejects unknown fields, revoked or expired keys, invalid
signatures, repeated principals or roles when the policy requires distinctness,
and records whose `new_catalog_hash` differs from the runtime catalog hash. A
reviewer key counts once regardless of policy: a repeated signature is one
approval presented N times, not N approvals, and without that rule a threshold
of N is satisfiable by a single key whenever the policy does not demand
distinct principals, or demands distinct roles while the key's trusted entry
pins no role.
The key identifier is the reviewer key's identity for both of those rules. A
verifier that registers one key under two identifiers has neither: the record
can present it twice toward one threshold, and revoking one identifier leaves
the other usable. `trusted_reviewers` must therefore map distinct identifiers to
distinct keys.
`catalog_id` is always checked. `sequence`, `previous_record_hash`, and
`previous_catalog_hash` are checked when the caller supplies the corresponding
checkpoint, which it must obtain externally as described below.

The signing input is RFC 8785 (JCS): UTF-8 output, object members ordered by
their UTF-16 code units, and no escaping beyond what ECMAScript `JSON.stringify`
performs. A record whose identities are not ASCII therefore signs the same bytes
here as under any other JCS implementation. Where JCS cannot pin a value down,
cMCP refuses it rather than emit bytes another implementation would read
differently: floating point numbers, integers outside the exact range of an IEEE
754 double, non-string object keys, and unpaired surrogates are rejected as
malformed. Approval records carry none of them.

The schema is the structural authority. `verify_catalog_change` loads
`schemas/catalog-approval.schema.json` and validates the record against it before
any other check, and refuses to verify at all when the schema is missing from the
installation, as the catalog loader does for `catalog-entry.schema.json`. The
checks the verifier keeps in code are the ones JSON Schema cannot express: the
runtime hash binding, the policy pin, reviewer identity and key rules, and the
signatures.

The first record in a chain has no predecessor, and the schema cannot express
absence for a required digest. That record sets `previous_record_hash` to the
all-zero digest, `sha256:` followed by 64 zeros, so no predecessor is
distinguishable from a real chain link rather than left to producer convention.

`approved_at` and `expires_at` bound when the signature could have been produced.
They are not a lifetime on the record. The verifier judges them against
`validity_instant`, supplied by the caller, which should be a pinned checkpoint
or transparency-receipt timestamp where the caller has one. Where none is
supplied, each approval is judged at its own `approved_at`, so a record remains
verifiable after its approvals expire and an auditor can replay the chain later.
Judged against the verification clock instead, the record would be an
authorization token with a lifetime rather than a provenance record.

Revocation is a separate question and is always judged at verification time. A
key revoked today must not validate a record presented today, however old the
record and whatever instant its approvals are judged at.

Because a record replays indefinitely, revocation is the only thing that stops a
historical approval from counting. An operator's revocation list is therefore
load-bearing rather than a backstop: a key that should no longer count towards a
threshold stops counting when it is revoked, and not before. Nothing else expires
it, and membership of the trusted set plus revocation is the whole of the
key-state check.

The record chain is not a freshness oracle. A verifier must obtain the expected
previous-record checkpoint from an external pin or transparency receipt. A
valid chain presented from an old checkpoint remains an old, valid chain rather
than proof that it is the latest approval.

This provenance answers who approved which catalog change and which checks were
reported. It does not prove tool safety, prevent reviewer collusion, or replace
runtime catalog measurement and attestation.
