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
bootstrap trust. It rejects unknown fields, revoked or expired keys, invalid
signatures, duplicate principals or roles when the policy requires distinctness,
and records whose `new_catalog_hash` differs from the runtime catalog hash.

The record chain is not a freshness oracle. A verifier must obtain the expected
previous-record checkpoint from an external pin or transparency receipt. A
valid chain presented from an old checkpoint remains an old, valid chain rather
than proof that it is the latest approval.

This provenance answers who approved which catalog change and which checks were
reported. It does not prove tool safety, prevent reviewer collusion, or replace
runtime catalog measurement and attestation.
