# Generated requirement lock review

This draft port builds on agentrust-io/weight-custody-manifest#249. Source head `9fcf6bd6684dbd87473d1b0c670eaeb154749a75` still awaits independent acceptance; this port is not an accepted cross-project policy.

The read-only PR job runs standard-library regression controls, then compares changed requirements/*.txt files against the PR base. It rejects removed package/extras/marker identities, malformed or absent SHA-256 hashes, duplicate identities and lock deletion. Renames are enumerated as a deletion and addition, so moving a lock (with or without dependency loss) requires explicit maintainer review instead of treating it only as a new baseline. Version and SHA-256 hash-set changes are reported for human review; hash ordering and duplicate identical hashes are ignored. New locks receive only a structural check because no prior dependency baseline exists.

This recognizes the exact-pin/hash subset emitted by uv/pip-compile. It is not a general PEP 508 equivalence checker, dependency audit, package authentication or proof that an upgrade runs on Windows. Existing repository validation remains required. No SDK runtime or dependency pin changes.

Manual cross-platform resolution is optional and separate: run tools/check_lock_delta.py --resolve --python-version 3.11 with a reviewed generated lock and uv available. It creates isolated Linux/Windows resolution contexts without installing their packages. Keep platform/version choices specific to each lock.

Source: https://github.com/agentrust-io/weight-custody-manifest/pull/249 .


Explicitly excluded non-lock files: {"requirements/confinement.txt": "composed requirements with an include, outside the exact-pin lock subset"}. These remain under their existing compiler/composed-environment checks. The guard does not claim to validate them.

Hash options must follow the marker (when present); every trailing token must be
a complete lowercase SHA-256 hash option. Quoted marker literals are retained.
Marker text is compared as an identity, not evaluated or fully validated as
PEP 508 syntax; supported-platform resolution is a separate check.

The shared checker is byte-identical to WCM source head
`9fcf6bd6684dbd87473d1b0c670eaeb154749a75`. Its optional manual
`--all-locks` CLI checks the union of current and base top-level
`requirements/*.txt` paths; deleted/renamed paths and invalid bases fail, while
new locks are explicitly identified and structurally checked. This low-level
manual mode does not apply this port's exclusions. The PR workflow continues to
use `check_changed_locks.py`: all changed requirement locks are discovered with
`--no-renames`, and the existing exclusions above remain unchanged. The workflow
does not install packages or run platform resolvers. Tests exercise hash-only
changes through this real driver and valid/corrupted runtime, server and custom
lock filenames. Independent WCM source acceptance and repository-specific
review remain prerequisites; draft status is retained.
