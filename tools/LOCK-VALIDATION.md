# Generated requirement lock review

This draft port builds on agentrust-io/weight-custody-manifest#249. That initial implementation still awaits independent review; this port is not an accepted cross-project policy.

The read-only PR job runs standard-library regression controls, then compares changed requirements/*.txt files against the PR base. It rejects removed package/extras/marker identities, malformed or absent SHA-256 hashes, duplicate identities and lock deletion. Version changes are reported for human review. New locks receive only a structural check because no prior dependency baseline exists.

This recognizes the exact-pin/hash subset emitted by uv/pip-compile. It is not a general PEP 508 equivalence checker, dependency audit, package authentication or proof that an upgrade runs on Windows. Existing repository validation remains required. No source or dependency pin changes.

Manual cross-platform resolution is optional and separate: run tools/check_lock_delta.py --resolve --python-version 3.11 with a reviewed generated lock and uv available. It creates isolated Linux/Windows resolution contexts without installing their packages. Keep platform/version choices specific to each lock.

Source: https://github.com/agentrust-io/weight-custody-manifest/pull/249 .


Explicitly excluded non-lock files: {"requirements/confinement.txt": "composed requirements with an include, outside the exact-pin lock subset"}. These remain under their existing compiler/composed-environment checks. The guard does not claim to validate them.
