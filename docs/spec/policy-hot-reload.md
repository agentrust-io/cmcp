# Policy Hot-Reload

**Document status:** Design proposal, nothing built  
**Applies to:** cMCP Runtime gateway (`PolicyStore`, `startup`)  
**Related config:** `policy_reload_interval_seconds`

---

## Summary

Hot-reload is not missing. It is implemented in `PolicyStore.reload_if_stale`, wired
into `PolicyEvaluator`, and documented as a supported knob — and **it cannot swap a
policy in any production configuration.** This document records why, measures what
the current code does instead, and lays out the options for fixing it. No code
changes accompany it.

`STATUS.md` says real-time policy update is "Not yet" because
`policy_reload_interval_seconds` is `0`. That reads as "unimplemented, default off".
The truth is worse and more specific: it is implemented, it is off by default, and
turning it on in production buys a warning log line every request instead of a
policy update.

## What is actually there

`PolicyStore` (in `policy/bundle.py`) holds the active bundle behind an `RLock`.
`PolicyEvaluator.evaluate` calls `reload_if_stale()` on the way in. Once the
interval has elapsed, the store re-reads the bundle from disk and swaps it in if
the hash changed, keeping the current bundle if anything raises.

That is a reasonable poll-and-swap design. The problem is the trust anchor it
re-uses.

## The defect: the pin and the reload contradict each other

At startup the gateway **requires** `CMCP_POLICY_HASH` unless `CMCP_DEV_MODE=1`
(POLICY-001/#137: without a pinned hash, a tampered bundle loads silently). That
pinned hash is handed to `PolicyStore` as `expected_hash` and then re-used on
**every reload**:

```python
new_bundle = load_policy_bundle(self._bundle_path, self._expected_hash)
```

`load_policy_bundle` raises `PolicyHashMismatch` when the bundle on disk does not
match the hash it was given. So the reload path asks a question that answers
itself: *"has the bundle changed, and does it still hash to the value it had before
it changed?"* A bundle that has genuinely changed always fails. A bundle that has
not changed always passes and swaps nothing.

The line that would install a new bundle:

```python
if new_bundle.bundle_hash != self._bundle.bundle_hash:
```

is unreachable whenever `expected_hash` is set, because the call above it has
already raised.

**Measured, not inferred.** With `expected_hash` set to the startup hash, an
operator edit from allow-all to deny-all produces:

```
startup bundle hash : sha256:fdb2e39e...
new on-disk hash    : sha256:e1426d71...
reload_if_stale()   : False
active bundle hash  : sha256:fdb2e39e...   <-- unchanged
```

The gateway keeps enforcing allow-all. The operator's deny-all edit does not take
effect, and the only signal is a `WARNING`.

### Why no test caught it

Every reload test in `tests/unit/test_policy_bundle.py` constructs `PolicyStore`
**without** `expected_hash`:

```python
store = PolicyStore(bundle=old_bundle, bundle_path=str(bundle_dir),
                    reload_interval_seconds=1)
```

That is the dev-mode configuration, where reload does work.
`test_policy_store_bundle_swap_on_hash_change` passes and proves the swap logic is
correct — in the one configuration production never uses. The pinned-hash case,
which is the only case a deployment runs, is untested.

### Second defect: it re-reads the bundle on every request, forever

`reload_if_stale` advances `_last_reload_at` only on the success path. The failure
path returns without touching it, so the staleness check stays true and the next
call tries again immediately. Since the reload in production *always* fails, the
interval stops being an interval.

Measured: 50 policy evaluations after the first interval elapsed produce **50 full
bundle re-reads from disk**, each one reading every policy file and computing a
SHA-256 over the canonical bundle, on the request hot path.

So the production effect of setting `policy_reload_interval_seconds: 60` is not
"policy updates every minute". It is "after one minute, every tool call performs
full bundle I/O and hashing, and the policy never changes". That is a
self-inflicted load amplifier on the enforcement path, reached by following the
documented configuration.

### Third, smaller: the error text is from the wrong lifecycle

The swallowed exception logs `Policy bundle hash mismatch: gateway will not start`
during steady-state operation. The gateway is already running and is not going to
stop. `except Exception` also catches genuine faults (unreadable file, malformed
Cedar, permissions) and files them all under the same warning, so the log cannot
distinguish "operator edited the policy and the pin now disagrees" from "the disk
is failing".

## The real design question

Hot-reload and hash pinning are not accidentally in tension — they want different
things:

- **Pinning a hash** says *the policy is exactly this artifact, decided before the
  process started, and nothing may change it afterwards.* That is what makes a
  policy bundle attestable: the hash goes into the TRACE claim, and a verifier can
  check that the gateway enforced the bundle it said it did.
- **Hot-reload** says *the policy may change while the process runs.*

A design that wants both must answer: **when a new bundle arrives, what authorises
it?** A hash fixed at startup cannot, by construction. Something else has to.

There is a second question that follows immediately and matters just as much for
cMCP specifically: **what does a reload do to evidence?** A TRACE claim names the
policy bundle hash the call was evaluated under. If the bundle can change
mid-process, then claims from one process carry different bundle hashes, and every
consumer of those claims needs to cope with that. Any option below has to say what
the claim records and how a verifier reconstructs which policy was live for a
given call.

## Options

### A. Pin a signing key, not a bundle hash

The bundle carries a signature over its own manifest; the gateway pins the
**public key** allowed to sign policy. A reload verifies the new bundle's
signature rather than its hash.

- Trust moves from "this exact artifact" to "any artifact this authority
  approves", which is what actually makes runtime change safe.
- Fits the existing manifest (`author_identity`, `commit_sha` are already there,
  unsigned) and the direction the rest of the stack has taken.
- Cost: key management, revocation, and a rollback story — a validly signed *older*
  bundle is a downgrade attack unless the manifest carries a version that must
  increase monotonically.
- Evidence: the claim records the bundle hash *and* the signer plus the bundle
  version, so a verifier can check both what ran and who authorised it.

### B. Pin a set of acceptable hashes

`CMCP_POLICY_HASH` becomes a list. A reload accepts any bundle whose hash is in the
allowlist.

- Smallest change from what exists, and keeps the "exactly these artifacts" model.
- No new cryptography and nothing to revoke.
- Cost: every policy change still needs the operator to restart to extend the
  allowlist, so it does not deliver hot-reload — it only lets a fleet roll between
  a known set of policies without restart. Useful for staged rollout and
  fast rollback; not an answer to "we need to tighten a policy right now".

### C. Re-read the pin from a trusted source at reload time

The expected hash comes from somewhere the gateway can re-consult — a separate
hash file, a control plane, a transparency log — instead of a startup env var.

- Genuine hot-reload, and the authority for a policy change stays outside the
  gateway.
- Composes with the transparency direction: the pin could be an entry a verifier
  can independently look up.
- Cost: introduces a runtime dependency on that source and its own trust
  question. If the hash file sits next to the bundle and is writable by whoever
  writes the bundle, it authorises nothing.

### D. Operator-triggered reload that supplies the new hash

No polling. An admin action (signal, authenticated endpoint) hands the gateway the
new expected hash and it reloads once.

- Nothing changes under a running request without a human or a deploy pipeline
  asking, which is the most predictable behaviour and the easiest to audit.
- Removes the hot-path `reload_if_stale()` call from `evaluate` entirely, and with
  it the load amplifier.
- Cost: a new authenticated control surface on the gateway, which is attack
  surface on the enforcement component. Less convenient than polling.

### E. Keep it development-only, and make that honest

Accept that a pinned, attestable policy and runtime mutation do not belong in the
same deployment. Reload is permitted only when `CMCP_DEV_MODE=1`; configuring
`policy_reload_interval_seconds > 0` together with a pinned hash is a **startup
config error** rather than a warning at request time.

- Honest, costs nothing to build, and removes the failure mode entirely.
- Matches how the rest of the runtime treats this class of thing: fail at
  construction on a configuration that could never work.
- Cost: cMCP keeps telling operators that a policy change needs an enclave
  restart, which for a confidential gateway means an attestation cycle. That is a
  real operational burden and the reason this item is on the list at all.

## Recommendation is not the point yet, but two things are not optional

Whichever direction is chosen, two fixes stand on their own and do not depend on
it:

1. **A configuration that cannot work must not start.** `expected_hash` set
   together with `reload_interval_seconds > 0` is, today, guaranteed-inert. Under
   option E that pairing is the config error; under A/B/C/D it stops existing.
   Either way it must never again be a thing an operator can switch on and believe.
2. **The interval must be honoured on failure too.** `_last_reload_at` has to
   advance whether or not the reload succeeded, or a failing reload turns into
   per-request bundle I/O on the enforcement path. This is worth fixing even if
   hot-reload is removed, because the same shape will reappear in the next thing
   that polls.

And the test gap generalises past this feature: a code path whose only tests
construct it in the configuration production never uses is a path with no tests.
The reload tests should be parameterised over pinned and unpinned, so whichever
option lands is exercised the way it will actually be deployed.

## Not in scope

- Catalog hot-reload. `CMCP_CATALOG_HASH` has exactly the same pin, and
  `load_catalog` the same shape, so whatever is decided here should be applied
  there deliberately rather than by copy. It is not analysed in this document.
- What a reloaded policy means for an in-flight session that has already been
  admitted under the previous bundle.
