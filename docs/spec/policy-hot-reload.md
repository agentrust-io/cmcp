# Policy Hot-Reload

**Document status:** Implemented (option A, signing key), with revocation of
the policy signing key without a restart; see "Revocation without a restart"  
**Applies to:** cMCP Runtime gateway (`PolicyStore`, `startup`)  
**Related config:** `policy_reload_interval_seconds`

---

## Summary

Hot-reload was never missing. It was implemented in `PolicyStore.reload_if_stale`,
wired into `PolicyEvaluator`, and documented as a supported knob — and **it could
not swap a policy in any production configuration.** The sections below record why,
with the measurements, because the shape of that mistake is worth keeping.

**Now:** policy can change at runtime when the gateway pins a **signing key**
rather than an artifact hash (option A, built). The guaranteed-inert configuration
is refused at startup, a failing reload no longer re-reads the bundle on every
request, and a signed bundle whose version increases is installed without a
restart. A compromised signing key can be revoked on a running gateway through
the same reload path, provided a successor key was pinned at startup.

The rest of this document is the analysis that got there, kept because the
diagnosis matters more than the fix: a status file said "not yet" while the code
said "implemented and inert", and nothing failed.

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

## Decision (2026-08-10): option A, pin a signing key

**Direction chosen: A.** Runtime policy change gets its authority from a pinned
signing key rather than a pinned artifact hash. Nothing about it is implemented
yet; what follows is what the decision commits us to, so the implementation issue
starts from a settled model rather than reopening the choice.

What it means concretely:

- The bundle manifest gains a signature over its own canonical contents. The
  manifest already carries `author_identity` and `commit_sha`, both currently
  unsigned assertions; signing turns them into claims someone is accountable for.
- The gateway pins a **public key** (a new setting, not `CMCP_POLICY_HASH`). A
  reload verifies the new bundle's signature against it.
- The manifest's `version` must increase monotonically across reloads, and a
  bundle whose version does not is refused. Without this a validly signed *older*
  bundle is a downgrade attack: an attacker who can write the bundle directory
  replays yesterday's more permissive policy, and every signature still checks out.
- `CMCP_POLICY_HASH` keeps its current meaning and stays the right choice for a
  deployment that wants exactly one policy for the life of the process. A hash
  alone cannot authorise reload, so a hash with an interval and no key is refused
  at startup (see below). With both pinned, the hash is checked on the startup
  load and the key authorises every reload. (Until this was corrected the reload
  also re-checked the startup hash, which refused every changed bundle in the one
  shape production runs, since a hash is required outside dev mode.)
- Evidence: a TRACE claim records the bundle hash it evaluated under **plus** the
  signer identity and the bundle version, so a verifier can answer both "what
  policy ran" and "who authorised it" for a process whose policy changed mid-life.

### As built

```bash
export CMCP_POLICY_SIGNING_KEY=<raw Ed25519 public key, base64url or hex>
# and in cmcp-config.yaml
policy_reload_interval_seconds: 60
```

| Decision | Answer |
|---|---|
| Signature covers | The **bundle hash**, domain-separated: `sha256(cmcp-policy-bundle-v1\|<bundle_hash>)`. Reuses the hash the gateway already computes and measures. |
| Where the signature lives | `signature` in `manifest.json`, base64url. It is **excluded from the hashed manifest**, because it cannot be inside the pre-image it signs. Same idiom the delegation credential uses. Every bundle hash issued before signing existed is unchanged, since stripping an absent key is a no-op. |
| Monotonic version | Enforced on reload when a key is pinned. Versions are compared as tuples of integers, so `1.10.0` beats `1.9.0`; an unorderable version is refused **at load**, not at the first reload. |
| Hash and key both pinned | The hash is checked on the startup load only. Reloads are authorised by the key. |
| Key rotation and revocation | One step without a restart, to a successor key pinned at startup. See below. |
| In-flight sessions | The new bundle applies from the next evaluation, including for sessions already open. |
| Unsigned bundles | Still valid when no key is pinned. Signing is opt-in; a deployment pinning a hash needs none of it. |
| Unsigned bundle *with* a key pinned | Refused. Having asked for signed policy, being handed unsigned policy is a refusal, not a downgrade to the unsigned path. |

### Why the version check is not optional

Without it the signing-key model **is** a downgrade attack. Anyone who can write
the bundle directory replays yesterday's more permissive bundle: the authority
really signed it, the signature really verifies, and the gateway installs a policy
the operator already retired. Monotonicity is what makes "signed by the authority"
mean "the authority's *current* intent". `test_a_replayed_older_signed_bundle_is_refused`
constructs exactly that attack and fails if the check is removed, which was
verified by removing it.

### Revocation without a restart

Before this, a compromised signing key stopped being trusted only by changing
`CMCP_POLICY_SIGNING_KEY` and restarting, and until each gateway restarted the
holder of the key could keep installing signed bundles on it.

**Keys.** `CMCP_POLICY_SUCCESSOR_SIGNING_KEY` pins a second public key at startup.
It signs no bundle while the current key is trusted. A key id is
`sha256:<hex>` of the 32 raw public key bytes.

**Statement.** `signing-key-revocations.json` in the bundle directory holds a JSON
array of statements:

```json
[{"revoked_key_id": "sha256:<hex>", "signature": "<base64url Ed25519>"}]
```

The signature covers `cmcp-policy-key-revocation-v1|<revoked_key_id>`, a
different domain from the bundle signature, so neither can be replayed as the
other. The file is outside the bundle hash, so adding it does not change the
measured policy.

| Rule | Behaviour |
|---|---|
| What can be revoked | Only the current key. A statement naming the successor, or any other key, is refused (`POLICY_KEY_REVOCATION_INVALID`), so a stolen current key cannot remove the recovery path. |
| Who can sign it | The successor, or the current key itself. Self-revocation gives a thief nothing: it hands policy to the successor, or leaves no trusted key. |
| Effect | The current key is revoked and the successor becomes the key bundles must be signed by. With no successor pinned, no key remains and every reload is refused until a restart with a new key. |
| When | At the start of every reload attempt, before the bundle is read, and once at startup before the first load. Reload must be on for it to take effect without a restart. |
| Bad statements | Logged and skipped. The rest of the file and the bundle reload still proceed, because anyone who can write the directory can write a bad statement. |
| Monotonic | A revoked key is never trusted again in the process. There is no un-revoke statement, removing the file changes nothing at runtime, replaying an applied statement is a no-op, and the successor is promoted at most once. |
| Policy in force | It was signed by the revoked key, so it is not trusted. **Fail closed:** every tool call is refused with `POLICY_SIGNING_KEY_REVOKED`, in enforce, advisory and silent modes alike, and recorded as a deny in the audit chain. Advisory and silent decide what to do with a Cedar decision; a policy whose only authority is a revoked key does not produce one worth acting on. |
| Recovery | A bundle signed by the successor with a version above the running one. The version floor is not reset by a revocation, so if the revoked key was used to push a high version, the replacement must exceed it. |
| A bundle signed by the revoked key | Refused on reload and at startup with `POLICY_SIGNING_KEY_REVOKED`, not reported as an ordinary bad signature. |
| Evidence | Logged as `POLICY_SIGNING_KEY_REVOKED` with the revoked key, the signer and the key now trusted. Each TRACE claim carries `gateway.policy_signing` with `key_id` (the key the policy in force at claim time verified under) and `revoked_key_ids`. A `key_id` inside `revoked_key_ids` marks a session whose calls were refused for this reason. The field is optional and absent where no key is pinned. |

**What remains out of scope.** One successor per startup: after a rotation there
is no pinned successor until the next restart, so a second compromise before then
can only be answered by self-revocation (fail closed) and a restart. Revocation
state is in memory. A restart rebuilds it from the environment plus the statement
file on disk, so an operator should move `CMCP_POLICY_SIGNING_KEY` to the successor
before restarting; if the file is deleted and the old key is still configured, the
restart trusts it again. There is no expiry, no list of revoked keys distributed
to verifiers, and no mechanism that pushes a statement to a fleet: each gateway
reads its own bundle directory. The claim records the key for the policy in force
when the claim is built, not for each call, which is the same granularity as the
existing `trace.policy.bundle_hash`.

### In-flight sessions

A session admitted under the previous bundle is evaluated against the new one from
its next call. This is what an operator tightening a policy during an incident
expects, and it is the reason reload was wanted at all. The cost is that a
long-running session can see its effective permissions narrow with no signal; a
session-facing notification was considered and is not built.

## Two things that were not optional, and are now done

Both stood on their own, independent of the direction, and both have landed:

1. **A configuration that cannot work does not start.** `CMCP_POLICY_HASH`
   together with `policy_reload_interval_seconds > 0` and no signing key aborts
   startup (`POLICY_RELOAD_PINNED_HASH`): a pin on an exact artifact cannot
   authorise a policy that changes. With a key also pinned, the hash is checked on
   the startup load only and the key authorises reloads; both shapes are tested.
2. **The interval is honoured on failure.** `_last_reload_at` is stamped *before*
   the attempt, so an exception cannot skip it. A failing reload now costs one
   attempt per interval instead of one full bundle read plus hash per request.
   Worth doing regardless of what happens to hot-reload, because the same shape
   reappears in anything else that polls on the enforcement path.

The test gap generalised past this feature and was closed with it: a code path
whose only tests construct it in the configuration production never uses is a path
with no tests. The reload tests now cover pinned and unpinned side by side, one
asserting that a pinned hash cannot install a changed bundle and one asserting
that without the pin it can, so the difference the pin makes is visible in the
suite rather than discovered later. The load bound has a test above it that counts
the reads.

## Not in scope

- Catalog hot-reload. `CMCP_CATALOG_HASH` has exactly the same pin, and
  `load_catalog` the same shape, so whatever is decided here should be applied
  there deliberately rather than by copy. It is not analysed in this document.
- The limits of revocation listed under "Revocation without a restart" above.
