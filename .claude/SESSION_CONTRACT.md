Objective: Fix cmcp#653 - `session_state_path` is documented (docs/configuration.md)
and released (CHANGELOG.md, merged PR #629) but is non-functional: (1) the config
key is rejected at load time because `_KNOWN_TOP_KEYS` (config.py) omits it, before
the existing parsing code at config.py:489-491/561 is ever reached, and (2) even
with the key allowed, `run_startup` never constructs a `SqliteSessionStateStore` -
only an import and a dataclass field exist. `RuntimeContext.session_state_store`
stays None regardless of configuration, so the documented shared-persistent
session-sensitivity ratchet never activates. Confirmed both by direct code
inspection: `SqliteSessionStateStore(` has zero call sites in src/ outside its own
class definition.

Branch: fix/653-session-state-store-wiring
Parent: origin/main at fb5902c (Enforce operator sensitivity ceilings at tool and
response sinks); merging in origin/main at 8805801 per Imran's review on PR #661
to resolve a startup.py conflict with the kill-switch work that added its own
step 5f at the same location - keep main's 5f block, add the session-state-store
open as 5g after it, per his exact instructions

Allowed files:
- src/cmcp_runtime/config.py (add session_state_path to _KNOWN_TOP_KEYS)
- src/cmcp_runtime/startup.py (construct SqliteSessionStateStore when
  config.session_state_path is set, wire into RuntimeContext, matching the
  existing audit_store construction pattern: try/except -> _fatal + sys.exit(1)
  on open failure)
- tests/unit/test_config.py (session_state_path accepted, not rejected)
- tests/unit/test_startup.py (session_state_store actually constructed and wired
  when configured; stays None when not configured, preserving existing behavior)
- CHANGELOG.md

Non-goals:
- No changes to src/cmcp_runtime/session/store.py itself (SqliteSessionStateStore's
  own logic/locking/schema) - its own 10-test suite already covers that and the
  issue confirms it passes; this is purely a wiring gap.
- No change to InMemorySessionStateStore or its (non-)instantiation - the issue
  does not flag this as broken, and hydrate()'s `if self.state_store is None`
  branch already reproduces the documented "preserves existing single-instance
  behaviour exactly" default when unconfigured. Do not expand scope to construct
  it unconditionally without a separate, evidenced reason.
- No change to session/manager.py's `state_store=getattr(self._ctx,
  "session_state_store", None)` read site - it already does the right thing once
  the field is actually populated.
- Do not re-verify the store's own cross-process SQLite locking guarantees -
  covered by tests/unit/test_session_state_store.py already; this contract only
  verifies wiring (construction + config acceptance), not the store's internals.

Baseline: `.venv/bin/python -m pytest tests/unit/test_startup.py tests/unit/test_config.py tests/unit/test_session_state_store.py -q`
on origin/main at fb5902c before edits. Confirmed via direct grep that
`SqliteSessionStateStore(` and `InMemorySessionStateStore(` have zero call sites
in src/ outside session/store.py itself, and that RuntimeContext(...) in
run_startup (startup.py ~line 707) omits session_state_store entirely, falling
back to the dataclass default of None.

Acceptance gates:
1. A config file with `session_state_path: <path>` no longer raises "Unknown
   config key" at load_config.
2. `run_startup` with `session_state_path` configured produces a RuntimeContext
   whose `session_state_store` is a real `SqliteSessionStateStore` instance
   backed by that path, not None.
3. `run_startup` without `session_state_path` configured leaves
   `session_state_store` as None, unchanged from current behavior (regression
   guard against accidentally changing the unconfigured default).
4. A store-open failure (e.g. an unwritable path) fails startup closed via
   `_fatal` + `sys.exit(1)`, matching the existing `audit_store` open-failure
   pattern exactly (same shape, new error code or reused one - decide during
   implementation and justify the choice).
5. Full `pytest tests/unit -q` passes with no regressions beyond the one
   pre-existing, unrelated failure already documented in this repo's history
   (`test_startup_fails_on_unknown_tee_provider_name`, fails on clean main too).
6. Ruff and mypy clean on touched files.

Verification: `.venv/bin/python -m pytest tests/unit -q`, `ruff check`, `mypy` on
touched files, manual trace through `run_startup` confirming the new construction
site sits in the same step-ordering discipline the rest of the function follows.

Status: active
