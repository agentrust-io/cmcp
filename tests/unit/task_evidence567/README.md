# #567 task/callback evidence — test-only fixtures

Test-only fixtures for the bounded acceptance matrix settled in
[#567](https://github.com/agentrust-io/cmcp/issues/567)
([settled matrix](https://github.com/agentrust-io/cmcp/issues/567#issuecomment-5818228820),
[AM-12 ruling](https://github.com/agentrust-io/cmcp/issues/567#issuecomment-5837085072)).

**Scope:** files under `tests/unit/task_evidence567/` only. No production code,
no runtime Tasks support, no wire schema. The containers and disposition names
(`ESTABLISHED`, `NOT_ESTABLISHED`, `VERIFIED_CONTRADICTION`) are local test
notation, not proposed wire fields.

## What each group checks

| Group | Distinguishes | Does not claim |
|---|---|---|
| AM-01 | `CreateTaskResult` with `resultType: "task"`, bound to its source bytes and the creation contract, earns durable-at-return and `tasks/get`-resolvable-at-return. A generic `"complete"` result, a wrong or missing discriminator, legacy dual-shape bytes, changed bytes, or a wrong profile/source do not. | Later state, completion, effect |
| AM-02 | Acknowledgement meaning comes from the bound request (update vs cancel), not from identical response bytes. Result metadata is retained. | Processing, state change |
| AM-03 | Real `CedarBackend` on pinned permit/forbid documents: permit → established; absent, untrusted, non-matching or erroring → not established; only a matching explicit forbid → contradiction. The ack is kept in every case. | Authentication, cancellation effect |
| AM-04 | A reused request ID needs independent occurrence binding. Typed IDs are not coerced (`7` ≠ `"7"`, `True` ≠ `1`). | Identity from ID text |
| AM-05 | Equal payloads do not decide event identity: distinct, duplicate, or not established. Both receiver observations are kept. | An extra state transition |
| AM-06 | Source order is bound separately from arrival order. | Precedence or truth from order |
| AM-07 | A requested cancel is compared with an exact same-task snapshot stipulated by the fixture as the later comparison observation: cancelled → established, completed → contradiction, absent → not established (not failure). Wrong kind or task → not established. | Causality, independently verified chronology, terminal truth |
| AM-08 | `isError` does not change the observed task status. | Terminal relation, business success, effect |
| AM-09 | Conflicting terminal observations are both kept in either arrival order; no winner is selected. | Resolution |
| AM-10 | Exact committed `AuditEntry` A and B. The origin projection comes from a separately signed creation source, never from the entry. A wrong origin call contradicts origin, leaves dependent execution not established, and does not touch A↔B correlation. A null execution ID is never synthesized. Real `compute_hash` and `valid_execution_id` are load-bearing. | Operation, logical action or effect identity |
| AM-11 | The exact outer protocol error is retained; missing or unbound IDs → not established. | Task failure, authority, a successful ack |
| AM-12 | Every creation observation requires exactly one eligible `execution_correlation` assessment in the submission. Omitted, duplicate, malformed, wrong-subject and wrong-boundary rows fail; an explicit `NOT_ESTABLISHED` is accounted. No creation observation → outside the contract, not a pass. | Runtime completeness, verified execution |
| AM-13 | Same accounting for profile-required `protocol_error_binding`. | A profile requirement where none applies |

## Trust premises

Synthetic signatures authenticate fixture statement bytes. Pinned hashes bind
or select exact fixture bytes. Neither establishes live provenance or
production authority. Signer authority, source applicability and complete
exchange scope are stated test premises. The keys are deterministic and
public; they are not credentials.

AM-01 does not use the SDK `CreateTaskResult` parser as authority for the
target wire type. It reads the 2026 discriminator and required fields from the
exact bound response bytes. This is a fixture-local guard, not a full Tasks
schema validator.

For AM-07, the fixture binds the request, acknowledgement, snapshot and task.
It does not independently establish temporal ordering; the snapshot's role as
the later comparison observation is a stated fixture premise.

## Mutation check

`run_mutations.py` applies seven fixed mutations to disposable copies and runs
the full focused suite against each. Every mutation must fail its named
decisive test with an assertion, after which the copied Python body must be
restored byte-exactly. Where a named surviving control is defined, that control
must remain green.

| | Mutation | Must be caught by |
|---|---|---|
| A | Positive authority weakened to not established | AM-03 positive |
| B | Assessment subject matching loosened | AM-12 wrong subject |
| C | Malformed rows filtered before counting | AM-12 valid + malformed duplicate |
| D | Authority forced positive | AM-03 missing authority |
| E | Creation discriminator guard bypassed | AM-01 wrong discriminator |
| F | Origin projection's entry-comparison fields derived from `AuditEntry` | AM-10 different task |
| G | Wrong origin cascades into A↔B correlation | AM-10 M17 wrong origin call |

## Running

```sh
PYTHONPATH=src python -m pytest tests/unit/task_evidence567 -q
OUT="$(mktemp -d)/cmcp567-mutations"
PYTHONPATH=src python tests/unit/task_evidence567/run_mutations.py \
  --output-dir "$OUT"
```

## Open

Callback authentication, callback authority, terminal-result verification,
historical supersession, final wire representation, runtime completeness,
external effects and Tasks runtime/storage remain open per #567. Nothing here
takes a position on them.
