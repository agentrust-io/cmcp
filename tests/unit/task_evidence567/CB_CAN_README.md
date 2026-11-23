# Approved callback / cancellation fixture slice

This is an additive, conditional test-only continuation of #701, approved in
[#567's A/B ruling](https://github.com/agentrust-io/cmcp/issues/567#issuecomment-6226474462)
against the [bounded matrix](https://github.com/agentrust-io/cmcp/issues/567#issuecomment-6207609935).
Existing AM fixtures and the A–G mutation runner are unchanged.

The carrier profile is native `subscriptions/listen` at ext-tasks
[`7b8e2bd`](https://github.com/modelcontextprotocol/ext-tasks/blob/7b8e2bde214b35fd6f0d4f3899789388d623164d/specification/draft/tasks.md).
Its separate `notifications/subscriptions/acknowledged` notification, not a
JSON-RPC response or the requested task list, supplies the accepted list.
A task ID is a lookup key, never authority in this fixture profile.

## Evidence and trust premises

`Trust` fixes expected source, client, task, scope, evaluation ID/instant,
exclusive-task-membership rule, and role-specific public keys **outside**
submitted witnesses. Public deterministic Ed25519 test keys issue synthetic
statements. Their role authority is a stipulated premise, not inferred from
signature validity or a witness's own claims. Occurrence commitments use the
existing #701 observation helper; copied task text does not identify a record.
These local containers/signatures are not a callback wire protocol or real
client credential verification.

| Boundary | Independent premise/evidence | Selected contrast |
|---|---|---|
| CB-01 source | Fixed source/role key; authenticated exact-delivery statement | matching source E; missing/bad signature/wrong occurrence N; eligible incompatible source C |
| CB-02 bytes | Authentic exact-delivery SHA-256 commitment | match E; missing/wrong occurrence/malformed N; comparable different digest C |
| CB-03 task | Fixed membership rule; authentic exact-delivery membership | selected task E; text alone N; other task C only if memberships are incompatible |
| CB-04 reporting | Independently scoped reporting-policy role and context/time coverage | authenticated source may stay E while authority is E/N/C |
| CB-05 acceptance | Authentic complete exact ack bound to exact listen exchange | accepted E; missing/inapplicable binding N; absent from this complete list C only for this ack |
| CB-06 subscriber | Independent client authentication and access-policy roles for listen/task/context | acceptance/source authentication do not replace authority; E/N/C |
| CB-07 delivery context | Authentic D→L/subscriber evidence | correct E; missing, wrong L or wrong subscriber N; L's ack and authority stay E |
| CAN-01 operands | Real AM-03 Cedar policy plus independent request/client bindings for principal, action, resource, scope and instant | omit one provenance signature with identical operands/permit and other relations E: named binding N and composite authority N |
| CAN-02 applicability | Separate context-only authority over exact operand statement-body hashes, context and validity coverage | all individual bindings may remain E while joint and composite become N; older evidence still covering the evaluation remains E |

`E = ESTABLISHED`, `N = NOT_ESTABLISHED`, `C = VERIFIED_CONTRADICTION`:
existing #701 fixture terms, not final wire values. An invalid signature is N,
never contradiction by itself. An inapplicable Cedar permit is N; a matching
independently pinned explicit forbid is C. The composite requires client
authentication, every operand binding, joint applicability and policy inclusion.

CAN-01 omits just the selected operand signature, retaining its body and the
independent context receipt. This deliberately leaves joint applicability E:
otherwise a missing joint result could mask a composite that ignored the
missing operand. CAN-02 context variants reissue authentic context receipts
over the changed exact body hashes, avoiding a hash-mismatch confounder.
The context authority cannot authenticate an operand's value/provenance.

## Completeness

The source population and required boundary set are fixed before assessment.
Every captured delivery triggers CB-01..07 even if authentication fails. Every
captured cancellation request triggers the five CAN-01 operands, CAN-02 and
the composite cancellation-authority assessment. Listen/ack records support
delivery assessments; they do not replace their exact subject.

`account_slice` reuses #701's count-before-eligibility accounting without changing
it. Zero attempts is `UNACCOUNTED`; multiple targeted attempts are
`AMBIGUOUS_ACCOUNTING`; one malformed is `MALFORMED_ACCOUNTING`; exactly one
eligible is `ACCOUNTED`. No applicable subjects is `OUTSIDE_BOUNDED_CONTRACT`.
Wrong-subject/boundary and malformed attempts remain visible. An explicit N
can be accounted; that does not establish the relation. Valid plus malformed
duplicates are not filtered into a pass. Frozen population is a fixture premise,
not proof that all real traffic was captured.

## Run and limits

Run `python -m pytest tests/unit/task_evidence567 -q`. The unchanged
`run_mutations.py --output-dir <new-directory-outside-checkout>` still exercises
the old A–G guards over the entire focused suite. All new negative twins have
established positive controls; an always-N oracle is not accepted.

No Tasks runtime, live authentication, callback replay/out-of-order semantics,
terminal-result verification, external effect, webhook profile, HITL behavior,
normative schema or final wire representation is implemented or established.
Authority evidence states only its selected context and validity coverage;
this does not impose a new per-delivery reauthorization requirement.
