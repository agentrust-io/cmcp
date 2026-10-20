# Policy-state continuity: independent review acceptance criteria

Status: informative support for Rajnish's design in [#675](https://github.com/agentrust-io/cmcp/issues/675), against commit `3b2af0ba6c028094b63828978e23e79d9a084f9d`, 20 October 2026. This supplies review criteria, not a competing continuity design or implementation. All acceptance pairs are planned and unexecuted.

## Preserve the two identities

The current [session manager](../../src/cmcp_runtime/session/manager.py) creates a fresh session ID. Both [sensitivity storage](../../src/cmcp_runtime/session/store.py) and the [audit chain](../../src/cmcp_runtime/audit/chain.py) use session identity. Reusing an old audit ID is not a safe shortcut to policy resumption: chain initialization and sequence handling are not a reviewed audit-resume protocol.

The [maintainer direction](https://github.com/agentrust-io/cmcp/issues/675#issuecomment-5807567156) keeps audit IDs fresh and asks for a separate authenticated policy-state scope. A manifest identity or digest supplies context, not permission to resume. The design owner remains Rajnish; these criteria support independent verification of his proposed contract.

## Contract questions for the design

Identify the authenticated principal and tenant namespace, the trusted logical scope, and the authority permitting resumption. Define how they bind to stored policy state, configuration and invalidation generation. Caller-selected storage keys and matching manifests alone are insufficient. Anonymous continuity needs an explicit trusted mechanism or refusal; anonymity does not implicitly grant shared state.

State advancement needs atomic read/check/ratchet behavior across the supported concurrency boundary. Sensitivity comparison follows the configured order, not lexical or numeric maximum. Define when an operation observes and commits its floor, and what a concurrent raise means for an already admitted operation. Specify crash and storage-failure outcomes without claiming completed execution from dispatch alone.

Reset and invalidation need a generation or equivalent fence preventing a stale writer or old resume authority from reviving invalidated state. An intended resume with missing state differs from an authorized new logical session. Attestation refresh does not independently authorize reset, erase a ratchet or prove continuity under a changed principal.

Retain separate audit incarnations, including incomplete or orphaned histories. Any linkage between them needs an approved authenticated representation; no new audit field or chain-merging behavior is specified here. Database transaction isolation does not authenticate a principal or establish resistance to operator rollback of a database snapshot.

## Planned acceptance pairs

| ID | Valid control | Perturbation and expected observation |
| --- | --- | --- |
| PC-01 | Authorized principal resumes the correct logical policy scope after restart. | Same manifest with another principal or tenant cannot acquire that scope. |
| PC-02 | Independently authorized resumption names the intended scope. | Caller guesses its storage key; lookup success alone does not authorize resume. |
| PC-03 | Restart retains the policy floor and creates a fresh audit incarnation. | Reuse an old audit ID; the design refuses or prevents collision rather than overwriting old history. |
| PC-04 | Two supported concurrent instances preserve the strongest configured sensitivity. | Race a weaker update against a raise; no lost raise or downgraded committed state. |
| PC-05 | Valid fresh-session authorization creates new policy state. | Missing state on an intended resume cannot silently become a fresh low-sensitivity session. |
| PC-06 | Explicitly authorized reset advances the invalidation boundary. | Stale concurrent writer or old resume authority cannot resurrect the previous generation. |
| PC-07 | Successful fresh attestation preserves the appropriate policy history. | Weaker trust, changed principal or failed refresh cannot silently clear the ratchet. |
| PC-08 | Explicit trusted anonymous-continuity mechanism meets the chosen contract. | Anonymous caller supplies only a manifest or scope ID; no implicit resumption permission. |
| PC-09 | Atomic storage operation succeeds and evidence records its observed result. | Inject unavailable storage or crash at each commit boundary; retain explicit uncertainty and avoid reporting an unobserved commit. |
| PC-10 | Each audit incarnation verifies separately, with retained incomplete predecessors. | Restart after abrupt termination; preserve orphan evidence instead of rewriting history into one chain. |
| PC-11 | Current supported state is authenticated under the declared storage model. | Restore an older snapshot; either detect rollback under the selected mechanism or explicitly disclose the unsupported threat. |

Future test packets would pin source and dependencies, principal/resume configuration, storage topology, initial state, operation ordering, commit observations and all retained audit chains. Pair each refusal with a valid control. Disable the relevant authorization, generation or atomicity guard separately and demonstrate a behavioral failure, not merely a missing symbol. No such execution has occurred for this document.

## Decisions and evidence still needed

Rajnish's contract and maintainer review determine scope keys, authorization mechanism, reset semantics, storage/concurrency support, rollback threat model and audit-link representation before implementation. Restart/replica experiments then need the actual adapter and independent observations. This PR changes no runtime, persistence schema, wire credential or audit hash and does not close #675.

## References and limits

1. [Rajnish's #675 analysis](https://github.com/agentrust-io/cmcp/issues/675#issuecomment-5750172203) and [maintainer direction](https://github.com/agentrust-io/cmcp/issues/675#issuecomment-5807567156): ownership and fresh-audit/separate-policy-scope constraints. These take precedence over this proposed review checklist.
2. [RFC 9700, section 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14): prior art for binding resumable authority to the intended client/scope and handling replay and rotation. This analogy does not require OAuth, choose a credential format or establish that cMCP already implements those controls.
3. [SQLite, Isolation](https://www.sqlite.org/isolation.html): transaction visibility and writer serialization inform concurrency tests. This living documentation is not proof of replica-wide coordination, authorization or rollback-resistant storage.
4. [Session state at the reviewed commit](https://github.com/agentrust-io/cmcp/blob/3b2af0ba6c028094b63828978e23e79d9a084f9d/src/cmcp_runtime/session/state.py): existing ratchet/reset behavior is a baseline to preserve or explicitly revise through design review, not evidence that continuity already works.
