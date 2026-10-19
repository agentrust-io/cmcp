# Derived-output provenance: proposed integration acceptance

Status: informative proposal for the remaining criteria in
[#660](https://github.com/agentrust-io/cmcp/issues/660).
This is not a new runtime rule, classifier or completed integration example.
The [disclosure contract](spec/disclosure-authorization.md) and
[sink policy](spec/sink-policy.md) remain authoritative.

## Existing behavior and remaining boundary

The minimized durable attempt record landed in #721. Existing disclosure tests
already cover prompt text plus a low declared label, exact-byte substitution,
lower-ceiling approval and audit minimization. Sink policy accumulates session,
catalog and caller restrictions. This proposal does not reintroduce those as
missing features or claim a newly found bypass.

The remaining integration question is how a trusted controller supplies complete
source/derivation context to the release adapter. The adapter does not discover
omitted provenance. A model-written label provides neither source completeness
nor release authority. An independently authorized exact-output disclosure does
not declassify every later transformation of its inputs.

## Proposed bounded controller example

Select a declared synthetic source set, one transformation and one recipient.
The controller owns source enrollment and accumulated restrictions. It freezes
candidate bytes and the complete source/derivation scope before owner review.
The release signer authorizes the selected bytes and context, using the existing
contract. Recipient delivery and its acknowledgement remain distinct from
downstream installation or execution.

The controller's provenance and policy inputs are trusted premises, not something
an LLM or this example can certify. A required source that cannot be established
leaves the integration unavailable with no release. The representation of that
integration outcome and placement of the example require maintainer agreement;
no new adapter enum is specified here.

## Proposed acceptance matrix

These cases are a specification for future tests, not test results.

| ID | Controlled pair | Required distinction |
| --- | --- | --- |
| DO01 | Public-only derivation / same derivation also using a confidential source | Ordinary permitted release / inherited restriction requires authority |
| DO02 | Ordinary text / instruction to relabel the confidential derivation public | Identical accumulated restrictions; prompt text grants no permission |
| DO03 | Approved exact summary / altered bytes with the old approval | Authorized delivery / byte-binding refusal before callback |
| DO04 | Complete declared context / unresolved required source | Eligible request / unavailable integration with no delivery |
| DO05 | Explicit release grant / catalog review or policy advice only | Scoped authority / no disclosure grant |
| DO06 | Permitted recipient, source scope and policy / substituted context | Correct recipient / context refusal |
| DO07 | Authorized output / later unapproved derivation of the same source | First remains recorded; second independently needs permission |
| DO08 | Complete source inventory / deliberately omitted confidential source | Independent test oracle exposes the controller violation; adapter completeness is not claimed |

DO08 is a premise test: if an untrusted controller can omit sources, the adapter
alone cannot infer the missing restriction. A benchmark should report this
boundary explicitly, not declare safety merely because signed inputs agree.

## Reproduction and evaluation plan

Future fixture manifests name case/version, repository and released-package
revisions, source enrollment, trusted restriction inputs, candidate bytes,
recipient and policy context, expected callback count, valid twin, targeted
guard and evidence class. All content is synthetic and publishable. Runtime
audit rows retain existing minimization: no protected payload, source identifiers
or guessable protected-content digests are added by this design.

Use an independent source inventory and recipient spy as the test oracle.
Compare unchanged adapter behavior with the proposed controller-to-release
integration using the same source context; do not credit a decision rule for
extra observations withheld from the baseline. Report legitimate delivery,
unauthorized release, unavailable context and source omission separately.
Include held-out derivations and prompt attacks, without using the model's own
success report as ground truth.

Planned guard-removal checks separately bypass source accumulation, required
source availability, exact-byte binding and recipient binding. Valid twins reach
the relevant guard. Specific assertions fail when that guard is disabled;
crashes, missing imports and reject-all behavior are not adequate evidence.
This proposal contains no executed mutation or release campaign.

## Literature and its application

- [Denning, A Lattice Model of Secure Information Flow, 1976](https://doi.org/10.1145/360051.360056):
  established information-flow foundations motivate inherited restrictions.
  Access in this review was publisher abstract/metadata only.
- [Debenedetti et al., CaMeL, v2, 2025](https://arxiv.org/html/2503.18813v2):
  trusted control/data-flow separation informs enforcement placement; it does
  not supply this controller's complete provenance or automatic declassification.
- [Cutler et al., Cedar, 2024](https://arxiv.org/html/2403.04651):
  policy evaluation needs applicable inputs; supplied context is not automatically
  authenticated by the policy language.
- [Debenedetti et al., AgentDojo, NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/file/97091a5177d8dc64b1da8bf3e1f6fb54-Paper-Datasets_and_Benchmarks_Track.pdf):
  legitimate-task utility and adversarial behavior need paired evaluation;
  its benchmark outcomes are not this integration's release oracle.
- [draft-dogru-scitt-disclosure-evidence-07, 2026](https://datatracker.ietf.org/doc/html/draft-dogru-scitt-disclosure-evidence-07):
  source coverage and reconciliation are relevant prior art. This is an individual
  Internet-Draft, not an adopted IETF standard or validated cMCP implementation.

The proposed contribution tests a bounded trusted-source-to-release contract.
It does not claim general prompt-injection resistance, semantic secrecy detection,
complete mediation outside that contract, or completed #660 acceptance.
