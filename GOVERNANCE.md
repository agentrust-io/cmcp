# Governance

This document describes how cMCP is governed: who holds what role, how decisions are made, and how the project relates to its upstream foundation.

---

## Upstream governance body

AAIF hosting for cMCP is **proposed, not accepted**. [CHARTER.md](CHARTER.md) is the
authoritative record: it is a pre-acceptance draft, and the "cMCP" and "cMCP-compatible"
marks are currently held by OPAQUE Systems, Inc.

On acceptance the Foundation would set overall direction for the agentrust-io ecosystem, hold
the project's trademarks, and provide a neutral venue for resolving disputes that cannot be
resolved within the project itself, and Foundation policies would supersede this document
where they conflict. Until acceptance, this document governs and nothing here should be read
as a binding foundation commitment.

---

## Project lead

The project lead is responsible for the technical direction of cMCP, final say on architecture decisions, and representing the project to the Foundation.

| Name | Affiliation | GitHub |
|------|-------------|--------|
| Imran Siddique | OPAQUE Systems | @imran-siddique |

The project lead role is subject to Foundation confirmation. Succession is decided by a 2/3 maintainer vote, ratified by the Foundation.

---

## Roles and contributor ladder

### Contributor

Anyone who opens a pull request, files a substantive issue, or otherwise participates in the project. No formal requirements. All contributors must sign off commits under the Developer Certificate of Origin (see [CONTRIBUTING.md](CONTRIBUTING.md)).

### Reviewer

A Contributor who has had **3 or more pull requests merged** may be nominated for Reviewer by any existing Maintainer. Reviewers can approve pull requests and are expected to provide timely, substantive code review. Reviewer status is confirmed by lazy consensus among Maintainers (no objection within 5 business days).

Reviewers do not have merge access but their approval counts toward the merge requirements in CONTRIBUTING.md.

### Maintainer

A Reviewer who has held that role for **at least 60 days** and has demonstrated sustained contributions: consistent review activity, issue triage, or code: may be nominated for Maintainer by any existing Maintainer. Maintainer status requires explicit approval by 2/3 of current Maintainers.

Maintainers have merge access to `main` and are collectively responsible for the health of the project.

**Inactive Maintainers** (no meaningful activity for 6 months) may be moved to emeritus status by a 2/3 maintainer vote after a 2-week notice period. Emeritus Maintainers retain their history and credit but lose merge access.

---

## Decision-making

### Day-to-day changes (lazy consensus)

Most decisions: feature additions, bug fixes, documentation, refactors: are made by **lazy consensus on pull requests**. A PR is mergeable when:

- At least one Maintainer has approved it, and
- No Maintainer has raised a blocking objection within **5 business days** of the last substantive change.

For security-critical paths (as defined in CONTRIBUTING.md), two Maintainer approvals are required.

### Breaking changes and governance changes (explicit vote)

The following require an **explicit vote** rather than lazy consensus:

- Any change to a public API that is not backward-compatible
- Changes to the TRACE Claim schema
- Changes to this GOVERNANCE.md or CONTRIBUTING.md
- Addition or removal of a Maintainer
- Changes to the relationship with the Agentic AI Foundation

An explicit vote is conducted by opening a GitHub Discussion tagged `vote`. It runs for **7 calendar days**. Each Maintainer has one vote. Participation is voluntary; abstentions do not count against quorum. A simple majority of votes cast decides the outcome, except where this document specifies a higher threshold.

### Dispute resolution

If a PR or proposal reaches an impasse, any Maintainer may call for a formal vote. If the vote does not resolve the dispute, the project lead makes the final call. A 2/3 majority of Maintainers is required to override a project lead decision.

Where the dispute involves the project lead, there is currently no external venue: AAIF hosting is proposed and not accepted, so the Foundation cannot arbitrate for this project yet. Until acceptance such a dispute is resolved by a 2/3 majority of the remaining Maintainers. On acceptance, escalation to the Foundation for binding resolution replaces that fallback.

---

## Amendments

Changes to this document require an explicit vote (see above). Ratification by the Agentic AI Foundation becomes an additional requirement only once AAIF hosting is accepted; requiring it today would make this document unamendable, since there is no Foundation relationship to ratify through.
