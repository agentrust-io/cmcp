# What Does an AI Kill Switch Prove?

Technical report, version 2, October 11, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.
Patent Pending. Version 2 adds the external evaluation (section 9); no version 1 result changes.

Build: `python build_paper.py --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF 1.28.2). It reads
times.ttf, timesbd.ttf and arial.ttf from `--fonts` (default `C:/Windows/Fonts`); fonts are not
bundled. `manifest.json` lists the SHA-256 of every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/cmcp.

The report evaluates cMCP 9db65b589610eb4e8455003197de592636678203. Reproduce with Python 3.12
from this directory (on POSIX use `.venv/bin/python`):

    git clone https://github.com/agentrust-io/cmcp.git subjects/cmcp
    git -C subjects/cmcp checkout --detach 9db65b589610eb4e8455003197de592636678203
    python -m venv .venv
    .venv/Scripts/python -m pip install --require-hashes -r subjects/cmcp/requirements/dev.txt
    .venv/Scripts/python -m pip install --no-deps -e subjects/cmcp
    .venv/Scripts/python experiments/matrix.py --source subjects/cmcp --output fresh-results

The matrix runs the 27-assertion exercise and the two targeted weakenings, and exits nonzero if
any outcome differs from its expectation. Every listener binds to 127.0.0.1; no cloud resource,
model API or real credential is used.

The 81 cMCP component tests are tests/unit/test_kill_switch.py, test_kill_switch_durable.py,
test_kill_switch_mid_session.py, test_kill_switch_evidence.py and test_policy_key_revocation.py,
run with pytest from the pinned checkout. The 38 cA2A revocation tests are
tests/unit/test_revocation.py at agentrust-io/ca2a 540a578c462a413e829bed84aff0235b9018f676,
installed the same way from its requirements/dev.txt.

`experiments/results/reference/` holds the retained run; `rerun-2026-09-27/` and
`rerun-2026-10-01/` are later repetitions with the same outcomes, each summarized in its
rerun.json. All three were operated by the author. Logs replace local paths with placeholders.
`independent-2026-10-11/` holds the external evaluator's returned records, unchanged, with
received.json giving the hash of the package as received.
`comparison.md` records the primary-source comparison behind section 6.

Not run: a language model, confidential hardware, independently operated peers and database
rollback. The external evaluation is one individual's run with gateway and observer under one
administrator; it is not a certification.
Current implementation guidance: https://cmcp.agentrust-io.com/
