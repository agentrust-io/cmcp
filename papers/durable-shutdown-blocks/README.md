# When an Agent Kill Switch Trips

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `python build_paper.py --source . --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF
1.28.2). It reads Times New Roman, Arial and Courier New TrueType files from `--fonts`
(default `C:/Windows/Fonts`); fonts are not bundled. `manifest.json` lists the SHA-256 of
every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/cmcp.

The report evaluates cMCP 2cdb168ce52020406ff0ef6cbc34447f0ea55aee. Reproduce with Python 3.12
from this directory:

    git clone https://github.com/agentrust-io/cmcp.git subjects/cmcp
    git -C subjects/cmcp checkout --detach 2cdb168ce52020406ff0ef6cbc34447f0ea55aee
    python -m venv .venv
    .venv/Scripts/python -m pip install --require-hashes -r subjects/cmcp/requirements/dev.txt
    .venv/Scripts/python -B experiments/run.py --source subjects/cmcp --output fresh-results

`experiments/results/rerun-2026-10-01/` holds the October 1 rerun at that commit and
`experiments/results/main-a3f61e1-2026-10-01/` the same run against cMCP main.
`experiments/reference-2026-09.json` holds the earlier outcomes the rerun is compared with. The
freshness protocol in `experiments/trip_and_observation.py` is harness code, not cMCP code.

Not run: the Linux container isolation suite, any hardware-backed key, and multi-region
propagation.
Current implementation guidance: https://cmcp.agentrust-io.com/
