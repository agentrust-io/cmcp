# Exact-Output Disclosure for Agent Workflows

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `python build_paper.py --source . --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF
1.28.2). It reads Times New Roman, Arial and Courier New TrueType files from `--fonts`
(default `C:/Windows/Fonts`); fonts are not bundled. `manifest.json` lists the SHA-256 of
every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/cmcp.

The report evaluates cMCP 2cdb168 (merged in cMCP PR 672 on September 19, 2026). Rerun the
experiments from this directory with a Python 3.12 environment that has pytest, pytest-asyncio,
cryptography, rfc8785 and the other cmcp-runtime dependencies installed:

    python -B experiments/rerun.py --repo <cmcp clone> --output <new directory> [--revision <commit>]

`experiments/results/rerun-2026-10-01/` holds the October 1 runs at the evaluated revision
(`evaluated-2cdb168/`) and at main a3f61e1 (`main-a3f61e1/`). Each `summary.json` records
commands, package versions and every count; local paths are replaced by placeholders.

Software only, on one Windows host with synthetic payloads, generated Ed25519 keys, a local
SQLite ledger and a loopback recipient.
Current implementation guidance: https://cmcp.agentrust-io.com/
