# cMCP: Verifiable Policy Enforcement for AI Agent Tool Calls

Technical report, version 2, October 1, 2026. Not peer reviewed. Patent Pending.
Version 2 corrects statements that did not match the code or the experiments, names the
measured revision and the security advisories that affect it, and restores bold and italic type.

Build: `tectonic paper.tex` (prepared with Tectonic 0.16.9; set SOURCE_DATE_EPOCH=1790812800
to reproduce the published PDF byte for byte).

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/cmcp.

This package contains the manuscript source, figures, the performance runner and the October 1,
2026 rerun of every experiment in `experiments/results/rerun-2026-10-01/`, at cMCP commit
6f12cce (cmcp-runtime 0.3.0 plus four commits, the state measured on July 1) and at main
a3f61e1. Correctness results are unchanged. The two `-contended` performance files were taken
while another job ran on the host and are kept only as a record. Software only; no hardware TEE.
Current implementation guidance: https://cmcp.agentrust-io.com/
