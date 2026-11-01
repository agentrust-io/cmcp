# cMCP rerun, October 1, 2026

Every experiment in the paper, rerun in fresh virtual environments.

## Revisions

| Label | agentrust-io/cmcp commit | What it is |
|---|---|---|
| pin | `6f12ccec9b1e37638471a663af485daa7a247340` | Last commit before the published perf run (2026-07-01T20:52Z): cmcp-runtime 0.3.0 plus four commits, including #368 |
| main | `a3f61e1a4d866bcd4fd2a149fff4da34b7e68597` | Main on 2026-09-30, cmcp-runtime 0.7.0 |

The pin environment was resolved with `uv pip install --exclude-newer 2026-07-02`, so its
dependencies are the versions available on the day of the published run
(`pip-freeze-pin.list`: agent-governance-toolkit-core 4.1.0, cedarpy 4.8.6). The main
environment uses current releases (`pip-freeze-main.list`: cedarpy 4.12.1, no AGT
dependency).

Host: Windows 11 build 26200, CPython 3.12.10 (AMD64), the same platform string as the
published `perf-2026-07-01.json`. No hardware TEE.

## Commands

From a cMCP checkout at each revision, after `pip install -e .`:

```
python experiments/claim1-policy-hash-binding/run.py
python experiments/claim2-session-vs-call-policy/run.py
python experiments/claim2-false-positive-rate/run.py
python experiments/claim3-rug-pull-detection/run.py
python experiments/claim4-trace-claim-nonce/run.py
python experiments/claim5-temporal-adjacency/run.py
python experiments/claim6-cross-org-attestation/run.py
python experiments/claim-hw-attestation/run.py
```

From `agentrust-io/cmcp` in this repository, with the same environment:

```
python experiments/perf/run.py --calls 8000 --warmup 1000 --out <file>
```

Outputs: `correctness-pin/`, `correctness-main/`, `perf-pin-6f12cce.json`,
`perf-main-a3f61e1.json`. The two `-contended` perf files were taken while another
audit job was running on the host and are kept only as a record; do not compare them.

## Correctness results

All seven software experiments exit 0 at both revisions with identical results.
`claim-hw-attestation` prints SKIP (no TEE on this host).

| Paper value | Published | Rerun (pin and main) |
|---|---|---|
| Policy hash, bits changed by one character | 51% | 131/256 (51%) |
| Session mode catches cross-boundary calls | 2/2 | 2/2 |
| Per-call mode catches | 0/2 | 0/2 |
| FDP by persona (CDS, Compliance, Mixed, Billing, Batch) | 0, 33, 67, 100, 100% | same |
| Overall FDP | 69% (11/16) | 69% (11/16) |
| Rug-pull description tamper, bits changed | 48% | 123/256 (48%) |
| Claim 4 sub-checks | 6 | 6 PASS |
| Claim 5 sub-checks, false negatives | 0 | 6 PASS, 0 |
| Claim 6 sub-checks | pass | 7 PASS |
| CI test counts (claims 1 to 6) | 6, 6, 6, 6, 9, 9 | 6, 6, 6, 6, 9, 9 (test files at pin) |

Only difference between revisions: claim 5 on main lists more high-sensitivity domains
(`hipaa_phi`, `mnpi`, `pci_data` added).

Counts the paper reports that no experiment or test performs: 100 hash computations,
100 catalog loads, 100 key substitutions, 1000 keypairs, 1000 salts, 100 session-id and
field modifications, 100 call traces, 1000 key pairs (claim 6). Each experiment runs one or
two inputs per check. Version 2 of the paper removes these counts.

## Performance (microseconds, 8,000 measured calls after 1,000 warmup)

12-rule breakdown:

| Metric | Published | Pin rerun | Main rerun |
|---|---|---|---|
| Cedar p50 | 644 | 589 | 423 |
| Cedar p95 | 1366 | 1633 | 1251 |
| Cedar p99 | 2849 | 3378 | 3026 |
| Cedar mean | 729 | 733 | 628 |
| Throughput (evals/s) | 1372 | 1365 | 1593 |
| Audit p50 | 51 | 51 | 46 |
| Audit p99 | 342 | 506 | 378 |

Rule-count sweep, Cedar p50 and p99:

| Rules | Published p50 | Pin p50 | Main p50 | Published p99 | Pin p99 | Main p99 |
|---|---|---|---|---|---|---|
| 4 | 384 | 488 | 458 | 2243 | 3117 | 2514 |
| 7 | 531 | 514 | 468 | 3221 | 2990 | 2502 |
| 14 | 702 | 589 | 628 | 3665 | 2385 | 2978 |
| 27 | 981 | 723 | 927 | 3765 | 4013 | 3197 |
| 52 | 1415 | 1540 | 1592 | 5182 | 10997 | 5316 |
| 102 | 2458 | 2744 | 2627 | 7280 | 9829 | 6944 |
| 202 | 2863 | 6292 | 4791 | 7574 | 21467 | 11420 |
| 402 | 5360 | 10771 | 7605 | 9662 | 26802 | 14853 |

The breakdown reproduces. The sweep reproduces to about 100 rules; at 202 and 402 rules the
pin rerun is about twice the published p50. Each configuration is a single run, with no
repetition or confidence interval, so the published large-bundle points cannot be
distinguished from noise. The published 202-rule p50 (16% above 102 rules) is the outlier.

## Not repeatable here

- `claim-hw-attestation` needs a confidential VM (SEV-SNP, TDX or TPM). It SKIPs here.
- The Azure SEV-SNP capture in the cMCP repo
  (`experiments/hardware-validation/cmcp-in-tee-azure-2026-07-27/`) was not re-executed.

The two environment records were renamed from `requirements-*.txt` to `pip-freeze-*.list` on 2026-10-19 so Dependabot stops reading them as installable manifests (it treats any `.txt` or `.in` file whose lines all parse as requirements as one); their contents are unchanged from the published source.
