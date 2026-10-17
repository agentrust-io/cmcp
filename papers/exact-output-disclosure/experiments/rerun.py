"""Rerun every software experiment in the exact-output disclosure report.

Exports the evaluated cMCP revision from a local clone with `git archive`, then runs,
each in a fresh copy:

1. the existing disclosure test suite, unchanged (baseline);
2. the same suite with one control removed at a time (control removals);
3. concurrency.py: thread race, lost acknowledgment, storage rollback;
4. delivery_faults.py: process kills, storage faults and a recording receiver,
   on the unmodified source and on a copy with replay consumption removed.

Every count is compared with the values recorded when the report was written
(EXPECTED below). Local absolute paths are replaced by placeholders before
anything is written.

Usage, from this directory, with a Python that has the dependencies installed:

    python -B rerun.py --repo <cmcp clone> --output <new directory> [--revision SHA]

--revision defaults to the evaluated commit. Passing a later commit runs the same
suite and experiments against it; control removals whose source fragment no longer
exists are recorded as not applicable rather than failing the run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
REPO_NAME = "cmcp"
EVALUATED = "2cdb168ce52020406ff0ef6cbc34447f0ea55aee"
PYTHONPATH = ["src", ""]
SUITE = ["tests/unit/test_disclosure.py"]
SUITE_CWD = ""
# (label, file, exact fragment, replacement)
REMOVALS = [
    ("binding", "src/cmcp_runtime/disclosure.py",
     '"output_sha256": hashlib.sha256(request.payload).hexdigest(),', '"output_sha256": "omitted",'),
    ("replay", "src/cmcp_runtime/disclosure.py",
     "if not self._store.consume(request.request_id):", "if False:"),
]
SUITE_REMOVALS = ("binding", "replay")
# (label, script, removal label or None). A control must fail its criterion.
EXPERIMENTS = [
    ("concurrency", "concurrency.py", None),
    ("delivery-faults", "delivery_faults.py", None),
    ("delivery-faults-control-skip-consumption", "delivery_faults.py", "replay"),
]
EXPECTED = {  # recorded 2026-09-23 (suite, removals, concurrency) and 2026-09-27 (delivery faults)
    "baseline": {"tests": 46, "failures": 0},
    "binding": {"tests": 46, "failed_cases": [
        "test_independent_serialization_verifies",
        "test_substitution_rejected_before_delivery[payload-synthetic confidential canary 660!]"]},
    "replay": {"tests": 46, "failed_cases": [
        "test_expiry_rechecked_after_storage_wait", "test_replay_survives_reopen_and_failed_delivery",
        "test_shared_store_concurrent_attempts_deliver_once", "test_storage_failure_never_reaches_recipient"]},
    "concurrency": {"criterion_met": True},
    "delivery-faults": {"cases_passed": 9, "cases_total": 9, "criterion_met": True},
    "delivery-faults-control-skip-consumption": {"cases_passed": 0, "cases_total": 9, "criterion_met": False},
}
PACKAGES = ["cryptography", "pytest", "pytest-asyncio", "pydantic", "rfc8785", "httpx", "starlette",
            "cedarpy", "agent-manifest", "agentrust-trace", "pyyaml", "anyio", "click", "uvicorn"]


class Scrubber:
    def __init__(self, mapping):
        pairs = []
        for real, label in mapping:
            s = str(real)
            for form in {s, s.replace("\\", "/"), s.replace("/", "\\"), s.replace("\\", "\\\\")}:
                pairs.append((form, label))
        self.pairs = sorted(pairs, key=lambda p: -len(p[0]))

    def __call__(self, text: str) -> str:
        for real, label in self.pairs:
            text = re.sub(re.escape(real), lambda _m, l=label: l, text, flags=re.IGNORECASE)
        return re.sub(r'hostname="[^"]*"', 'hostname="<host>"', text)


def export(repo: Path, revision: str, dest: Path) -> str:
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", revision + "^{commit}"],
                                  text=True, creationflags=NO_WINDOW).strip()
    data = subprocess.check_output(["git", "-C", str(repo), "archive", sha], creationflags=NO_WINDOW)
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(dest, filter="data")
    return sha


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--revision", default=EVALUATED)
    args = ap.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    if (out / "summary.json").exists():
        raise SystemExit("Use a new output directory.")
    scratch = Path(tempfile.mkdtemp(prefix="study-rerun-"))
    scrub = Scrubber([(scratch, "<scratch>"), (args.repo.resolve(), "<repo>"), (Path(sys.executable).parent, "<python>"),
                      (Path(sys.prefix), "<venv>"), (HERE, "<experiments>"), (out.resolve(), "<output>"),
                      (Path.home(), "<home>")])
    env_base = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    clean = scratch / "source"
    sha = export(args.repo, args.revision, clean)
    evaluated = sha == EVALUATED
    runs = []

    def env_for(root: Path):
        return {**env_base, "PYTHONPATH": os.pathsep.join(str(root / p) if p else str(root) for p in PYTHONPATH)}

    def suite(label: str, root: Path, removal=None):
        report = scratch / f"{label}.xml"
        cmd = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin", "-q",
               "--tb=short", "--basetemp=" + str(scratch / f"{label}-tmp"), "--junitxml=" + str(report), *SUITE]
        begin = time.perf_counter()
        done = subprocess.run(cmd, cwd=root / SUITE_CWD if SUITE_CWD else root, env=env_for(root),
                              capture_output=True, text=True, timeout=900, creationflags=NO_WINDOW)
        rec = {"label": label, "kind": "suite", "exit_code": done.returncode,
               "seconds": round(time.perf_counter() - begin, 1),
               "command": "python -B -m pytest -p no:cacheprovider -p pytest_asyncio.plugin -q --tb=short "
                          + " ".join(SUITE), "removal": removal}
        (out / f"{label}.log").write_text(scrub(done.stdout + "\nSTDERR\n" + done.stderr), encoding="utf-8")
        if report.exists():
            (out / f"{label}.xml").write_text(scrub(report.read_text(encoding="utf-8")), encoding="utf-8")
            tree = ET.parse(report)
            suites = tree.getroot().iter("testsuite")
            totals = {k: 0 for k in ("tests", "failures", "errors", "skipped")}
            for s in suites:
                for k in totals:
                    totals[k] += int(s.attrib.get(k, "0"))
            rec.update(totals)
            rec["failed_cases"] = sorted(c.attrib["name"] for c in tree.iter("testcase")
                                         if c.find("failure") is not None or c.find("error") is not None)
        runs.append(rec)
        print(json.dumps({k: rec.get(k) for k in ("label", "exit_code", "tests", "failures", "errors")}), flush=True)
        return rec

    def experiment(label: str, script: str, root: Path, removal=None):
        cmd = [sys.executable, "-B", str(HERE / script), "run", str(scratch / "work" / label)]
        begin = time.perf_counter()
        done = subprocess.run(cmd, cwd=root / SUITE_CWD if SUITE_CWD else root, env=env_for(root),
                              capture_output=True, text=True, timeout=1800, creationflags=NO_WINDOW)
        try:
            result = json.loads(done.stdout)
        except json.JSONDecodeError:
            result = {"criterion_met": False, "unparsed_stdout_tail": done.stdout[-2000:]}
        (out / f"{label}.json").write_text(scrub(json.dumps(result, indent=2)), encoding="utf-8")
        if done.stderr.strip():
            (out / f"{label}.stderr.log").write_text(scrub(done.stderr[-20000:]), encoding="utf-8")
        rec = {"label": label, "kind": "experiment", "script": script, "exit_code": done.returncode,
               "criterion_met": result.get("criterion_met"), "cases_passed": result.get("cases_passed"),
               "cases_total": result.get("cases_total"), "seconds": round(time.perf_counter() - begin, 1),
               "command": f"python -B {script} run <scratch>", "removal": removal}
        runs.append(rec)
        print(json.dumps({k: rec[k] for k in ("label", "exit_code", "criterion_met", "cases_passed", "cases_total")}),
              flush=True)
        return rec

    def removed_copy(name: str):
        label, file, old, new = next(r for r in REMOVALS if r[0] == name)
        root = scratch / f"copy-{name}-{len(runs)}"
        shutil.copytree(clean, root)
        path = root / file
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            return None, {"file": file, "fragment": old, "applicable": False}
        path.write_text(text.replace(old, new), encoding="utf-8")
        return root, {"file": file, "fragment": old, "replacement": new, "applicable": True,
                      "original_sha256": hashlib.sha256(text.encode()).hexdigest()}

    suite("baseline", clean)
    for name in SUITE_REMOVALS:
        root, removal = removed_copy(name)
        if root is None:
            runs.append({"label": name, "kind": "suite", "removal": removal, "not_applicable": True})
            continue
        suite(name, root, removal)
    for label, script, removal_name in EXPERIMENTS:
        if removal_name is None:
            experiment(label, script, clean)
            continue
        root, removal = removed_copy(removal_name)
        if root is None:
            runs.append({"label": label, "kind": "experiment", "removal": removal, "not_applicable": True})
            continue
        experiment(label, script, root, removal)

    comparison = {}
    for rec in runs:
        want = EXPECTED.get(rec["label"])
        if want is None or rec.get("not_applicable"):
            continue
        got = {k: rec.get(k) for k in want}
        if "failed_cases" in got:
            got["failed_cases"] = sorted(got["failed_cases"] or [])
            want = {**want, "failed_cases": sorted(want["failed_cases"])}
        comparison[rec["label"]] = {"expected": want, "observed": got, "matches": got == want}

    def valid(rec):
        if rec.get("not_applicable"):
            return True
        if rec["kind"] == "suite":
            if rec["removal"] is None:
                return rec["exit_code"] == 0 and rec.get("tests", 0) > 0
            return rec["exit_code"] == 1 and rec.get("failures", 0) > 0 and rec.get("errors", 1) == 0
        if rec["removal"] is None:
            return rec["exit_code"] == 0 and rec["criterion_met"] is True
        return rec["exit_code"] == 1 and rec["criterion_met"] is False

    for rec in runs:
        rec["valid"] = valid(rec)
    versions = {}
    for name in PACKAGES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    git_version = subprocess.run(["git", "--version"], capture_output=True, text=True,
                                 creationflags=NO_WINDOW).stdout.strip()
    summary = {
        "report": "exact-output-disclosure", "started_utc": started,
        "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "software_only": True, "repository": f"https://github.com/agentrust-io/{REPO_NAME}",
        "revision": sha, "is_evaluated_revision": evaluated,
        "python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
        "git": git_version, "package_versions": versions,
        "all_installed_distributions": {d.metadata["Name"]: d.version for d in importlib.metadata.distributions()},
        "command": f"python -B rerun.py --repo <repo> --output <output> --revision {sha}",
        "harness_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.glob("*.py"))},
        "runs": runs, "comparison_with_recorded_values": comparison,
        "all_runs_valid": all(r["valid"] for r in runs),
        "all_match_recorded_values": all(c["matches"] for c in comparison.values()),
    }
    (out / "summary.json").write_text(scrub(json.dumps(summary, indent=2)), encoding="utf-8")
    leftovers = [f.name for f in out.rglob("*") if f.is_file() and re.search(
        r"[A-Za-z]:[\\/]+Users|/home/|Users[\\/]+\w+", f.read_text(encoding="utf-8", errors="ignore"))]
    sums = {f.relative_to(out).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted(out.rglob("*")) if f.is_file() and f.name != "SHA256SUMS.json"}
    (out / "SHA256SUMS.json").write_text(json.dumps(sums, indent=2), encoding="utf-8")
    shutil.rmtree(scratch, ignore_errors=True)
    print(json.dumps({"all_runs_valid": summary["all_runs_valid"],
                      "all_match_recorded_values": summary["all_match_recorded_values"],
                      "path_leftovers": leftovers}), flush=True)
    raise SystemExit(0 if summary["all_runs_valid"] and not leftovers else 1)


if __name__ == "__main__":
    main()
