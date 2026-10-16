"""Rerun every software result in this report from a pinned cMCP commit.

Steps, all on a fresh export of the pinned commit (git archive) in a temporary directory:

1. The six selected test files (86 tests).
2. Two control removals, each on an isolated copy: the durable block lookup and the refusal
   signature check. Each must make the selected tests fail.
3. store_scope.py: block persistence across 20 reopened stores, and an independent store.
4. trip_and_observation.py: the operator trip with slow operations in flight and the
   fresh-observation prototype, then its two controls (admission halt check removed;
   verifier without the nonce check). Each control must fail the criterion.

Results are compared with reference-2026-09.json. Local paths are replaced with placeholders.

  python experiments/run.py --source <cmcp clone> --output experiments/results/rerun-YYYY-MM-DD

Run it with the interpreter of a virtual environment built from the pinned
requirements/dev.txt. No network, cloud, container or repository writes.
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
PIN = "2cdb168ce52020406ff0ef6cbc34447f0ea55aee"
SELECTION = ["tests/unit/test_kill_switch.py", "tests/unit/test_kill_switch_durable.py",
             "tests/unit/test_kill_switch_evidence.py", "tests/unit/test_kill_switch_mid_session.py",
             "tests/confinement/test_adapter.py", "tests/confinement/test_gateway.py"]
MUTANTS = [  # (label, file, exact fragment, replacement)
    ("durable-block", "src/cmcp_runtime/kill_switch.py",
     "return self._store.is_blocked(agent_id)", "return False"),
    ("receipt-signature", "src/cmcp_verify/kill_switch.py",
     "public_key.verify(_b64url_decode(signature), _canonical_json(receipt))", "pass  # signature check removed"),
]
CONTROLS = [  # (label, file or None, fragment, replacement, extra args)
    ("halt-admission", "src/cmcp_runtime/mcp/proxy.py",
     "            self._ensure_not_halted()\n", "            pass\n", []),
    ("no-nonce-check", None, "", "", ["--no-nonce-check"]),
]
VERSIONS = ["pytest", "pytest-asyncio", "cryptography", "pydantic", "rfc8785", "agent-manifest",
            "agentrust-trace", "cedarpy", "httpx", "starlette", "anyio", "mcp"]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, creationflags=NO_WINDOW, **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", type=Path, required=True, help="a git clone of agentrust-io/cmcp")
    ap.add_argument("--commit", default=PIN)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit("Use a new, empty output directory.")
    out.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="shutdown-blocks-"))
    src_repo = args.source.resolve()
    pairs = sorted([(str(scratch), "<scratch>"), (str(src_repo), "<source>"), (str(out), "<output>"),
                    (str(HERE), "<experiments>"), (str(Path(sys.executable).parent.parent), "<venv>"),
                    (str(Path(sys.base_prefix)), "<python>"), (str(Path.home()), "<home>"),
                    (tempfile.gettempdir(), "<tmp>")], key=lambda p: -len(p[0]))

    def scrub(text: str, xml: bool = False) -> str:
        for real, label in pairs:
            if xml:
                label = label.replace("<", "&lt;").replace(">", "&gt;")
            for form in {real, real.replace("\\", "/"), real.replace("\\", "\\\\")}:
                text = re.sub(re.escape(form), label, text, flags=re.IGNORECASE)
        host = "&lt;host&gt;" if xml else "<host>"
        return re.sub(r'hostname="[^"]*"', f'hostname="{host}"', text)

    git = ["git", "-c", f"safe.directory={src_repo.as_posix()}", "-C", str(src_repo)]
    tree = sh(git + ["rev-parse", args.commit + "^{tree}"], check=True).stdout.strip()
    snap = scratch / "cmcp"
    snap.mkdir()
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(git + ["archive", args.commit],
                                                                 creationflags=NO_WINDOW))) as tar:
        tar.extractall(snap, filter="data")
    env_base = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    env_base.pop("PYTHONPATH", None)
    ref = json.loads((HERE / "reference-2026-09.json").read_text(encoding="utf-8"))
    record = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "subject": "agentrust-io/cmcp", "commit": args.commit, "tree": tree,
              "python": platform.python_version(), "platform": platform.platform(),
              "package_versions": {n: _version(n) for n in VERSIONS},
              "installed_distributions": {d.metadata["Name"]: d.version
                                          for d in importlib.metadata.distributions()},
              "software_only": True, "pytest": {}, "boundary": None, "experiment": None, "controls": {}}

    def env_for(root):
        return {**env_base, "PYTHONPATH": os.pathsep.join([str(root / "src"), str(root)])}

    def pytest(label, root):
        report = out / f"pytest-{label}.xml"
        cmd = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin",
               "-q", "--tb=short", f"--basetemp={scratch / (label + '-tmp')}", f"--junitxml={report}", *SELECTION]
        begin = time.perf_counter()
        done = sh(cmd, cwd=root, env=env_for(root), timeout=600)
        (out / f"pytest-{label}.log").write_text(scrub(done.stdout + "\nSTDERR\n" + done.stderr), encoding="utf-8")
        parsed = ET.parse(report)
        counts = {k: 0 for k in ("tests", "failures", "errors", "skipped")}
        for s in parsed.getroot().iter("testsuite"):
            for k in counts:
                counts[k] += int(s.attrib.get(k, "0"))
        failed = sorted(c.attrib["name"] for c in parsed.iter("testcase") if c.find("failure") is not None)
        report.write_text(scrub(report.read_text(encoding="utf-8"), xml=True), encoding="utf-8")
        ET.parse(report)  # the scrubbed report must still be well-formed XML
        rec = {"exit_code": done.returncode, **counts, "failed_cases": failed,
               "duration_seconds": round(time.perf_counter() - begin, 1),
               "command": scrub(" ".join(["python"] + cmd[1:]))}
        prior = ref["pytest"][label]
        rec["matches_reference"] = (all(rec[k] == prior[k] for k in ("exit_code", "tests", "failures", "errors", "skipped"))
                                    and failed == sorted(prior["failed_cases"]))
        record["pytest"][label] = rec
        print(json.dumps({label: {k: rec[k] for k in ("exit_code", "tests", "failures", "matches_reference")}}),
              flush=True)

    def mutate(label, file, old, new):
        root = scratch / ("copy-" + label)
        shutil.copytree(snap, root)
        path = root / file
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise SystemExit(f"{label}: expected exactly one match in {file}")
        path.write_text(text.replace(old, new), encoding="utf-8")
        return root, {"file": file, "old": old, "new": new}

    pytest("baseline", snap)
    for label, file, old, new in MUTANTS:
        root, mutation = mutate(label, file, old, new)
        pytest(label, root)
        record["pytest"][label]["mutation"] = mutation

    done = sh([sys.executable, "-B", str(HERE / "store_scope.py"), str(scratch / "store-scope")],
              cwd=snap, env=env_for(snap), timeout=300)
    boundary = json.loads(done.stdout) if done.returncode == 0 else {"stderr": scrub(done.stderr[-4000:])}
    record["boundary"] = {"exit_code": done.returncode, "result": boundary,
                          "matches_reference": boundary == ref["boundary"],
                          "command": "python -B experiments/store_scope.py <scratch>"}
    (out / "store-scope.json").write_text(json.dumps(boundary, indent=2), encoding="utf-8")
    print(json.dumps({"store-scope": done.returncode}), flush=True)

    def experiment(label, root, extra):
        cmd = [sys.executable, "-B", str(HERE / "trip_and_observation.py"), "run", str(scratch / ("exp-" + label)), *extra]
        d = sh(cmd, cwd=root, env=env_for(root), timeout=900)
        try:
            result = json.loads(d.stdout)
        except json.JSONDecodeError:
            result = {"criterion_met": False, "stdout_tail": d.stdout[-3000:], "stderr_tail": d.stderr[-3000:]}
        result = json.loads(scrub(json.dumps(result)))
        (out / f"{label}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        rec = {"exit_code": d.returncode, "cases_passed": result.get("cases_passed"),
               "cases_total": result.get("cases_total"), "criterion_met": result.get("criterion_met"),
               "command": "python -B experiments/trip_and_observation.py run <scratch> " + " ".join(extra)}
        print(json.dumps({label: rec}), flush=True)
        return rec, result

    rec, result = experiment("trip-and-observation", snap, [])
    rec["valid"] = rec["exit_code"] == 0 and rec["criterion_met"] is True
    rec["matches_reference"] = _same_outcomes(result, ref["experiment"])
    record["experiment"] = rec
    for label, file, old, new, extra in CONTROLS:
        root, mutation = mutate(label, file, old, new) if file else (snap, None)
        rec, result = experiment("control-" + label, root, extra)
        rec["mutation"] = mutation
        rec["valid"] = rec["exit_code"] == 1 and rec["criterion_met"] is False
        rec["matches_reference"] = _same_outcomes(result, ref["controls"][label])
        record["controls"][label] = rec

    p = record["pytest"]
    record["summary"] = {
        "baseline_passed": p["baseline"]["exit_code"] == 0 and p["baseline"]["failures"] == 0,
        "baseline_tests": p["baseline"]["tests"],
        "mutations_detected": {k: p[k]["failures"] for k in p if k != "baseline"},
        "experiment_cases": f'{record["experiment"]["cases_passed"]} of {record["experiment"]["cases_total"]}',
        "controls_failing_as_required": sum(c["valid"] for c in record["controls"].values()),
        "all_match_reference": (all(r["matches_reference"] for r in p.values())
                                and record["boundary"]["matches_reference"]
                                and record["experiment"]["matches_reference"]
                                and all(c["matches_reference"] for c in record["controls"].values())),
    }
    (out / "commands.txt").write_text(
        "# Environment (Python 3.12), from a clone of agentrust-io/cmcp\n"
        f"git -C <source> checkout --detach {args.commit}\n"
        "python -m venv <venv>\n"
        "<venv>/Scripts/python -m pip install --require-hashes -r <source>/requirements/dev.txt\n"
        "# Run (from this report's directory)\n"
        f"<venv>/Scripts/python -B experiments/run.py --source <source> --commit {args.commit} --output <output>\n"
        "# Individual commands, as executed\n"
        + "\n".join([r["command"] for r in record["pytest"].values()] + [record["boundary"]["command"],
                     record["experiment"]["command"]] + [c["command"] for c in record["controls"].values()]) + "\n",
        encoding="utf-8")
    record["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record["harness_sha256"] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(HERE.glob("*.py"))}
    (out / "run.json").write_text(scrub(json.dumps(record, indent=2)), encoding="utf-8")
    shutil.rmtree(scratch, ignore_errors=True)
    leftovers = [f.name for f in out.iterdir() if re.search(r"[A-Za-z]:[\\/]+Users|/home/|Users[\\/]+\w+[\\/]",
                                                            f.read_text(encoding="utf-8", errors="ignore"))]
    sums = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(out.iterdir()) if f.is_file()}
    (out / "SHA256SUMS.json").write_text(json.dumps(sums, indent=2), encoding="utf-8")
    print(json.dumps({**record["summary"], "path_leftovers": leftovers}), flush=True)
    ok = (record["summary"]["baseline_passed"] and not leftovers and record["experiment"]["valid"]
          and all(p[k]["exit_code"] == 1 and p[k]["failures"] > 0 for k in p if k != "baseline")
          and all(c["valid"] for c in record["controls"].values()))
    raise SystemExit(0 if ok else 1)


def _version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _same_outcomes(new, old):
    """Compare pass/fail outcomes and observed states; ignore timings."""
    def strip(x):
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if not (k.endswith("_ms_after_start") or k.endswith("_ms_after_trip_start")
                                                              or k in ("observed_at", "experiment"))}
        if isinstance(x, list):
            return [strip(v) for v in x]
        return x
    return strip(new) == strip(old)


if __name__ == "__main__":
    main()
