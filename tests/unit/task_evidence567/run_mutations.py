"""Finite, local-only A–G mutation check for the #567 test-only helpers.

Every mutant runs the full focused suite in its own disposable COPY. Never
mutates repository files. Assertion failures at named tests are required;
collection/import errors, skips, zero exit, or a dead restored control fail
this script. Use --output-dir with a new path outside the checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


def hashes(root: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.py"))}


def execute(repo: Path, suite: Path, output: Path, name: str) -> dict:
    xml = output / f"{name}.xml"
    command = [sys.executable, "-m", "pytest", "-c", str(repo / "pyproject.toml"),
               str(suite), "-q", "-p", "no:cacheprovider", "--import-mode=importlib",
               f"--junitxml={xml}"]
    env = {**os.environ, "PYTHONPATH": str(repo / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run(command, cwd=repo, env=env, text=True, capture_output=True, check=False)
    (output / f"{name}.txt").write_text(done.stdout + done.stderr)
    parsed = ET.parse(xml).getroot()
    cases = list(parsed.iter("testcase"))
    failures = [{"test": case.attrib["name"], "message": case.find("failure").attrib.get("message", "")}
                for case in cases if case.find("failure") is not None]
    return {"command": command, "exit": done.returncode, "tests": len(cases),
            "failures": failures, "errors": len(list(parsed.iter("error"))),
            "skips": len(list(parsed.iter("skipped")))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    repo = source.parents[2]
    output = args.output_dir.resolve()
    if output == repo or repo in output.parents:
        raise ValueError("Use a new output directory outside the checkout")
    output.mkdir(parents=True, exist_ok=False)
    before = hashes(source)
    # Fixed before running; no expected assertion or fixture input is changed.
    mutations = (
        ("A_positive_relation", "authority_origin.py",
         'return Boundary(ESTABLISHED, "trusted_policy_includes_exact_request")',
         'return Boundary(NOT_ESTABLISHED, "trusted_policy_includes_exact_request")',
         "test_am03_authority_worlds_preserve_ack[AM03-positive]",
         "test_am03_authority_worlds_preserve_ack[AM03-authentication-only-no-authority]"),
        ("B_subject_binding", "accounting.py",
         "if row.subject is subject and row.boundary == boundary",
         "if row.subject is not None and row.boundary == boundary",
         "test_wrong_subject_does_not_discharge_another_creation",
         "test_exact_one_accounts_without_upgrading_disposition[AM12-NE]"),
        ("C_malformed_filtering", "accounting.py",
         "if row.subject is subject and row.boundary == boundary",
         "if row.subject is subject and row.boundary == boundary and eligible_assessment(row)",
         "test_valid_plus_malformed_duplicate_cannot_be_filtered_to_pass[AM12-VALID-PLUS-MALFORMED-DUPLICATE]",
         "test_exact_one_accounts_without_upgrading_disposition[AM12-POSITIVE]"),
        ("D_all_positive_authority", "authority_origin.py",
         "boundary = _authority_boundary(evidence)",
         'boundary = Boundary(ESTABLISHED, "forced_positive")',
         "test_am03_authority_worlds_preserve_ack[AM03-authentication-only-no-authority]",
         None),
        ("E_creation_label_echo", "observations.py",
         "or not _sep2663_creation_discriminator_guard(response.payload)",
         "or False",
         "test_am01_wrong_discriminator_is_not_promoted_by_signed_type_label",
         "test_am01_exact_create_task_result_source_at_return_only"),
        ("F_self_derived_origin", "authority_origin.py",
         "    origin_projection = creation_projection\n",
         "    origin_projection = CreationProjection(\n"
         "        task=creation_projection.task,\n"
         "        call_id=entry.call_id,\n"
         "        request_hash=entry.request_payload_hash,\n"
         "        server_identity=entry.server_identity,\n"
         "        tool_name=entry.tool_name,\n"
         "        execution_id=creation_projection.execution_id,\n"
         "    )\n",
         "test_am10_different_task_with_fresh_source_and_scope_cannot_join_entry",
         "test_am10_positive_committed_origin_and_execution_are_established"),
        ("G_forbidden_origin_cascade", "authority_origin.py",
         '            Boundary(CONTRADICTION, "origin_projection_disagrees_with_committed_entry"),\n'
         '            Boundary(NOT_ESTABLISHED, "dependent_execution_join_lacks_supported_origin"),\n'
         '            correlation,\n',
         '            Boundary(CONTRADICTION, "origin_projection_disagrees_with_committed_entry"),\n'
         '            Boundary(NOT_ESTABLISHED, "dependent_execution_join_lacks_supported_origin"),\n'
         '            Boundary(NOT_ESTABLISHED, "forbidden_origin_cascade"),\n',
         "test_am10_m17_wrong_origin_call_preserves_entry_to_entry_correlation",
         "test_am10_positive_committed_origin_and_execution_are_established"),
    )
    baseline = execute(repo, source, output, "baseline")
    results = []
    good = baseline["exit"] == 0 and not baseline["errors"] and not baseline["skips"]
    if good:
        for name, file, old, new, decisive, surviving_control in mutations:
            with tempfile.TemporaryDirectory(prefix=f"cmcp567-{name}-") as temporary:
                copied = Path(temporary) / "task_evidence567"
                shutil.copytree(source, copied, ignore=shutil.ignore_patterns("__pycache__"))
                target = copied / file
                original = target.read_bytes()
                assert original.decode().count(old) == 1, "Mutation anchor must be exact and unique"
                target.write_bytes(original.decode().replace(old, new, 1).encode())
                run = execute(repo, copied, output, name)
                failed_tests = {item["test"] for item in run["failures"]}
                decisive_failure = any(item["test"] == decisive and "assert" in item["message"]
                                       for item in run["failures"])
                killed = (run["exit"] == 1 and run["errors"] == 0 and run["skips"] == 0
                          and decisive_failure and run["tests"] == baseline["tests"]
                          and (surviving_control is None or surviving_control not in failed_tests))
                target.write_bytes(original)
                restored = target.read_bytes() == original and hashes(copied) == before
                restored_run = execute(repo, copied, output, f"{name}-restored")
                source_unchanged = hashes(source) == before
                result = {"name": name, "expected": "named assertion fails, full suite exits 1",
                          "decisive_test": decisive, "surviving_control": surviving_control,
                          "run": run, "decisive": killed, "restored_byte_exact": restored,
                          "restored_run": restored_run, "source_unchanged": source_unchanged}
                results.append(result)
                good = (good and killed and restored and source_unchanged
                        and restored_run["exit"] == 0 and restored_run["tests"] == baseline["tests"]
                        and restored_run["errors"] == 0 and restored_run["skips"] == 0)
    report = {"baseline": baseline, "mutations": results, "source_hashes_before": before,
              "source_hashes_after": hashes(source), "source_unchanged": hashes(source) == before}
    report["pass"] = good and len(results) == len(mutations) and report["source_unchanged"]
    (output / "RESULTS.json").write_text(json.dumps(report, indent=2) + "\n")
    sys.stdout.write(json.dumps({"pass": report["pass"], "mutations": [
        {"name": r["name"], "exit": r["run"]["exit"], "failures": len(r["run"]["failures"]),
         "errors": r["run"]["errors"], "decisive": r["decisive"],
         "restored": r["restored_byte_exact"], "restored_exit": r["restored_run"]["exit"]}
        for r in results]}, indent=2) + "\n")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
