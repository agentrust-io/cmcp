"""Run positive and targeted mutation controls; unrelated failures never count as coverage."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--source", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
rows = []
for mutation, expected in [
    ("none", None),
    ("forget-block", "restart-retains-block"),
    ("disable-auto", "automatic-trip-refuses-allowed-tool"),
]:
    out = a.output / mutation
    cmd = [
        sys.executable,
        str(Path(__file__).with_name("run.py")),
        "--source",
        str(a.source),
        "--output",
        str(out),
        "--mutation",
        mutation,
    ]
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False
    )
    (a.output / f"{mutation}.log").write_bytes(result.stdout)
    metadata = json.loads((out / "run.json").read_text()) if (out / "run.json").exists() else {}
    observations = (
        json.loads((out / "observations.json").read_text())
        if (out / "observations.json").exists()
        else []
    )
    failures = [o["id"] for o in observations if o.get("passed") is False]
    matched = (
        (result.returncode == 0 and metadata.get("outcome") == "pass" and not failures)
        if expected is None
        else (
            result.returncode != 0
            and metadata.get("error") == f"AssertionError: {expected}"
            and failures == [expected]
        )
    )
    rows.append(
        {
            "mutation": mutation,
            "exit_code": result.returncode,
            "expected_failure": expected,
            "observed_failures": failures,
            "matched_expectation": matched,
        }
    )
(a.output / "matrix.json").write_text(json.dumps(rows, indent=2) + "\n")
print(json.dumps(rows, indent=2))
raise SystemExit(0 if all(r["matched_expectation"] for r in rows) else 1)
