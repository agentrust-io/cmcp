"""Tests for the standalone installed-distribution release smoke check."""

import subprocess
import sys
from importlib.metadata import version
from pathlib import Path


def test_distribution_smoke_script_exercises_installed_public_api(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "verify_python_distribution.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--expected-version",
            version("cmcp-runtime"),
            "--forbidden-source-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "verified cmcp-runtime" in completed.stdout
