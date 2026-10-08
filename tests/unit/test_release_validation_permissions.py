"""Release validation preserves CI checks without publishing-token authority."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml


def _workflow(name: str) -> dict:
    return yaml.safe_load(Path(f".github/workflows/{name}.yml").read_text(encoding="utf-8"))


def test_release_validation_permissions() -> None:
    ci = _workflow("ci")
    validation = _workflow("release-validation")
    release = _workflow("release")
    expected = copy.deepcopy(ci["jobs"])
    expected["test"]["permissions"].pop("id-token")
    steps = expected["test"]["steps"]
    coverage = [step for step in steps if step.get("name") == "Upload coverage report"]
    assert len(coverage) == 1
    assert coverage[0]["if"] == "github.event_name != 'release' && github.workflow != 'Release'"
    steps.remove(coverage[0])
    assert validation["jobs"] == expected
    assert validation["permissions"] == {"contents": "read"}
    assert set(validation[True]) == {"workflow_call"}
    assert release["jobs"]["test"]["uses"] == "./.github/workflows/release-validation.yml"
    assert release["jobs"]["test"]["permissions"] == {"contents": "read"}
    assert release["permissions"] == {"contents": "read"}
    assert [
        name for name, job in release["jobs"].items()
        if job.get("permissions", {}).get("id-token") == "write"
    ] == ["publish"]
    for job in validation["jobs"].values():
        assert job.get("permissions", {}).get("id-token", "none") == "none"
        assert not any("codecov/" in step.get("uses", "") for step in job["steps"])
