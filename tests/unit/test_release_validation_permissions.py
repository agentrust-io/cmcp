"""Release validation preserves CI checks without publishing-token authority."""

from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest
import yaml

# Reviewed under agentrust-io/.github#54. Codecov is the sole test-job exception.
OIDC_JOBS = {
    ("ci.yml", "test"),  # Codecov tokenless coverage upload
    ("release.yml", "publish"),  # PyPI trusted publishing
    ("docker.yml", "build-and-push"),  # Container signing and attestation
    ("scorecard.yml", "scorecard"),  # Scorecard
}


def _oidc_write(permissions: dict | str) -> bool:
    if isinstance(permissions, str):
        assert permissions in {"read-all", "write-all"}, "unsupported permission shorthand"
        return permissions == "write-all"
    assert isinstance(permissions, dict), "permissions must be a mapping or shorthand"
    return permissions.get("id-token") == "write"


def _assert_oidc_jobs(directory: Path) -> None:
    grants = set()
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    assert paths, "no workflow files found"
    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults = workflow.get("permissions", {})
        assert not _oidc_write(defaults), f"{path.name}: workflow-wide OIDC grant"
        for name, job in workflow["jobs"].items():
            permissions = job.get("permissions", defaults)
            assert permissions != "write-all", f"{path.name}/{name}: write-all grant"
            if _oidc_write(permissions):
                grants.add((path.name, name))
    assert grants == OIDC_JOBS, f"OIDC job drift: {grants ^ OIDC_JOBS}"


def test_workflow_oidc_grants() -> None:
    _assert_oidc_jobs(Path(".github/workflows"))


@pytest.mark.parametrize(
    "case",
    [
        "validation-job", "sbom-job", "workflow-inheritance", "workflow-write-all",
        "allowed-job-write-all", "other-job-write-all", "new-yml", "new-yaml",
        "removed-allowance",
    ],
)
def test_oidc_guard_detects_permission_drift(tmp_path: Path, case: str) -> None:
    directory = tmp_path / "workflows"
    shutil.copytree(".github/workflows", directory)
    _assert_oidc_jobs(directory)
    if case in {"new-yml", "new-yaml"}:
        extension = case.removeprefix("new-")
        (directory / f"unexpected.{extension}").write_text(
            "permissions: {contents: read}\njobs:\n"
            "  validation:\n    permissions: {id-token: write}\n",
            encoding="utf-8",
        )
    else:
        filename = "sbom.yml" if case == "sbom-job" else "release-validation.yml"
        if case in {"allowed-job-write-all", "removed-allowance"}:
            filename = "ci.yml"
        path = directory / filename
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        job = workflow["jobs"]["sbom" if case == "sbom-job" else "test"]
        if case == "workflow-inheritance":
            workflow["permissions"]["id-token"] = "write"
            job.pop("permissions", None)
        elif case == "workflow-write-all":
            workflow["permissions"] = "write-all"
        elif case in {"allowed-job-write-all", "other-job-write-all"}:
            job["permissions"] = "write-all"
        elif case == "removed-allowance":
            job["permissions"].pop("id-token")
        else:
            job.setdefault("permissions", {})["id-token"] = "write"
        path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_oidc_jobs(directory)


def test_oidc_guard_accepts_read_only_inheritance(tmp_path: Path) -> None:
    directory = tmp_path / "workflows"
    shutil.copytree(".github/workflows", directory)
    (directory / "read-only.yaml").write_text(
        "permissions: read-all\njobs:\n  validation:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    _assert_oidc_jobs(directory)


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
