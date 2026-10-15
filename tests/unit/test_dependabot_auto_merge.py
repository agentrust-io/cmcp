"""Exercise the workflow's real shell gate without contacting GitHub."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/dependabot-auto-merge.yml"


@pytest.mark.parametrize(
    ("metadata", "allowed"),
    [
        ([{"updateType": "version-update:semver-patch"}], True),
        ([{"updateType": "version-update:semver-minor"}], True),
        ([{"updateType": "version-update:semver-major"}], False),
        (
            [
                {"updateType": "version-update:semver-minor"},
                {"updateType": "version-update:semver-patch"},
            ],
            True,
        ),
        (
            [
                {"updateType": "version-update:semver-patch"},
                {"updateType": "version-update:semver-major"},
            ],
            False,
        ),
        ([{"updateType": "version-update:semver-patch"}, {}], False),
        ([{"updateType": None}], False),
        ([{"updateType": "unknown"}], False),
        ([{"updateType": "version-update:semver-patch"}, "unknown"], False),
        ([], False),
        ({"updateType": "version-update:semver-patch"}, False),
        (None, False),
        ("not metadata", False),
    ],
)
def test_only_fully_classified_minor_patch_groups_queue(
    tmp_path: Path, metadata: object, allowed: bool
) -> None:
    _run_gate(tmp_path, json.dumps(metadata), allowed)


def test_malformed_metadata_never_queues(tmp_path: Path) -> None:
    _run_gate(tmp_path, "{invalid", False)


def _run_gate(tmp_path: Path, metadata: str, allowed: bool) -> None:
    if sys.platform != "linux":
        pytest.skip("Bash/jq execution matches the workflow's Ubuntu runner")
    workflow = yaml.safe_load(WORKFLOW.read_text())
    step = workflow["jobs"]["enable"]["steps"][-1]
    gh = tmp_path / "gh"
    output = tmp_path / "gh-args"
    gh.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$AUDIT_GH_ARGS"\n')
    gh.chmod(0o755)
    head = "a" * 40
    url = "https://github.com/example/repo/pull/1"
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "AUDIT_GH_ARGS": str(output),
        "UPDATED_DEPENDENCIES": metadata,
        "PR_HEAD_SHA": head,
        "PR_URL": url,
        "GH_TOKEN": "unused-local-test-token",
    }
    subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert output.exists() is allowed
    if allowed:
        assert output.read_text().splitlines() == [
            "pr",
            "merge",
            "--auto",
            "--squash",
            "--match-head-commit",
            head,
            url,
        ]


def test_workflow_keeps_event_and_permission_boundaries() -> None:
    # BaseLoader retains YAML's literal "on" key instead of YAML 1.1's boolean.
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request"}
    assert set(workflow["on"]["pull_request"]["types"]) == {
        "opened",
        "reopened",
        "synchronize",
    }
    job = workflow["jobs"]["enable"]
    assert "user.login == 'dependabot[bot]'" in job["if"]
    assert "head.repo.full_name == github.repository" in job["if"]
    assert job["permissions"] == {"contents": "write", "pull-requests": "write"}
    metadata = job["steps"][0]
    action, revision = metadata["uses"].split("@")
    assert action == "dependabot/fetch-metadata"
    assert len(revision) == 40 and all(c in "0123456789abcdef" for c in revision)
    assert "skip-verification" not in metadata.get("with", {})
    assert "skip-commit-verification" not in metadata.get("with", {})
    assert all("checkout@" not in step.get("uses", "") for step in job["steps"])
