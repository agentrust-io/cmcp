"""Static release invariants for the CMCP runtime container."""

import re
from pathlib import Path

import yaml


def _dockerfile() -> str:
    return (Path(__file__).parents[2] / "Dockerfile").read_text(encoding="utf-8")


def test_runtime_image_uses_non_editable_production_install() -> None:
    dockerfile = _dockerfile()

    assert 'pip install -e ".[dev]"' not in dockerfile
    assert "pip wheel" in dockerfile
    assert "--no-index" in dockerfile


def test_runtime_image_drops_root_privileges() -> None:
    dockerfile = _dockerfile()

    assert "USER 10001:10001" in dockerfile
    assert "useradd --system --uid 10001" in dockerfile


def test_runtime_image_pins_python_patch_and_distribution() -> None:
    stages = [
        line for line in _dockerfile().splitlines()
        if line.startswith("FROM ")
    ]

    assert len(stages) == 2
    for stage, name in zip(stages, ("builder", "runtime"), strict=True):
        assert re.fullmatch(
            rf"FROM python:3\.11\.15-slim-bookworm@sha256:[0-9a-f]{{64}} AS {name}", stage
        ), stage


def test_runtime_dependencies_install_from_the_hashed_lock() -> None:
    dockerfile = _dockerfile()

    assert "--require-hashes -r /tmp/runtime.txt" in dockerfile
    assert "--no-deps /wheels/cmcp_runtime-*.whl" in dockerfile
    assert "--find-links" not in dockerfile


def test_container_prs_build_without_registry_write() -> None:
    workflow_path = Path(__file__).parents[2] / ".github" / "workflows" / "docker.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    triggers = workflow[True]
    steps = workflow["jobs"]["build-and-push"]["steps"]
    build = next(step for step in steps if step.get("name") == "Build and push")

    assert "pull_request" in triggers
    assert build["with"]["push"] == "${{ startsWith(github.ref, 'refs/tags/') }}"
    assert "steps.tag.outputs.tag || github.sha" in build["with"]["tags"]
    assert "cmcp-gateway:latest" in build["with"]["tags"]
    assert all(
        "startsWith(github.ref, 'refs/tags/')" in step.get("if", "")
        for step in steps
        if step.get("name") in {
            "Log in to GitHub Container Registry",
            "Install cosign",
            "Sign the image (keyless, by digest)",
            "Attest build provenance (SLSA)",
        }
    )
