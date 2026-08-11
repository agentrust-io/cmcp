"""Static release invariants for the CMCP runtime container."""

from pathlib import Path


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

    assert stages == [
        "FROM python:3.11.15-slim-bookworm AS builder",
        "FROM python:3.11.15-slim-bookworm AS runtime",
    ]
