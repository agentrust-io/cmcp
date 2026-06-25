"""Tests for scripts/gen_agt_evidence.py, scripts/verify_agt_evidence.py, and cmcp-enforcement.yaml."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
_REPO_ROOT = Path(__file__).parent.parent.parent


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[name] = mod  # register before exec so @dataclass can find the module
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _load_verifier():
    return _load_module("verify_agt_evidence")


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_agt_evidence", _SCRIPTS_DIR / "gen_agt_evidence.py"
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


@pytest.fixture(scope="module")
def generator():
    return _load_generator()


@pytest.fixture(scope="module")
def evidence(generator) -> dict:
    return generator.generate_evidence()


# --------------------------------------------------------------------------- #
# Schema and top-level structure                                               #
# --------------------------------------------------------------------------- #


def test_schema_field(evidence):
    assert evidence["schema"] == "agt-runtime-evidence/v1"


def test_has_toolkit_version(evidence):
    assert "toolkit_version" in evidence
    assert isinstance(evidence["toolkit_version"], str)


def test_has_deployment_object(evidence):
    assert isinstance(evidence.get("deployment"), dict)


# --------------------------------------------------------------------------- #
# Deployment sub-fields                                                        #
# --------------------------------------------------------------------------- #


def test_policy_files_not_empty(evidence):
    pf = evidence["deployment"]["policy_files_loaded"]
    assert isinstance(pf, list)
    assert len(pf) > 0, "policy_files_loaded must contain at least one entry"


def test_policy_file_paths_exist(evidence):
    """Every reported policy file must exist on disk relative to repo root."""
    for rel in evidence["deployment"]["policy_files_loaded"]:
        full = _REPO_ROOT / rel
        assert full.exists(), f"Policy file missing: {full}"


def test_registered_tools_not_empty(evidence):
    tools = evidence["deployment"]["registered_tools"]
    assert isinstance(tools, list)
    assert len(tools) > 0, "registered_tools must not be empty"


def test_registered_tools_from_catalog(evidence):
    """Tool list is derived from the bfsi-demo catalog."""
    catalog_path = _REPO_ROOT / "examples" / "bfsi-demo" / "catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    expected = [e["tool_name"] for e in catalog if isinstance(e, dict) and "tool_name" in e]
    assert evidence["deployment"]["registered_tools"] == expected


def test_audit_sink_enabled(evidence):
    sink = evidence["deployment"]["audit_sink"]
    assert sink.get("enabled") is True
    assert sink.get("target") or sink.get("path") or sink.get("url"), (
        "audit_sink must have a non-empty target, path, or url"
    )


def test_identity_enabled(evidence):
    assert evidence["deployment"]["identity"]["enabled"] is True


def test_packages_valid(evidence):
    packages = evidence["deployment"]["packages"]
    assert isinstance(packages, list)
    assert len(packages) > 0
    for pkg in packages:
        assert isinstance(pkg.get("package"), str) and pkg["package"].strip()
        assert isinstance(pkg.get("version"), str) and pkg["version"].strip()


def test_cmcp_runtime_in_packages(evidence):
    names = [p["package"] for p in evidence["deployment"]["packages"]]
    assert "cmcp-runtime" in names


def test_agt_in_packages(evidence):
    names = [p["package"] for p in evidence["deployment"]["packages"]]
    assert "agent-governance-toolkit-core" in names


# --------------------------------------------------------------------------- #
# main() writes valid JSON                                                     #
# --------------------------------------------------------------------------- #


def test_main_writes_valid_json(tmp_path, generator):
    out = tmp_path / "agt-evidence.json"
    generator.main(str(out))
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "agt-runtime-evidence/v1"
    assert data["generated_at"]  # populated by main()


# --------------------------------------------------------------------------- #
# Integration: GovernanceVerifier.verify_evidence() must pass all checks      #
# --------------------------------------------------------------------------- #


def test_verify_evidence_passes(tmp_path, generator):
    """GovernanceVerifier.verify_evidence() must succeed with no evidence failures."""
    GovernanceVerifier = _load_verifier().GovernanceVerifier

    gov_dir = tmp_path / "governance"
    gov_dir.mkdir()
    shutil.copy(
        _REPO_ROOT / "governance" / "cmcp-enforcement.yaml",
        gov_dir / "cmcp-enforcement.yaml",
    )

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path, strict=True)

    failures = [c for c in attestation.evidence_checks if c.status == "fail"]
    assert not failures, (
        "Evidence checks failed:\n"
        + "\n".join(f"  {c.check_id}: {c.message}" for c in failures)
    )


def test_verify_evidence_json_is_valid(tmp_path, generator):
    """to_json() output is valid JSON with expected top-level keys."""
    GovernanceVerifier = _load_verifier().GovernanceVerifier

    gov_dir = tmp_path / "governance"
    gov_dir.mkdir()
    shutil.copy(
        _REPO_ROOT / "governance" / "cmcp-enforcement.yaml",
        gov_dir / "cmcp-enforcement.yaml",
    )

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path)
    output = json.loads(attestation.to_json())

    assert output["schema"] == "governance-attestation/v1"
    assert output["mode"] == "evidence"
    assert isinstance(output["controls_total"], int)
    assert isinstance(output["controls_passed"], int)
    assert isinstance(output["attestation_hash"], str) and len(output["attestation_hash"]) == 64


def test_verify_returns_all_check_ids(tmp_path, generator):
    """All 8 GOV-00N check IDs must be present in the attestation."""
    GovernanceVerifier = _load_verifier().GovernanceVerifier

    gov_dir = tmp_path / "governance"
    gov_dir.mkdir()
    shutil.copy(
        _REPO_ROOT / "governance" / "cmcp-enforcement.yaml",
        gov_dir / "cmcp-enforcement.yaml",
    )

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path)
    check_ids = {c.check_id for c in attestation.evidence_checks}
    expected = {
        "GOV-001", "GOV-002", "GOV-003", "GOV-004",
        "GOV-005", "GOV-006", "GOV-007", "GOV-008",
    }
    assert expected == check_ids


def test_verify_fails_on_missing_policy_file(tmp_path, generator):
    """If a listed policy file is absent, GOV-003 must fail."""
    GovernanceVerifier = _load_verifier().GovernanceVerifier

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path)
    gov003 = next(c for c in attestation.evidence_checks if c.check_id == "GOV-003")
    assert gov003.status == "fail"


def test_verify_fails_if_deny_by_default_missing(tmp_path, generator):
    """If deny_by_default is absent from policy YAML, GOV-004 must fail."""
    GovernanceVerifier = _load_verifier().GovernanceVerifier

    gov_dir = tmp_path / "governance"
    gov_dir.mkdir()
    (gov_dir / "cmcp-enforcement.yaml").write_text("name: test\n", encoding="utf-8")

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path)
    gov004 = next(c for c in attestation.evidence_checks if c.check_id == "GOV-004")
    assert gov004.status == "fail"


# --------------------------------------------------------------------------- #
# Governance YAML has deny semantics                                           #
# --------------------------------------------------------------------------- #


def test_governance_yaml_has_deny_by_default():
    """cmcp-enforcement.yaml must have deny_by_default: true at the top level."""
    import yaml
    gov_path = _REPO_ROOT / "governance" / "cmcp-enforcement.yaml"
    data = yaml.safe_load(gov_path.read_text(encoding="utf-8"))
    assert data.get("deny_by_default") is True, (
        "governance/cmcp-enforcement.yaml must have deny_by_default: true"
    )
