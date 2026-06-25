#!/usr/bin/env python3
"""Validate agt-evidence.json and emit a governance attestation.

Usage:
    python scripts/verify_agt_evidence.py [--evidence PATH] [--json] [--strict]

Exit codes:
    0  All checks passed
    1  One or more checks failed

This script has no dependencies beyond the stdlib and PyYAML (already a
cmcp-runtime dependency), so it runs in CI without any extra installs.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml  # pyyaml — already in cmcp-runtime dependencies


@dataclasses.dataclass
class EvidenceCheck:
    check_id: str
    description: str
    status: str  # "pass" | "fail"
    message: str


@dataclasses.dataclass
class GovernanceAttestation:
    schema: str
    mode: str
    generated_at: str
    evidence_path: str
    controls_total: int
    controls_passed: int
    attestation_hash: str
    evidence_checks: list[EvidenceCheck]

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": self.schema,
                "mode": self.mode,
                "generated_at": self.generated_at,
                "evidence_path": self.evidence_path,
                "controls_total": self.controls_total,
                "controls_passed": self.controls_passed,
                "attestation_hash": self.attestation_hash,
                "evidence_checks": [
                    {
                        "check_id": c.check_id,
                        "description": c.description,
                        "status": c.status,
                        "message": c.message,
                    }
                    for c in self.evidence_checks
                ],
            },
            indent=2,
        )


class GovernanceVerifier:
    """Validate an agt-evidence.json file and produce a governance attestation."""

    def verify_evidence(
        self, evidence_path: Path, *, strict: bool = False
    ) -> GovernanceAttestation:
        evidence_path = Path(evidence_path)
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        base_dir = evidence_path.parent
        checks: list[EvidenceCheck] = []

        def check(
            check_id: str,
            description: str,
            condition: bool,
            fail_msg: str,
            pass_msg: str = "ok",
        ) -> None:
            checks.append(
                EvidenceCheck(
                    check_id=check_id,
                    description=description,
                    status="pass" if condition else "fail",
                    message=pass_msg if condition else fail_msg,
                )
            )

        check(
            "GOV-001",
            "Evidence schema version is agt-runtime-evidence/v1",
            evidence.get("schema") == "agt-runtime-evidence/v1",
            f"schema must be 'agt-runtime-evidence/v1', got {evidence.get('schema')!r}",
        )

        tv = evidence.get("toolkit_version", "")
        check(
            "GOV-002",
            "AGT toolkit version reported",
            bool(tv and tv != "not-installed"),
            f"toolkit_version is missing or 'not-installed': {tv!r}",
        )

        deployment = evidence.get("deployment", {})
        pf = deployment.get("policy_files_loaded", [])

        all_exist = bool(pf) and all((base_dir / p).exists() for p in pf)
        check(
            "GOV-003",
            "Policy files listed and present on disk",
            all_exist,
            "policy_files_loaded is empty or one or more referenced files do not exist",
        )

        deny_by_default = False
        for rel in pf:
            full = base_dir / rel
            if full.exists() and full.suffix in (".yaml", ".yml"):
                try:
                    data = yaml.safe_load(full.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("deny_by_default"):
                        deny_by_default = True
                        break
                except Exception:
                    pass
        check(
            "GOV-004",
            "At least one policy file enforces deny_by_default: true",
            deny_by_default,
            "No policy file found with deny_by_default: true — default-deny not established",
        )

        sink = deployment.get("audit_sink", {})
        check(
            "GOV-005",
            "Audit sink is enabled",
            sink.get("enabled") is True,
            "audit_sink.enabled must be true",
        )

        identity = deployment.get("identity", {})
        check(
            "GOV-006",
            "Agent identity enforcement is enabled",
            identity.get("enabled") is True,
            "identity.enabled must be true",
        )

        packages = deployment.get("packages", [])
        cmcp_pkg = next((p for p in packages if p.get("package") == "cmcp-runtime"), None)
        check(
            "GOV-007",
            "cmcp-runtime package version reported",
            bool(cmcp_pkg and cmcp_pkg.get("version", "not-installed") != "not-installed"),
            "cmcp-runtime not found in packages or version is 'not-installed'",
        )

        agt_pkg = next(
            (p for p in packages if p.get("package") == "agent-governance-toolkit-core"), None
        )
        check(
            "GOV-008",
            "agent-governance-toolkit-core version reported",
            bool(agt_pkg and agt_pkg.get("version", "not-installed") != "not-installed"),
            "agent-governance-toolkit-core not found or version is 'not-installed'",
        )

        controls_passed = sum(1 for c in checks if c.status == "pass")
        attestation_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

        return GovernanceAttestation(
            schema="governance-attestation/v1",
            mode="evidence",
            generated_at=datetime.now(timezone.utc).isoformat(),
            evidence_path=str(evidence_path),
            controls_total=len(checks),
            controls_passed=controls_passed,
            attestation_hash=attestation_hash,
            evidence_checks=checks,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate agt-evidence.json and emit a governance attestation."
    )
    parser.add_argument(
        "--evidence", default="agt-evidence.json", help="Path to the evidence file"
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Emit JSON attestation to stdout"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any check fails (default behaviour; flag kept for compatibility)",
    )
    args = parser.parse_args()

    evidence_path = Path(args.evidence)
    if not evidence_path.exists():
        print(f"ERROR: evidence file not found: {evidence_path}", file=sys.stderr)
        return 1

    attestation = GovernanceVerifier().verify_evidence(evidence_path)
    failures = [c for c in attestation.evidence_checks if c.status == "fail"]

    if args.json_output:
        print(attestation.to_json())
    else:
        for c in attestation.evidence_checks:
            icon = "PASS" if c.status == "pass" else "FAIL"
            print(f"  [{icon}] {c.check_id}: {c.description} - {c.message}")
        print(f"\n{attestation.controls_passed}/{attestation.controls_total} controls passed")
        if failures:
            print(
                f"\nFAILED: {', '.join(c.check_id for c in failures)}", file=sys.stderr
            )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
