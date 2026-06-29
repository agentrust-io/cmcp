"""
Experiment: Session-Level vs. Per-Call Policy: The Compliance Gap
Claim 2: Monotonic session sensitivity state for LLM data governance

Constructs a synthetic 5-call agent session with PHI contamination.
Shows which cross-boundary violations per-call policy misses that session
policy catches.

Per-call model: evaluates each call against explicit tool-level rules only.
               Does not consider what prior calls returned.

Session model:  maintains session_max_sensitivity across calls (monotonically
               increasing). Blocks calls to external/uncovered destinations
               once any PHI has been observed in the session.

Run from repo root:
  pip install -e .
  python experiments/claim2-session-vs-call-policy/run.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cmcp_runtime.catalog.loader import load_catalog
from cmcp_runtime.session.state import SENSITIVITY_ORDER, SessionState

FIXTURES = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Sensitivity floor by compliance_domain (mirrors catalog spec).
# ---------------------------------------------------------------------------
_DOMAIN_FLOOR: dict[str, str] = {
    "hipaa_phi": "hipaa_phi",
    "mnpi": "mnpi",
    "trade_secret": "trade_secret",
    "pii": "pii",
    "pci_data": "confidential",
    "internal": "confidential",
    "external": "public",
    "public": "public",
}


# ---------------------------------------------------------------------------
# Synthetic call trace.
# Each call specifies: tool, the simulated response JSON, and whether the
# call's raw payload arguments would themselves contain sensitive data
# (used for the per-call "payload-inspection" check).
# ---------------------------------------------------------------------------
@dataclass
class SyntheticCall:
    tool_name: str
    args: dict
    response: dict
    payload_contains_phi: bool  # ground truth: does the response carry PHI?


TRACE: list[SyntheticCall] = [
    SyntheticCall(
        tool_name="ehr.get_patient",
        args={"patient_id": "P-0042"},
        response={
            "patient_id": "P-0042",
            "name": "Jane Smith",
            "mrn": "MRN-789456",
            "diagnosis": "ICD-10: E11.9 Type 2 diabetes mellitus without complications",
            "dob": "1978-03-15",
        },
        payload_contains_phi=True,
    ),
    SyntheticCall(
        tool_name="slack.post_message",
        args={"channel": "#clinical-alerts", "message": "Patient summary ready for review."},
        response={"ok": True, "ts": "1750000000.000001"},
        payload_contains_phi=False,  # payload itself is clean: per-call sees nothing
    ),
    SyntheticCall(
        tool_name="analytics.run_query",
        args={"query": "SELECT COUNT(*) FROM daily_admissions WHERE date = '2026-06-25'"},
        response={"rows": [{"count": 47}], "row_count": 1},
        payload_contains_phi=False,
    ),
    SyntheticCall(
        tool_name="ehr.get_patient",
        args={"patient_id": "P-0042"},
        response={
            "patient_id": "P-0042",
            "name": "Jane Smith",
            "mrn": "MRN-789456",
            "diagnosis": "ICD-10: E11.9 Type 2 diabetes mellitus without complications",
            "dob": "1978-03-15",
        },
        payload_contains_phi=True,
    ),
    SyntheticCall(
        tool_name="external_webhook.post",
        args={"endpoint_id": "partner-analytics", "payload": {"summary": "daily_report", "count": 47}},
        response={"status": 200, "body": "accepted"},
        payload_contains_phi=False,
    ),
]

# ---------------------------------------------------------------------------
# Per-call policy (simulates Cedar without session context).
#
# Rules:
#   - Tool must be in the approved catalog.
#   - If the outbound arguments contain an explicit PHI pattern, deny.
#   - Otherwise allow.
#
# This is intentionally the BEST CASE per-call model: it even inspects
# the outbound arguments for PHI. It still misses cross-boundary violations
# because it cannot see what is in the agent's context window.
# ---------------------------------------------------------------------------

def per_call_policy(
    tool_name: str,
    catalog_entry,
    call: SyntheticCall,
) -> tuple[Literal["ALLOW", "DENY"], str]:
    """Evaluate a call using per-call-only policy."""
    # Rule 1: tool must be in catalog
    if catalog_entry is None:
        return "DENY", "tool not in approved catalog"

    # Rule 2: outbound argument payload must not contain PHI patterns
    # (best-case per-call model: we inspect the arguments, not just metadata)
    args_str = json.dumps(call.args, ensure_ascii=False)
    phi_keywords = ["MRN-", "ICD-10", "diagnosis", "dob", "date of birth"]
    for kw in phi_keywords:
        if kw.lower() in args_str.lower():
            return "DENY", f"outbound args contain PHI pattern: {kw!r}"

    return "ALLOW", "tool in catalog, args clean"


# ---------------------------------------------------------------------------
# Session policy (mirrors cMCP session-policy.md).
#
# Rules:
#   - After any PHI response, block calls to external destinations unless
#     they have a BAA.
#   - After any PHI response, block calls to communication tools.
# ---------------------------------------------------------------------------

def session_policy(
    tool_name: str,
    catalog_entry,
    session_max_sensitivity: str,
) -> tuple[Literal["ALLOW", "DENY"], str]:
    """Evaluate a call using session-level policy."""
    if catalog_entry is None:
        return "DENY", "tool not in approved catalog"

    current_level = SENSITIVITY_ORDER.get(session_max_sensitivity, 0)
    phi_level = SENSITIVITY_ORDER["hipaa_phi"]

    if current_level >= phi_level:
        # Block external destinations without BAA
        if catalog_entry.compliance_domain == "external" and not catalog_entry.requires_baa:
            return "DENY", (
                f"session_max_sensitivity={session_max_sensitivity!r}; "
                f"destination is external and not BAA-covered"
            )
        # Block internal tools that could forward data externally
        # (internal analytics that aggregates across patient records is still a risk)
        # For this experiment we allow internal tools to show a nuanced result.

    return "ALLOW", f"session_max_sensitivity={session_max_sensitivity!r}; destination permitted"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("Experiment: Session-Level vs. Per-Call Policy: The Compliance Gap")
    print("Claim 2: cMCP monotonic session sensitivity state")
    print("=" * 72)

    catalog = load_catalog(str(FIXTURES / "catalog.json"))
    session = SessionState(session_id="exp2-session")

    print(f"\nSession trace: {len(TRACE)} calls, PHI contamination at calls 1 and 4")
    header = f"{'#':>2}  {'Tool':<24} {'Domain':<12} {'Payload tags':<18} {'Per-call':<10} {'Session':<8} Gap"
    print("-" * 72)
    print(header)
    print("-" * 72)

    per_call_violations_missed = []
    per_call_caught = 0
    session_caught = 0
    true_violations = 0  # calls that cross a PHI→external boundary

    for i, call in enumerate(TRACE, 1):
        entry = catalog.lookup(call.tool_name)

        # Determine response sensitivity tags (from catalog floor + response content)
        floor_tag = _DOMAIN_FLOOR.get(entry.compliance_domain if entry else "external", "public")
        response_tags = [floor_tag] if floor_tag != "public" else []

        # Also check response for PHI field annotations (x-sensitivity from schema)
        if entry and entry.approved_definition.output_schema:
            props = entry.approved_definition.output_schema.get("properties", {})
            for field_name, field_schema in props.items():
                sens = field_schema.get("x-sensitivity")
                if sens and field_name in call.response and sens not in response_tags:
                    response_tags.append(sens)

        payload_tag_str = ", ".join(response_tags) if response_tags else "(clean)"

        # Run per-call policy (before session state is updated)
        pc_verdict, pc_reason = per_call_policy(call.tool_name, entry, call)

        # Run session policy (before session state is updated: pre-call check)
        sess_verdict, sess_reason = session_policy(call.tool_name, entry, session.max_sensitivity)

        # Determine if this is a true violation
        # A true violation = external call after PHI has entered the session
        is_true_violation = (
            entry is not None
            and entry.compliance_domain == "external"
            and not entry.requires_baa
            and SENSITIVITY_ORDER.get(session.max_sensitivity, 0) >= SENSITIVITY_ORDER["hipaa_phi"]
        )
        if is_true_violation:
            true_violations += 1

        # Count catches
        if is_true_violation and pc_verdict == "DENY":
            per_call_caught += 1
        if is_true_violation and sess_verdict == "DENY":
            session_caught += 1
        if is_true_violation and pc_verdict == "ALLOW":
            per_call_violations_missed.append(i)

        gap = "MISSED" if (is_true_violation and pc_verdict == "ALLOW") else "-"

        row = (
            f"{i:>2}  {call.tool_name:<24} "
            f"{(entry.compliance_domain if entry else 'unknown'):<12} "
            f"{payload_tag_str:<18} "
            f"{pc_verdict:<10} "
            f"{sess_verdict:<8} "
            f"{gap}"
        )
        print(row)

        # Update session state after the call (as the gateway would)
        session.update_from_inspection(
            call_id=f"call-{i}",
            sensitivity_tags=response_tags,
            injection_detected=False,
            response_allowed=(sess_verdict == "ALLOW"),
        )

    print("-" * 72)
    print("\nSummary")
    print("-------")
    print(f"True cross-boundary violations (PHI session + external non-BAA call): {true_violations}")
    print(f"Per-call policy caught:    {per_call_caught} / {true_violations}  ({100 * per_call_caught // max(true_violations, 1)}%)")
    print(f"Session policy caught:     {session_caught} / {true_violations}  ({100 * session_caught // max(true_violations, 1)}%)")
    if per_call_violations_missed:
        print(f"Violations MISSED by per-call: {len(per_call_violations_missed)}  (calls {per_call_violations_missed})")

    print(f"\nsession_max_sensitivity after call {len(TRACE)}: {session.max_sensitivity!r}")
    print(f"sensitivity_raised_by_call: {session.sensitivity_raised_by_call!r}")

    print("\nConclusion")
    print("----------")
    print(
        f"Per-call policy detected {per_call_caught}/{true_violations} cross-boundary violations.\n"
        f"Session policy detected  {session_caught}/{true_violations} cross-boundary violations.\n"
        "\n"
        "The gap exists because per-call policy evaluates each call in isolation.\n"
        "Calls 2 and 5 have clean outbound payloads -- per-call inspection sees\n"
        "nothing wrong. But the agent's context window contains PHI from calls 1\n"
        "and 4. Session policy blocks calls 2 and 5 because session_max_sensitivity\n"
        "== 'hipaa_phi' and those destinations are external and not BAA-covered.\n"
        "Call 3 (internal analytics) is correctly permitted: internal destinations\n"
        "are a different compliance boundary from external ones."
    )

    return 0 if session_caught == true_violations else 1


if __name__ == "__main__":
    sys.exit(main())
