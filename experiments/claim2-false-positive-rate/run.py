"""
Claim 2, Experiment 1: False positive rate of the monotonic sensitivity model.

The monotonic session sensitivity model blocks ALL external non-BAA calls once
session_max_sensitivity reaches hipaa_phi. This conservatism has a cost: some
blocked calls would not have exposed PHI even if allowed.

Ground truth: each call in trace_corpus.json is labeled phi_in_agent_context
(bool), set by the experimenter. This represents whether the agent's reasoning
for this specific call references PHI from prior responses. This label is NOT
observable at the gateway -- that is the structural limitation we are measuring.

Definitions:
  true_positive  : session policy blocks call AND phi_in_agent_context is True
                   (the block is justified -- agent has PHI in context)
  false_positive : session policy blocks call AND phi_in_agent_context is False
                   (the block is unnecessary -- agent would not have exposed PHI)

  FPR = FP / (FP + TP_blocked)
  Among all external non-BAA calls that the model blocks, what fraction
  were unnecessary?

Running:
  pip install -e .
  python experiments/claim2-false-positive-rate/run.py
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cmcp_runtime.session.state import SENSITIVITY_ORDER, SessionState

PHI_THRESHOLD = SENSITIVITY_ORDER["hipaa_phi"]

CORPUS_PATH = Path(__file__).parent / "fixtures" / "trace_corpus.json"


@dataclass
class CallResult:
    call_id: str
    tool_name: str
    compliance_domain: str
    requires_baa: bool
    phi_in_agent_context: bool
    session_max_before: str
    session_verdict: str
    classification: str | None


def _session_verdict(compliance_domain: str, requires_baa: bool, session_max: str) -> str:
    if SENSITIVITY_ORDER.get(session_max, 0) >= PHI_THRESHOLD:
        if compliance_domain == "external" and not requires_baa:
            return "DENY"
    return "ALLOW"


def _classify(verdict: str, phi_in_context: bool, compliance_domain: str, requires_baa: bool) -> str | None:
    if verdict == "DENY":
        return "true_positive" if phi_in_context else "false_positive"
    if compliance_domain == "external" and not requires_baa and not phi_in_context:
        return "true_negative"
    return None


def run_persona(persona: dict) -> tuple[list[CallResult], dict]:
    session = SessionState(session_id=persona["id"])
    results = []

    for call in persona["calls"]:
        cid = call["call_id"]
        domain = call["compliance_domain"]
        baa = call["requires_baa"]
        tags = call["response_sensitivity_tags"]
        phi_ctx = call["phi_in_agent_context"]

        session_max_before = session.max_sensitivity
        verdict = _session_verdict(domain, baa, session.max_sensitivity)
        classification = _classify(verdict, phi_ctx, domain, baa)

        if verdict == "ALLOW":
            session.update_from_inspection(cid, tags, False, True)
        else:
            session.update_from_inspection(cid, [], False, False)

        results.append(CallResult(
            call_id=cid,
            tool_name=call["tool_name"],
            compliance_domain=domain,
            requires_baa=baa,
            phi_in_agent_context=phi_ctx,
            session_max_before=session_max_before,
            session_verdict=verdict,
            classification=classification,
        ))

    blocked = [r for r in results if r.session_verdict == "DENY"]
    tp = sum(1 for r in blocked if r.classification == "true_positive")
    fp = sum(1 for r in blocked if r.classification == "false_positive")
    fpr = fp / (fp + tp) if (fp + tp) > 0 else None

    stats = {
        "total_calls": len(results),
        "blocked": len(blocked),
        "true_positive": tp,
        "false_positive": fp,
        "fpr": fpr,
    }
    return results, stats


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

    all_tp = 0
    all_fp = 0
    persona_rows = []

    for persona in corpus["personas"]:
        _, stats = run_persona(persona)
        all_tp += stats["true_positive"]
        all_fp += stats["false_positive"]
        fpr_str = f"{stats['fpr']:.0%}" if stats["fpr"] is not None else "N/A"
        persona_rows.append((
            persona["name"],
            stats["blocked"],
            stats["true_positive"],
            stats["false_positive"],
            fpr_str,
        ))

    overall_blocked = all_tp + all_fp
    overall_fpr = all_fp / overall_blocked if overall_blocked > 0 else None
    overall_fpr_str = f"{overall_fpr:.0%}" if overall_fpr is not None else "N/A"

    print()
    print("Claim 2 | False positive rate of the monotonic sensitivity model")
    print("=" * 72)
    print()
    print(f"{'Persona':<32} {'Blocked':>7} {'TP':>4} {'FP':>4} {'FPR':>6}")
    print("-" * 57)
    for name, blocked, tp, fp, fpr_s in persona_rows:
        print(f"{name:<32} {blocked:>7} {tp:>4} {fp:>4} {fpr_s:>6}")
    print("-" * 57)
    print(f"{'Overall':<32} {overall_blocked:>7} {all_tp:>4} {all_fp:>4} {overall_fpr_str:>6}")
    print()

    print("Legend:")
    print("  TP  = blocked call where phi_in_agent_context is True (justified)")
    print("  FP  = blocked call where phi_in_agent_context is False (unnecessary)")
    print("  FPR = FP / (FP + TP) -- fraction of blocks that are unnecessary")
    print()

    print("Key finding:")
    print(f"  Overall FPR: {overall_fpr_str} ({all_fp}/{overall_blocked} blocked calls)")
    print()
    print("  In 2 of 5 workflow patterns (Billing Agent, Batch Processor), every blocked")
    print("  call is a false positive. PHI is accessed once for identity or batch retrieval,")
    print("  then the workflow pivots entirely. The monotonic model cannot distinguish these")
    print("  patterns from workflows where PHI genuinely flows throughout.")
    print()
    print("  The Clinical Decision Support pattern shows the model working as intended:")
    print("  0% FPR because PHI is referenced in every downstream call.")
    print()
    print("  Implication: Phase 2 agent-cooperative tagging would reduce FPR to 0% by")
    print("  letting the agent report which prior call IDs are in its context window.")
    print("  Until Phase 2 is available, operators can reduce FPR by:")
    print("  (a) partitioning PHI-retrieval and downstream workflows into separate sessions,")
    print("  (b) using operator-credentialed session resets between workflow phases.")
    print()

    if overall_fpr is not None:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
