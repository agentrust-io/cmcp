"""Session lifecycle management — implements issues #60 and #55."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    generate_trace_claim,
)
from cmcp_gateway.session.state import SessionState
from cmcp_gateway.startup import GatewayContext

logger = logging.getLogger(__name__)


class SessionManager:
    """Creates, tracks, and closes agent sessions."""

    def __init__(self, ctx: GatewayContext) -> None:
        self._ctx = ctx
        # Stores signed claim dicts keyed by session_id, populated on close.
        self._closed_claims: dict[str, dict[str, Any]] = {}

    def create_session(self) -> tuple[SessionState, AuditChain]:
        """Create a new session. Returns (state, chain)."""
        session_id = str(uuid4())
        state = SessionState(session_id=session_id)
        chain = AuditChain(session_id=session_id)
        logger.info("Session created: session_id=%s", session_id)
        return state, chain

    def close_session(
        self, session_id: str, state: SessionState, chain: AuditChain
    ) -> dict[str, Any]:
        """
        Close a session:
        1. Append a session_end audit entry to the chain.
        2. Build the GatewayClaim from chain + state + ctx.
        3. Sign it with ctx.signing_key.
        4. Store the signed claim JSON, keyed by session_id.
        5. Return the signed claim dict.
        """
        chain.append(
            "session_end",
            session_sensitivity_before=state.max_sensitivity,
            session_sensitivity_after=state.max_sensitivity,
        )

        ctx = self._ctx
        report = ctx.attestation_report

        # Convert AttestationReport (datetime) to AttestationReportInfo (str).
        generated_at_str = report.attestation_generated_at.isoformat()
        age_seconds = (
            datetime.now(UTC) - report.attestation_generated_at
        ).total_seconds()
        attestation_stale = age_seconds > report.attestation_validity_seconds

        attestation_info = AttestationReportInfo(
            provider=report.provider,
            measurement=report.measurement,
            report_data=report.report_data,
            attestation_generated_at=generated_at_str,
            attestation_validity_seconds=report.attestation_validity_seconds,
            measurement_note=report.measurement_note,
            raw_evidence=(
                base64.urlsafe_b64encode(report.raw_evidence).rstrip(b"=").decode()
                if report.raw_evidence is not None
                else None
            ),
        )

        bundle = ctx.policy_bundle
        policy_info = PolicyBundleInfo(
            hash=bundle.bundle_hash,
            enforcement_mode=str(ctx.config.attestation.enforcement_mode),
            policy_version=bundle.manifest.version,
        )

        catalog = ctx.catalog
        # Detect catalog exceptions — entries where catalog_exception=True.
        catalog_exceptions: list[dict[str, str]] = [
            {"tool_name": name}
            for name, entry in catalog.entries.items()
            if entry.catalog_exception
        ]
        catalog_info = ToolCatalogInfo(
            hash=catalog.catalog_hash,
            drift_detected=False,
        )

        # Build call summary from chain entries.
        entries = chain.entries
        tool_calls = [e for e in entries if e.entry_type == "tool_call"]
        tool_calls_total = len(tool_calls)
        tool_calls_allowed = sum(
            1 for e in tool_calls if e.policy_decision == "allow"
        )
        tool_calls_denied = sum(
            1 for e in tool_calls if e.policy_decision in ("deny", "advisory_deny")
        )
        tool_calls_faulted = sum(
            1 for e in tool_calls if e.policy_decision == "fault"
        )
        tools_invoked = sorted(
            {e.tool_name for e in tool_calls if e.tool_name is not None}
        )

        # Identify compliance domains from catalog entries touched.
        compliance_domains_touched = sorted(
            {
                catalog.entries[name].compliance_domain
                for name in tools_invoked
                if name in catalog.entries
            }
        )

        call_summary = CallSummary(
            tool_calls_total=tool_calls_total,
            tool_calls_allowed=tool_calls_allowed,
            tool_calls_denied=tool_calls_denied,
            tool_calls_faulted=tool_calls_faulted,
            tools_invoked=tools_invoked,
            session_max_sensitivity=state.max_sensitivity,
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=compliance_domains_touched,
                cross_boundary_events=[],
            ),
        )

        claim = generate_trace_claim(
            session_id=session_id,
            signing_key=ctx.signing_key,
            attestation_report=attestation_info,
            policy_bundle=policy_info,
            tool_catalog=catalog_info,
            call_summary=call_summary,
            audit_chain_root=chain.chain_root,
            audit_chain_tip=chain.chain_tip,
            audit_chain_length=chain.length,
            attestation_stale=attestation_stale,
            catalog_exceptions=catalog_exceptions,
            do_sign=True,
        )

        claim_dict = claim.model_dump(exclude_none=True)
        self._closed_claims[session_id] = claim_dict
        logger.info("Session closed: session_id=%s", session_id)
        return claim_dict

    def get_trace_claim(self, session_id: str) -> dict[str, Any] | None:
        """Return the signed TRACE Claim for a closed session."""
        return self._closed_claims.get(session_id)

    def get_audit_bundle(
        self, session_id: str, chain: AuditChain
    ) -> dict[str, Any]:
        """
        Build a signed audit bundle for export (issue #55):
        {
            "session_id": ...,
            "entries": [list of entry dicts from chain],
            "bundle_signature": base64url(sha256(canonical_json(entries)) signed with signing_key)
        }

        Raises ValueError if the chain is broken (verify_chain() fails).
        """
        if not chain.verify_chain():
            raise ValueError(
                f"Audit chain integrity check failed for session_id={session_id}"
            )

        entries_dicts = [asdict(e) for e in chain.entries]
        canonical = json.dumps(
            entries_dicts,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        digest = hashlib.sha256(canonical).digest()
        raw_sig = self._ctx.signing_key.sign(digest)
        bundle_signature = (
            base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
        )

        return {
            "session_id": session_id,
            "entries": entries_dicts,
            "bundle_signature": bundle_signature,
        }
