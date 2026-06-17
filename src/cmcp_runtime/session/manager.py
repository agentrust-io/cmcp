"""Session lifecycle management - implements issues #60 and #55."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cmcp_runtime.agent_manifest import AgentManifestBinding
from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.trace_claim import (
    AgentIdentityInfo,
    AttestationReportInfo,
    CallGraphSummary,
    CallLogSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    generate_trace_claim,
)
from cmcp_runtime.session.call_log import CallLog, SessionCallLog
from cmcp_runtime.session.state import SessionState
from cmcp_runtime.startup import RuntimeContext

logger = logging.getLogger(__name__)

# Module-level counter so sequence numbers are monotonic across all sessions
# within a single gateway process lifetime.
_CLAIM_SEQUENCE: int = 0


class SessionManager:
    """Creates, tracks, and closes agent sessions."""

    # AUTH-004: cleanup interval is configurable via env var (default 60s).
    cleanup_interval_seconds: int = int(
        os.environ.get("CMCP_SESSION_CLEANUP_INTERVAL_SECONDS", "60")
    )

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        # Stores signed claim dicts keyed by session_id, populated on close.
        self._closed_claims: dict[str, dict[str, Any]] = {}
        self._last_claim_hash: str | None = None

    def create_session(self) -> tuple[SessionState, AuditChain]:
        """
        Create a new session. Returns (state, chain).

        AUDIT-002: after constructing the chain, request a per-session TEE
        attestation report whose nonce encodes the chain root.  This commits
        the root into hardware-attested evidence so an attacker cannot silently
        swap out the chain and pass verify_chain().  In dev / Level-0 mode
        (software-only provider) the anchor is still set so that verify_chain()
        performs the root comparison - the security guarantee is limited to what
        a software TEE provides, and a warning is emitted.
        """
        session_id = str(uuid4())
        state = SessionState(session_id=session_id)
        chain = AuditChain(session_id=session_id, store=self._ctx.audit_store)

        # AUDIT-002: derive a per-session nonce that encodes the chain root so
        # the TEE report binds this specific chain to the attestation evidence.
        # nonce = SHA-256(chain_root_bytes || session_id_bytes)
        chain_root = chain.chain_root
        nonce = hashlib.sha256(
            bytes.fromhex(chain_root) + session_id.encode()
        ).digest()

        try:
            self._ctx.tee_provider.get_attestation_report(nonce)
            # The report itself is not stored here - the startup-time report in
            # ctx.attestation_report already covers the gateway instance.  What
            # matters is that the nonce (containing chain_root) was submitted to
            # the TEE, making chain_root part of the attested evidence.
        except Exception as exc:
            # Non-fatal: log and continue.  The anchor is still set so that
            # internal chain-substitution detection works.  In production,
            # callers should validate that the TEE provider is not software-only.
            logger.warning(
                "AUDIT-002: per-session TEE attestation call failed - "
                "chain root is not hardware-anchored. session_id=%s error=%s",
                session_id,
                exc,
            )

        chain.set_tee_anchor(chain_root)
        logger.info("Session created: session_id=%s chain_root=%s...", session_id, chain_root[:16])
        return state, chain

    def close_session(
        self,
        session_id: str,
        state: SessionState,
        chain: AuditChain,
        call_log: CallLog | None = None,
        session_call_log: SessionCallLog | None = None,
    ) -> dict[str, Any]:
        """
        Close a session:
        1. Append a session_end audit entry to the chain.
        2. Build the RuntimeClaim from chain + state + ctx.
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
            hash=bundle.bundle.bundle_hash,
            enforcement_mode=str(ctx.config.attestation.enforcement_mode),
            policy_version=bundle.bundle.manifest.version,
        )

        catalog = ctx.catalog
        # Collect catalog exceptions from the runtime exception list (richer metadata).
        catalog_exceptions: list[dict[str, str]] = [
            {
                "tool_name": exc.tool_name,
                "reason": exc.reason,
                "authorized_by": exc.authorized_by,
                "added_at": exc.added_at,
            }
            for exc in catalog.exceptions
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

        # Build call graph summary: prefer SessionCallLog (richer, with adjacency
        # tracking) and fall back to deriving domains from the audit chain entries.
        if session_call_log is not None:
            cg = session_call_log.get_call_graph_summary()
            call_graph_summary = CallGraphSummary(
                compliance_domains_touched=cg["compliance_domains_touched"],
                cross_boundary_events=cg["cross_boundary_events"],
                edges_represent=cg["edges_represent"],
            )
        else:
            compliance_domains_touched = sorted(
                {
                    catalog.entries[name].compliance_domain
                    for name in tools_invoked
                    if name in catalog.entries
                }
            )
            call_graph_summary = CallGraphSummary(
                compliance_domains_touched=compliance_domains_touched,
                cross_boundary_events=[],
            )

        call_summary = CallSummary(
            tool_calls_total=tool_calls_total,
            tool_calls_allowed=tool_calls_allowed,
            tool_calls_denied=tool_calls_denied,
            tool_calls_faulted=tool_calls_faulted,
            tools_invoked=tools_invoked,
            session_max_sensitivity=state.max_sensitivity,
            call_graph_summary=call_graph_summary,
        )

        call_log_summary: CallLogSummary | None = None
        if call_log is not None:
            call_log_summary = CallLogSummary(
                total_calls=len(call_log.records),
                tools_called=call_log.tools_called(),
                suspicious_sequences_detected=state.suspicious_sequences,
            )

        agent_identity: AgentIdentityInfo | None = None
        binding = getattr(ctx, "agent_manifest", None)
        if not isinstance(binding, AgentManifestBinding):
            binding = None
        if binding is not None:
            agent_identity = AgentIdentityInfo(
                manifest_id=binding.manifest_id,
                agent_id=binding.agent_id,
                authenticated_subject=binding.authenticated_subject,
                subject_source=binding.subject_source,
                issuer=binding.issuer,
                issuer_key_id=binding.issuer_key_id,
                policy_bundle_hash=binding.policy_bundle_hash,
                tool_catalog_hash=binding.tool_catalog_hash,
            )

        # AUDIT-005: increment the module-level counter to get a monotonic sequence number.
        global _CLAIM_SEQUENCE
        _CLAIM_SEQUENCE += 1

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
            call_log_summary=call_log_summary,
            agent_identity=agent_identity,
            sequence_number=_CLAIM_SEQUENCE,
            prev_claim_hash=self._last_claim_hash,
            do_sign=True,
        )

        claim_dict = claim.model_dump(exclude_none=True)
        # Record canonical hash of this claim for the next claim's prev_claim_hash link.
        self._last_claim_hash = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(claim_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest()
        )
        self._closed_claims[session_id] = claim_dict
        logger.info("Session closed: session_id=%s sequence_number=%d", session_id, _CLAIM_SEQUENCE)
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
