"""Issue #595: every hardware branch must read evidence from the cmcp envelope.

#469/#370 moved signed platform evidence out of ``trace.runtime`` and into
``gateway.attestation_evidence``, because ``RuntimeInfo`` belongs to
agentrust-trace and is ``extra="forbid"``: a claim carrying evidence under
``trace.runtime`` is rejected as CLAIM_MALFORMED before any platform branch
runs. ``_evidence_field()`` exists to read the new location with a fallback to
the old one.

Only the ``tpm2`` branch used it. The other four read ``_runtime`` directly, so
against a claim produced by current code:

* ``azure-cvm-sev-snp`` did ``_runtime["raw_evidence"]`` and raised ``KeyError``
  on a schema-valid claim;
* ``amd-sev-snp``, ``intel-tdx`` and ``opaque``/``opaque-managed`` used
  ``_runtime.get(...)``, silently passing ``None`` to their platform verifier,
  so attestation degraded to unverified with no indication why.

Each test below asserts the platform verifier *receives the evidence bytes*,
which is the property that was broken. Asserting on the final verdict would
pass for the wrong reason, since a verifier handed ``None`` also reports
``hardware_attestation`` as unverified.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    _to_dict,
    canonical_json,
    generate_trace_claim,
)
from cmcp_runtime.tee.base import jwk_thumbprint
from cmcp_verify.verify import ApprovedHashes, verify_trace_claim

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
VALID_MEASUREMENT = "sha256:" + "c" * 64

EVIDENCE = b"\xde\xad\xbe\xef" * 8
CERT_CHAIN = b"-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n"


def _claim(provider: str, *, platform_override: str | None = None) -> dict:
    """A schema-valid claim carrying evidence through the real producer path."""
    key = SigningKey()
    chain = AuditChain(f"{provider}-session")
    root_hex = chain.chain_root.removeprefix("sha256:").removeprefix("sha384:")
    report_data = (
        jwk_thumbprint(key.public_key_bytes)
        + hashlib.sha256(bytes.fromhex(root_hex)).digest()
    ).hex()
    claim = generate_trace_claim(
        session_id=f"{provider}-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider=provider,
            measurement=VALID_MEASUREMENT,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
            raw_evidence=base64.b64encode(EVIDENCE).decode(),
            cert_chain=base64.b64encode(CERT_CHAIN).decode(),
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH, enforcement_mode="enforcing", policy_version="1.0.0"
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=1,
            tool_calls_allowed=1,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=["test.tool"],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[], cross_boundary_events=[]
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=False,
    )
    claim_dict = _to_dict(claim)
    if platform_override is not None:
        claim_dict["trace"]["runtime"]["platform"] = platform_override
    # Sign last, so the signature covers the evidence and any platform override.
    claim_dict["signature"] = (
        base64.urlsafe_b64encode(key.sign(canonical_json(claim_dict))).rstrip(b"=").decode()
    )
    return claim_dict


def _approved() -> ApprovedHashes:
    return ApprovedHashes(policy_bundle_hash=POLICY_HASH, tool_catalog_hash=CATALOG_HASH)


def _evidence_is_in_the_envelope_not_runtime(claim: dict) -> None:
    """The producer path put the evidence where #469 says it goes."""
    assert "raw_evidence" in claim["gateway"]["attestation_evidence"]
    assert "raw_evidence" not in claim["trace"]["runtime"]


class _Spy:
    """Captures the kwargs the platform verifier was called with."""

    def __init__(self) -> None:
        self.kwargs: dict | None = None

    def __call__(self, **kwargs):
        self.kwargs = kwargs

        class _Result:
            verified = False
            verified_fields: list[str] = []
            unverified_fields: list[str] = []
            details: dict[str, str] = {}
            failure_reason = "spy"

        return _Result()


@pytest.mark.parametrize(
    ("provider", "platform_override", "module", "func"),
    [
        ("azure-cvm-sev-snp", None, "cmcp_verify.azure_cvm", "verify_azure_cvm_measurement"),
        ("sev-snp", None, "cmcp_verify.sev_snp", "verify_sev_snp_measurement"),
        ("tdx", None, "cmcp_verify.tdx", "verify_tdx_measurement"),
        ("tdx", "opaque", "cmcp_verify.opaque", "verify_opaque_measurement"),
    ],
)
def test_platform_branch_reads_evidence_from_the_envelope(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    platform_override: str | None,
    module: str,
    func: str,
) -> None:
    """The branch must receive the evidence bytes, not None and not a KeyError."""
    claim = _claim(provider, platform_override=platform_override)
    _evidence_is_in_the_envelope_not_runtime(claim)

    spy = _Spy()
    monkeypatch.setattr(f"{module}.{func}", spy)

    # Before the fix: azure-cvm-sev-snp raised KeyError here, and the other
    # three called their verifier with raw_evidence=None.
    verify_trace_claim(claim, _approved())

    assert spy.kwargs is not None, f"{func} was never reached"
    assert spy.kwargs["raw_evidence"] == EVIDENCE


def test_sev_snp_reads_the_cert_chain_from_the_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The VCEK chain is the other field the SNP branch read from runtime."""
    claim = _claim("sev-snp")
    assert "cert_chain" in claim["gateway"]["attestation_evidence"]
    assert "cert_chain" not in claim["trace"]["runtime"]

    spy = _Spy()
    monkeypatch.setattr("cmcp_verify.sev_snp.verify_sev_snp_measurement", spy)
    verify_trace_claim(claim, _approved())

    assert spy.kwargs is not None
    assert spy.kwargs["cert_chain_pem"] == CERT_CHAIN
