"""
Conformance tests: Cedar policy enforcement bound to the TEE (issue #124).
Covers POLICY-TEE-001 through POLICY-TEE-005.

**Scope.** These are software-only by design, the same choice #552 made. The
``SoftwareOnlyProvider`` echoes the attestation nonce into ``report_data``, which
is the collector-side shape SEV-SNP and TDX present, so a round trip here proves
the *contract*. Whether real silicon signs those 64 bytes is a hardware question
and is recorded as a provider requirement rather than asserted as passing.

**What these cases deliberately do not claim.** Host-bypass prevention is not one
of them. Attestation validation and memory encryption do not by themselves show
that a host cannot bypass a deny, and a documentation citation is not a passing
conformance case. That criterion stays open on #124, alongside the TPM
limitations recorded in POLICY-TEE-002.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

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
    generate_trace_claim,
)
from cmcp_runtime.policy.bundle import load_policy_bundle
from cmcp_runtime.tee.base import (
    SoftwareOnlyProvider,
    audit_root_commitment,
    jwk_thumbprint,
    make_audit_bound_nonce,
    make_measurement_bound_nonce,
)
from cmcp_runtime.tee.measurement import gateway_measurement, policy_digest
from cmcp_runtime.tee.report_binding import (
    MEASUREMENT_BOUND_PROVIDERS,
    binds_measurement_into_report_data,
    measurement_bound_nonce_for,
    refresh_measurement_binding,
)
from cmcp_verify.tpm import verify_tpm_measurement
from cmcp_verify.verify import ApprovedHashes, verify_trace_claim

_KEY = bytes(range(32))
_POLICY_HASH = "sha256:" + "11" * 32
_CATALOG_HASH = "sha256:" + "22" * 32
_APPROVED = ApprovedHashes(policy_bundle_hash=_POLICY_HASH, tool_catalog_hash=_CATALOG_HASH)


# ---- harness ----------------------------------------------------------------


@dataclass
class _Attestation:
    mode: str = "enforcing"
    validity_seconds: int = 86400


@dataclass
class _Config:
    policy_bundle_path: str = "policies/"
    listen_addr: str = "0.0.0.0:8443"
    dev_mode: bool = False
    bearer_token: str | None = None
    attestation: _Attestation = field(default_factory=_Attestation)


@dataclass
class _SigningKeyStub:
    public_key_bytes: bytes = _KEY


@dataclass
class _Ctx:
    """The slice of RuntimeContext that refresh_measurement_binding touches."""

    config: _Config
    tee_provider: object
    signing_key: _SigningKeyStub = field(default_factory=_SigningKeyStub)
    gateway_measurement: object | None = None
    attestation_report: object | None = None


@pytest.fixture
def stub_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin code_digest: an editable test install has no RECORD to measure."""
    monkeypatch.setattr("cmcp_runtime.tee.measurement.code_digest", lambda: "c" * 64)


def _loadable_bundle(root: Path, rule: str) -> str:
    """A bundle load_policy_bundle accepts, so both digests see the same tree."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "authored_at": "2026-08-23T00:00:00Z",
                "author_identity": "conformance@example.com",
                "commit_sha": "abc123",
            }
        )
    )
    (root / "allow.cedar").write_text(rule)
    (root / "schema.cedarschema").write_text('{"cMCP": {"entityTypes": {}, "actions": {}}}')
    return str(root)


class _BoundProvider(SoftwareOnlyProvider):
    """Stands in for a launch-measurement platform.

    SoftwareOnlyProvider echoes the nonce into report_data, which is the shape
    SEV-SNP and TDX present to a collector, so only the provider name has to be
    borrowed for the binding path to engage.
    """

    def __init__(self, provider: str = "sev-snp") -> None:
        self._provider = provider

    def provider_name(self) -> str:
        return self._provider

    def get_attestation_report(self, nonce: bytes):  # type: ignore[no-untyped-def]
        report = super().get_attestation_report(nonce)
        report.provider = self._provider
        return report


def _claim(*, provider: str, report_data: str):
    """A signed TRACE claim whose report_data the caller controls."""
    key = SigningKey()
    chain = AuditChain("policy-tee-conformance")
    claim = generate_trace_claim(
        session_id="policy-tee-conformance",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider=provider,
            measurement="DEVELOPMENT_ONLY" if provider == "software-only" else "ab" * 32,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=_POLICY_HASH, enforcement_mode="enforcing", policy_version="1.0.0"
        ),
        tool_catalog=ToolCatalogInfo(hash=_CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=0,
            tool_calls_allowed=0,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=["external"], cross_boundary_events=[]
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
    )
    return _to_dict(claim), key


# ---- POLICY-TEE-001: Measurement composition --------------------------------


class TestPolicyTee001MeasurementComposition:
    """POLICY-TEE-001: the measurement commits code, policy and config, and keeps
    the three separable so a verifier learns which one moved."""

    def test_the_digest_commits_all_three_inputs(self, tmp_path, stub_code) -> None:
        config = _Config(policy_bundle_path=_loadable_bundle(tmp_path / "b", "permit(principal, action, resource);"))
        measurement = gateway_measurement(config)

        assert set(measurement.components) == {"code", "policy", "config"}
        assert measurement.digest_hex.startswith("sha256:")

    def test_a_policy_edit_moves_only_the_policy_component(self, tmp_path, stub_code) -> None:
        """A bare digest tells a verifier the gateway changed. The components tell
        it which input did, which is the complaint #433 makes about raw PCRs."""
        root = tmp_path / "b"
        config = _Config(policy_bundle_path=_loadable_bundle(root, "permit(principal, action, resource);"))
        before = gateway_measurement(config)

        (root / "allow.cedar").write_text("forbid(principal, action, resource);")
        after = gateway_measurement(config)

        assert after.digest != before.digest
        assert after.components["policy"] != before.components["policy"]
        assert after.components["code"] == before.components["code"]
        assert after.components["config"] == before.components["config"]

    def test_the_digest_is_stable_for_unchanged_inputs(self, tmp_path, stub_code) -> None:
        config = _Config(policy_bundle_path=_loadable_bundle(tmp_path / "b", "permit(principal, action, resource);"))

        assert gateway_measurement(config).digest == gateway_measurement(config).digest


# ---- POLICY-TEE-002: Report-data binding, and what a session claim shows -----


class TestPolicyTee002StartupBinding:
    """POLICY-TEE-002: the startup report commits the measurement in
    report_data[32:64] on the providers whose hardware offers no append-only
    index of its own."""

    def test_the_bound_provider_set_is_exactly_the_launch_measurement_platforms(self) -> None:
        expected = {"sev-snp", "azure-cvm-sev-snp", "tdx"}
        assert set(MEASUREMENT_BOUND_PROVIDERS) == expected

    @pytest.mark.parametrize("provider", sorted(MEASUREMENT_BOUND_PROVIDERS))
    def test_each_bound_provider_uses_report_data(self, provider: str) -> None:
        assert binds_measurement_into_report_data(provider) is True

    def test_the_startup_nonce_is_thumbprint_then_measurement(self) -> None:
        digest = b"\xab" * 32
        nonce = make_measurement_bound_nonce(_KEY, digest)

        assert len(nonce) == 64
        assert nonce[:32] == jwk_thumbprint(_KEY)
        assert nonce[32:] == digest

    def test_a_verifier_recomputing_from_scratch_matches_both_halves(
        self, tmp_path, stub_code
    ) -> None:
        """Nothing the verifier checks is read out of the report itself."""
        config = _Config(policy_bundle_path=_loadable_bundle(tmp_path / "b", "permit(principal, action, resource);"))
        measurement = gateway_measurement(config)
        provider = SoftwareOnlyProvider()

        report = provider.get_attestation_report(
            measurement_bound_nonce_for(_KEY, measurement)
        )
        report_data = bytes.fromhex(report.report_data)

        assert report_data[:32] == jwk_thumbprint(_KEY)
        assert report_data[32:] == gateway_measurement(config).digest


class TestPolicyTee002SessionClaimIsNotStartupEvidence:
    """POLICY-TEE-002: startup wiring alone does not establish both bindings in a
    session claim. Both nonces occupy report_data[32:64], so one report carries
    one of them, never both."""

    def test_the_two_nonces_contend_for_the_same_slot(self) -> None:
        chain = AuditChain("policy-tee-conformance")
        measurement_nonce = make_measurement_bound_nonce(_KEY, b"\xab" * 32)
        audit_nonce = make_audit_bound_nonce(_KEY, chain.chain_root)

        # Same layout, same first half, different second half.
        assert measurement_nonce[:32] == audit_nonce[:32] == jwk_thumbprint(_KEY)
        assert measurement_nonce[32:] != audit_nonce[32:]

    def test_a_session_claim_commits_the_audit_root_not_the_measurement(self) -> None:
        """So a session claim must not be read as evidence of measurement binding."""
        chain = AuditChain("policy-tee-conformance")
        measurement_digest = b"\xab" * 32
        session_nonce = make_audit_bound_nonce(_KEY, chain.chain_root)

        assert session_nonce[32:] == audit_root_commitment(chain.chain_root)
        assert session_nonce[32:] != measurement_digest


class TestPolicyTee002TpmIsNotCoveredByThisMechanism:
    """POLICY-TEE-002: a False return for TPM means 'not handled by report_data',
    which must not be read as evidence that the startup NV-certify pair is still
    current after a reload."""

    def test_tpm_does_not_bind_through_report_data(self) -> None:
        assert binds_measurement_into_report_data("tpm") is False

    def test_a_wrong_qualifying_data_is_rejected(self) -> None:
        """#709: before it, a quote with the wrong qualifying_data still verified."""
        pcr_digest = b"\x02" * 32
        attest = _tpms_attest(qualifying_data=b"\x01" * 32, pcr_digest=pcr_digest)

        result = verify_tpm_measurement(
            "sha256:" + pcr_digest.hex(),
            attest,
            expected_qualifying_data=b"\x99" * 32,
        )

        assert "qualifying_data" in result.unverified_fields

    def test_a_wrong_pcr_digest_is_rejected_independently(self) -> None:
        """The two rejections are separate, so a negative case can pin either."""
        qualifying = b"\x01" * 32
        attest = _tpms_attest(qualifying_data=qualifying, pcr_digest=b"\x02" * 32)

        result = verify_tpm_measurement(
            "sha256:" + ("\xee".encode().hex() * 0 or "ee" * 32),
            attest,
            expected_qualifying_data=qualifying,
        )

        assert "pcr_digest" in result.unverified_fields
        assert "qualifying_data" in result.verified_fields


_TPM_GENERATED_VALUE = 0xFF544347


def _tpms_attest(*, qualifying_data: bytes, pcr_digest: bytes) -> bytes:
    """A minimal well-formed bare TPMS_ATTEST carrying both committed values."""
    return (
        struct.pack(">I", _TPM_GENERATED_VALUE)
        + struct.pack(">H", 0x8018)  # TPM_ST_ATTEST_QUOTE
        + struct.pack(">H", 4) + b"name"  # qualifiedSigner
        + struct.pack(">H", len(qualifying_data)) + qualifying_data  # extraData
        + b"\x00" * 17  # clockInfo
        + b"\x00" * 8  # firmwareVersion
        + struct.pack(">I", 0)  # TPML_PCR_SELECTION count
        + struct.pack(">H", len(pcr_digest)) + pcr_digest
    )


# ---- POLICY-TEE-003: Freshness across a policy reload -----------------------


class TestPolicyTee003FreshnessOnReload:
    """POLICY-TEE-003: report_data carries only its current value, so the
    committed measurement is the live one only because a reload re-attests."""

    def test_a_reload_produces_a_report_reflecting_the_new_measurement(
        self, tmp_path, stub_code
    ) -> None:
        root = tmp_path / "b"
        config = _Config(policy_bundle_path=_loadable_bundle(root, "permit(principal, action, resource);"))
        ctx = _Ctx(config=config, tee_provider=_BoundProvider())

        assert refresh_measurement_binding(ctx) is True
        first = bytes.fromhex(ctx.attestation_report.report_data)

        (root / "allow.cedar").write_text("forbid(principal, action, resource);")
        assert refresh_measurement_binding(ctx) is True
        second = bytes.fromhex(ctx.attestation_report.report_data)

        assert second[32:] == gateway_measurement(config).digest
        assert second != first

    def test_an_unchanged_policy_still_re_attests(self, tmp_path, stub_code) -> None:
        """The control, and the reason there is no short-circuit on an unchanged
        digest: report_data carries no history, so the same digest re-signed now
        is a different assertion from the same digest signed an hour ago."""
        config = _Config(policy_bundle_path=_loadable_bundle(tmp_path / "b", "permit(principal, action, resource);"))
        ctx = _Ctx(config=config, tee_provider=_BoundProvider())

        assert refresh_measurement_binding(ctx) is True
        first_digest = ctx.gateway_measurement.digest

        assert refresh_measurement_binding(ctx) is True
        assert ctx.gateway_measurement.digest == first_digest

    def test_a_provider_outside_the_bound_set_does_not_rebind(
        self, tmp_path, stub_code
    ) -> None:
        """TPM and software-only return False here, which means 'not handled by
        this mechanism' and must not be read as a current binding."""
        config = _Config(policy_bundle_path=_loadable_bundle(tmp_path / "b", "permit(principal, action, resource);"))
        ctx = _Ctx(config=config, tee_provider=_BoundProvider("tpm"))

        assert refresh_measurement_binding(ctx) is False
        assert ctx.attestation_report is None

    def test_a_stale_pre_reload_report_no_longer_matches_a_recompute(
        self, tmp_path, stub_code
    ) -> None:
        root = tmp_path / "b"
        config = _Config(policy_bundle_path=_loadable_bundle(root, "permit(principal, action, resource);"))
        ctx = _Ctx(config=config, tee_provider=_BoundProvider())
        refresh_measurement_binding(ctx)
        stale = bytes.fromhex(ctx.attestation_report.report_data)

        (root / "allow.cedar").write_text("forbid(principal, action, resource);")

        assert stale[32:] != gateway_measurement(config).digest


# ---- POLICY-TEE-004: Verifier-side tamper detection -------------------------


class TestPolicyTee004TamperDetection:
    """POLICY-TEE-004: a verifier that recomputes the digest rejects a report
    committing anything else, and fails closed on an unusable expected value."""

    def test_a_matching_measurement_verifies(self) -> None:
        digest = b"\xab" * 32
        key = SigningKey()
        claim, _ = _claim(
            provider="sev-snp",
            report_data=make_measurement_bound_nonce(
                key.public_key_bytes, digest
            ).hex(),
        )
        result = verify_trace_claim(claim, _APPROVED, expected_gateway_measurement=digest)

        assert "measurement_binding" in result.verified_fields

    def test_a_substituted_measurement_is_rejected(self) -> None:
        key = SigningKey()
        claim, _ = _claim(
            provider="sev-snp",
            report_data=make_measurement_bound_nonce(
                key.public_key_bytes, b"\xab" * 32
            ).hex(),
        )
        result = verify_trace_claim(
            claim, _APPROVED, expected_gateway_measurement=b"\xee" * 32
        )

        assert "measurement_binding" in result.unverified_fields

    def test_an_unusable_expected_digest_fails_closed(self) -> None:
        """Junk must not be read as 'skip the check'."""
        key = SigningKey()
        claim, _ = _claim(
            provider="sev-snp",
            report_data=make_measurement_bound_nonce(
                key.public_key_bytes, b"\xab" * 32
            ).hex(),
        )
        result = verify_trace_claim(
            claim, _APPROVED, expected_gateway_measurement="not-a-digest"
        )

        assert "measurement_binding" in result.unverified_fields

    def test_the_check_is_opt_in_so_a_claim_cannot_vouch_for_itself(self) -> None:
        """Without an out-of-band expected digest no measurement verdict is given,
        because reading it from the claim would be circular."""
        key = SigningKey()
        claim, _ = _claim(
            provider="sev-snp",
            report_data=make_measurement_bound_nonce(
                key.public_key_bytes, b"\xab" * 32
            ).hex(),
        )
        result = verify_trace_claim(claim, _APPROVED)

        assert "measurement_binding" not in result.verified_fields
        assert "measurement_binding" not in result.unverified_fields


# ---- POLICY-TEE-005: Two constructions over one policy ----------------------


class TestPolicyTee005TwoConstructions:
    """POLICY-TEE-005: the measurement's policy component and the bundle's
    canonical hash are computed separately, at different startup steps, over the
    same policy. They are tested against the same mutation and are deliberately
    not asserted equal: #552 kept them separate on purpose."""

    def test_both_move_under_the_same_policy_mutation(self, tmp_path, stub_code) -> None:
        root = tmp_path / "b"
        path = _loadable_bundle(root, "permit(principal, action, resource);")

        measured_before = policy_digest(path)
        canonical_before = load_policy_bundle(path).bundle_hash

        (root / "allow.cedar").write_text("forbid(principal, action, resource);")

        measured_after = policy_digest(path)
        canonical_after = load_policy_bundle(path).bundle_hash

        assert measured_after != measured_before
        assert canonical_after != canonical_before

    def test_neither_is_asserted_to_equal_the_other(self, tmp_path, stub_code) -> None:
        """Two separately-computed values over the same bytes. Equality is not the
        property under test, and asserting it would undo #552's separation."""
        path = _loadable_bundle(tmp_path / "b", "permit(principal, action, resource);")

        measured = policy_digest(path)
        canonical = load_policy_bundle(path).bundle_hash.removeprefix("sha256:")

        assert measured != canonical

    def test_unchanged_policy_control_holds_both_still(self, tmp_path, stub_code) -> None:
        """The control: neither moves when the policy does not."""
        path = _loadable_bundle(tmp_path / "b", "permit(principal, action, resource);")

        assert policy_digest(path) == policy_digest(path)
        assert load_policy_bundle(path).bundle_hash == load_policy_bundle(path).bundle_hash

    def test_the_measurement_check_rejects_its_own_mismatch(self, tmp_path, stub_code) -> None:
        """Each verification path rejects independently of the other."""
        root = tmp_path / "b"
        config = _Config(policy_bundle_path=_loadable_bundle(root, "permit(principal, action, resource);"))
        before = gateway_measurement(config)

        (root / "allow.cedar").write_text("forbid(principal, action, resource);")

        key = SigningKey()
        claim, _ = _claim(
            provider="sev-snp",
            report_data=make_measurement_bound_nonce(
                key.public_key_bytes, before.digest
            ).hex(),
        )
        result = verify_trace_claim(
            claim, _APPROVED, expected_gateway_measurement=gateway_measurement(config).digest
        )

        assert "measurement_binding" in result.unverified_fields

    def test_the_bundle_hash_check_rejects_its_own_mismatch(self, tmp_path, stub_code) -> None:
        """And the canonical hash is checked against approved hashes, separately."""
        root = tmp_path / "b"
        path = _loadable_bundle(root, "permit(principal, action, resource);")
        approved = ApprovedHashes(
            policy_bundle_hash=load_policy_bundle(path).bundle_hash,
            tool_catalog_hash=_CATALOG_HASH,
        )

        (root / "allow.cedar").write_text("forbid(principal, action, resource);")
        mutated_hash = load_policy_bundle(path).bundle_hash

        assert mutated_hash != approved.policy_bundle_hash
