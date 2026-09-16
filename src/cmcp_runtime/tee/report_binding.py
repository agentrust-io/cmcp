"""Commit the gateway measurement into report_data where there is no NV index (#552).

#432 answered "what to measure": :func:`~cmcp_runtime.tee.measurement.gateway_measurement`
folds the installed code, the policy bundle and the effective config into one
SHA-256, and the TPM tier extends it into a ``TPM_NT_EXTEND`` NV index that is
certified by the platform AK. That path is validated on real Azure Trusted Launch
vTPM hardware.

It ran for the ``tpm`` provider only. The stated reason was that "SEV-SNP and TDX
commit their own binding through the report's fields", which is true and not
equivalent: **those fields carry the launch measurement, and a launch measurement
is boot-time.** It does not move when the Cedar bundle reloads mid-session through
``PolicyEvaluator._maybe_reload()``. So on SEV-SNP, TDX and Azure CVM the policy
actually in force was committed to nothing.

## What this module does

Nothing new is invented. The already-validated digest is wired into the one field
those platforms do sign over a caller-supplied value: ``report_data``. The nonce
layout is :func:`~cmcp_runtime.tee.base.make_measurement_bound_nonce`, which is the
same 64-byte shape AUDIT-006 already uses for the audit-chain root.

## Why re-attesting on reload is not optional

The NV index is append-only, so a verifier can appraise a *relation* between two
certified values and staleness shows up as a broken chain. ``report_data`` has no
history at all: it holds one value, and a report built before a bundle reload
looks perfectly well-formed on its own. The commitment is only as live as the last
report, so the report has to be replaced whenever the measurement moves. That is
what :func:`refresh_measurement_binding` is for, and a verifier that recomputes the
digest and compares is what catches a gateway that failed to do it.

## Failure handling, and why it is not fail-closed

A refresh that cannot re-attest logs and leaves the previous report in place; the
gateway keeps serving. Refusing traffic on a TEE hiccup would trade a *detectable*
weakness for an outage: a stale ``report_data`` no longer matches the recomputed
measurement, so the verifier rejects the claim. That mirrors how AUDIT-006 handles
a failed per-session attestation in :mod:`cmcp_runtime.session.manager`.

The startup path is stricter, and deliberately so: see ``_gateway_measurement`` in
:mod:`cmcp_runtime.startup`, where an unmeasurable gateway on one of these
platforms is fatal in production for the same reason it is fatal on the TPM tier.

Out of scope, per #552: binding the audit-chain root (that is session activity
rather than gateway identity, and AUDIT-006 already owns report_data[32:64] on the
per-session report), and validation on real SEV-SNP and TDX silicon.
"""

from __future__ import annotations

import logging
from typing import Any

from cmcp_runtime.tee.base import AttestationReport, make_measurement_bound_nonce
from cmcp_runtime.tee.measurement import (
    GatewayMeasurement,
    MeasurementUnavailable,
    gateway_measurement,
)

logger = logging.getLogger(__name__)

# Providers whose hardware report commits a boot-time launch measurement and offers
# no append-only index of its own, so the gateway measurement goes into report_data.
#
# "tpm" is absent because this report-data mechanism is not its measurement path.
# TPM startup separately collects an NV-certify pair, but the current reload path
# does not extend/re-certify that index and the ordinary TRACE schema does not carry
# the pair. A False return for TPM therefore means "not handled by this mechanism";
# it must not be read as evidence that the startup pair is current after a reload.
# "opaque" is absent because its provider raises rather than producing a report,
# and "software-only" is absent because there is no hardware to commit to -- the
# round trip is still exercised there through SoftwareOnlyProvider in tests.
MEASUREMENT_BOUND_PROVIDERS: frozenset[str] = frozenset({
    "sev-snp",
    "azure-cvm-sev-snp",
    "tdx",
})


def binds_measurement_into_report_data(provider_name: str) -> bool:
    """True when this provider commits the gateway measurement via ``report_data``."""
    return provider_name in MEASUREMENT_BOUND_PROVIDERS


def measurement_bound_nonce_for(
    signing_key_public_bytes: bytes, measurement: GatewayMeasurement
) -> bytes:
    """Build the 64-byte nonce committing ``measurement`` alongside the key binding."""
    return make_measurement_bound_nonce(signing_key_public_bytes, measurement.digest)


def refresh_measurement_binding(ctx: Any) -> bool:
    """Re-attest when the gateway measurement has moved, e.g. after a policy reload.

    ``ctx`` is a :class:`~cmcp_runtime.startup.RuntimeContext`; it is typed loosely
    to keep this module free of an import cycle back through startup.

    Called on every policy-bundle reload, including reloads that found nothing
    changed: see :meth:`~cmcp_runtime.policy.evaluator.PolicyEvaluator._notify_reload`
    for why an unchanged measurement is still worth re-signing.

    Returns True only when a new report was obtained and installed. Every other
    outcome -- a provider that does not use this binding, an unmeasurable gateway,
    a failed attestation call -- returns False and leaves ``ctx`` exactly as it was.

    Both ``ctx.gateway_measurement`` and ``ctx.attestation_report`` are assigned only
    after the new report is in hand, so a failure at any earlier step leaves neither
    changed. They are two statements rather than one atomic swap, which is worth
    stating exactly rather than overclaiming: a concurrent reader could observe the
    new measurement beside the old report for one interpreter step. That is benign
    today because nothing reads the pair together (``SessionManager`` reads only
    ``attestation_report``), and it is recorded here so that stops being an accident
    if something later does.
    """
    provider = ctx.tee_provider
    provider_name = provider.provider_name()
    if not binds_measurement_into_report_data(provider_name):
        return False

    try:
        measurement = gateway_measurement(ctx.config)
    except MeasurementUnavailable as exc:
        logger.warning(
            "#552: the gateway could not be re-measured after a policy-bundle "
            "reload, so "
            "report_data still commits the previous measurement and verification "
            "will reject it: %s %s",
            exc,
            exc.detail or "",
        )
        return False

    # No short-circuit on an unchanged digest. #552 asks for a refresh on every
    # reload precisely because report_data carries no history: an identical digest
    # re-signed now is a different assertion from the same digest signed an hour
    # ago, and the second is the only thing skipping would leave a verifier.
    current = getattr(ctx, "gateway_measurement", None)

    nonce = measurement_bound_nonce_for(ctx.signing_key.public_key_bytes, measurement)
    try:
        report = provider.get_attestation_report(nonce)
    except Exception as exc:  # noqa: BLE001 - any TEE fault leaves the old binding
        logger.warning(
            "#552: re-attestation failed after the gateway measurement changed, so "
            "report_data still commits the previous measurement and verification "
            "will reject it. provider=%s error=%s: %s",
            provider_name,
            type(exc).__name__,
            exc,
        )
        return False

    # Guard on the concrete type for the same reason AUDIT-006 does: a provider that
    # returns something malformed must not displace a well-formed report.
    if not isinstance(report, AttestationReport):
        logger.warning(
            "#552: the TEE provider returned a %s, not an AttestationReport - "
            "keeping the previous report. provider=%s",
            type(report).__name__,
            provider_name,
        )
        return False

    unchanged = current is not None and current.digest == measurement.digest
    previous = current.digest_hex if current is not None else "none"
    ctx.gateway_measurement = measurement
    ctx.attestation_report = report
    logger.info(
        "#552: gateway measurement rebound into report_data: %s -> %s%s "
        "(code=%s policy=%s config=%s) provider=%s",
        previous,
        measurement.digest_hex,
        " (unchanged, re-signed)" if unchanged else "",
        measurement.components["code"][:12],
        measurement.components["policy"][:12],
        measurement.components["config"][:12],
        provider_name,
    )
    return True
