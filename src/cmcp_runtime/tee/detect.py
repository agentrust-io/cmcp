"""TEE provider detection loop: implements issue #72 (dev mode) and #77 (abstraction)."""

from __future__ import annotations

import logging

from cmcp_runtime.config import Config
from cmcp_runtime.config import TEEProvider as TEEProviderEnum
from cmcp_runtime.errors import AttestationProviderUnsupported
from cmcp_runtime.tee.base import SoftwareOnlyProvider, TEEProvider

logger = logging.getLogger(__name__)

# Detection probe order from docs/spec/attestation.md §1.1
_PROBE_ORDER: list[str] = ["tpm", "sev-snp", "tdx", "opaque"]


def _get_provider_impl(name: str, config: Config | None = None) -> TEEProvider | None:
    """Import and return a provider implementation by name, or None if not found."""
    if name == "tpm":
        try:
            from cmcp_runtime.tee.tpm import TPMProvider
            return TPMProvider()
        except ImportError:
            return None
    if name == "sev-snp":
        try:
            from cmcp_runtime.tee.sev_snp import SEVSNPProvider
            expected = config.attestation.expected_measurement if config else None
            return SEVSNPProvider(expected_measurement=expected)
        except ImportError:
            return None
    if name == "tdx":
        try:
            from cmcp_runtime.tee.tdx import TDXProvider
            return TDXProvider()
        except ImportError:
            return None
    if name == "opaque":
        try:
            from cmcp_runtime.tee.opaque import OpaqueProvider
            return OpaqueProvider()
        except ImportError:
            return None
    return None


def detect_provider(config: Config) -> TEEProvider:
    """
    Detect and return the active TEE provider.

    Follows the probe order from docs/spec/attestation.md §1.1:
      tpm -> sev-snp -> tdx -> opaque

    If no hardware provider is found:
    - CMCP_DEV_MODE=1: returns SoftwareOnlyProvider with a WARN log
    - Otherwise: raises AttestationProviderUnsupported (gateway must not start)

    If config.attestation.provider is not "auto", only that provider is tried.
    """
    dev_mode = config.dev_mode

    if config.attestation.provider != TEEProviderEnum.AUTO:
        # Explicit provider requested
        name = config.attestation.provider.value
        if name == "software-only":
            if not dev_mode:
                raise AttestationProviderUnsupported(
                    "provider=software-only requires CMCP_DEV_MODE=1"
                )
            logger.warning(
                "Running in development mode: attestation is not hardware-backed. "
                "TRACE Claims produced here must not be used for compliance purposes."
            )
            return SoftwareOnlyProvider()
        impl = _get_provider_impl(name, config)
        if impl is None or not impl.detect():
            raise AttestationProviderUnsupported(
                f"Requested provider '{name}' not available on this host",
                detail="Check that the TEE hardware is present and accessible",
            )
        logger.info("TEE provider: %s (explicitly configured)", name)
        return impl

    # Auto-detection
    for name in _PROBE_ORDER:
        impl = _get_provider_impl(name, config)
        if impl is not None and impl.detect():
            logger.info("TEE provider: %s (auto-detected)", name)
            return impl

    # No hardware provider found
    if dev_mode:
        logger.warning(
            "No hardware TEE detected. Running in development mode: "
            "attestation is not hardware-backed. "
            "TRACE Claims produced here must not be used for compliance purposes."
        )
        return SoftwareOnlyProvider()

    raise AttestationProviderUnsupported(
        "No supported TEE provider detected and CMCP_DEV_MODE is not set. "
        "The gateway cannot start without hardware attestation. "
        "Set CMCP_DEV_MODE=1 for local development.",
        detail=f"Probed: {', '.join(_PROBE_ORDER)}",
    )
