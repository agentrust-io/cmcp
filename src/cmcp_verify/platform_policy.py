"""Verifier-owned SNP platform requirements, separate from report authenticity."""
from __future__ import annotations

from dataclasses import dataclass

from agent_manifest import (
    PLATFORM_INFO_BITS,
    appraise_platform_info,
    parse_platform_info,
)


@dataclass(frozen=True)
class SnpPlatformPolicy:
    """Require named bits on/off in an authenticated SNP PLATFORM_INFO word.

    This is relying-party input, never a policy accepted from the claim issuer.
    Passing even an empty policy requires authenticated SNP evidence. It does
    not appraise guest POLICY, TCB versions, revocation, GPU state, or runtime
    behavior. Names and their bit meanings come from agent-manifest.
    """

    require: frozenset[str] = frozenset()
    forbid: frozenset[str] = frozenset()
    reject_unrecognized_bits: bool = False

    def __post_init__(self) -> None:
        for name in ("require", "forbid"):
            value = getattr(self, name)
            if not isinstance(value, (set, frozenset)) or not all(
                isinstance(item, str) for item in value
            ):
                raise ValueError(f"{name} must be a set of PLATFORM_INFO field names")
            object.__setattr__(self, name, frozenset(value))
        unknown = (self.require | self.forbid) - set(PLATFORM_INFO_BITS)
        if unknown:
            raise ValueError("unknown PLATFORM_INFO fields: " + ", ".join(sorted(unknown)))
        if self.require & self.forbid:
            raise ValueError("platform policy cannot require and forbid the same field")
        if not isinstance(self.reject_unrecognized_bits, bool):
            raise ValueError("reject_unrecognized_bits must be a boolean")

    def appraise(self, platform_info: int) -> None:
        """Raise on an unmet requirement; caller must first authenticate the word."""
        appraise_platform_info(
            parse_platform_info(platform_info),
            require=set(self.require),
            forbid=set(self.forbid),
            reject_unrecognized_bits=self.reject_unrecognized_bits,
        )
