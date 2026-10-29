"""Ed25519 signing key management: implements issue #46."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


class SigningKey:
    """
    Ed25519 keypair the gateway signs TRACE Claims with.

    By default it is generated at startup, held only in memory and never written to
    disk or logged, so every restart produces a different keypair (conformance:
    ATTEST-004). With sealing on the TPM tier (#462) the same key comes back on
    every start from a seed the TPM unseals, and ATTEST-004 does not apply.
    The public key is embedded in every TRACE Claim so verifiers can check
    signatures without trusting the operator.
    """

    def __init__(self, seed: bytes | None = None) -> None:
        self._private: Ed25519PrivateKey = (
            Ed25519PrivateKey.generate()
            if seed is None
            else Ed25519PrivateKey.from_private_bytes(seed)
        )
        self._public: Ed25519PublicKey = self._private.public_key()
        self._public_bytes: bytes = self._public.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    @property
    def public_key_hex(self) -> str:
        """32-byte Ed25519 public key, hex-encoded: included in every TRACE Claim."""
        return self._public_bytes.hex()

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte public key bytes."""
        return self._public_bytes

    def sign(self, data: bytes) -> bytes:
        """Sign data with the private key. Returns 64-byte Ed25519 signature."""
        return self._private.sign(data)

    def __repr__(self) -> str:
        return f"SigningKey(public={self.public_key_hex[:16]}...)"
