"""Pinned trust anchors for TPM attestation key certificate chains.

A chain that validates to an unpinned root is not evidence: an attacker who can
present any self-consistent chain would pass. These are the roots cMCP will
accept, keyed by platform.

Adding a platform means adding its vendor root here, which is a deliberate,
reviewable act. For client firmware TPMs the vendor roots are not yet published in
a form we can pin, which is why that tier is still open (see issue #431).
"""

from __future__ import annotations

# Azure Trusted Launch / confidential VM virtual TPM.
#
# Chain observed on a Standard_D2s_v5 in eastus, 2026-07-31, with the platform
# attestation key certificate read from vTPM NV index 0x01C101D0:
#
#   CN=<vm-id>.TrustedVM.Azure.windows.net
#     CN=Azure Cloud Virtual TPM CA - 11
#       CN=Azure Cloud Virtual TPM CA 2025
#         CN=Azure Virtual TPM Root Certificate Authority 2023   <- this cert
#
# On that host the intermediates are fetchable over the certificate AIA extension,
# so only the self-signed root is pinned here.
#
# NOT SUFFICIENT FLEET-WIDE, measured 2026-08-01 on a Standard_D2s_v7 in eastus2.
# The same NV index there held a 994-byte certificate issued by
# CN=Global Virtual TPM CA - 03 with NO AIA extension, so no intermediates can be
# fetched, none are stored elsewhere in NV, and no chain reaches this root.
# Verification correctly fails closed on such a host. Azure runs both hierarchies
# concurrently, so a deployment must pin the root its own hosts actually present;
# see docs/testing/hardware-validation.md.
AZURE_VTPM_ROOT_2023_PEM = b"""\
-----BEGIN CERTIFICATE-----
MIIFsDCCA5igAwIBAgIQUfQx2iySCIpOKeDZKd5KpzANBgkqhkiG9w0BAQwFADBp
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTow
OAYDVQQDEzFBenVyZSBWaXJ0dWFsIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhv
cml0eSAyMDIzMB4XDTIzMDYwMTE4MDg1M1oXDTQ4MDYwMTE4MTU0MVowaTELMAkG
A1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE6MDgGA1UE
AxMxQXp1cmUgVmlydHVhbCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
MjAyMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALoMMwvdRJ7+bW00
adKE1VemNqJS+268Ure8QcfZXVOsVO22+PL9WRoPnWo0r5dVoomYGbobh4HC72s9
sGY6BGRe+Ui2LMwuWnirBtOjaJ34r1ZieNMcVNJT/dXW5HN/HLlm/gSKlWzqCEx6
gFFAQTvyYl/5jYI4Oe05zJ7ojgjK/6ZHXpFysXnyUITJ9qgjn546IJh/G5OMC3mD
fFU7A/GAi+LYaOHSzXj69Lk1vCftNq9DcQHtB7otO0VxFkRLaULcfu/AYHM7FC/S
q6cJb9Au8K/IUhw/5lJSXZawLJwHpcEYzETm2blad0VHsACaLNucZL5wBi8GEusQ
9Wo8W1p1rUCMp89pufxa3Ar9sYZvWeJlvKggWcQVUlhvvIZEnT+fteEvwTdoajl5
qSvZbDPGCPjb91rSznoiLq8XqgQBBFjnEiTL+ViaZmyZPYUsBvBY3lKXB1l2hgga
hfBIag4j0wcgqlL82SL7pAdGjq0Fou6SKgHnkkrV5CNxUBBVMNCwUoj5mvEjd5mF
7XPgfM98qNABb2Aqtfl+VuCkU/G1XvFoTqS9AkwbLTGFMS9+jCEU2rw6wnKuGv1T
x9iuSdNvsXt8stx4fkVeJvnFpJeAIwBZVgKRSTa3w3099k0mW8qGiMnwCI5SfdZ2
SJyD4uEmszsnieE6wAWd1tLLg1jvAgMBAAGjVDBSMA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRL/iZalMH2M8ODSCbd8+WwZLKqlTAQ
BgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEALgNAyg8I0ANNO/8I
2BhpTOsbywN2YSmShAmig5h4sCtaJSM1dRXwA+keY6PCXQEt/PRAQAiHNcOF5zbu
OU1Bw/Z5Z7k9okt04eu8CsS2Bpc+POg9js6lBtmigM5LWJCH1goMD0kJYpzkaCzx
1TdD3yjo0xSxgGhabk5Iu1soD3OxhUyIFcxaluhwkiVINt3Jhy7G7VJTlEwkk21A
oOrQxUsJH0f2GXjYShS1r9qLPzLf7ykcOm62jHGmLZVZujBzLIdNk1bljP9VuGW+
cISBwzkNeEMMFufcL2xh6s/oiUnXicFWvG7E6ioPnayYXrHy3Rh68XLnhfpzeCzv
bz/I4yMV38qGo/cAY2OJpXUuuD/ZbI5rT+lRBEkDW1kxHP8cpwkRwGopV8+gX2KS
UucIIN4l8/rrNDEX8T0b5U+BUqiO7Z5YnxCya/H0ZIwmQnTlLRTU2fW+OGG+xyIr
jMi/0l6/yWPUkIAkNtvS/yO7USRVLPbtGVk3Qre6HcqacCXzEjINcJhGEVg83Y8n
M+Y+a9J0lUnHytMSFZE85h88OseRS2QwqjozUo2j1DowmhSSUv9Na5Ae22ycciBk
EZSq8a4rSlwqthaELNpeoTLUk6iVoUkK/iLvaMvrkdj9yJY1O/gvlfN2aiNTST/2
bd+PA4RBToG9rXn6vNkUWdbLibU=
-----END CERTIFICATE-----
"""

# Platform key to pinned root. Used by cmcp_verify.tpm.verify_tpm_quote_chained.
TPM_TRUSTED_ROOTS: dict[str, bytes] = {
    "azure-vtpm": AZURE_VTPM_ROOT_2023_PEM,
}


def trusted_roots_for(platform: str) -> bytes:
    """
    Return the pinned root(s) for a platform.

    Raises KeyError rather than returning an empty bundle: verifying against no
    trust anchor would silently accept any chain.
    """
    return TPM_TRUSTED_ROOTS[platform]
