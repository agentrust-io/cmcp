"""
Vendored Azure vTPM CA certificates for hosts that publish no AIA.

Azure Trusted Launch presents more than one vTPM attestation-key certificate
hierarchy at NV index 0x01C101D0. One is issued by ``Azure Cloud Virtual TPM
CA - 11`` and carries an AIA extension, so :func:`TPMProvider._chain_from_leaf`
can walk to the root over the network. The other is issued by ``Global Virtual
TPM CA - 03`` and carries no AIA at all, so there is nothing to walk and the
chain stops at the leaf. Verification then fails closed, correctly but
uselessly, because the chain never reaches a pinned root.

Both hierarchies terminate at the same self-signed root, the one already pinned
in ``cmcp_verify.tpm_roots``. What is missing on a CA-03 host is therefore not a
trust anchor but the intermediate needed to reach it, and Microsoft does not
publish that intermediate at a fetchable URL -- only inline in the Trusted
Launch FAQ. It has to be vendored, which is what this module does.

Source, both certificates:
    https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
    ("vTPM AK certificate" section, the ``.p7b`` for Root + ICA-03)

The root is additionally downloadable, and was verified byte-identical to the
copy published inline on that page and to the constant pinned in
``cmcp_verify.tpm_roots``:
    https://www.microsoft.com/pkiops/certs/Azure%20Virtual%20TPM%20Root%20Certificate%20Authority%202023.crt

Adding a certificate here does not widen what is trusted. Nothing in this module
is a trust anchor: these are chain-building material, supplied in place of an
AIA fetch, and :func:`vendored_issuer_for` returns a certificate only after
checking that it actually signed the one being resolved. A wrong or colliding
certificate cannot produce a chain that verifies -- it fails closed exactly as
it does today.
"""

from __future__ import annotations

import logging

from cryptography import x509

logger = logging.getLogger(__name__)

# CN=Global Virtual TPM CA - 03
#   issuer   CN=Azure Virtual TPM Root Certificate Authority 2023
#   serial   33000000092740E5AC727B0EA6000000000009
#   validity 2025-04-24 -> 2027-04-24
#   sha256   FD:7C:92:DA:BC:E4:DC:EC:9F:EA:A3:0F:8B:08:7A:DA:
#            05:98:41:31:89:18:21:52:B8:81:F5:56:40:64:A2:9C
#
# NOTE: intermediates expire on a far shorter cycle than roots, and there is no
# URL to poll for the replacement. test_vtpm_ca_bundle.py fails ahead of the
# notAfter above so this is refreshed deliberately rather than discovered as an
# outage on a CA-03 host.
GLOBAL_VIRTUAL_TPM_CA_03_PEM = b"""\
-----BEGIN CERTIFICATE-----
MIIFnDCCA4SgAwIBAgITMwAAAAknQOWscnsOpgAAAAAACTANBgkqhkiG9w0BAQwF
ADBpMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MTowOAYDVQQDEzFBenVyZSBWaXJ0dWFsIFRQTSBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAyMDIzMB4XDTI1MDQyNDE4MDExN1oXDTI3MDQyNDE4MDExN1owJTEj
MCEGA1UEAxMaR2xvYmFsIFZpcnR1YWwgVFBNIENBIC0gMDMwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDYGYtis5ka0cxQkhU11jslgX6wzjR/UXQIFdUn
8juTUMJl91VokwUPX3WfXeog7mtbWyYWD8SI0BSnchRGlV8u3AhcW61/HetHqmIL
tD0c75UATi+gsTQnpwKPA/m38MGGyXFETr3xHXjilUPfIhmxO4ImuNJ0R95bZYhx
bLYmOZpVUcj8oz980An8HlIqSzrskQR6NiuEmikHkHc1/CpoNunrr8kQNPF6gxex
IrvXsKLUAuUqnNtcQWc/8Er5EN9+TdX6AOjUmKriVGbCInP1m/aC+DWH/+aJ/8aD
pKze6fe7OHh2BL9hxqIsmJAStIh4siRdLYTt8hKGmkdzOWnRAgMBAAGjggF/MIIB
ezASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwICBDAXBgNVHSUEEDAO
BgVngQUIAQYFZ4EFCAMwHQYDVR0OBBYEFGcJhvj5gV6TrfnJZOcUCtqZywotMB8G
A1UdIwQYMBaAFEv+JlqUwfYzw4NIJt3z5bBksqqVMHYGA1UdHwRvMG0wa6BpoGeG
ZWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL0F6dXJlJTIwVmly
dHVhbCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIw
MjMuY3JsMIGDBggrBgEFBQcBAQR3MHUwcwYIKwYBBQUHMAKGZ2h0dHA6Ly93d3cu
bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvQXp1cmUlMjBWaXJ0dWFsJTIwVFBN
JTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMy5jcnQwDQYJ
KoZIhvcNAQEMBQADggIBAJPP3Z2z1zhzUS3qSRVgyoUVnaxCGuMHzPQAZuoPBVpz
wKnv4HqyjMgT8pBtQqxkqAsg7KiqbPfO97bMCHcuqkkfHjw8yg6IYt01RjUjVPKq
lrsY2iw7hFWNWr8SGMa10JdNYNyf5dxob5+mKAwEOhLzKNwq9rM/uIvZky77pNly
RLt55XEPfBMYdI9I8uQ5Uqmrw7mVJfERMfTBhSQF9BrcajAsaLcs7qEUyj0yUdJf
cgZkfCoUEUSPr3OwLHaYeV1J6VidhIYsYo53sXXal91d60NspYgei2nJFei/+R3E
SWnGbPBW+EQ4FbvZXxu57zUMX9mM7lC+GoXLvA6/vtKShEi9ZXl2PSnBQ/R2A7b3
AXyg4fmMLFausEk6OiuU8E/bvp+gPLOJ8YrX7SAJVuEn+koJaK5G7os5DMIh7/KM
l9cI9WxPwqoWjp4VBfrF4hDOCmKWrqtFUDQCML8qD8RTxlQKQtgeGAcNDfoAuL9K
VtSG5/iIhuyBEFYEHa3vRWbSaHCUzaHJsTmLcz4cp1VDdepzqZRVuErBzJKFnBXb
zRNW32EFmcAUKZImIsE5dgB7y7eiijf33VWNfWmK05fxzQziWFWRYlET4SVc3jMn
PBiY3N8BfK8EBOYbLvzo0qn2n3SAmPhYX3Ag6vbbIHd4Qc8DQKHRV0PB8D3jPGmD
-----END CERTIFICATE-----
"""

# CN=Azure Virtual TPM Root Certificate Authority 2023
#   self-signed, validity 2023-06-01 -> 2048-06-01
#   sha256   E6:C5:96:B1:7F:8F:FE:FB:A5:C3:00:F7:14:CF:B1:26:
#            0C:60:28:70:4E:CF:7B:EC:C4:AB:50:18:EF:B0:0E:95
#
# Present so an assembled chain terminates at the root, which is what the
# verifier compares against its pinned set. Byte-identical to
# cmcp_verify.tpm_roots.AZURE_VTPM_ROOT_2023_PEM; a test asserts they stay so.
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

_BUNDLE_PEMS = (GLOBAL_VIRTUAL_TPM_CA_03_PEM, AZURE_VTPM_ROOT_2023_PEM)


def _bundle() -> list[x509.Certificate]:
    return [x509.load_pem_x509_certificate(pem) for pem in _BUNDLE_PEMS]


def vendored_issuer_for(cert: x509.Certificate) -> x509.Certificate | None:
    """
    Return the vendored certificate that issued ``cert``, or None.

    Subject/issuer names are not identities: a name match alone would let a
    same-named certificate with a different key into the chain. The candidate is
    therefore accepted only if it actually signed ``cert``, so the worst case for
    an unrecognised or re-keyed CA is the present behaviour, a short chain that
    fails to reach a pinned root.
    """
    if cert.subject == cert.issuer:
        # A self-signed certificate is its own issuer and would resolve to
        # itself, appending forever. The caller already stops at the root; this
        # keeps that from depending on the order of two checks.
        return None
    for candidate in _bundle():
        if candidate.subject != cert.issuer:
            continue
        try:
            cert.verify_directly_issued_by(candidate)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "vendored candidate %s did not sign %s: %s",
                candidate.subject.rfc4514_string(),
                cert.subject.rfc4514_string(),
                exc,
            )
            continue
        return candidate
    return None
