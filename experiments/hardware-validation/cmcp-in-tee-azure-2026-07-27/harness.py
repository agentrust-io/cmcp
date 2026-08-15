"""cMCP attestation collector + verifier, running inside a real SEV-SNP CVM."""
import json, sys, urllib.request
sys.path.insert(0, "/home/azureuser/src")
from cmcp_runtime.tee.azure_cvm import AzureCVMProvider
from cmcp_verify.azure_cvm import verify_azure_cvm_measurement

out = {}
p = AzureCVMProvider()
out["provider_detect"] = p.detect()
nonce = bytes.fromhex("11" * 32)
rep = p.get_attestation_report(nonce)
out["provider"] = rep.provider
out["measurement"] = rep.measurement
out["report_data"] = rep.report_data
out["evidence_bytes"] = len(rep.raw_evidence or b"")

chain = urllib.request.urlopen("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain", timeout=30).read()
from cryptography import x509
certs = x509.load_pem_x509_certificates(chain)
root = next(c for c in certs if c.subject == c.issuer)   # ARK only, not the ASK+ARK bundle
ark = root.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.PEM)
out["ark_subject"] = root.subject.rfc4514_string()
res = verify_azure_cvm_measurement(rep.measurement, rep.raw_evidence, nonce.hex(), ark)
out["verified"] = res.verified
out["failure_reason"] = res.failure_reason
out["verified_fields"] = list(getattr(res, "verified_fields", []) or [])
out["unverified_fields"] = list(getattr(res, "unverified_fields", []) or [])

bad = verify_azure_cvm_measurement(rep.measurement, rep.raw_evidence, "00" * 32, ark)
out["wrong_nonce_rejected"] = not bad.verified
out["wrong_nonce_reason"] = bad.failure_reason
print(json.dumps(out, indent=2, default=str))
