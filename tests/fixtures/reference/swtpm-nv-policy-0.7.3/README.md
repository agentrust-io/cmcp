# swtpm NV policy-binding reference corpus

This corpus was emitted by a fresh `swtpm` 0.7.3 instance through
`tpm2-tools` 5.6 in an Ubuntu 24.04 container. Neither cMCP nor Agent Manifest
constructed the signed attestation or signature bytes. The synthetic certificate
binds the exact TPM-created AK public key to a test root; it establishes no
hardware provenance or production enrollment.

The `production/` pair uses cMCP's exact configured index profile:

- handle `0x01500432`;
- SHA-256 Name algorithm;
- `TPM_NT_EXTEND`;
- `ownerwrite|ownerread|authread|no_da|written` (`0x22060042`);
- empty authorization policy; and
- a 32-byte data area, certified in full at offset zero.

The resulting written Name is
`000bd884eed008e17b8e06485bcf29a5f0e88ca44a4355d711fa2cafb368c3ff3763`.
The test independently derives it from the verifier-owned `TPMS_NV_PUBLIC`
serialization and compares it with the Name in both signed attestations and the
output of `tpm2_nvreadpublic`.

## Negative profiles

`wrong-public/` reuses handle `0x01500432` but defines it as an ordinary writable
index (`0x22060002`). Its 32-byte pre- and post-values were deliberately arranged
to satisfy `post = SHA256(pre || gateway_digest)`, and the same fresh AK signed
both phase-bound attestations. Its signed Name is
`000b7ee6de688f90e26e0bbf3b8fc4d3ad1888999a5c85129f9f1a0bf56aefd58d18`.
This is an independently produced regression for the rule that valid signatures,
matching Names, and an internally consistent byte relation do not authorize an
evidence-selected NV public area.

`wrong-range/` uses the canonical production Name, but both valid AK signatures
certify only 16 bytes at offset 16. This is a regression for the separate rule
that the signed range must equal the policy-authorized offset zero and 32-byte
extent.

The negative profiles are not corrupt-signature tests: verification authenticates
the chain, signatures, and nonce/phase transcript bindings before denying the
public-area or range mismatch. The transcript is fresh only when a surrounding
protocol issues and consumes the nonce correctly; the corpus itself does not
demonstrate that protocol state.

## Producer sequence

The software TPM was started with Unix control and command sockets, then initialized
through `TCTI=swtpm`. The essential production commands were:

```sh
tpm2_createek -G rsa -c ek.ctx -u ek.pub
tpm2_createak -C ek.ctx -G rsa -g sha256 -s rsassa \
  -c ak.ctx -u ak.pub -n ak.name

tpm2_nvdefine 0x01500432 -C o -g sha256 -s 32 \
  -a 'ownerread|ownerwrite|authread|no_da|nt=extend'
tpm2_nvextend 0x01500432 -C o -i seed-event.bin

tpm2_nvcertify -C ak.ctx -c o -g sha256 -s rsassa -f tss \
  -q ac2bc955b7d97a5589f9a6c48db86f87aea9d9af22e43cc97330f7b560145fa3 \
  --size 32 --offset 0 --attestation pre-attest.bin \
  -o pre-tpmt-signature.bin 0x01500432
tpm2_nvextend 0x01500432 -C o -i gateway-digest.bin
tpm2_nvcertify -C ak.ctx -c o -g sha256 -s rsassa -f tss \
  -q 230587d8162f6a14fb8573d2b3fddec4b98413ffad0f83e804aff3740d8bfa8c \
  --size 32 --offset 0 --attestation post-attest.bin \
  -o post-tpmt-signature.bin 0x01500432
```

For the wrong-public-area profile, the same handle was undefined and recreated
without `nt=extend`; deterministic pre/post bytes were written before the two
certifies. For the wrong-range profile, `tpm2_nvcertify` used `--size 16
--offset 16` against the production profile. The CA private key, TPM state,
context files, and all other private material were excluded from the corpus and
destroyed with the isolated generation environment.

## Assurance boundary

The corpus demonstrates interoperability with genuine software-TPM output and
exercises the verifier's exact signed-Name and signed-range policy. It does not
prove a physical TPM, vendor enrollment, EK-to-AK credential activation,
non-exportability, hardware key residency, requester/TPM co-location, boot state,
runtime integrity, or safe application behavior. A software TPM may be operated
as a remote signing oracle.
