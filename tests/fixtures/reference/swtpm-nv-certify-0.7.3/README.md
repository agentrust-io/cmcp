# swtpm NV-certify reference pair

These files are an independent-producer reference for cMCP's gateway-measurement
appraisal path. They were emitted by `swtpm` 0.7.3 and `tpm2-tools` 5.6 in an
Ubuntu 24.04 container, using a restricted RSA-2048 attestation key configured for
RSASSA/SHA-256. Neither cMCP nor Agent Manifest produced the attestation or
signature bytes.

The pair certifies a 32-byte `TPM_NT_EXTEND` index immediately before and after
extending the gateway digest:

```text
post-contents = SHA256(pre-contents || gateway-digest)
```

Both attestations are bare 173-byte `TPMS_ATTEST` structures with type
`TPM_ST_ATTEST_NV` (`0x8014`). Both signatures are 262-byte marshalled
`TPMT_SIGNATURE` values: RSASSA (`0x0014`), SHA-256 (`0x000b`), and a 256-byte
signature. `nv-public.yaml` is the output of `tpm2_nvreadpublic 0x01500018`; its
Name is checked against the Name signed into both attestations.

## Signed bindings

- Verifier nonce: 32 bytes of `a5`.
- Pre qualifying data:
  `ac2bc955b7d97a5589f9a6c48db86f87aea9d9af22e43cc97330f7b560145fa3`.
- Post qualifying data:
  `230587d8162f6a14fb8573d2b3fddec4b98413ffad0f83e804aff3740d8bfa8c`.
- NV handle used by the producer: `0x01500018`.
- Certified offset and size: `0` and `32` bytes.
- Index Name:
  `000bcf69802ad7625fffd515aecef934a1632ca6c7df36bf5a4e241d33701465a854`.
- Gateway digest:
  `4ea5ee68fea05586106890ded5733820bb77d919cda27bc4b8139b7cd33b8889`.

The qualifying data are cMCP's length-prefixed, phase-separated hashes for
`pre` and `post`. The first extend used `seed-event.bin` because a newly defined
extend index is uninitialized and cannot yet be certified.

## Certificate construction and assurance boundary

`ak-public.pem` is the exact public key returned by `tpm2_readpublic` for the swtpm
AK. `ak-cert.pem` is a test certificate made afterwards by placing that public key
under `synthetic-root.pem`; the test asserts that the certificate and TPM output
contain identical public keys. The synthetic CA private key and all TPM state,
contexts, and private material were destroyed and are not committed.

This corpus proves that the parser and appraisal path accept one independently
emitted software-TPM wire image, authenticate both signatures under the included
test chain, bind the two phases and index Name, and check the extend relation. It
does **not** prove a physical TPM, vendor enrollment, EK-to-AK credential
activation, non-exportability, hardware key residency, requester/TPM co-location,
boot state, runtime integrity, or safe application behavior. A software TPM may
also be operated as a remote signing oracle.

## Producer sequence

The essential commands were:

```sh
tpm2_createek -G rsa -c ek.ctx -u ek.pub
tpm2_createak -C ek.ctx -G rsa -g sha256 -s rsassa \
  -c ak.ctx -u ak.pub -n ak.name
tpm2_flushcontext -t

tpm2_nvdefine 0x01500018 -C o -g sha256 -s 32 \
  -a 'ownerread|ownerwrite|nt=extend'
tpm2_nvextend 0x01500018 -C o -i seed-event.bin

tpm2_nvcertify -C ak.ctx -c o -g sha256 -s rsassa -f tss \
  -q ac2bc955b7d97a5589f9a6c48db86f87aea9d9af22e43cc97330f7b560145fa3 \
  --size 32 --offset 0 --attestation pre-attest.bin \
  -o pre-tpmt-signature.bin 0x01500018

tpm2_nvextend 0x01500018 -C o -i gateway-digest.bin

tpm2_nvcertify -C ak.ctx -c o -g sha256 -s rsassa -f tss \
  -q 230587d8162f6a14fb8573d2b3fddec4b98413ffad0f83e804aff3740d8bfa8c \
  --size 32 --offset 0 --attestation post-attest.bin \
  -o post-tpmt-signature.bin 0x01500018
```

`tpm2_print` 5.6 does not understand the `TPM_ST_ATTEST_NV` union. The tests
therefore parse the signed structures with the released Agent Manifest parser and
independently compare the signed Name with `tpm2_nvreadpublic` output.
