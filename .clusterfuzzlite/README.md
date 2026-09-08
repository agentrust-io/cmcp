# Fuzzing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/),
running Atheris against the untrusted input surface. Mirrors the setup in
agentrust-io/agent-manifest, where the same targets found a real bug.

## What is fuzzed

| Target | Surface |
| --- | --- |
| `fuzz_attestation_parsers.py` | `parse_event_log` walks a TCG event log: a Spec ID header declaring which digest algorithms are present and how long each is, then events each carrying their own declared digest count and data length. `parse_nv_certify` reads a bare or size-prefixed TPM NV certification. Every one of those lengths comes from the blob, which arrives from the platform before anything about it is verified. |
| `fuzz_canonical_json.py` | The bytes a catalog approval signature covers. |

## The properties

The parser target asserts each function fails closed: it returns, or raises the
`ValueError` its module documents (`EventLogError` is a `ValueError`). A
`struct.error`, `IndexError`, `MemoryError` or `OverflowError` reaching the
caller means a declared length was believed.

`fuzz_canonical_json.py` asserts a round trip: parsing the canonical output must
reproduce the input. That is stronger than checking for a crash, deliberately.
The three RFC 8785 bugs found in the sibling agent-manifest canonicalizer in
September 2026 were all silent; the sharpest normalized two distinct object keys
into one, so the output carried that key twice and a field disappeared from a
document whose signature claimed to cover it. Nothing raised. cmcp does not have
that bug, and this is what keeps it that way.

Equality is asserted up to JSON's number model, since JSON has one number type
and a large float legitimately re-parses as an int.

## Standing when added

Both parsers already fail closed: a local probe of 12,000 mutated inputs found
no undeclared exception escaping either. The canonicalizer is clean too: 17,918
generated documents round-tripped and 12,080 were refused as declared, with no
invariant violation. These are regression guards.

## Bundling gotcha

`compile_python_fuzzer` bundles each target with PyInstaller, which follows
static imports only. The cryptography and pydantic stacks reach `email.mime`
lazily, so without help the bundled target dies at runtime with
`ModuleNotFoundError: No module named 'email.mime'`, and libFuzzer reports that
as a crash in the target rather than a build problem. `build.sh` passes
`--collect-submodules=email`. A new dependency with a lazy import can need the
same treatment.

## Running locally

```
git clone https://github.com/google/clusterfuzzlite --depth 1 /tmp/clusterfuzzlite
python /tmp/clusterfuzzlite/infra/helper.py build_image --external $PWD
python /tmp/clusterfuzzlite/infra/helper.py build_fuzzers --external --sanitizer address $PWD
python /tmp/clusterfuzzlite/infra/helper.py run_fuzzer --external $PWD fuzz_canonical_json
```

## In CI

`cflite_pr.yml` fuzzes only code the pull request touched, for five minutes.
`cflite_batch.yml` runs every target for an hour, nightly. Both are read-only.
Budget 45 minutes for the PR job: the oss-fuzz base image build dominates.
