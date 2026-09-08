#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# Installed rather than put on the path so the targets exercise the same import
# surface a consumer gets.

cd "$SRC/cmcp"
pip3 install --no-cache-dir .

# compile_python_fuzzer bundles each target with PyInstaller, which follows
# static imports only. The cryptography and pydantic stacks reach email.mime
# lazily, so without this the bundled target dies at runtime with
# "ModuleNotFoundError: No module named 'email.mime'" and libFuzzer reports it
# as a crash in the target.
PYI_ARGS=(--collect-submodules=email)

for target in "$SRC"/cmcp/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target" "${PYI_ARGS[@]}"
done
