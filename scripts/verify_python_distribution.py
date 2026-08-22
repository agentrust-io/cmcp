"""Smoke-test an installed CMCP distribution outside the checkout."""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import version
from pathlib import Path

import cmcp_runtime
import cmcp_verify
from cmcp_runtime.catalog.approval import CATALOG_APPROVAL_SCHEMA_PATH
from cmcp_runtime.catalog.loader import CATALOG_ENTRY_SCHEMA_PATH
from cmcp_runtime.config import Config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--forbidden-source-root", required=True, type=Path)
    args = parser.parse_args()

    installed_version = version("cmcp-runtime")
    if installed_version != args.expected_version:
        raise SystemExit(
            f"installed version {installed_version!r} != expected {args.expected_version!r}"
        )
    if cmcp_runtime.__version__ != installed_version:
        raise SystemExit(
            f"runtime version {cmcp_runtime.__version__!r} != metadata {installed_version!r}"
        )

    forbidden_root = args.forbidden_source_root.resolve()
    for module in (cmcp_runtime, cmcp_verify):
        module_path = Path(module.__file__).resolve()
        if module_path.is_relative_to(forbidden_root):
            raise SystemExit(
                f"smoke test imported checkout source {module_path}, not the distribution"
            )

    for schema_path in (CATALOG_ENTRY_SCHEMA_PATH, CATALOG_APPROVAL_SCHEMA_PATH):
        resolved = schema_path.resolve()
        if not resolved.is_file():
            raise SystemExit(f"schema {resolved} is missing from the distribution")
        if resolved.is_relative_to(forbidden_root):
            raise SystemExit(f"schema resolved to checkout source {resolved}, not the distribution")

    config = Config()
    if config.max_response_size_bytes <= 0:
        raise SystemExit("installed Config produced an invalid response-size bound")

    sys.stdout.write(
        f"verified cmcp-runtime {installed_version} from "
        f"{Path(cmcp_runtime.__file__).resolve()}\n"
    )


if __name__ == "__main__":
    main()
