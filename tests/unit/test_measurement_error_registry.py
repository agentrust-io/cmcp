"""Keep startup measurement diagnostics and operator recovery discoverable."""

from pathlib import Path

from cmcp_runtime.tee.measurement import MeasurementUnavailable

ROOT = Path(__file__).resolve().parents[2]


def _row(text, first_column):
    rows = [line for line in text.splitlines() if line.startswith(f"| {first_column} |")]
    assert len(rows) == 1
    columns = [column.strip() for column in rows[0].split("|")[1:-1]]
    assert len(columns) == 5
    return columns


def test_measurement_failure_registry_columns_match_runtime_and_modes():
    registry = (ROOT / "docs/spec/error-codes.md").read_text(encoding="utf-8")
    columns = _row(registry, f"`{MeasurementUnavailable.code}`")
    assert columns[1] == f"{MeasurementUnavailable.http_status} / startup"
    assert columns[2] == "FATAL (production); WARN (dev mode)"
    for phrase in (
        "TPM/NV",
        "production startup aborts",
        "`CMCP_DEV_MODE`",
        "without established gateway measurement",
        "do not infer TPM replacement",
        "rotate a signing key solely from this code",
    ):
        assert phrase in columns[3]
    assert columns[4] == "[failure-modes.md](failure-modes.md#measurement-unavailable-at-startup)"


def test_measurement_failure_decision_table_covers_both_modes():
    failure_modes = (ROOT / "docs/spec/failure-modes.md").read_text(encoding="utf-8")
    assert "## Decision Table" in failure_modes
    table = failure_modes.split("## Decision Table", 1)[1].split("\n## ", 1)[0]
    columns = _row(table, "Gateway measurement or TPM/NV operation unavailable at startup")
    assert "runtime does not start" in columns[1]
    assert (
        "`CMCP_DEV_MODE`: warn and continue without established gateway measurement" in columns[1]
    )
    assert columns[2] == "Dev mode only (see Measurement unavailable at startup)"
    assert "not evidence of a successfully measured gateway" in columns[3]
    assert "`FATAL MEASUREMENT_UNAVAILABLE`" in columns[4]
    assert "dev mode: `WARN`" in columns[4]


def test_measurement_failure_recovery_guidance_is_retained():
    failure_modes = (ROOT / "docs/spec/failure-modes.md").read_text(encoding="utf-8")
    assert "## Measurement unavailable at startup" in failure_modes
    section = failure_modes.split("## Measurement unavailable at startup", 1)[1].split("\n## ", 1)[
        0
    ]
    prose = " ".join(section.split())
    for phrase in (
        "TPM open errors",
        "NV index define/read/validation errors",
        "`TPM2_NV_Extend` failure",
        "chain-value mismatch",
        "truncated NV values",
        "certify failures",
        "**Production**: startup aborts",
        "**Development**: with `CMCP_DEV_MODE`, the runtime logs a warning and continues.",
        "not evidence of a successfully measured gateway",
        "restore readable, supported measurement inputs",
        "investigate device access, library support, NV index configuration",
        "This code alone is not evidence that the TPM changed.",
        "Do not bypass measurement or rotate a signing key merely to suppress this error.",
        "Sealed-key recovery remains a separate decision (FM-1b).",
    ):
        assert phrase in prose
