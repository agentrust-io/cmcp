"""Keep the measurement failure emitted at startup discoverable by operators."""
from pathlib import Path

from cmcp_runtime.tee.measurement import MeasurementUnavailable


def test_measurement_failure_has_registry_row_and_recovery_guidance():
    root = Path(__file__).resolve().parents[2]
    code = MeasurementUnavailable.code
    registry = (root / 'docs/spec/error-codes.md').read_text(encoding='utf-8')
    rows = [row for row in registry.splitlines() if row.startswith(f'| `{code}` |')]
    assert len(rows) == 1
    assert '500' in rows[0] and 'FATAL' in rows[0]
    assert code in (root / 'docs/spec/failure-modes.md').read_text(encoding='utf-8')
