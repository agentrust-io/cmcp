"""Non-operational execution-state foundation; no gateway integration (#565)."""

from cmcp_runtime.execution.registry import (
    Admission,
    AdmissionStatus,
    Disposition,
    ExecutionRegistry,
    ExecutionStateError,
    valid_execution_id,
)

__all__ = [
    "Admission",
    "AdmissionStatus",
    "Disposition",
    "ExecutionRegistry",
    "ExecutionStateError",
    "valid_execution_id",
]
