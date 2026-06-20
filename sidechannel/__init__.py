"""VORLATH Shield side-channel measurement harness.

A *measurement* tool, not a fix. It quantifies the timing dependency that
``SECURITY.md`` already discloses (the pure-Python PQ legs are not constant-time)
using the classic dudect / Welch's two-sample t-test methodology.

See ``tech/CONSTANT_TIME.md`` for methodology, measured results, and scope.
"""
from .ct_measure import (
    TARGETS,
    LeakageResult,
    measure_operation,
    run_all,
    welch_t,
)

__all__ = [
    "TARGETS",
    "LeakageResult",
    "measure_operation",
    "run_all",
    "welch_t",
]
