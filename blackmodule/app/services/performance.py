import logging
import time


logger = logging.getLogger("blackmodule.performance")
SLOW_OPERATION_SECONDS = 1.0


def performance_timer() -> float:
    return time.perf_counter()


def log_slow_operation(
    operation: str,
    started_at: float,
    *,
    result_count: int | None = None,
    candidate_count: int | None = None,
) -> float:
    """Log only operational metadata; never include client or identity data."""
    duration = time.perf_counter() - started_at
    if duration >= SLOW_OPERATION_SECONDS:
        logger.warning(
            "slow_operation operation=%s duration_seconds=%.3f result_count=%s candidate_count=%s",
            operation,
            duration,
            result_count if result_count is not None else "n/a",
            candidate_count if candidate_count is not None else "n/a",
        )
    return duration
