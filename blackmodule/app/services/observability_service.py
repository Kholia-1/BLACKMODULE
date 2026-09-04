import json
import logging
import re
import sys
import time
import uuid
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timezone
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import (
    LOG_LEVEL,
    MONITORING_ERROR_THRESHOLD,
    MONITORING_ERROR_WINDOW_SECONDS,
    MONITORING_LATENCY_WARNING_MS,
)


REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_request_id: ContextVar[str | None] = ContextVar("blackmodule_request_id", default=None)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def get_request_id() -> str | None:
    return _request_id.get()


def _redact(value: str) -> str:
    """Last-resort protection for accidental credential-shaped log content."""
    sanitized = value
    patterns = (
        r"(?i)(password|password_hash|secret|token|api[_ -]?key)\s*[=:]\s*[^\s,;]+",
        r"(?i)(authorization)\s*[=:]\s*[^\s,;]+",
    )
    for pattern in patterns:
        sanitized = re.sub(pattern, lambda match: f"{match.group(1)}=[REDACTED]", sanitized)
    return sanitized


class JsonLogFormatter(logging.Formatter):
    """Emit a stable JSON envelope containing only approved technical fields."""

    EXTRA_FIELDS = (
        "event",
        "request_id",
        "method",
        "route",
        "status_code",
        "duration_ms",
        "error_type",
        "component",
        "job_id",
        "result_count",
        "candidate_count",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact(record.getMessage()),
        }
        for field in self.EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["error_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_structured_logging() -> None:
    """Configure BLACKMODULE loggers without replacing server/framework handlers."""
    formatter = JsonLogFormatter()
    logger = logging.getLogger("blackmodule")
    if not any(getattr(handler, "_blackmodule_json", False) for handler in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        handler._blackmodule_json = True
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    logger.propagate = False

    # The middleware emits the safe request log, so Uvicorn's duplicate access
    # line (which contains the concrete URL) is disabled. Lifecycle/error logs
    # keep their original destinations but use the same JSON envelope.
    logging.getLogger("uvicorn.access").disabled = True
    for logger_name in ("uvicorn", "uvicorn.error"):
        server_logger = logging.getLogger(logger_name)
        for handler in server_logger.handlers:
            handler.setFormatter(formatter)


class MonitoringRegistry:
    """Small process-local metrics registry ready for a future external collector."""

    def __init__(
        self,
        *,
        error_threshold: int = MONITORING_ERROR_THRESHOLD,
        error_window_seconds: int = MONITORING_ERROR_WINDOW_SECONDS,
        latency_warning_ms: float = MONITORING_LATENCY_WARNING_MS,
    ):
        self.started_at = time.time()
        self.error_threshold = error_threshold
        self.error_window_seconds = error_window_seconds
        self.latency_warning_ms = latency_warning_ms
        self._lock = Lock()
        self._request_total = 0
        self._http_5xx_total = 0
        self._latency_total_ms = 0.0
        self._latency_max_ms = 0.0
        self._slow_request_total = 0
        self._recent_5xx = deque()
        self._components = {}
        self._scheduler_jobs = {}

    def record_request(self, status_code: int, duration_ms: float) -> None:
        now = time.monotonic()
        with self._lock:
            self._request_total += 1
            self._latency_total_ms += duration_ms
            self._latency_max_ms = max(self._latency_max_ms, duration_ms)
            if duration_ms >= self.latency_warning_ms:
                self._slow_request_total += 1
            if status_code >= 500:
                self._http_5xx_total += 1
                self._recent_5xx.append(now)
            self._prune_errors(now)

    def record_component(self, component: str, ready: bool) -> None:
        now = utc_now_iso()
        with self._lock:
            previous = self._components.get(component, {})
            failures = 0 if ready else int(previous.get("consecutive_failures", 0)) + 1
            self._components[component] = {
                "status": "UP" if ready else "DOWN",
                "last_checked_at": now,
                "consecutive_failures": failures,
            }

    def record_scheduler_job(self, job_id: str, success: bool, duration_ms: float) -> None:
        with self._lock:
            previous = self._scheduler_jobs.get(job_id, {})
            self._scheduler_jobs[job_id] = {
                "last_status": "SUCCESS" if success else "FAILURE",
                "last_finished_at": utc_now_iso(),
                "last_duration_ms": round(duration_ms, 3),
                "success_total": int(previous.get("success_total", 0)) + int(success),
                "failure_total": int(previous.get("failure_total", 0)) + int(not success),
            }

    def snapshot(self) -> dict:
        now_monotonic = time.monotonic()
        with self._lock:
            self._prune_errors(now_monotonic)
            total = self._request_total
            error_rate = (self._http_5xx_total / total * 100) if total else 0.0
            availability = ((total - self._http_5xx_total) / total * 100) if total else 100.0
            alerts = []
            down_components = [
                name for name, state in self._components.items()
                if state["status"] == "DOWN"
            ]
            for component in down_components:
                alerts.append({"code": "COMPONENT_UNAVAILABLE", "component": component})
            if len(self._recent_5xx) >= self.error_threshold:
                alerts.append({
                    "code": "REPEATED_HTTP_5XX",
                    "count": len(self._recent_5xx),
                    "window_seconds": self.error_window_seconds,
                })
            return {
                "generated_at": utc_now_iso(),
                "uptime_seconds": round(max(0.0, time.time() - self.started_at), 3),
                "availability_percent": round(availability, 3),
                "requests": {
                    "total": total,
                    "http_5xx_total": self._http_5xx_total,
                    "recent_http_5xx": len(self._recent_5xx),
                    "error_rate_percent": round(error_rate, 3),
                },
                "latency_ms": {
                    "average": round(self._latency_total_ms / total, 3) if total else 0.0,
                    "maximum": round(self._latency_max_ms, 3),
                    "slow_requests_total": self._slow_request_total,
                    "warning_threshold": self.latency_warning_ms,
                },
                "components": {name: dict(value) for name, value in self._components.items()},
                "scheduler_jobs": {
                    name: dict(value) for name, value in self._scheduler_jobs.items()
                },
                "alerts": alerts,
            }

    def _prune_errors(self, now: float) -> None:
        threshold = now - self.error_window_seconds
        while self._recent_5xx and self._recent_5xx[0] <= threshold:
            self._recent_5xx.popleft()


monitoring_registry = MonitoringRegistry()
http_logger = logging.getLogger("blackmodule.http")
health_logger = logging.getLogger("blackmodule.health")


def _incoming_request_id(request: Request) -> str:
    candidate = request.headers.get(REQUEST_ID_HEADER, "")
    if _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    return template if isinstance(template, str) else "/unmatched"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Correlate requests, collect metrics and safely report HTTP failures."""

    async def dispatch(self, request: Request, call_next):
        request_id = _incoming_request_id(request)
        token = _request_id.set(request_id)
        request.state.request_id = request_id
        started_at = time.perf_counter()
        try:
            try:
                response = await call_next(request)
                status_code = response.status_code
            except Exception as error:
                duration_ms = (time.perf_counter() - started_at) * 1000
                monitoring_registry.record_request(500, duration_ms)
                http_logger.error(
                    "Unhandled application error.",
                    extra={
                        "event": "http_request_failed",
                        "request_id": request_id,
                        "method": request.method,
                        "route": _route_template(request),
                        "status_code": 500,
                        "duration_ms": round(duration_ms, 3),
                        "error_type": type(error).__name__,
                    },
                )
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error", "request_id": request_id},
                    headers={REQUEST_ID_HEADER: request_id},
                )

            duration_ms = (time.perf_counter() - started_at) * 1000
            monitoring_registry.record_request(status_code, duration_ms)
            response.headers[REQUEST_ID_HEADER] = request_id
            level = logging.ERROR if status_code >= 500 else (
                logging.WARNING if duration_ms >= MONITORING_LATENCY_WARNING_MS else logging.INFO
            )
            http_logger.log(
                level,
                "HTTP request completed.",
                extra={
                    "event": "http_request_completed",
                    "request_id": request_id,
                    "method": request.method,
                    "route": _route_template(request),
                    "status_code": status_code,
                    "duration_ms": round(duration_ms, 3),
                },
            )
            return response
        finally:
            _request_id.reset(token)


def record_health(component: str, ready: bool) -> None:
    previous = monitoring_registry.snapshot().get("components", {}).get(component)
    monitoring_registry.record_component(component, ready)
    previous_status = previous.get("status") if previous else None
    new_status = "UP" if ready else "DOWN"
    if new_status != previous_status:
        health_logger.log(
            logging.INFO if ready else logging.ERROR,
            "Health component status changed.",
            extra={
                "event": "health_status_changed",
                "component": component,
                "status_code": 200 if ready else 503,
            },
        )
