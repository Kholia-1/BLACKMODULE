import io
import json
import logging
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.services.observability_service import (
    configure_structured_logging,
    JsonLogFormatter,
    MonitoringRegistry,
    ObservabilityMiddleware,
    REQUEST_ID_HEADER,
    get_request_id,
    http_logger,
)


ROOT = Path(__file__).resolve().parents[1]


def _test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(ObservabilityMiddleware)

    @app.get("/ok")
    def ok(request: Request):
        return {"request_id": get_request_id(), "state_id": request.state.request_id}

    @app.get("/failure/{item_id}")
    def failure(item_id: str):
        raise RuntimeError(f"password=not-for-logs item={item_id}")

    return app


class PreproductionP5Tests(unittest.TestCase):
    def test_01_docker_log_rotation_is_configured_for_every_production_service(self):
        compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
        self.assertIn("x-default-logging: &default-logging", compose)
        self.assertIn("max-size: ${DOCKER_LOG_MAX_SIZE:-10m}", compose)
        self.assertIn("max-file: ${DOCKER_LOG_MAX_FILES:-5}", compose)
        self.assertEqual(4, compose.count("logging: *default-logging"))

    def test_02_request_id_is_propagated_and_available_in_request_context(self):
        client = TestClient(_test_app())
        response = client.get("/ok", headers={REQUEST_ID_HEADER: "pilot-request-42"})
        self.assertEqual(200, response.status_code)
        self.assertEqual("pilot-request-42", response.headers[REQUEST_ID_HEADER])
        self.assertEqual("pilot-request-42", response.json()["request_id"])
        self.assertEqual("pilot-request-42", response.json()["state_id"])

    def test_03_invalid_incoming_request_id_is_replaced(self):
        client = TestClient(_test_app())
        response = client.get("/ok", headers={REQUEST_ID_HEADER: "invalid value with spaces"})
        generated = response.headers[REQUEST_ID_HEADER]
        self.assertNotEqual("invalid value with spaces", generated)
        self.assertEqual(generated, response.json()["request_id"])

    def test_04_unhandled_5xx_is_generic_correlated_and_safely_logged(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonLogFormatter())
        http_logger.addHandler(handler)
        try:
            response = TestClient(
                _test_app(), raise_server_exceptions=False
            ).get("/failure/customer-reference", headers={REQUEST_ID_HEADER: "error-42"})
        finally:
            http_logger.removeHandler(handler)
        self.assertEqual(500, response.status_code)
        self.assertEqual("error-42", response.headers[REQUEST_ID_HEADER])
        self.assertEqual("error-42", response.json()["request_id"])
        rendered = stream.getvalue()
        self.assertIn('"event":"http_request_failed"', rendered)
        self.assertIn('"route":"/failure/{item_id}"', rendered)
        self.assertNotIn("not-for-logs", rendered)
        self.assertNotIn("customer-reference", rendered)

    def test_05_json_formatter_redacts_credential_shaped_values(self):
        record = logging.LogRecord(
            "blackmodule.test", logging.ERROR, __file__, 1,
            "failure password=test-value api_key=another-value", (), None,
        )
        rendered = JsonLogFormatter().format(record)
        self.assertNotIn("test-value", rendered)
        self.assertNotIn("another-value", rendered)
        self.assertEqual("ERROR", json.loads(rendered)["level"])

    def test_06_metrics_cover_availability_latency_health_scheduler_and_alerts(self):
        registry = MonitoringRegistry(
            error_threshold=2, error_window_seconds=60, latency_warning_ms=50
        )
        registry.record_request(200, 10)
        registry.record_request(500, 60)
        registry.record_request(503, 20)
        registry.record_component("database", False)
        registry.record_scheduler_job("health_supervision", False, 12.5)
        snapshot = registry.snapshot()
        self.assertEqual(3, snapshot["requests"]["total"])
        self.assertEqual(2, snapshot["requests"]["http_5xx_total"])
        self.assertEqual(1, snapshot["latency_ms"]["slow_requests_total"])
        self.assertEqual("DOWN", snapshot["components"]["database"]["status"])
        self.assertEqual(
            "FAILURE", snapshot["scheduler_jobs"]["health_supervision"]["last_status"]
        )
        self.assertEqual(
            {"COMPONENT_UNAVAILABLE", "REPEATED_HTTP_5XX"},
            {alert["code"] for alert in snapshot["alerts"]},
        )

    def test_07_health_ready_reports_database_without_raw_error(self):
        from app import main

        class ReadyDb:
            def execute(self, _statement):
                return self

            def scalar(self):
                return 1

        class BrokenDb:
            def execute(self, _statement):
                raise RuntimeError("secret=database-detail")

        with patch.object(main, "get_scheduler_status", return_value={"running": True, "jobs": []}):
            self.assertEqual("ready", main.health_ready(ReadyDb())["database"])
            with self.assertRaises(HTTPException) as error:
                main.health_ready(BrokenDb())
        self.assertEqual(503, error.exception.status_code)
        self.assertNotIn("database-detail", str(error.exception.detail))

    def test_08_metrics_access_is_restricted_in_production(self):
        from app import main

        with patch.object(main, "IS_PRODUCTION", True), patch.object(
            main, "BLACKMODULE_API_KEY", "configured-monitoring-key"
        ), patch.object(
            main, "get_scheduler_status", return_value={"running": True, "jobs": []}
        ):
            with self.assertRaises(HTTPException) as denied:
                main.health_metrics("wrong-key")
            allowed = main.health_metrics("configured-monitoring-key")
        self.assertEqual(403, denied.exception.status_code)
        self.assertTrue(allowed["scheduler"]["running"])

    def test_09_scheduler_supervision_is_periodic_and_errors_are_not_printed_raw(self):
        scheduler_source = (
            ROOT / "blackmodule" / "app" / "scheduler.py"
        ).read_text(encoding="utf-8")
        self.assertIn('id="health_supervision"', scheduler_source)
        self.assertIn("MONITORING_HEALTHCHECK_INTERVAL_SECONDS", scheduler_source)
        self.assertNotIn("print(", scheduler_source)
        self.assertNotIn("{error}", scheduler_source)

    def test_10_production_healthcheck_supervises_readiness(self):
        compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:10000/health/ready", compose)

    def test_11_duplicate_uvicorn_access_log_is_disabled(self):
        access_logger = logging.getLogger("uvicorn.access")
        previous = access_logger.disabled
        try:
            configure_structured_logging()
            self.assertTrue(access_logger.disabled)
        finally:
            access_logger.disabled = previous


if __name__ == "__main__":
    unittest.main()
