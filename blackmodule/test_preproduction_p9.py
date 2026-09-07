import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


ROOT = Path(__file__).resolve().parents[1]
BLACKMODULE_ROOT = ROOT / "blackmodule"


class PreproductionP9ATests(unittest.TestCase):
    def _production_environment(self, **overrides):
        environment = os.environ.copy()
        environment.update(
            {
                "BLACKMODULE_ENV": "production",
                "DATABASE_URL": (
                    "postgresql://pilot_user:strong-pilot-db-passphrase@db:5432/blackmodule"
                ),
                "SECRET_KEY": "pilot-session-secret-with-at-least-32-characters",
                "BLACKMODULE_API_KEY": "pilot-api-key-with-at-least-32-characters",
                "INITIAL_ADMIN_PASSWORD": "",
                "PUBLIC_HOSTNAME": "blackmodule-pilot.example.bank",
                "FORWARDED_ALLOW_IPS": "172.18.0.1/32",
                "SESSION_HTTPS_ONLY": "true",
            }
        )
        environment.update(overrides)
        return environment

    def _import_config(self, **overrides):
        return subprocess.run(
            [sys.executable, "-c", "import app.config"],
            cwd=BLACKMODULE_ROOT,
            env=self._production_environment(**overrides),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_01_complete_production_proxy_configuration_is_accepted(self):
        result = self._import_config()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_02_public_hostname_is_required_and_validated(self):
        missing = self._import_config(PUBLIC_HOSTNAME="")
        self.assertNotEqual(0, missing.returncode)
        self.assertIn("PUBLIC_HOSTNAME doit", missing.stderr)

        unsafe = self._import_config(PUBLIC_HOSTNAME="https://pilot.example.bank")
        self.assertNotEqual(0, unsafe.returncode)
        self.assertIn("nom DNS explicite", unsafe.stderr)

    def test_03_secure_session_cookie_is_mandatory_in_production(self):
        result = self._import_config(SESSION_HTTPS_ONLY="false")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SESSION_HTTPS_ONLY=true", result.stderr)

    def test_04_forwarded_allow_ips_refuses_wildcards_and_open_networks(self):
        wildcard = self._import_config(FORWARDED_ALLOW_IPS="*")
        self.assertNotEqual(0, wildcard.returncode)
        self.assertIn("IP/CIDR explicites", wildcard.stderr)

        open_network = self._import_config(FORWARDED_ALLOW_IPS="0.0.0.0/0")
        self.assertNotEqual(0, open_network.returncode)
        self.assertIn("tout Internet", open_network.stderr)

    def test_05_trusted_host_headers_and_secure_cookie_are_effective(self):
        command = """
import json
import logging
from fastapi.testclient import TestClient
from app.main import app
logging.disable(logging.CRITICAL)
client = TestClient(app, base_url='https://blackmodule-pilot.example.bank')
allowed = client.get('/web/login', headers={'Host': 'blackmodule-pilot.example.bank'})
denied = client.get('/health/live', headers={'Host': 'attacker.invalid'})
print(json.dumps({
    'allowed': allowed.status_code,
    'denied': denied.status_code,
    'cookie': allowed.headers.get('set-cookie', ''),
    'headers': dict(allowed.headers),
}))
"""
        result = subprocess.run(
            [sys.executable, "-c", command],
            cwd=BLACKMODULE_ROOT,
            env=self._production_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout.strip())
        self.assertEqual(200, payload["allowed"])
        self.assertEqual(400, payload["denied"])
        self.assertIn("secure", payload["cookie"].lower())
        headers = payload["headers"]
        self.assertEqual("nosniff", headers["x-content-type-options"])
        self.assertEqual("DENY", headers["x-frame-options"])
        self.assertEqual("no-referrer", headers["referrer-policy"])
        self.assertIn("camera=()", headers["permissions-policy"])
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.assertIn("script-src 'self' 'unsafe-inline'", headers["content-security-policy"])
        self.assertNotIn("'unsafe-eval'", headers["content-security-policy"])

    def test_06_untrusted_peer_cannot_spoof_forwarded_client_or_scheme(self):
        inner_app = FastAPI()

        @inner_app.get("/")
        def identity(request: Request):
            return {
                "client": request.client.host,
                "scheme": request.url.scheme,
            }

        proxied_app = ProxyHeadersMiddleware(
            inner_app,
            trusted_hosts=["10.20.30.40"],
        )
        client = TestClient(
            proxied_app,
            client=("203.0.113.25", 4567),
        )
        response = client.get(
            "/",
            headers={
                "X-Forwarded-For": "198.51.100.99",
                "X-Forwarded-Proto": "https",
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("203.0.113.25", response.json()["client"])
        self.assertEqual("http", response.json()["scheme"])

    def test_07_production_compose_configures_proxy_headers_and_internal_health(self):
        compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
        self.assertIn("PUBLIC_HOSTNAME: ${PUBLIC_HOSTNAME:?", compose)
        self.assertIn("FORWARDED_ALLOW_IPS: ${FORWARDED_ALLOW_IPS:?", compose)
        self.assertIn("--proxy-headers", compose)
        self.assertIn("--forwarded-allow-ips", compose)
        self.assertNotIn("--forwarded-allow-ips\n      - \"*\"", compose)
        self.assertIn('Host: $${PUBLIC_HOSTNAME}', compose)

    def test_08_proxy_filtering_documentation_covers_technical_endpoints(self):
        documentation = (
            ROOT / "docs" / "preproduction-reverse-proxy.md"
        ).read_text(encoding="utf-8")
        for endpoint in ("/health/live", "/health/ready", "/health/metrics"):
            self.assertIn(endpoint, documentation)
        self.assertIn("ne doit pas exposer publiquement", documentation)


if __name__ == "__main__":
    unittest.main()
