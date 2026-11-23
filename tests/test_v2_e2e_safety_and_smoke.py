"""
Unit and safety regression tests for Phase 4E disposable-target guards,
local server port ownership, readiness validation, and fail-closed cleanup.

Runs in the default non-integration test suite (`pytest -m "not integration"`)
without requiring Neo4j or Playwright Chromium.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import types
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from tests.test_v2_end_to_end_integration import (
    validate_disposable_neo4j_uri as integration_validate_uri,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SMOKE_PATH = _REPO_ROOT / "scripts" / "v2_browser_smoke.py"


def _load_smoke_module():
    spec = importlib.util.spec_from_file_location("v2_browser_smoke_under_test", _SMOKE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_smoke = _load_smoke_module()


@pytest.mark.parametrize(
    "uri",
    [
        "bolt://localhost:7687",
        "bolt://localhost:17687",
        "bolt://127.0.0.1:7687",
        "neo4j://[::1]:7687",
        "bolt+ssc://localhost:7687",
        "neo4j+s://127.0.0.1:17687",
    ],
)
def test_disposable_neo4j_uri_accepts_loopback_bolt_endpoints(uri: str):
    assert _smoke.validate_disposable_neo4j_uri(uri) == uri
    assert integration_validate_uri(uri) == uri


@pytest.mark.parametrize(
    "bad_uri",
    [
        "",
        "   ",
        "bolt://production-host:7687",
        "bolt://neo4j-test.internal.corp:7687",  # "test" in hostname must NOT bypass guard
        "bolt://demo-neo4j.example.com:7687",
        "neo4j+s://abcd1234.databases.neo4j.io",
        "bolt://0.0.0.0:7687",
        "bolt://192.168.1.50:7687",
        "http://localhost:7474",
        "https://localhost:7473",
        "bolt://neo4j:password@localhost:7687",
        "bolt://localhost:99999",
    ],
)
def test_disposable_neo4j_uri_rejects_non_loopback_or_unsafe_targets(bad_uri: str):
    with pytest.raises(RuntimeError):
        _smoke.validate_disposable_neo4j_uri(bad_uri)
    with pytest.raises(ValueError):
        integration_validate_uri(bad_uri)


def test_require_disposable_env_fails_closed_on_missing_or_remote_target(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("RUN_NEO4J_INTEGRATION", raising=False)
    with pytest.raises(RuntimeError, match="RUN_NEO4J_INTEGRATION=1"):
        _smoke._require_disposable_neo4j_env()

    monkeypatch.setenv("RUN_NEO4J_INTEGRATION", "1")
    monkeypatch.setenv("NEO4J_TEST_URI", "bolt://prod-neo4j.corp:7687")
    monkeypatch.setenv("NEO4J_TEST_USERNAME", "neo4j")
    monkeypatch.setenv("NEO4J_TEST_PASSWORD", "secret")
    with pytest.raises(RuntimeError, match="non-loopback Neo4j host"):
        _smoke._require_disposable_neo4j_env()

    monkeypatch.setenv("NEO4J_TEST_URI", "bolt://localhost:17687")
    cfg = _smoke._require_disposable_neo4j_env()
    assert cfg["uri"] == "bolt://localhost:17687"


def test_assert_database_is_empty_blocks_non_empty_database():
    def _mock_driver(node_count: int):
        session = MagicMock()
        session.run.return_value.single.return_value = {"total_nodes": node_count}
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        driver.session.return_value.__exit__.return_value = None
        return driver

    _smoke._assert_database_is_empty(_mock_driver(0))

    with pytest.raises(RuntimeError, match="non-empty Neo4j database"):
        _smoke._assert_database_is_empty(_mock_driver(5))


def test_run_browser_smoke_skips_cleanup_when_preflight_emptiness_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify finally block NEVER runs cleanup if pre-flight database emptiness fails."""
    monkeypatch.setenv("RUN_NEO4J_INTEGRATION", "1")
    monkeypatch.setenv("NEO4J_TEST_URI", "bolt://localhost:17687")
    monkeypatch.setenv("NEO4J_TEST_USERNAME", "neo4j")
    monkeypatch.setenv("NEO4J_TEST_PASSWORD", "phase6-test-password")

    # Provide minimal stub for playwright.sync_api so test runs even without playwright installed
    fake_pw_mod = types.ModuleType("playwright")
    fake_sync_mod = types.ModuleType("playwright.sync_api")
    fake_sync_mod.sync_playwright = MagicMock()
    monkeypatch.setitem(sys.modules, "playwright", fake_pw_mod)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync_mod)

    session = MagicMock()
    session.run.return_value.single.return_value = {"total_nodes": 12}
    fake_driver = MagicMock()
    fake_driver.session.return_value.__enter__.return_value = session
    fake_driver.session.return_value.__exit__.return_value = None
    monkeypatch.setattr(_smoke.GraphDatabase, "driver", MagicMock(return_value=fake_driver))

    cleanup_called: List[bool] = []
    monkeypatch.setattr(
        _smoke,
        "_cleanup_owned_entities",
        lambda *args, **kwargs: cleanup_called.append(True),
    )

    with pytest.raises(RuntimeError, match="non-empty Neo4j database"):
        _smoke.run_browser_smoke()

    assert cleanup_called == []
    fake_driver.close.assert_called_once()


def test_assert_port_available_detects_occupied_loopback_port():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    occupied_port = listener.getsockname()[1]
    try:
        with pytest.raises(RuntimeError, match="already"):
            _smoke._assert_port_available("127.0.0.1", occupied_port)
    finally:
        listener.close()

    # Probe an unused ephemeral port by binding/closing to obtain an available port number
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()
    _smoke._assert_port_available("127.0.0.1", free_port)


def test_wait_for_http_rejects_early_exited_child_even_when_foreign_server_returns_200(
    tmp_path: Path,
):
    """Prove _wait_for_http cannot be fooled by an unrelated server when owned child exits."""

    class _ReadyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"status": "ready", "database": "connected"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _ReadyHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    log_path = tmp_path / "child.log"
    log_path.write_text("Address already in use\n", encoding="utf-8")
    exited_proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(1)"])
    exited_proc.wait(timeout=10)

    try:
        with pytest.raises(RuntimeError, match="exited early with code 1"):
            _smoke._wait_for_http(
                f"http://127.0.0.1:{port}/ready",
                proc=exited_proc,
                timeout_sec=5.0,
                body_validator=_smoke._is_fastapi_ready_payload,
                log_path=log_path,
            )
    finally:
        server.shutdown()
        server.server_close()


def test_wait_for_http_rejects_wrong_200_payload_from_unrelated_service():
    class _WrongHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body>Other App</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _WrongHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with pytest.raises(RuntimeError, match="failed readiness validator"):
            _smoke._wait_for_http(
                f"http://127.0.0.1:{port}/ready",
                timeout_sec=0.6,
                body_validator=_smoke._is_fastapi_ready_payload,
            )
    finally:
        server.shutdown()
        server.server_close()


def test_http_readiness_payload_validators():
    assert _smoke._is_fastapi_ready_payload(b'{"status":"ready","database":"connected"}') is True
    assert _smoke._is_fastapi_ready_payload(b'{"status":"ok"}') is False
    assert _smoke._is_fastapi_ready_payload(b"not-json") is False

    assert (
        _smoke._is_fastapi_health_payload(
            b'{"status":"ok","app":"Network Traffic Analysis"}'
        )
        is True
    )
    assert _smoke._is_fastapi_health_payload(b'{"status":"ok","app":"Other"}') is False

    assert (
        _smoke._is_vite_root_html(
            b'<html><head><title>Network Traffic & Security Alert Graph</title></head>'
            b'<body><div id="root"></div></body></html>'
        )
        is True
    )
    assert _smoke._is_vite_root_html(b"<html><body>Other</body></html>") is False
