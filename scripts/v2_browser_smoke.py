"""
Real End-to-End Browser Smoke Validation Script (Phase 4E).

Seeds deterministic synthetic demo fixtures into a disposable Neo4j container via the
real V2 CLI entrypoints, boots FastAPI (`uvicorn`) + React (`vite`), drives headless
Chromium via Playwright across the Correlations workflow (Legacy V1 + V2 Alert-Flow
Correlations + Evidence Inspector + RoutingDomain filter + unverified_incomplete
lifecycle), verifies zero browser-triggered Neo4j mutations, and cleans up ONLY
synthetic `demo-v2-*` entities.

Prerequisites:
  - RUN_NEO4J_INTEGRATION=1
  - NEO4J_TEST_URI, NEO4J_TEST_USERNAME, NEO4J_TEST_PASSWORD
  - Playwright Chromium browser installed (`playwright` package + `playwright install chromium`)
  - Frontend dependencies installed under `frontend/`
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List
from urllib.error import URLError
from urllib.request import urlopen

from neo4j import GraphDatabase

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.graph.schema import ensure_schema
from src.ingestion.suricata_eve_parser import parse_suricata_eve_alert_file

_DEMO_DIR = _REPO_ROOT / "tests" / "fixtures" / "demo_v2"
_CORP_DOMAIN = "demo-v2-corp"
_BRANCH_DOMAIN = "demo-v2-branch"
_DEMO_DOMAINS = [_CORP_DOMAIN, _BRANCH_DOMAIN]
_DEMO_RULESET_NS = "demo-v2-rules"


def _require_disposable_neo4j_env() -> Dict[str, str]:
    if os.environ.get("RUN_NEO4J_INTEGRATION") != "1":
        raise RuntimeError(
            "Refusing to run: set RUN_NEO4J_INTEGRATION=1 to confirm disposable Neo4j target."
        )
    uri = os.environ.get("NEO4J_TEST_URI")
    username = os.environ.get("NEO4J_TEST_USERNAME")
    password = os.environ.get("NEO4J_TEST_PASSWORD")
    if not uri or not username or not password:
        raise RuntimeError(
            "NEO4J_TEST_URI, NEO4J_TEST_USERNAME, and NEO4J_TEST_PASSWORD must all be set."
        )
    return {"uri": uri, "username": username, "password": password}


def _cleanup_demo_domains(driver) -> None:
    with driver.session() as session:
        session.run(
            "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms DETACH DELETE ae",
            doms=_DEMO_DOMAINS,
        ).consume()
        session.run(
            "MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms DETACH DELETE fo",
            doms=_DEMO_DOMAINS,
        ).consume()
        session.run(
            "MATCH (ip:IPAddress) "
            "WHERE (ip.routing_domain_id IN $doms "
            "       OR ANY(d IN $doms WHERE ip.scoped_id STARTS WITH (d + '#'))) "
            "  AND NOT ((ip)--(:AlertFact)) "
            "  AND NOT ((:FlowObservation)-->(ip)) "
            "  AND NOT ((:AlertEvent)-->(ip)) "
            "DETACH DELETE ip",
            doms=_DEMO_DOMAINS,
        ).consume()
        session.run(
            "MATCH (ad:AlertDefinition) WHERE ad.ruleset_namespace = $ns "
            "AND NOT (()-[:TRIGGERED_RULE]->(ad)) DETACH DELETE ad",
            ns=_DEMO_RULESET_NS,
        ).consume()
        session.run(
            "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
            "AND NOT ((:IPAddress)-[:IN_DOMAIN]->(rd)) DETACH DELETE rd",
            doms=_DEMO_DOMAINS,
        ).consume()


def _snapshot_demo_graph(driver) -> Dict[str, Any]:
    with driver.session() as session:
        rec = session.run(
            "OPTIONAL MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
            "WITH count(fo) AS flows "
            "OPTIONAL MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
            "WITH flows, count(ae) AS alerts "
            "OPTIONAL MATCH (ae2:AlertEvent)-[r:CORRELATED_WITH]->(fo2:FlowObservation) "
            "WHERE ae2.routing_domain_id IN $doms "
            "RETURN flows, alerts, count(r) AS rels",
            doms=_DEMO_DOMAINS,
        ).single()
        edges = [
            (r["eid"], r["oid"], dict(r["props"]))
            for r in session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS eid, fo.observation_id AS oid, properties(r) AS props "
                "ORDER BY ae.event_id ASC, fo.observation_id ASC",
                doms=_DEMO_DOMAINS,
            )
        ]
        return {"counts": (rec["flows"], rec["alerts"], rec["rels"]), "edges": edges}


def _run_cli(args: List[str], env: Dict[str, str]) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", *args],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"CLI command failed ({' '.join(args)}): "
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )


def _wait_for_http(url: str, timeout_sec: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_sec
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2.0) as resp:
                if resp.status == 200:
                    return
        except (URLError, OSError) as exc:
            last_err = exc
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}: {last_err}")


def _terminate_proc(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_browser_smoke() -> None:
    from playwright.sync_api import sync_playwright

    cfg = _require_disposable_neo4j_env()
    sub_env = {
        **os.environ,
        "NEO4J_URI": cfg["uri"],
        "NEO4J_USERNAME": cfg["username"],
        "NEO4J_PASSWORD": cfg["password"],
        "DATA_IMPORT_ENABLED": "false",
    }

    driver = GraphDatabase.driver(cfg["uri"], auth=(cfg["username"], cfg["password"]))
    api_proc: subprocess.Popen | None = None
    vite_proc: subprocess.Popen | None = None

    try:
        driver.verify_connectivity()
        ensure_schema(driver)
        _cleanup_demo_domains(driver)

        # 1. Seed synthetic demo dataset via REAL CLIs (Zeek + Suricata + Phase 4B)
        _run_cli(
            [
                "src.services.zeek_ingestion",
                "--file",
                str(_DEMO_DIR / "corp_conn.log.jsonl"),
                "--sensor-id",
                "zeek-demo-01",
                "--routing-domain-id",
                _CORP_DOMAIN,
                "--source-provenance",
                "phase4e-corp-zeek",
            ],
            sub_env,
        )
        _run_cli(
            [
                "src.services.suricata_ingestion",
                "--file",
                str(_DEMO_DIR / "corp_eve.jsonl"),
                "--sensor-id",
                "suricata-demo-01",
                "--ruleset-namespace",
                _DEMO_RULESET_NS,
                "--log-source-id",
                "corp-eve-demo-01",
                "--routing-domain-id",
                _CORP_DOMAIN,
                "--source-provenance",
                "phase4e-corp-eve",
            ],
            sub_env,
        )
        _run_cli(
            [
                "src.services.zeek_ingestion",
                "--file",
                str(_DEMO_DIR / "branch_conn.log.jsonl"),
                "--sensor-id",
                "zeek-branch-01",
                "--routing-domain-id",
                _BRANCH_DOMAIN,
                "--source-provenance",
                "phase4e-branch-zeek",
            ],
            sub_env,
        )
        _run_cli(
            [
                "src.services.suricata_ingestion",
                "--file",
                str(_DEMO_DIR / "branch_eve.jsonl"),
                "--sensor-id",
                "suricata-branch-01",
                "--ruleset-namespace",
                _DEMO_RULESET_NS,
                "--log-source-id",
                "branch-eve-demo-01",
                "--routing-domain-id",
                _BRANCH_DOMAIN,
                "--source-provenance",
                "phase4e-branch-eve",
            ],
            sub_env,
        )
        _run_cli(
            ["src.services.correlation_service", "--routing-domain-id", _CORP_DOMAIN],
            sub_env,
        )
        _run_cli(
            ["src.services.correlation_service", "--routing-domain-id", _BRANCH_DOMAIN],
            sub_env,
        )

        # Establish one genuine unverified_incomplete edge (Alert EF with candidate_cap=1)
        corp_alerts, _ = parse_suricata_eve_alert_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id="suricata-demo-01",
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-eve",
        )
        alert_a = next(a for a in corp_alerts if a.sid == 9100001)
        alert_ef = next(a for a in corp_alerts if a.sid == 9100005)

        _run_cli(
            [
                "src.services.zeek_ingestion",
                "--file",
                str(_DEMO_DIR / "corp_stale_rival_conn.log.jsonl"),
                "--sensor-id",
                "zeek-demo-01",
                "--routing-domain-id",
                _CORP_DOMAIN,
                "--source-provenance",
                "phase4e-corp-rival-zeek",
            ],
            sub_env,
        )
        _run_cli(
            [
                "src.services.correlation_service",
                "--candidate-cap",
                "1",
                "--event-id",
                alert_ef.event_id,
            ],
            sub_env,
        )

        pre_browser_snapshot = _snapshot_demo_graph(driver)
        assert pre_browser_snapshot["counts"] == (9, 7, 4), (
            f"Unexpected pre-browser snapshot: {pre_browser_snapshot['counts']}"
        )

        # 2. Boot real FastAPI + real Vite dev server (log to DEVNULL/files so pipes never block)
        api_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "src.api.app:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=_REPO_ROOT,
            env=sub_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        _wait_for_http("http://127.0.0.1:8000/ready", timeout_sec=30.0)

        npm_exe = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm_exe:
            raise RuntimeError("npm executable not found on PATH")
        vite_proc = subprocess.Popen(
            [
                npm_exe,
                "--prefix",
                "frontend",
                "run",
                "dev",
                "--",
                "--host",
                "127.0.0.1",
                "--port",
                "5173",
                "--strictPort",
            ],
            cwd=_REPO_ROOT,
            env=sub_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        _wait_for_http("http://127.0.0.1:5173/", timeout_sec=30.0)

        # 3. Drive real headless Chromium across full user flow
        observed_requests: List[tuple[str, str]] = []
        observed_api_statuses: List[tuple[str, int]] = []
        page_errors: List[str] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})

            def _on_request(req) -> None:
                if "127.0.0.1:5173" in req.url or "127.0.0.1:8000" in req.url:
                    observed_requests.append((req.method.upper(), req.url))

            def _on_response(resp) -> None:
                if "/api/" in resp.url or resp.url.endswith("/health") or resp.url.endswith("/ready"):
                    observed_api_statuses.append((resp.url, resp.status))

            page.on("request", _on_request)
            page.on("response", _on_response)
            page.on("pageerror", lambda err: page_errors.append(str(err)))

            # Vite dev server keeps an open HMR WebSocket, so use domcontentloaded
            # and wait directly on rendered UI indicators rather than networkidle.
            page.goto("http://127.0.0.1:5173/", wait_until="domcontentloaded", timeout=30000)
            page.get_by_text("API Liveness").wait_for(timeout=20000)
            page.get_by_text("Neo4j Connected").wait_for(timeout=20000)

            # Open Correlations view -> Legacy Correlations tab default
            page.get_by_role("button", name="Correlations").click()
            legacy_tab = page.get_by_role("tab", name="Legacy Correlations")
            legacy_tab.wait_for(timeout=10000)
            assert legacy_tab.get_attribute("aria-selected") == "true"

            # Switch to Alert-Flow Correlations (safe default: include_unverified=false)
            v2_tab = page.get_by_role("tab", name="Alert–Flow Correlations")
            v2_tab.click()

            table = page.get_by_role("table", name="Persisted alert-flow correlations")
            table.get_by_text("CDemoCorpStrong01").wait_for(timeout=15000)
            table.get_by_text("CDemoCorpIsoFlow01").wait_for(timeout=10000)
            table.get_by_text("CDemoBranchIsoFlow01").wait_for(timeout=10000)
            assert table.get_by_text("CDemoCorpLifecycle01").count() == 0

            # Inspect Scenario A row & verify full identifiers and Decimal string metadata
            inspect_btn = page.get_by_role(
                "button",
                name=f"Inspect evidence for correlation {alert_a.event_id}",
            ).first
            inspect_btn.click()

            dialog = page.get_by_role("dialog", name="Persisted Correlation Evidence Inspector")
            dialog.get_by_text(alert_a.event_id).wait_for(timeout=10000)
            dialog.get_by_text("WITHIN_INTERVAL").wait_for(timeout=10000)
            dialog.get_by_text("Yes (true)").wait_for(timeout=10000)
            page.keyboard.press("Escape")
            dialog.wait_for(state="detached", timeout=10000)

            # Filter by RoutingDomain=demo-v2-branch -> strict isolation
            page.get_by_role("textbox", name="RoutingDomain").fill("demo-v2-branch")
            page.get_by_role("button", name="Apply Filters").click()
            table.get_by_text("CDemoBranchIsoFlow01").wait_for(timeout=10000)
            assert table.get_by_text("CDemoCorpStrong01").count() == 0

            # Reset and enable Include unverified correlations -> reveals unverified_incomplete
            page.get_by_role("button", name="Reset").click()
            page.get_by_label("Include unverified correlations").check()
            page.get_by_role("button", name="Apply Filters").click()
            table.get_by_text("CDemoCorpLifecycle01").wait_for(timeout=10000)
            table.get_by_text("Previously Verified — Current Check Incomplete").wait_for(timeout=10000)
            page.get_by_text("Unverified Correlations Visible:").wait_for(timeout=10000)

            # Return to Legacy V1 tab -> continues working cleanly
            legacy_tab.click()
            page.get_by_text("Legacy V1 Correlation Notice:").wait_for(timeout=10000)

            browser.close()

        # 4. Assert zero uncaught JS errors, read-only network & zero 5xx errors
        assert not page_errors, f"Uncaught browser JS errors observed: {page_errors}"
        non_get = [(m, u) for m, u in observed_requests if m != "GET"]
        assert not non_get, f"Unexpected non-GET browser requests observed: {non_get}"
        server_errors = [(u, s) for u, s in observed_api_statuses if s >= 500]
        assert not server_errors, f"Unexpected 5xx API responses observed: {server_errors}"
        assert any("/api/v1/correlations/alert-flows" in u and s == 200 for u, s in observed_api_statuses)

        # 5. Confirm zero graph mutations occurred during real browser browsing
        post_browser_snapshot = _snapshot_demo_graph(driver)
        assert post_browser_snapshot == pre_browser_snapshot, (
            "Browser interaction altered Neo4j demo graph state!"
        )
        print("V2 BROWSER E2E SMOKE PASSED: Neo4j -> FastAPI -> React Chromium read-only flow verified.")
    finally:
        _terminate_proc(vite_proc)
        _terminate_proc(api_proc)
        _cleanup_demo_domains(driver)
        driver.close()


if __name__ == "__main__":
    run_browser_smoke()
