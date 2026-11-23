"""
Real End-to-End Browser Smoke Validation Script (Phase 4E).

Seeds deterministic synthetic demo fixtures into a verified-empty, local disposable
Neo4j container via the real V2 CLI entrypoints, boots FastAPI (`uvicorn`) + React
(`vite`), drives headless Chromium via Playwright across the Correlations workflow
(Legacy V1 + V2 Alert-Flow Correlations + Evidence Inspector + RoutingDomain filter
+ unverified_incomplete lifecycle), verifies no observable browser-triggered Neo4j
mutations, and cleans up ONLY entities owned by this run.

Safety Guards (Fail-Closed):
  - Requires explicit RUN_NEO4J_INTEGRATION=1 and NEO4J_TEST_* credentials.
  - Rejects any non-loopback NEO4J_TEST_URI host (allows only localhost, 127.0.0.1, ::1).
  - Refuses to mutate or delete data if the target Neo4j database is non-empty
    (`MATCH (n) RETURN count(n)` must equal 0 before any schema DDL or writes).
  - Refuses to run if local ports 127.0.0.1:8000 or 127.0.0.1:5173 are already occupied,
    and verifies owned child processes remain alive and serve expected payloads.

Prerequisites:
  - RUN_NEO4J_INTEGRATION=1
  - NEO4J_TEST_URI (local loopback Bolt URI), NEO4J_TEST_USERNAME, NEO4J_TEST_PASSWORD
  - Empty disposable Neo4j instance (e.g. fresh `docker compose up -d neo4j-test`)
  - Playwright Chromium browser installed (`playwright` package + `playwright install chromium`)
  - Frontend dependencies installed under `frontend/`
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

from neo4j import GraphDatabase

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.correlation import CorrelationPolicy
from src.graph.schema import ensure_schema
from src.ingestion.suricata_eve_parser import parse_suricata_eve_alert_file
from src.ingestion.zeek_conn_parser import parse_zeek_conn_file

_DEMO_DIR = _REPO_ROOT / "tests" / "fixtures" / "demo_v2"
_CORP_DOMAIN = "demo-v2-corp"
_BRANCH_DOMAIN = "demo-v2-branch"
_DEMO_DOMAINS = [_CORP_DOMAIN, _BRANCH_DOMAIN]
_DEMO_RULESET_NS = "demo-v2-rules"

_ALLOWED_NEO4J_SCHEMES = frozenset({"bolt", "neo4j", "bolt+s", "bolt+ssc", "neo4j+s", "neo4j+ssc"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_API_HOST = "127.0.0.1"
_API_PORT = 8000
_VITE_HOST = "127.0.0.1"
_VITE_PORT = 5173
_ALLOWED_BROWSER_NETLOCS = frozenset({f"{_VITE_HOST}:{_VITE_PORT}", f"{_API_HOST}:{_API_PORT}"})


def validate_disposable_neo4j_uri(uri: str) -> str:
    """Validate that a Neo4j URI targets only a local loopback disposable endpoint.

    Never assumes a URI is disposable merely because its hostname contains 'test' or 'demo'.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise RuntimeError("NEO4J_TEST_URI must be a non-empty Bolt/Neo4j URI.")
    cleaned = uri.strip()
    parsed = urlparse(cleaned)

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_NEO4J_SCHEMES:
        raise RuntimeError(
            f"Refusing to run against unsupported NEO4J_TEST_URI scheme {parsed.scheme!r}. "
            f"Allowed schemes: {sorted(_ALLOWED_NEO4J_SCHEMES)}."
        )
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError(
            "Refusing NEO4J_TEST_URI with embedded credentials; pass credentials via "
            "NEO4J_TEST_USERNAME and NEO4J_TEST_PASSWORD."
        )
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise RuntimeError(
            f"Refusing to run destructive smoke validation against non-loopback Neo4j host "
            f"{parsed.hostname!r} (URI: {cleaned!r}). Only local disposable loopback hosts "
            f"{sorted(_LOOPBACK_HOSTS)} are permitted."
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError(f"Invalid port in NEO4J_TEST_URI {cleaned!r}: {exc}") from exc
    if port is not None and not (1 <= port <= 65535):
        raise RuntimeError(f"Out-of-range port in NEO4J_TEST_URI {cleaned!r}: {port}")

    return cleaned


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
    validated_uri = validate_disposable_neo4j_uri(uri)
    return {"uri": validated_uri, "username": username, "password": password}


def _assert_database_is_empty(driver) -> None:
    """Fail closed if the target Neo4j database already contains any nodes."""
    with driver.session() as session:
        rec = session.run("MATCH (n) RETURN count(n) AS total_nodes").single()
        total_nodes = int(rec["total_nodes"]) if rec is not None else 0
    if total_nodes != 0:
        raise RuntimeError(
            f"Refusing to run browser smoke validation against non-empty Neo4j database "
            f"({total_nodes} existing node(s) found). Start a fresh disposable container "
            "(e.g. `docker compose down && docker compose up -d neo4j-test`) before running."
        )


def _assert_port_available(host: str, port: int) -> None:
    """Fail closed if a TCP listener is already bound on `(host, port)`."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            raise RuntimeError(
                f"Port {host}:{port} is already accepting connections from an existing process; "
                "refusing to run browser smoke against an unowned server."
            )
    except OSError:
        pass

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
    except OSError as exc:
        raise RuntimeError(
            f"Port {host}:{port} is unavailable or already bound ({exc}); "
            "refusing to run browser smoke against an unowned server."
        ) from exc
    finally:
        probe.close()


def _precompute_demo_entity_ids() -> Dict[str, Any]:
    """Parse fixtures upfront with real parsers to obtain exact deterministic owned entity IDs."""
    corp_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_conn.log.jsonl",
        sensor_id="zeek-demo-01",
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-zeek",
    )
    branch_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "branch_conn.log.jsonl",
        sensor_id="zeek-branch-01",
        routing_domain_id=_BRANCH_DOMAIN,
        source_provenance="phase4e-branch-zeek",
    )
    rival_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_stale_rival_conn.log.jsonl",
        sensor_id="zeek-demo-01",
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-rival-zeek",
    )
    corp_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "corp_eve.jsonl",
        sensor_id="suricata-demo-01",
        ruleset_namespace=_DEMO_RULESET_NS,
        log_source_id="corp-eve-demo-01",
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-eve",
    )
    branch_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "branch_eve.jsonl",
        sensor_id="suricata-branch-01",
        ruleset_namespace=_DEMO_RULESET_NS,
        log_source_id="branch-eve-demo-01",
        routing_domain_id=_BRANCH_DOMAIN,
        source_provenance="phase4e-branch-eve",
    )

    all_flows = corp_flows + branch_flows + rival_flows
    all_alerts = corp_alerts + branch_alerts

    scoped_ids: Set[str] = set()
    for flow in all_flows:
        scoped_ids.add(flow.src_scoped_id)
        scoped_ids.add(flow.dst_scoped_id)
    for alert in all_alerts:
        scoped_ids.add(alert.src_scoped_id)
        scoped_ids.add(alert.dst_scoped_id)

    return {
        "corp_flows": corp_flows,
        "branch_flows": branch_flows,
        "corp_alerts": corp_alerts,
        "branch_alerts": branch_alerts,
        "event_ids": sorted({a.event_id for a in all_alerts}),
        "obs_ids": sorted({f.observation_id for f in all_flows}),
        "def_ids": sorted({a.alert_definition_id for a in all_alerts}),
        "scoped_ids": sorted(scoped_ids),
        "domain_ids": sorted(_DEMO_DOMAINS),
    }


def _cleanup_owned_entities(
    driver,
    *,
    event_ids: Iterable[str],
    obs_ids: Iterable[str],
    def_ids: Iterable[str],
    scoped_ids: Iterable[str],
    domain_ids: Iterable[str],
) -> None:
    """Remove ONLY exact entities owned by this smoke run, preserving any unrelated relationships."""
    e_list = list(event_ids)
    o_list = list(obs_ids)
    d_list = list(def_ids)
    s_list = list(scoped_ids)
    dom_list = list(domain_ids)

    with driver.session() as session:
        if e_list:
            session.run(
                "MATCH (ae:AlertEvent) WHERE ae.event_id IN $eids DETACH DELETE ae",
                eids=e_list,
            ).consume()
        if o_list:
            session.run(
                "MATCH (fo:FlowObservation) WHERE fo.observation_id IN $oids DETACH DELETE fo",
                oids=o_list,
            ).consume()
        if d_list:
            session.run(
                "MATCH (ad:AlertDefinition) WHERE ad.definition_id IN $dids "
                "AND NOT (()-[:TRIGGERED_RULE]->(ad)) DETACH DELETE ad",
                dids=d_list,
            ).consume()
        if s_list:
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.scoped_id IN $sids "
                "OPTIONAL MATCH (ip)-[r]-() WHERE type(r) <> 'IN_DOMAIN' "
                "WITH ip, count(r) AS other_rels "
                "WHERE other_rels = 0 "
                "DETACH DELETE ip",
                sids=s_list,
            ).consume()
        if dom_list:
            session.run(
                "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
                "OPTIONAL MATCH (rd)-[r]-() "
                "WITH rd, count(r) AS rels "
                "WHERE rels = 0 "
                "DELETE rd",
                doms=dom_list,
            ).consume()


def _snapshot_full_disposable_graph(driver) -> Dict[str, Any]:
    """Capture global label/rel counts, demo entity digests, CORRELATED_WITH props, and schema.

    Because the browser smoke validates exclusive empty disposable database ownership
    prior to seeding, comparing this snapshot before and after Chromium interaction
    detects mutations across any label, relationship type, demo entity digest,
    correlation edge property, or schema object.
    """
    with driver.session() as session:
        label_counts = sorted(
            (tuple(sorted(rec["lbls"])), int(rec["cnt"]))
            for rec in session.run(
                "MATCH (n) RETURN labels(n) AS lbls, count(n) AS cnt"
            )
        )
        rel_counts = sorted(
            (str(rec["rel_type"]), int(rec["cnt"]))
            for rec in session.run(
                "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS cnt"
            )
        )
        alert_digests = [
            (str(rec["eid"]), rec["digest"])
            for rec in session.run(
                "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS eid, ae.payload_digest AS digest "
                "ORDER BY ae.event_id ASC",
                doms=_DEMO_DOMAINS,
            )
        ]
        flow_digests = [
            (str(rec["oid"]), rec["digest"])
            for rec in session.run(
                "MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
                "RETURN fo.observation_id AS oid, fo.payload_digest AS digest "
                "ORDER BY fo.observation_id ASC",
                doms=_DEMO_DOMAINS,
            )
        ]
        edges = [
            (str(rec["eid"]), str(rec["oid"]), dict(rec["props"]))
            for rec in session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS eid, fo.observation_id AS oid, properties(r) AS props "
                "ORDER BY ae.event_id ASC, fo.observation_id ASC",
                doms=_DEMO_DOMAINS,
            )
        ]
        constraints = sorted(
            str(rec["name"]) for rec in session.run("SHOW CONSTRAINTS YIELD name")
        )
        indexes = sorted(
            str(rec["name"]) for rec in session.run("SHOW INDEXES YIELD name")
        )

        return {
            "label_counts": label_counts,
            "rel_counts": rel_counts,
            "alert_digests": alert_digests,
            "flow_digests": flow_digests,
            "edges": edges,
            "constraints": constraints,
            "indexes": indexes,
        }


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


def _read_log_tail(log_path: Optional[Path], max_chars: int = 2000) -> str:
    if log_path is None or not log_path.exists():
        return ""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[-max_chars:]


def _wait_for_http(
    url: str,
    *,
    proc: Optional[subprocess.Popen] = None,
    timeout_sec: float = 30.0,
    body_validator: Optional[Callable[[bytes], bool]] = None,
    log_path: Optional[Path] = None,
) -> bytes:
    """Wait until an owned child server responds HTTP 200 and passes `body_validator`.

    Fails immediately if `proc` exits before readiness is established, preventing
    false readiness acceptance from an unrelated process on the same port.
    """
    deadline = time.monotonic() + timeout_sec
    last_err: str = "no response yet"
    while time.monotonic() < deadline:
        if proc is not None:
            rc = proc.poll()
            if rc is not None:
                tail = _read_log_tail(log_path)
                raise RuntimeError(
                    f"Owned child process exited early with code {rc} before {url} became ready."
                    + (f"\nProcess log tail:\n{tail}" if tail else "")
                )
        try:
            with urlopen(url, timeout=2.0) as resp:
                body = resp.read()
                if resp.status == 200:
                    if proc is not None and proc.poll() is not None:
                        raise RuntimeError(
                            f"Owned child process exited (code {proc.returncode}) while probing {url}."
                        )
                    if body_validator is None or body_validator(body):
                        return body
                    last_err = f"HTTP 200 body failed readiness validator for {url}"
                else:
                    last_err = f"HTTP status {resp.status}"
        except (URLError, OSError) as exc:
            last_err = str(exc)
        time.sleep(0.25)

    tail = _read_log_tail(log_path)
    raise RuntimeError(
        f"Timed out waiting for {url}: {last_err}"
        + (f"\nProcess log tail:\n{tail}" if tail else "")
    )


def _is_fastapi_ready_payload(body: bytes) -> bool:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return payload == {"status": "ready", "database": "connected"}


def _is_fastapi_health_payload(body: bytes) -> bool:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return payload.get("status") == "ok" and payload.get("app") == "Network Traffic Analysis"


def _is_vite_root_html(body: bytes) -> bool:
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return False
    return '<div id="root"></div>' in text and "Network Traffic & Security Alert Graph" in text


def _terminate_proc(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    if os.name != "nt":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError:
            proc.terminate()
    else:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
        else:
            proc.kill()
        proc.wait(timeout=5)


def run_browser_smoke() -> None:
    from playwright.sync_api import sync_playwright

    cfg = _require_disposable_neo4j_env()
    owned = _precompute_demo_entity_ids()

    sub_env = {
        **os.environ,
        "NEO4J_URI": cfg["uri"],
        "NEO4J_USERNAME": cfg["username"],
        "NEO4J_PASSWORD": cfg["password"],
        "DATA_IMPORT_ENABLED": "false",
    }

    driver = GraphDatabase.driver(cfg["uri"], auth=(cfg["username"], cfg["password"]))
    cleanup_authorized = False
    smoke_succeeded = False
    api_proc: subprocess.Popen | None = None
    vite_proc: subprocess.Popen | None = None
    api_log_fh = None
    vite_log_fh = None
    temp_dir = Path(tempfile.mkdtemp(prefix="v2_browser_smoke_"))
    api_log_path = temp_dir / "uvicorn.log"
    vite_log_path = temp_dir / "vite.log"

    try:
        # 0. Verify connectivity, exclusive empty disposable DB, and unoccupied local ports
        driver.verify_connectivity()
        _assert_database_is_empty(driver)
        _assert_port_available(_API_HOST, _API_PORT)
        _assert_port_available(_VITE_HOST, _VITE_PORT)

        ensure_schema(driver)
        cleanup_authorized = True

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
        alert_a = next(a for a in owned["corp_alerts"] if a.sid == 9100001)
        flow_a = next(f for f in owned["corp_flows"] if f.zeek_uid == "CDemoCorpStrong01")
        alert_ef = next(a for a in owned["corp_alerts"] if a.sid == 9100005)
        flow_ef = next(f for f in owned["corp_flows"] if f.zeek_uid == "CDemoCorpLifecycle01")

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

        pre_browser_snapshot = _snapshot_full_disposable_graph(driver)
        assert len(pre_browser_snapshot["flow_digests"]) == 9
        assert len(pre_browser_snapshot["alert_digests"]) == 7
        assert len(pre_browser_snapshot["edges"]) == 4

        strong_edge_props = next(
            props
            for eid, oid, props in pre_browser_snapshot["edges"]
            if eid == alert_a.event_id and oid == flow_a.observation_id
        )
        expected_policy_fp = CorrelationPolicy().policy_fingerprint
        assert strong_edge_props["policy_fingerprint"] == expected_policy_fp
        expected_evidence_digest = strong_edge_props["evidence_digest"]

        # 2. Boot owned FastAPI + owned Vite dev server (log to temp files so pipes never block)
        popen_kwargs: Dict[str, Any] = {"start_new_session": True} if os.name != "nt" else {}
        api_log_fh = open(api_log_path, "w", encoding="utf-8")
        api_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "src.api.app:app",
                "--host",
                _API_HOST,
                "--port",
                str(_API_PORT),
            ],
            cwd=_REPO_ROOT,
            env=sub_env,
            stdout=api_log_fh,
            stderr=subprocess.STDOUT,
            **popen_kwargs,
        )
        _wait_for_http(
            f"http://{_API_HOST}:{_API_PORT}/health",
            proc=api_proc,
            timeout_sec=30.0,
            body_validator=_is_fastapi_health_payload,
            log_path=api_log_path,
        )
        _wait_for_http(
            f"http://{_API_HOST}:{_API_PORT}/ready",
            proc=api_proc,
            timeout_sec=30.0,
            body_validator=_is_fastapi_ready_payload,
            log_path=api_log_path,
        )

        npm_exe = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm_exe:
            raise RuntimeError("npm executable not found on PATH")
        vite_log_fh = open(vite_log_path, "w", encoding="utf-8")
        vite_proc = subprocess.Popen(
            [
                npm_exe,
                "--prefix",
                "frontend",
                "run",
                "dev",
                "--",
                "--host",
                _VITE_HOST,
                "--port",
                str(_VITE_PORT),
                "--strictPort",
            ],
            cwd=_REPO_ROOT,
            env=sub_env,
            stdout=vite_log_fh,
            stderr=subprocess.STDOUT,
            **popen_kwargs,
        )
        _wait_for_http(
            f"http://{_VITE_HOST}:{_VITE_PORT}/",
            proc=vite_proc,
            timeout_sec=30.0,
            body_validator=_is_vite_root_html,
            log_path=vite_log_path,
        )

        # 3. Drive real headless Chromium across full user flow
        observed_http_requests: List[Tuple[str, str]] = []
        unexpected_external_requests: List[str] = []
        observed_api_statuses: List[Tuple[str, int]] = []
        observed_v2_payloads: List[Tuple[str, Dict[str, Any]]] = []
        page_errors: List[str] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})

                def _on_request(req) -> None:
                    parsed_req = urlparse(req.url)
                    if parsed_req.scheme in {"http", "https"}:
                        if parsed_req.netloc in _ALLOWED_BROWSER_NETLOCS:
                            observed_http_requests.append((req.method.upper(), req.url))
                        else:
                            unexpected_external_requests.append(req.url)

                def _on_response(resp) -> None:
                    parsed_resp = urlparse(resp.url)
                    if parsed_resp.netloc not in _ALLOWED_BROWSER_NETLOCS:
                        return
                    path = parsed_resp.path
                    if path.startswith("/api/") or path in {"/health", "/ready"}:
                        observed_api_statuses.append((resp.url, resp.status))

                page.on("request", _on_request)
                page.on("response", _on_response)
                page.on("pageerror", lambda err: page_errors.append(str(err)))

                # Vite dev server keeps an open HMR WebSocket, so use domcontentloaded
                # and wait directly on rendered UI indicators rather than networkidle.
                page.goto(
                    f"http://{_VITE_HOST}:{_VITE_PORT}/",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
                page.get_by_text("API Liveness").wait_for(timeout=20000)
                page.get_by_text("Neo4j Connected").wait_for(timeout=20000)

                # Open Correlations view -> Legacy Correlations tab default
                page.get_by_role("button", name="Correlations").click()
                legacy_tab = page.get_by_role("tab", name="Legacy Correlations")
                legacy_tab.wait_for(timeout=10000)
                assert legacy_tab.get_attribute("aria-selected") == "true"

                # Switch to Alert-Flow Correlations (safe default: include_unverified=false)
                v2_tab = page.get_by_role("tab", name="Alert–Flow Correlations")
                with page.expect_response(
                    lambda r: urlparse(r.url).path == "/api/v1/correlations/alert-flows"
                    and parse_qs(urlparse(r.url).query).get("include_unverified") == ["false"]
                    and "routing_domain_id" not in parse_qs(urlparse(r.url).query),
                    timeout=15000,
                ) as default_resp_info:
                    v2_tab.click()
                default_resp = default_resp_info.value
                assert default_resp.status == 200
                observed_v2_payloads.append((default_resp.url, default_resp.json()))

                table = page.get_by_role("table", name="Persisted alert-flow correlations")
                table.get_by_text("CDemoCorpStrong01").wait_for(timeout=15000)
                table.get_by_text("CDemoCorpIsoFlow01").wait_for(timeout=10000)
                table.get_by_text("CDemoBranchIsoFlow01").wait_for(timeout=10000)
                assert table.locator("tbody tr").count() == 3
                assert table.get_by_text("CDemoCorpLifecycle01").count() == 0

                # Inspect Scenario A row & verify complete persisted evidence fields
                inspect_btn = page.get_by_role(
                    "button",
                    name=f"Inspect evidence for correlation {alert_a.event_id} and {flow_a.observation_id}",
                )
                inspect_btn.click()

                dialog = page.get_by_role("dialog", name="Persisted Correlation Evidence Inspector")
                dialog.get_by_text(alert_a.event_id).wait_for(timeout=10000)
                dialog.get_by_text(flow_a.observation_id).wait_for(timeout=10000)
                dialog.get_by_text("CDemoCorpStrong01").wait_for(timeout=10000)
                dialog.get_by_text(_CORP_DOMAIN, exact=True).wait_for(timeout=10000)
                dialog.get_by_text("cid_verified_5tuple_temporal").wait_for(timeout=10000)
                dialog.get_by_text("WITHIN_INTERVAL").wait_for(timeout=10000)
                dialog.get_by_text("MATCH", exact=True).wait_for(timeout=10000)
                dialog.get_by_text("0", exact=True).wait_for(timeout=10000)
                dialog.get_by_text("Yes (true)").wait_for(timeout=10000)
                dialog.get_by_text(expected_policy_fp).wait_for(timeout=10000)
                dialog.get_by_text(expected_evidence_digest).wait_for(timeout=10000)
                page.keyboard.press("Escape")
                dialog.wait_for(state="detached", timeout=10000)

                # Filter by RoutingDomain=demo-v2-branch -> wait explicitly for API response & DOM detach
                page.get_by_role("textbox", name="RoutingDomain").fill(_BRANCH_DOMAIN)
                with page.expect_response(
                    lambda r: urlparse(r.url).path == "/api/v1/correlations/alert-flows"
                    and parse_qs(urlparse(r.url).query).get("routing_domain_id") == [_BRANCH_DOMAIN],
                    timeout=15000,
                ) as branch_resp_info:
                    page.get_by_role("button", name="Apply Filters").click()
                branch_resp = branch_resp_info.value
                assert branch_resp.status == 200
                observed_v2_payloads.append((branch_resp.url, branch_resp.json()))

                page.get_by_text(f"domain={_BRANCH_DOMAIN}").wait_for(timeout=10000)
                table.get_by_text("CDemoCorpStrong01").wait_for(state="detached", timeout=10000)
                table.get_by_text("CDemoBranchIsoFlow01").wait_for(timeout=10000)
                assert table.locator("tbody tr").count() == 1
                assert table.get_by_text("CDemoCorpStrong01").count() == 0

                # Reset and enable Include unverified correlations -> reveals unverified_incomplete
                page.get_by_role("button", name="Reset").click()
                table.get_by_text("CDemoCorpStrong01").wait_for(timeout=10000)
                page.get_by_label("Include unverified correlations").check()
                with page.expect_response(
                    lambda r: urlparse(r.url).path == "/api/v1/correlations/alert-flows"
                    and parse_qs(urlparse(r.url).query).get("include_unverified") == ["true"],
                    timeout=15000,
                ) as unv_resp_info:
                    page.get_by_role("button", name="Apply Filters").click()
                unv_resp = unv_resp_info.value
                assert unv_resp.status == 200
                observed_v2_payloads.append((unv_resp.url, unv_resp.json()))

                table.get_by_text("CDemoCorpLifecycle01").wait_for(timeout=10000)
                table.get_by_text("Previously Verified — Current Check Incomplete").wait_for(timeout=10000)
                page.get_by_text("Unverified Correlations Visible:").wait_for(timeout=10000)
                assert table.locator("tbody tr").count() == 4

                # Open Evidence Inspector on the unverified_incomplete row to verify warning & reason
                inspect_unv_btn = page.get_by_role(
                    "button",
                    name=f"Inspect evidence for correlation {alert_ef.event_id} and {flow_ef.observation_id}",
                )
                inspect_unv_btn.click()
                dialog.get_by_text(alert_ef.event_id).wait_for(timeout=10000)
                dialog.get_by_text(flow_ef.observation_id).wait_for(timeout=10000)
                dialog.get_by_text("Unverified Incomplete Status:").wait_for(timeout=10000)
                dialog.get_by_text("CANDIDATE_CAP_TRUNCATED").wait_for(timeout=10000)
                page.keyboard.press("Escape")
                dialog.wait_for(state="detached", timeout=10000)

                # Return to Legacy V1 tab -> continues working cleanly
                legacy_tab.click()
                page.get_by_text("Legacy V1 Correlation Notice:").wait_for(timeout=10000)
            finally:
                browser.close()

        # 4. Assert owned servers remained alive, zero JS/HTTP errors, read-only & real payloads
        assert api_proc.poll() is None, f"Owned FastAPI process exited during test: {api_proc.returncode}"
        assert vite_proc.poll() is None, f"Owned Vite process exited during test: {vite_proc.returncode}"
        assert not page_errors, f"Uncaught browser JS errors observed: {page_errors}"
        assert not unexpected_external_requests, (
            f"Unexpected external browser requests observed: {unexpected_external_requests}"
        )
        non_get = [(m, u) for m, u in observed_http_requests if m != "GET"]
        assert not non_get, f"Unexpected non-GET browser requests observed: {non_get}"
        error_responses = [(u, s) for u, s in observed_api_statuses if s >= 400]
        assert not error_responses, f"Unexpected >=400 API responses observed: {error_responses}"

        # Prove real Neo4j-backed JSON responses drove every step of the UI
        assert any(
            parse_qs(urlparse(u).query).get("include_unverified") == ["false"]
            and "routing_domain_id" not in parse_qs(urlparse(u).query)
            and body.get("total") == 3
            and all(item.get("verification_status") == "verified" for item in body.get("items", []))
            for u, body in observed_v2_payloads
        ), f"Missing expected verified-only default API response: {observed_v2_payloads}"

        assert any(
            parse_qs(urlparse(u).query).get("routing_domain_id") == [_BRANCH_DOMAIN]
            and body.get("total") == 1
            and body.get("items", [{}])[0].get("zeek_uid") == "CDemoBranchIsoFlow01"
            for u, body in observed_v2_payloads
        ), f"Missing expected domain-filtered API response: {observed_v2_payloads}"

        assert any(
            parse_qs(urlparse(u).query).get("include_unverified") == ["true"]
            and body.get("total") == 4
            and any(
                item.get("event_id") == alert_ef.event_id
                and item.get("verification_status") == "unverified_incomplete"
                and item.get("last_incomplete_reason") == "CANDIDATE_CAP_TRUNCATED"
                for item in body.get("items", [])
            )
            for u, body in observed_v2_payloads
        ), f"Missing expected include_unverified=true API response: {observed_v2_payloads}"

        # 5. Confirm zero observable graph or schema mutations during real browser browsing
        post_browser_snapshot = _snapshot_full_disposable_graph(driver)
        assert post_browser_snapshot == pre_browser_snapshot, (
            "Browser interaction altered disposable Neo4j graph or schema snapshot!"
        )
        smoke_succeeded = True
        print("V2 BROWSER E2E SMOKE PASSED: Neo4j -> FastAPI -> React Chromium read-only flow verified.")
    finally:
        _terminate_proc(vite_proc)
        _terminate_proc(api_proc)
        if vite_log_fh is not None:
            vite_log_fh.close()
        if api_log_fh is not None:
            api_log_fh.close()
        shutil.rmtree(temp_dir, ignore_errors=True)
        if cleanup_authorized:
            _cleanup_owned_entities(
                driver,
                event_ids=owned["event_ids"],
                obs_ids=owned["obs_ids"],
                def_ids=owned["def_ids"],
                scoped_ids=owned["scoped_ids"],
                domain_ids=owned["domain_ids"],
            )
            if smoke_succeeded:
                with driver.session() as session:
                    remaining = session.run("MATCH (n) RETURN count(n) AS cnt").single()["cnt"]
                    if remaining != 0:
                        raise RuntimeError(
                            f"Post-smoke cleanup left {remaining} residual node(s) in disposable Neo4j."
                        )
        driver.close()


if __name__ == "__main__":
    run_browser_smoke()
