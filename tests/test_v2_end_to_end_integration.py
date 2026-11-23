"""
Live Neo4j 5.26 End-to-End Integration Validation for the Complete V2 Workflow (Phase 4E).

Exercises the entire real pipeline against a disposable Neo4j instance:
  Synthetic Zeek conn.log JSONL + Suricata EVE JSONL
    -> real streaming parsers & V2 ingestion services/CLIs
    -> bounded keyset-paginated Phase 4A/4B correlation service
    -> Neo4j graph persistence & stale-edge reconciliation
    -> real FastAPI lifespan + read-only Phase 4C API endpoints

Strictly opt-in via RUN_NEO4J_INTEGRATION=1 and NEO4J_TEST_* environment variables.
All writes and cleanups are scoped strictly to dedicated `demo-v2-*` RoutingDomains.
"""

from __future__ import annotations

from decimal import Decimal
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from src.api.app import create_app
from src.correlation import CorrelationPolicy
from src.graph.schema import ensure_schema
from src.ingestion.suricata_eve_parser import parse_suricata_eve_alert_file
from src.ingestion.zeek_conn_parser import parse_zeek_conn_file
from src.services.correlation_service import (
    main as correlation_cli_main,
    run_alert_flow_correlation,
)
from src.services.suricata_ingestion import (
    ingest_suricata_eve_file,
    main as suricata_cli_main,
)
from src.services.zeek_ingestion import (
    ingest_zeek_conn_file,
    main as zeek_cli_main,
)

pytestmark = pytest.mark.integration

_DEMO_DIR = Path(__file__).resolve().parent / "fixtures" / "demo_v2"
_CORP_DOMAIN = "demo-v2-corp"
_BRANCH_DOMAIN = "demo-v2-branch"
_TOL_DOMAIN = "demo-v2-tol"
_ALL_DEMO_DOMAINS = [_CORP_DOMAIN, _BRANCH_DOMAIN, _TOL_DOMAIN]
_DEMO_RULESET_NS = "demo-v2-rules"
_ZEEK_SENSOR = "zeek-demo-01"
_SURICATA_SENSOR = "suricata-demo-01"


@pytest.fixture(scope="module")
def neo4j_test_config() -> Dict[str, str]:
    """Require explicit opt-in and disposable NEO4J_TEST_* configuration."""
    if os.environ.get("RUN_NEO4J_INTEGRATION") != "1":
        pytest.skip("Live Neo4j integration tests disabled (set RUN_NEO4J_INTEGRATION=1 to enable)")

    uri = os.environ.get("NEO4J_TEST_URI")
    username = os.environ.get("NEO4J_TEST_USERNAME")
    password = os.environ.get("NEO4J_TEST_PASSWORD")
    if not uri or not username or not password:
        pytest.skip(
            "RUN_NEO4J_INTEGRATION=1 is set but NEO4J_TEST_* environment variables are incomplete"
        )
    return {"uri": uri, "username": username, "password": password}


@pytest.fixture(scope="module")
def live_driver(neo4j_test_config: Dict[str, str]):
    """Connect to the disposable Neo4j test container and verify schema readiness."""
    driver = None
    try:
        driver = GraphDatabase.driver(
            neo4j_test_config["uri"],
            auth=(neo4j_test_config["username"], neo4j_test_config["password"]),
        )
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError, Exception) as exc:
        if driver is not None:
            driver.close()
        pytest.fail(f"Failed to connect to disposable Neo4j at {neo4j_test_config['uri']}: {exc}")

    ensure_schema(driver)
    yield driver
    driver.close()


def _cleanup_demo_domains(driver, domains: List[str], ruleset_namespaces: List[str]) -> None:
    """Safely remove ONLY synthetic Phase 4E demo entities scoped by domain & ruleset."""
    with driver.session() as session:
        session.run(
            "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms DETACH DELETE ae",
            doms=domains,
        ).consume()
        session.run(
            "MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms DETACH DELETE fo",
            doms=domains,
        ).consume()
        session.run(
            "MATCH (ip:IPAddress) "
            "WHERE (ip.routing_domain_id IN $doms "
            "       OR ANY(d IN $doms WHERE ip.scoped_id STARTS WITH (d + '#'))) "
            "  AND NOT ((ip)--(:AlertFact)) "
            "  AND NOT ((:FlowObservation)-->(ip)) "
            "  AND NOT ((:AlertEvent)-->(ip)) "
            "DETACH DELETE ip",
            doms=domains,
        ).consume()
        session.run(
            "MATCH (ad:AlertDefinition) "
            "WHERE ad.ruleset_namespace IN $nss "
            "  AND NOT (()-[:TRIGGERED_RULE]->(ad)) "
            "DETACH DELETE ad",
            nss=ruleset_namespaces,
        ).consume()
        session.run(
            "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
            "AND NOT ((:IPAddress)-[:IN_DOMAIN]->(rd)) "
            "DETACH DELETE rd",
            doms=domains,
        ).consume()


def _snapshot_demo_graph(driver, domains: List[str]) -> Dict[str, Any]:
    """Capture node/relationship state in demo domains to prove GET endpoints never mutate Neo4j."""
    with driver.session() as session:
        counts = session.run(
            "OPTIONAL MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
            "WITH count(fo) AS flow_cnt "
            "OPTIONAL MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
            "WITH flow_cnt, count(ae) AS alert_cnt "
            "OPTIONAL MATCH (ae2:AlertEvent)-[r:CORRELATED_WITH]->(fo2:FlowObservation) "
            "WHERE ae2.routing_domain_id IN $doms "
            "RETURN flow_cnt, alert_cnt, count(r) AS rel_cnt",
            doms=domains,
        ).single()

        rels = [
            (rec["event_id"], rec["observation_id"], dict(rec["props"]))
            for rec in session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS event_id, fo.observation_id AS observation_id, "
                "       properties(r) AS props "
                "ORDER BY ae.event_id ASC, fo.observation_id ASC",
                doms=domains,
            )
        ]

        return {
            "counts": (counts["flow_cnt"], counts["alert_cnt"], counts["rel_cnt"]),
            "rels": rels,
        }


def _configure_env_for_cli_and_app(monkeypatch: pytest.MonkeyPatch, cfg: Dict[str, str]) -> None:
    monkeypatch.setenv("NEO4J_URI", cfg["uri"])
    monkeypatch.setenv("NEO4J_USERNAME", cfg["username"])
    monkeypatch.setenv("NEO4J_PASSWORD", cfg["password"])


def test_e2e_01_ingestion_correlation_pagination_idempotency_and_api(
    live_driver,
    neo4j_test_config: Dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
):
    """Scenarios A-D + pagination anti-starvation + idempotency + real FastAPI lifespan verification."""
    _cleanup_demo_domains(live_driver, _ALL_DEMO_DOMAINS, [_DEMO_RULESET_NS, "demo-v2-tol-ns"])
    _configure_env_for_cli_and_app(monkeypatch, neo4j_test_config)

    try:
        # 1. Real parser-to-Neo4j ingestion for demo-v2-corp
        corp_zeek_res = ingest_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-zeek",
            batch_size=3,
            driver=live_driver,
        )
        assert corp_zeek_res.parse_summary.total_raw_records == 7
        assert corp_zeek_res.parse_summary.valid_records == 7
        assert corp_zeek_res.parse_summary.skipped_records == 0
        assert corp_zeek_res.persistence_summary.created_count == 7
        assert corp_zeek_res.persistence_summary.duplicate_matched_count == 0

        corp_suri_res = ingest_suricata_eve_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-eve",
            batch_size=2,
            driver=live_driver,
        )
        assert corp_suri_res.parse_summary.total_raw_records == 6
        assert corp_suri_res.parse_summary.valid_records == 5
        assert corp_suri_res.parse_summary.ignored_non_alert_records == 1
        assert corp_suri_res.parse_summary.skipped_records == 0
        assert corp_suri_res.persistence_summary.created_count == 5
        assert corp_suri_res.persistence_summary.definitions_created_count == 5

        # 2. Real CLI entrypoints for demo-v2-branch using disposable env vars
        assert (
            zeek_cli_main(
                [
                    "--file",
                    str(_DEMO_DIR / "branch_conn.log.jsonl"),
                    "--sensor-id",
                    "zeek-branch-01",
                    "--routing-domain-id",
                    _BRANCH_DOMAIN,
                    "--source-provenance",
                    "phase4e-branch-zeek",
                ]
            )
            == 0
        )
        assert (
            suricata_cli_main(
                [
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
                ]
            )
            == 0
        )

        # 3. Verify explicit event_ids exceeding max_alerts never silently truncates
        with pytest.raises(ValueError, match="exceeds max_alerts"):
            run_alert_flow_correlation(
                event_ids=["a" * 64, "b" * 64],
                max_alerts=1,
                driver=live_driver,
            )

        # 4. Bounded keyset-paginated Phase 4B correlation for demo-v2-corp (max_alerts=2 proves cursor sweep)
        policy = CorrelationPolicy()
        corp_pages = []
        cursor = None
        while True:
            page = run_alert_flow_correlation(
                policy=policy,
                routing_domain_id=_CORP_DOMAIN,
                max_alerts=2,
                batch_size=2,
                after_cursor=cursor,
                driver=live_driver,
            )
            corp_pages.append(page)
            if not page.has_more:
                assert page.next_cursor is None
                break
            assert page.next_cursor is not None
            cursor = page.next_cursor
            assert len(corp_pages) <= 5  # anti-infinite-loop safeguard

        assert len(corp_pages) == 3  # 5 alerts paged as 2 + 2 + 1 (NULL-ns Alert A on final page)
        assert sum(p.alerts_evaluated for p in corp_pages) == 5
        assert sum(p.strong for p in corp_pages) == 3
        assert sum(p.ambiguous for p in corp_pages) == 1
        assert sum(p.rejected for p in corp_pages) == 1
        assert sum(p.correlations_created for p in corp_pages) == 3

        # Run branch domain via CLI entrypoint cleanly
        assert (
            correlation_cli_main(
                ["--routing-domain-id", _BRANCH_DOMAIN, "--max-alerts", "10", "--batch-size", "10"]
            )
            == 0
        )

        # 5. Parse ground-truth IDs using real parsers for Cypher verification
        corp_flows, _ = parse_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-zeek",
        )
        corp_alerts, _ = parse_suricata_eve_alert_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-eve",
        )
        branch_flows, _ = parse_zeek_conn_file(
            _DEMO_DIR / "branch_conn.log.jsonl",
            sensor_id="zeek-branch-01",
            routing_domain_id=_BRANCH_DOMAIN,
            source_provenance="phase4e-branch-zeek",
        )
        branch_alerts, _ = parse_suricata_eve_alert_file(
            _DEMO_DIR / "branch_eve.jsonl",
            sensor_id="suricata-branch-01",
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="branch-eve-demo-01",
            routing_domain_id=_BRANCH_DOMAIN,
            source_provenance="phase4e-branch-eve",
        )

        alert_a = next(a for a in corp_alerts if a.sid == 9100001)
        alert_d = next(a for a in corp_alerts if a.sid == 9100004)
        flow_a = next(f for f in corp_flows if f.zeek_uid == "CDemoCorpStrong01")

        # 6. Verify persisted Cypher graph state
        with live_driver.session() as session:
            cross_domain_cnt = session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms AND ae.routing_domain_id <> fo.routing_domain_id "
                "RETURN count(r) AS cnt",
                doms=[_CORP_DOMAIN, _BRANCH_DOMAIN],
            ).single()["cnt"]
            assert cross_domain_cnt == 0

            demo_counts = session.run(
                "MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
                "WITH count(fo) AS flows "
                "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
                "WITH flows, count(ae) AS alerts "
                "MATCH (ae2:AlertEvent)-[:TRIGGERED_RULE]->(ad:AlertDefinition) "
                "WHERE ae2.routing_domain_id IN $doms "
                "RETURN flows, alerts, count(ad) AS def_links",
                doms=[_CORP_DOMAIN, _BRANCH_DOMAIN],
            ).single()
            assert demo_counts["flows"] == 8
            assert demo_counts["alerts"] == 7
            assert demo_counts["def_links"] == 7

            strong_row = session.run(
                "MATCH (ae:AlertEvent {event_id: $eid})-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "RETURN fo.observation_id AS obs_id, ae.timestamp_epoch_decimal AS a_ts, "
                "       ae.timestamp_epoch_ns AS a_ns, fo.start_epoch_decimal AS f_ts, "
                "       properties(r) AS props",
                eid=alert_a.event_id,
            ).single()
            assert strong_row is not None
            assert strong_row["obs_id"] == flow_a.observation_id
            assert strong_row["a_ts"] == "1795428002.123456789123"
            assert strong_row["a_ns"] is None
            assert strong_row["f_ts"] == "1795428000.123456789"
            props = dict(strong_row["props"])
            assert props["verification_status"] == "verified"
            assert props["used_decimal_fallback"] is True
            assert props["temporal_delta_decimal"] == "0"
            assert props["policy_fingerprint"] == policy.policy_fingerprint
            assert props["evidence_version"] == policy.evidence_version
            assert len(props["evidence_digest"]) == 64

        snapshot_before_repeat = _snapshot_demo_graph(live_driver, [_CORP_DOMAIN, _BRANCH_DOMAIN])
        assert snapshot_before_repeat["counts"] == (8, 7, 4)

        # 7. Idempotency: repeat ingestion & repeat correlation produce zero duplicate nodes/edges
        repeat_zeek = ingest_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-zeek",
            driver=live_driver,
        )
        assert repeat_zeek.persistence_summary.created_count == 0
        assert repeat_zeek.persistence_summary.duplicate_matched_count == 7

        repeat_suri = ingest_suricata_eve_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-eve",
            driver=live_driver,
        )
        assert repeat_suri.persistence_summary.created_count == 0
        assert repeat_suri.persistence_summary.duplicate_matched_count == 5

        repeat_corr = run_alert_flow_correlation(
            policy=policy,
            routing_domain_id=_CORP_DOMAIN,
            driver=live_driver,
        )
        assert repeat_corr.correlations_created == 0
        assert repeat_corr.correlations_unchanged == 3
        assert repeat_corr.correlations_updated == 0
        assert repeat_corr.stale_correlations_removed == 0

        snapshot_after_repeat = _snapshot_demo_graph(live_driver, [_CORP_DOMAIN, _BRANCH_DOMAIN])
        assert snapshot_after_repeat == snapshot_before_repeat

        # 8. Real FastAPI app + lifespan against live disposable Neo4j
        with TestClient(create_app()) as client:
            health_res = client.get("/health")
            assert health_res.status_code == 200
            assert health_res.json()["status"] == "ok"

            ready_res = client.get("/ready")
            assert ready_res.status_code == 200
            assert ready_res.json() == {"status": "ready", "database": "connected"}

            corp_api = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": _CORP_DOMAIN},
            )
            assert corp_api.status_code == 200
            corp_body = corp_api.json()
            assert corp_body["total"] == 3
            assert all(item["verification_status"] == "verified" for item in corp_body["items"])
            assert all(item["routing_domain_id"] == _CORP_DOMAIN for item in corp_body["items"])

            # Verify exact string Decimal delta on Scenario A item
            strong_api_item = next(
                item for item in corp_body["items"] if item["event_id"] == alert_a.event_id
            )
            assert strong_api_item["zeek_uid"] == "CDemoCorpStrong01"
            assert isinstance(strong_api_item["temporal_delta_decimal"], str)
            assert strong_api_item["temporal_delta_decimal"] == "0"
            assert strong_api_item["used_decimal_fallback"] is True

            # Branch isolation & pagination check
            branch_api = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": _BRANCH_DOMAIN},
            )
            assert branch_api.status_code == 200
            assert branch_api.json()["total"] == 1
            assert branch_api.json()["items"][0]["observation_id"] == branch_flows[0].observation_id

            # Pagination across corp items (limit=2, offset=2)
            page1 = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": _CORP_DOMAIN, "limit": 2, "offset": 0},
            ).json()
            page2 = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": _CORP_DOMAIN, "limit": 2, "offset": 2},
            ).json()
            assert page1["total"] == 3 and len(page1["items"]) == 2
            assert page2["total"] == 3 and len(page2["items"]) == 1

            # Existing non-correlated AlertEvent -> HTTP 200 empty; missing AlertEvent -> HTTP 404
            empty_alert_res = client.get(
                f"/api/v1/correlations/alert-flows/{alert_d.event_id}",
                params={"routing_domain_id": _CORP_DOMAIN},
            )
            assert empty_alert_res.status_code == 200
            assert empty_alert_res.json()["items"] == []
            assert empty_alert_res.json()["total"] == 0

            missing_res = client.get(f"/api/v1/correlations/alert-flows/{'0' * 64}")
            assert missing_res.status_code == 404

            # Branch uncorrelated alert (overlapping IP in corp) -> 200 empty, no cross-domain leak
            branch_uncorr = next(a for a in branch_alerts if a.sid == 9100006)
            branch_empty_res = client.get(
                f"/api/v1/correlations/alert-flows/{branch_uncorr.event_id}",
                params={"routing_domain_id": _BRANCH_DOMAIN},
            )
            assert branch_empty_res.status_code == 200
            assert branch_empty_res.json()["total"] == 0

        # Confirm zero graph writes occurred during GET requests
        assert _snapshot_demo_graph(live_driver, [_CORP_DOMAIN, _BRANCH_DOMAIN]) == snapshot_before_repeat
    finally:
        _cleanup_demo_domains(live_driver, _ALL_DEMO_DOMAINS, [_DEMO_RULESET_NS, "demo-v2-tol-ns"])


def test_e2e_02_verification_lifecycle_and_stale_reconciliation(
    live_driver,
    neo4j_test_config: Dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
):
    """Scenarios E & F: incomplete reevaluation preserves edge as unverified_incomplete; complete removal deletes stale edge."""
    _cleanup_demo_domains(live_driver, _ALL_DEMO_DOMAINS, [_DEMO_RULESET_NS])
    _configure_env_for_cli_and_app(monkeypatch, neo4j_test_config)

    try:
        ingest_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-zeek",
            driver=live_driver,
        )
        ingest_suricata_eve_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-eve",
            driver=live_driver,
        )

        corp_alerts, _ = parse_suricata_eve_alert_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=_DEMO_RULESET_NS,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-eve",
        )
        alert_ef = next(a for a in corp_alerts if a.sid == 9100005)

        initial = run_alert_flow_correlation(
            routing_domain_id=_CORP_DOMAIN,
            driver=live_driver,
        )
        assert initial.correlations_created == 3

        # Scenario E: ingest competing rival flow and trigger truncated candidate lookup (candidate_cap=1)
        rival_ingest = ingest_zeek_conn_file(
            _DEMO_DIR / "corp_stale_rival_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=_CORP_DOMAIN,
            source_provenance="phase4e-corp-rival-zeek",
            driver=live_driver,
        )
        assert rival_ingest.persistence_summary.created_count == 1

        incomplete_run = run_alert_flow_correlation(
            policy=CorrelationPolicy(candidate_cap=1),
            event_ids=[alert_ef.event_id],
            driver=live_driver,
        )
        assert incomplete_run.alerts_evaluated == 1
        assert incomplete_run.candidate_cap_exceeded == 1
        assert incomplete_run.incomplete_evaluations == 1
        assert incomplete_run.stale_correlations_removed == 0

        with TestClient(create_app()) as client:
            # Default API excludes unverified_incomplete (hides Alert EF, shows 2 verified edges)
            default_list = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": _CORP_DOMAIN},
            ).json()
            assert default_list["total"] == 2
            assert all(item["event_id"] != alert_ef.event_id for item in default_list["items"])

            detail_default = client.get(
                f"/api/v1/correlations/alert-flows/{alert_ef.event_id}",
                params={"routing_domain_id": _CORP_DOMAIN},
            )
            assert detail_default.status_code == 200
            assert detail_default.json()["total"] == 0

            # Explicit include_unverified=true or verification_status=unverified_incomplete reveals it
            unverified_res = client.get(
                f"/api/v1/correlations/alert-flows/{alert_ef.event_id}",
                params={"routing_domain_id": _CORP_DOMAIN, "include_unverified": "true"},
            )
            assert unverified_res.status_code == 200
            unverified_items = unverified_res.json()["items"]
            assert len(unverified_items) == 1
            assert unverified_items[0]["verification_status"] == "unverified_incomplete"
            assert unverified_items[0]["last_incomplete_reason"] is not None
            assert unverified_items[0]["last_incomplete_at_utc"] is not None

        # Scenario F: complete reevaluation (candidate_cap=200) classifies AMBIGUOUS & removes stale edge
        reconciled_run = run_alert_flow_correlation(
            policy=CorrelationPolicy(candidate_cap=200),
            event_ids=[alert_ef.event_id],
            driver=live_driver,
        )
        assert reconciled_run.alerts_evaluated == 1
        assert reconciled_run.ambiguous == 1
        assert reconciled_run.incomplete_evaluations == 0
        assert reconciled_run.stale_correlations_removed == 1

        with TestClient(create_app()) as client:
            after_removal = client.get(
                f"/api/v1/correlations/alert-flows/{alert_ef.event_id}",
                params={"routing_domain_id": _CORP_DOMAIN, "include_unverified": "true"},
            )
            assert after_removal.status_code == 200
            assert after_removal.json()["items"] == []
            assert after_removal.json()["total"] == 0
    finally:
        _cleanup_demo_domains(live_driver, _ALL_DEMO_DOMAINS, [_DEMO_RULESET_NS])


def test_e2e_03_subnanosecond_decimal_delta_and_db_unavailable_503(
    live_driver,
    neo4j_test_config: Dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify non-zero sub-nanosecond Decimal delta preserves verbatim string end-to-end and 503 works cleanly."""
    _cleanup_demo_domains(live_driver, _ALL_DEMO_DOMAINS, ["demo-v2-tol-ns"])
    _configure_env_for_cli_and_app(monkeypatch, neo4j_test_config)

    zeek_file = tmp_path / "tol_conn.log.jsonl"
    eve_file = tmp_path / "tol_eve.jsonl"
    zeek_file.write_text(
        json.dumps(
            {
                "ts": 1795428000.000000000,
                "uid": "CDemoTolSubNs01",
                "id.orig_h": "192.0.2.200",
                "id.orig_p": 55111,
                "id.resp_h": "198.51.100.200",
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 5.000000000,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    eve_file.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-23T09:59:59.999999999877+0000",
                "flow_id": 8899001,
                "event_type": "alert",
                "src_ip": "192.0.2.200",
                "src_port": 55111,
                "dest_ip": "198.51.100.200",
                "dest_port": 443,
                "proto": "TCP",
                "alert": {"gid": 1, "signature_id": 9109001, "rev": 1, "signature": "SubNs Pre-Start"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    try:
        ingest_zeek_conn_file(
            zeek_file,
            sensor_id="zeek-tol-01",
            routing_domain_id=_TOL_DOMAIN,
            driver=live_driver,
        )
        ingest_suricata_eve_file(
            eve_file,
            sensor_id="suricata-tol-01",
            ruleset_namespace="demo-v2-tol-ns",
            log_source_id="tol-eve-01",
            routing_domain_id=_TOL_DOMAIN,
            driver=live_driver,
        )

        tol_policy = CorrelationPolicy(
            pre_start_tolerance_sec=Decimal("1"),
            allow_tolerance_match=True,
        )
        summary = run_alert_flow_correlation(
            policy=tol_policy,
            routing_domain_id=_TOL_DOMAIN,
            driver=live_driver,
        )
        assert summary.strong == 1
        assert summary.correlations_created == 1

        with TestClient(create_app()) as client:
            res = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": _TOL_DOMAIN},
            )
            assert res.status_code == 200
            items = res.json()["items"]
            assert len(items) == 1
            assert items[0]["temporal_relation"] == "WITHIN_PRE_TOLERANCE"
            assert isinstance(items[0]["temporal_delta_decimal"], str)
            assert items[0]["temporal_delta_decimal"] == "-0.000000000123"
            assert items[0]["used_decimal_fallback"] is True

        # Database unavailable (incomplete Neo4j env) returns HTTP 503 cleanly
        monkeypatch.delenv("NEO4J_URI", raising=False)
        monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
        with TestClient(create_app()) as unavail_client:
            unavail_res = unavail_client.get("/api/v1/correlations/alert-flows")
            assert unavail_res.status_code == 503
    finally:
        _cleanup_demo_domains(live_driver, [_TOL_DOMAIN], ["demo-v2-tol-ns"])
