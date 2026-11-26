"""
Live Neo4j 5.26 End-to-End Integration Validation for the Complete V2 Workflow (Phase 4E).

Exercises the entire real pipeline against a disposable local Neo4j instance:
  Synthetic Zeek conn.log JSONL + Suricata EVE JSONL
    -> real streaming parsers & V2 ingestion services/CLIs
    -> bounded keyset-paginated Phase 4A/4B correlation service
    -> Neo4j graph persistence & stale-edge reconciliation
    -> real FastAPI lifespan + read-only Phase 4C API endpoints

Safety Guarantees (Fail-Closed):
  - Strictly opt-in via RUN_NEO4J_INTEGRATION=1 and NEO4J_TEST_* environment variables.
  - Rejects any non-loopback NEO4J_TEST_URI host (allows only localhost, 127.0.0.1, ::1).
  - Isolates each test run inside unique per-run `demo-v2-*-<run_id>` RoutingDomains
    and ruleset namespaces, verifies zero pre-existing entities before writing, and
    never executes unconditional pre-test `DETACH DELETE` against shared domains.
  - Cleans up ONLY exact run-owned entity IDs in `try...finally`, preserving any
    unrelated entities or V1/V2 relationships.
"""

from __future__ import annotations

from decimal import Decimal
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse
import uuid

import pytest
from fastapi.testclient import TestClient
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from src.api.app import create_app
from src.correlation import CorrelationPolicy
from src.graph.correlation_repository import (
    AlertSelectionCursor,
    Neo4jCorrelationRepository,
)
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
_ZEEK_SENSOR = "zeek-demo-01"
_SURICATA_SENSOR = "suricata-demo-01"
_ALLOWED_NEO4J_SCHEMES = frozenset({"bolt", "neo4j", "bolt+s", "bolt+ssc", "neo4j+s", "neo4j+ssc"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_disposable_neo4j_uri(uri: str) -> str:
    """Validate that a Neo4j URI targets only a local loopback disposable endpoint.

    Never assumes a URI is disposable merely because its hostname contains 'test' or 'demo'.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise ValueError("NEO4J_TEST_URI must be a non-empty Bolt/Neo4j URI.")
    cleaned = uri.strip()
    parsed = urlparse(cleaned)

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_NEO4J_SCHEMES:
        raise ValueError(
            f"Unsupported NEO4J_TEST_URI scheme {parsed.scheme!r}. "
            f"Allowed schemes: {sorted(_ALLOWED_NEO4J_SCHEMES)}."
        )
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "NEO4J_TEST_URI must not contain embedded credentials; "
            "pass credentials via NEO4J_TEST_USERNAME and NEO4J_TEST_PASSWORD."
        )
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(
            f"Refusing to run integration tests against non-loopback Neo4j host "
            f"{parsed.hostname!r} (URI: {cleaned!r}). Only local loopback hosts "
            f"{sorted(_LOOPBACK_HOSTS)} are permitted."
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in NEO4J_TEST_URI {cleaned!r}: {exc}") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Out-of-range port in NEO4J_TEST_URI {cleaned!r}: {port}")

    return cleaned


def _make_run_scope() -> Dict[str, str]:
    """Generate unique per-test RoutingDomain and ruleset namespace identifiers."""
    tag = uuid.uuid4().hex[:8]
    return {
        "tag": tag,
        "corp_domain": f"demo-v2-corp-{tag}",
        "branch_domain": f"demo-v2-branch-{tag}",
        "tol_domain": f"demo-v2-tol-{tag}",
        "ruleset_ns": f"demo-v2-rules-{tag}",
        "tol_ns": f"demo-v2-tol-ns-{tag}",
    }


@pytest.fixture(scope="module")
def neo4j_test_config() -> Dict[str, str]:
    """Require explicit opt-in and validated local loopback NEO4J_TEST_* configuration."""
    if os.environ.get("RUN_NEO4J_INTEGRATION") != "1":
        pytest.skip("Live Neo4j integration tests disabled (set RUN_NEO4J_INTEGRATION=1 to enable)")

    uri = os.environ.get("NEO4J_TEST_URI")
    username = os.environ.get("NEO4J_TEST_USERNAME")
    password = os.environ.get("NEO4J_TEST_PASSWORD")
    if not uri or not username or not password:
        pytest.skip(
            "RUN_NEO4J_INTEGRATION=1 is set but NEO4J_TEST_* environment variables are incomplete"
        )
    try:
        validated_uri = validate_disposable_neo4j_uri(uri)
    except ValueError as exc:
        pytest.fail(f"Unsafe NEO4J_TEST_URI rejected: {exc}")
    return {"uri": validated_uri, "username": username, "password": password}


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


def _assert_domains_and_rulesets_clean(
    driver,
    domains: Iterable[str],
    ruleset_namespaces: Iterable[str],
) -> None:
    """Fail closed if any pre-existing entity occupies the run-scoped domains/namespaces."""
    dom_list = list(domains)
    ns_list = list(ruleset_namespaces)
    with driver.session() as session:
        rec = session.run(
            "OPTIONAL MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
            "WITH count(ae) AS ae_cnt "
            "OPTIONAL MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
            "WITH ae_cnt, count(fo) AS fo_cnt "
            "OPTIONAL MATCH (ip:IPAddress) WHERE ip.routing_domain_id IN $doms "
            "  OR ANY(d IN $doms WHERE ip.scoped_id STARTS WITH (d + '#')) "
            "WITH ae_cnt, fo_cnt, count(ip) AS ip_cnt "
            "OPTIONAL MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
            "WITH ae_cnt, fo_cnt, ip_cnt, count(rd) AS rd_cnt "
            "OPTIONAL MATCH (ad:AlertDefinition) WHERE ad.ruleset_namespace IN $nss "
            "RETURN ae_cnt, fo_cnt, ip_cnt, rd_cnt, count(ad) AS ad_cnt",
            doms=dom_list,
            nss=ns_list,
        ).single()
        existing = {
            "AlertEvent": int(rec["ae_cnt"]),
            "FlowObservation": int(rec["fo_cnt"]),
            "IPAddress": int(rec["ip_cnt"]),
            "RoutingDomain": int(rec["rd_cnt"]),
            "AlertDefinition": int(rec["ad_cnt"]),
        }
        non_zero = {k: v for k, v in existing.items() if v > 0}
        if non_zero:
            raise RuntimeError(
                f"Refusing to overwrite pre-existing entities in target domains={dom_list} "
                f"or rulesets={ns_list}: {non_zero}"
            )


def _collect_owned_ids(
    *,
    flows: Iterable[Any] = (),
    alerts: Iterable[Any] = (),
    domains: Iterable[str] = (),
) -> Dict[str, List[str]]:
    """Derive exact deterministic entity IDs from parsed records for owned-only cleanup."""
    scoped_ids: Set[str] = set()
    obs_ids: Set[str] = set()
    event_ids: Set[str] = set()
    def_ids: Set[str] = set()

    for flow in flows:
        obs_ids.add(flow.observation_id)
        scoped_ids.add(flow.src_scoped_id)
        scoped_ids.add(flow.dst_scoped_id)
    for alert in alerts:
        event_ids.add(alert.event_id)
        def_ids.add(alert.alert_definition_id)
        scoped_ids.add(alert.src_scoped_id)
        scoped_ids.add(alert.dst_scoped_id)

    return {
        "event_ids": sorted(event_ids),
        "obs_ids": sorted(obs_ids),
        "def_ids": sorted(def_ids),
        "scoped_ids": sorted(scoped_ids),
        "domain_ids": sorted(set(domains)),
    }


def _cleanup_owned_entities(
    driver,
    *,
    event_ids: Iterable[str] = (),
    obs_ids: Iterable[str] = (),
    def_ids: Iterable[str] = (),
    scoped_ids: Iterable[str] = (),
    domain_ids: Iterable[str] = (),
) -> None:
    """Safely remove ONLY exact synthetic entities owned by this test run."""
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


def _snapshot_demo_graph(
    driver,
    domains: List[str],
    ruleset_namespaces: List[str],
) -> Dict[str, Any]:
    """Capture owned entity digests, counts, CORRELATED_WITH properties, and schema metadata."""
    with driver.session() as session:
        flow_digests = [
            (str(rec["oid"]), rec["digest"])
            for rec in session.run(
                "MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
                "RETURN fo.observation_id AS oid, fo.payload_digest AS digest "
                "ORDER BY fo.observation_id ASC",
                doms=domains,
            )
        ]
        alert_digests = [
            (str(rec["eid"]), rec["digest"])
            for rec in session.run(
                "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS eid, ae.payload_digest AS digest "
                "ORDER BY ae.event_id ASC",
                doms=domains,
            )
        ]
        def_ids = [
            str(rec["did"])
            for rec in session.run(
                "MATCH (ad:AlertDefinition) WHERE ad.ruleset_namespace IN $nss "
                "RETURN ad.definition_id AS did ORDER BY ad.definition_id ASC",
                nss=ruleset_namespaces,
            )
        ]
        ip_scoped_ids = [
            str(rec["sid"])
            for rec in session.run(
                "MATCH (ip:IPAddress) WHERE ip.routing_domain_id IN $doms "
                "RETURN ip.scoped_id AS sid ORDER BY ip.scoped_id ASC",
                doms=domains,
            )
        ]
        domain_ids = [
            str(rec["dom"])
            for rec in session.run(
                "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
                "RETURN rd.domain_id AS dom ORDER BY rd.domain_id ASC",
                doms=domains,
            )
        ]
        rels = [
            (str(rec["event_id"]), str(rec["observation_id"]), dict(rec["props"]))
            for rec in session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS event_id, fo.observation_id AS observation_id, "
                "       properties(r) AS props "
                "ORDER BY ae.event_id ASC, fo.observation_id ASC",
                doms=domains,
            )
        ]
        constraints = sorted(
            str(rec["name"]) for rec in session.run("SHOW CONSTRAINTS YIELD name")
        )
        indexes = sorted(
            str(rec["name"]) for rec in session.run("SHOW INDEXES YIELD name")
        )

        return {
            "counts": (len(flow_digests), len(alert_digests), len(rels)),
            "flow_digests": flow_digests,
            "alert_digests": alert_digests,
            "def_ids": def_ids,
            "ip_scoped_ids": ip_scoped_ids,
            "domain_ids": domain_ids,
            "rels": rels,
            "constraints": constraints,
            "indexes": indexes,
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
    """Scenarios A-D + strict keyset pagination + idempotency + real FastAPI lifespan verification."""
    scope = _make_run_scope()
    corp_domain = scope["corp_domain"]
    branch_domain = scope["branch_domain"]
    ruleset_ns = scope["ruleset_ns"]

    _assert_domains_and_rulesets_clean(live_driver, [corp_domain, branch_domain], [ruleset_ns])
    _configure_env_for_cli_and_app(monkeypatch, neo4j_test_config)

    # Pre-compute exact deterministic entity IDs via real parsers before mutating Neo4j
    corp_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=corp_domain,
        source_provenance="phase4e-corp-zeek",
    )
    corp_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "corp_eve.jsonl",
        sensor_id=_SURICATA_SENSOR,
        ruleset_namespace=ruleset_ns,
        log_source_id="corp-eve-demo-01",
        routing_domain_id=corp_domain,
        source_provenance="phase4e-corp-eve",
    )
    branch_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "branch_conn.log.jsonl",
        sensor_id="zeek-branch-01",
        routing_domain_id=branch_domain,
        source_provenance="phase4e-branch-zeek",
    )
    branch_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "branch_eve.jsonl",
        sensor_id="suricata-branch-01",
        ruleset_namespace=ruleset_ns,
        log_source_id="branch-eve-demo-01",
        routing_domain_id=branch_domain,
        source_provenance="phase4e-branch-eve",
    )
    owned = _collect_owned_ids(
        flows=corp_flows + branch_flows,
        alerts=corp_alerts + branch_alerts,
        domains=[corp_domain, branch_domain],
    )

    alert_a = next(a for a in corp_alerts if a.sid == 9100001)
    alert_b = next(a for a in corp_alerts if a.sid == 9100002)
    alert_c1 = next(a for a in corp_alerts if a.sid == 9100003)
    alert_d = next(a for a in corp_alerts if a.sid == 9100004)
    alert_ef = next(a for a in corp_alerts if a.sid == 9100005)
    flow_a = next(f for f in corp_flows if f.zeek_uid == "CDemoCorpStrong01")

    try:
        # 1. Real parser-to-Neo4j ingestion for corp_domain
        corp_zeek_res = ingest_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=corp_domain,
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
            ruleset_namespace=ruleset_ns,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=corp_domain,
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

        # 2. Real CLI entrypoints for branch_domain using disposable env vars
        assert (
            zeek_cli_main(
                [
                    "--file",
                    str(_DEMO_DIR / "branch_conn.log.jsonl"),
                    "--sensor-id",
                    "zeek-branch-01",
                    "--routing-domain-id",
                    branch_domain,
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
                    ruleset_ns,
                    "--log-source-id",
                    "branch-eve-demo-01",
                    "--routing-domain-id",
                    branch_domain,
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

        # 4a. Directly verify keyset page ordering places NULL-ns Alert A (inserted FIRST) on Page 3
        corr_repo = Neo4jCorrelationRepository(live_driver)
        p1 = corr_repo.list_correlatable_alert_page(
            routing_domain_id=corp_domain, max_alerts=2, after_cursor=None
        )
        assert p1.event_ids == (alert_b.event_id, alert_c1.event_id)
        assert p1.has_more is True
        assert p1.next_cursor == AlertSelectionCursor(1795428125_000000000, alert_c1.event_id)

        p2 = corr_repo.list_correlatable_alert_page(
            routing_domain_id=corp_domain, max_alerts=2, after_cursor=p1.next_cursor
        )
        assert p2.event_ids == (alert_d.event_id, alert_ef.event_id)
        assert p2.has_more is True
        assert p2.next_cursor == AlertSelectionCursor(1795428505_000000000, alert_ef.event_id)

        p3 = corr_repo.list_correlatable_alert_page(
            routing_domain_id=corp_domain, max_alerts=2, after_cursor=p2.next_cursor
        )
        assert p3.event_ids == (alert_a.event_id,)
        assert p3.has_more is False
        assert p3.next_cursor is None

        # 4b. Bounded keyset-paginated Phase 4B correlation for corp_domain (max_alerts=2)
        policy = CorrelationPolicy()
        corp_pages = []
        cursor = None
        while True:
            page = run_alert_flow_correlation(
                policy=policy,
                routing_domain_id=corp_domain,
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

        assert len(corp_pages) == 3
        assert [p.alerts_evaluated for p in corp_pages] == [2, 2, 1]
        # Page 1: Alert B (AMBIGUOUS) + Alert C1 (STRONG)
        assert (
            corp_pages[0].strong,
            corp_pages[0].ambiguous,
            corp_pages[0].rejected,
            corp_pages[0].correlations_created,
        ) == (1, 1, 0, 1)
        assert corp_pages[0].next_cursor == AlertSelectionCursor(
            1795428125_000000000, alert_c1.event_id
        )
        # Page 2: Alert D (REJECTED) + Alert EF (STRONG)
        assert (
            corp_pages[1].strong,
            corp_pages[1].ambiguous,
            corp_pages[1].rejected,
            corp_pages[1].correlations_created,
        ) == (1, 0, 1, 1)
        assert corp_pages[1].next_cursor == AlertSelectionCursor(
            1795428505_000000000, alert_ef.event_id
        )
        # Page 3: NULL-ns Alert A (STRONG) evaluated last despite being line 1 of corp_eve.jsonl
        assert (
            corp_pages[2].strong,
            corp_pages[2].ambiguous,
            corp_pages[2].rejected,
            corp_pages[2].correlations_created,
        ) == (1, 0, 0, 1)
        assert corp_pages[2].has_more is False
        assert corp_pages[2].next_cursor is None

        # Run branch domain via CLI entrypoint cleanly
        assert (
            correlation_cli_main(
                ["--routing-domain-id", branch_domain, "--max-alerts", "10", "--batch-size", "10"]
            )
            == 0
        )

        # 5. Verify persisted Cypher graph state
        with live_driver.session() as session:
            cross_domain_cnt = session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms AND ae.routing_domain_id <> fo.routing_domain_id "
                "RETURN count(r) AS cnt",
                doms=[corp_domain, branch_domain],
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
                doms=[corp_domain, branch_domain],
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

        snapshot_before_repeat = _snapshot_demo_graph(
            live_driver, [corp_domain, branch_domain], [ruleset_ns]
        )
        assert snapshot_before_repeat["counts"] == (8, 7, 4)

        # 6. Idempotency: repeat ingestion & repeat correlation produce zero duplicate nodes/edges
        repeat_zeek = ingest_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=corp_domain,
            source_provenance="phase4e-corp-zeek",
            driver=live_driver,
        )
        assert repeat_zeek.persistence_summary.created_count == 0
        assert repeat_zeek.persistence_summary.duplicate_matched_count == 7

        repeat_suri = ingest_suricata_eve_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=ruleset_ns,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=corp_domain,
            source_provenance="phase4e-corp-eve",
            driver=live_driver,
        )
        assert repeat_suri.persistence_summary.created_count == 0
        assert repeat_suri.persistence_summary.duplicate_matched_count == 5

        repeat_corr = run_alert_flow_correlation(
            policy=policy,
            routing_domain_id=corp_domain,
            driver=live_driver,
        )
        assert repeat_corr.correlations_created == 0
        assert repeat_corr.correlations_unchanged == 3
        assert repeat_corr.correlations_updated == 0
        assert repeat_corr.stale_correlations_removed == 0

        snapshot_after_repeat = _snapshot_demo_graph(
            live_driver, [corp_domain, branch_domain], [ruleset_ns]
        )
        assert snapshot_after_repeat == snapshot_before_repeat

        # 7. Real FastAPI app + lifespan against live disposable Neo4j
        with TestClient(create_app()) as client:
            health_res = client.get("/health")
            assert health_res.status_code == 200
            assert health_res.json()["status"] == "ok"

            ready_res = client.get("/ready")
            assert ready_res.status_code == 200
            assert ready_res.json() == {"status": "ready", "database": "connected"}

            corp_api = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": corp_domain},
            )
            assert corp_api.status_code == 200
            corp_body = corp_api.json()
            assert corp_body["total"] == 3
            assert all(item["verification_status"] == "verified" for item in corp_body["items"])
            assert all(item["routing_domain_id"] == corp_domain for item in corp_body["items"])

            # Verify exact string Decimal delta on Scenario A item
            strong_api_item = next(
                item for item in corp_body["items"] if item["event_id"] == alert_a.event_id
            )
            assert strong_api_item["zeek_uid"] == "CDemoCorpStrong01"
            assert isinstance(strong_api_item["temporal_delta_decimal"], str)
            assert strong_api_item["temporal_delta_decimal"] == "0"
            assert strong_api_item["used_decimal_fallback"] is True

            # Branch isolation & observation_id filter check
            branch_api = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": branch_domain},
            )
            assert branch_api.status_code == 200
            assert branch_api.json()["total"] == 1
            assert branch_api.json()["items"][0]["observation_id"] == branch_flows[0].observation_id

            obs_filtered = client.get(
                "/api/v1/correlations/alert-flows",
                params={"observation_id": flow_a.observation_id},
            )
            assert obs_filtered.status_code == 200
            assert obs_filtered.json()["total"] == 1
            assert obs_filtered.json()["items"][0]["event_id"] == alert_a.event_id

            # Pagination across corp items (limit=2, offset=2)
            page1 = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": corp_domain, "limit": 2, "offset": 0},
            ).json()
            page2 = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": corp_domain, "limit": 2, "offset": 2},
            ).json()
            assert page1["total"] == 3 and len(page1["items"]) == 2
            assert page2["total"] == 3 and len(page2["items"]) == 1

            # Existing non-correlated AlertEvent -> HTTP 200 empty; missing AlertEvent -> HTTP 404
            empty_alert_res = client.get(
                f"/api/v1/correlations/alert-flows/{alert_d.event_id}",
                params={"routing_domain_id": corp_domain},
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
                params={"routing_domain_id": branch_domain},
            )
            assert branch_empty_res.status_code == 200
            assert branch_empty_res.json()["total"] == 0

            # Phase 4F.1 Scenario A detail endpoints -> exact persisted Suricata AlertEvent & Zeek FlowObservation
            alert_detail_res = client.get(
                f"/api/v1/alert-events/{alert_a.event_id}",
                params={"routing_domain_id": corp_domain},
            )
            assert alert_detail_res.status_code == 200
            alert_detail = alert_detail_res.json()
            assert alert_detail["event_id"] == alert_a.event_id
            assert alert_detail["routing_domain_id"] == corp_domain
            assert alert_detail["source_type"] == "suricata"
            assert alert_detail["engine"] == "suricata"
            assert alert_detail["sid"] == 9100001
            assert alert_detail["signature"] == "SYNTHETIC Demo Strong Match TLS Observation"
            assert alert_detail["src_ip"] == "192.0.2.10"
            assert alert_detail["src_port"] == 54321
            assert alert_detail["dst_ip"] == "198.51.100.20"
            assert alert_detail["dst_port"] == 443
            assert alert_detail["flow_id"] == "8810001"
            assert isinstance(alert_detail["timestamp_epoch_decimal"], str)
            assert alert_detail["timestamp_epoch_decimal"] == "1795428002.123456789123"
            assert "timestamp_epoch_ns" not in alert_detail

            flow_detail_res = client.get(
                f"/api/v1/flow-observations/{flow_a.observation_id}",
                params={"routing_domain_id": corp_domain},
            )
            assert flow_detail_res.status_code == 200
            flow_detail = flow_detail_res.json()
            assert flow_detail["observation_id"] == flow_a.observation_id
            assert flow_detail["zeek_uid"] == "CDemoCorpStrong01"
            assert flow_detail["routing_domain_id"] == corp_domain
            assert flow_detail["source_type"] == "zeek"
            assert flow_detail["start_epoch_decimal"] == "1795428000.123456789"
            assert flow_detail["duration_decimal"] == "10"
            assert flow_detail["orig_bytes"] == 640
            assert flow_detail["resp_bytes"] == 2400
            assert flow_detail["orig_ip_bytes"] == 928
            assert flow_detail["resp_ip_bytes"] == 2736
            assert flow_detail["conn_state"] == "SF"
            assert flow_detail["service"] == "ssl"
            assert "start_epoch_ns" not in flow_detail
            assert "end_epoch_ns" not in flow_detail

            # Cross-domain wrong-scope checks fail closed with HTTP 404
            wrong_domain_alert = client.get(
                f"/api/v1/alert-events/{alert_a.event_id}",
                params={"routing_domain_id": branch_domain},
            )
            assert wrong_domain_alert.status_code == 404

            wrong_domain_flow = client.get(
                f"/api/v1/flow-observations/{flow_a.observation_id}",
                params={"routing_domain_id": branch_domain},
            )
            assert wrong_domain_flow.status_code == 404

        # Confirm zero observable graph or schema mutations occurred during GET requests
        assert (
            _snapshot_demo_graph(live_driver, [corp_domain, branch_domain], [ruleset_ns])
            == snapshot_before_repeat
        )
    finally:
        _cleanup_owned_entities(live_driver, **owned)


def test_e2e_02_verification_lifecycle_and_stale_reconciliation(
    live_driver,
    neo4j_test_config: Dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
):
    """Scenarios E & F: incomplete reevaluation preserves edge as unverified_incomplete; complete removal deletes stale edge."""
    scope = _make_run_scope()
    corp_domain = scope["corp_domain"]
    ruleset_ns = scope["ruleset_ns"]

    _assert_domains_and_rulesets_clean(live_driver, [corp_domain], [ruleset_ns])
    _configure_env_for_cli_and_app(monkeypatch, neo4j_test_config)

    corp_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=corp_domain,
        source_provenance="phase4e-corp-zeek",
    )
    rival_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_stale_rival_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=corp_domain,
        source_provenance="phase4e-corp-rival-zeek",
    )
    corp_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "corp_eve.jsonl",
        sensor_id=_SURICATA_SENSOR,
        ruleset_namespace=ruleset_ns,
        log_source_id="corp-eve-demo-01",
        routing_domain_id=corp_domain,
        source_provenance="phase4e-corp-eve",
    )
    owned = _collect_owned_ids(
        flows=corp_flows + rival_flows,
        alerts=corp_alerts,
        domains=[corp_domain],
    )
    alert_ef = next(a for a in corp_alerts if a.sid == 9100005)

    try:
        ingest_zeek_conn_file(
            _DEMO_DIR / "corp_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=corp_domain,
            source_provenance="phase4e-corp-zeek",
            driver=live_driver,
        )
        ingest_suricata_eve_file(
            _DEMO_DIR / "corp_eve.jsonl",
            sensor_id=_SURICATA_SENSOR,
            ruleset_namespace=ruleset_ns,
            log_source_id="corp-eve-demo-01",
            routing_domain_id=corp_domain,
            source_provenance="phase4e-corp-eve",
            driver=live_driver,
        )

        initial = run_alert_flow_correlation(
            routing_domain_id=corp_domain,
            driver=live_driver,
        )
        assert initial.correlations_created == 3

        # Scenario E: ingest competing rival flow and trigger truncated candidate lookup (candidate_cap=1)
        rival_ingest = ingest_zeek_conn_file(
            _DEMO_DIR / "corp_stale_rival_conn.log.jsonl",
            sensor_id=_ZEEK_SENSOR,
            routing_domain_id=corp_domain,
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
                params={"routing_domain_id": corp_domain},
            ).json()
            assert default_list["total"] == 2
            assert all(item["event_id"] != alert_ef.event_id for item in default_list["items"])

            detail_default = client.get(
                f"/api/v1/correlations/alert-flows/{alert_ef.event_id}",
                params={"routing_domain_id": corp_domain},
            )
            assert detail_default.status_code == 200
            assert detail_default.json()["total"] == 0

            # Explicit include_unverified=true reveals it with factual reason & timestamp
            unverified_res = client.get(
                f"/api/v1/correlations/alert-flows/{alert_ef.event_id}",
                params={"routing_domain_id": corp_domain, "include_unverified": "true"},
            )
            assert unverified_res.status_code == 200
            unverified_items = unverified_res.json()["items"]
            assert len(unverified_items) == 1
            assert unverified_items[0]["verification_status"] == "unverified_incomplete"
            assert unverified_items[0]["last_incomplete_reason"] == "CANDIDATE_SET_TRUNCATED"
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
                params={"routing_domain_id": corp_domain, "include_unverified": "true"},
            )
            assert after_removal.status_code == 200
            assert after_removal.json()["items"] == []
            assert after_removal.json()["total"] == 0
    finally:
        _cleanup_owned_entities(live_driver, **owned)


def test_e2e_03_subnanosecond_decimal_delta_and_db_unavailable_503(
    live_driver,
    neo4j_test_config: Dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verify non-zero sub-nanosecond Decimal delta preserves verbatim string end-to-end and 503 works cleanly."""
    scope = _make_run_scope()
    tol_domain = scope["tol_domain"]
    tol_ns = scope["tol_ns"]

    _assert_domains_and_rulesets_clean(live_driver, [tol_domain], [tol_ns])
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

    tol_flows, _ = parse_zeek_conn_file(
        zeek_file, sensor_id="zeek-tol-01", routing_domain_id=tol_domain
    )
    tol_alerts, _ = parse_suricata_eve_alert_file(
        eve_file,
        sensor_id="suricata-tol-01",
        ruleset_namespace=tol_ns,
        log_source_id="tol-eve-01",
        routing_domain_id=tol_domain,
    )
    owned = _collect_owned_ids(flows=tol_flows, alerts=tol_alerts, domains=[tol_domain])

    try:
        ingest_zeek_conn_file(
            zeek_file,
            sensor_id="zeek-tol-01",
            routing_domain_id=tol_domain,
            driver=live_driver,
        )
        ingest_suricata_eve_file(
            eve_file,
            sensor_id="suricata-tol-01",
            ruleset_namespace=tol_ns,
            log_source_id="tol-eve-01",
            routing_domain_id=tol_domain,
            driver=live_driver,
        )

        tol_policy = CorrelationPolicy(
            pre_start_tolerance_sec=Decimal("1"),
            allow_tolerance_match=True,
        )
        summary = run_alert_flow_correlation(
            policy=tol_policy,
            routing_domain_id=tol_domain,
            driver=live_driver,
        )
        assert summary.strong == 1
        assert summary.correlations_created == 1

        with TestClient(create_app()) as client:
            res = client.get(
                "/api/v1/correlations/alert-flows",
                params={"routing_domain_id": tol_domain},
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
            assert unavail_client.get(f"/api/v1/alert-events/{tol_alerts[0].event_id}").status_code == 503
            assert unavail_client.get(f"/api/v1/flow-observations/{tol_flows[0].observation_id}").status_code == 503
    finally:
        _cleanup_owned_entities(live_driver, **owned)


def test_e2e_04_owned_cleanup_and_preflight_collision_safety(live_driver):
    """Verify pre-flight refuses pre-existing domain data and owned cleanup preserves unrelated V1/V2 edges."""
    scope = _make_run_scope()
    domain = scope["branch_domain"]
    ruleset_ns = scope["ruleset_ns"]

    _assert_domains_and_rulesets_clean(live_driver, [domain], [ruleset_ns])

    branch_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "branch_conn.log.jsonl",
        sensor_id="zeek-branch-01",
        routing_domain_id=domain,
        source_provenance="phase4e-cleanup-zeek",
    )
    branch_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "branch_eve.jsonl",
        sensor_id="suricata-branch-01",
        ruleset_namespace=ruleset_ns,
        log_source_id="branch-eve-cleanup-01",
        routing_domain_id=domain,
        source_provenance="phase4e-cleanup-eve",
    )
    owned = _collect_owned_ids(flows=branch_flows, alerts=branch_alerts, domains=[domain])
    shared_src_scoped = branch_flows[0].src_scoped_id
    shared_dst_scoped = branch_flows[0].dst_scoped_id
    foreign_flow_key = f"foreign-v1-flow-{scope['tag']}"

    try:
        ingest_zeek_conn_file(
            _DEMO_DIR / "branch_conn.log.jsonl",
            sensor_id="zeek-branch-01",
            routing_domain_id=domain,
            source_provenance="phase4e-cleanup-zeek",
            driver=live_driver,
        )
        ingest_suricata_eve_file(
            _DEMO_DIR / "branch_eve.jsonl",
            sensor_id="suricata-branch-01",
            ruleset_namespace=ruleset_ns,
            log_source_id="branch-eve-cleanup-01",
            routing_domain_id=domain,
            source_provenance="phase4e-cleanup-eve",
            driver=live_driver,
        )

        # Pre-flight collision check must fail closed when domain already contains entities
        with pytest.raises(RuntimeError, match="Refusing to overwrite pre-existing entities"):
            _assert_domains_and_rulesets_clean(live_driver, [domain], [ruleset_ns])

        # Attach an unrelated V1 COMMUNICATED_TO edge to the shared IPAddress pair
        with live_driver.session() as session:
            session.run(
                "MATCH (a:IPAddress {scoped_id: $src}), (b:IPAddress {scoped_id: $dst}) "
                "MERGE (a)-[:COMMUNICATED_TO {flow_key: $fk, protocol: 'TCP'}]->(b)",
                src=shared_src_scoped,
                dst=shared_dst_scoped,
                fk=foreign_flow_key,
            ).consume()

        # Run owned cleanup: must remove V2 FlowObservation/AlertEvent/AlertDefinition
        # while PRESERVING the IPAddresses, COMMUNICATED_TO edge, and RoutingDomain.
        _cleanup_owned_entities(live_driver, **owned)

        with live_driver.session() as session:
            preserved = session.run(
                "MATCH (a:IPAddress {scoped_id: $src})-[c:COMMUNICATED_TO {flow_key: $fk}]->"
                "(b:IPAddress {scoped_id: $dst}) "
                "OPTIONAL MATCH (rd:RoutingDomain {domain_id: $dom}) "
                "OPTIONAL MATCH (fo:FlowObservation) WHERE fo.observation_id IN $oids "
                "OPTIONAL MATCH (ae:AlertEvent) WHERE ae.event_id IN $eids "
                "RETURN count(c) AS comm_cnt, count(rd) AS rd_cnt, "
                "       count(fo) AS fo_cnt, count(ae) AS ae_cnt",
                src=shared_src_scoped,
                dst=shared_dst_scoped,
                fk=foreign_flow_key,
                dom=domain,
                oids=owned["obs_ids"],
                eids=owned["event_ids"],
            ).single()
            assert preserved["comm_cnt"] == 1
            assert preserved["rd_cnt"] == 1
            assert preserved["fo_cnt"] == 0
            assert preserved["ae_cnt"] == 0
    finally:
        # Remove the synthetic V1 edge, then re-run owned cleanup to leave zero residual nodes
        with live_driver.session() as session:
            session.run(
                "MATCH (:IPAddress)-[c:COMMUNICATED_TO {flow_key: $fk}]->(:IPAddress) DELETE c",
                fk=foreign_flow_key,
            ).consume()
        _cleanup_owned_entities(live_driver, **owned)
