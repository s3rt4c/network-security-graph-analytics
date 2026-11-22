"""
Live Neo4j 5.26 integration tests for Phase 4B Zeek-Suricata Correlation
Retrieval, Safe Persistence, and Stale Correlation Reconciliation.

Strictly opt-in via RUN_NEO4J_INTEGRATION=1 with explicit NEO4J_TEST_* credentials.
Exercises scenarios A through T against disposable Neo4j without mocking database logic.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple
import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable

from src.correlation import (
    CommunityIdSeedPolicy,
    CorrelationPolicy,
    CorrelationStatus,
    SensorPairingPolicy,
    TemporalRelation,
    TupleOrientation,
)
from src.graph.correlation_repository import (
    CYPHER_RETRIEVE_CANDIDATES_BY_CID,
    CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS,
    VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE,
    VERIFICATION_STATUS_VERIFIED,
    AlertSelectionCursor,
    Neo4jCorrelationRepository,
)
from src.graph.repository import Neo4jRepository
from src.graph.schema import MigrationRequiredError, SchemaNotReadyError, ensure_schema
from src.ingestion.community_id import compute_community_id
from src.ingestion.models import AlertRecord, TrafficRecord
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    ZeekConnectionObservation,
    alert_definition_id,
    compute_alert_event_id,
    compute_observation_id,
    compute_v2_flow_key,
    scoped_ip_id,
)
from src.services.correlation_service import run_alert_flow_correlation

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def live_driver():
    """Connect to live test Neo4j instance only when RUN_NEO4J_INTEGRATION=1 is set."""
    if os.environ.get("RUN_NEO4J_INTEGRATION") != "1":
        pytest.skip("Live Neo4j integration tests disabled (set RUN_NEO4J_INTEGRATION=1 to enable)")

    test_uri = os.environ.get("NEO4J_TEST_URI")
    test_user = os.environ.get("NEO4J_TEST_USERNAME")
    test_pass = os.environ.get("NEO4J_TEST_PASSWORD")

    if not test_uri or not test_user or not test_pass:
        pytest.skip(
            "RUN_NEO4J_INTEGRATION=1 is set but NEO4J_TEST_* environment variables are incomplete"
        )

    driver = None
    try:
        driver = GraphDatabase.driver(test_uri, auth=(test_user, test_pass))
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError, Exception) as exc:
        if driver is not None:
            driver.close()
        pytest.fail(f"Failed to connect to test Neo4j instance at {test_uri}: {exc}")

    ensure_schema(driver)
    yield driver

    if driver is not None:
        driver.close()


def _cleanup_test_entities(
    driver,
    *,
    event_ids: Iterable[str] = (),
    obs_ids: Iterable[str] = (),
    def_ids: Iterable[str] = (),
    scoped_ids: Iterable[str] = (),
    domain_ids: Iterable[str] = (),
) -> None:
    with driver.session() as session:
        e_list = list(event_ids)
        o_list = list(obs_ids)
        d_list = list(def_ids)
        s_list = list(scoped_ids)
        dom_list = list(domain_ids)

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
                "AND NOT ((ip)--(:AlertFact)) "
                "AND NOT ((:FlowObservation)-->(ip)) "
                "AND NOT ((:AlertEvent)-->(ip)) "
                "DETACH DELETE ip",
                sids=s_list,
            ).consume()
        if dom_list:
            session.run(
                "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
                "AND NOT ((:IPAddress)-[:IN_DOMAIN]->(rd)) DETACH DELETE rd",
                doms=dom_list,
            ).consume()


def _make_flow(
    *,
    tag: str,
    domain: str,
    sensor_id: str = "zeek-4b",
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    protocol: str = "TCP",
    src_port: Optional[int] = 54321,
    dst_port: Optional[int] = 443,
    community_id: Optional[str] = None,
    use_default_cid: bool = True,
    start_epoch: Optional[Decimal] = Decimal("1795200100.000000"),
    end_epoch: Optional[Decimal] = Decimal("1795200120.000000"),
    duration: Optional[Decimal] = Decimal("20.000000"),
    source_type: str = "zeek",
) -> ZeekConnectionObservation:
    norm_dom = domain.strip().lower()
    src_scoped = scoped_ip_id(norm_dom, src_ip)
    dst_scoped = scoped_ip_id(norm_dom, dst_ip)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, protocol, src_port, dst_port)
    start_ts = "1795200100.000000" if start_epoch is None else str(start_epoch)
    zeek_uid = f"CZ4B_{tag}"
    obs_id = compute_observation_id(
        source_type=source_type,
        sensor_id=sensor_id,
        source_record_id=zeek_uid,
        timestamp=start_ts,
        flow_key=fk,
        source_provenance=f"it-4b-{tag}",
    )
    cid = community_id
    if cid is None and use_default_cid:
        cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return ZeekConnectionObservation(
        observation_id=obs_id,
        flow_key=fk,
        zeek_uid=zeek_uid,
        routing_domain_id=norm_dom,
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        start_ts=start_ts,
        src_port=src_port,
        dst_port=dst_port,
        community_id=cid,
        start_epoch=start_epoch,
        duration=duration,
        end_epoch=end_epoch,
        end_ts=None if end_epoch is None else str(end_epoch),
        sensor_id=sensor_id.strip().lower(),
        source_type=source_type,
        source_provenance=f"it-4b-{tag}",
    )


def _make_alert(
    *,
    tag: str,
    domain: str,
    sensor_id: str = "suricata-4b",
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    protocol: Optional[str] = "TCP",
    src_port: Optional[int] = 54321,
    dst_port: Optional[int] = 443,
    community_id: Optional[str] = None,
    use_default_cid: bool = True,
    timestamp_source: str = "2026-11-20T18:41:50.000000+0000",
    timestamp_epoch_decimal: Optional[Decimal] = Decimal("1795200110.000000"),
    sid: int = 4001001,
    source_type: str = "suricata",
) -> SuricataAlertObservation:
    norm_dom = domain.strip().lower()
    src_scoped = scoped_ip_id(norm_dom, src_ip)
    dst_scoped = scoped_ip_id(norm_dom, dst_ip)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, protocol or "UNKNOWN", src_port, dst_port)
    def_id = alert_definition_id(source_type, "it-4b-ns", 1, sid)
    ev_id = compute_alert_event_id(
        source_type=source_type,
        sensor_id=sensor_id,
        source_record_id=f"eve:4b:{tag}",
        timestamp=timestamp_source,
        def_id=def_id,
        flow_reference=fk,
    )
    cid = community_id
    if cid is None and use_default_cid and protocol is not None:
        cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return SuricataAlertObservation(
        event_id=ev_id,
        alert_definition_id=def_id,
        source_record_id=f"eve:4b:{tag}",
        log_source_id="it-4b-eve",
        sensor_id=sensor_id.strip().lower(),
        ruleset_namespace="it-4b-ns",
        routing_domain_id=norm_dom,
        flow_key=fk,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        timestamp_source=timestamp_source,
        timestamp_epoch_decimal=timestamp_epoch_decimal,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        flow_id=900001,
        community_id=cid,
        gid=1,
        sid=sid,
        rev=1,
        signature="SYNTHETIC Phase 4B Rule",
        severity=2,
        source_type=source_type,
        source_provenance=f"it-4b-{tag}",
    )


def _collect_plan_operators(plan_node: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(plan_node, dict):
        return []
    ops: List[str] = []
    op = plan_node.get("operatorType")
    if isinstance(op, str):
        ops.append(op)
    for child in plan_node.get("children") or []:
        ops.extend(_collect_plan_operators(child))
    return ops


def _edge_rows(driver, event_id: str) -> List[Dict[str, Any]]:
    with driver.session() as session:
        res = session.run(
            "MATCH (ae:AlertEvent {event_id: $eid})-[r:CORRELATED_WITH]->(fo:FlowObservation) "
            "RETURN elementId(r) AS rel_id, fo.observation_id AS observation_id, properties(r) AS props "
            "ORDER BY fo.observation_id ASC",
            eid=event_id,
        )
        return [{"rel_id": r["rel_id"], "observation_id": r["observation_id"], "props": dict(r["props"])} for r in res]


def _seed(live_driver, alerts: List[SuricataAlertObservation], flows: List[ZeekConnectionObservation]) -> None:
    repo = Neo4jRepository(live_driver)
    if flows:
        repo.write_zeek_observations(flows)
    if alerts:
        repo.write_suricata_alert_events(alerts)


# ---------------------------------------------------------------------------
# Tests A - T (All 20 Mandatory Live Neo4j Scenarios)
# ---------------------------------------------------------------------------

def test_a_unique_forward_tcp_and_query_plan(live_driver):
    """TEST A: Forward TCP correlation, zero inverse edge, immutable nodes untouched, and EXPLAIN plan check."""
    dom = "it-4b-a"
    a = _make_alert(tag="a", domain=dom)
    f = _make_flow(tag="a", domain=dom)
    _seed(live_driver, [a], [f])

    try:
        # Verify EXPLAIN query plans for Path A and Path B use indexes with zero Cartesian/AllNodesScan
        with live_driver.session() as session:
            pre_ae_digest = session.run(
                "MATCH (ae:AlertEvent {event_id: $eid}) RETURN ae.payload_digest AS d",
                eid=a.event_id,
            ).single()["d"]
            pre_fo_digest = session.run(
                "MATCH (fo:FlowObservation {observation_id: $oid}) RETURN fo.payload_digest AS d",
                oid=f.observation_id,
            ).single()["d"]

            plan_a = session.run(
                "EXPLAIN " + CYPHER_RETRIEVE_CANDIDATES_BY_CID,
                community_id=a.community_id,
                routing_domain_id=dom,
                allowed_sensors=None,
                fetch_limit=201,
            ).consume().plan
            ops_a = _collect_plan_operators(plan_a)
            assert any("IndexSeek" in op for op in ops_a)
            assert not any("AllNodesScan" in op or "CartesianProduct" in op for op in ops_a)

            plan_b = session.run(
                "EXPLAIN " + CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS,
                src_scoped_id=a.src_scoped_id,
                dst_scoped_id=a.dst_scoped_id,
                routing_domain_id=dom,
                allowed_sensors=None,
                fetch_limit=201,
            ).consume().plan
            ops_b = _collect_plan_operators(plan_b)
            assert any("IndexSeek" in op for op in ops_b)
            assert not any("AllNodesScan" in op or "CartesianProduct" in op for op in ops_b)

        summary = run_alert_flow_correlation(event_ids=[a.event_id], driver=live_driver)
        assert summary.alerts_evaluated == 1
        assert summary.strong == 1
        assert summary.correlations_created == 1
        assert summary.batches_committed == 1

        edges = _edge_rows(live_driver, a.event_id)
        assert len(edges) == 1
        assert edges[0]["observation_id"] == f.observation_id
        props = edges[0]["props"]
        assert props["correlation_method"] == "cid_verified_5tuple_temporal"
        assert props["routing_domain_id"] == dom
        assert props["tuple_orientation"] == TupleOrientation.FORWARD.value
        assert props["community_id_agreement"] == "MATCH"
        assert props["temporal_relation"] == TemporalRelation.WITHIN_INTERVAL.value
        assert props["temporal_delta_decimal"] == "0"
        assert props["used_decimal_fallback"] is False
        assert isinstance(props["evidence_digest"], str) and len(props["evidence_digest"]) == 64

        with live_driver.session() as session:
            inv = session.run(
                "MATCH (:FlowObservation {observation_id: $oid})-[r:CORRELATED_WITH]->(:AlertEvent {event_id: $eid}) "
                "RETURN count(r) AS c",
                oid=f.observation_id,
                eid=a.event_id,
            ).single()["c"]
            assert inv == 0
            post_ae_digest = session.run(
                "MATCH (ae:AlertEvent {event_id: $eid}) RETURN ae.payload_digest AS d, ae._corr_tx_lock AS lk",
                eid=a.event_id,
            ).single()
            assert post_ae_digest["d"] == pre_ae_digest
            assert post_ae_digest["lk"] is None
            post_fo_digest = session.run(
                "MATCH (fo:FlowObservation {observation_id: $oid}) RETURN fo.payload_digest AS d",
                oid=f.observation_id,
            ).single()["d"]
            assert post_fo_digest == pre_fo_digest
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_b_unique_reverse_tcp(live_driver):
    """TEST B: Reverse TCP orientation creates 1 REVERSE CORRELATED_WITH edge despite different flow_key."""
    dom = "it-4b-b"
    a = _make_alert(tag="b", domain=dom, src_ip="198.51.100.20", dst_ip="192.0.2.10", src_port=443, dst_port=54321)
    f = _make_flow(tag="b", domain=dom, src_ip="192.0.2.10", dst_ip="198.51.100.20", src_port=54321, dst_port=443)
    assert a.flow_key != f.flow_key
    _seed(live_driver, [a], [f])

    try:
        res = Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id)
        assert res.decision.status == CorrelationStatus.STRONG
        assert res.action == "created"
        edges = _edge_rows(live_driver, a.event_id)
        assert len(edges) == 1
        assert edges[0]["observation_id"] == f.observation_id
        assert edges[0]["props"]["tuple_orientation"] == TupleOrientation.REVERSE.value
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[f.src_scoped_id, f.dst_scoped_id],
            domain_ids=[dom],
        )


def test_c_same_cid_different_times_rejected(live_driver):
    """TEST C: Matching CID outside flow temporal window is REJECTED with 0 edges."""
    dom = "it-4b-c"
    a = _make_alert(tag="c", domain=dom, timestamp_epoch_decimal=Decimal("1795200900"))
    f = _make_flow(tag="c", domain=dom, start_epoch=Decimal("1795200100"), end_epoch=Decimal("1795200120"))
    _seed(live_driver, [a], [f])

    try:
        res = Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id)
        assert res.decision.status == CorrelationStatus.REJECTED
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_d_cid_matching_plus_null_cid_competitor_ambiguous(live_driver):
    """TEST D: Alert with CID plus matching flow AND NULL-CID competitor yields AMBIGUOUS and 0 edges."""
    dom = "it-4b-d"
    a = _make_alert(tag="d", domain=dom)
    f_cid = _make_flow(tag="d1", domain=dom)
    f_null = _make_flow(tag="d2", domain=dom, use_default_cid=False, community_id=None)
    _seed(live_driver, [a], [f_cid, f_null])

    try:
        repo = Neo4jCorrelationRepository(live_driver)
        res_def = repo.correlate_alert_event(a.event_id)
        assert res_def.decision.status == CorrelationStatus.AMBIGUOUS
        assert len(res_def.decision.strong_candidate_ids) == 2
        assert _edge_rows(live_driver, a.event_id) == []

        res_req = repo.correlate_alert_event(a.event_id, policy=CorrelationPolicy(require_community_id=True))
        assert res_req.decision.status == CorrelationStatus.AMBIGUOUS
        assert res_req.decision.strong_candidate_ids == (f_cid.observation_id,)
        assert res_req.decision.plausible_rival_ids == (f_null.observation_id,)
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f_cid.observation_id, f_null.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_e_overlapping_sessions_ambiguous(live_driver):
    """TEST E: Two overlapping Zeek FlowObservations matching the alert produce AMBIGUOUS and 0 edges."""
    dom = "it-4b-e"
    a = _make_alert(tag="e", domain=dom, timestamp_epoch_decimal=Decimal("1795200110"))
    f1 = _make_flow(tag="e1", domain=dom, start_epoch=Decimal("1795200100"), end_epoch=Decimal("1795200120"))
    f2 = _make_flow(tag="e2", domain=dom, start_epoch=Decimal("1795200105"), end_epoch=Decimal("1795200125"))
    _seed(live_driver, [a], [f1, f2])

    try:
        res = Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id)
        assert res.decision.status == CorrelationStatus.AMBIGUOUS
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f1.observation_id, f2.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_f_strong_plus_temporally_unresolved_rival_ambiguous(live_driver):
    """TEST F: One STRONG candidate plus one missing-start_epoch rival yields AMBIGUOUS and 0 edges."""
    dom = "it-4b-f"
    a = _make_alert(tag="f", domain=dom)
    f_strong = _make_flow(tag="f1", domain=dom)
    f_unresolved = _make_flow(tag="f2", domain=dom, start_epoch=None, end_epoch=None, duration=None)
    _seed(live_driver, [a], [f_strong, f_unresolved])

    try:
        res = Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id)
        assert res.decision.status == CorrelationStatus.AMBIGUOUS
        assert res.decision.strong_candidate_ids == (f_strong.observation_id,)
        assert res.decision.plausible_rival_ids == (f_unresolved.observation_id,)
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f_strong.observation_id, f_unresolved.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_g_cross_domain_same_raw_ips_isolated(live_driver):
    """TEST G: Identical raw IPs, ports, timestamps, and CID in distinct RoutingDomains never cross-correlate."""
    dom1, dom2 = "it-4b-g1", "it-4b-g2"
    a = _make_alert(tag="g", domain=dom1, src_ip="10.10.0.5", dst_ip="10.10.0.20")
    f = _make_flow(tag="g", domain=dom2, src_ip="10.10.0.5", dst_ip="10.10.0.20")
    assert a.community_id == f.community_id
    _seed(live_driver, [a], [f])

    try:
        res = Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id)
        assert res.decision.status == CorrelationStatus.REJECTED
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id, f.src_scoped_id, f.dst_scoped_id],
            domain_ids=[dom1, dom2],
        )


def test_h_two_zeek_sensors_ambiguous_vs_explicit_pairing(live_driver):
    """TEST H: Multiple Zeek sensors produce AMBIGUOUS under ANY_IN_DOMAIN, STRONG under EXPLICIT_PAIRS."""
    dom = "it-4b-h"
    a = _make_alert(tag="h", domain=dom, sensor_id="suricata-edge")
    f_edge = _make_flow(tag="h1", domain=dom, sensor_id="zeek-edge")
    f_core = _make_flow(tag="h2", domain=dom, sensor_id="zeek-core")
    _seed(live_driver, [a], [f_edge, f_core])

    try:
        repo = Neo4jCorrelationRepository(live_driver)
        res_any = repo.correlate_alert_event(a.event_id)
        assert res_any.decision.status == CorrelationStatus.AMBIGUOUS
        assert _edge_rows(live_driver, a.event_id) == []

        paired = CorrelationPolicy(
            sensor_policy=SensorPairingPolicy.from_explicit_pairs({"suricata-edge": ["zeek-edge"]})
        )
        res_paired = repo.correlate_alert_event(a.event_id, policy=paired)
        assert res_paired.decision.status == CorrelationStatus.STRONG
        edges = _edge_rows(live_driver, a.event_id)
        assert len(edges) == 1
        assert edges[0]["observation_id"] == f_edge.observation_id
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f_edge.observation_id, f_core.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_i_missing_timestamp_and_null_ns_exact_decimal_fallback(live_driver):
    """TEST I: Timezone-naive alerts fail closed; NULL ns (sub-ns / post-2262) flows retrieve and correlate accurately."""
    dom = "it-4b-i"
    a_naive = _make_alert(
        tag="i-naive",
        domain=dom,
        timestamp_source="2026-11-20T18:41:50.000000",
        timestamp_epoch_decimal=None,
    )
    a_post2262 = _make_alert(
        tag="i-2300",
        domain=dom,
        timestamp_source="2300-01-01T00:00:05+0000",
        timestamp_epoch_decimal=Decimal("10413792005"),
    )
    f_post2262 = _make_flow(
        tag="i-2300",
        domain=dom,
        start_epoch=Decimal("10413792000"),
        end_epoch=Decimal("10413792010"),
        duration=Decimal("10"),
    )
    _seed(live_driver, [a_naive, a_post2262], [f_post2262])

    try:
        repo = Neo4jCorrelationRepository(live_driver)
        res_naive = repo.correlate_alert_event(a_naive.event_id)
        assert res_naive.decision.status == CorrelationStatus.INSUFFICIENT
        assert _edge_rows(live_driver, a_naive.event_id) == []

        res_2300 = repo.correlate_alert_event(a_post2262.event_id)
        assert res_2300.decision.status == CorrelationStatus.STRONG
        edges = _edge_rows(live_driver, a_post2262.event_id)
        assert len(edges) == 1
        assert edges[0]["props"]["used_decimal_fallback"] is True
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a_naive.event_id, a_post2262.event_id],
            obs_ids=[f_post2262.observation_id],
            def_ids=[a_naive.alert_definition_id, a_post2262.alert_definition_id],
            scoped_ids=[a_naive.src_scoped_id, a_naive.dst_scoped_id],
            domain_ids=[dom],
        )


def test_j_long_running_zeek_flow_retrievable(live_driver):
    """TEST J: Long-running Zeek flow (start=100, end=3600) matches alert at t=2000."""
    dom = "it-4b-j"
    a = _make_alert(tag="j", domain=dom, timestamp_epoch_decimal=Decimal("2000"))
    f = _make_flow(tag="j", domain=dom, start_epoch=Decimal("100"), end_epoch=Decimal("3600"), duration=Decimal("3500"))
    _seed(live_driver, [a], [f])

    try:
        res = Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id)
        assert res.decision.status == CorrelationStatus.STRONG
        assert len(_edge_rows(live_driver, a.event_id)) == 1
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_k_candidate_cap_overflow_fails_closed(live_driver):
    """TEST K: Exceeding candidate_cap yields TRUNCATED / INSUFFICIENT and never creates or destroys edges."""
    dom = "it-4b-k"
    a = _make_alert(tag="k", domain=dom)
    f1 = _make_flow(tag="k1", domain=dom)
    f2 = _make_flow(tag="k2", domain=dom, src_port=11111)  # Rejected individually
    f3 = _make_flow(tag="k3", domain=dom, src_port=22222)  # Rejected individually
    _seed(live_driver, [a], [f1])

    try:
        # Step 1: Establish valid correlation when only f1 exists under cap=2
        pol_cap2 = CorrelationPolicy(candidate_cap=2)
        res1 = run_alert_flow_correlation(event_ids=[a.event_id], policy=pol_cap2, driver=live_driver)
        assert res1.strong == 1
        assert res1.correlations_created == 1
        edges1 = _edge_rows(live_driver, a.event_id)
        assert len(edges1) == 1
        orig_digest = edges1[0]["props"]["evidence_digest"]
        assert edges1[0]["props"]["verification_status"] == VERIFICATION_STATUS_VERIFIED

        # Step 2: Ingest f2 & f3 so candidate set (3) > cap (2) -> TRUNCATED preserves edge & digest,
        # marks verification_status='unverified_incomplete' cleanly for downstream readers.
        _seed(live_driver, [], [f2, f3])
        res2 = run_alert_flow_correlation(event_ids=[a.event_id], policy=pol_cap2, driver=live_driver)
        assert res2.insufficient == 1
        assert res2.candidate_cap_exceeded == 1
        assert res2.incomplete_evaluations == 1
        assert res2.stale_correlations_removed == 0

        corr_repo = Neo4jCorrelationRepository(live_driver)
        corrs_all = corr_repo.get_alert_correlations(a.event_id, include_unverified=True)
        assert len(corrs_all) == 1
        assert corrs_all[0]["evidence_digest"] == orig_digest
        assert corrs_all[0]["verification_status"] == VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
        assert corrs_all[0]["last_incomplete_reason"] == "CANDIDATE_SET_TRUNCATED"
        assert corr_repo.get_alert_correlations(a.event_id, include_unverified=False) == []

        # Step 3: Re-run with cap=10 -> COMPLETE evaluation clears unverified flag back to 'verified'
        res3 = run_alert_flow_correlation(
            event_ids=[a.event_id],
            policy=CorrelationPolicy(candidate_cap=10),
            driver=live_driver,
        )
        assert res3.strong == 1
        assert res3.correlations_updated == 1
        corrs_verified = corr_repo.get_alert_correlations(a.event_id, include_unverified=False)
        assert len(corrs_verified) == 1
        assert corrs_verified[0]["verification_status"] == VERIFICATION_STATUS_VERIFIED
        assert corrs_verified[0]["last_incomplete_reason"] is None
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f1.observation_id, f2.observation_id, f3.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_l_idempotent_repeated_runs_no_unnecessary_rewrite(live_driver):
    """TEST L: Repeated runs produce 1 edge and do not rewrite unchanged relationship metadata."""
    dom = "it-4b-l"
    a = _make_alert(tag="l", domain=dom)
    f = _make_flow(tag="l", domain=dom)
    _seed(live_driver, [a], [f])

    try:
        r1 = run_alert_flow_correlation(event_ids=[a.event_id], driver=live_driver)
        assert r1.correlations_created == 1
        e1 = _edge_rows(live_driver, a.event_id)
        assert len(e1) == 1

        r2 = run_alert_flow_correlation(event_ids=[a.event_id], driver=live_driver)
        assert r2.correlations_unchanged == 1
        assert r2.correlations_created == 0
        assert r2.correlations_updated == 0
        e2 = _edge_rows(live_driver, a.event_id)
        assert len(e2) == 1
        assert e2[0]["rel_id"] == e1[0]["rel_id"]
        assert e2[0]["props"]["decided_at_utc"] == e1[0]["props"]["decided_at_utc"]
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_m_second_matching_flow_removes_stale_edge(live_driver):
    """TEST M: Ingesting a second matching Zeek flow makes prior STRONG alert AMBIGUOUS and removes stale edge."""
    dom = "it-4b-m"
    a = _make_alert(tag="m", domain=dom)
    f1 = _make_flow(tag="m1", domain=dom)
    f2 = _make_flow(tag="m2", domain=dom)
    _seed(live_driver, [a], [f1])

    try:
        r1 = run_alert_flow_correlation(event_ids=[a.event_id], driver=live_driver)
        assert r1.correlations_created == 1
        assert len(_edge_rows(live_driver, a.event_id)) == 1

        _seed(live_driver, [], [f2])
        r2 = run_alert_flow_correlation(event_ids=[a.event_id], driver=live_driver)
        assert r2.ambiguous == 1
        assert r2.stale_correlations_removed == 1
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f1.observation_id, f2.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_n_policy_change_updates_and_removes_obsolete_correlation(live_driver):
    """TEST N: Changing policy updates metadata on valid match and removes edge when stricter policy rejects."""
    dom = "it-4b-n"
    a = _make_alert(tag="n", domain=dom, timestamp_epoch_decimal=Decimal("1795200121.5"))
    f = _make_flow(tag="n", domain=dom, start_epoch=Decimal("1795200100"), end_epoch=Decimal("1795200120"))
    _seed(live_driver, [a], [f])

    try:
        p1 = CorrelationPolicy(post_end_tolerance_sec=Decimal("2"), allow_tolerance_match=True)
        r1 = run_alert_flow_correlation(event_ids=[a.event_id], policy=p1, driver=live_driver)
        assert r1.correlations_created == 1

        p2 = CorrelationPolicy(post_end_tolerance_sec=Decimal("3"), allow_tolerance_match=True)
        r2 = run_alert_flow_correlation(event_ids=[a.event_id], policy=p2, driver=live_driver)
        assert r2.correlations_updated == 1
        edges2 = _edge_rows(live_driver, a.event_id)
        assert len(edges2) == 1
        assert edges2[0]["props"]["policy_fingerprint"] == p2.policy_fingerprint

        p_strict = CorrelationPolicy()
        r3 = run_alert_flow_correlation(event_ids=[a.event_id], policy=p_strict, driver=live_driver)
        assert r3.rejected == 1
        assert r3.stale_correlations_removed == 1
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_o_reconciliation_transaction_failure_rolls_back_atomically(live_driver, monkeypatch):
    """TEST O: Mid-transaction write failure rolls back prior edge deletion in the same batch atomically."""
    dom = "it-4b-o"
    # Sort guarantee: event_id ordering processed inside one tx -> construct two alerts; first deletes stale, second fails create
    a1 = _make_alert(tag="o1", domain=dom, src_ip="192.0.2.51", dst_ip="198.51.100.51")
    a2 = _make_alert(tag="o2", domain=dom, src_ip="192.0.2.52", dst_ip="198.51.100.52")
    # Ensure a_first < a_second in lexicographic event_id order
    a_first, a_second = (a1, a2) if a1.event_id < a2.event_id else (a2, a1)

    f_first_1 = _make_flow(tag="of1", domain=dom, src_ip=a_first.src_ip, dst_ip=a_first.dst_ip)
    f_first_2 = _make_flow(tag="of2", domain=dom, src_ip=a_first.src_ip, dst_ip=a_first.dst_ip)
    f_second = _make_flow(tag="os1", domain=dom, src_ip=a_second.src_ip, dst_ip=a_second.dst_ip)
    _seed(live_driver, [a_first], [f_first_1])

    try:
        # Establish initial edge on a_first
        repo = Neo4jCorrelationRepository(live_driver)
        assert repo.correlate_alert_event(a_first.event_id).action == "created"
        before_edge = _edge_rows(live_driver, a_first.event_id)
        assert len(before_edge) == 1

        # Add f_first_2 (makes a_first AMBIGUOUS -> triggers DELETE inside batch) and a_second + f_second (triggers CREATE)
        _seed(live_driver, [a_second], [f_first_2, f_second])
        monkeypatch.setattr(
            "src.graph.correlation_repository.CYPHER_CREATE_CORRELATION",
            "INVALID CYPHER SYNTAX TO ROLL BACK BATCH",
        )

        with pytest.raises(Neo4jError):
            repo.correlate_alert_batch([a_first.event_id, a_second.event_id])

        # Verify atomic rollback: a_first STILL has its original edge, a_second has 0 edges
        after_edge = _edge_rows(live_driver, a_first.event_id)
        assert len(after_edge) == 1
        assert after_edge[0]["rel_id"] == before_edge[0]["rel_id"]
        assert _edge_rows(live_driver, a_second.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a1.event_id, a2.event_id],
            obs_ids=[f_first_1.observation_id, f_first_2.observation_id, f_second.observation_id],
            def_ids=[a1.alert_definition_id, a2.alert_definition_id],
            scoped_ids=[a1.src_scoped_id, a1.dst_scoped_id, a2.src_scoped_id, a2.dst_scoped_id],
            domain_ids=[dom],
        )


def test_p_workspace_replacement_rollback_and_cleanup_with_correlations(live_driver, monkeypatch):
    """TEST P: replace_workspace_data rollback restores CORRELATED_WITH edges, and valid cleanup removes them cleanly."""
    dom = "it-4b-p"
    a = _make_alert(tag="p", domain=dom)
    f = _make_flow(tag="p", domain=dom)
    canary_id = "it-4b-p-canary"
    _seed(live_driver, [a], [f])

    with live_driver.session() as session:
        session.run("CREATE (:CorrelationRollbackCanary {canary_id: $cid})", cid=canary_id).consume()

    try:
        assert Neo4jCorrelationRepository(live_driver).correlate_alert_event(a.event_id).action == "created"
        before_edges = _edge_rows(live_driver, a.event_id)
        assert len(before_edges) == 1

        repo = Neo4jRepository(live_driver)
        with monkeypatch.context() as mc:
            mc.setattr(
                "src.graph.repository.CYPHER_WRITE_TRAFFIC_BATCH",
                "INVALID CYPHER SYNTAX FOR WORKSPACE ROLLBACK",
            )
            with pytest.raises(Exception):
                repo.replace_workspace_data(
                    traffic_records=[TrafficRecord("00:11:22:33:44:01", "00:11:22:33:44:02", "198.51.100.250", "203.0.113.250", "TCP")],
                    alert_records=None,
                    domain_id="default",
                )

        # Rollback preserved the CORRELATED_WITH relationship and properties 100%
        after_rollback_edges = _edge_rows(live_driver, a.event_id)
        assert len(after_rollback_edges) == 1
        assert after_rollback_edges[0]["observation_id"] == before_edges[0]["observation_id"]
        assert after_rollback_edges[0]["props"]["evidence_digest"] == before_edges[0]["props"]["evidence_digest"]

        # Valid cleanup removes CORRELATED_WITH cleanly without leaving orphans or touching external nodes
        repo.replace_workspace_data(traffic_records=[], alert_records=[], domain_id="default")
        with live_driver.session() as session:
            corr_cnt = session.run("MATCH ()-[r:CORRELATED_WITH]->() RETURN count(r) AS c").single()["c"]
            canary_cnt = session.run(
                "MATCH (c:CorrelationRollbackCanary {canary_id: $cid}) RETURN count(c) AS c",
                cid=canary_id,
            ).single()["c"]
            assert corr_cnt == 0
            assert canary_cnt == 1
    finally:
        with live_driver.session() as session:
            session.run(
                "MATCH (c:CorrelationRollbackCanary {canary_id: $cid}) DETACH DELETE c",
                cid=canary_id,
            ).consume()
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom, "default"],
        )


def test_q_dry_run_performs_zero_writes(live_driver):
    """TEST Q: Dry-run evaluates candidates accurately while performing zero Neo4j mutations."""
    dom = "it-4b-q"
    a = _make_alert(tag="q", domain=dom)
    f = _make_flow(tag="q", domain=dom)
    _seed(live_driver, [a], [f])

    try:
        summary = run_alert_flow_correlation(event_ids=[a.event_id], dry_run=True, driver=live_driver)
        assert summary.dry_run is True
        assert summary.alerts_evaluated == 1
        assert summary.strong == 1
        assert summary.correlations_created == 0
        assert summary.batches_committed == 0
        assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_r_multi_batch_interruption_and_idempotent_retry(live_driver, monkeypatch):
    """TEST R: Multi-batch run preserves Batch 1 commit on Batch 2 failure and converges on retry."""
    dom = "it-4b-r"
    a1 = _make_alert(tag="r1", domain=dom, src_ip="192.0.2.61", dst_ip="198.51.100.61")
    a2 = _make_alert(tag="r2", domain=dom, src_ip="192.0.2.62", dst_ip="198.51.100.62")
    f1 = _make_flow(tag="r1", domain=dom, src_ip="192.0.2.61", dst_ip="198.51.100.61")
    f2 = _make_flow(tag="r2", domain=dom, src_ip="192.0.2.62", dst_ip="198.51.100.62")
    _seed(live_driver, [a1, a2], [f1, f2])

    try:
        orig_batch = Neo4jCorrelationRepository.correlate_alert_batch
        call_num = {"n": 0}

        def _fail_second_batch(self, batch_ids, **kwargs):
            call_num["n"] += 1
            if call_num["n"] == 2:
                with monkeypatch.context() as mc:
                    mc.setattr(
                        "src.graph.correlation_repository.CYPHER_CREATE_CORRELATION",
                        "INVALID CYPHER FOR BATCH 2 INTERRUPTION",
                    )
                    return orig_batch(self, batch_ids, **kwargs)
            return orig_batch(self, batch_ids, **kwargs)

        with monkeypatch.context() as mc:
            mc.setattr(Neo4jCorrelationRepository, "correlate_alert_batch", _fail_second_batch)
            with pytest.raises(Neo4jError):
                run_alert_flow_correlation(
                    event_ids=[a1.event_id, a2.event_id],
                    batch_size=1,
                    driver=live_driver,
                )

        assert len(_edge_rows(live_driver, a1.event_id)) == 1
        assert _edge_rows(live_driver, a2.event_id) == []

        retry_sum = run_alert_flow_correlation(
            event_ids=[a1.event_id, a2.event_id],
            batch_size=1,
            driver=live_driver,
        )
        assert retry_sum.alerts_evaluated == 2
        assert retry_sum.correlations_unchanged == 1
        assert retry_sum.correlations_created == 1
        assert retry_sum.batches_committed == 2
        assert len(_edge_rows(live_driver, a1.event_id)) == 1
        assert len(_edge_rows(live_driver, a2.event_id)) == 1
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a1.event_id, a2.event_id],
            obs_ids=[f1.observation_id, f2.observation_id],
            def_ids=[a1.alert_definition_id, a2.alert_definition_id],
            scoped_ids=[a1.src_scoped_id, a1.dst_scoped_id, a2.src_scoped_id, a2.dst_scoped_id],
            domain_ids=[dom],
        )


def test_s_unsupported_source_types_never_correlate(live_driver):
    """TEST S: Non-zeek FlowObservations and non-suricata AlertEvents cannot generate CORRELATED_WITH edges."""
    dom = "it-4b-s"
    a_valid = _make_alert(tag="s-suricata", domain=dom, src_ip="192.0.2.71", dst_ip="198.51.100.71")
    f_tshark = _make_flow(tag="s-tshark", domain=dom, src_ip="192.0.2.71", dst_ip="198.51.100.71", source_type="tshark")
    a_snort = _make_alert(tag="s-snort", domain=dom, src_ip="192.0.2.72", dst_ip="198.51.100.72", source_type="snort")
    f_zeek = _make_flow(tag="s-zeek", domain=dom, src_ip="192.0.2.72", dst_ip="198.51.100.72", source_type="zeek")

    _seed(live_driver, [a_valid, a_snort], [f_tshark, f_zeek])

    try:
        repo = Neo4jCorrelationRepository(live_driver)
        listed = repo.list_correlatable_alert_event_ids(routing_domain_id=dom)
        assert listed == [a_valid.event_id]

        res = run_alert_flow_correlation(routing_domain_id=dom, driver=live_driver)
        assert res.alerts_evaluated == 1
        assert res.rejected == 1
        assert res.correlations_created == 0
        assert _edge_rows(live_driver, a_valid.event_id) == []

        with pytest.raises(ValueError, match="source_type"):
            repo.correlate_alert_event(a_snort.event_id)
        assert _edge_rows(live_driver, a_snort.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a_valid.event_id, a_snort.event_id],
            obs_ids=[f_tshark.observation_id, f_zeek.observation_id],
            def_ids=[a_valid.alert_definition_id, a_snort.alert_definition_id],
            scoped_ids=[a_valid.src_scoped_id, a_valid.dst_scoped_id, a_snort.src_scoped_id, a_snort.dst_scoped_id],
            domain_ids=[dom],
        )


def test_t_concurrent_correlation_workers_and_migration_guard(live_driver):
    """TEST T: Concurrent correlation workers serialize safely without duplicate edges, and unmigrated DB blocks cleanly."""
    dom = "it-4b-t"
    a1 = _make_alert(tag="t1", domain=dom, src_ip="192.0.2.81", dst_ip="198.51.100.81")
    a2 = _make_alert(tag="t2", domain=dom, src_ip="192.0.2.82", dst_ip="198.51.100.82")
    f1 = _make_flow(tag="t1", domain=dom, src_ip="192.0.2.81", dst_ip="198.51.100.81")
    f2 = _make_flow(tag="t2", domain=dom, src_ip="192.0.2.82", dst_ip="198.51.100.82")
    _seed(live_driver, [a1, a2], [f1, f2])

    legacy_addr = "198.51.100.252"
    try:
        # 1. Two concurrent workers correlating overlapping alert sets in opposite input orders
        def _worker(order_ids: List[str]):
            return Neo4jCorrelationRepository(live_driver).correlate_alert_batch(order_ids)

        with ThreadPoolExecutor(max_workers=2) as pool:
            fut1 = pool.submit(_worker, [a1.event_id, a2.event_id])
            fut2 = pool.submit(_worker, [a2.event_id, a1.event_id])
            b1 = fut1.result(timeout=30)
            b2 = fut2.result(timeout=30)

        assert b1.strong == 2
        assert b2.strong == 2
        assert (b1.correlations_created + b2.correlations_created) == 2
        assert (b1.correlations_unchanged + b2.correlations_unchanged) == 2
        assert len(_edge_rows(live_driver, a1.event_id)) == 1
        assert len(_edge_rows(live_driver, a2.event_id)) == 1

        # 2. Preflight MigrationRequiredError blocks runner when unmigrated IPAddress node exists
        with live_driver.session() as session:
            session.run("CREATE (:IPAddress {address: $addr})", addr=legacy_addr).consume()
        with pytest.raises(MigrationRequiredError):
            run_alert_flow_correlation(routing_domain_id=dom, driver=live_driver)
    finally:
        with live_driver.session() as session:
            session.run(
                "MATCH (ip:IPAddress {address: $addr}) WHERE ip.scoped_id IS NULL DETACH DELETE ip",
                addr=legacy_addr,
            ).consume()
        _cleanup_test_entities(
            live_driver,
            event_ids=[a1.event_id, a2.event_id],
            obs_ids=[f1.observation_id, f2.observation_id],
            def_ids=[a1.alert_definition_id, a2.alert_definition_id],
            scoped_ids=[a1.src_scoped_id, a1.dst_scoped_id, a2.src_scoped_id, a2.dst_scoped_id],
            domain_ids=[dom],
        )


def test_u_dry_run_missing_schema_fails_without_ddl_and_write_mode_recovers(live_driver):
    """TEST U: Dry-run against missing schema fails with SchemaNotReadyError without running DDL; write mode initializes schema."""
    dom = "it-4b-u"
    a = _make_alert(tag="u", domain=dom)
    f = _make_flow(tag="u", domain=dom)
    _seed(live_driver, [a], [f])

    target_index = "flow_observation_community_id_index"

    def _index_exists() -> bool:
        with live_driver.session() as session:
            names = {
                str(rec["name"])
                for rec in session.run("SHOW INDEXES YIELD name RETURN name")
                if rec.get("name") is not None
            }
        return target_index in names

    try:
        with live_driver.session() as session:
            session.run(f"DROP INDEX {target_index} IF EXISTS").consume()
        assert _index_exists() is False

        # Dry-run must fail clearly with SchemaNotReadyError and MUST NOT recreate the index or write edges
        with pytest.raises(SchemaNotReadyError) as exc_info:
            run_alert_flow_correlation(routing_domain_id=dom, dry_run=True, driver=live_driver)
        assert target_index in exc_info.value.missing_indexes
        assert _index_exists() is False
        assert _edge_rows(live_driver, a.event_id) == []

        # Normal write mode runs ensure_schema(), restores the index, and persists the correlation
        write_sum = run_alert_flow_correlation(routing_domain_id=dom, dry_run=False, driver=live_driver)
        assert _index_exists() is True
        assert write_sum.strong == 1
        assert write_sum.correlations_created == 1
        assert len(_edge_rows(live_driver, a.event_id)) == 1

        # Subsequent dry-run on initialized schema succeeds with zero writes
        dry_ok = run_alert_flow_correlation(routing_domain_id=dom, dry_run=True, driver=live_driver)
        assert dry_ok.dry_run is True
        assert dry_ok.strong == 1
        assert dry_ok.correlations_created == 0
        assert dry_ok.batches_committed == 0
    finally:
        ensure_schema(live_driver)
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id],
            obs_ids=[f.observation_id],
            def_ids=[a.alert_definition_id],
            scoped_ids=[a.src_scoped_id, a.dst_scoped_id],
            domain_ids=[dom],
        )


def test_v_keyset_pagination_beyond_max_alerts_identical_and_null_timestamps(live_driver):
    """TEST V: Keyset continuation paginates > max_alerts across identical and NULL timestamps with zero skips or duplicates."""
    dom = "it-4b-v"
    ts_same = Decimal("1795205000")
    ts_later = Decimal("1795205010")

    alerts = [
        _make_alert(tag="v1", domain=dom, src_ip="192.0.2.101", dst_ip="198.51.100.101", timestamp_source="2026-11-20T20:03:20+0000", timestamp_epoch_decimal=ts_same),
        _make_alert(tag="v2", domain=dom, src_ip="192.0.2.102", dst_ip="198.51.100.102", timestamp_source="2026-11-20T20:03:20+0000", timestamp_epoch_decimal=ts_same),
        _make_alert(tag="v3", domain=dom, src_ip="192.0.2.103", dst_ip="198.51.100.103", timestamp_source="2026-11-20T20:03:20+0000", timestamp_epoch_decimal=ts_same),
        _make_alert(tag="v4", domain=dom, src_ip="192.0.2.104", dst_ip="198.51.100.104", timestamp_source="2026-11-20T20:03:30+0000", timestamp_epoch_decimal=ts_later),
        _make_alert(tag="v5", domain=dom, src_ip="192.0.2.105", dst_ip="198.51.100.105", timestamp_source="2026-11-20T20:03:30+0000", timestamp_epoch_decimal=ts_later),
        _make_alert(tag="v6-naive", domain=dom, src_ip="192.0.2.106", dst_ip="198.51.100.106", timestamp_source="2026-11-20T20:03:40", timestamp_epoch_decimal=None),
        _make_alert(tag="v7-naive", domain=dom, src_ip="192.0.2.107", dst_ip="198.51.100.107", timestamp_source="2026-11-20T20:03:41", timestamp_epoch_decimal=None),
    ]
    flows = [
        _make_flow(tag=f"v{i}", domain=dom, src_ip=a.src_ip, dst_ip=a.dst_ip, start_epoch=Decimal("1795204990"), end_epoch=Decimal("1795205020"), duration=Decimal("30"))
        for i, a in enumerate(alerts, start=1)
    ]
    _seed(live_driver, alerts, flows)

    try:
        repo = Neo4jCorrelationRepository(live_driver)
        expected_order = sorted(
            [a.event_id for a in alerts[:3]]
        ) + sorted(
            [a.event_id for a in alerts[3:5]]
        ) + sorted(
            [a.event_id for a in alerts[5:]]
        )

        # 1. Inspect exact keyset page order across 4 pages (max_alerts=2)
        paged_ids: List[str] = []
        cursor: Optional[AlertSelectionCursor] = None
        page_count = 0
        while True:
            page = repo.list_correlatable_alert_page(
                routing_domain_id=dom, max_alerts=2, after_cursor=cursor
            )
            paged_ids.extend(page.event_ids)
            page_count += 1
            if not page.has_more:
                assert page.next_cursor is None
                break
            assert page.next_cursor is not None
            cursor = AlertSelectionCursor.from_token(page.next_cursor.to_token())

        assert page_count == 4
        assert paged_ids == expected_order

        # 2. Run correlation runner across all pages (max_alerts=2) and verify full coverage
        total_eval = 0
        total_strong = 0
        total_insuff = 0
        total_created = 0
        run_cursor: Optional[AlertSelectionCursor] = None
        while True:
            s = run_alert_flow_correlation(
                routing_domain_id=dom,
                max_alerts=2,
                batch_size=2,
                after_cursor=run_cursor,
                driver=live_driver,
            )
            total_eval += s.alerts_evaluated
            total_strong += s.strong
            total_insuff += s.insufficient
            total_created += s.correlations_created
            if not s.has_more:
                assert s.next_cursor is None
                break
            assert s.next_cursor is not None
            run_cursor = s.next_cursor

        assert total_eval == 7
        assert total_strong == 5
        assert total_insuff == 2
        assert total_created == 5
        for a in alerts[:5]:
            assert len(_edge_rows(live_driver, a.event_id)) == 1
        for a in alerts[5:]:
            assert _edge_rows(live_driver, a.event_id) == []
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id for a in alerts],
            obs_ids=[f.observation_id for f in flows],
            def_ids=sorted({a.alert_definition_id for a in alerts}),
            scoped_ids=sorted({a.src_scoped_id for a in alerts} | {a.dst_scoped_id for a in alerts}),
            domain_ids=[dom],
        )


def test_w_only_uncorrelated_progress_and_explicit_event_ids_limit(live_driver):
    """TEST W: only_uncorrelated advances past permanently uncorrelated alerts via cursor, and oversized explicit event_ids raise."""
    dom = "it-4b-w"
    a1 = _make_alert(tag="w1", domain=dom, src_ip="192.0.2.111", dst_ip="198.51.100.111", timestamp_source="2026-11-20T20:10:01+0000", timestamp_epoch_decimal=Decimal("1795205401"))
    a2 = _make_alert(tag="w2", domain=dom, src_ip="192.0.2.112", dst_ip="198.51.100.112", timestamp_source="2026-11-20T20:10:02+0000", timestamp_epoch_decimal=Decimal("1795205402"))
    a3 = _make_alert(tag="w3", domain=dom, src_ip="192.0.2.113", dst_ip="198.51.100.113", timestamp_source="2026-11-20T20:10:03+0000", timestamp_epoch_decimal=Decimal("1795205403"))
    a4 = _make_alert(tag="w4", domain=dom, src_ip="192.0.2.114", dst_ip="198.51.100.114", timestamp_source="2026-11-20T20:10:04+0000", timestamp_epoch_decimal=Decimal("1795205404"))

    f1 = _make_flow(tag="w1", domain=dom, src_ip=a1.src_ip, dst_ip=a1.dst_ip, start_epoch=Decimal("1795205390"), end_epoch=Decimal("1795205420"), duration=Decimal("30"))
    # a2 has two overlapping matching flows -> permanently AMBIGUOUS (stays uncorrelated!)
    f2a = _make_flow(tag="w2a", domain=dom, src_ip=a2.src_ip, dst_ip=a2.dst_ip, start_epoch=Decimal("1795205390"), end_epoch=Decimal("1795205420"), duration=Decimal("30"))
    f2b = _make_flow(tag="w2b", domain=dom, src_ip=a2.src_ip, dst_ip=a2.dst_ip, start_epoch=Decimal("1795205395"), end_epoch=Decimal("1795205425"), duration=Decimal("30"))
    # a3 has zero matching flows -> REJECTED (stays uncorrelated!)
    # a4 has one valid match -> STRONG
    f4 = _make_flow(tag="w4", domain=dom, src_ip=a4.src_ip, dst_ip=a4.dst_ip, start_epoch=Decimal("1795205390"), end_epoch=Decimal("1795205420"), duration=Decimal("30"))

    alerts = [a1, a2, a3, a4]
    flows = [f1, f2a, f2b, f4]
    _seed(live_driver, alerts, flows)

    try:
        # Explicit event_ids exceeding max_alerts MUST fail clearly rather than silently dropping IDs
        with pytest.raises(ValueError, match="exceeds max_alerts"):
            run_alert_flow_correlation(
                event_ids=[a.event_id for a in alerts],
                max_alerts=2,
                driver=live_driver,
            )

        # Page 1 (only_uncorrelated=True, max_alerts=2): evaluates a1 (STRONG) and a2 (AMBIGUOUS)
        p1 = run_alert_flow_correlation(
            routing_domain_id=dom,
            only_uncorrelated=True,
            max_alerts=2,
            driver=live_driver,
        )
        assert p1.alerts_evaluated == 2
        assert p1.strong == 1
        assert p1.ambiguous == 1
        assert p1.correlations_created == 1
        assert p1.has_more is True
        assert p1.next_cursor is not None

        # Page 2 advances strictly past a2 (despite a2 remaining uncorrelated!) to evaluate a3 and a4
        p2 = run_alert_flow_correlation(
            routing_domain_id=dom,
            only_uncorrelated=True,
            max_alerts=2,
            after_cursor=p1.next_cursor,
            driver=live_driver,
        )
        assert p2.alerts_evaluated == 2
        assert p2.rejected == 1
        assert p2.strong == 1
        assert p2.correlations_created == 1
        assert p2.has_more is False
        assert p2.next_cursor is None

        assert len(_edge_rows(live_driver, a1.event_id)) == 1
        assert _edge_rows(live_driver, a2.event_id) == []
        assert _edge_rows(live_driver, a3.event_id) == []
        assert len(_edge_rows(live_driver, a4.event_id)) == 1
    finally:
        _cleanup_test_entities(
            live_driver,
            event_ids=[a.event_id for a in alerts],
            obs_ids=[f.observation_id for f in flows],
            def_ids=sorted({a.alert_definition_id for a in alerts}),
            scoped_ids=sorted({a.src_scoped_id for a in alerts} | {a.dst_scoped_id for a in alerts}),
            domain_ids=[dom],
        )
