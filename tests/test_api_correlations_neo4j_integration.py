"""
Live Neo4j 5.26 integration tests for Phase 4C Read-Only Correlation API.

Strictly opt-in via RUN_NEO4J_INTEGRATION=1 with explicit NEO4J_TEST_* credentials.
Verifies FastAPI + Pydantic + Neo4jCorrelationRepository + Neo4jReadRepository end-to-end
against disposable Neo4j without mocking database or correlation logic.
"""

from __future__ import annotations

from decimal import Decimal
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple
import pytest
from fastapi.testclient import TestClient
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from src.api.app import create_app
from src.api.dependencies import get_correlation_repository, get_read_repository
from src.correlation import CorrelationPolicy
from src.graph.correlation_repository import (
    VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE,
    VERIFICATION_STATUS_VERIFIED,
    Neo4jCorrelationRepository,
)
from src.graph.read_repository import Neo4jReadRepository
from src.graph.repository import Neo4jRepository
from src.graph.schema import ensure_schema
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

pytestmark = pytest.mark.integration

_DOM_A = "api4c-dom-a"
_DOM_B = "api4c-dom-b"
_V1_SID = 7777401


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


def _make_flow(
    *,
    tag: str,
    domain: str,
    src_ip: str = "203.0.113.10",
    dst_ip: str = "203.0.113.20",
    protocol: str = "TCP",
    src_port: Optional[int] = 51000,
    dst_port: Optional[int] = 443,
    sensor_id: str = "zeek-4c",
    start_epoch: Optional[Decimal] = Decimal("1795300100.000000"),
    end_epoch: Optional[Decimal] = Decimal("1795300120.000000"),
    duration: Optional[Decimal] = Decimal("20.000000"),
    community_id: Optional[str] = None,
    use_default_cid: bool = True,
) -> ZeekConnectionObservation:
    norm_dom = domain.strip().lower()
    src_scoped = scoped_ip_id(norm_dom, src_ip)
    dst_scoped = scoped_ip_id(norm_dom, dst_ip)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, protocol, src_port, dst_port)
    start_ts = "1795300100.000000" if start_epoch is None else str(start_epoch)
    zeek_uid = f"CZ4C_{tag}"
    obs_id = compute_observation_id(
        source_type="zeek",
        sensor_id=sensor_id,
        source_record_id=zeek_uid,
        timestamp=start_ts,
        flow_key=fk,
        source_provenance=f"it-4c-{tag}",
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
        source_type="zeek",
        source_provenance=f"it-4c-{tag}",
    )


def _make_alert(
    *,
    tag: str,
    domain: str,
    src_ip: str = "203.0.113.10",
    dst_ip: str = "203.0.113.20",
    protocol: str = "TCP",
    src_port: Optional[int] = 51000,
    dst_port: Optional[int] = 443,
    sensor_id: str = "suricata-4c",
    timestamp_source: str = "2026-11-21T22:28:30.000000+0000",
    timestamp_epoch_decimal: Optional[Decimal] = Decimal("1795300110.000000"),
    sid: int = 4401001,
    source_type: str = "suricata",
) -> SuricataAlertObservation:
    norm_dom = domain.strip().lower()
    src_scoped = scoped_ip_id(norm_dom, src_ip)
    dst_scoped = scoped_ip_id(norm_dom, dst_ip)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, protocol, src_port, dst_port)
    def_id = alert_definition_id(source_type, "it-4c-ns", 1, sid)
    ev_id = compute_alert_event_id(
        source_type=source_type,
        sensor_id=sensor_id,
        source_record_id=f"eve:4c:{tag}",
        timestamp=timestamp_source,
        def_id=def_id,
        flow_reference=fk,
    )
    cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return SuricataAlertObservation(
        event_id=ev_id,
        alert_definition_id=def_id,
        source_record_id=f"eve:4c:{tag}",
        log_source_id="it-4c-eve",
        sensor_id=sensor_id.strip().lower(),
        ruleset_namespace="it-4c-ns",
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
        flow_id=940001,
        community_id=cid,
        gid=1,
        sid=sid,
        rev=1,
        signature="SYNTHETIC Phase 4C API Rule",
        severity=2,
        source_type=source_type,
        source_provenance=f"it-4c-{tag}",
    )


def _cleanup_synthetic(
    driver,
    *,
    event_ids: Iterable[str],
    obs_ids: Iterable[str],
    def_ids: Iterable[str],
    scoped_ids: Iterable[str],
    domain_ids: Iterable[str],
    v1_l2s: Iterable[str],
    v1_sid: Optional[int] = None,
) -> None:
    with driver.session() as session:
        e_list = list(event_ids)
        o_list = list(obs_ids)
        d_list = list(def_ids)
        s_list = list(scoped_ids)
        dom_list = list(domain_ids)
        l2_list = list(v1_l2s)

        if v1_sid is not None:
            session.run(
                "MATCH (fact:AlertFact) WHERE fact.sid = $sid DETACH DELETE fact",
                sid=v1_sid,
            ).consume()
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
        if l2_list:
            session.run(
                "MATCH (l2:Layer2Identifier) WHERE l2.identifier IN $l2s DETACH DELETE l2",
                l2s=l2_list,
            ).consume()
        if dom_list:
            session.run(
                "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $doms "
                "AND NOT ((:IPAddress)-[:IN_DOMAIN]->(rd)) DETACH DELETE rd",
                doms=dom_list,
            ).consume()


def _snapshot_graph_and_schema(driver, domain_ids: List[str]) -> Tuple[Any, ...]:
    with driver.session() as session:
        counts = session.run(
            "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
            "WITH count(ae) AS ae_cnt "
            "MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN $doms "
            "WITH ae_cnt, count(fo) AS fo_cnt "
            "OPTIONAL MATCH (ae2:AlertEvent)-[r:CORRELATED_WITH]->(fo2:FlowObservation) "
            "WHERE ae2.routing_domain_id IN $doms "
            "RETURN ae_cnt, fo_cnt, count(r) AS rel_cnt",
            doms=domain_ids,
        ).single()

        edge_props = [
            (
                rec["event_id"],
                rec["observation_id"],
                dict(rec["props"]),
            )
            for rec in session.run(
                "MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation) "
                "WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS event_id, fo.observation_id AS observation_id, "
                "       properties(r) AS props "
                "ORDER BY ae.event_id ASC, fo.observation_id ASC",
                doms=domain_ids,
            )
        ]

        node_digests = [
            (rec["id"], rec["digest"])
            for rec in session.run(
                "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN $doms "
                "RETURN ae.event_id AS id, ae.payload_digest AS digest "
                "ORDER BY ae.event_id ASC",
                doms=domain_ids,
            )
        ]

        constraints = sorted(
            str(rec.get("name")) for rec in session.run("SHOW CONSTRAINTS")
        )
        indexes = sorted(str(rec.get("name")) for rec in session.run("SHOW INDEXES"))

        return (
            (counts["ae_cnt"], counts["fo_cnt"], counts["rel_cnt"]),
            edge_props,
            node_digests,
            constraints,
            indexes,
        )


@pytest.fixture(scope="module")
def seeded_api_env(live_driver):
    """Seed V2 verified/unverified/empty/cross-domain alerts + V1 legacy data in live Neo4j."""
    write_repo = Neo4jRepository(live_driver, batch_size=100)
    corr_repo = Neo4jCorrelationRepository(live_driver)
    read_repo = Neo4jReadRepository(live_driver)

    # 1. Three verified correlations in DOM_A (a1 uses sub-nanosecond exact Decimal tolerance)
    f1 = _make_flow(
        tag="f1",
        domain=_DOM_A,
        src_ip="203.0.113.10",
        dst_ip="203.0.113.20",
        src_port=51001,
        dst_port=443,
        start_epoch=Decimal("1795300100.000000"),
        end_epoch=Decimal("1795300120.000000"),
    )
    a1 = _make_alert(
        tag="a1",
        domain=_DOM_A,
        src_ip="203.0.113.10",
        dst_ip="203.0.113.20",
        src_port=51001,
        dst_port=443,
        timestamp_source="2026-11-21T22:28:19.999999999877+0000",
        timestamp_epoch_decimal=Decimal("1795300099.999999999877"),
    )

    f2 = _make_flow(
        tag="f2",
        domain=_DOM_A,
        src_ip="203.0.113.11",
        dst_ip="203.0.113.21",
        src_port=51002,
        dst_port=8443,
    )
    a2 = _make_alert(
        tag="a2",
        domain=_DOM_A,
        src_ip="203.0.113.11",
        dst_ip="203.0.113.21",
        src_port=51002,
        dst_port=8443,
    )

    f3 = _make_flow(
        tag="f3",
        domain=_DOM_A,
        src_ip="203.0.113.12",
        dst_ip="203.0.113.22",
        src_port=51003,
        dst_port=8080,
    )
    a3 = _make_alert(
        tag="a3",
        domain=_DOM_A,
        src_ip="203.0.113.12",
        dst_ip="203.0.113.22",
        src_port=51003,
        dst_port=8080,
    )

    # 2. One verified correlation in DOM_B reusing the exact same raw IPs/ports as a1/f1
    f_dom_b = _make_flow(
        tag="f-dom-b",
        domain=_DOM_B,
        src_ip="203.0.113.10",
        dst_ip="203.0.113.20",
        src_port=51001,
        dst_port=443,
    )
    a_dom_b = _make_alert(
        tag="a-dom-b",
        domain=_DOM_B,
        src_ip="203.0.113.10",
        dst_ip="203.0.113.20",
        src_port=51001,
        dst_port=443,
    )

    # 3. One correlation that transitions from verified -> unverified_incomplete via real cap truncation
    f_unv_orig = _make_flow(
        tag="f-unv-orig",
        domain=_DOM_A,
        src_ip="203.0.113.30",
        dst_ip="203.0.113.40",
        src_port=52001,
        dst_port=443,
    )
    a_unv = _make_alert(
        tag="a-unv",
        domain=_DOM_A,
        src_ip="203.0.113.30",
        dst_ip="203.0.113.40",
        src_port=52001,
        dst_port=443,
    )
    f_unv_rival = _make_flow(
        tag="f-unv-rival",
        domain=_DOM_A,
        src_ip="203.0.113.30",
        dst_ip="203.0.113.40",
        src_port=52009,
        dst_port=443,
        start_epoch=Decimal("1795300500.000000"),
        end_epoch=Decimal("1795300510.000000"),
        use_default_cid=False,
    )

    # 4. Existing Suricata AlertEvent with zero correlations
    a_empty = _make_alert(
        tag="a-empty",
        domain=_DOM_A,
        src_ip="203.0.113.50",
        dst_ip="203.0.113.60",
        src_port=53000,
        dst_port=22,
    )

    # 5. Non-Suricata AlertEvent (should never appear on V2 Suricata correlation routes)
    a_non_suricata = _make_alert(
        tag="a-non-suri",
        domain=_DOM_A,
        src_ip="203.0.113.70",
        dst_ip="203.0.113.80",
        src_port=54000,
        dst_port=25,
        source_type="snort",
    )

    # Seed V2 alerts/flows (first without f_unv_rival so a_unv becomes verified cleanly)
    all_flows = [f1, f2, f3, f_dom_b, f_unv_orig]
    all_alerts = [a1, a2, a3, a_dom_b, a_unv, a_empty, a_non_suricata]
    write_repo.write_zeek_observations(all_flows)
    write_repo.write_suricata_alert_events(all_alerts)

    # Correlate a1 with exact Decimal pre-tolerance so temporal_delta_decimal = "-0.000000000123"
    tol_policy = CorrelationPolicy(
        pre_start_tolerance_sec=Decimal("1"),
        allow_tolerance_match=True,
    )
    res_a1 = corr_repo.correlate_alert_event(a1.event_id, policy=tol_policy)
    assert res_a1.action == "created"

    res_rest = corr_repo.correlate_alert_batch([a2.event_id, a3.event_id, a_dom_b.event_id, a_unv.event_id])
    assert res_rest.correlations_created == 4

    # Now add rival flow and re-evaluate a_unv with candidate_cap=1 to trigger real unverified_incomplete
    write_repo.write_zeek_observations([f_unv_rival])
    res_unv = corr_repo.correlate_alert_event(
        a_unv.event_id,
        policy=CorrelationPolicy(candidate_cap=1),
    )
    assert res_unv.action == "incomplete_skipped"
    assert res_unv.existing_correlation_unverified is True

    # Seed isolated V1 traffic + alert record for backward-compatibility coexistence test
    v1_l2s = ["02:00:00:4c:aa:01", "02:00:00:4c:aa:02"]
    v1_traffic = [
        TrafficRecord(
            eth_src_resolved=v1_l2s[0],
            eth_dst_resolved=v1_l2s[1],
            ip_src="203.0.113.201",
            ip_dst="203.0.113.202",
            protocol="TCP",
        )
    ]
    v1_alerts = [
        AlertRecord(
            src_ip="203.0.113.201",
            dst_ip="203.0.113.202",
            sid=_V1_SID,
            gid=1,
            rev=1,
            message="SYNTHETIC Phase 4C V1 Coexistence Alert",
            priority=1,
            protocol="TCP",
            src_port=55555,
            dst_port=80,
        )
    ]
    write_repo.write_traffic_records(v1_traffic)
    write_repo.write_alert_records(v1_alerts)

    app = create_app()
    app.dependency_overrides[get_correlation_repository] = lambda: corr_repo
    app.dependency_overrides[get_read_repository] = lambda: read_repo
    client = TestClient(app)

    env = {
        "driver": live_driver,
        "client": client,
        "write_repo": write_repo,
        "corr_repo": corr_repo,
        "a1": a1,
        "f1": f1,
        "a2": a2,
        "f2": f2,
        "a3": a3,
        "f3": f3,
        "a_dom_b": a_dom_b,
        "f_dom_b": f_dom_b,
        "a_unv": a_unv,
        "f_unv_orig": f_unv_orig,
        "f_unv_rival": f_unv_rival,
        "a_empty": a_empty,
        "a_non_suricata": a_non_suricata,
        "dom_a_verified_ids": sorted([a1.event_id, a2.event_id, a3.event_id]),
    }

    try:
        yield env
    finally:
        app.dependency_overrides.clear()
        scoped_ids = {
            a.src_scoped_id for a in all_alerts
        } | {
            a.dst_scoped_id for a in all_alerts
        } | {
            scoped_ip_id("default", "203.0.113.201"),
            scoped_ip_id("default", "203.0.113.202"),
        }
        _cleanup_synthetic(
            live_driver,
            event_ids=[a.event_id for a in all_alerts],
            obs_ids=[f.observation_id for f in (all_flows + [f_unv_rival])],
            def_ids={a.alert_definition_id for a in all_alerts},
            scoped_ids=scoped_ids,
            domain_ids=[_DOM_A, _DOM_B],
            v1_l2s=v1_l2s,
            v1_sid=_V1_SID,
        )


def test_01_read_only_invariant_across_all_get_endpoints(seeded_api_env):
    """Scenario 9 + Scenarios 1-8: Exercise all GET endpoints and verify zero DB/schema mutations."""
    driver = seeded_api_env["driver"]
    client = seeded_api_env["client"]
    a1 = seeded_api_env["a1"]
    f1 = seeded_api_env["f1"]
    a_dom_b = seeded_api_env["a_dom_b"]
    f_dom_b = seeded_api_env["f_dom_b"]
    a_unv = seeded_api_env["a_unv"]
    a_empty = seeded_api_env["a_empty"]
    a_non_suricata = seeded_api_env["a_non_suricata"]

    before = _snapshot_graph_and_schema(driver, [_DOM_A, _DOM_B])

    # Scenario 1: Verified correlation returned with accurate persisted evidence & exact Decimal string
    r1 = client.get(f"/api/v1/correlations/alert-flows/{a1.event_id}")
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["total"] == 1
    assert len(d1["items"]) == 1
    item1 = d1["items"][0]
    assert item1["event_id"] == a1.event_id
    assert item1["observation_id"] == f1.observation_id
    assert item1["zeek_uid"] == f1.zeek_uid
    assert item1["routing_domain_id"] == _DOM_A
    assert item1["correlation_method"] == "cid_verified_5tuple_temporal"
    assert item1["evidence_version"] == "v1"
    assert item1["tuple_orientation"] == "FORWARD"
    assert item1["community_id_agreement"] == "MATCH"
    assert item1["temporal_relation"] == "WITHIN_PRE_TOLERANCE"
    assert item1["temporal_delta_decimal"] == "-0.000000000123"
    assert isinstance(item1["temporal_delta_decimal"], str)
    assert item1["used_decimal_fallback"] is True
    assert item1["sensor_context"] == "ALLOWED_ANY_IN_DOMAIN:suricata-4c->zeek-4c"
    assert item1["verification_status"] == VERIFICATION_STATUS_VERIFIED
    assert item1["last_incomplete_reason"] is None
    assert item1["last_incomplete_at_utc"] is None
    assert isinstance(item1["decided_at_utc"], str) and item1["decided_at_utc"].endswith("Z")
    assert len(item1["evidence_digest"]) == 64
    assert len(item1["policy_fingerprint"]) == 64

    # Scenario 2: Unverified correlation excluded by default API filter (list and detail)
    r_list_default = client.get(f"/api/v1/correlations/alert-flows?routing_domain_id={_DOM_A}")
    assert r_list_default.status_code == 200
    list_default_data = r_list_default.json()
    assert list_default_data["total"] == 3
    returned_eids = [row["event_id"] for row in list_default_data["items"]]
    assert returned_eids == seeded_api_env["dom_a_verified_ids"]
    assert a_unv.event_id not in returned_eids

    r_unv_default_detail = client.get(f"/api/v1/correlations/alert-flows/{a_unv.event_id}")
    assert r_unv_default_detail.status_code == 200
    assert r_unv_default_detail.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}

    # Scenario 3: include_unverified=true and verification_status=unverified_incomplete return preserved unverified edge
    r_list_inc = client.get(
        f"/api/v1/correlations/alert-flows?routing_domain_id={_DOM_A}&include_unverified=true"
    )
    assert r_list_inc.status_code == 200
    assert r_list_inc.json()["total"] == 4
    unv_rows = [row for row in r_list_inc.json()["items"] if row["event_id"] == a_unv.event_id]
    assert len(unv_rows) == 1
    assert unv_rows[0]["verification_status"] == VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
    assert unv_rows[0]["last_incomplete_reason"] == "CANDIDATE_CAP_EXCEEDED"
    assert isinstance(unv_rows[0]["last_incomplete_at_utc"], str)

    r_detail_unv = client.get(
        f"/api/v1/correlations/alert-flows/{a_unv.event_id}?verification_status=unverified_incomplete"
    )
    assert r_detail_unv.status_code == 200
    assert r_detail_unv.json()["total"] == 1
    assert (
        r_detail_unv.json()["items"][0]["verification_status"]
        == VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
    )

    r_conflict = client.get(
        f"/api/v1/correlations/alert-flows/{a_unv.event_id}"
        f"?include_unverified=false&verification_status=unverified_incomplete"
    )
    assert r_conflict.status_code == 422

    # Scenario 4: Missing or non-Suricata AlertEvent returns 404; malformed ID returns 422
    assert client.get(f"/api/v1/correlations/alert-flows/{'f' * 64}").status_code == 404
    assert client.get(f"/api/v1/correlations/alert-flows/{a_non_suricata.event_id}").status_code == 404
    assert client.get("/api/v1/correlations/alert-flows/not-valid").status_code == 422

    # Scenario 5: Existing Suricata AlertEvent with zero CORRELATED_WITH edges returns 200 empty
    r_empty = client.get(f"/api/v1/correlations/alert-flows/{a_empty.event_id}")
    assert r_empty.status_code == 200
    assert r_empty.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}

    # Scenario 6: RoutingDomain filtering prevents cross-domain leakage even on identical raw IPs
    r_dom_b = client.get(f"/api/v1/correlations/alert-flows?routing_domain_id={_DOM_B}")
    assert r_dom_b.status_code == 200
    dom_b_data = r_dom_b.json()
    assert dom_b_data["total"] == 1
    assert dom_b_data["items"][0]["event_id"] == a_dom_b.event_id
    assert dom_b_data["items"][0]["observation_id"] == f_dom_b.observation_id
    assert dom_b_data["items"][0]["routing_domain_id"] == _DOM_B

    # Cross-domain detail check must return 404 rather than leaking a1's existence across domains
    assert (
        client.get(f"/api/v1/correlations/alert-flows/{a1.event_id}?routing_domain_id={_DOM_B}").status_code
        == 404
    )

    # Scenario 7: Stable, non-duplicated pagination across pages with exact total
    p1 = client.get(
        f"/api/v1/correlations/alert-flows?routing_domain_id={_DOM_A}&limit=2&offset=0"
    ).json()
    p2 = client.get(
        f"/api/v1/correlations/alert-flows?routing_domain_id={_DOM_A}&limit=2&offset=2"
    ).json()
    assert p1["total"] == 3
    assert p2["total"] == 3
    assert len(p1["items"]) == 2
    assert len(p2["items"]) == 1
    paged_ids = [row["event_id"] for row in (p1["items"] + p2["items"])]
    assert paged_ids == seeded_api_env["dom_a_verified_ids"]
    assert len(set(paged_ids)) == 3

    # Scenario 8: V1 traffic-alerts endpoint continues returning legacy AlertFact records only
    r_v1 = client.get("/api/v1/correlations/traffic-alerts")
    assert r_v1.status_code == 200
    v1_matches = [
        item
        for item in r_v1.json()["items"]
        if item["source_ip"] == "203.0.113.201" and item["target_ip"] == "203.0.113.202"
    ]
    assert len(v1_matches) == 1
    assert v1_matches[0]["sid"] == _V1_SID
    assert v1_matches[0]["traffic_protocol"] == "TCP"

    # V2 endpoint must never leak V1 AlertFact records
    r_v2_obs = client.get(
        f"/api/v1/correlations/alert-flows?observation_id={f1.observation_id}"
    )
    assert r_v2_obs.status_code == 200
    assert r_v2_obs.json()["total"] == 1
    assert r_v2_obs.json()["items"][0]["event_id"] == a1.event_id

    after = _snapshot_graph_and_schema(driver, [_DOM_A, _DOM_B])
    assert after == before


def test_02_persisted_status_vs_concurrent_ingestion_no_live_recalculation(seeded_api_env):
    """Scenario 10: Ingesting a new competing flow does not trigger live recalculation on GET,
    and unverified edges are never promoted to verified on read.
    """
    driver = seeded_api_env["driver"]
    write_repo = seeded_api_env["write_repo"]
    client = seeded_api_env["client"]
    a2 = seeded_api_env["a2"]
    f2 = seeded_api_env["f2"]
    a_unv = seeded_api_env["a_unv"]

    competing_flow = _make_flow(
        tag="f2-late-rival",
        domain=_DOM_A,
        src_ip="203.0.113.11",
        dst_ip="203.0.113.21",
        src_port=51002,
        dst_port=8443,
        sensor_id="zeek-4c-late",
        start_epoch=Decimal("1795300105.000000"),
        end_epoch=Decimal("1795300125.000000"),
    )
    write_repo.write_zeek_observations([competing_flow])

    try:
        # GET must remain read-only and report the previously persisted edge rather than
        # automatically recalculating AMBIGUOUS or deleting/modifying the edge on read.
        r_a2 = client.get(f"/api/v1/correlations/alert-flows/{a2.event_id}")
        assert r_a2.status_code == 200
        d_a2 = r_a2.json()
        assert d_a2["total"] == 1
        assert d_a2["items"][0]["observation_id"] == f2.observation_id
        assert d_a2["items"][0]["verification_status"] == VERIFICATION_STATUS_VERIFIED

        # Unverified edge remains unverified_incomplete and excluded from default verified-only calls
        assert (
            client.get(f"/api/v1/correlations/alert-flows/{a_unv.event_id}").json()["total"]
            == 0
        )
        r_unv = client.get(
            f"/api/v1/correlations/alert-flows/{a_unv.event_id}?include_unverified=true"
        )
        assert r_unv.status_code == 200
        assert (
            r_unv.json()["items"][0]["verification_status"]
            == VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
        )
    finally:
        with driver.session() as session:
            session.run(
                "MATCH (fo:FlowObservation {observation_id: $oid}) DETACH DELETE fo",
                oid=competing_flow.observation_id,
            ).consume()
