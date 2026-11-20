"""
Live Neo4j integration tests for Phase 3A.2 Zeek FlowObservation persistence and reads.

Strictly opt-in via RUN_NEO4J_INTEGRATION=1 with explicit NEO4J_TEST_* credentials.
Executes against the disposable Neo4j 5.26 CI container; never targets unknown databases.
"""

from dataclasses import replace
from decimal import Decimal
import json
import os
from pathlib import Path
import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from src.graph.read_repository import Neo4jReadRepository
from src.graph.repository import (
    Neo4jRepository,
    ObservationConflictError,
)
from src.graph.schema import ensure_schema
from src.ingestion.models import AlertRecord, TrafficRecord
from src.ingestion.v2_models import ZeekConnectionObservation
from src.ingestion.zeek_conn_parser import iter_zeek_conn_lines
from src.services.zeek_ingestion import ingest_zeek_conn_file

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "zeek"
OVERLAPPING_FIXTURE = FIXTURE_DIR / "conn_overlapping_rfc1918.jsonl"


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
            "RUN_NEO4J_INTEGRATION=1 is set but NEO4J_TEST_URI / NEO4J_TEST_USERNAME / "
            "NEO4J_TEST_PASSWORD are incomplete"
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


def _cleanup_test_entities(driver, obs_ids, scoped_ids, domain_ids):
    """Strictly scoped teardown removing only synthetic entities created by a test."""
    with driver.session() as session:
        if obs_ids:
            session.run(
                "MATCH (fo:FlowObservation) WHERE fo.observation_id IN $ids DETACH DELETE fo",
                ids=list(obs_ids),
            ).consume()
        if scoped_ids:
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.scoped_id IN $sids DETACH DELETE ip",
                sids=list(scoped_ids),
            ).consume()
        non_default_domains = [d for d in domain_ids if d != "default"]
        if non_default_domains:
            session.run(
                "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $dids AND NOT (:IPAddress)-[:IN_DOMAIN]->(rd) "
                "DELETE rd",
                dids=non_default_domains,
            ).consume()


# ---------------------------------------------------------------------------
# TEST A: Persist one Zeek observation + verify schema, links, timestamps, metrics
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_a_persist_single_observation(live_driver):
    """TEST A: Persist one Zeek observation and verify node, links, domain, timestamps, and metrics."""
    ensure_schema(live_driver)

    with live_driver.session() as session:
        constraint_names = {c.get("name") for c in session.run("SHOW CONSTRAINTS").data()}
        assert "flow_observation_unique" in constraint_names

        index_names = {i.get("name") for i in session.run("SHOW INDEXES").data()}
        assert "flow_observation_community_id_index" in index_names
        assert "flow_observation_sensor_id_index" in index_names
        assert "flow_observation_routing_domain_index" in index_names
        assert "flow_observation_start_epoch_ns_index" in index_names

    line = (
        '{"ts":1725148800.123456789,"uid":"CLiveTestA0000001","id.orig_h":"198.51.100.11","id.orig_p":51000,'
        '"id.resp_h":"198.51.100.22","id.resp_p":443,"proto":"tcp","service":"ssl","duration":2.500000001,'
        '"orig_bytes":1200,"resp_bytes":4800,"conn_state":"SF","local_orig":true,"local_resp":false,'
        '"missed_bytes":16,"history":"ShADadFf","orig_pkts":10,"orig_ip_bytes":1720,'
        '"resp_pkts":14,"resp_ip_bytes":5500}'
    )
    obs = list(iter_zeek_conn_lines([line], sensor_id="zeek-live-a", routing_domain_id="corp-a"))[0]
    repo = Neo4jRepository(live_driver, batch_size=50)

    try:
        summary = repo.write_zeek_observations([obs])
        assert summary.total_received == 1
        assert summary.created_count == 1
        assert summary.duplicate_matched_count == 0
        assert summary.batches_committed == 1

        with live_driver.session() as session:
            row = session.run(
                """
                MATCH (fo:FlowObservation {observation_id: $oid})
                MATCH (fo)-[:HAS_ORIGINATOR]->(orig:IPAddress)-[:IN_DOMAIN]->(rd_o:RoutingDomain)
                MATCH (fo)-[:HAS_RESPONDER]->(resp:IPAddress)-[:IN_DOMAIN]->(rd_r:RoutingDomain)
                RETURN fo, orig.scoped_id AS orig_scoped, resp.scoped_id AS resp_scoped,
                       rd_o.domain_id AS orig_domain, rd_r.domain_id AS resp_domain,
                       COUNT { MATCH (orig)-[:COMMUNICATED_TO]->(resp) } AS comm_edges
                """,
                oid=obs.observation_id,
            ).single()

            assert row is not None
            fo = row["fo"]
            assert row["orig_scoped"] == "corp-a#198.51.100.11"
            assert row["resp_scoped"] == "corp-a#198.51.100.22"
            assert row["orig_domain"] == "corp-a"
            assert row["resp_domain"] == "corp-a"
            assert row["comm_edges"] == 0  # Must NOT convert Zeek observation into COMMUNICATED_TO

            assert fo["zeek_uid"] == "CLiveTestA0000001"
            assert fo["flow_key"] == obs.flow_key
            assert fo["community_id"] == obs.community_id
            assert fo["start_ts"] == "1725148800.123456789"
            assert fo["end_ts"] == "1725148802.62345679"
            assert fo["start_epoch_decimal"] == "1725148800.123456789"
            assert fo["end_epoch_decimal"] == "1725148802.62345679"
            assert fo["duration_decimal"] == "2.500000001"
            assert fo["start_epoch_ns"] == 1725148800123456789
            assert fo["end_epoch_ns"] == 1725148802623456790
            assert fo["orig_bytes"] == 1200
            assert fo["resp_bytes"] == 4800
            assert fo["orig_ip_bytes"] == 1720
            assert fo["resp_ip_bytes"] == 5500
            assert fo["orig_pkts"] == 10
            assert fo["resp_pkts"] == 14
            assert fo["missed_bytes"] == 16
            assert fo["service"] == "ssl"
            assert fo["conn_state"] == "SF"
            assert fo["local_orig"] is True
            assert fo["local_resp"] is False
    finally:
        _cleanup_test_entities(
            live_driver,
            [obs.observation_id],
            [obs.src_scoped_id, obs.dst_scoped_id],
            ["corp-a"],
        )


# ---------------------------------------------------------------------------
# TEST B: Import identical observation twice + reject conflicting duplicate ID
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_b_idempotent_reimport_and_conflict_rejection(live_driver):
    """TEST B: Repeated import creates zero duplicate nodes/edges/doubled metrics; conflicts fail without overwrite."""
    line = (
        '{"ts":1725148900.5,"uid":"CLiveTestB0000001","id.orig_h":"198.51.100.31","id.orig_p":52000,'
        '"id.resp_h":"198.51.100.32","id.resp_p":80,"proto":"tcp","orig_bytes":500,"resp_bytes":1500,'
        '"orig_pkts":5,"resp_pkts":7}'
    )
    obs = list(iter_zeek_conn_lines([line], sensor_id="zeek-live-b", routing_domain_id="corp-b"))[0]
    repo = Neo4jRepository(live_driver, batch_size=50)

    try:
        s1 = repo.write_zeek_observations([obs])
        assert s1.created_count == 1
        assert s1.duplicate_matched_count == 0

        # Exact re-import
        s2 = repo.write_zeek_observations([obs])
        assert s2.created_count == 0
        assert s2.duplicate_matched_count == 1

        with live_driver.session() as session:
            counts = session.run(
                """
                MATCH (fo:FlowObservation {observation_id: $oid})
                OPTIONAL MATCH (fo)-[ro:HAS_ORIGINATOR]->(:IPAddress)
                OPTIONAL MATCH (fo)-[rr:HAS_RESPONDER]->(:IPAddress)
                RETURN count(DISTINCT fo) AS node_count,
                       count(DISTINCT ro) AS orig_rel_count,
                       count(DISTINCT rr) AS resp_rel_count,
                       fo.orig_bytes AS orig_bytes,
                       fo.orig_pkts AS orig_pkts
                """,
                oid=obs.observation_id,
            ).single()
            assert counts["node_count"] == 1
            assert counts["orig_rel_count"] == 1
            assert counts["resp_rel_count"] == 1
            assert counts["orig_bytes"] == 500
            assert counts["orig_pkts"] == 5

        # Conflicting payload for the SAME observation_id must raise and NOT overwrite existing data
        conflicting = replace(obs, orig_bytes=999999)
        with pytest.raises(ObservationConflictError) as exc_info:
            repo.write_zeek_observations([conflicting])
        assert obs.observation_id in exc_info.value.conflicting_observation_ids

        with live_driver.session() as session:
            persisted_bytes = session.run(
                "MATCH (fo:FlowObservation {observation_id: $oid}) RETURN fo.orig_bytes AS b",
                oid=obs.observation_id,
            ).single()["b"]
            assert persisted_bytes == 500
    finally:
        _cleanup_test_entities(
            live_driver,
            [obs.observation_id],
            [obs.src_scoped_id, obs.dst_scoped_id],
            ["corp-b"],
        )


# ---------------------------------------------------------------------------
# TEST C: Two different zeek_uid values sharing 5-tuple and Community ID
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_c_distinct_uids_same_tuple_and_community_id(live_driver):
    """TEST C: Distinct zeek_uid observations sharing 5-tuple and Community ID remain separate nodes."""
    lines = [
        '{"ts":1725149000.1,"uid":"CLiveTestC_UID_01","id.orig_h":"198.51.100.41","id.orig_p":44000,"id.resp_h":"198.51.100.42","id.resp_p":443,"proto":"tcp"}',
        '{"ts":1725149000.1,"uid":"CLiveTestC_UID_02","id.orig_h":"198.51.100.41","id.orig_p":44000,"id.resp_h":"198.51.100.42","id.resp_p":443,"proto":"tcp"}',
    ]
    obs_list = list(iter_zeek_conn_lines(lines, sensor_id="zeek-live-c", routing_domain_id="corp-c"))
    assert len(obs_list) == 2
    assert obs_list[0].community_id == obs_list[1].community_id
    assert obs_list[0].flow_key == obs_list[1].flow_key
    assert obs_list[0].observation_id != obs_list[1].observation_id

    repo = Neo4jRepository(live_driver, batch_size=50)
    try:
        summary = repo.write_zeek_observations(obs_list)
        assert summary.created_count == 2

        with live_driver.session() as session:
            rows = session.run(
                "MATCH (fo:FlowObservation) WHERE fo.community_id = $cid AND fo.routing_domain_id = 'corp-c' "
                "RETURN fo.observation_id AS oid, fo.zeek_uid AS uid ORDER BY fo.zeek_uid ASC",
                cid=obs_list[0].community_id,
            ).data()
            assert len(rows) == 2
            assert [r["uid"] for r in rows] == ["CLiveTestC_UID_01", "CLiveTestC_UID_02"]
    finally:
        _cleanup_test_entities(
            live_driver,
            [o.observation_id for o in obs_list],
            [obs_list[0].src_scoped_id, obs_list[0].dst_scoped_id],
            ["corp-c"],
        )


# ---------------------------------------------------------------------------
# TEST D: Overlapping RFC 1918 IPs in corp and branch RoutingDomains
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_d_overlapping_rfc1918_domain_isolation(live_driver):
    """TEST D: Overlapping RFC 1918 IPs across corp and branch remain strictly domain-isolated."""
    corp_res = ingest_zeek_conn_file(
        OVERLAPPING_FIXTURE,
        sensor_id="zeek-overlap-d",
        routing_domain_id="corp-overlap-d",
        driver=live_driver,
    )
    branch_res = ingest_zeek_conn_file(
        OVERLAPPING_FIXTURE,
        sensor_id="zeek-overlap-d",
        routing_domain_id="branch-overlap-d",
        driver=live_driver,
    )
    assert corp_res.persistence_summary.created_count == 1
    assert branch_res.persistence_summary.created_count == 1

    obs_ids = []
    try:
        with live_driver.session() as session:
            rows = session.run(
                """
                MATCH (fo:FlowObservation)
                WHERE fo.routing_domain_id IN ['corp-overlap-d', 'branch-overlap-d']
                MATCH (fo)-[:HAS_ORIGINATOR]->(orig:IPAddress)
                MATCH (fo)-[:HAS_RESPONDER]->(resp:IPAddress)
                RETURN fo.observation_id AS oid, fo.routing_domain_id AS fo_dom,
                       fo.community_id AS cid,
                       orig.scoped_id AS orig_scoped, orig.routing_domain_id AS orig_dom,
                       resp.scoped_id AS resp_scoped, resp.routing_domain_id AS resp_dom
                ORDER BY fo.routing_domain_id ASC
                """
            ).data()
            assert len(rows) == 2
            obs_ids = [r["oid"] for r in rows]

            for r in rows:
                assert r["orig_dom"] == r["fo_dom"]
                assert r["resp_dom"] == r["fo_dom"]

            assert rows[0]["orig_scoped"] == "branch-overlap-d#10.0.0.5"
            assert rows[0]["resp_scoped"] == "branch-overlap-d#10.0.0.20"
            assert rows[1]["orig_scoped"] == "corp-overlap-d#10.0.0.5"
            assert rows[1]["resp_scoped"] == "corp-overlap-d#10.0.0.20"
            assert rows[0]["cid"] == rows[1]["cid"]
            assert rows[0]["oid"] != rows[1]["oid"]
    finally:
        _cleanup_test_entities(
            live_driver,
            obs_ids,
            [
                "corp-overlap-d#10.0.0.5",
                "corp-overlap-d#10.0.0.20",
                "branch-overlap-d#10.0.0.5",
                "branch-overlap-d#10.0.0.20",
            ],
            ["corp-overlap-d", "branch-overlap-d"],
        )


# ---------------------------------------------------------------------------
# TEST E: Nanosecond & sub-nanosecond timestamps survive Neo4j round-trip
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_e_nanosecond_timestamp_survival(live_driver):
    """TEST E: Exact nanosecond and sub-nanosecond timestamps survive Neo4j write/read without float truncation."""
    lines = [
        '{"ts":1725148800.123456781,"uid":"CLiveNano00001","id.orig_h":"198.51.100.51","id.orig_p":40001,"id.resp_h":"198.51.100.52","id.resp_p":443,"proto":"tcp","duration":0.000000004}',
        '{"ts":1725148800.123456789,"uid":"CLiveNano00001","id.orig_h":"198.51.100.51","id.orig_p":40001,"id.resp_h":"198.51.100.52","id.resp_p":443,"proto":"tcp"}',
        '{"ts":1725148800.1234567895,"uid":"CLivePico00001","id.orig_h":"198.51.100.51","id.orig_p":40002,"id.resp_h":"198.51.100.52","id.resp_p":443,"proto":"tcp"}',
    ]
    obs_list = list(iter_zeek_conn_lines(lines, sensor_id="zeek-live-e", routing_domain_id="corp-e"))
    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    try:
        repo.write_zeek_observations(obs_list)

        r0 = read_repo.get_flow_observation(obs_list[0].observation_id)
        r1 = read_repo.get_flow_observation(obs_list[1].observation_id)
        r2 = read_repo.get_flow_observation(obs_list[2].observation_id)

        assert r0 is not None and r1 is not None and r2 is not None
        assert r0["start_ts"] == "1725148800.123456781"
        assert r0["start_epoch_decimal"] == "1725148800.123456781"
        assert r0["start_epoch_ns"] == 1725148800123456781
        assert r0["end_epoch_decimal"] == "1725148800.123456785"
        assert r0["end_epoch_ns"] == 1725148800123456785

        assert r1["start_ts"] == "1725148800.123456789"
        assert r1["start_epoch_decimal"] == "1725148800.123456789"
        assert r1["start_epoch_ns"] == 1725148800123456789
        assert r1["end_epoch_decimal"] is None
        assert r1["end_epoch_ns"] is None

        # Picosecond precision must NEVER be truncated into start_epoch_ns
        assert r2["start_ts"] == "1725148800.1234567895"
        assert r2["start_epoch_decimal"] == "1725148800.1234567895"
        assert r2["start_epoch_ns"] is None
    finally:
        _cleanup_test_entities(
            live_driver,
            [o.observation_id for o in obs_list],
            [obs_list[0].src_scoped_id, obs_list[0].dst_scoped_id],
            ["corp-e"],
        )


# ---------------------------------------------------------------------------
# TEST F: Batching, transactional failure rollback, and idempotent retry
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_f_batching_failure_rollback_and_retry(live_driver):
    """TEST F: Failed batch rolls back atomically, prior committed batch stays intact, and retry is idempotent."""
    lines = [
        json.dumps({
            "ts": 1725149100 + i,
            "uid": f"CLiveBatchF{i:04d}",
            "id.orig_h": "198.51.100.61",
            "id.orig_p": 45000 + i,
            "id.resp_h": "198.51.100.62",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 100 * (i + 1),
        })
        for i in range(4)
    ]
    obs_list = list(iter_zeek_conn_lines(lines, sensor_id="zeek-live-f", routing_domain_id="corp-f"))
    repo = Neo4jRepository(live_driver, batch_size=2)
    read_repo = Neo4jReadRepository(live_driver)

    # Batch 1: [obs0, obs1] (succeeds)
    # Batch 2: [obs2, conflicting_obs0] (conflicts on obs0 inside Neo4j -> ENTIRE batch 2 rolls back, so obs2 is NOT persisted!)
    conflicting_obs0 = replace(obs_list[0], orig_bytes=999999)

    try:
        with pytest.raises(ObservationConflictError) as exc_info:
            repo.write_zeek_observations([obs_list[0], obs_list[1], obs_list[2], conflicting_obs0], batch_size=2)

        assert exc_info.value.batches_committed == 1
        assert obs_list[0].observation_id in exc_info.value.conflicting_observation_ids

        # Batch 1 survived intact; Batch 2 (including new obs2) rolled back cleanly
        assert read_repo.get_flow_observation(obs_list[0].observation_id) is not None
        assert read_repo.get_flow_observation(obs_list[1].observation_id) is not None
        assert read_repo.get_flow_observation(obs_list[2].observation_id) is None

        # Retry with the full clean 4-observation stream -> obs0 & obs1 matched idempotently, obs2 & obs3 created
        retry_summary = repo.write_zeek_observations(obs_list, batch_size=2)
        assert retry_summary.total_received == 4
        assert retry_summary.created_count == 2
        assert retry_summary.duplicate_matched_count == 2
        assert retry_summary.batches_committed == 2

        items, total = read_repo.list_flow_observations(routing_domain_id="corp-f", limit=10)
        assert total == 4
        assert len(items) == 4
    finally:
        _cleanup_test_entities(
            live_driver,
            [o.observation_id for o in obs_list],
            [obs_list[0].src_scoped_id, obs_list[0].dst_scoped_id],
            ["corp-f"],
        )


# ---------------------------------------------------------------------------
# TEST G: Atomic workspace replacement removes FlowObservations & rolls back cleanly
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_g_atomic_workspace_replacement_and_rollback(live_driver, monkeypatch):
    """TEST G: Workspace replacement cleans up FlowObservations without orphans, preserves external nodes, and rolls back on failure."""
    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    obs = list(
        iter_zeek_conn_lines(
            [
                '{"ts":1725149200.25,"uid":"CLiveReplaceG01","id.orig_h":"198.51.100.71","id.orig_p":51111,'
                '"id.resp_h":"198.51.100.72","id.resp_p":443,"proto":"tcp","orig_bytes":256}'
            ],
            sensor_id="zeek-live-g",
            routing_domain_id="default",
        )
    )[0]

    try:
        # Create an unrelated external node to confirm scoped cleanup never touches non-application labels
        with live_driver.session() as session:
            session.run("MERGE (:ExternalReference {ref_id: 'keep-phase-3a2-g'})").consume()

        repo.write_zeek_observations([obs])
        assert read_repo.get_flow_observation(obs.observation_id) is not None

        # 1. Simulate mid-transaction failure after scoped cleanup -> rollback must preserve FlowObservation
        monkeypatch.setattr(
            "src.graph.repository.CYPHER_WRITE_TRAFFIC_BATCH",
            "INVALID CYPHER SYNTAX FOR ROLLBACK TEST",
        )
        with pytest.raises(Exception):
            repo.replace_workspace_data(
                traffic_records=[
                    TrafficRecord("02:00:00:aa:00:01", "02:00:00:aa:00:02", "198.51.100.81", "198.51.100.82", "TCP")
                ],
                alert_records=None,
            )

        # FlowObservation and its links survived rollback completely intact
        restored = read_repo.get_flow_observation(obs.observation_id)
        assert restored is not None
        assert restored["orig_bytes"] == 256
        assert restored["src_scoped_id"] == "default#198.51.100.71"

        # 2. Restore real CYPHER_WRITE_TRAFFIC_BATCH and perform clean workspace replacement
        monkeypatch.undo()
        repo.replace_workspace_data(
            traffic_records=[
                TrafficRecord("02:00:00:aa:00:01", "02:00:00:aa:00:02", "198.51.100.81", "198.51.100.82", "TCP")
            ],
            alert_records=[
                AlertRecord("198.51.100.81", "198.51.100.82", sid=777001, message="Post-replace alert", priority=2)
            ],
        )

        # Zero FlowObservation nodes remain (no orphans!)
        with live_driver.session() as session:
            fo_count = session.run("MATCH (fo:FlowObservation) RETURN count(fo) AS c").single()["c"]
            assert fo_count == 0

            # External node was NEVER deleted
            ext_count = session.run(
                "MATCH (e:ExternalReference {ref_id: 'keep-phase-3a2-g'}) RETURN count(e) AS c"
            ).single()["c"]
            assert ext_count == 1
    finally:
        with live_driver.session() as session:
            session.run("MATCH (e:ExternalReference {ref_id: 'keep-phase-3a2-g'}) DETACH DELETE e").consume()
            session.run("MATCH (a:AlertFact {sid: 777001}) DETACH DELETE a").consume()
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.address IN ['198.51.100.71', '198.51.100.72', '198.51.100.81', '198.51.100.82'] DETACH DELETE ip"
            ).consume()
            session.run(
                "MATCH (l2:Layer2Identifier) WHERE l2.identifier IN ['02:00:00:aa:00:01', '02:00:00:aa:00:02'] DETACH DELETE l2"
            ).consume()


# ---------------------------------------------------------------------------
# TEST H: Read queries — lookup, filters, temporal bounds, deterministic pagination
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_live_zeek_h_observation_read_queries_and_pagination(live_driver):
    """TEST H: Exact lookup, domain/sensor/Community ID/ns-range filtering, and deterministic pagination."""
    shared_cid = "1:liveReadSharedCid=="
    # 5 observations: 2 share exact same start_epoch_ns to verify deterministic observation_id tie-breaking
    lines_s1_d1 = [
        f'{{"ts":1725150000.000000001,"uid":"CReadH_01","id.orig_h":"198.51.100.91","id.orig_p":50001,"id.resp_h":"198.51.100.92","id.resp_p":443,"proto":"tcp","community_id":"{shared_cid}"}}',
        f'{{"ts":1725150000.000000001,"uid":"CReadH_02","id.orig_h":"198.51.100.91","id.orig_p":50001,"id.resp_h":"198.51.100.92","id.resp_p":443,"proto":"tcp","community_id":"{shared_cid}"}}',
        '{"ts":1725150001.000000000,"uid":"CReadH_03","id.orig_h":"198.51.100.91","id.orig_p":50002,"id.resp_h":"198.51.100.92","id.resp_p":80,"proto":"tcp","community_id":"1:liveReadOtherCid1=="}',
    ]
    lines_s2_d1 = [
        '{"ts":1725150002.000000000,"uid":"CReadH_04","id.orig_h":"198.51.100.91","id.orig_p":50003,"id.resp_h":"198.51.100.92","id.resp_p":53,"proto":"udp","community_id":"1:liveReadOtherCid2=="}',
    ]
    lines_s1_d2 = [
        f'{{"ts":1725150003.000000000,"uid":"CReadH_05","id.orig_h":"198.51.100.91","id.orig_p":50001,"id.resp_h":"198.51.100.92","id.resp_p":443,"proto":"tcp","community_id":"{shared_cid}"}}',
    ]

    obs_all = (
        list(iter_zeek_conn_lines(lines_s1_d1, sensor_id="sensor-read-a", routing_domain_id="dom-read-1"))
        + list(iter_zeek_conn_lines(lines_s2_d1, sensor_id="sensor-read-b", routing_domain_id="dom-read-1"))
        + list(iter_zeek_conn_lines(lines_s1_d2, sensor_id="sensor-read-a", routing_domain_id="dom-read-2"))
    )

    repo = Neo4jRepository(live_driver, batch_size=50)
    read_repo = Neo4jReadRepository(live_driver)

    try:
        repo.write_zeek_observations(obs_all)

        # 1. Exact lookup & missing lookup
        one = read_repo.get_flow_observation(obs_all[0].observation_id)
        assert one is not None
        assert one["zeek_uid"] == "CReadH_01"
        assert read_repo.get_flow_observation("nonexistent-observation-id") is None

        # 2. Domain filter
        d1_items, d1_total = read_repo.list_flow_observations(routing_domain_id="dom-read-1", limit=10)
        assert d1_total == 4
        assert len(d1_items) == 4

        # 3. Sensor filter
        s2_items, s2_total = read_repo.list_flow_observations(sensor_id="sensor-read-b", limit=10)
        assert s2_total == 1
        assert s2_items[0]["zeek_uid"] == "CReadH_04"

        # 4. Community ID filter — must return all 3 distinct observations without collapsing
        cid_items, cid_total = read_repo.list_flow_observations(community_id=shared_cid, limit=10)
        assert cid_total == 3
        assert {item["zeek_uid"] for item in cid_items} == {"CReadH_01", "CReadH_02", "CReadH_05"}

        # 5. Exact integer nanosecond temporal range filter
        range_items, range_total = read_repo.list_flow_observations(
            routing_domain_id="dom-read-1",
            start_epoch_ns_min=1725150001000000000,
            start_epoch_ns_max=1725150002000000000,
            limit=10,
        )
        assert range_total == 2
        assert [item["zeek_uid"] for item in range_items] == ["CReadH_03", "CReadH_04"]

        # 6. Deterministic pagination across pages
        p1, t1 = read_repo.list_flow_observations(routing_domain_id="dom-read-1", limit=2, offset=0)
        p2, t2 = read_repo.list_flow_observations(routing_domain_id="dom-read-1", limit=2, offset=2)
        p3, t3 = read_repo.list_flow_observations(routing_domain_id="dom-read-1", limit=2, offset=4)

        assert t1 == t2 == t3 == 4
        assert len(p1) == 2 and len(p2) == 2 and len(p3) == 0
        paged_ids = [item["observation_id"] for item in p1 + p2]
        full_ids = [item["observation_id"] for item in d1_items]
        assert paged_ids == full_ids
        assert len(set(paged_ids)) == 4
        # Tied timestamps on page 1 must be strictly ordered by observation_id ASC
        assert p1[0]["observation_id"] < p1[1]["observation_id"]
    finally:
        _cleanup_test_entities(
            live_driver,
            [o.observation_id for o in obs_all],
            list({o.src_scoped_id for o in obs_all} | {o.dst_scoped_id for o in obs_all}),
            ["dom-read-1", "dom-read-2"],
        )
