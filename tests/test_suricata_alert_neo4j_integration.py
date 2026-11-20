"""
Live Neo4j integration tests for Phase 3B.2 Suricata AlertDefinition and AlertEvent persistence.

Strictly opt-in via RUN_NEO4J_INTEGRATION=1 with explicit NEO4J_TEST_* credentials.
Executes against the disposable Neo4j 5.26 CI container; never targets unknown databases.

Covers mandatory live Neo4j verification cases TEST A through TEST J:
TEST A. Persist standard Suricata EVE fixture (:AlertEvent, :AlertDefinition, relationships, V1 isolation)
TEST B. Shared :AlertDefinition across multiple firings and rule revisions (immutable vs per-event metadata)
TEST C. Distinct events for identical timestamp, 5-tuple, flow_id, and SID across different log lines
TEST D. Idempotent re-import (duplicate_matched_count, zero duplicate nodes/edges)
TEST E. Immutable conflict rejection and entire-batch transaction rollback (AlertEventConflictError)
TEST F. Explicit RoutingDomain isolation for overlapping RFC 1918 subnets (no cross-domain linkage)
TEST G. Lossless high-precision Decimal timestamps, timezone-naive timestamps, and uint64 flow_id > INT64_MAX
TEST H. Read queries (get_alert_event & list_alert_events filters, numeric ns window, NULLS LAST pagination)
TEST I. Preflight MigrationRequiredError safety when unmigrated legacy IPAddress exists
TEST J. Scoped cleanup (CYPHER_SCOPED_CLEANUP clears AlertEvent/AlertDefinition safely without nuking custom labels)
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
    INT64_MAX,
    AlertEventConflictError,
    Neo4jRepository,
)
from src.graph.schema import MigrationRequiredError, ensure_schema
from src.ingestion.suricata_eve_parser import iter_suricata_eve_alert_lines
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    alert_definition_id,
    compute_alert_event_id,
    compute_v2_flow_key,
    scoped_ip_id,
)
from src.services.suricata_ingestion import ingest_suricata_eve_file

pytestmark = pytest.mark.integration

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "suricata"
STANDARD_FIXTURE = FIXTURE_DIR / "eve_standard_alerts.jsonl"
OVERLAPPING_FIXTURE = FIXTURE_DIR / "eve_overlapping_rfc1918.jsonl"


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


def _cleanup_test_entities(driver, event_ids, def_ids, scoped_ids, domain_ids):
    """Strictly scoped teardown removing only synthetic entities created by a test."""
    with driver.session() as session:
        if event_ids:
            session.run(
                "MATCH (ae:AlertEvent) WHERE ae.event_id IN $event_ids DETACH DELETE ae",
                event_ids=list(event_ids),
            ).consume()
        if def_ids:
            session.run(
                "MATCH (ad:AlertDefinition) WHERE ad.definition_id IN $def_ids "
                "AND NOT (()-[:TRIGGERED_RULE]->(ad)) DETACH DELETE ad",
                def_ids=list(def_ids),
            ).consume()
        if scoped_ids:
            session.run(
                "MATCH (ip:IPAddress) WHERE ip.scoped_id IN $scoped_ids "
                "AND NOT ((ip)--(:AlertFact)) "
                "AND NOT ((:FlowObservation)-->(ip)) "
                "AND NOT ((:AlertEvent)-->(ip)) "
                "DETACH DELETE ip",
                scoped_ids=list(scoped_ids),
            ).consume()
        if domain_ids:
            session.run(
                "MATCH (rd:RoutingDomain) WHERE rd.domain_id IN $domain_ids "
                "AND NOT ((:IPAddress)-[:IN_DOMAIN]->(rd)) DETACH DELETE rd",
                domain_ids=list(domain_ids),
            ).consume()


def _build_synthetic_alert(
    *,
    sensor_id: str,
    ruleset_namespace: str,
    log_source_id: str,
    source_record_id: str,
    routing_domain_id: str,
    src_ip: str = "198.51.100.10",
    dst_ip: str = "203.0.113.20",
    protocol: str | None = "TCP",
    src_port: int | None = 45000,
    dst_port: int | None = 443,
    flow_id: int | None = 700001,
    community_id: str | None = "1:intCid==",
    gid: int | None = 1,
    sid: int = 3001001,
    rev: int | None = 1,
    signature: str | None = "SYNTHETIC Live Test Rule",
    category: str | None = "Misc Activity",
    severity: int | None = 2,
    action: str | None = "allowed",
    timestamp_source: str = "2026-11-20T15:00:00.000000+0000",
    timestamp_epoch_decimal: Decimal | None = Decimal("1795186800.000000"),
) -> SuricataAlertObservation:
    norm_domain = routing_domain_id.strip().lower()
    src_scoped = scoped_ip_id(norm_domain, src_ip)
    dst_scoped = scoped_ip_id(norm_domain, dst_ip)
    flow_key = compute_v2_flow_key(
        src_scoped, dst_scoped, protocol or "UNKNOWN", src_port, dst_port
    )
    def_id = alert_definition_id("suricata", ruleset_namespace, gid, sid)
    ev_id = compute_alert_event_id(
        source_type="suricata",
        sensor_id=sensor_id,
        source_record_id=source_record_id,
        timestamp=timestamp_source,
        def_id=def_id,
        flow_reference=flow_key,
    )
    return SuricataAlertObservation(
        event_id=ev_id,
        alert_definition_id=def_id,
        source_record_id=source_record_id,
        log_source_id=log_source_id,
        sensor_id=sensor_id.strip().lower(),
        ruleset_namespace=ruleset_namespace.strip().lower(),
        routing_domain_id=norm_domain,
        flow_key=flow_key,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        timestamp_source=timestamp_source,
        timestamp_epoch_decimal=timestamp_epoch_decimal,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        flow_id=flow_id,
        community_id=community_id,
        gid=gid,
        sid=sid,
        rev=rev,
        signature=signature,
        category=category,
        severity=severity,
        action=action,
        source_type="suricata",
    )


def test_a_persist_standard_suricata_fixture_and_isolation(live_driver):
    """TEST A: End-to-end standard fixture ingestion, AlertDefinition purity, IPv6 & V1 isolation."""
    domain = "it-3b2-test-a"
    log_source = "it-3b2-std-a"
    namespace = "it-et-open-a"
    sensor = "it-suricata-a"

    with live_driver.session() as session:
        pre_af = session.run("MATCH (n:AlertFact) RETURN count(n) AS c").single()["c"]
        pre_fo = session.run("MATCH (n:FlowObservation) RETURN count(n) AS c").single()["c"]

    event_ids, def_ids, scoped_ids = set(), set(), set()
    try:
        res = ingest_suricata_eve_file(
            STANDARD_FIXTURE,
            sensor_id=sensor,
            ruleset_namespace=namespace,
            log_source_id=log_source,
            routing_domain_id=domain,
            driver=live_driver,
        )
        assert res.parse_summary.valid_records == 5
        assert res.parse_summary.ignored_non_alert_records == 3
        assert res.persistence_summary.total_received == 5
        assert res.persistence_summary.created_count == 5
        assert res.persistence_summary.duplicate_matched_count == 0
        assert res.persistence_summary.definitions_created_count == 5

        with live_driver.session() as session:
            rows = list(
                session.run(
                    """
                    MATCH (ae:AlertEvent {routing_domain_id: $domain})
                    MATCH (ae)-[:TRIGGERED_RULE]->(ad:AlertDefinition)
                    MATCH (ae)-[:HAS_SOURCE]->(s:IPAddress)-[:IN_DOMAIN]->(rd:RoutingDomain {domain_id: $domain})
                    MATCH (ae)-[:HAS_DESTINATION]->(d:IPAddress)-[:IN_DOMAIN]->(rd)
                    RETURN ae, ad, properties(ad) AS ad_props, s.scoped_id AS s_sid, d.scoped_id AS d_sid
                    """,
                    domain=domain,
                )
            )
            assert len(rows) == 5
            for r in rows:
                ae = r["ae"]
                ad_props = r["ad_props"]
                event_ids.add(ae["event_id"])
                def_ids.add(ad_props["definition_id"])
                scoped_ids.update([r["s_sid"], r["d_sid"]])

                # AlertDefinition must contain ONLY stable rule identity properties
                assert set(ad_props.keys()).issubset(
                    {"definition_id", "engine", "ruleset_namespace", "gid", "sid"}
                )
                for mutable_key in ("rev", "signature", "category", "severity", "action"):
                    assert mutable_key not in ad_props

            # Verify missing gid=None vs explicit gid=1 preserved cleanly
            sids_by_def = {r["ad_props"]["sid"]: r["ad_props"] for r in rows}
            assert "gid" not in sids_by_def[9900001]
            assert sids_by_def[9900001]["definition_id"] == f"suricata:{namespace}:none:9900001"
            assert sids_by_def[2001219]["gid"] == 1
            assert sids_by_def[2001219]["definition_id"] == f"suricata:{namespace}:1:2001219"

            # Verify IPv6 canonicalization
            assert f"{domain}#2001:db8::1" in scoped_ids
            assert f"{domain}#2001:db8::2" in scoped_ids

            # Ensure V1 AlertFact & Phase 3A FlowObservation counts were not altered
            post_af = session.run("MATCH (n:AlertFact) RETURN count(n) AS c").single()["c"]
            post_fo = session.run("MATCH (n:FlowObservation) RETURN count(n) AS c").single()["c"]
            assert post_af == pre_af
            assert post_fo == pre_fo
    finally:
        _cleanup_test_entities(live_driver, event_ids, def_ids, scoped_ids, [domain])


def test_b_shared_definition_across_revisions_and_repeated_firings(live_driver):
    """TEST B: Repeated firings and rule rev changes share one AlertDefinition while preserving per-event metadata."""
    domain = "it-3b2-test-b"
    ns = "it-et-open-b"
    a1 = _build_synthetic_alert(
        sensor_id="s-b",
        ruleset_namespace=ns,
        log_source_id="ls-b",
        source_record_id="ls-b:line:1:fp1",
        routing_domain_id=domain,
        sid=2001219,
        rev=20,
        severity=2,
        signature="SYNTHETIC Rule Rev 20",
        timestamp_source="2026-11-20T15:01:00.000000+0000",
        timestamp_epoch_decimal=Decimal("1795186860.000000"),
    )
    a2 = _build_synthetic_alert(
        sensor_id="s-b",
        ruleset_namespace=ns,
        log_source_id="ls-b",
        source_record_id="ls-b:line:2:fp2",
        routing_domain_id=domain,
        sid=2001219,
        rev=21,
        severity=1,
        signature="SYNTHETIC Rule Rev 21",
        timestamp_source="2026-11-20T15:02:00.000000+0000",
        timestamp_epoch_decimal=Decimal("1795186920.000000"),
    )
    assert a1.alert_definition_id == a2.alert_definition_id

    repo = Neo4jRepository(live_driver)
    read_repo = Neo4jReadRepository(live_driver)
    try:
        summary = repo.write_suricata_alert_events([a1, a2])
        assert summary.created_count == 2
        assert summary.definitions_created_count == 1
        assert summary.definitions_matched_count == 0

        with live_driver.session() as session:
            def_count = session.run(
                "MATCH (ad:AlertDefinition {definition_id: $def_id}) "
                "OPTIONAL MATCH (ae:AlertEvent)-[:TRIGGERED_RULE]->(ad) "
                "RETURN count(DISTINCT ad) AS defs, count(DISTINCT ae) AS events",
                def_id=a1.alert_definition_id,
            ).single()
            assert def_count["defs"] == 1
            assert def_count["events"] == 2

        got1 = read_repo.get_alert_event(a1.event_id)
        got2 = read_repo.get_alert_event(a2.event_id)
        assert got1["rev"] == 20 and got1["severity"] == 2 and got1["signature"] == "SYNTHETIC Rule Rev 20"
        assert got2["rev"] == 21 and got2["severity"] == 1 and got2["signature"] == "SYNTHETIC Rule Rev 21"
    finally:
        _cleanup_test_entities(
            live_driver,
            [a1.event_id, a2.event_id],
            [a1.alert_definition_id],
            [a1.src_scoped_id, a1.dst_scoped_id],
            [domain],
        )


def test_c_identical_tuple_timestamp_flow_id_sid_on_distinct_lines(live_driver):
    """TEST C: Two identical EVE alert payloads on distinct lines create 2 distinct AlertEvents."""
    domain = "it-3b2-test-c"
    eve_obj = {
        "timestamp": "2026-11-20T15:05:00.000000+0000",
        "flow_id": 880088,
        "event_type": "alert",
        "src_ip": "198.51.100.30",
        "src_port": 50000,
        "dest_ip": "203.0.113.40",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {"gid": 1, "signature_id": 3002002, "rev": 1, "signature": "SYNTHETIC Duplicate Firing"},
    }
    raw_line = json.dumps(eve_obj)
    events = list(
        iter_suricata_eve_alert_lines(
            [raw_line, raw_line],
            sensor_id="s-c",
            ruleset_namespace="it-ns-c",
            log_source_id="ls-c",
            routing_domain_id=domain,
        )
    )
    assert len(events) == 2
    assert events[0].event_id != events[1].event_id

    repo = Neo4jRepository(live_driver)
    try:
        summary = repo.write_suricata_alert_events(events)
        assert summary.created_count == 2
        assert summary.definitions_created_count == 1
        with live_driver.session() as session:
            cnt = session.run(
                "MATCH (ae:AlertEvent {routing_domain_id: $domain}) RETURN count(ae) AS c",
                domain=domain,
            ).single()["c"]
            assert cnt == 2
    finally:
        _cleanup_test_entities(
            live_driver,
            [e.event_id for e in events],
            [events[0].alert_definition_id],
            [events[0].src_scoped_id, events[0].dst_scoped_id],
            [domain],
        )


def test_d_idempotent_reimport(live_driver):
    """TEST D: Re-importing identical EVE file creates 0 new nodes/edges and reports duplicate matches."""
    domain = "it-3b2-test-d"
    kwargs = dict(
        sensor_id="it-s-d",
        ruleset_namespace="it-ns-d",
        log_source_id="it-ls-d",
        routing_domain_id=domain,
        driver=live_driver,
    )
    event_ids, def_ids, scoped_ids = set(), set(), set()
    try:
        first = ingest_suricata_eve_file(STANDARD_FIXTURE, **kwargs)
        assert first.persistence_summary.created_count == 5
        assert first.persistence_summary.definitions_created_count == 5

        with live_driver.session() as session:
            before_nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            before_rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]

        second = ingest_suricata_eve_file(STANDARD_FIXTURE, **kwargs)
        assert second.persistence_summary.total_received == 5
        assert second.persistence_summary.created_count == 0
        assert second.persistence_summary.duplicate_matched_count == 5
        assert second.persistence_summary.definitions_created_count == 0
        assert second.persistence_summary.definitions_matched_count == 5

        with live_driver.session() as session:
            after_nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            after_rels = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            assert after_nodes == before_nodes
            assert after_rels == before_rels

            recs = session.run(
                "MATCH (ae:AlertEvent {routing_domain_id: $domain}) "
                "RETURN ae.event_id AS eid, ae.alert_definition_id AS did, ae.src_scoped_id AS s, ae.dst_scoped_id AS d",
                domain=domain,
            )
            for rec in recs:
                event_ids.add(rec["eid"])
                def_ids.add(rec["did"])
                scoped_ids.update([rec["s"], rec["d"]])
    finally:
        _cleanup_test_entities(live_driver, event_ids, def_ids, scoped_ids, [domain])


def test_e_conflict_rejection_and_batch_rollback(live_driver):
    """TEST E: Conflicting event_id rejects with AlertEventConflictError and rolls back entire batch."""
    domain = "it-3b2-test-e"
    ns = "it-ns-e"
    e1 = _build_synthetic_alert(
        sensor_id="s-e",
        ruleset_namespace=ns,
        log_source_id="ls-e",
        source_record_id="ls-e:line:1:a",
        routing_domain_id=domain,
        sid=3005001,
        rev=1,
    )
    e2_good = _build_synthetic_alert(
        sensor_id="s-e",
        ruleset_namespace=ns,
        log_source_id="ls-e",
        source_record_id="ls-e:line:2:b",
        routing_domain_id=domain,
        sid=3005002,
        rev=1,
    )
    e1_conflict = replace(e1, rev=99, signature="TAMPERED")

    repo = Neo4jRepository(live_driver, batch_size=2)
    try:
        repo.write_suricata_alert_events([e1], batch_size=1)

        # Second write sends batch [e2_good, e1_conflict] together in one batch: e2_good MUST roll back!
        with pytest.raises(AlertEventConflictError) as exc_info:
            repo.write_suricata_alert_events([e2_good, e1_conflict], batch_size=2)

        assert e1.event_id in exc_info.value.conflicting_event_ids
        assert exc_info.value.batches_committed == 0

        read_repo = Neo4jReadRepository(live_driver)
        assert read_repo.get_alert_event(e2_good.event_id) is None
        orig = read_repo.get_alert_event(e1.event_id)
        assert orig is not None
        assert orig["rev"] == 1
        assert orig["signature"] == "SYNTHETIC Live Test Rule"
    finally:
        _cleanup_test_entities(
            live_driver,
            [e1.event_id, e2_good.event_id],
            [e1.alert_definition_id, e2_good.alert_definition_id],
            [e1.src_scoped_id, e1.dst_scoped_id],
            [domain],
        )


def test_f_explicit_routing_domain_overlapping_rfc1918_isolation(live_driver):
    """TEST F: Overlapping RFC 1918 subnets across corp-a and corp-b stay strictly domain-isolated."""
    domain_a = "it-3b2-corp-a"
    domain_b = "it-3b2-corp-b"
    event_ids, def_ids, scoped_ids = set(), set(), set()

    try:
        res_a = ingest_suricata_eve_file(
            OVERLAPPING_FIXTURE,
            sensor_id="s-corp-a",
            ruleset_namespace="it-ns-f",
            log_source_id="ls-corp-a",
            routing_domain_id=domain_a,
            driver=live_driver,
        )
        res_b = ingest_suricata_eve_file(
            OVERLAPPING_FIXTURE,
            sensor_id="s-corp-b",
            ruleset_namespace="it-ns-f",
            log_source_id="ls-corp-b",
            routing_domain_id=domain_b,
            driver=live_driver,
        )
        assert res_a.persistence_summary.created_count == 1
        assert res_b.persistence_summary.created_count == 1

        with live_driver.session() as session:
            cross_links = session.run(
                """
                MATCH (ae:AlertEvent)-[:HAS_SOURCE|HAS_DESTINATION]->(ip:IPAddress)
                WHERE ae.routing_domain_id IN [$da, $db]
                  AND ae.routing_domain_id <> ip.routing_domain_id
                RETURN count(ae) AS c
                """,
                da=domain_a,
                db=domain_b,
            ).single()["c"]
            assert cross_links == 0

            ips = list(
                session.run(
                    "MATCH (ip:IPAddress) WHERE ip.routing_domain_id IN [$da, $db] "
                    "RETURN ip.scoped_id AS sid, ip.address AS addr, ip.routing_domain_id AS dom",
                    da=domain_a,
                    db=domain_b,
                )
            )
            assert len(ips) == 4
            for r in ips:
                scoped_ids.add(r["sid"])

            evs = list(
                session.run(
                    "MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN [$da, $db] "
                    "RETURN ae.event_id AS eid, ae.alert_definition_id AS did",
                    da=domain_a,
                    db=domain_b,
                )
            )
            assert len(evs) == 2
            for r in evs:
                event_ids.add(r["eid"])
                def_ids.add(r["did"])
    finally:
        _cleanup_test_entities(live_driver, event_ids, def_ids, scoped_ids, [domain_a, domain_b])


def test_g_lossless_timestamps_naive_and_unsigned_uint64_flow_id(live_driver):
    """TEST G: Lossless high-precision timestamps, sub-ns non-truncation, naive timestamps, and flow_id > INT64_MAX."""
    domain = "it-3b2-test-g"
    ns = "it-ns-g"
    big_flow_id_1 = INT64_MAX + 12345  # 9223372036854788152 (> signed int64)
    big_flow_id_max = 2**64 - 1        # 18446744073709551615 (max uint64)

    e_precise = _build_synthetic_alert(
        sensor_id="s-g",
        ruleset_namespace=ns,
        log_source_id="ls-g",
        source_record_id="ls-g:line:1:p",
        routing_domain_id=domain,
        sid=3007001,
        flow_id=big_flow_id_1,
        timestamp_source="2026-11-20T15:10:00.123456789+0000",
        timestamp_epoch_decimal=Decimal("1795187400.123456789"),
    )
    e_subns = _build_synthetic_alert(
        sensor_id="s-g",
        ruleset_namespace=ns,
        log_source_id="ls-g",
        source_record_id="ls-g:line:2:s",
        routing_domain_id=domain,
        sid=3007002,
        flow_id=42,
        timestamp_source="2026-11-20T15:10:00.123456789123+0000",
        timestamp_epoch_decimal=Decimal("1795187400.123456789123"),
    )
    e_naive = _build_synthetic_alert(
        sensor_id="s-g",
        ruleset_namespace=ns,
        log_source_id="ls-g",
        source_record_id="ls-g:line:3:n",
        routing_domain_id=domain,
        sid=3007003,
        flow_id=big_flow_id_max,
        timestamp_source="2026-11-20T15:10:01.000000",
        timestamp_epoch_decimal=None,
    )

    repo = Neo4jRepository(live_driver)
    read_repo = Neo4jReadRepository(live_driver)
    try:
        summary = repo.write_suricata_alert_events([e_precise, e_subns, e_naive])
        assert summary.created_count == 3

        got_p = read_repo.get_alert_event(e_precise.event_id)
        assert got_p["timestamp_source"] == "2026-11-20T15:10:00.123456789+0000"
        assert got_p["timestamp_epoch_decimal"] == "1795187400.123456789"
        assert got_p["timestamp_epoch_ns"] == 1795187400123456789
        assert got_p["flow_id"] == str(big_flow_id_1)

        got_s = read_repo.get_alert_event(e_subns.event_id)
        assert got_s["timestamp_source"] == "2026-11-20T15:10:00.123456789123+0000"
        assert got_s["timestamp_epoch_decimal"] == "1795187400.123456789123"
        assert got_s["timestamp_epoch_ns"] is None
        assert got_s["flow_id"] == "42"

        got_n = read_repo.get_alert_event(e_naive.event_id)
        assert got_n["timestamp_source"] == "2026-11-20T15:10:01.000000"
        assert got_n["timestamp_epoch_decimal"] is None
        assert got_n["timestamp_epoch_ns"] is None
        assert got_n["flow_id"] == "18446744073709551615"
    finally:
        _cleanup_test_entities(
            live_driver,
            [e_precise.event_id, e_subns.event_id, e_naive.event_id],
            [e_precise.alert_definition_id, e_subns.alert_definition_id, e_naive.alert_definition_id],
            [e_precise.src_scoped_id, e_precise.dst_scoped_id],
            [domain],
        )


def test_h_read_repository_filters_and_pagination(live_driver):
    """TEST H: list_alert_events supports indexed filters, numeric ns window, and NULLS LAST pagination."""
    domain = "it-3b2-test-h"
    ns = "it-ns-h"
    t1_ns = 1795188000000000000
    t2_ns = 1795188005000000000

    e1 = _build_synthetic_alert(
        sensor_id="s-h",
        ruleset_namespace=ns,
        log_source_id="ls-h",
        source_record_id="ls-h:1",
        routing_domain_id=domain,
        sid=3008001,
        flow_id=2**63 + 7,
        community_id="1:h1==",
        timestamp_source="2026-11-20T15:20:00+0000",
        timestamp_epoch_decimal=Decimal("1795188000"),
    )
    e2 = _build_synthetic_alert(
        sensor_id="s-h",
        ruleset_namespace=ns,
        log_source_id="ls-h",
        source_record_id="ls-h:2",
        routing_domain_id=domain,
        sid=3008002,
        flow_id=888,
        community_id="1:h2==",
        timestamp_source="2026-11-20T15:20:05+0000",
        timestamp_epoch_decimal=Decimal("1795188005"),
    )
    e3_naive = _build_synthetic_alert(
        sensor_id="s-h",
        ruleset_namespace=ns,
        log_source_id="ls-h",
        source_record_id="ls-h:3",
        routing_domain_id=domain,
        sid=3008003,
        flow_id=999,
        community_id="1:h3==",
        timestamp_source="2026-11-20T15:20:10",
        timestamp_epoch_decimal=None,
    )

    repo = Neo4jRepository(live_driver)
    read_repo = Neo4jReadRepository(live_driver)
    try:
        repo.write_suricata_alert_events([e3_naive, e2, e1])

        # Default ordering: t1, t2, then naive (NULLS LAST)
        all_items, all_total = read_repo.list_alert_events(routing_domain_id=domain)
        assert all_total == 3
        assert [item["event_id"] for item in all_items] == [e1.event_id, e2.event_id, e3_naive.event_id]

        # Pagination check
        p1, p1_total = read_repo.list_alert_events(routing_domain_id=domain, limit=2, offset=1)
        assert p1_total == 3
        assert [item["event_id"] for item in p1] == [e2.event_id, e3_naive.event_id]

        # Temporal window excludes naive e3_naive
        windowed, w_total = read_repo.list_alert_events(
            routing_domain_id=domain, start_epoch_ns=t1_ns, end_epoch_ns=t2_ns
        )
        assert w_total == 2
        assert [item["event_id"] for item in windowed] == [e1.event_id, e2.event_id]

        # Filter by uint64 flow_id (both int and str), community_id, sid, sensor_id, flow_key
        by_fid_int, fid_tot = read_repo.list_alert_events(routing_domain_id=domain, flow_id=2**63 + 7)
        assert fid_tot == 1 and by_fid_int[0]["event_id"] == e1.event_id
        by_fid_str, _ = read_repo.list_alert_events(routing_domain_id=domain, flow_id=str(2**63 + 7))
        assert len(by_fid_str) == 1 and by_fid_str[0]["event_id"] == e1.event_id

        by_cid, _ = read_repo.list_alert_events(routing_domain_id=domain, community_id="1:h2==")
        assert len(by_cid) == 1 and by_cid[0]["event_id"] == e2.event_id

        by_sid, _ = read_repo.list_alert_events(routing_domain_id=domain, sid=3008002, sensor_id="s-h")
        assert len(by_sid) == 1 and by_sid[0]["event_id"] == e2.event_id

        by_fk, fk_tot = read_repo.list_alert_events(routing_domain_id=domain, flow_key=e1.flow_key)
        assert fk_tot == 3
    finally:
        _cleanup_test_entities(
            live_driver,
            [e1.event_id, e2.event_id, e3_naive.event_id],
            [e1.alert_definition_id, e2.alert_definition_id, e3_naive.alert_definition_id],
            [e1.src_scoped_id, e1.dst_scoped_id],
            [domain],
        )


def test_i_preflight_migration_required_blocks_suricata_ingestion(live_driver):
    """TEST I: Ingestion blocks cleanly with MigrationRequiredError if unmigrated legacy IPAddress exists."""
    legacy_addr = "198.51.100.251"
    domain = "it-3b2-test-i"
    with live_driver.session() as session:
        session.run(
            "CREATE (ip:IPAddress {address: $addr})",
            addr=legacy_addr,
        ).consume()

    try:
        with pytest.raises(MigrationRequiredError) as exc_info:
            ingest_suricata_eve_file(
                OVERLAPPING_FIXTURE,
                sensor_id="s-i",
                ruleset_namespace="it-ns-i",
                log_source_id="ls-i",
                routing_domain_id=domain,
                driver=live_driver,
            )
        assert exc_info.value.unmigrated_count >= 1
        with live_driver.session() as session:
            cnt = session.run(
                "MATCH (ae:AlertEvent {routing_domain_id: $domain}) RETURN count(ae) AS c",
                domain=domain,
            ).single()["c"]
            assert cnt == 0
    finally:
        with live_driver.session() as session:
            session.run(
                "MATCH (ip:IPAddress {address: $addr}) WHERE ip.scoped_id IS NULL DETACH DELETE ip",
                addr=legacy_addr,
            ).consume()


def test_j_scoped_cleanup_clears_alert_events_and_definitions_without_touching_custom_labels(live_driver):
    """TEST J: replace_workspace_data clears AlertEvent & AlertDefinition via CYPHER_SCOPED_CLEANUP safely."""
    domain = "it-3b2-test-j"
    ev = _build_synthetic_alert(
        sensor_id="s-j",
        ruleset_namespace="it-ns-j",
        log_source_id="ls-j",
        source_record_id="ls-j:1",
        routing_domain_id=domain,
        sid=3009001,
    )
    canary_id = "it-3b2-canary-node"

    repo = Neo4jRepository(live_driver)
    repo.write_suricata_alert_events([ev])

    with live_driver.session() as session:
        session.run(
            "CREATE (:IntegrationTestCanary {canary_id: $cid})",
            cid=canary_id,
        ).consume()

    try:
        persisted_traffic, persisted_alerts = repo.replace_workspace_data(
            traffic_records=[],
            alert_records=[],
            domain_id="default",
        )
        assert (persisted_traffic, persisted_alerts) == (0, 0)

        with live_driver.session() as session:
            ev_cnt = session.run(
                "MATCH (ae:AlertEvent) WHERE ae.event_id = $eid RETURN count(ae) AS c",
                eid=ev.event_id,
            ).single()["c"]
            def_cnt = session.run(
                "MATCH (ad:AlertDefinition) WHERE ad.definition_id = $did RETURN count(ad) AS c",
                did=ev.alert_definition_id,
            ).single()["c"]
            canary_cnt = session.run(
                "MATCH (c:IntegrationTestCanary {canary_id: $cid}) RETURN count(c) AS c",
                cid=canary_id,
            ).single()["c"]
            default_rd_cnt = session.run(
                "MATCH (rd:RoutingDomain {domain_id: 'default'}) RETURN count(rd) AS c"
            ).single()["c"]

            assert ev_cnt == 0
            assert def_cnt == 0
            assert canary_cnt == 1
            assert default_rd_cnt == 1
    finally:
        with live_driver.session() as session:
            session.run(
                "MATCH (c:IntegrationTestCanary {canary_id: $cid}) DETACH DELETE c",
                cid=canary_id,
            ).consume()
        _cleanup_test_entities(
            live_driver,
            [ev.event_id],
            [ev.alert_definition_id],
            [ev.src_scoped_id, ev.dst_scoped_id],
            [domain],
        )
