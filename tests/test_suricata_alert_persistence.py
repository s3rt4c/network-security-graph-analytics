"""
Unit tests for Phase 3B.2 Suricata AlertDefinition and AlertEvent Neo4j persistence,
schema DDL, read repository queries, and streaming ingestion entrypoint.

Covers scenarios A through O:
A. Schema constraints, indexes, and scoped cleanup Cypher definitions
B. Payload normalization and domain/IP canonicalization
C. Lossless uint64 flow_id decimal string preservation (including > INT64_MAX)
D. Exact Decimal epoch / nanosecond preservation and timezone-naive timestamp policy
E. Validation of required/optional int64 bounds, ports, IP family, and ID consistency
F. Missing GID vs GID=1 distinct AlertDefinition identity preserved cleanly
G. Deterministic immutable payload_digest sensitivity across all event fields
H. Conflict detection (AlertEventConflictError) and intra-batch rollback guarantees
I. Intra-batch duplicate deduplication, multi-batch streaming, and empty-stream safety
J. Cypher graph model isolation (no FlowObservation links, no V1 edge replacement, no AlertDefinition mutation)
K. Neo4jReadRepository get_alert_event & list_alert_events filtering and NULLS LAST pagination
L. Streaming ingestion entrypoint (ingest_suricata_eve_file), ensure_schema & MigrationRequiredError
M. CLI entrypoint (python -m src.services.suricata_ingestion) success & error exit codes
N. Public package exports in src.graph
O. V1 isolation (AlertFact/TrafficRecord contracts unchanged)
"""

from dataclasses import replace
from decimal import Decimal, localcontext
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import src.graph as graph_pkg
from src.graph.read_repository import Neo4jReadRepository
from src.graph.repository import (
    CYPHER_SCOPED_CLEANUP,
    CYPHER_WRITE_ALERT_BATCH,
    CYPHER_WRITE_SURICATA_ALERT_BATCH,
    CYPHER_WRITE_TRAFFIC_BATCH,
    INT64_MAX,
    AlertEventConflictError,
    AlertEventPersistenceSummary,
    Neo4jRepository,
    compute_alert_event_payload_digest,
    suricata_alert_to_payload,
)
from src.graph.schema import MigrationRequiredError, SCHEMA_STATEMENTS
from src.ingestion.models import AlertRecord
from src.ingestion.suricata_eve_parser import iter_suricata_eve_alert_lines
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    alert_definition_id,
    compute_alert_event_id,
    compute_v2_flow_key,
    scoped_ip_id,
)
from src.services.suricata_ingestion import (
    SuricataIngestionResult,
    ingest_suricata_eve_file,
    main as suricata_cli_main,
)

FIXTURE_STANDARD = Path(__file__).parent / "fixtures" / "suricata" / "eve_standard_alerts.jsonl"


def _make_alert_obs(
    *,
    sensor_id: str = "sensor-dmz-01",
    ruleset_namespace: str = "et-open",
    log_source_id: str = "eve-dmz-01",
    source_record_id: str = "eve-dmz-01:line:1:abc123",
    routing_domain_id: str = "corp-a",
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.20",
    protocol: str | None = "TCP",
    src_port: int | None = 54321,
    dst_port: int | None = 443,
    flow_id: int | None = 1001001,
    community_id: str | None = "1:syntheticCid==",
    gid: int | None = 1,
    sid: int = 2001219,
    rev: int | None = 20,
    signature: str | None = "SYNTHETIC Test Alert",
    category: str | None = "Attempted Information Leak",
    severity: int | None = 2,
    action: str | None = "allowed",
    app_proto: str | None = "tls",
    direction: str | None = "to_server",
    tx_id: int | None = 0,
    pcap_cnt: int | None = 42,
    timestamp_source: str = "2026-11-20T14:15:30.123456+0000",
    timestamp_epoch_decimal: Decimal | None = Decimal("1795184130.123456"),
    source_type: str = "suricata",
    source_provenance: str | None = "unit-test",
) -> SuricataAlertObservation:
    norm_domain = routing_domain_id.strip().lower()
    src_scoped = scoped_ip_id(norm_domain, src_ip)
    dst_scoped = scoped_ip_id(norm_domain, dst_ip)
    flow_key = compute_v2_flow_key(
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        protocol=protocol or "UNKNOWN",
        src_port=src_port,
        dst_port=dst_port,
    )
    def_id = alert_definition_id(
        engine=source_type,
        ruleset_namespace=ruleset_namespace,
        gid=gid,
        sid=sid,
    )
    ev_id = compute_alert_event_id(
        source_type=source_type,
        sensor_id=sensor_id,
        source_record_id=source_record_id,
        timestamp=timestamp_source,
        def_id=def_id,
        flow_reference=flow_key,
        source_provenance=source_provenance,
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
        app_proto=app_proto,
        direction=direction,
        tx_id=tx_id,
        pcap_cnt=pcap_cnt,
        source_type=source_type,
        source_provenance=source_provenance,
    )


# ---------------------------------------------------------------------------
# A. Schema DDL & Scoped Cleanup
# ---------------------------------------------------------------------------

def test_a_schema_constraints_and_indexes_for_suricata():
    text = " ".join(SCHEMA_STATEMENTS)
    assert "CONSTRAINT alert_definition_unique" in text
    assert "FOR (ad:AlertDefinition) REQUIRE ad.definition_id IS UNIQUE" in text
    assert "CONSTRAINT alert_event_unique" in text
    assert "FOR (ae:AlertEvent) REQUIRE ae.event_id IS UNIQUE" in text
    assert "INDEX alert_event_flow_key_index" in text
    assert "FOR (ae:AlertEvent) ON (ae.flow_key)" in text
    assert "INDEX alert_event_community_id_index" in text
    assert "FOR (ae:AlertEvent) ON (ae.community_id)" in text
    assert "INDEX alert_event_flow_id_index" in text
    assert "FOR (ae:AlertEvent) ON (ae.flow_id)" in text
    assert "INDEX alert_event_sensor_id_index" in text
    assert "FOR (ae:AlertEvent) ON (ae.sensor_id)" in text
    assert "INDEX alert_event_routing_domain_index" in text
    assert "FOR (ae:AlertEvent) ON (ae.routing_domain_id)" in text
    assert "INDEX alert_event_timestamp_epoch_ns_index" in text
    assert "FOR (ae:AlertEvent) ON (ae.timestamp_epoch_ns)" in text


def test_a_scoped_cleanup_includes_alert_event_and_definition():
    for label in (
        "n:IPAddress",
        "n:Layer2Identifier",
        "n:AlertFact",
        "n:RoutingDomain",
        "n:FlowObservation",
        "n:AlertEvent",
        "n:AlertDefinition",
    ):
        assert label in CYPHER_SCOPED_CLEANUP


def test_a_alert_definition_cypher_only_stores_stable_identity_fields():
    # Mutable rule fields must never be set on AlertDefinition node (ad.*)
    assert "ad.definition_id" not in CYPHER_WRITE_SURICATA_ALERT_BATCH or "MERGE (ad:AlertDefinition {definition_id: row.alert_definition_id})" in CYPHER_WRITE_SURICATA_ALERT_BATCH
    for stable_prop in ("ad.engine", "ad.ruleset_namespace", "ad.gid", "ad.sid"):
        assert stable_prop in CYPHER_WRITE_SURICATA_ALERT_BATCH
    for mutable_prop in ("ad.rev", "ad.signature", "ad.category", "ad.severity", "ad.action"):
        assert mutable_prop not in CYPHER_WRITE_SURICATA_ALERT_BATCH
    for event_prop in ("ae.rev", "ae.signature", "ae.category", "ae.severity", "ae.action"):
        assert event_prop in CYPHER_WRITE_SURICATA_ALERT_BATCH


# ---------------------------------------------------------------------------
# B. Payload Normalization & IP Canonicalization
# ---------------------------------------------------------------------------

def test_b_payload_normalizes_and_canonicalizes_ipv6():
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
    canon_src = "2001:db8::1"
    canon_dst = "2001:db8::2"
    src_scoped = scoped_ip_id("dmz", canon_src)
    dst_scoped = scoped_ip_id("dmz", canon_dst)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, "TCP", 60000, 80)
    def_id = alert_definition_id("suricata", "et-open", 1, 2010002)
    ev_id = compute_alert_event_id("suricata", "sensor-1", "src:line:1:fp", "2026-11-20T14:15:32+0000", def_id, fk)

    obs = SuricataAlertObservation(
        event_id=ev_id,
        alert_definition_id=def_id,
        source_record_id="src:line:1:fp",
        log_source_id="src",
        sensor_id="Sensor-1",
        ruleset_namespace="ET-OPEN",
        routing_domain_id="DMZ",
        flow_key=fk,
        src_ip=expanded,
        dst_ip="2001:0db8:0000:0000:0000:0000:0000:0002",
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        timestamp_source="2026-11-20T14:15:32+0000",
        timestamp_epoch_decimal=Decimal("1795184132"),
        protocol="tcp",
        src_port=60000,
        dst_port=80,
        gid=1,
        sid=2010002,
    )
    payload = suricata_alert_to_payload(obs)
    assert payload["src_ip"] == canon_src
    assert payload["dst_ip"] == canon_dst
    assert payload["sensor_id"] == "sensor-1"
    assert payload["ruleset_namespace"] == "et-open"
    assert payload["routing_domain_id"] == "dmz"
    assert payload["protocol"] == "TCP"
    assert len(payload["payload_digest"]) == 64


# ---------------------------------------------------------------------------
# C. Lossless uint64 flow_id Preservation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("flow_id", "expected"),
    [
        (None, None),
        (0, "0"),
        (INT64_MAX, str(INT64_MAX)),
        (2**63, "9223372036854775808"),
        (2**64 - 1, "18446744073709551615"),
    ],
)
def test_c_flow_id_stored_losslessly_as_decimal_string(flow_id, expected):
    obs = _make_alert_obs(flow_id=flow_id)
    payload = suricata_alert_to_payload(obs)
    assert payload["flow_id"] == expected
    if expected is not None:
        assert isinstance(payload["flow_id"], str)


@pytest.mark.parametrize("bad_flow_id", [-1, True, False, 1.5, "12345"])
def test_c_invalid_flow_id_rejected(bad_flow_id):
    obs = _make_alert_obs(flow_id=10)
    bad = replace(obs, flow_id=bad_flow_id)
    with pytest.raises(ValueError, match="flow_id"):
        suricata_alert_to_payload(bad)


# ---------------------------------------------------------------------------
# D. Exact Temporal & Naive Timestamp Policy
# ---------------------------------------------------------------------------

def test_d_high_precision_decimal_epoch_preserved_under_low_context():
    obs = _make_alert_obs(
        timestamp_source="2026-11-20T14:15:32.123456789+0000",
        timestamp_epoch_decimal=Decimal("1795184132.123456789"),
    )
    with localcontext() as ctx:
        ctx.prec = 6  # Deliberately tiny context precision; helper must not round!
        payload = suricata_alert_to_payload(obs)

    assert payload["timestamp_source"] == "2026-11-20T14:15:32.123456789+0000"
    assert payload["timestamp_epoch_decimal"] == "1795184132.123456789"
    assert payload["timestamp_epoch_ns"] == 1795184132123456789


def test_d_naive_timestamp_retains_source_and_leaves_epoch_and_ns_none():
    obs = _make_alert_obs(
        timestamp_source="2026-11-20T14:15:32.123456",
        timestamp_epoch_decimal=None,
    )
    payload = suricata_alert_to_payload(obs)
    assert payload["timestamp_source"] == "2026-11-20T14:15:32.123456"
    assert payload["timestamp_epoch_decimal"] is None
    assert payload["timestamp_epoch_ns"] is None


@pytest.mark.parametrize(
    "bad_epoch",
    [1795184132.5, Decimal("NaN"), Decimal("Infinity"), Decimal("-1"), True],
)
def test_d_invalid_epoch_rejected(bad_epoch):
    obs = replace(_make_alert_obs(), timestamp_epoch_decimal=bad_epoch)
    with pytest.raises((ValueError, TypeError)):
        suricata_alert_to_payload(obs)


def test_d_sub_ns_and_out_of_int64_range_epochs_preserve_decimal_without_truncating_ns():
    sub_ns = _make_alert_obs(
        timestamp_source="2026-11-20T14:15:32.123456789123+0000",
        timestamp_epoch_decimal=Decimal("1795184132.123456789123"),
    )
    p_sub = suricata_alert_to_payload(sub_ns)
    assert p_sub["timestamp_epoch_decimal"] == "1795184132.123456789123"
    assert p_sub["timestamp_epoch_ns"] is None

    out_of_range = _make_alert_obs(
        timestamp_source="5138-11-16T09:46:39+0000",
        timestamp_epoch_decimal=Decimal("99999999999"),
    )
    p_oor = suricata_alert_to_payload(out_of_range)
    assert p_oor["timestamp_epoch_decimal"] == "99999999999"
    assert p_oor["timestamp_epoch_ns"] is None


# ---------------------------------------------------------------------------
# E. Numeric Bounds & Identity Consistency Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["sid", "gid", "rev", "severity", "tx_id", "pcap_cnt"])
def test_e_int64_overflow_or_negative_rejected(field):
    base = _make_alert_obs()
    with pytest.raises(ValueError, match=field):
        suricata_alert_to_payload(replace(base, **{field: INT64_MAX + 1}))
    with pytest.raises(ValueError, match=field):
        suricata_alert_to_payload(replace(base, **{field: -1}))
    with pytest.raises(ValueError, match=field):
        suricata_alert_to_payload(replace(base, **{field: True}))


def test_e_identity_and_endpoint_consistency_enforced():
    obs = _make_alert_obs()
    with pytest.raises(TypeError):
        suricata_alert_to_payload({"event_id": "x"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="src_scoped_id"):
        suricata_alert_to_payload(replace(obs, src_scoped_id="other#10.0.0.5"))
    with pytest.raises(ValueError, match="dst_scoped_id"):
        suricata_alert_to_payload(replace(obs, dst_scoped_id="other#10.0.0.20"))
    with pytest.raises(ValueError, match="flow_key"):
        suricata_alert_to_payload(replace(obs, flow_key="deadbeef"))
    with pytest.raises(ValueError, match="alert_definition_id"):
        suricata_alert_to_payload(replace(obs, alert_definition_id="suricata:et-open:1:999999"))
    with pytest.raises(ValueError, match="address family mismatch"):
        suricata_alert_to_payload(replace(obs, dst_ip="2001:db8::1"))
    with pytest.raises(ValueError, match="#"):
        suricata_alert_to_payload(replace(obs, routing_domain_id="corp#bad"))


# ---------------------------------------------------------------------------
# F. Missing GID vs GID=1 Identity Distinction
# ---------------------------------------------------------------------------

def test_f_missing_gid_preserved_distinct_from_gid_one():
    obs_none = _make_alert_obs(gid=None, sid=9900001)
    obs_one = _make_alert_obs(gid=1, sid=9900001)
    p_none = suricata_alert_to_payload(obs_none)
    p_one = suricata_alert_to_payload(obs_one)

    assert p_none["gid"] is None
    assert p_none["alert_definition_id"] == "suricata:et-open:none:9900001"
    assert p_one["gid"] == 1
    assert p_one["alert_definition_id"] == "suricata:et-open:1:9900001"
    assert p_none["alert_definition_id"] != p_one["alert_definition_id"]


# ---------------------------------------------------------------------------
# G. Deterministic Immutable Payload Digest Sensitivity
# ---------------------------------------------------------------------------

def test_g_payload_digest_deterministic_and_sensitive_to_every_field():
    obs1 = _make_alert_obs()
    obs2 = _make_alert_obs()
    p1 = suricata_alert_to_payload(obs1)
    p2 = suricata_alert_to_payload(obs2)
    assert p1["payload_digest"] == p2["payload_digest"]
    assert compute_alert_event_payload_digest(p1) == p1["payload_digest"]

    for kwargs in [
        {"rev": 21},
        {"signature": "Changed"},
        {"severity": 1},
        {"action": "blocked"},
        {"flow_id": 999999999},
        {"source_provenance": "other-file"},
    ]:
        altered = suricata_alert_to_payload(_make_alert_obs(**kwargs))
        assert altered["payload_digest"] != p1["payload_digest"]


# ---------------------------------------------------------------------------
# H & I. Conflict Detection, Intra-Batch Deduplication & Streaming Batching
# ---------------------------------------------------------------------------

def test_h_intra_batch_conflict_aborts_before_tx():
    mock_driver = MagicMock()
    repo = Neo4jRepository(mock_driver, batch_size=10)

    ev1 = _make_alert_obs(source_record_id="r:1", rev=1)
    ev1_conflict = replace(ev1, rev=2)

    with pytest.raises(AlertEventConflictError) as exc_info:
        repo.write_suricata_alert_events([ev1, ev1_conflict])

    assert exc_info.value.conflicting_event_ids == (ev1.event_id,)
    assert exc_info.value.batches_committed == 0
    mock_driver.session.return_value.__enter__.return_value.execute_write.assert_not_called()


def test_h_db_conflict_after_prior_batch_reports_committed_batches():
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    batch1 = _make_alert_obs(source_record_id="r:1")
    batch2 = _make_alert_obs(source_record_id="r:2")

    calls = {"n": 0}

    def execute_side_effect(fn, batch):
        calls["n"] += 1
        if calls["n"] == 1:
            return (1, 0, 1, 0)
        raise AlertEventConflictError([batch[0]["event_id"]])

    mock_session.execute_write.side_effect = execute_side_effect
    repo = Neo4jRepository(mock_driver, batch_size=1)

    with pytest.raises(AlertEventConflictError) as exc_info:
        repo.write_suricata_alert_events([batch1, batch2])

    assert exc_info.value.batches_committed == 1
    assert exc_info.value.conflicting_event_ids == (batch2.event_id,)


def test_i_intra_batch_duplicates_and_streaming_batches():
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    seen_batch_lengths = []

    def execute_side_effect(fn, batch):
        seen_batch_lengths.append(len(batch))
        return (len(batch), 0, 1, 0)

    mock_session.execute_write.side_effect = execute_side_effect
    repo = Neo4jRepository(mock_driver, batch_size=3)

    e1 = _make_alert_obs(source_record_id="r:1")
    e2 = _make_alert_obs(source_record_id="r:2")
    e3 = _make_alert_obs(source_record_id="r:3")

    # Generator with duplicate e1 inside batch 1, and e3 in batch 2
    def _gen():
        yield e1
        yield e1
        yield e2
        yield e3

    summary = repo.write_suricata_alert_events(_gen(), batch_size=3)
    assert isinstance(summary, AlertEventPersistenceSummary)
    assert seen_batch_lengths == [2, 1]
    assert summary.total_received == 4
    assert summary.created_count == 3
    assert summary.duplicate_matched_count == 1
    assert summary.batches_committed == 2


def test_i_empty_stream_and_invalid_batch_size():
    mock_driver = MagicMock()
    repo = Neo4jRepository(mock_driver, batch_size=50)

    summary = repo.write_suricata_alert_events([])
    assert summary == AlertEventPersistenceSummary(0, 0, 0, 0, 0, 0)
    mock_driver.session.assert_not_called()

    for bad_bs in (0, -5, True):
        with pytest.raises(ValueError, match="batch_size"):
            repo.write_suricata_alert_events([], batch_size=bad_bs)


def test_i_execute_suricata_alert_batch_parses_counts_and_raises_conflict():
    mock_tx = MagicMock()
    ok_res = MagicMock()
    ok_res.single.return_value = {
        "created_count": 3,
        "matched_count": 1,
        "definitions_created_count": 2,
        "definitions_matched_count": 1,
        "conflicting_ids": [None],
    }
    mock_tx.run.return_value = ok_res

    counts = Neo4jRepository._execute_suricata_alert_batch(mock_tx, [{"event_id": "e1"}])
    assert counts == (3, 1, 2, 1)

    conflict_res = MagicMock()
    conflict_res.single.return_value = {
        "created_count": 0,
        "matched_count": 0,
        "definitions_created_count": 0,
        "definitions_matched_count": 0,
        "conflicting_ids": ["e-conflict-2", "e-conflict-1", "e-conflict-2"],
    }
    mock_tx.run.return_value = conflict_res

    with pytest.raises(AlertEventConflictError) as exc_info:
        Neo4jRepository._execute_suricata_alert_batch(mock_tx, [{"event_id": "e-conflict-1"}])
    assert exc_info.value.conflicting_event_ids == ("e-conflict-1", "e-conflict-2")


# ---------------------------------------------------------------------------
# J. Cypher Graph Model Structure & Relationship Discipline
# ---------------------------------------------------------------------------

def test_j_cypher_relationships_and_phase_boundaries():
    assert "MERGE (ae)-[:TRIGGERED_RULE]->(ad)" in CYPHER_WRITE_SURICATA_ALERT_BATCH
    assert "MERGE (ae)-[:HAS_SOURCE]->(src_ip)" in CYPHER_WRITE_SURICATA_ALERT_BATCH
    assert "MERGE (ae)-[:HAS_DESTINATION]->(dst_ip)" in CYPHER_WRITE_SURICATA_ALERT_BATCH
    assert "MERGE (src_ip)-[:IN_DOMAIN]->(rd)" in CYPHER_WRITE_SURICATA_ALERT_BATCH
    assert "MERGE (dst_ip)-[:IN_DOMAIN]->(rd)" in CYPHER_WRITE_SURICATA_ALERT_BATCH

    for forbidden in (
        "FlowObservation",
        "AlertFact",
        "COMMUNICATED_TO",
        "SOURCE_OF",
        "TARGETS",
        "RULE_TRIGGERED_BY",
        "TRIGGERED_BY",
    ):
        assert forbidden not in CYPHER_WRITE_SURICATA_ALERT_BATCH


# ---------------------------------------------------------------------------
# K. Neo4jReadRepository get_alert_event & list_alert_events
# ---------------------------------------------------------------------------

def test_k_read_repository_guardrails_and_filters():
    none_repo = Neo4jReadRepository(None)
    assert none_repo.get_alert_event("abc") is None
    assert none_repo.list_alert_events() == ([], 0)

    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    repo = Neo4jReadRepository(mock_driver)

    assert repo.get_alert_event("") is None
    assert repo.get_alert_event("   ") is None

    for bad_kw in (
        {"limit": 0},
        {"limit": True},
        {"offset": -1},
        {"offset": False},
        {"sid": -1},
        {"sid": INT64_MAX + 1},
        {"flow_id": -1},
        {"flow_id": True},
        {"flow_id": "abc"},
        {"start_epoch_ns": True},
        {"end_epoch_ns": "123"},
    ):
        with pytest.raises(ValueError):
            repo.list_alert_events(**bad_kw)

    # Capture Cypher + params emitted on full filter call with uint64 flow_id int
    count_res = MagicMock()
    count_res.single.return_value = {"total": 0}
    page_res = []
    mock_tx = MagicMock()
    mock_tx.run.side_effect = [count_res, page_res]
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)

    items, total = repo.list_alert_events(
        routing_domain_id=" CORP-A ",
        sensor_id=" Sensor-01 ",
        flow_key="fk-1",
        community_id="1:cid==",
        flow_id=2**64 - 1,
        sid=2001219,
        start_epoch_ns=1700000000000000000,
        end_epoch_ns=1800000000000000000,
        limit=50,
        offset=10,
    )
    assert (items, total) == ([], 0)
    count_cypher, params = mock_tx.run.call_args_list[0].args[0], mock_tx.run.call_args_list[0].kwargs
    page_cypher = mock_tx.run.call_args_list[1].args[0]

    assert params["routing_domain_id"] == "corp-a"
    assert params["sensor_id"] == "sensor-01"
    assert params["flow_id"] == "18446744073709551615"
    assert params["sid"] == 2001219
    assert "ae.timestamp_epoch_ns IS NOT NULL AND ae.timestamp_epoch_ns >= $start_epoch_ns" in count_cypher
    assert "ae.timestamp_epoch_ns IS NOT NULL AND ae.timestamp_epoch_ns <= $end_epoch_ns" in count_cypher
    assert "CASE WHEN ae.timestamp_epoch_ns IS NULL THEN 1 ELSE 0 END ASC" in page_cypher
    assert "ae.timestamp_epoch_ns ASC" in page_cypher
    assert "ae.event_id ASC" in page_cypher


# ---------------------------------------------------------------------------
# L & M. Streaming Ingestion Service & CLI Entrypoint
# ---------------------------------------------------------------------------

def test_l_ingestion_service_validates_eagerly_and_enforces_migration_guard(tmp_path):
    with patch("src.services.suricata_ingestion.GraphDatabase.driver") as drv_cls:
        with pytest.raises(FileNotFoundError):
            ingest_suricata_eve_file(
                tmp_path / "does_not_exist.jsonl",
                sensor_id="s1",
                ruleset_namespace="et-open",
                log_source_id="ls1",
            )
        with pytest.raises(ValueError, match="batch_size"):
            ingest_suricata_eve_file(
                FIXTURE_STANDARD,
                sensor_id="s1",
                ruleset_namespace="et-open",
                log_source_id="ls1",
                batch_size=0,
            )
        drv_cls.assert_not_called()

    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    check_res = MagicMock()
    check_res.single.return_value = {"unmigrated_count": 3}
    mock_session.run.return_value = check_res

    with pytest.raises(MigrationRequiredError):
        ingest_suricata_eve_file(
            FIXTURE_STANDARD,
            sensor_id="Sensor-DMZ",
            ruleset_namespace="ET-Open",
            log_source_id="dmz-01",
            routing_domain_id="DMZ",
            driver=mock_driver,
        )
    mock_session.execute_write.assert_not_called()


def test_l_ingestion_service_streams_fixture_and_closes_owned_driver():
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    check_res = MagicMock()
    check_res.single.return_value = {"unmigrated_count": 0}
    mock_session.run.return_value = check_res

    def exec_write(fn, batch):
        return (len(batch), 0, len(batch), 0)

    mock_session.execute_write.side_effect = exec_write

    with patch(
        "src.services.suricata_ingestion.get_neo4j_config",
        return_value={"uri": "bolt://localhost:7687", "username": "neo4j", "password": "pw"},
    ), patch("src.services.suricata_ingestion.GraphDatabase.driver", return_value=mock_driver):
        res = ingest_suricata_eve_file(
            FIXTURE_STANDARD,
            sensor_id="Suricata-DMZ-01",
            ruleset_namespace="ET-Open",
            log_source_id="dmz-eve-01",
            routing_domain_id="DMZ",
            batch_size=2,
        )

    assert isinstance(res, SuricataIngestionResult)
    assert res.sensor_id == "suricata-dmz-01"
    assert res.ruleset_namespace == "et-open"
    assert res.routing_domain_id == "dmz"
    assert res.parse_summary.valid_records == 5
    assert res.parse_summary.ignored_non_alert_records == 3
    assert res.persistence_summary.total_received == 5
    assert res.persistence_summary.batches_committed == 3
    mock_driver.verify_connectivity.assert_called_once()
    mock_driver.close.assert_called_once()


def test_m_cli_main_success_and_failure(capsys):
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    check_res = MagicMock()
    check_res.single.return_value = {"unmigrated_count": 0}
    mock_session.run.return_value = check_res
    mock_session.execute_write.return_value = (5, 0, 5, 0)

    with patch(
        "src.services.suricata_ingestion.get_neo4j_config",
        return_value={"uri": "bolt://localhost:7687", "username": "neo4j", "password": "pw"},
    ), patch("src.services.suricata_ingestion.GraphDatabase.driver", return_value=mock_driver):
        rc = suricata_cli_main(
            [
                "--file",
                str(FIXTURE_STANDARD),
                "--sensor-id",
                "s-01",
                "--ruleset-namespace",
                "et-open",
                "--log-source-id",
                "ls-01",
            ]
        )
    assert rc == 0
    out_json = json.loads(capsys.readouterr().out)
    assert out_json["parse_summary"]["valid_records"] == 5
    assert out_json["persistence_summary"]["total_received"] == 5

    rc_err = suricata_cli_main(
        [
            "--file",
            "missing_eve_file.jsonl",
            "--sensor-id",
            "s-01",
            "--ruleset-namespace",
            "et-open",
            "--log-source-id",
            "ls-01",
        ]
    )
    assert rc_err == 1
    assert "ERROR:" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# N & O. Exports & V1 Isolation
# ---------------------------------------------------------------------------

def test_n_graph_package_exports():
    for sym in (
        "AlertEventConflictError",
        "AlertEventPersistenceSummary",
        "suricata_alert_to_payload",
        "compute_alert_event_payload_digest",
        "CYPHER_WRITE_SURICATA_ALERT_BATCH",
    ):
        assert hasattr(graph_pkg, sym)


def test_o_v1_alert_and_traffic_contracts_unchanged():
    assert "MERGE (src)-[:SOURCE_OF]->(fact)" in CYPHER_WRITE_ALERT_BATCH
    assert "MERGE (fact)-[:TARGETS]->(dst)" in CYPHER_WRITE_ALERT_BATCH
    assert "AlertEvent" not in CYPHER_WRITE_ALERT_BATCH
    assert "AlertEvent" not in CYPHER_WRITE_TRAFFIC_BATCH

    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    repo = Neo4jRepository(mock_driver)
    written = repo.write_alert_records(
        [AlertRecord(src_ip="192.0.2.1", dst_ip="198.51.100.2", sid=100, gid=1, message="test")]
    )
    assert written == 1
    assert iter_suricata_eve_alert_lines is not None


# ---------------------------------------------------------------------------
# P. Review-Hardening Tests: alert_definition_id/severity filters, boundaries & counters
# ---------------------------------------------------------------------------

def test_p_list_alert_events_alert_definition_id_and_severity_filters():
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    repo = Neo4jReadRepository(mock_driver)

    # Validation guardrails for alert_definition_id & severity
    for bad_kw in (
        {"alert_definition_id": 123},
        {"alert_definition_id": True},
        {"severity": True},
        {"severity": False},
        {"severity": -1},
        {"severity": "1"},
        {"severity": 1.5},
        {"severity": INT64_MAX + 1},
    ):
        with pytest.raises(ValueError):
            repo.list_alert_events(**bad_kw)

    # 1. With alert_definition_id + severity=0 (falsy int) + routing_domain_id
    count_res = MagicMock()
    count_res.single.return_value = {"total": 0}
    mock_tx = MagicMock()
    mock_tx.run.side_effect = [count_res, []]
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)

    items, total = repo.list_alert_events(
        alert_definition_id="  Suricata:ET-Open:1:2001219  ",
        severity=0,
        routing_domain_id="DMZ",
    )
    assert (items, total) == ([], 0)
    count_cypher = mock_tx.run.call_args_list[0].args[0]
    page_cypher = mock_tx.run.call_args_list[1].args[0]
    params = mock_tx.run.call_args_list[0].kwargs

    assert "MATCH (ae:AlertEvent)-[:TRIGGERED_RULE]->(ad:AlertDefinition)" in count_cypher
    assert "MATCH (ae:AlertEvent)-[:TRIGGERED_RULE]->(ad:AlertDefinition)" in page_cypher
    assert "ad.definition_id = $alert_definition_id" in count_cypher
    assert "ae.severity = $severity" in count_cypher
    assert "ae.routing_domain_id = $routing_domain_id" in count_cypher
    assert params["alert_definition_id"] == "suricata:et-open:1:2001219"
    assert params["severity"] == 0
    assert params["routing_domain_id"] == "dmz"

    # 2. When alert_definition_id is omitted or whitespace-only, keep lean single-node MATCH
    mock_tx2 = MagicMock()
    mock_tx2.run.side_effect = [count_res, []]
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx2)

    repo.list_alert_events(alert_definition_id="   ", severity=2)
    count_cypher2 = mock_tx2.run.call_args_list[0].args[0]
    params2 = mock_tx2.run.call_args_list[0].kwargs
    assert "MATCH (ae:AlertEvent)" in count_cypher2
    assert "TRIGGERED_RULE" not in count_cypher2
    assert "alert_definition_id" not in params2
    assert params2["severity"] == 2


def test_p_numeric_temporal_and_large_flow_id_boundary_contracts():
    # Exact INT64_MAX nanosecond boundary (9223372036.854775807 -> INT64_MAX)
    max_ns_obs = _make_alert_obs(
        timestamp_source="2262-04-11T23:47:16.854775807+0000",
        timestamp_epoch_decimal=Decimal("9223372036.854775807"),
    )
    p_max = suricata_alert_to_payload(max_ns_obs)
    assert p_max["timestamp_epoch_decimal"] == "9223372036.854775807"
    assert p_max["timestamp_epoch_ns"] == INT64_MAX

    # One nanosecond beyond INT64_MAX -> exact decimal retained, ns index omitted (None)
    over_ns_obs = _make_alert_obs(
        timestamp_source="2262-04-11T23:47:16.854775808+0000",
        timestamp_epoch_decimal=Decimal("9223372036.854775808"),
    )
    p_over = suricata_alert_to_payload(over_ns_obs)
    assert p_over["timestamp_epoch_decimal"] == "9223372036.854775808"
    assert p_over["timestamp_epoch_ns"] is None

    # Trailing zeros beyond 9th decimal digit are exact nanoseconds (must NOT become None)
    tz_obs = _make_alert_obs(
        timestamp_source="2026-11-20T14:15:32.123456789000+0000",
        timestamp_epoch_decimal=Decimal("1795184132.123456789000"),
    )
    p_tz = suricata_alert_to_payload(tz_obs)
    assert p_tz["timestamp_epoch_decimal"] == "1795184132.123456789"
    assert p_tz["timestamp_epoch_ns"] == 1795184132123456789

    # Epoch zero (falsy Decimal(0))
    zero_obs = _make_alert_obs(
        timestamp_source="1970-01-01T00:00:00+0000",
        timestamp_epoch_decimal=Decimal("0"),
    )
    p_zero = suricata_alert_to_payload(zero_obs)
    assert p_zero["timestamp_epoch_decimal"] == "0"
    assert p_zero["timestamp_epoch_ns"] == 0

    # Read repository large flow_id canonicalization & rejection
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    count_res = MagicMock()
    count_res.single.return_value = {"total": 0}
    mock_tx = MagicMock()
    mock_tx.run.side_effect = [count_res, []]
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)

    read_repo = Neo4jReadRepository(mock_driver)
    read_repo.list_alert_events(flow_id="  00018446744073709551615  ")
    assert mock_tx.run.call_args_list[0].kwargs["flow_id"] == "18446744073709551615"

    for bad_fid in ("", "   ", "-5", "12.3", "²", 1.2):
        with pytest.raises(ValueError, match="flow_id"):
            read_repo.list_alert_events(flow_id=bad_fid)


def test_p_multi_batch_definition_counter_accumulation():
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Simulate 3 batches sharing 1 new definition:
    # Batch 1 creates def (1, 0), Batch 2 & 3 match pre-existing def (0, 1) each.
    mock_session.execute_write.side_effect = [
        (2, 0, 1, 0),
        (2, 0, 0, 1),
        (1, 0, 0, 1),
    ]
    repo = Neo4jRepository(mock_driver, batch_size=2)
    events = [_make_alert_obs(source_record_id=f"r:{i}") for i in range(5)]

    summary = repo.write_suricata_alert_events(events, batch_size=2)
    assert summary.total_received == 5
    assert summary.created_count == 5
    assert summary.duplicate_matched_count == 0
    assert summary.definitions_created_count == 1
    assert summary.definitions_matched_count == 2
    assert summary.batches_committed == 3
