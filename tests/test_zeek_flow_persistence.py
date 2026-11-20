"""
Unit tests for Phase 3A.2 Zeek FlowObservation Neo4j persistence, schema, reads, and entrypoint.
"""

from dataclasses import replace
from decimal import Decimal, getcontext, localcontext
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.graph.read_repository import Neo4jReadRepository
from src.graph.repository import (
    CYPHER_SCOPED_CLEANUP,
    CYPHER_WRITE_ZEEK_OBSERVATION_BATCH,
    INT64_MAX,
    Neo4jRepository,
    ObservationConflictError,
    ObservationPersistenceSummary,
    decimal_epoch_to_ns,
    format_exact_decimal,
    iter_batches,
    zeek_observation_to_payload,
)
from src.graph.schema import MigrationRequiredError, SCHEMA_STATEMENTS
from src.ingestion.v2_models import (
    ZeekConnectionObservation,
    add_exact_decimals,
    canonicalize_event_timestamp,
    compute_observation_id,
    compute_v2_flow_key,
    format_canonical_decimal,
    scoped_ip_id,
)
from src.ingestion.zeek_conn_parser import iter_zeek_conn_lines
from src.services.zeek_ingestion import ingest_zeek_conn_file, main as zeek_cli_main

FIXTURE_STANDARD = Path(__file__).parent / "fixtures" / "zeek" / "conn_standard.jsonl"


def _make_observation(
    *,
    uid: str = "CUnitObs000000001",
    routing_domain_id: str = "corp",
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.20",
    protocol: str = "TCP",
    src_port: int | None = 54321,
    dst_port: int | None = 443,
    community_id: str | None = "1:testCommunityId==",
    start_ts: str = "1725148800.123456789",
    start_epoch: Decimal | None = Decimal("1725148800.123456789"),
    duration: Decimal | None = Decimal("1.500000001"),
    end_epoch: Decimal | None = Decimal("1725148801.623456790"),
    end_ts: str | None = "1725148801.62345679",
    orig_bytes: int | None = 1200,
    resp_bytes: int | None = 4800,
    orig_pkts: int | None = 10,
    resp_pkts: int | None = 12,
    orig_ip_bytes: int | None = 1720,
    resp_ip_bytes: int | None = 5440,
    missed_bytes: int | None = 0,
    service: str | None = "ssl",
    conn_state: str | None = "SF",
    history: str | None = "ShADadFf",
    local_orig: bool | None = True,
    local_resp: bool | None = False,
    sensor_id: str = "zeek-edge-01",
    source_provenance: str | None = None,
) -> ZeekConnectionObservation:
    src_scoped = scoped_ip_id(routing_domain_id, src_ip)
    dst_scoped = scoped_ip_id(routing_domain_id, dst_ip)
    flow_key = compute_v2_flow_key(src_scoped, dst_scoped, protocol, src_port, dst_port)
    obs_id = compute_observation_id(
        source_type="zeek",
        sensor_id=sensor_id,
        source_record_id=uid,
        timestamp=start_epoch if start_epoch is not None else start_ts,
        flow_key=flow_key,
        source_provenance=source_provenance,
    )
    return ZeekConnectionObservation(
        observation_id=obs_id,
        flow_key=flow_key,
        zeek_uid=uid,
        routing_domain_id=routing_domain_id,
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        start_ts=start_ts,
        src_port=src_port,
        dst_port=dst_port,
        community_id=community_id,
        start_epoch=start_epoch,
        duration=duration,
        end_epoch=end_epoch,
        end_ts=end_ts,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        orig_pkts=orig_pkts,
        resp_pkts=resp_pkts,
        orig_ip_bytes=orig_ip_bytes,
        resp_ip_bytes=resp_ip_bytes,
        missed_bytes=missed_bytes,
        service=service,
        conn_state=conn_state,
        history=history,
        local_orig=local_orig,
        local_resp=local_resp,
        sensor_id=sensor_id,
        source_type="zeek",
        source_provenance=source_provenance,
    )


# ---------------------------------------------------------------------------
# Schema & Cleanup Contract Tests
# ---------------------------------------------------------------------------

def test_flow_observation_schema_constraints_and_indexes():
    """Verify FlowObservation uniqueness constraint and targeted query indexes are defined."""
    statements_text = " ".join(SCHEMA_STATEMENTS)

    assert "CONSTRAINT flow_observation_unique IF NOT EXISTS" in statements_text
    assert "FOR (fo:FlowObservation) REQUIRE fo.observation_id IS UNIQUE" in statements_text

    assert "INDEX flow_observation_community_id_index IF NOT EXISTS" in statements_text
    assert "FOR (fo:FlowObservation) ON (fo.community_id)" in statements_text

    assert "INDEX flow_observation_sensor_id_index IF NOT EXISTS" in statements_text
    assert "FOR (fo:FlowObservation) ON (fo.sensor_id)" in statements_text

    assert "INDEX flow_observation_routing_domain_index IF NOT EXISTS" in statements_text
    assert "FOR (fo:FlowObservation) ON (fo.routing_domain_id)" in statements_text

    assert "INDEX flow_observation_start_epoch_ns_index IF NOT EXISTS" in statements_text
    assert "FOR (fo:FlowObservation) ON (fo.start_epoch_ns)" in statements_text

    # Community ID, flow_key, and zeek_uid must NEVER be globally unique constraints
    assert "REQUIRE fo.community_id IS UNIQUE" not in statements_text
    assert "REQUIRE fo.flow_key IS UNIQUE" not in statements_text
    assert "REQUIRE fo.zeek_uid IS UNIQUE" not in statements_text


def test_scoped_cleanup_includes_flow_observation():
    """Verify atomic workspace cleanup removes application-owned FlowObservation nodes."""
    assert "n:FlowObservation" in CYPHER_SCOPED_CLEANUP
    assert "n:IPAddress" in CYPHER_SCOPED_CLEANUP
    assert "n:RoutingDomain" in CYPHER_SCOPED_CLEANUP


def test_cypher_write_zeek_observation_batch_contract():
    """Verify Cypher write merges on observation_id, uses HAS_ORIGINATOR/HAS_RESPONDER, and never touches COMMUNICATED_TO."""
    assert "MERGE (fo:FlowObservation {observation_id: row.observation_id})" in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH
    assert "ON CREATE SET" in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH
    assert "MERGE (fo)-[:HAS_ORIGINATOR]->(src_ip)" in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH
    assert "MERGE (fo)-[:HAS_RESPONDER]->(dst_ip)" in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH
    assert "MERGE (src_ip)-[:IN_DOMAIN]->(rd)" in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH
    assert "MERGE (dst_ip)-[:IN_DOMAIN]->(rd)" in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH
    assert "COMMUNICATED_TO" not in CYPHER_WRITE_ZEEK_OBSERVATION_BATCH


# ---------------------------------------------------------------------------
# Temporal Serialization & Payload Validation Tests
# ---------------------------------------------------------------------------

def test_payload_serialization_preserves_exact_decimal_timestamps_and_native_types():
    """Verify Neo4j payload contains zero Decimal/float timestamps and preserves nanosecond precision."""
    obs = _make_observation(
        start_ts="1725148800.123456789",
        start_epoch=Decimal("1725148800.123456789"),
        duration=Decimal("1.500000001"),
        end_epoch=Decimal("1725148801.623456790"),
        end_ts="1725148801.62345679",
    )
    payload = zeek_observation_to_payload(obs)

    # Zero Decimal or float objects in Neo4j payload
    for key, val in payload.items():
        assert not isinstance(val, Decimal), f"Field {key} leaked Decimal"
        assert not isinstance(val, float), f"Field {key} leaked float"

    assert payload["start_ts"] == "1725148800.123456789"
    assert payload["end_ts"] == "1725148801.62345679"
    assert payload["start_epoch_decimal"] == "1725148800.123456789"
    assert payload["end_epoch_decimal"] == "1725148801.62345679"
    assert payload["duration_decimal"] == "1.500000001"
    assert payload["start_epoch_ns"] == 1725148800123456789
    assert payload["end_epoch_ns"] == 1725148801623456790
    assert len(payload["payload_digest"]) == 64


def test_decimal_epoch_to_ns_never_truncates_higher_precision_or_overflows():
    """Verify picosecond (>9 fractional digits) and out-of-int64-range timestamps yield None for ns index while keeping exact strings."""
    # Exact nanosecond precision -> exact int64
    assert decimal_epoch_to_ns(Decimal("0")) == 0
    assert decimal_epoch_to_ns(Decimal("1725148800.123456789")) == 1725148800123456789
    assert format_exact_decimal(Decimal("-0.0")) == "0"

    # Picosecond precision (10 fractional digits) -> must NOT truncate!
    pico = Decimal("1725148800.1234567895")
    assert decimal_epoch_to_ns(pico) is None
    assert format_exact_decimal(pico) == "1725148800.1234567895"

    # Year > 2262 exceeds signed 64-bit integer nanosecond range -> must return None
    overflow_epoch = Decimal(INT64_MAX // 1_000_000_000 + 10)
    assert decimal_epoch_to_ns(overflow_epoch) is None
    assert format_exact_decimal(overflow_epoch) == str(overflow_epoch)

    # Negative / NaN / Infinity / float rejected loudly
    with pytest.raises(ValueError):
        decimal_epoch_to_ns(Decimal("-1"))
    with pytest.raises(ValueError):
        decimal_epoch_to_ns(Decimal("NaN"))
    with pytest.raises(ValueError):
        decimal_epoch_to_ns(1725148800.5)  # type: ignore[arg-type]


def test_missing_temporal_and_directional_metrics_remain_none():
    """Verify absent duration/end timestamps and absent directional metrics remain None rather than inventing zeros."""
    obs = _make_observation(
        duration=None,
        end_epoch=None,
        end_ts=None,
        orig_bytes=None,
        resp_bytes=None,
        orig_pkts=None,
        resp_pkts=None,
        orig_ip_bytes=None,
        resp_ip_bytes=None,
        missed_bytes=None,
        service=None,
        conn_state=None,
        history=None,
        local_orig=None,
        local_resp=None,
        community_id=None,
    )
    payload = zeek_observation_to_payload(obs)

    assert payload["duration_decimal"] is None
    assert payload["end_epoch_decimal"] is None
    assert payload["end_epoch_ns"] is None
    assert payload["end_ts"] is None
    assert payload["orig_bytes"] is None
    assert payload["resp_bytes"] is None
    assert payload["orig_pkts"] is None
    assert payload["resp_pkts"] is None
    assert payload["orig_ip_bytes"] is None
    assert payload["resp_ip_bytes"] is None
    assert payload["missed_bytes"] is None
    assert payload["community_id"] is None


def test_directional_metrics_kept_distinct_payload_vs_ip_bytes():
    """Verify payload bytes, IP bytes, packet counts, and missed_bytes remain separate fields."""
    obs = _make_observation(
        orig_bytes=100,
        resp_bytes=200,
        orig_ip_bytes=340,
        resp_ip_bytes=520,
        orig_pkts=4,
        resp_pkts=6,
        missed_bytes=12,
    )
    payload = zeek_observation_to_payload(obs)
    assert payload["orig_bytes"] == 100
    assert payload["resp_bytes"] == 200
    assert payload["orig_ip_bytes"] == 340
    assert payload["resp_ip_bytes"] == 520
    assert payload["orig_pkts"] == 4
    assert payload["resp_pkts"] == 6
    assert payload["missed_bytes"] == 12
    assert "observed_bytes" not in payload


def test_scoped_domain_and_endpoint_consistency_validation():
    """Verify mismatched domain/scoped_id/IP/IP-version combinations are rejected before DB writes."""
    base = _make_observation(routing_domain_id="corp", src_ip="10.0.0.5", dst_ip="10.0.0.20")

    # Cross-domain dst_scoped_id must fail
    bad_domain_dst = replace(base, dst_scoped_id="branch#10.0.0.20")
    with pytest.raises(ValueError, match="Inconsistent dst_scoped_id"):
        zeek_observation_to_payload(bad_domain_dst)

    # Mismatched src_ip vs src_scoped_id must fail
    bad_src_ip = replace(base, src_ip="10.0.0.99")
    with pytest.raises(ValueError, match="Inconsistent src_scoped_id"):
        zeek_observation_to_payload(bad_src_ip)

    # Mismatched IPv4 -> IPv6 must fail
    bad_ip_ver = replace(base, dst_ip="2001:db8::1", dst_scoped_id="corp#2001:db8::1")
    with pytest.raises(ValueError, match="Mismatched IP versions"):
        zeek_observation_to_payload(bad_ip_ver)

    # Hash delimiter in routing_domain_id must fail
    bad_domain_char = replace(base, routing_domain_id="corp#bad")
    with pytest.raises(ValueError, match="cannot contain delimiter '#'"):
        zeek_observation_to_payload(bad_domain_char)


# ---------------------------------------------------------------------------
# Streaming Batching, Idempotency & Conflict Detection Tests
# ---------------------------------------------------------------------------

def test_iter_batches_consumes_lazily_without_full_materialization():
    """Verify iter_batches pulls only batch_size elements at a time from a generator."""
    yielded = []

    def gen():
        for i in range(10):
            yielded.append(i)
            yield i

    batches = iter_batches(gen(), size=3)
    first = next(batches)
    assert first == [0, 1, 2]
    assert yielded == [0, 1, 2]

    second = next(batches)
    assert second == [3, 4, 5]
    assert yielded == [0, 1, 2, 3, 4, 5]

    rest = list(batches)
    assert rest == [[6, 7, 8], [9]]

    with pytest.raises(ValueError):
        list(iter_batches([], 0))
    with pytest.raises(ValueError):
        list(iter_batches([], True))  # type: ignore[arg-type]


def test_write_zeek_observations_streams_bounded_batches_without_list_materialization():
    """Verify write_zeek_observations consumes a single-pass iterator lazily in bounded batches."""
    yielded_count = 0
    seen_batch_sizes = []

    def obs_generator():
        nonlocal yielded_count
        for i in range(5):
            yielded_count += 1
            yield _make_observation(uid=f"CStream{i:04d}")

    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    def fake_execute_write(work_fn, batch):
        seen_batch_sizes.append(len(batch))
        # When batch 1 (size 2) runs, the generator must NOT have yielded all 5 items!
        if len(seen_batch_sizes) == 1:
            assert yielded_count == 2
        tx = MagicMock()
        tx.run.return_value.single.return_value = {
            "created_count": len(batch),
            "matched_count": 0,
            "conflicting_ids": [],
        }
        return work_fn(tx, batch)

    mock_session.execute_write.side_effect = fake_execute_write

    repo = Neo4jRepository(mock_driver, batch_size=2)
    summary = repo.write_zeek_observations(obs_generator())

    assert seen_batch_sizes == [2, 2, 1]
    assert summary == ObservationPersistenceSummary(
        total_received=5,
        created_count=5,
        duplicate_matched_count=0,
        batches_committed=3,
    )


def test_write_zeek_observations_empty_iterator_opens_no_session():
    """Verify empty observation iterable performs zero Neo4j calls."""
    mock_driver = MagicMock()
    repo = Neo4jRepository(mock_driver, batch_size=10)
    summary = repo.write_zeek_observations(iter([]))
    assert summary == ObservationPersistenceSummary(0, 0, 0, 0)
    assert mock_driver.session.call_count == 0


def test_write_zeek_observations_deduplicates_exact_in_batch_duplicates_and_tracks_db_matches():
    """Verify exact duplicate observations within a batch and across batches are handled idempotently."""
    obs1 = _make_observation(uid="CDupe0001")
    obs2 = _make_observation(uid="CDupe0002")

    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    sent_batches = []

    def fake_execute_write(work_fn, batch):
        sent_batches.append(batch)
        tx = MagicMock()
        tx.run.return_value.single.return_value = {
            "created_count": 1,
            "matched_count": 1,
            "conflicting_ids": [],
        }
        return work_fn(tx, batch)

    mock_session.execute_write.side_effect = fake_execute_write

    repo = Neo4jRepository(mock_driver, batch_size=10)
    summary = repo.write_zeek_observations([obs1, obs1, obs2])

    # In-batch duplicate of obs1 was deduped before sending to Neo4j
    assert len(sent_batches) == 1
    assert len(sent_batches[0]) == 2
    assert summary.total_received == 3
    assert summary.created_count == 1
    assert summary.duplicate_matched_count == 2  # 1 in-batch dupe + 1 existing DB match
    assert summary.batches_committed == 1


def test_write_zeek_observations_rejects_conflicting_duplicate_identity_intra_batch_and_in_db():
    """Verify conflicting properties for the same observation_id raise ObservationConflictError."""
    obs_a = _make_observation(uid="CConflict001", orig_bytes=100)
    obs_a_conflict = replace(obs_a, orig_bytes=9999)  # Same observation_id, conflicting payload!

    # 1. Intra-batch conflict: rejected before any Neo4j write executes
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    repo = Neo4jRepository(mock_driver, batch_size=10)

    with pytest.raises(ObservationConflictError) as exc_info:
        repo.write_zeek_observations([obs_a, obs_a_conflict])
    assert exc_info.value.conflicting_observation_ids == (obs_a.observation_id,)
    assert mock_session.execute_write.call_count == 0

    # 2. Cross-batch / DB-existing conflict: Neo4j returns conflicting_ids -> raises inside tx callback
    def fake_execute_write_conflict(work_fn, batch):
        tx = MagicMock()
        tx.run.return_value.single.return_value = {
            "created_count": 0,
            "matched_count": 0,
            "conflicting_ids": [obs_a.observation_id],
        }
        return work_fn(tx, batch)

    mock_session.execute_write.side_effect = fake_execute_write_conflict
    with pytest.raises(ObservationConflictError) as exc_info2:
        repo.write_zeek_observations([obs_a_conflict])
    assert exc_info2.value.conflicting_observation_ids == (obs_a.observation_id,)
    assert exc_info2.value.batches_committed == 0


def test_write_zeek_observations_partial_batch_failure_preserves_prior_committed_batches():
    """Verify if batch 2 fails after batch 1 commits, error propagates with honest batch boundary."""
    observations = [_make_observation(uid=f"CPartial{i:03d}") for i in range(4)]

    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    call_num = 0

    def fake_execute_write(work_fn, batch):
        nonlocal call_num
        call_num += 1
        if call_num == 1:
            tx = MagicMock()
            tx.run.return_value.single.return_value = {
                "created_count": len(batch),
                "matched_count": 0,
                "conflicting_ids": [],
            }
            return work_fn(tx, batch)
        raise RuntimeError("Simulated transient failure on batch 2")

    mock_session.execute_write.side_effect = fake_execute_write
    repo = Neo4jRepository(mock_driver, batch_size=2)

    with pytest.raises(RuntimeError, match="batch 2"):
        repo.write_zeek_observations(observations)

    assert call_num == 2


# ---------------------------------------------------------------------------
# Read Repository Unit Tests
# ---------------------------------------------------------------------------

def test_read_repository_get_and_list_flow_observations_filtering_and_ordering():
    """Verify exact observation lookup, filters, exact ns temporal bounds, and deterministic ordering."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    captured_queries = []

    sample_row = {
        "observation_id": "obs-1",
        "flow_key": "fk-1",
        "zeek_uid": "CUid1",
        "routing_domain_id": "corp",
        "src_scoped_id": "corp#10.0.0.1",
        "dst_scoped_id": "corp#10.0.0.2",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": 443,
        "community_id": "1:abc=",
        "start_ts": "1725148800.123456789",
        "end_ts": "1725148801.123456789",
        "start_epoch_decimal": "1725148800.123456789",
        "end_epoch_decimal": "1725148801.123456789",
        "duration_decimal": "1",
        "start_epoch_ns": 1725148800123456789,
        "end_epoch_ns": 1725148801123456789,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 2,
        "resp_pkts": 3,
        "orig_ip_bytes": 180,
        "resp_ip_bytes": 320,
        "missed_bytes": 0,
        "service": "ssl",
        "conn_state": "SF",
        "history": "ShAD",
        "local_orig": True,
        "local_resp": False,
        "sensor_id": "zeek-1",
        "source_type": "zeek",
        "source_provenance": None,
    }

    def fake_execute_read(work_fn):
        tx = MagicMock()

        def fake_run(cypher, **params):
            captured_queries.append((cypher, params))
            res = MagicMock()
            if "RETURN count(fo) AS total" in cypher:
                res.single.return_value = {"total": 1}
            elif "MATCH (fo:FlowObservation {observation_id: $observation_id})" in cypher:
                res.single.return_value = sample_row
            else:
                res.__iter__.return_value = iter([sample_row])
            return res

        tx.run.side_effect = fake_run
        return work_fn(tx)

    mock_session.execute_read.side_effect = fake_execute_read
    read_repo = Neo4jReadRepository(mock_driver)

    # 1. Exact lookup
    found = read_repo.get_flow_observation("obs-1")
    assert found is not None
    assert found["observation_id"] == "obs-1"
    assert found["start_epoch_decimal"] == "1725148800.123456789"
    assert found["start_epoch_ns"] == 1725148800123456789

    # 2. Filtered paginated list with exact integer nanosecond bounds
    items, total = read_repo.list_flow_observations(
        routing_domain_id="CORP",
        sensor_id="ZEEK-1",
        community_id="1:abc=",
        start_epoch_ns_min=1725148800000000000,
        start_epoch_ns_max=1725148802000000000,
        limit=25,
        offset=0,
    )
    assert total == 1
    assert len(items) == 1

    page_cypher, page_params = captured_queries[-1]
    assert page_params["routing_domain_id"] == "corp"
    assert page_params["sensor_id"] == "zeek-1"
    assert page_params["community_id"] == "1:abc="
    assert page_params["start_epoch_ns_min"] == 1725148800000000000
    assert page_params["start_epoch_ns_max"] == 1725148802000000000
    # Must filter on numeric start_epoch_ns, never lexicographic start_ts string comparison
    assert "fo.start_epoch_ns >=" in page_cypher
    assert "fo.start_epoch_ns <=" in page_cypher
    assert "fo.start_ts >=" not in page_cypher
    # Deterministic tie-breaking on unique observation_id
    assert "ORDER BY CASE WHEN fo.start_epoch_ns IS NULL THEN 1 ELSE 0 END ASC," in page_cypher
    assert "fo.start_epoch_ns ASC," in page_cypher
    assert "fo.observation_id ASC" in page_cypher


def test_read_repository_flow_observation_validation_errors():
    """Verify invalid lookup IDs, pagination bounds, and temporal bounds fail loudly."""
    read_repo = Neo4jReadRepository(MagicMock())

    with pytest.raises(ValueError, match="non-empty string"):
        read_repo.get_flow_observation("   ")
    with pytest.raises(ValueError, match="limit must be"):
        read_repo.list_flow_observations(limit=0)
    with pytest.raises(ValueError, match="offset must be"):
        read_repo.list_flow_observations(offset=-1)
    with pytest.raises(ValueError, match="cannot be greater"):
        read_repo.list_flow_observations(start_epoch_ns_min=200, start_epoch_ns_max=100)
    with pytest.raises(ValueError, match="start_epoch_ns_min must be an integer"):
        read_repo.list_flow_observations(start_epoch_ns_min=True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Parser-to-Database Entrypoint Tests
# ---------------------------------------------------------------------------

def test_ingest_zeek_conn_file_streams_and_enforces_schema_safety():
    """Verify entrypoint connects stream_zeek_conn_file -> ensure_schema -> write_zeek_observations."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Preflight check returns 0 unmigrated nodes
    mock_check_res = MagicMock()
    mock_check_res.single.return_value = {"unmigrated_count": 0}
    mock_ddl_res = MagicMock()
    mock_session.run.side_effect = lambda stmt, **kw: mock_check_res if "unmigrated_count" in stmt else mock_ddl_res

    def fake_execute_write(work_fn, batch):
        tx = MagicMock()
        tx.run.return_value.single.return_value = {
            "created_count": len(batch),
            "matched_count": 0,
            "conflicting_ids": [],
        }
        return work_fn(tx, batch)

    mock_session.execute_write.side_effect = fake_execute_write

    result = ingest_zeek_conn_file(
        FIXTURE_STANDARD,
        sensor_id="zeek-edge-01",
        routing_domain_id="corp-prod",
        source_provenance="batch-test",
        batch_size=2,
        driver=mock_driver,
    )

    mock_driver.verify_connectivity.assert_called_once()
    assert result.parse_summary.valid_records == 5
    assert result.persistence_summary.total_received == 5
    assert result.persistence_summary.created_count == 5
    assert result.persistence_summary.batches_committed == 3
    assert result.routing_domain_id == "corp-prod"
    assert result.sensor_id == "zeek-edge-01"
    # Caller-supplied driver must NOT be closed by ingest_zeek_conn_file
    assert mock_driver.close.call_count == 0


def test_ingest_zeek_conn_file_refuses_unmigrated_legacy_database():
    """Verify entrypoint refuses writes and raises MigrationRequiredError if legacy V1 IP nodes exist."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_check_res = MagicMock()
    mock_check_res.single.return_value = {"unmigrated_count": 3}
    mock_session.run.return_value = mock_check_res

    with pytest.raises(MigrationRequiredError) as exc_info:
        ingest_zeek_conn_file(
            FIXTURE_STANDARD,
            sensor_id="zeek-edge-01",
            driver=mock_driver,
        )

    assert exc_info.value.unmigrated_count == 3
    assert mock_session.execute_write.call_count == 0


def test_ingest_zeek_conn_file_closes_owned_driver_and_cli_exit_codes():
    """Verify owned Neo4j driver is closed in finally block and CLI returns exit code 0/1 cleanly."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    mock_check_res = MagicMock()
    mock_check_res.single.return_value = {"unmigrated_count": 0}
    mock_session.run.side_effect = lambda stmt, **kw: mock_check_res if "unmigrated_count" in stmt else MagicMock()
    mock_session.execute_write.side_effect = lambda fn, batch: (len(batch), 0)

    with (
        patch("src.services.zeek_ingestion.get_neo4j_config", return_value={"uri": "bolt://x", "username": "u", "password": "p"}),
        patch("src.services.zeek_ingestion.GraphDatabase.driver", return_value=mock_driver),
    ):
        rc = zeek_cli_main(["--file", str(FIXTURE_STANDARD), "--sensor-id", "zeek-cli-01", "--batch-size", "3"])
        assert rc == 0
        mock_driver.close.assert_called_once()

    # Missing file returns exit code 1 cleanly without touching Neo4j
    rc_err = zeek_cli_main(["--file", "nonexistent_conn.jsonl", "--sensor-id", "zeek-cli-01"])
    assert rc_err == 1


# ---------------------------------------------------------------------------
# Exact Lossless Decimal Precision Hardening Regression Tests (A - K)
# ---------------------------------------------------------------------------

def test_decimal_precision_a_b_c_nanosecond_picosecond_and_over_28_digits():
    """Tests A, B, C: 9-digit ns, 10/12-digit sub-ns, and >28 significant digits never round."""
    # A: 9-digit nanosecond precision -> exact string + exact int64 ns
    ns_val = Decimal("1725148800.123456789")
    assert format_exact_decimal(ns_val) == "1725148800.123456789"
    assert canonicalize_event_timestamp(ns_val) == "1725148800.123456789"
    assert decimal_epoch_to_ns(ns_val) == 1725148800123456789

    # B: 10-digit and 12-digit fractional precision -> exact strings, ns index must be None
    d10 = Decimal("1725148800.1234567895")
    d12 = Decimal("1725148800.123456789012")
    assert format_exact_decimal(d10) == "1725148800.1234567895"
    assert format_exact_decimal(d12) == "1725148800.123456789012"
    assert canonicalize_event_timestamp(d10) == "1725148800.1234567895"
    assert canonicalize_event_timestamp(d12) == "1725148800.123456789012"
    assert decimal_epoch_to_ns(d10) is None
    assert decimal_epoch_to_ns(d12) is None

    # C: 39 significant digits (> default prec=28) -> every single digit preserved
    v39 = Decimal("1725148800.12345678901234567890123456789")
    expected_39 = "1725148800.12345678901234567890123456789"
    assert format_canonical_decimal(v39) == expected_39
    assert format_exact_decimal(v39) == expected_39
    assert canonicalize_event_timestamp(v39) == expected_39
    assert canonicalize_event_timestamp(expected_39) == expected_39
    assert decimal_epoch_to_ns(v39) is None


def test_decimal_precision_d_distinct_beyond_28th_significant_digit_do_not_collapse():
    """Test D: Timestamps differing only beyond the 28th significant digit stay distinct in ts and observation_id."""
    ts_a = "1725148800.12345678901234567890123456781"
    ts_b = "1725148800.12345678901234567890123456782"

    assert canonicalize_event_timestamp(ts_a) == ts_a
    assert canonicalize_event_timestamp(ts_b) == ts_b
    assert canonicalize_event_timestamp(ts_a) != canonicalize_event_timestamp(ts_b)

    obs_id_a = compute_observation_id("zeek", "sensor-1", "CUidExtreme", ts_a, "fk-1")
    obs_id_b = compute_observation_id("zeek", "sensor-1", "CUidExtreme", ts_b, "fk-1")
    assert obs_id_a != obs_id_b

    lines = [
        f'{{"ts":{ts_a},"uid":"CUidExtreme","id.orig_h":"10.0.0.1","id.orig_p":50000,"id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp"}}',
        f'{{"ts":{ts_b},"uid":"CUidExtreme","id.orig_h":"10.0.0.1","id.orig_p":50000,"id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp"}}',
    ]
    recs = list(iter_zeek_conn_lines(lines, sensor_id="sensor-1"))
    assert len(recs) == 2
    assert recs[0].start_ts == ts_a
    assert recs[1].start_ts == ts_b
    assert recs[0].observation_id != recs[1].observation_id


def test_decimal_precision_e_equivalent_numeric_representations():
    """Test E: Equivalent numeric representations canonicalize identically, including long trailing zeros."""
    assert canonicalize_event_timestamp("1725148800.1") == "1725148800.1"
    assert canonicalize_event_timestamp("1725148800.100") == "1725148800.1"
    assert format_exact_decimal(Decimal("1725148800.1")) == format_exact_decimal(Decimal("1725148800.100"))
    assert format_exact_decimal(Decimal("1725148800.0000")) == "1725148800"
    assert format_exact_decimal(Decimal("1.7251488001E+9")) == "1725148800.1"

    # Trailing zeros past 9th fractional place ARE exact integer nanoseconds!
    exact_ns_with_zeros = Decimal("1725148800.1234567890000000000000000000")
    assert format_exact_decimal(exact_ns_with_zeros) == "1725148800.123456789"
    assert decimal_epoch_to_ns(exact_ns_with_zeros) == 1725148800123456789


def test_decimal_precision_f_context_independence_under_low_precision():
    """Test F: Deliberately low Decimal context precision never rounds outputs or mutates global context."""
    original_global_prec = getcontext().prec
    ts_str = "1725148800.123456789"
    dur_str = "0.000000001"
    iso_ts = "2024-09-01T12:00:00.123456789Z"

    line_num = (
        f'{{"ts":{ts_str},"uid":"CLowPrec01","id.orig_h":"10.0.0.1","id.orig_p":50000,'
        f'"id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp","duration":{dur_str}}}'
    )
    line_iso = json.dumps({
        "ts": iso_ts,
        "uid": "CLowPrecIso",
        "id.orig_h": "10.0.0.1",
        "id.orig_p": 50001,
        "id.resp_h": "10.0.0.2",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": "0.500000001",
    })

    # Parse under normal context as golden reference
    ref_num = list(iter_zeek_conn_lines([line_num], sensor_id="s-ctx"))[0]
    ref_iso = list(iter_zeek_conn_lines([line_iso], sensor_id="s-ctx"))[0]

    # Repeat under deliberately tiny localcontext(prec=6)
    with localcontext() as ctx:
        ctx.prec = 6
        assert canonicalize_event_timestamp(Decimal(ts_str)) == ts_str
        assert format_exact_decimal(Decimal(ts_str)) == ts_str
        assert decimal_epoch_to_ns(Decimal(ts_str)) == 1725148800123456789
        assert add_exact_decimals(Decimal(ts_str), Decimal(dur_str)) == Decimal("1725148800.123456790")

        low_num = list(iter_zeek_conn_lines([line_num], sensor_id="s-ctx"))[0]
        low_iso = list(iter_zeek_conn_lines([line_iso], sensor_id="s-ctx"))[0]
        low_payload = zeek_observation_to_payload(low_num)

    assert getcontext().prec == original_global_prec
    assert low_num.start_ts == ref_num.start_ts == ts_str
    assert low_num.end_epoch == ref_num.end_epoch == Decimal("1725148800.123456790")
    assert low_num.end_ts == ref_num.end_ts == "1725148800.12345679"
    assert low_num.observation_id == ref_num.observation_id
    assert low_payload["start_epoch_decimal"] == ts_str
    assert low_payload["end_epoch_decimal"] == "1725148800.12345679"
    assert low_payload["start_epoch_ns"] == 1725148800123456789
    assert low_payload["end_epoch_ns"] == 1725148800123456790

    assert low_iso.start_epoch == ref_iso.start_epoch == Decimal("1725192000.123456789")
    assert low_iso.end_epoch == ref_iso.end_epoch == Decimal("1725192000.623456790")
    assert low_iso.observation_id == ref_iso.observation_id


def test_decimal_precision_g_sub_nanosecond_tiny_remainder_rejected_for_ns_index():
    """Test G: Tiny nonzero digit far past the 9th fractional place must return None (never round to integer ns)."""
    tiny_sub_ns = Decimal("1725148800.1234567890000000000000000001")
    assert decimal_epoch_to_ns(tiny_sub_ns) is None
    assert format_exact_decimal(tiny_sub_ns) == "1725148800.1234567890000000000000000001"

    # Even smaller remainder at 60 fractional digits
    ultra_tiny = Decimal("1725148800." + "0" * 59 + "1")
    assert decimal_epoch_to_ns(ultra_tiny) is None
    assert format_exact_decimal(ultra_tiny) == "1725148800." + "0" * 59 + "1"

    # Pathological negative scientific exponent never crashes or truncates
    assert decimal_epoch_to_ns(Decimal("1E-100000")) is None


def test_decimal_precision_h_int64_upper_boundary_and_overflow():
    """Test H: Exact INT64_MAX nanosecond boundary succeeds; INT64_MAX+1 and huge exponents return None."""
    exact_max_epoch = Decimal("9223372036.854775807")
    overflow_by_1ns = Decimal("9223372036.854775808")
    overflow_by_sub_ns = Decimal("9223372036.8547758071")

    assert decimal_epoch_to_ns(exact_max_epoch) == INT64_MAX
    assert decimal_epoch_to_ns(overflow_by_1ns) is None
    assert decimal_epoch_to_ns(overflow_by_sub_ns) is None
    assert decimal_epoch_to_ns(Decimal("10000000000")) is None  # 10**19 ns > INT64_MAX
    assert decimal_epoch_to_ns(Decimal("9000000000")) == 9_000_000_000_000_000_000
    assert decimal_epoch_to_ns(Decimal("1E+100000")) is None

    # Read repository also rejects out-of-int64 bounds explicitly
    read_repo = Neo4jReadRepository(MagicMock())
    with pytest.raises(ValueError, match="signed 64-bit integer range"):
        read_repo.list_flow_observations(start_epoch_ns_min=INT64_MAX + 1)
    with pytest.raises(ValueError, match="signed 64-bit integer range"):
        read_repo.list_flow_observations(start_epoch_ns_max=-(2**63) - 1)


def test_decimal_precision_i_j_k_exact_addition_stable_id_and_payload_without_leakage():
    """Tests I, J, K: High-precision start_epoch + duration, stable observation_id across parses, no Decimal/float in payload."""
    ts_hi = "1725148800.12345678901234567890123456781"
    dur_hi = "0.00000000000000000000000000008"
    expected_end = "1725148800.12345678901234567890123456789"

    line = (
        f'{{"ts":{ts_hi},"uid":"CHiAdd0001","id.orig_h":"10.1.0.5","id.orig_p":41000,'
        f'"id.resp_h":"10.1.0.6","id.resp_p":443,"proto":"tcp","duration":{dur_hi}}}'
    )

    rec1 = list(iter_zeek_conn_lines([line], sensor_id="s-hi", routing_domain_id="corp"))[0]
    with localcontext() as ctx:
        ctx.prec = 8
        rec2 = list(iter_zeek_conn_lines([line], sensor_id="s-hi", routing_domain_id="corp"))[0]
        payload = zeek_observation_to_payload(rec2)

    # I: Exact addition without rounding
    assert rec1.end_epoch == Decimal(expected_end)
    assert rec1.end_ts == expected_end
    assert rec2.end_epoch == Decimal(expected_end)
    assert rec2.end_ts == expected_end

    # J: Identical stable observation_id across repeated parses and varying Decimal contexts
    assert rec1.observation_id == rec2.observation_id

    # K: Neo4j payload has zero Decimal/float leakage and exact lossless string fields
    for k, v in payload.items():
        assert not isinstance(v, Decimal), f"Payload field {k} leaked Decimal"
        assert not isinstance(v, float), f"Payload field {k} leaked float"
    assert payload["start_ts"] == ts_hi
    assert payload["start_epoch_decimal"] == ts_hi
    assert payload["duration_decimal"] == dur_hi
    assert payload["end_ts"] == expected_end
    assert payload["end_epoch_decimal"] == expected_end
    assert payload["start_epoch_ns"] is None
    assert payload["end_epoch_ns"] is None
