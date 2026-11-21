"""
Unit tests for Phase 4B Neo4j Correlation Repository and Bounded Runner Service.

Tests pure retrieval merge/completeness logic, Cypher query construction,
evidence digest determinism, reconciliation state transitions, dry-run
read-only invariants, multi-batch partial progress, MigrationRequiredError
propagation, and CLI behavior without requiring a live Neo4j database.
"""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest

from src.correlation import (
    CandidateCompleteness,
    CommunityIdSeedPolicy,
    CommunityIdStatus,
    CorrelationDecision,
    CorrelationPolicy,
    CorrelationStatus,
    SensorPairingPolicy,
    SensorPolicyMode,
    TupleCompleteness,
    alert_to_snapshot,
    correlate_alert_to_flows,
)
from src.graph.correlation_repository import (
    CYPHER_CREATE_CORRELATION,
    CYPHER_DELETE_CORRELATIONS_BY_ELEMENT_IDS,
    CYPHER_LIST_EXISTING_CORRELATIONS,
    CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE,
    CYPHER_LOAD_ALERT_EVENT_READ,
    CYPHER_RETRIEVE_CANDIDATES_BY_CID,
    CYPHER_RETRIEVE_CANDIDATES_BY_CID_UNBOUNDED,
    CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS,
    CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS_UNBOUNDED,
    CYPHER_UPDATE_CORRELATION_BY_ELEMENT_ID,
    Neo4jCorrelationRepository,
    build_correlation_edge_properties,
    compute_correlation_evidence_digest,
    derive_correlation_method,
    merge_and_classify_candidates,
    resolve_allowed_zeek_sensors,
)
from src.graph.schema import MigrationRequiredError
from src.ingestion.community_id import compute_community_id
from src.ingestion.v2_models import scoped_ip_id
from src.services.correlation_service import (
    CorrelationRunSummary,
    main as cli_main,
    run_alert_flow_correlation,
)


def _alert_row(
    *,
    event_id: str = "ae-1",
    domain: str = "corp",
    sensor_id: str = "suricata-01",
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    protocol: Optional[str] = "TCP",
    src_port: Optional[int] = 54321,
    dst_port: Optional[int] = 443,
    community_id: Optional[str] = None,
    use_default_cid: bool = True,
    timestamp_source: str = "2026-11-20T14:15:10.000000+0000",
    timestamp_epoch_decimal: Optional[str] = "1795184110",
    timestamp_epoch_ns: Optional[int] = 1795184110000000000,
    source_type: str = "suricata",
) -> Dict[str, Any]:
    cid = community_id
    if cid is None and use_default_cid and protocol is not None:
        cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return {
        "event_id": event_id,
        "alert_definition_id": "suricata:et-open:1:2001219",
        "log_source_id": "eve-main",
        "sensor_id": sensor_id,
        "routing_domain_id": domain,
        "src_scoped_id": scoped_ip_id(domain, src_ip),
        "dst_scoped_id": scoped_ip_id(domain, dst_ip),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "timestamp_source": timestamp_source,
        "timestamp_epoch_decimal": timestamp_epoch_decimal,
        "timestamp_epoch_ns": timestamp_epoch_ns,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "community_id": cid,
        "source_type": source_type,
        "source_provenance": "eve-batch",
    }


def _flow_row(
    *,
    obs_id: str = "obs-1",
    zeek_uid: str = "CZ001",
    domain: str = "corp",
    sensor_id: str = "zeek-01",
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    protocol: str = "TCP",
    src_port: Optional[int] = 54321,
    dst_port: Optional[int] = 443,
    community_id: Optional[str] = None,
    use_default_cid: bool = True,
    start_ts: str = "1795184100",
    start_epoch_decimal: Optional[str] = "1795184100",
    end_epoch_decimal: Optional[str] = "1795184120",
    duration_decimal: Optional[str] = "20",
    start_epoch_ns: Optional[int] = 1795184100000000000,
    end_epoch_ns: Optional[int] = 1795184120000000000,
    source_type: str = "zeek",
) -> Dict[str, Any]:
    cid = community_id
    if cid is None and use_default_cid:
        cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return {
        "observation_id": obs_id,
        "zeek_uid": zeek_uid,
        "routing_domain_id": domain,
        "src_scoped_id": scoped_ip_id(domain, src_ip),
        "dst_scoped_id": scoped_ip_id(domain, dst_ip),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "community_id": cid,
        "start_ts": start_ts,
        "start_epoch_decimal": start_epoch_decimal,
        "end_epoch_decimal": end_epoch_decimal,
        "duration_decimal": duration_decimal,
        "start_epoch_ns": start_epoch_ns,
        "end_epoch_ns": end_epoch_ns,
        "sensor_id": sensor_id,
        "source_type": source_type,
        "source_provenance": "zeek-batch",
    }


class _FakeResult:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def single(self) -> Optional[Dict[str, Any]]:
        return self._rows[0] if self._rows else None

    def consume(self) -> None:
        return None


class _FakeDriver:
    """In-memory Neo4j driver/tx recorder for testing query contracts and reconciliation."""

    def __init__(
        self,
        *,
        alerts: Optional[Dict[str, Dict[str, Any]]] = None,
        path_a_by_event: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        path_b_by_event: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        existing_rels: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        fail_on_event_create: Optional[str] = None,
    ):
        self.alerts = dict(alerts or {})
        self.path_a_by_event = dict(path_a_by_event or {})
        self.path_b_by_event = dict(path_b_by_event or {})
        self.existing_rels = {k: [dict(x) for x in v] for k, v in (existing_rels or {}).items()}
        self.fail_on_event_create = fail_on_event_create
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self.read_tx_count = 0
        self.write_tx_count = 0
        self._rel_seq = 100

    def verify_connectivity(self) -> None:
        return None

    def close(self) -> None:
        return None

    def session(self):
        driver = self

        class _FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def run(self, query: str, **params):
                if "unmigrated_count" in query:
                    return _FakeResult([{"unmigrated_count": 0}])
                return _FakeResult([])

            def execute_read(self, fn):
                driver.read_tx_count += 1
                tx = _FakeTx("read")
                return fn(tx)

            def execute_write(self, fn):
                driver.write_tx_count += 1
                snapshot_rels = {k: [dict(x) for x in v] for k, v in driver.existing_rels.items()}
                tx = _FakeTx("write")
                try:
                    return fn(tx)
                except Exception:
                    # Atomic transaction rollback
                    driver.existing_rels = snapshot_rels
                    raise

        class _FakeTx:
            def __init__(self, mode: str):
                self.mode = mode
                self._current_event_id: Optional[str] = None

            def run(self, query: str, **params):
                driver.calls.append((self.mode, query, dict(params)))

                if "RETURN ae.event_id AS event_id" in query and "FROM" not in query and "LIMIT $max_alerts" in query:
                    eids = sorted(driver.alerts.keys())
                    return _FakeResult([{"event_id": eid} for eid in eids[: params["max_alerts"]]])

                if query == CYPHER_LOAD_ALERT_EVENT_READ or query == CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE:
                    eid = params["event_id"]
                    self._current_event_id = eid
                    row = driver.alerts.get(eid)
                    return _FakeResult([row] if row is not None else [])

                if "MATCH (fo:FlowObservation {community_id: $community_id})" in query:
                    assert self._current_event_id is not None
                    rows = list(driver.path_a_by_event.get(self._current_event_id, []))
                    lim = params.get("fetch_limit")
                    return _FakeResult(rows[:lim] if lim is not None else rows)

                if "CALL {" in query and ":HAS_ORIGINATOR" in query:
                    assert self._current_event_id is not None
                    rows = list(driver.path_b_by_event.get(self._current_event_id, []))
                    lim = params.get("fetch_limit")
                    return _FakeResult(rows[:lim] if lim is not None else rows)

                if query == CYPHER_LIST_EXISTING_CORRELATIONS:
                    eid = params["event_id"]
                    return _FakeResult(list(driver.existing_rels.get(eid, [])))

                if query == CYPHER_DELETE_CORRELATIONS_BY_ELEMENT_IDS:
                    assert self.mode == "write"
                    eid = params["event_id"]
                    del_ids = set(params["rel_ids"])
                    before = driver.existing_rels.get(eid, [])
                    kept = [r for r in before if r["rel_id"] not in del_ids]
                    deleted = len(before) - len(kept)
                    driver.existing_rels[eid] = kept
                    return _FakeResult([{"deleted_count": deleted}])

                if query == CYPHER_CREATE_CORRELATION:
                    assert self.mode == "write"
                    eid = params["event_id"]
                    if driver.fail_on_event_create == eid:
                        raise RuntimeError(f"Injected write failure on {eid}")
                    driver._rel_seq += 1
                    rel_id = f"rel-{driver._rel_seq}"
                    entry = {
                        "rel_id": rel_id,
                        "observation_id": params["observation_id"],
                        "evidence_digest": params["props"]["evidence_digest"],
                        "policy_fingerprint": params["props"]["policy_fingerprint"],
                        "props": dict(params["props"]),
                    }
                    driver.existing_rels.setdefault(eid, []).append(entry)
                    return _FakeResult([{"rel_id": rel_id}])

                if query == CYPHER_UPDATE_CORRELATION_BY_ELEMENT_ID:
                    assert self.mode == "write"
                    eid = params["event_id"]
                    rel_id = params["rel_id"]
                    for row in driver.existing_rels.get(eid, []):
                        if row["rel_id"] == rel_id:
                            row["evidence_digest"] = params["props"]["evidence_digest"]
                            row["policy_fingerprint"] = params["props"]["policy_fingerprint"]
                            row["props"] = dict(params["props"])
                            return _FakeResult([{"rel_id": rel_id}])
                    return _FakeResult([])

                return _FakeResult([])

        return _FakeSession()


# ---------------------------------------------------------------------------
# 1. Cypher Query Structure, Sensor Narrowing & Prefilter Safety
# ---------------------------------------------------------------------------

def test_cypher_queries_enforce_domain_source_bidirectional_union_and_no_temporal_prefilter():
    # Path A: indexed community_id + routing_domain_id + zeek + no temporal filter
    assert "MATCH (fo:FlowObservation {community_id: $community_id})" in CYPHER_RETRIEVE_CANDIDATES_BY_CID
    assert "fo.routing_domain_id = $routing_domain_id" in CYPHER_RETRIEVE_CANDIDATES_BY_CID
    assert "fo.source_type = 'zeek'" in CYPHER_RETRIEVE_CANDIDATES_BY_CID
    assert "LIMIT $fetch_limit" in CYPHER_RETRIEVE_CANDIDATES_BY_CID
    assert "LIMIT $fetch_limit" not in CYPHER_RETRIEVE_CANDIDATES_BY_CID_UNBOUNDED

    # Path B: forward + reverse UNION over scoped_id + domain + zeek + no temporal filter
    assert "CALL {" in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert "UNION" in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert "UNION ALL" not in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert ":HAS_ORIGINATOR" in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert ":HAS_RESPONDER" in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert "ip_address" not in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert "fo.start_epoch_ns >=" not in CYPHER_RETRIEVE_CANDIDATES_BY_CID
    assert "fo.start_epoch_ns >=" not in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert "fo.end_epoch_ns" not in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS.split("RETURN")[0]
    assert "LIMIT $fetch_limit" in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
    assert "LIMIT $fetch_limit" not in CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS_UNBOUNDED

    # Write lock cypher sets & removes marker within tx without leaving property behind
    assert "SET ae._corr_tx_lock = true" in CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE
    assert "REMOVE ae._corr_tx_lock" in CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE
    assert "SET" not in CYPHER_LOAD_ALERT_EVENT_READ


def test_resolve_allowed_zeek_sensors_modes():
    assert resolve_allowed_zeek_sensors("Suricata-01", CorrelationPolicy()) is None

    same_pol = CorrelationPolicy(sensor_policy=SensorPairingPolicy.same_sensor_id())
    assert resolve_allowed_zeek_sensors(" Suricata-01 ", same_pol) == ["suricata-01"]

    explicit_pol = CorrelationPolicy(
        sensor_policy=SensorPairingPolicy.from_explicit_pairs(
            {"suricata-edge": ["zeek-core", "zeek-dmz"]}
        )
    )
    assert resolve_allowed_zeek_sensors("SURICATA-EDGE", explicit_pol) == ["zeek-core", "zeek-dmz"]
    assert resolve_allowed_zeek_sensors("unconfigured-sensor", explicit_pol) == []


# ---------------------------------------------------------------------------
# 2. Candidate Union, Deduplication, Missing CID & Overflow Detection
# ---------------------------------------------------------------------------

def test_merge_and_classify_candidates_dedup_conflict_and_overflow():
    r1 = _flow_row(obs_id="obs-1", zeek_uid="Z1")
    r2_null_cid = _flow_row(obs_id="obs-2", zeek_uid="Z2", use_default_cid=False, community_id=None)

    # Deduplication across Path A and Path B, exact cap -> COMPLETE
    res = merge_and_classify_candidates([r1], [r1, r2_null_cid], candidate_cap=2)
    assert res.completeness == CandidateCompleteness.COMPLETE
    assert [c.observation_id for c in res.candidates] == ["obs-1", "obs-2"]
    assert res.path_a_overflow is False
    assert res.path_b_overflow is False

    # Conflicting duplicate observation_id between paths -> ValueError
    r1_tampered = dict(r1, src_port=60000)
    with pytest.raises(ValueError, match="Conflicting duplicate"):
        merge_and_classify_candidates([r1], [r1_tampered], candidate_cap=10)

    # Overflow in Path A, Path B, or union -> TRUNCATED (neither path can mask the other)
    r3 = _flow_row(obs_id="obs-3", zeek_uid="Z3")
    res_union_over = merge_and_classify_candidates([r1, r2_null_cid], [r2_null_cid, r3], candidate_cap=2)
    assert res_union_over.completeness == CandidateCompleteness.TRUNCATED

    res_path_b_over = merge_and_classify_candidates([r1], [r1, r2_null_cid, r3], candidate_cap=2)
    assert res_path_b_over.completeness == CandidateCompleteness.TRUNCATED
    assert res_path_b_over.path_a_overflow is False
    assert res_path_b_over.path_b_overflow is True

    # Unbounded cap (None) -> COMPLETE
    res_unbounded = merge_and_classify_candidates([r1], [r2_null_cid, r3], candidate_cap=None)
    assert res_unbounded.completeness == CandidateCompleteness.COMPLETE


def test_retrieval_always_executes_path_b_when_cid_present_and_handles_corrupt_row():
    alert = alert_to_snapshot(_alert_row(event_id="ae-cid-1"))
    f_cid = _flow_row(obs_id="obs-cid", zeek_uid="ZC")
    f_null = _flow_row(obs_id="obs-null-cid", zeek_uid="ZN", use_default_cid=False, community_id=None)

    driver = _FakeDriver(
        alerts={"ae-cid-1": _alert_row(event_id="ae-cid-1")},
        path_a_by_event={"ae-cid-1": [f_cid]},
        path_b_by_event={"ae-cid-1": [f_cid, f_null]},
    )
    repo = Neo4jCorrelationRepository(driver)
    # Require CID -> f_cid STRONG, f_null INSUFFICIENT -> AMBIGUOUS (must never drop f_null!)
    res = repo.correlate_alert_event(
        "ae-cid-1",
        policy=CorrelationPolicy(require_community_id=True, candidate_cap=10),
    )
    assert res.decision.status == CorrelationStatus.AMBIGUOUS
    assert res.action == "no_change"
    assert any("CALL {" in q for _, q, _ in driver.calls)
    assert any("{community_id: $community_id}" in q for _, q, _ in driver.calls)

    # Corrupted row in DB (invalid float epoch or conflicting payload) -> RETRIEVAL_ERROR, zero mutations
    bad_flow = _flow_row(obs_id="obs-bad", source_type="suricata")
    driver_err = _FakeDriver(
        alerts={"ae-cid-1": _alert_row(event_id="ae-cid-1")},
        path_b_by_event={"ae-cid-1": [bad_flow]},
        existing_rels={"ae-cid-1": [{"rel_id": "rel-old", "observation_id": "obs-prev", "evidence_digest": "d"}]},
    )
    repo_err = Neo4jCorrelationRepository(driver_err)
    out_err = repo_err.correlate_alert_batch(["ae-cid-1"])
    assert out_err.retrieval_errors == 1
    assert out_err.incomplete_evaluations == 1
    assert out_err.stale_correlations_removed == 0
    assert out_err.outcomes[0].action == "incomplete_skipped"
    assert out_err.outcomes[0].existing_correlation_unverified is True
    assert len(driver_err.existing_rels["ae-cid-1"]) == 1  # Prior edge not blindly wiped!


# ---------------------------------------------------------------------------
# 3. Evidence Digest, Relationship Props & Method Derivation
# ---------------------------------------------------------------------------

def test_evidence_digest_determinism_policy_sensitivity_and_no_confidence_score():
    alert = alert_to_snapshot(_alert_row())
    flow = _flow_row()
    p1 = CorrelationPolicy()
    p2 = CorrelationPolicy(post_end_tolerance_sec=Decimal("1"), allow_tolerance_match=True)

    d1 = correlate_alert_to_flows(alert, [flow], policy=p1, candidate_completeness=CandidateCompleteness.COMPLETE)
    d2 = correlate_alert_to_flows(alert, [flow], policy=p2, candidate_completeness=CandidateCompleteness.COMPLETE)

    props1a = build_correlation_edge_properties(d1, alert, decided_at_utc="2026-11-21T10:00:00Z")
    props1b = build_correlation_edge_properties(d1, alert, decided_at_utc="2026-11-21T12:00:00Z")
    props2 = build_correlation_edge_properties(d2, alert, decided_at_utc="2026-11-21T10:00:00Z")

    # Decided timestamp must NOT affect deterministic evidence_digest
    assert props1a["evidence_digest"] == props1b["evidence_digest"]
    # Policy fingerprint change MUST alter evidence_digest
    assert props1a["evidence_digest"] != props2["evidence_digest"]
    assert props1a["policy_fingerprint"] != props2["policy_fingerprint"]
    assert props1a["correlation_method"] == "cid_verified_5tuple_temporal"
    assert "confidence" not in props1a
    assert "score" not in props1a

    # Missing CID TCP fallback -> tuple_temporal_no_cid
    flow_nocid = _flow_row(obs_id="obs-nocid", use_default_cid=False, community_id=None)
    d_nocid = correlate_alert_to_flows(
        alert, [flow_nocid], policy=p1, candidate_completeness=CandidateCompleteness.COMPLETE
    )
    assert derive_correlation_method(d_nocid.selected_evidence) == "tuple_temporal_no_cid"

    # Non-STRONG decision cannot build edge properties
    ambig_dec = replace(d1, status=CorrelationStatus.AMBIGUOUS, auto_correlate_allowed=False)
    with pytest.raises(ValueError, match="STRONG"):
        build_correlation_edge_properties(ambig_dec, alert)


# ---------------------------------------------------------------------------
# 4. Idempotency, Stale Reconciliation & Dry-Run Read-Only Guarantees
# ---------------------------------------------------------------------------

def test_reconciliation_idempotent_update_stale_removal_and_dry_run():
    a_row = _alert_row(event_id="ae-rec-1", timestamp_epoch_ns=None, timestamp_epoch_decimal="10413792005")
    f1 = _flow_row(
        obs_id="obs-f1",
        start_ts="10413792000",
        start_epoch_decimal="10413792000",
        end_epoch_decimal="10413792010",
        duration_decimal="10",
        start_epoch_ns=None,
        end_epoch_ns=None,
    )
    driver = _FakeDriver(
        alerts={"ae-rec-1": a_row},
        path_a_by_event={"ae-rec-1": [f1]},
        path_b_by_event={"ae-rec-1": [f1]},
    )
    repo = Neo4jCorrelationRepository(driver)

    # Dry-run creates zero edges and runs inside execute_read only
    dry_res = repo.correlate_alert_batch(["ae-rec-1"], dry_run=True)
    assert dry_res.strong == 1
    assert dry_res.correlations_created == 0
    assert driver.write_tx_count == 0
    assert driver.read_tx_count == 1
    assert driver.existing_rels.get("ae-rec-1", []) == []

    # First live run creates 1 edge with used_decimal_fallback=True (NULL ns preserved)
    run1 = repo.correlate_alert_batch(["ae-rec-1"])
    assert run1.correlations_created == 1
    assert len(driver.existing_rels["ae-rec-1"]) == 1
    props_created = driver.existing_rels["ae-rec-1"][0]["props"]
    assert props_created["used_decimal_fallback"] is True

    # Second identical run sees unchanged digest -> zero CREATE/UPDATE/DELETE queries
    calls_before = len(driver.calls)
    run2 = repo.correlate_alert_batch(["ae-rec-1"])
    assert run2.correlations_unchanged == 1
    assert run2.correlations_created == 0
    assert run2.correlations_updated == 0
    new_queries = [q for _, q, _ in driver.calls[calls_before:]]
    assert not any(q in (CYPHER_CREATE_CORRELATION, CYPHER_UPDATE_CORRELATION_BY_ELEMENT_ID, CYPHER_DELETE_CORRELATIONS_BY_ELEMENT_IDS) for q in new_queries)

    # Policy change updates metadata in place (correlations_updated == 1)
    p_tol = CorrelationPolicy(post_end_tolerance_sec=Decimal("2"), allow_tolerance_match=True)
    run3 = repo.correlate_alert_batch(["ae-rec-1"], policy=p_tol)
    assert run3.correlations_updated == 1
    assert len(driver.existing_rels["ae-rec-1"]) == 1

    # Add competing flow -> AMBIGUOUS removes stale edge
    f2 = dict(f1, observation_id="obs-f2", zeek_uid="CZ002")
    driver.path_a_by_event["ae-rec-1"].append(f2)
    driver.path_b_by_event["ae-rec-1"].append(f2)
    run4 = repo.correlate_alert_batch(["ae-rec-1"], policy=p_tol)
    assert run4.ambiguous == 1
    assert run4.stale_correlations_removed == 1
    assert driver.existing_rels["ae-rec-1"] == []


def test_reconciliation_target_switch_and_input_validation_errors():
    a1 = _alert_row(event_id="ae-switch")
    f1 = _flow_row(obs_id="obs-old", zeek_uid="Z-old")
    f2 = _flow_row(obs_id="obs-new", zeek_uid="Z-new")
    driver = _FakeDriver(
        alerts={"ae-switch": a1},
        path_a_by_event={"ae-switch": [f2]},
        path_b_by_event={"ae-switch": [f2]},
        existing_rels={"ae-switch": [{"rel_id": "rel-stale-target", "observation_id": f1["observation_id"], "evidence_digest": "old"}]},
    )
    repo = Neo4jCorrelationRepository(driver)

    res = repo.correlate_alert_event("ae-switch")
    assert res.action == "created"
    assert res.stale_removed == 1
    assert len(driver.existing_rels["ae-switch"]) == 1
    assert driver.existing_rels["ae-switch"][0]["observation_id"] == "obs-new"

    with pytest.raises(LookupError, match="AlertEvent not found"):
        repo.correlate_alert_event("missing-event")
    with pytest.raises(ValueError, match="non-empty"):
        repo.correlate_alert_batch(["  "])
    with pytest.raises(ValueError, match="max_alerts"):
        repo.list_correlatable_alert_event_ids(max_alerts=0)
    with pytest.raises(ValueError, match="batch_size"):
        run_alert_flow_correlation(batch_size=0, driver=driver)
    assert repo.correlate_alert_batch([]).alerts_evaluated == 0


# ---------------------------------------------------------------------------
# 5. Bounded Runner, Multi-Batch Partial Progress, Migration Guard & CLI
# ---------------------------------------------------------------------------

def test_runner_multi_batch_partial_progress_migration_guard_and_cli(monkeypatch):
    a1 = _alert_row(event_id="ae-1")
    a2 = _alert_row(event_id="ae-2")
    f1 = _flow_row(obs_id="obs-1")
    driver = _FakeDriver(
        alerts={"ae-1": a1, "ae-2": a2},
        path_a_by_event={"ae-1": [f1], "ae-2": [f1]},
        path_b_by_event={"ae-1": [f1], "ae-2": [f1]},
        fail_on_event_create="ae-2",
    )

    # Batch 1 (ae-1) commits; Batch 2 (ae-2) raises & rolls back atomically while Batch 1 persists
    with pytest.raises(RuntimeError, match="Injected write failure on ae-2"):
        run_alert_flow_correlation(batch_size=1, driver=driver)
    assert len(driver.existing_rels["ae-1"]) == 1
    assert driver.existing_rels.get("ae-2", []) == []

    # Clear failure & re-run converges idempotently across both alerts
    driver.fail_on_event_create = None
    summary = run_alert_flow_correlation(batch_size=1, driver=driver)
    assert isinstance(summary, CorrelationRunSummary)
    assert summary.alerts_evaluated == 2
    assert summary.correlations_unchanged == 1
    assert summary.correlations_created == 1
    assert summary.batches_committed == 2
    assert len(driver.existing_rels["ae-2"]) == 1

    # MigrationRequiredError propagates cleanly before any correlation writes
    legacy_driver = MagicMock()
    legacy_session = MagicMock()
    legacy_driver.session.return_value.__enter__.return_value = legacy_session
    check_res = MagicMock()
    check_res.single.return_value = {"unmigrated_count": 3}
    legacy_session.run.return_value = check_res
    with pytest.raises(MigrationRequiredError):
        run_alert_flow_correlation(driver=legacy_driver)

    # CLI entrypoint invokes run_alert_flow_correlation cleanly and outputs JSON
    def _fake_runner(**kwargs):
        return summary

    monkeypatch.setattr("src.services.correlation_service.run_alert_flow_correlation", _fake_runner)
    rc = cli_main(["--routing-domain-id", "corp", "--dry-run", "--max-alerts", "50", "--batch-size", "10"])
    assert rc == 0

    def _fail_migration(**kwargs):
        raise MigrationRequiredError(2)

    monkeypatch.setattr("src.services.correlation_service.run_alert_flow_correlation", _fail_migration)
    assert cli_main(["--dry-run"]) == 1
