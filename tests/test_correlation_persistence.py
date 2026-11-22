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
    CYPHER_GET_ALERT_CORRELATIONS,
    CYPHER_LIST_CORRELATABLE_ALERT_IDS,
    CYPHER_LIST_EXISTING_CORRELATIONS,
    CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE,
    CYPHER_LOAD_ALERT_EVENT_READ,
    CYPHER_MARK_CORRELATIONS_UNVERIFIED,
    CYPHER_RETRIEVE_CANDIDATES_BY_CID,
    CYPHER_RETRIEVE_CANDIDATES_BY_CID_UNBOUNDED,
    CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS,
    CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS_UNBOUNDED,
    CYPHER_UPDATE_CORRELATION_BY_ELEMENT_ID,
    VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE,
    VERIFICATION_STATUS_VERIFIED,
    AlertSelectionCursor,
    Neo4jCorrelationRepository,
    build_correlation_edge_properties,
    compute_correlation_evidence_digest,
    derive_correlation_method,
    merge_and_classify_candidates,
    resolve_allowed_zeek_sensors,
)
from src.graph.schema import (
    REQUIRED_CORRELATION_CONSTRAINTS,
    REQUIRED_CORRELATION_INDEXES,
    MigrationRequiredError,
    SchemaNotReadyError,
    verify_schema_read_only,
)
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
        constraints: Optional[List[str]] = None,
        indexes: Optional[Dict[str, str]] = None,
        unmigrated_count: int = 0,
    ):
        self.alerts = dict(alerts or {})
        self.path_a_by_event = dict(path_a_by_event or {})
        self.path_b_by_event = dict(path_b_by_event or {})
        self.existing_rels = {k: [dict(x) for x in v] for k, v in (existing_rels or {}).items()}
        self.fail_on_event_create = fail_on_event_create
        self.constraints = (
            list(constraints) if constraints is not None else list(REQUIRED_CORRELATION_CONSTRAINTS)
        )
        self.indexes = (
            dict(indexes)
            if indexes is not None
            else {idx: "ONLINE" for idx in REQUIRED_CORRELATION_INDEXES}
        )
        self.unmigrated_count = unmigrated_count
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self.session_runs: List[str] = []
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
                driver.session_runs.append(query)
                if "unmigrated_count" in query:
                    return _FakeResult([{"unmigrated_count": driver.unmigrated_count}])
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

                if "unmigrated_count" in query:
                    return _FakeResult([{"unmigrated_count": driver.unmigrated_count}])

                if query.strip().startswith("SHOW CONSTRAINTS"):
                    return _FakeResult([{"name": c} for c in driver.constraints])

                if query.strip().startswith("SHOW INDEXES"):
                    return _FakeResult([{"name": k, "state": v} for k, v in driver.indexes.items()])

                if query == CYPHER_LIST_CORRELATABLE_ALERT_IDS:
                    only_uncorr = bool(params.get("only_uncorrelated", False))
                    after_eid = params.get("after_event_id")
                    after_ts = params.get("after_ts")
                    after_ts_is_null = bool(params.get("after_ts_is_null", False))
                    dom = params.get("routing_domain_id")
                    sensor = params.get("sensor_id")

                    matched = []
                    for row in driver.alerts.values():
                        if row.get("source_type") != "suricata":
                            continue
                        if dom is not None and row.get("routing_domain_id") != dom:
                            continue
                        if sensor is not None and str(row.get("sensor_id", "")).strip().lower() != sensor:
                            continue
                        eid = str(row["event_id"])
                        if only_uncorr and driver.existing_rels.get(eid):
                            continue
                        ts = row.get("timestamp_epoch_ns")
                        if after_eid is not None:
                            if not after_ts_is_null:
                                if not (
                                    ts is None
                                    or ts > after_ts
                                    or (ts == after_ts and eid > after_eid)
                                ):
                                    continue
                            else:
                                if not (ts is None and eid > after_eid):
                                    continue
                        matched.append((0 if ts is not None else 1, ts if ts is not None else 0, eid, ts))

                    matched.sort(key=lambda item: (item[0], item[1], item[2]))
                    lim = params["fetch_limit"]
                    return _FakeResult(
                        [{"event_id": item[2], "timestamp_epoch_ns": item[3]} for item in matched[:lim]]
                    )

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

                if query == CYPHER_MARK_CORRELATIONS_UNVERIFIED:
                    assert self.mode == "write"
                    eid = params["event_id"]
                    cnt = 0
                    for row in driver.existing_rels.get(eid, []):
                        row["verification_status"] = VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
                        row["last_incomplete_reason"] = params["reason"]
                        row["last_incomplete_at_utc"] = params["marked_at_utc"]
                        if "props" in row:
                            row["props"]["verification_status"] = VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
                            row["props"]["last_incomplete_reason"] = params["reason"]
                            row["props"]["last_incomplete_at_utc"] = params["marked_at_utc"]
                        cnt += 1
                    return _FakeResult([{"marked_count": cnt}])

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
                        "verification_status": params["props"].get("verification_status", VERIFICATION_STATUS_VERIFIED),
                        "last_incomplete_reason": params["props"].get("last_incomplete_reason"),
                        "last_incomplete_at_utc": params["props"].get("last_incomplete_at_utc"),
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
                            row["verification_status"] = params["props"].get("verification_status", VERIFICATION_STATUS_VERIFIED)
                            row["last_incomplete_reason"] = params["props"].get("last_incomplete_reason")
                            row["last_incomplete_at_utc"] = params["props"].get("last_incomplete_at_utc")
                            row["props"] = dict(params["props"])
                            return _FakeResult([{"rel_id": rel_id}])
                    return _FakeResult([])

                if query == CYPHER_GET_ALERT_CORRELATIONS:
                    out = []
                    inc_unv = bool(params.get("include_unverified", True))
                    target_eid = params.get("event_id")
                    for eid, rels in sorted(driver.existing_rels.items()):
                        if target_eid is not None and eid != target_eid:
                            continue
                        for r in rels:
                            vstat = r.get("verification_status") or VERIFICATION_STATUS_VERIFIED
                            if not inc_unv and vstat != VERIFICATION_STATUS_VERIFIED:
                                continue
                            props = r.get("props") or {}
                            out.append(
                                {
                                    "event_id": eid,
                                    "observation_id": r["observation_id"],
                                    "zeek_uid": "CZ",
                                    "evidence_digest": r["evidence_digest"],
                                    "verification_status": vstat,
                                    "last_incomplete_reason": r.get("last_incomplete_reason"),
                                    "last_incomplete_at_utc": r.get("last_incomplete_at_utc"),
                                    "routing_domain_id": props.get("routing_domain_id"),
                                }
                            )
                    return _FakeResult(out[: params["limit"]])

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

    def _fail_schema(**kwargs):
        raise SchemaNotReadyError(missing_indexes=["flow_observation_community_id_index"])

    monkeypatch.setattr("src.services.correlation_service.run_alert_flow_correlation", _fail_schema)
    assert cli_main(["--dry-run"]) == 1


# ---------------------------------------------------------------------------
# 6. Independent Review Hardening Tests (Dry-Run DDL, Pagination, Freshness)
# ---------------------------------------------------------------------------

def test_review_dry_run_executes_read_only_schema_preflight_zero_ddl_and_rejects_missing_schema():
    a1 = _alert_row(event_id="ae-dry-1")
    f1 = _flow_row(obs_id="obs-dry-1")

    # Initialized schema: dry-run succeeds with ZERO session.run DDL and ZERO write tx
    ok_driver = _FakeDriver(
        alerts={"ae-dry-1": a1},
        path_a_by_event={"ae-dry-1": [f1]},
        path_b_by_event={"ae-dry-1": [f1]},
    )
    dry_summary = run_alert_flow_correlation(dry_run=True, driver=ok_driver)
    assert dry_summary.dry_run is True
    assert dry_summary.strong == 1
    assert dry_summary.correlations_created == 0
    assert dry_summary.batches_committed == 0
    assert ok_driver.write_tx_count == 0
    assert ok_driver.session_runs == []  # ensure_schema() DDL was NEVER called!
    assert all(
        not any(ddl in q for ddl in ("CREATE CONSTRAINT", "CREATE INDEX", "DROP CONSTRAINT"))
        for _, q, _ in ok_driver.calls
    )

    # Missing index or constraint: dry-run fails with SchemaNotReadyError and executes ZERO DDL
    missing_driver = _FakeDriver(
        alerts={"ae-dry-1": a1},
        constraints=[c for c in REQUIRED_CORRELATION_CONSTRAINTS if c != "alert_event_unique"],
        indexes={
            k: "ONLINE"
            for k in REQUIRED_CORRELATION_INDEXES
            if k != "flow_observation_community_id_index"
        },
    )
    with pytest.raises(SchemaNotReadyError) as exc_info:
        run_alert_flow_correlation(dry_run=True, driver=missing_driver)
    assert "alert_event_unique" in exc_info.value.missing_constraints
    assert "flow_observation_community_id_index" in exc_info.value.missing_indexes
    assert missing_driver.write_tx_count == 0
    assert missing_driver.session_runs == []

    # Failed index state also raises SchemaNotReadyError without DDL
    failed_idx_driver = _FakeDriver(
        indexes={
            **{k: "ONLINE" for k in REQUIRED_CORRELATION_INDEXES},
            "flow_observation_community_id_index": "FAILED",
        }
    )
    with pytest.raises(SchemaNotReadyError) as exc_fail:
        verify_schema_read_only(failed_idx_driver)
    assert "flow_observation_community_id_index" in exc_fail.value.failed_indexes

    # Unmigrated V1 IPAddress nodes in dry-run raise MigrationRequiredError without DDL
    legacy_driver = _FakeDriver(unmigrated_count=4)
    with pytest.raises(MigrationRequiredError) as exc_mig:
        run_alert_flow_correlation(dry_run=True, driver=legacy_driver)
    assert exc_mig.value.unmigrated_count == 4
    assert legacy_driver.write_tx_count == 0
    assert legacy_driver.session_runs == []

    # Normal write mode still executes ensure_schema() preflight
    write_driver = _FakeDriver(
        alerts={"ae-dry-1": a1},
        path_a_by_event={"ae-dry-1": [f1]},
        path_b_by_event={"ae-dry-1": [f1]},
    )
    w_summary = run_alert_flow_correlation(dry_run=False, driver=write_driver)
    assert w_summary.correlations_created == 1
    assert any("CREATE CONSTRAINT" in q for q in write_driver.session_runs)


def test_review_keyset_pagination_identical_timestamps_null_ts_only_uncorrelated_and_explicit_limit():
    # Build 7 alerts: 3 with identical timestamp, 2 with later timestamp, 2 with NULL timestamp
    t1 = 1795184110000000000
    t2 = 1795184120000000000
    alerts = {
        "ae-01": _alert_row(event_id="ae-01", timestamp_epoch_decimal="1795184110", timestamp_epoch_ns=t1),
        "ae-02": _alert_row(event_id="ae-02", timestamp_epoch_decimal="1795184110", timestamp_epoch_ns=t1),
        "ae-03": _alert_row(event_id="ae-03", timestamp_epoch_decimal="1795184110", timestamp_epoch_ns=t1),
        "ae-04": _alert_row(event_id="ae-04", timestamp_epoch_decimal="1795184120", timestamp_epoch_ns=t2),
        "ae-05": _alert_row(event_id="ae-05", timestamp_epoch_decimal="1795184120", timestamp_epoch_ns=t2),
        "ae-06": _alert_row(event_id="ae-06", timestamp_epoch_decimal=None, timestamp_epoch_ns=None),
        "ae-07": _alert_row(event_id="ae-07", timestamp_epoch_decimal=None, timestamp_epoch_ns=None),
    }
    f_t1 = _flow_row(obs_id="obs-t1", start_epoch_decimal="1795184100", end_epoch_decimal="1795184130", start_epoch_ns=1795184100000000000, end_epoch_ns=1795184130000000000)
    driver = _FakeDriver(
        alerts=alerts,
        path_a_by_event={eid: [f_t1] for eid in alerts},
        path_b_by_event={eid: [f_t1] for eid in alerts},
    )

    # Paginate across ALL 7 alerts with max_alerts=2 (4 pages: 2, 2, 2, 1) -> zero skips, zero duplicates
    seen_eids: List[str] = []
    cursor: Optional[AlertSelectionCursor] = None
    pages = 0
    while True:
        page = Neo4jCorrelationRepository(driver).list_correlatable_alert_page(
            max_alerts=2, after_cursor=cursor
        )
        seen_eids.extend(page.event_ids)
        pages += 1
        if not page.has_more:
            assert page.next_cursor is None
            break
        assert page.next_cursor is not None
        # Verify JSON token roundtrip
        cursor = AlertSelectionCursor.from_token(page.next_cursor.to_token())
    assert pages == 4
    assert seen_eids == ["ae-01", "ae-02", "ae-03", "ae-04", "ae-05", "ae-06", "ae-07"]

    # Runner pagination end-to-end (max_alerts=2) correlates all 5 timed alerts and evaluates 2 naive alerts
    total_eval = 0
    total_created = 0
    run_cursor: Optional[str] = None
    while True:
        s = run_alert_flow_correlation(max_alerts=2, batch_size=2, after_cursor=run_cursor, driver=driver)
        total_eval += s.alerts_evaluated
        total_created += s.correlations_created
        if not s.has_more:
            assert s.next_cursor is None
            break
        assert s.next_cursor is not None
        run_cursor = s.next_cursor.to_token()
    assert total_eval == 7
    assert total_created == 5

    # only_uncorrelated=True progresses across remaining uncorrelated alerts (ae-06, ae-07) with max_alerts=1
    u1 = run_alert_flow_correlation(only_uncorrelated=True, max_alerts=1, driver=driver)
    assert u1.alerts_evaluated == 1
    assert u1.insufficient == 1
    assert u1.has_more is True
    assert u1.next_cursor == AlertSelectionCursor(timestamp_epoch_ns=None, event_id="ae-06")
    u2 = run_alert_flow_correlation(
        only_uncorrelated=True, max_alerts=1, after_cursor=u1.next_cursor, driver=driver
    )
    assert u2.alerts_evaluated == 1
    assert u2.insufficient == 1
    assert u2.has_more is False
    assert u2.next_cursor is None

    # Explicit event_ids exceeding max_alerts MUST raise ValueError (never silently dropped)
    with pytest.raises(ValueError, match="exceeds max_alerts"):
        run_alert_flow_correlation(event_ids=["ae-01", "ae-02", "ae-03"], max_alerts=2, driver=driver)

    # Combining explicit event_ids and after_cursor raises ValueError
    with pytest.raises(ValueError, match="after_cursor cannot be combined"):
        run_alert_flow_correlation(
            event_ids=["ae-01"],
            after_cursor=AlertSelectionCursor(timestamp_epoch_ns=t1, event_id="ae-01"),
            driver=driver,
        )

    # Invalid cursor token raises ValueError
    with pytest.raises(ValueError):
        AlertSelectionCursor.from_token("{invalid-json")
    with pytest.raises(ValueError):
        AlertSelectionCursor.from_token('{"event_id":"ae-01"}')


def test_review_incomplete_reevaluation_marks_existing_edge_unverified_non_destructively_and_recovers():
    a1 = _alert_row(event_id="ae-fresh")
    f1 = _flow_row(obs_id="obs-1", zeek_uid="Z1")
    f2_bad = _flow_row(obs_id="obs-2", zeek_uid="Z2", src_port=11111)
    f3_bad = _flow_row(obs_id="obs-3", zeek_uid="Z3", src_port=22222)

    driver = _FakeDriver(
        alerts={"ae-fresh": a1},
        path_a_by_event={"ae-fresh": [f1]},
        path_b_by_event={"ae-fresh": [f1]},
    )
    repo = Neo4jCorrelationRepository(driver)

    # 1. Create verified correlation
    r1 = repo.correlate_alert_event("ae-fresh", policy=CorrelationPolicy(candidate_cap=2))
    assert r1.action == "created"
    orig_digest = r1.evidence_digest
    corrs_1 = repo.get_alert_correlations("ae-fresh")
    assert len(corrs_1) == 1
    assert corrs_1[0]["verification_status"] == VERIFICATION_STATUS_VERIFIED
    assert corrs_1[0]["last_incomplete_reason"] is None

    # 2. Overflow candidate_cap=2 -> TRUNCATED preserves edge & digest, marks verification_status='unverified_incomplete'
    driver.path_b_by_event["ae-fresh"] = [f1, f2_bad, f3_bad]
    r2 = repo.correlate_alert_event("ae-fresh", policy=CorrelationPolicy(candidate_cap=2))
    assert r2.action == "incomplete_skipped"
    assert r2.stale_removed == 0
    assert r2.existing_correlation_unverified is True

    corrs_all = repo.get_alert_correlations("ae-fresh", include_unverified=True)
    assert len(corrs_all) == 1
    assert corrs_all[0]["evidence_digest"] == orig_digest  # original evidence preserved!
    assert corrs_all[0]["verification_status"] == VERIFICATION_STATUS_UNVERIFIED_INCOMPLETE
    assert corrs_all[0]["last_incomplete_reason"] == "CANDIDATE_SET_TRUNCATED"
    assert repo.get_alert_correlations("ae-fresh", include_unverified=False) == []

    # 3. Raise candidate_cap -> COMPLETE STRONG clears unverified flag back to 'verified'
    r3 = repo.correlate_alert_event("ae-fresh", policy=CorrelationPolicy(candidate_cap=10))
    assert r3.action == "updated"
    corrs_3 = repo.get_alert_correlations("ae-fresh", include_unverified=False)
    assert len(corrs_3) == 1
    assert corrs_3[0]["verification_status"] == VERIFICATION_STATUS_VERIFIED
    assert corrs_3[0]["last_incomplete_reason"] is None
