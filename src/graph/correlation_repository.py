"""
Phase 4B Neo4j Zeek-Suricata Correlation Repository.

Implements bounded, read-only candidate retrieval (indexed Community ID +
domain-scoped bidirectional endpoint union), explicit CandidateCompleteness
reporting into the Phase 4A correlation engine, idempotent (:AlertEvent)-[:CORRELATED_WITH]->(:FlowObservation)
persistence, and safe stale-correlation reconciliation.

Guarantees & Limitations:
- Reuses Phase 4A (`src/correlation/`) without duplicating eligibility logic.
- NEVER relies on Phase 4A's default `CandidateCompleteness.UNKNOWN`; always passes
  explicit completeness (`COMPLETE`, `TRUNCATED`, or `RETRIEVAL_ERROR`).
- NEVER omits NULL-community_id flows: Path B (scoped endpoint union) executes
  even when the AlertEvent has a non-null `community_id`.
- NEVER applies an unsafe database temporal prefilter that could drop long-lived
  flows, missing end/start epochs, sub-nanosecond timestamps, or out-of-int64 dates.
- Write transactions acquire a per-AlertEvent node write lock (`SET`/`WITH`/`REMOVE`
  of an ephemeral marker inside the same transaction) to serialize concurrent
  correlation workers without altering committed AlertEvent telemetry properties or
  `payload_digest`.
- Under Neo4j Read Committed isolation, concurrency with independent Zeek/Suricata
  ingestion writes is NOT globally serializable; run ingestion and correlation
  sequentially or re-run correlation idempotently to reconcile newly ingested flows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src.correlation import (
    AlertSnapshot,
    CandidateCompleteness,
    CommunityIdStatus,
    CorrelationCandidateEvidence,
    CorrelationDecision,
    CorrelationPolicy,
    CorrelationStatus,
    FlowSnapshot,
    SensorPolicyMode,
    TupleCompleteness,
    alert_to_snapshot,
    correlate_alert_to_flows,
    flow_to_snapshot,
)

logger = logging.getLogger(__name__)

CORRELATION_REL_TYPE = "CORRELATED_WITH"

CYPHER_LIST_CORRELATABLE_ALERT_IDS = """
MATCH (ae:AlertEvent)
WHERE ae.source_type = 'suricata'
  AND ($routing_domain_id IS NULL OR ae.routing_domain_id = $routing_domain_id)
  AND ($sensor_id IS NULL OR toLower(trim(ae.sensor_id)) = $sensor_id)
  AND (NOT $only_uncorrelated OR NOT (ae)-[:CORRELATED_WITH]->(:FlowObservation))
RETURN ae.event_id AS event_id
ORDER BY CASE WHEN ae.timestamp_epoch_ns IS NULL THEN 1 ELSE 0 END ASC,
         ae.timestamp_epoch_ns ASC,
         ae.event_id ASC
LIMIT $max_alerts
"""

_ALERT_EVENT_RETURN_COLUMNS = """
RETURN ae.event_id AS event_id,
       ae.alert_definition_id AS alert_definition_id,
       ae.log_source_id AS log_source_id,
       ae.sensor_id AS sensor_id,
       ae.routing_domain_id AS routing_domain_id,
       ae.src_scoped_id AS src_scoped_id,
       ae.dst_scoped_id AS dst_scoped_id,
       ae.src_ip AS src_ip,
       ae.dst_ip AS dst_ip,
       ae.timestamp_source AS timestamp_source,
       ae.timestamp_epoch_decimal AS timestamp_epoch_decimal,
       ae.timestamp_epoch_ns AS timestamp_epoch_ns,
       ae.protocol AS protocol,
       ae.src_port AS src_port,
       ae.dst_port AS dst_port,
       ae.community_id AS community_id,
       ae.source_type AS source_type,
       ae.source_provenance AS source_provenance
"""

CYPHER_LOAD_ALERT_EVENT_READ = f"""
MATCH (ae:AlertEvent {{event_id: $event_id}})
{_ALERT_EVENT_RETURN_COLUMNS}
"""

# Acquires Neo4j's per-node write lock on ae for the write transaction duration
# without modifying committed properties or payload_digest.
CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE = f"""
MATCH (ae:AlertEvent {{event_id: $event_id}})
SET ae._corr_tx_lock = true
WITH ae
REMOVE ae._corr_tx_lock
{_ALERT_EVENT_RETURN_COLUMNS}
"""

_FLOW_PROJECTION = """
OPTIONAL MATCH (fo)-[:HAS_ORIGINATOR]->(orig:IPAddress)
OPTIONAL MATCH (fo)-[:HAS_RESPONDER]->(resp:IPAddress)
RETURN fo.observation_id AS observation_id,
       fo.zeek_uid AS zeek_uid,
       fo.routing_domain_id AS routing_domain_id,
       coalesce(orig.scoped_id, fo.src_scoped_id) AS src_scoped_id,
       coalesce(resp.scoped_id, fo.dst_scoped_id) AS dst_scoped_id,
       coalesce(orig.address, fo.src_ip) AS src_ip,
       coalesce(resp.address, fo.dst_ip) AS dst_ip,
       fo.protocol AS protocol,
       fo.src_port AS src_port,
       fo.dst_port AS dst_port,
       fo.community_id AS community_id,
       fo.start_ts AS start_ts,
       fo.start_epoch_decimal AS start_epoch_decimal,
       fo.end_epoch_decimal AS end_epoch_decimal,
       fo.duration_decimal AS duration_decimal,
       fo.start_epoch_ns AS start_epoch_ns,
       fo.end_epoch_ns AS end_epoch_ns,
       fo.sensor_id AS sensor_id,
       fo.source_type AS source_type,
       fo.source_provenance AS source_provenance
"""

# PATH A: Indexed Community ID retrieval scoped to RoutingDomain + source_type='zeek'.
_PATH_A_MATCH = """
MATCH (fo:FlowObservation {community_id: $community_id})
WHERE fo.routing_domain_id = $routing_domain_id
  AND fo.source_type = 'zeek'
  AND ($allowed_sensors IS NULL OR toLower(trim(fo.sensor_id)) IN $allowed_sensors)
WITH fo
ORDER BY fo.observation_id ASC
"""

CYPHER_RETRIEVE_CANDIDATES_BY_CID = f"""
{_PATH_A_MATCH}
LIMIT $fetch_limit
{_FLOW_PROJECTION}
"""

CYPHER_RETRIEVE_CANDIDATES_BY_CID_UNBOUNDED = f"""
{_PATH_A_MATCH}
{_FLOW_PROJECTION}
"""

# PATH B: Scoped bidirectional endpoint retrieval (forward + reverse).
# Always executed even when AlertEvent.community_id is non-null so competing
# FlowObservations with community_id IS NULL can NEVER be hidden.
# Omits narrow database temporal prefilters so long-lived flows, NULL ns fields,
# sub-nanosecond epochs, missing end epochs, and clock offsets remain intact.
_PATH_B_MATCH = """
CALL {
    MATCH (a:IPAddress {scoped_id: $src_scoped_id})<-[:HAS_ORIGINATOR]-(fo:FlowObservation)-[:HAS_RESPONDER]->(b:IPAddress {scoped_id: $dst_scoped_id})
    WHERE fo.routing_domain_id = $routing_domain_id
      AND fo.source_type = 'zeek'
      AND ($allowed_sensors IS NULL OR toLower(trim(fo.sensor_id)) IN $allowed_sensors)
    RETURN fo
    UNION
    MATCH (b:IPAddress {scoped_id: $dst_scoped_id})<-[:HAS_ORIGINATOR]-(fo:FlowObservation)-[:HAS_RESPONDER]->(a:IPAddress {scoped_id: $src_scoped_id})
    WHERE fo.routing_domain_id = $routing_domain_id
      AND fo.source_type = 'zeek'
      AND ($allowed_sensors IS NULL OR toLower(trim(fo.sensor_id)) IN $allowed_sensors)
    RETURN fo
}
WITH fo
ORDER BY fo.observation_id ASC
"""

CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS = f"""
{_PATH_B_MATCH}
LIMIT $fetch_limit
{_FLOW_PROJECTION}
"""

CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS_UNBOUNDED = f"""
{_PATH_B_MATCH}
{_FLOW_PROJECTION}
"""

CYPHER_LIST_EXISTING_CORRELATIONS = """
MATCH (ae:AlertEvent {event_id: $event_id})-[r:CORRELATED_WITH]->(fo:FlowObservation)
RETURN elementId(r) AS rel_id,
       fo.observation_id AS observation_id,
       r.evidence_digest AS evidence_digest,
       r.policy_fingerprint AS policy_fingerprint
ORDER BY fo.observation_id ASC, elementId(r) ASC
"""

CYPHER_DELETE_CORRELATIONS_BY_ELEMENT_IDS = """
MATCH (ae:AlertEvent {event_id: $event_id})-[r:CORRELATED_WITH]->(:FlowObservation)
WHERE elementId(r) IN $rel_ids
DELETE r
RETURN count(r) AS deleted_count
"""

CYPHER_CREATE_CORRELATION = """
MATCH (ae:AlertEvent {event_id: $event_id})
MATCH (fo:FlowObservation {observation_id: $observation_id})
CREATE (ae)-[r:CORRELATED_WITH]->(fo)
SET r = $props
RETURN elementId(r) AS rel_id
"""

CYPHER_UPDATE_CORRELATION_BY_ELEMENT_ID = """
MATCH (ae:AlertEvent {event_id: $event_id})-[r:CORRELATED_WITH]->(fo:FlowObservation {observation_id: $observation_id})
WHERE elementId(r) = $rel_id
SET r = $props
RETURN elementId(r) AS rel_id
"""

CYPHER_GET_ALERT_CORRELATIONS = """
MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation)
WHERE ($event_id IS NULL OR ae.event_id = $event_id)
  AND ($routing_domain_id IS NULL OR r.routing_domain_id = $routing_domain_id)
RETURN ae.event_id AS event_id,
       fo.observation_id AS observation_id,
       fo.zeek_uid AS zeek_uid,
       r.correlation_method AS correlation_method,
       r.evidence_version AS evidence_version,
       r.policy_fingerprint AS policy_fingerprint,
       r.routing_domain_id AS routing_domain_id,
       r.tuple_orientation AS tuple_orientation,
       r.community_id_agreement AS community_id_agreement,
       r.temporal_relation AS temporal_relation,
       r.temporal_delta_decimal AS temporal_delta_decimal,
       r.used_decimal_fallback AS used_decimal_fallback,
       r.sensor_context AS sensor_context,
       r.evidence_digest AS evidence_digest,
       r.decided_at_utc AS decided_at_utc
ORDER BY ae.event_id ASC, fo.observation_id ASC
LIMIT $limit
"""


@dataclass(frozen=True)
class CandidateRetrievalResult:
    """Bounded neo4j candidate retrieval output and explicit completeness signal."""

    candidates: Tuple[FlowSnapshot, ...]
    completeness: CandidateCompleteness
    path_a_count: int
    path_b_count: int
    path_a_overflow: bool
    path_b_overflow: bool
    error_message: Optional[str] = None


@dataclass(frozen=True)
class AlertCorrelationOutcome:
    """Per-alert correlation evaluation and Neo4j reconciliation outcome."""

    event_id: str
    decision: CorrelationDecision
    action: str
    stale_removed: int
    incomplete_evaluation: bool
    existing_correlation_unverified: bool
    evidence_digest: Optional[str] = None
    retrieval_error: Optional[str] = None


@dataclass(frozen=True)
class CorrelationBatchResult:
    """Atomic batch evaluation and reconciliation result with exact batch counters."""

    outcomes: Tuple[AlertCorrelationOutcome, ...]
    alerts_evaluated: int
    strong: int
    ambiguous: int
    insufficient: int
    rejected: int
    correlations_created: int
    correlations_unchanged: int
    correlations_updated: int
    stale_correlations_removed: int
    candidate_cap_exceeded: int
    retrieval_errors: int
    incomplete_evaluations: int


def resolve_allowed_zeek_sensors(
    alert_sensor_id: str,
    policy: CorrelationPolicy,
) -> Optional[List[str]]:
    """Resolve allowed Zeek sensor IDs for database candidate narrowing, or None if unrestricted.

    Only excludes sensors that Phase 4A gate G2 would unconditionally hard-reject
    (`SensorPolicyStatus.DISALLOWED`).
    """
    norm_alert_sensor = alert_sensor_id.strip().lower()
    mode = policy.sensor_policy.mode
    if mode == SensorPolicyMode.ANY_IN_DOMAIN:
        return None
    if mode == SensorPolicyMode.SAME_SENSOR_ID:
        return [norm_alert_sensor]
    for s_id, z_tuple in policy.sensor_policy.explicit_pairs:
        if s_id == norm_alert_sensor:
            return list(z_tuple)
    return []


def merge_and_classify_candidates(
    path_a_rows: Iterable[Any],
    path_b_rows: Iterable[Any],
    candidate_cap: Optional[int],
) -> CandidateRetrievalResult:
    """Deduplicate Path A (CID) and Path B (endpoint) candidate rows and classify completeness.

    Never claims COMPLETE when either path hits `candidate_cap + 1` OR when the
    deduplicated union exceeds `candidate_cap`. Raises ValueError if two rows claim
    the same `observation_id` with conflicting properties or fail snapshot validation.
    """
    if candidate_cap is not None and (
        isinstance(candidate_cap, bool) or not isinstance(candidate_cap, int) or candidate_cap < 1
    ):
        raise ValueError(f"candidate_cap must be a positive integer or None, got {candidate_cap!r}")

    path_a_list = list(path_a_rows)
    path_b_list = list(path_b_rows)
    path_a_overflow = candidate_cap is not None and len(path_a_list) > candidate_cap
    path_b_overflow = candidate_cap is not None and len(path_b_list) > candidate_cap

    merged: Dict[str, FlowSnapshot] = {}
    for raw_row in path_a_list + path_b_list:
        row_data = dict(raw_row) if not isinstance(raw_row, (FlowSnapshot, dict)) and hasattr(raw_row, "keys") else raw_row
        snap = flow_to_snapshot(row_data)
        existing = merged.get(snap.observation_id)
        if existing is not None:
            if existing != snap:
                raise ValueError(
                    f"Conflicting duplicate candidate FlowObservation retrieved for "
                    f"observation_id={snap.observation_id!r}"
                )
            continue
        merged[snap.observation_id] = snap

    union_overflow = candidate_cap is not None and len(merged) > candidate_cap
    truncated = path_a_overflow or path_b_overflow or union_overflow
    completeness = CandidateCompleteness.TRUNCATED if truncated else CandidateCompleteness.COMPLETE

    ordered = tuple(merged[obs_id] for obs_id in sorted(merged.keys()))
    return CandidateRetrievalResult(
        candidates=ordered,
        completeness=completeness,
        path_a_count=len(path_a_list),
        path_b_count=len(path_b_list),
        path_a_overflow=path_a_overflow,
        path_b_overflow=path_b_overflow,
    )


def derive_correlation_method(evidence: CorrelationCandidateEvidence) -> str:
    """Map verified Phase 4A STRONG evidence classifications to a factual method label."""
    cid = evidence.community_id_status
    tpl = evidence.tuple_completeness

    if cid == CommunityIdStatus.MATCH and tpl == TupleCompleteness.COMPLETE_5TUPLE:
        return "cid_verified_5tuple_temporal"
    if cid == CommunityIdStatus.VERIFIED_SEED_OFFSET and tpl == TupleCompleteness.COMPLETE_5TUPLE:
        return "cid_seed_verified_5tuple_temporal"
    if cid == CommunityIdStatus.MATCH and tpl == TupleCompleteness.ICMP_VIA_CID:
        return "cid_verified_icmp_temporal"
    if cid == CommunityIdStatus.VERIFIED_SEED_OFFSET and tpl == TupleCompleteness.ICMP_VIA_CID:
        return "cid_seed_verified_icmp_temporal"
    if cid in {
        CommunityIdStatus.MISSING_ALERT,
        CommunityIdStatus.MISSING_FLOW,
        CommunityIdStatus.MISSING_BOTH,
    } and tpl == TupleCompleteness.COMPLETE_5TUPLE:
        return "tuple_temporal_no_cid"

    raise ValueError(
        f"Cannot derive correlation_method for incompatible evidence state: "
        f"cid={cid.value}, tuple={tpl.value}"
    )


def build_sensor_context(
    alert: AlertSnapshot,
    evidence: CorrelationCandidateEvidence,
) -> str:
    """Build concise, factual sensor pairing provenance string."""
    return f"{evidence.sensor_policy_status.value}:{alert.sensor_id}->{evidence.zeek_sensor_id}"


def compute_correlation_evidence_digest(
    decision: CorrelationDecision,
    alert: AlertSnapshot,
    evidence: CorrelationCandidateEvidence,
) -> str:
    """Compute deterministic SHA-256 digest over factual evidence and active policy identity.

    Excludes processing timestamps so repeated identical runs produce identical digests
    and do not rewrite unchanged relationship metadata.
    """
    payload = {
        "event_id": alert.event_id,
        "observation_id": evidence.observation_id,
        "correlation_method": derive_correlation_method(evidence),
        "evidence_version": decision.evidence_version,
        "policy_fingerprint": decision.policy_fingerprint,
        "routing_domain_id": evidence.routing_domain_id,
        "tuple_orientation": evidence.tuple_orientation.value,
        "tuple_completeness": evidence.tuple_completeness.value,
        "protocol_status": evidence.protocol_status.value,
        "community_id_agreement": evidence.community_id_status.value,
        "temporal_relation": evidence.temporal_relation.value,
        "temporal_delta_decimal": evidence.temporal_delta_decimal,
        "used_decimal_fallback": evidence.used_decimal_fallback,
        "sensor_context": build_sensor_context(alert, evidence),
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_correlation_edge_properties(
    decision: CorrelationDecision,
    alert: AlertSnapshot,
    *,
    decided_at_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct validated :CORRELATED_WITH relationship properties from a STRONG decision."""
    if (
        decision.status != CorrelationStatus.STRONG
        or not decision.auto_correlate_allowed
        or decision.selected_evidence is None
    ):
        raise ValueError(
            f"Only STRONG decisions with auto_correlate_allowed=True can build correlation edges, "
            f"got status={decision.status.value}, allowed={decision.auto_correlate_allowed}"
        )

    ev = decision.selected_evidence
    method = derive_correlation_method(ev)
    sensor_ctx = build_sensor_context(alert, ev)
    digest = compute_correlation_evidence_digest(decision, alert, ev)
    timestamp_utc = (
        decided_at_utc.strip()
        if isinstance(decided_at_utc, str) and decided_at_utc.strip()
        else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    return {
        "correlation_method": method,
        "evidence_version": decision.evidence_version,
        "policy_fingerprint": decision.policy_fingerprint,
        "routing_domain_id": ev.routing_domain_id,
        "tuple_orientation": ev.tuple_orientation.value,
        "community_id_agreement": ev.community_id_status.value,
        "temporal_relation": ev.temporal_relation.value,
        "temporal_delta_decimal": ev.temporal_delta_decimal,
        "used_decimal_fallback": ev.used_decimal_fallback,
        "sensor_context": sensor_ctx,
        "evidence_digest": digest,
        "decided_at_utc": timestamp_utc,
    }


def _record_to_dict(record: Any) -> Dict[str, Any]:
    if isinstance(record, dict):
        return record
    return {k: record[k] for k in record.keys()}


class Neo4jCorrelationRepository:
    """Neo4j repository for bounded Zeek-Suricata candidate retrieval and edge reconciliation."""

    def __init__(self, driver):
        self.driver = driver

    def list_correlatable_alert_event_ids(
        self,
        *,
        routing_domain_id: Optional[str] = None,
        sensor_id: Optional[str] = None,
        only_uncorrelated: bool = False,
        max_alerts: int = 1000,
    ) -> List[str]:
        """List bounded Suricata AlertEvent IDs eligible for correlation evaluation."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")
        if isinstance(only_uncorrelated, bool) is False or not isinstance(only_uncorrelated, bool):
            raise ValueError(f"only_uncorrelated must be a bool, got {only_uncorrelated!r}")
        if isinstance(max_alerts, bool) or not isinstance(max_alerts, int) or max_alerts < 1:
            raise ValueError(f"max_alerts must be a positive integer, got {max_alerts!r}")

        norm_domain = (
            routing_domain_id.strip().lower()
            if isinstance(routing_domain_id, str) and routing_domain_id.strip()
            else None
        )
        if norm_domain is not None and "#" in norm_domain:
            raise ValueError(f"routing_domain_id cannot contain '#': {norm_domain!r}")
        norm_sensor = (
            sensor_id.strip().lower()
            if isinstance(sensor_id, str) and sensor_id.strip()
            else None
        )

        def _work(tx) -> List[str]:
            res = tx.run(
                CYPHER_LIST_CORRELATABLE_ALERT_IDS,
                routing_domain_id=norm_domain,
                sensor_id=norm_sensor,
                only_uncorrelated=only_uncorrelated,
                max_alerts=max_alerts,
            )
            return [str(rec["event_id"]) for rec in res]

        with self.driver.session() as session:
            return session.execute_read(_work)

    def retrieve_candidates_in_tx(
        self,
        tx,
        alert: AlertSnapshot,
        policy: CorrelationPolicy,
    ) -> CandidateRetrievalResult:
        """Retrieve bounded Path A (CID) + Path B (scoped endpoint union) candidates in one tx."""
        allowed_sensors = resolve_allowed_zeek_sensors(alert.sensor_id, policy)
        fetch_limit = policy.candidate_cap + 1 if policy.candidate_cap is not None else None

        path_a_rows: List[Dict[str, Any]] = []
        if alert.community_id is not None:
            cid_cypher = (
                CYPHER_RETRIEVE_CANDIDATES_BY_CID
                if fetch_limit is not None
                else CYPHER_RETRIEVE_CANDIDATES_BY_CID_UNBOUNDED
            )
            cid_params: Dict[str, Any] = {
                "community_id": alert.community_id,
                "routing_domain_id": alert.routing_domain_id,
                "allowed_sensors": allowed_sensors,
            }
            if fetch_limit is not None:
                cid_params["fetch_limit"] = fetch_limit
            path_a_rows = [_record_to_dict(r) for r in tx.run(cid_cypher, **cid_params)]

        # Always execute Path B even when alert.community_id is non-null so
        # competing FlowObservations lacking community_id are never omitted.
        ep_cypher = (
            CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS
            if fetch_limit is not None
            else CYPHER_RETRIEVE_CANDIDATES_BY_ENDPOINTS_UNBOUNDED
        )
        ep_params: Dict[str, Any] = {
            "src_scoped_id": alert.src_scoped_id,
            "dst_scoped_id": alert.dst_scoped_id,
            "routing_domain_id": alert.routing_domain_id,
            "allowed_sensors": allowed_sensors,
        }
        if fetch_limit is not None:
            ep_params["fetch_limit"] = fetch_limit
        path_b_rows = [_record_to_dict(r) for r in tx.run(ep_cypher, **ep_params)]

        try:
            return merge_and_classify_candidates(path_a_rows, path_b_rows, policy.candidate_cap)
        except ValueError as exc:
            logger.warning(
                "Candidate retrieval data error for AlertEvent %s: %s",
                alert.event_id,
                exc,
            )
            return CandidateRetrievalResult(
                candidates=(),
                completeness=CandidateCompleteness.RETRIEVAL_ERROR,
                path_a_count=len(path_a_rows),
                path_b_count=len(path_b_rows),
                path_a_overflow=fetch_limit is not None and len(path_a_rows) > (policy.candidate_cap or 0),
                path_b_overflow=fetch_limit is not None and len(path_b_rows) > (policy.candidate_cap or 0),
                error_message=str(exc),
            )

    def reconcile_alert_in_tx(
        self,
        tx,
        alert: AlertSnapshot,
        decision: CorrelationDecision,
        *,
        dry_run: bool,
        retrieval_error: Optional[str] = None,
        decided_at_utc: Optional[str] = None,
    ) -> AlertCorrelationOutcome:
        """Reconcile outgoing (:AlertEvent)-[:CORRELATED_WITH]->(:FlowObservation) edges.

        Safety rules:
        - When `dry_run=True`: performs zero graph mutations and leaves stale edges intact.
        - When evaluation is incomplete (`completeness != COMPLETE` or `candidate_cap_exceeded`):
          creates zero new edges and performs zero destructive cleanup of prior edges, while
          explicitly flagging `incomplete_evaluation=True` and
          `existing_correlation_unverified=bool(existing)`.
        - When `COMPLETE` and `STRONG`: idempotently maintains exactly one edge to the selected
          FlowObservation, skipping writes if `evidence_digest` matches, updating properties when
          policy/digest changes, and removing any obsolete edges.
        - When `COMPLETE` and non-`STRONG` (`AMBIGUOUS`, `INSUFFICIENT`, `REJECTED`): removes all
          stale outgoing `:CORRELATED_WITH` edges from `alert.event_id`.
        """
        existing = [
            _record_to_dict(r)
            for r in tx.run(CYPHER_LIST_EXISTING_CORRELATIONS, event_id=alert.event_id)
        ]
        incomplete = (
            decision.candidate_completeness != CandidateCompleteness.COMPLETE
            or decision.candidate_cap_exceeded
            or retrieval_error is not None
        )

        if dry_run:
            return AlertCorrelationOutcome(
                event_id=alert.event_id,
                decision=decision,
                action="dry_run",
                stale_removed=0,
                incomplete_evaluation=incomplete,
                existing_correlation_unverified=(incomplete and bool(existing)),
                evidence_digest=None,
                retrieval_error=retrieval_error,
            )

        if incomplete:
            return AlertCorrelationOutcome(
                event_id=alert.event_id,
                decision=decision,
                action="incomplete_skipped",
                stale_removed=0,
                incomplete_evaluation=True,
                existing_correlation_unverified=bool(existing),
                evidence_digest=None,
                retrieval_error=retrieval_error,
            )

        if decision.status == CorrelationStatus.STRONG and decision.auto_correlate_allowed:
            target_obs_id = decision.selected_observation_id
            assert target_obs_id is not None
            props = build_correlation_edge_properties(
                decision,
                alert,
                decided_at_utc=decided_at_utc,
            )
            digest = props["evidence_digest"]

            if (
                len(existing) == 1
                and existing[0]["observation_id"] == target_obs_id
                and existing[0].get("evidence_digest") == digest
            ):
                return AlertCorrelationOutcome(
                    event_id=alert.event_id,
                    decision=decision,
                    action="unchanged",
                    stale_removed=0,
                    incomplete_evaluation=False,
                    existing_correlation_unverified=False,
                    evidence_digest=digest,
                )

            matching_target = [row for row in existing if row["observation_id"] == target_obs_id]
            keep_rel_id = matching_target[0]["rel_id"] if matching_target else None
            obsolete_rel_ids = [
                row["rel_id"] for row in existing if row["rel_id"] != keep_rel_id
            ]

            stale_removed = 0
            if obsolete_rel_ids:
                del_res = tx.run(
                    CYPHER_DELETE_CORRELATIONS_BY_ELEMENT_IDS,
                    event_id=alert.event_id,
                    rel_ids=obsolete_rel_ids,
                ).single()
                stale_removed = int(del_res["deleted_count"]) if del_res else len(obsolete_rel_ids)

            if keep_rel_id is not None:
                upd_res = tx.run(
                    CYPHER_UPDATE_CORRELATION_BY_ELEMENT_ID,
                    event_id=alert.event_id,
                    observation_id=target_obs_id,
                    rel_id=keep_rel_id,
                    props=props,
                ).single()
                if upd_res is None:
                    raise RuntimeError(
                        f"Failed to update CORRELATED_WITH edge for event_id={alert.event_id!r}"
                    )
                action = "updated"
            else:
                crt_res = tx.run(
                    CYPHER_CREATE_CORRELATION,
                    event_id=alert.event_id,
                    observation_id=target_obs_id,
                    props=props,
                ).single()
                if crt_res is None:
                    raise RuntimeError(
                        f"Failed to create CORRELATED_WITH edge for "
                        f"event_id={alert.event_id!r}, observation_id={target_obs_id!r}"
                    )
                action = "created"

            return AlertCorrelationOutcome(
                event_id=alert.event_id,
                decision=decision,
                action=action,
                stale_removed=stale_removed,
                incomplete_evaluation=False,
                existing_correlation_unverified=False,
                evidence_digest=digest,
            )

        # COMPLETE and non-STRONG (AMBIGUOUS, INSUFFICIENT, or REJECTED): remove stale links.
        stale_removed = 0
        if existing:
            rel_ids = [row["rel_id"] for row in existing]
            del_res = tx.run(
                CYPHER_DELETE_CORRELATIONS_BY_ELEMENT_IDS,
                event_id=alert.event_id,
                rel_ids=rel_ids,
            ).single()
            stale_removed = int(del_res["deleted_count"]) if del_res else len(rel_ids)
            action = "removed_stale"
        else:
            action = "no_change"

        return AlertCorrelationOutcome(
            event_id=alert.event_id,
            decision=decision,
            action=action,
            stale_removed=stale_removed,
            incomplete_evaluation=False,
            existing_correlation_unverified=False,
            evidence_digest=None,
        )

    def correlate_alert_batch(
        self,
        event_ids: Iterable[str],
        *,
        policy: Optional[CorrelationPolicy] = None,
        dry_run: bool = False,
    ) -> CorrelationBatchResult:
        """Evaluate and reconcile a bounded batch of AlertEvents in one managed transaction.

        Uses a deterministic sorted `event_id` order for lock acquisition to prevent
        worker deadlocks. In `dry_run=True` mode, executes inside `session.execute_read`
        and performs zero mutations.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")
        if not isinstance(dry_run, bool):
            raise ValueError(f"dry_run must be a bool, got {dry_run!r}")

        active_policy = policy if policy is not None else CorrelationPolicy()

        cleaned_ids: List[str] = []
        seen_ids = set()
        for raw_id in event_ids:
            if not isinstance(raw_id, str) or not raw_id.strip():
                raise ValueError(f"event_id must be a non-empty string, got {raw_id!r}")
            eid = raw_id.strip()
            if eid not in seen_ids:
                seen_ids.add(eid)
                cleaned_ids.append(eid)
        # Canonical sorted lock ordering eliminates cyclic lock wait deadlocks.
        ordered_ids = sorted(cleaned_ids)

        if not ordered_ids:
            return CorrelationBatchResult(
                outcomes=(),
                alerts_evaluated=0,
                strong=0,
                ambiguous=0,
                insufficient=0,
                rejected=0,
                correlations_created=0,
                correlations_unchanged=0,
                correlations_updated=0,
                stale_correlations_removed=0,
                candidate_cap_exceeded=0,
                retrieval_errors=0,
                incomplete_evaluations=0,
            )

        def _work(tx) -> CorrelationBatchResult:
            load_cypher = (
                CYPHER_LOAD_ALERT_EVENT_READ if dry_run else CYPHER_LOAD_AND_LOCK_ALERT_EVENT_WRITE
            )
            outcomes: List[AlertCorrelationOutcome] = []
            strong_cnt = 0
            ambiguous_cnt = 0
            insufficient_cnt = 0
            rejected_cnt = 0
            created_cnt = 0
            unchanged_cnt = 0
            updated_cnt = 0
            stale_removed_cnt = 0
            cap_exceeded_cnt = 0
            retrieval_err_cnt = 0
            incomplete_cnt = 0

            for event_id in ordered_ids:
                alert_rec = tx.run(load_cypher, event_id=event_id).single()
                if alert_rec is None:
                    raise LookupError(f"AlertEvent not found: {event_id!r}")
                alert_snap = alert_to_snapshot(_record_to_dict(alert_rec))

                retrieval = self.retrieve_candidates_in_tx(tx, alert_snap, active_policy)
                decision = correlate_alert_to_flows(
                    alert_snap,
                    retrieval.candidates,
                    policy=active_policy,
                    candidate_completeness=retrieval.completeness,
                )
                outcome = self.reconcile_alert_in_tx(
                    tx,
                    alert_snap,
                    decision,
                    dry_run=dry_run,
                    retrieval_error=retrieval.error_message,
                )
                outcomes.append(outcome)

                if decision.status == CorrelationStatus.STRONG:
                    strong_cnt += 1
                elif decision.status == CorrelationStatus.AMBIGUOUS:
                    ambiguous_cnt += 1
                elif decision.status == CorrelationStatus.INSUFFICIENT:
                    insufficient_cnt += 1
                else:
                    rejected_cnt += 1

                if outcome.action == "created":
                    created_cnt += 1
                elif outcome.action == "unchanged":
                    unchanged_cnt += 1
                elif outcome.action == "updated":
                    updated_cnt += 1

                stale_removed_cnt += outcome.stale_removed
                if decision.candidate_cap_exceeded or retrieval.completeness == CandidateCompleteness.TRUNCATED:
                    cap_exceeded_cnt += 1
                if retrieval.completeness == CandidateCompleteness.RETRIEVAL_ERROR:
                    retrieval_err_cnt += 1
                if outcome.incomplete_evaluation:
                    incomplete_cnt += 1

            return CorrelationBatchResult(
                outcomes=tuple(outcomes),
                alerts_evaluated=len(outcomes),
                strong=strong_cnt,
                ambiguous=ambiguous_cnt,
                insufficient=insufficient_cnt,
                rejected=rejected_cnt,
                correlations_created=created_cnt,
                correlations_unchanged=unchanged_cnt,
                correlations_updated=updated_cnt,
                stale_correlations_removed=stale_removed_cnt,
                candidate_cap_exceeded=cap_exceeded_cnt,
                retrieval_errors=retrieval_err_cnt,
                incomplete_evaluations=incomplete_cnt,
            )

        with self.driver.session() as session:
            if dry_run:
                return session.execute_read(_work)
            return session.execute_write(_work)

    def correlate_alert_event(
        self,
        event_id: str,
        *,
        policy: Optional[CorrelationPolicy] = None,
        dry_run: bool = False,
    ) -> AlertCorrelationOutcome:
        """Evaluate and reconcile a single AlertEvent in one managed transaction."""
        batch = self.correlate_alert_batch([event_id], policy=policy, dry_run=dry_run)
        return batch.outcomes[0]

    def get_alert_correlations(
        self,
        event_id: Optional[str] = None,
        *,
        routing_domain_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve persisted (:AlertEvent)-[:CORRELATED_WITH]->(:FlowObservation) records."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError(f"limit must be a positive integer, got {limit!r}")

        norm_event = event_id.strip() if isinstance(event_id, str) and event_id.strip() else None
        norm_domain = (
            routing_domain_id.strip().lower()
            if isinstance(routing_domain_id, str) and routing_domain_id.strip()
            else None
        )

        def _work(tx) -> List[Dict[str, Any]]:
            res = tx.run(
                CYPHER_GET_ALERT_CORRELATIONS,
                event_id=norm_event,
                routing_domain_id=norm_domain,
                limit=limit,
            )
            return [_record_to_dict(r) for r in res]

        with self.driver.session() as session:
            return session.execute_read(_work)
