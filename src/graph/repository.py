"""
Neo4j Graph Persistence Repository.

Implements batched UNWIND write operations using managed transactions
(session.execute_write) for normalized TrafficRecord, AlertRecord, and
ZeekConnectionObservation models, supporting V2 scoped IP identities,
RoutingDomain associations, and discrete FlowObservation persistence.
"""

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import ipaddress
from itertools import islice
import json
import logging
from typing import Iterable, List, Dict, Any, Iterator, TypeVar, Optional, Tuple

from src.ingestion.models import TrafficRecord, AlertRecord
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    ZeekConnectionObservation,
    alert_definition_id,
    compute_v2_flow_key,
    format_canonical_decimal,
    scoped_ip_id,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1


class ObservationConflictError(ValueError):
    """Raised when an observation_id already exists with conflicting immutable properties."""

    def __init__(
        self,
        conflicting_observation_ids: Iterable[str],
        message: Optional[str] = None,
        batches_committed: int = 0,
    ):
        self.conflicting_observation_ids = tuple(sorted(set(str(x) for x in conflicting_observation_ids)))
        self.batches_committed = batches_committed
        sample = ", ".join(self.conflicting_observation_ids[:5])
        extra = (
            f" (+{len(self.conflicting_observation_ids) - 5} more)"
            if len(self.conflicting_observation_ids) > 5
            else ""
        )
        super().__init__(
            message
            or f"Conflicting FlowObservation payload for existing observation_id(s): {sample}{extra}. "
            "Existing observations are immutable and were not overwritten."
        )


@dataclass(frozen=True)
class ObservationPersistenceSummary:
    """Summary counters returned after streaming Zeek FlowObservation persistence."""

    total_received: int
    created_count: int
    duplicate_matched_count: int
    batches_committed: int


class AlertEventConflictError(ValueError):
    """Raised when a Suricata event_id already exists with conflicting immutable properties."""

    def __init__(
        self,
        conflicting_event_ids: Iterable[str],
        message: Optional[str] = None,
        batches_committed: int = 0,
    ):
        self.conflicting_event_ids = tuple(sorted(set(str(x) for x in conflicting_event_ids)))
        self.batches_committed = batches_committed
        sample = ", ".join(self.conflicting_event_ids[:5])
        extra = (
            f" (+{len(self.conflicting_event_ids) - 5} more)"
            if len(self.conflicting_event_ids) > 5
            else ""
        )
        super().__init__(
            message
            or f"Conflicting AlertEvent payload for existing event_id(s): {sample}{extra}. "
            "Existing alert events are immutable and were not overwritten."
        )


@dataclass(frozen=True)
class AlertEventPersistenceSummary:
    """Summary counters returned after streaming Suricata AlertEvent persistence."""

    total_received: int
    created_count: int
    duplicate_matched_count: int
    definitions_created_count: int
    definitions_matched_count: int
    batches_committed: int


# Scoped deletion of all application-owned graph entities
CYPHER_SCOPED_CLEANUP = """
MATCH (n)
WHERE n:IPAddress OR n:Layer2Identifier OR n:AlertFact OR n:RoutingDomain OR n:FlowObservation OR n:AlertEvent OR n:AlertDefinition
DETACH DELETE n
"""

# Cypher statements for batched parameter ingestion
CYPHER_WRITE_TRAFFIC_BATCH = """
UNWIND $batch AS row
MERGE (rd:RoutingDomain {domain_id: row.routing_domain_id})
MERGE (src_ip:IPAddress {scoped_id: row.src_scoped_id})
ON CREATE SET
    src_ip.address = row.ip_src,
    src_ip.routing_domain_id = row.routing_domain_id
ON MATCH SET
    src_ip.address = coalesce(src_ip.address, row.ip_src),
    src_ip.routing_domain_id = coalesce(src_ip.routing_domain_id, row.routing_domain_id)
MERGE (src_ip)-[:IN_DOMAIN]->(rd)

MERGE (dst_ip:IPAddress {scoped_id: row.dst_scoped_id})
ON CREATE SET
    dst_ip.address = row.ip_dst,
    dst_ip.routing_domain_id = row.routing_domain_id
ON MATCH SET
    dst_ip.address = coalesce(dst_ip.address, row.ip_dst),
    dst_ip.routing_domain_id = coalesce(dst_ip.routing_domain_id, row.routing_domain_id)
MERGE (dst_ip)-[:IN_DOMAIN]->(rd)

MERGE (src_ip)-[c:COMMUNICATED_TO {flow_key: row.flow_key}]->(dst_ip)
SET
    c.protocol = row.protocol,
    c.src_port = row.src_port,
    c.dst_port = row.dst_port,
    c.observed_packet_count = row.observed_packet_count,
    c.observed_bytes = row.observed_bytes,
    c.first_seen = row.first_seen,
    c.last_seen = row.last_seen,
    c.observed_window_seconds = row.observed_window_seconds

FOREACH (pair IN row.l2_pairs |
    MERGE (src_l2:Layer2Identifier {identifier: pair.src})
    MERGE (dst_l2:Layer2Identifier {identifier: pair.dst})
    MERGE (src_ip)-[:OBSERVED_WITH]->(src_l2)
    MERGE (dst_ip)-[:OBSERVED_WITH]->(dst_l2)
    MERGE (src_l2)-[:L2_COMMUNICATED_TO {protocol: row.protocol}]->(dst_l2)
)
"""

CYPHER_WRITE_ALERT_BATCH = """
UNWIND $batch AS row
MERGE (rd:RoutingDomain {domain_id: row.routing_domain_id})
MERGE (src:IPAddress {scoped_id: row.src_scoped_id})
ON CREATE SET
    src.address = row.src_ip,
    src.routing_domain_id = row.routing_domain_id
ON MATCH SET
    src.address = coalesce(src.address, row.src_ip),
    src.routing_domain_id = coalesce(src.routing_domain_id, row.routing_domain_id)
MERGE (src)-[:IN_DOMAIN]->(rd)

MERGE (dst:IPAddress {scoped_id: row.dst_scoped_id})
ON CREATE SET
    dst.address = row.dst_ip,
    dst.routing_domain_id = row.routing_domain_id
ON MATCH SET
    dst.address = coalesce(dst.address, row.dst_ip),
    dst.routing_domain_id = coalesce(dst.routing_domain_id, row.routing_domain_id)
MERGE (dst)-[:IN_DOMAIN]->(rd)

MERGE (fact:AlertFact {fact_key: row.fact_key})
ON CREATE SET
    fact.routing_domain_id = row.routing_domain_id,
    fact.sid = row.sid,
    fact.gid = row.gid,
    fact.rev = row.rev,
    fact.message = row.message,
    fact.priority = row.priority,
    fact.protocol = row.protocol,
    fact.src_port = row.src_port,
    fact.dst_port = row.dst_port
ON MATCH SET
    fact.routing_domain_id = coalesce(fact.routing_domain_id, row.routing_domain_id)
MERGE (src)-[:SOURCE_OF]->(fact)
MERGE (fact)-[:TARGETS]->(dst)
"""

CYPHER_WRITE_ZEEK_OBSERVATION_BATCH = """
UNWIND $batch AS row
OPTIONAL MATCH (pre:FlowObservation {observation_id: row.observation_id})
WITH row, (pre IS NOT NULL) AS existed_before
MERGE (fo:FlowObservation {observation_id: row.observation_id})
ON CREATE SET
    fo.payload_digest = row.payload_digest,
    fo.flow_key = row.flow_key,
    fo.zeek_uid = row.zeek_uid,
    fo.routing_domain_id = row.routing_domain_id,
    fo.src_scoped_id = row.src_scoped_id,
    fo.dst_scoped_id = row.dst_scoped_id,
    fo.src_ip = row.src_ip,
    fo.dst_ip = row.dst_ip,
    fo.protocol = row.protocol,
    fo.src_port = row.src_port,
    fo.dst_port = row.dst_port,
    fo.community_id = row.community_id,
    fo.start_ts = row.start_ts,
    fo.end_ts = row.end_ts,
    fo.start_epoch_decimal = row.start_epoch_decimal,
    fo.end_epoch_decimal = row.end_epoch_decimal,
    fo.duration_decimal = row.duration_decimal,
    fo.start_epoch_ns = row.start_epoch_ns,
    fo.end_epoch_ns = row.end_epoch_ns,
    fo.orig_bytes = row.orig_bytes,
    fo.resp_bytes = row.resp_bytes,
    fo.orig_pkts = row.orig_pkts,
    fo.resp_pkts = row.resp_pkts,
    fo.orig_ip_bytes = row.orig_ip_bytes,
    fo.resp_ip_bytes = row.resp_ip_bytes,
    fo.missed_bytes = row.missed_bytes,
    fo.service = row.service,
    fo.conn_state = row.conn_state,
    fo.history = row.history,
    fo.local_orig = row.local_orig,
    fo.local_resp = row.local_resp,
    fo.sensor_id = row.sensor_id,
    fo.source_type = row.source_type,
    fo.source_provenance = row.source_provenance
WITH fo, row, existed_before,
     (fo.payload_digest IS NULL OR fo.payload_digest <> row.payload_digest) AS is_conflict
FOREACH (_ IN CASE WHEN NOT is_conflict THEN [1] ELSE [] END |
    MERGE (rd:RoutingDomain {domain_id: row.routing_domain_id})
    ON CREATE SET rd.name = CASE
        WHEN row.routing_domain_id = 'default' THEN 'Default Routing Domain'
        ELSE row.routing_domain_id
    END
    MERGE (src_ip:IPAddress {scoped_id: row.src_scoped_id})
    ON CREATE SET
        src_ip.address = row.src_ip,
        src_ip.routing_domain_id = row.routing_domain_id
    ON MATCH SET
        src_ip.address = coalesce(src_ip.address, row.src_ip),
        src_ip.routing_domain_id = coalesce(src_ip.routing_domain_id, row.routing_domain_id)
    MERGE (src_ip)-[:IN_DOMAIN]->(rd)
    MERGE (dst_ip:IPAddress {scoped_id: row.dst_scoped_id})
    ON CREATE SET
        dst_ip.address = row.dst_ip,
        dst_ip.routing_domain_id = row.routing_domain_id
    ON MATCH SET
        dst_ip.address = coalesce(dst_ip.address, row.dst_ip),
        dst_ip.routing_domain_id = coalesce(dst_ip.routing_domain_id, row.routing_domain_id)
    MERGE (dst_ip)-[:IN_DOMAIN]->(rd)
    MERGE (fo)-[:HAS_ORIGINATOR]->(src_ip)
    MERGE (fo)-[:HAS_RESPONDER]->(dst_ip)
)
RETURN count(CASE WHEN NOT existed_before AND NOT is_conflict THEN 1 END) AS created_count,
       count(CASE WHEN existed_before AND NOT is_conflict THEN 1 END) AS matched_count,
       collect(CASE WHEN is_conflict THEN row.observation_id ELSE null END) AS conflicting_ids
"""

CYPHER_WRITE_SURICATA_ALERT_BATCH = """
UNWIND $batch AS row
OPTIONAL MATCH (pre_ev:AlertEvent {event_id: row.event_id})
OPTIONAL MATCH (pre_def:AlertDefinition {definition_id: row.alert_definition_id})
WITH collect({
    row: row,
    existed_ev_before: (pre_ev IS NOT NULL),
    existed_def_before: (pre_def IS NOT NULL)
}) AS items
UNWIND items AS item
WITH item.row AS row,
     item.existed_ev_before AS existed_ev_before,
     item.existed_def_before AS existed_def_before
MERGE (ae:AlertEvent {event_id: row.event_id})
ON CREATE SET
    ae.payload_digest = row.payload_digest,
    ae.alert_definition_id = row.alert_definition_id,
    ae.source_record_id = row.source_record_id,
    ae.log_source_id = row.log_source_id,
    ae.sensor_id = row.sensor_id,
    ae.ruleset_namespace = row.ruleset_namespace,
    ae.routing_domain_id = row.routing_domain_id,
    ae.flow_key = row.flow_key,
    ae.src_scoped_id = row.src_scoped_id,
    ae.dst_scoped_id = row.dst_scoped_id,
    ae.src_ip = row.src_ip,
    ae.dst_ip = row.dst_ip,
    ae.timestamp_source = row.timestamp_source,
    ae.timestamp_epoch_decimal = row.timestamp_epoch_decimal,
    ae.timestamp_epoch_ns = row.timestamp_epoch_ns,
    ae.protocol = row.protocol,
    ae.src_port = row.src_port,
    ae.dst_port = row.dst_port,
    ae.flow_id = row.flow_id,
    ae.community_id = row.community_id,
    ae.gid = row.gid,
    ae.sid = row.sid,
    ae.rev = row.rev,
    ae.signature = row.signature,
    ae.category = row.category,
    ae.severity = row.severity,
    ae.action = row.action,
    ae.app_proto = row.app_proto,
    ae.direction = row.direction,
    ae.tx_id = row.tx_id,
    ae.pcap_cnt = row.pcap_cnt,
    ae.source_type = row.source_type,
    ae.source_provenance = row.source_provenance
WITH ae, row, existed_ev_before, existed_def_before,
     (ae.payload_digest IS NULL OR ae.payload_digest <> row.payload_digest) AS is_conflict
FOREACH (_ IN CASE WHEN NOT is_conflict THEN [1] ELSE [] END |
    MERGE (ad:AlertDefinition {definition_id: row.alert_definition_id})
    ON CREATE SET
        ad.engine = row.source_type,
        ad.ruleset_namespace = row.ruleset_namespace,
        ad.gid = row.gid,
        ad.sid = row.sid
    MERGE (rd:RoutingDomain {domain_id: row.routing_domain_id})
    ON CREATE SET rd.name = CASE
        WHEN row.routing_domain_id = 'default' THEN 'Default Routing Domain'
        ELSE row.routing_domain_id
    END
    MERGE (src_ip:IPAddress {scoped_id: row.src_scoped_id})
    ON CREATE SET
        src_ip.address = row.src_ip,
        src_ip.routing_domain_id = row.routing_domain_id
    ON MATCH SET
        src_ip.address = coalesce(src_ip.address, row.src_ip),
        src_ip.routing_domain_id = coalesce(src_ip.routing_domain_id, row.routing_domain_id)
    MERGE (src_ip)-[:IN_DOMAIN]->(rd)
    MERGE (dst_ip:IPAddress {scoped_id: row.dst_scoped_id})
    ON CREATE SET
        dst_ip.address = row.dst_ip,
        dst_ip.routing_domain_id = row.routing_domain_id
    ON MATCH SET
        dst_ip.address = coalesce(dst_ip.address, row.dst_ip),
        dst_ip.routing_domain_id = coalesce(dst_ip.routing_domain_id, row.routing_domain_id)
    MERGE (dst_ip)-[:IN_DOMAIN]->(rd)
    MERGE (ae)-[:TRIGGERED_RULE]->(ad)
    MERGE (ae)-[:HAS_SOURCE]->(src_ip)
    MERGE (ae)-[:HAS_DESTINATION]->(dst_ip)
)
RETURN count(CASE WHEN NOT existed_ev_before AND NOT is_conflict THEN 1 END) AS created_count,
       count(CASE WHEN existed_ev_before AND NOT is_conflict THEN 1 END) AS matched_count,
       count(DISTINCT CASE WHEN NOT existed_def_before AND NOT is_conflict THEN row.alert_definition_id END) AS definitions_created_count,
       count(DISTINCT CASE WHEN existed_def_before AND NOT is_conflict THEN row.alert_definition_id END) AS definitions_matched_count,
       collect(CASE WHEN is_conflict THEN row.event_id ELSE null END) AS conflicting_ids
"""


def canonicalize_ip(ip_str: str) -> str:
    """Return the canonical string representation of an IPv4 or IPv6 address.

    Guarantees equivalent representations (such as expanded vs compressed IPv6)
    map to the exact same string key for graph identity.
    """
    cleaned = ip_str.strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned


def _traffic_record_to_payload(record: TrafficRecord, domain_id: str = "default") -> Dict[str, Any]:
    """Transform a TrafficRecord domain model into a Cypher parameter dictionary.

    Supports both enriched aggregates (with observed_l2_pairs) and legacy records
    (falling back to scalar eth_src_resolved / eth_dst_resolved).
    Generates deterministic scoped IP identifiers based on domain_id (default 'default').
    """
    if record.observed_l2_pairs:
        l2_pairs = [{"src": p[0], "dst": p[1]} for p in record.observed_l2_pairs]
    else:
        l2_pairs = [{"src": record.eth_src_resolved, "dst": record.eth_dst_resolved}]

    ip_src_canon = canonicalize_ip(record.ip_src)
    ip_dst_canon = canonicalize_ip(record.ip_dst)
    norm_domain = domain_id.strip().lower() if domain_id and domain_id.strip() else "default"

    return {
        "ip_src": ip_src_canon,
        "ip_dst": ip_dst_canon,
        "src_scoped_id": scoped_ip_id(norm_domain, ip_src_canon),
        "dst_scoped_id": scoped_ip_id(norm_domain, ip_dst_canon),
        "routing_domain_id": norm_domain,
        "flow_key": record.flow_key,
        "protocol": record.protocol,
        "src_port": record.src_port,
        "dst_port": record.dst_port,
        "observed_packet_count": record.observed_packet_count,
        "observed_bytes": record.observed_bytes,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "observed_window_seconds": record.observed_window_seconds,
        "l2_pairs": l2_pairs,
    }


def compute_alert_fact_key(alert: AlertRecord, domain_id: Optional[str] = None) -> str:
    """Generate a deterministic SHA-256 fact_key for a normalized AlertRecord.

    NOTE: fact_key represents a deterministic identity for a unique normalized
    alert fact, NOT an IDS event ID or timestamped instance.
    When domain_id is specified and non-default, it isolates the fact_key to that
    specific routing domain to avoid cross-domain alert collisions.
    For 'default' domain or None, the key matches V1 calculation for backwards compatibility.
    """
    norm_domain = domain_id.strip().lower() if domain_id and domain_id.strip() else "default"
    canonical_payload = {
        "src_ip": canonicalize_ip(alert.src_ip),
        "dst_ip": canonicalize_ip(alert.dst_ip),
        "sid": alert.sid,
        "gid": alert.gid,
        "rev": alert.rev,
        "message": alert.message,
        "priority": alert.priority,
        "protocol": alert.protocol,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
    }
    if norm_domain != "default":
        canonical_payload["routing_domain_id"] = norm_domain
    # Deterministic canonical serialization: sort keys, stable delimiters, UTF-8
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def chunk_list(items: List[T], size: int) -> Iterator[List[T]]:
    """Yield successive chunks of list up to the specified size."""
    if size < 1:
        raise ValueError(f"Batch size must be at least 1, got {size}")
    for i in range(0, len(items), size):
        yield items[i : i + size]


def iter_batches(items: Iterable[T], size: int) -> Iterator[List[T]]:
    """Yield bounded batches from an arbitrary iterable without materializing the full input."""
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise ValueError(f"Batch size must be an integer >= 1, got {size!r}")
    iterator = iter(items)
    while True:
        batch = list(islice(iterator, size))
        if not batch:
            break
        yield batch


def format_exact_decimal(value: Optional[Decimal], field_name: str = "value") -> Optional[str]:
    """Serialize a non-negative finite Decimal to a lossless canonical decimal string.

    Independent of active decimal.getcontext().prec (never invokes Decimal.normalize()).
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, Decimal):
        raise ValueError(f"Expected Decimal or None for '{field_name}', got {type(value).__name__}")
    if value.is_nan() or value.is_infinite():
        raise ValueError(f"'{field_name}' cannot be NaN or Infinite: {value}")
    if value < 0:
        raise ValueError(f"'{field_name}' must be non-negative, got {value}")
    return format_canonical_decimal(value)


def decimal_epoch_to_ns(epoch: Optional[Decimal], field_name: str = "epoch") -> Optional[int]:
    """Convert a non-negative Decimal Unix epoch (seconds) to exact signed 64-bit integer nanoseconds.

    Lossless, context-independent policy:
    - Inspects Decimal.as_tuple() and uses exact Python integer arithmetic (never float, never
      context-sensitive Decimal multiplication or rounding).
    - Returns None if ANY nonzero fractional digit exists beyond the 9th decimal place
      (sub-nanosecond precision), ensuring higher precision is NEVER silently truncated.
    - Returns None if the integer nanosecond value falls outside signed 64-bit integer bounds
      [-(2**63), 2**63 - 1].
    Exact original timestamps always remain stored in start_ts / start_epoch_decimal / end_epoch_decimal.
    """
    if epoch is None:
        return None
    if isinstance(epoch, bool) or not isinstance(epoch, Decimal):
        raise ValueError(f"Expected Decimal or None for '{field_name}', got {type(epoch).__name__}")
    if epoch.is_nan() or epoch.is_infinite():
        raise ValueError(f"'{field_name}' cannot be NaN or Infinite: {epoch}")
    if epoch < 0:
        raise ValueError(f"'{field_name}' must be non-negative, got {epoch}")

    _, digits, exp = epoch.as_tuple()
    if not isinstance(exp, int):
        raise ValueError(f"'{field_name}' cannot be NaN or Infinite: {epoch}")

    if not digits or all(d == 0 for d in digits):
        return 0

    digit_str = "".join(str(d) for d in digits).lstrip("0")
    stripped = digit_str.rstrip("0")
    trailing_zeros = len(digit_str) - len(stripped)

    # Exact value is int(stripped) * 10**(exp + trailing_zeros + 9) nanoseconds
    eff_ns_exp = exp + trailing_zeros + 9
    if eff_ns_exp < 0:
        # At least one nonzero digit exists beyond the 9th fractional decimal place
        return None

    # Since int(stripped) >= 1, any eff_ns_exp >= 19 yields >= 10**19 > INT64_MAX (9.22e18)
    if eff_ns_exp >= 19:
        return None

    ns_int = int(stripped) * (10 ** eff_ns_exp)
    if ns_int < INT64_MIN or ns_int > INT64_MAX:
        return None
    return ns_int


def _validate_required_str(
    value: Any,
    field_name: str,
    model_name: str = "ZeekConnectionObservation",
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{model_name}.{field_name} must be a non-empty string")
    return value.strip()


def _validate_optional_str(
    value: Any,
    field_name: str,
    model_name: str = "ZeekConnectionObservation",
) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    raise ValueError(f"{model_name}.{field_name} must be a string or None")


def _validate_optional_port(
    value: Any,
    field_name: str,
    model_name: str = "ZeekConnectionObservation",
) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 65535):
        raise ValueError(f"{model_name}.{field_name} must be an integer in 0..65535 or None, got {value!r}")
    return value


def _validate_optional_metric_int(
    value: Any,
    field_name: str,
    model_name: str = "ZeekConnectionObservation",
) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > INT64_MAX:
        raise ValueError(
            f"{model_name}.{field_name} must be an integer in 0..{INT64_MAX} or None, got {value!r}"
        )
    return value


def _validate_required_metric_int(
    value: Any,
    field_name: str,
    model_name: str = "SuricataAlertObservation",
) -> int:
    if value is None or isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > INT64_MAX:
        raise ValueError(
            f"{model_name}.{field_name} must be an integer in 0..{INT64_MAX}, got {value!r}"
        )
    return value


def _validate_optional_uint_str(
    value: Any,
    field_name: str,
    model_name: str = "SuricataAlertObservation",
) -> Optional[str]:
    """Validate an optional unsigned integer (e.g. uint64 flow_id) and serialize losslessly."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"{model_name}.{field_name} must be a non-negative integer or None, got {value!r}"
        )
    return str(value)


def _validate_optional_bool(value: Any, field_name: str) -> Optional[bool]:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"ZeekConnectionObservation.{field_name} must be a bool or None, got {value!r}")
    return value


def compute_observation_payload_digest(payload: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest of all immutable persisted FlowObservation properties."""
    canonical = {k: v for k, v in payload.items() if k != "payload_digest"}
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def zeek_observation_to_payload(obs: ZeekConnectionObservation) -> Dict[str, Any]:
    """Validate and convert a ZeekConnectionObservation into a Neo4j-native parameter dictionary.

    Enforces:
    - Mutual consistency between routing_domain_id, src_ip, dst_ip, src_scoped_id, and dst_scoped_id
    - Lossless string serialization of Decimal timestamps/durations (no float conversion)
    - Lossless optional 64-bit integer nanosecond index fields (None if sub-ns or out-of-range)
    - Separation of directional payload vs IP-level byte and packet metrics (None never replaced by 0)
    - Deterministic payload_digest for immutable observation conflict detection
    """
    if not isinstance(obs, ZeekConnectionObservation):
        raise TypeError(f"Expected ZeekConnectionObservation, got {type(obs).__name__}")

    observation_id = _validate_required_str(obs.observation_id, "observation_id")
    flow_key = _validate_required_str(obs.flow_key, "flow_key")
    zeek_uid = _validate_required_str(obs.zeek_uid, "zeek_uid")
    routing_domain_id = _validate_required_str(obs.routing_domain_id, "routing_domain_id").lower()
    if "#" in routing_domain_id:
        raise ValueError(f"routing_domain_id cannot contain delimiter '#': '{routing_domain_id}'")

    raw_src_ip = _validate_required_str(obs.src_ip, "src_ip")
    raw_dst_ip = _validate_required_str(obs.dst_ip, "dst_ip")
    try:
        src_ip_obj = ipaddress.ip_address(raw_src_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid src_ip '{raw_src_ip}': {exc}") from exc
    try:
        dst_ip_obj = ipaddress.ip_address(raw_dst_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid dst_ip '{raw_dst_ip}': {exc}") from exc

    if src_ip_obj.version != dst_ip_obj.version:
        raise ValueError(
            f"Mismatched IP versions for observation '{observation_id}': "
            f"IPv{src_ip_obj.version} -> IPv{dst_ip_obj.version}"
        )

    canon_src_ip = str(src_ip_obj)
    canon_dst_ip = str(dst_ip_obj)

    src_scoped_id = _validate_required_str(obs.src_scoped_id, "src_scoped_id")
    dst_scoped_id = _validate_required_str(obs.dst_scoped_id, "dst_scoped_id")
    expected_src_scoped = scoped_ip_id(routing_domain_id, canon_src_ip)
    expected_dst_scoped = scoped_ip_id(routing_domain_id, canon_dst_ip)

    if src_scoped_id != expected_src_scoped:
        raise ValueError(
            f"Inconsistent src_scoped_id '{src_scoped_id}' for routing_domain_id='{routing_domain_id}' "
            f"and src_ip='{canon_src_ip}' (expected '{expected_src_scoped}')"
        )
    if dst_scoped_id != expected_dst_scoped:
        raise ValueError(
            f"Inconsistent dst_scoped_id '{dst_scoped_id}' for routing_domain_id='{routing_domain_id}' "
            f"and dst_ip='{canon_dst_ip}' (expected '{expected_dst_scoped}')"
        )

    protocol = _validate_required_str(obs.protocol, "protocol").upper()
    start_ts = _validate_required_str(obs.start_ts, "start_ts")
    end_ts = _validate_optional_str(obs.end_ts, "end_ts")
    sensor_id = _validate_required_str(obs.sensor_id, "sensor_id").lower()
    source_type = _validate_required_str(obs.source_type, "source_type").lower()

    payload: Dict[str, Any] = {
        "observation_id": observation_id,
        "flow_key": flow_key,
        "zeek_uid": zeek_uid,
        "routing_domain_id": routing_domain_id,
        "src_scoped_id": src_scoped_id,
        "dst_scoped_id": dst_scoped_id,
        "src_ip": canon_src_ip,
        "dst_ip": canon_dst_ip,
        "protocol": protocol,
        "src_port": _validate_optional_port(obs.src_port, "src_port"),
        "dst_port": _validate_optional_port(obs.dst_port, "dst_port"),
        "community_id": _validate_optional_str(obs.community_id, "community_id"),
        "start_ts": start_ts,
        "end_ts": end_ts,
        "start_epoch_decimal": format_exact_decimal(obs.start_epoch, "start_epoch"),
        "end_epoch_decimal": format_exact_decimal(obs.end_epoch, "end_epoch"),
        "duration_decimal": format_exact_decimal(obs.duration, "duration"),
        "start_epoch_ns": decimal_epoch_to_ns(obs.start_epoch, "start_epoch"),
        "end_epoch_ns": decimal_epoch_to_ns(obs.end_epoch, "end_epoch"),
        "orig_bytes": _validate_optional_metric_int(obs.orig_bytes, "orig_bytes"),
        "resp_bytes": _validate_optional_metric_int(obs.resp_bytes, "resp_bytes"),
        "orig_pkts": _validate_optional_metric_int(obs.orig_pkts, "orig_pkts"),
        "resp_pkts": _validate_optional_metric_int(obs.resp_pkts, "resp_pkts"),
        "orig_ip_bytes": _validate_optional_metric_int(obs.orig_ip_bytes, "orig_ip_bytes"),
        "resp_ip_bytes": _validate_optional_metric_int(obs.resp_ip_bytes, "resp_ip_bytes"),
        "missed_bytes": _validate_optional_metric_int(obs.missed_bytes, "missed_bytes"),
        "service": _validate_optional_str(obs.service, "service"),
        "conn_state": _validate_optional_str(obs.conn_state, "conn_state"),
        "history": _validate_optional_str(obs.history, "history"),
        "local_orig": _validate_optional_bool(obs.local_orig, "local_orig"),
        "local_resp": _validate_optional_bool(obs.local_resp, "local_resp"),
        "sensor_id": sensor_id,
        "source_type": source_type,
        "source_provenance": _validate_optional_str(obs.source_provenance, "source_provenance"),
    }
    payload["payload_digest"] = compute_observation_payload_digest(payload)
    return payload


def compute_alert_event_payload_digest(payload: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest over immutable Suricata AlertEvent properties."""
    canonical_fields = {k: v for k, v in payload.items() if k != "payload_digest"}
    serialized = json.dumps(
        canonical_fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def suricata_alert_to_payload(obs: SuricataAlertObservation) -> Dict[str, Any]:
    """Validate and convert a SuricataAlertObservation into a Neo4j Cypher parameter dictionary."""
    if not isinstance(obs, SuricataAlertObservation):
        raise TypeError(f"Expected SuricataAlertObservation, got {type(obs).__name__}")

    event_id = _validate_required_str(obs.event_id, "event_id", model_name="SuricataAlertObservation")
    alert_def_id = _validate_required_str(
        obs.alert_definition_id, "alert_definition_id", model_name="SuricataAlertObservation"
    )
    source_record_id = _validate_required_str(
        obs.source_record_id, "source_record_id", model_name="SuricataAlertObservation"
    )
    log_source_id = _validate_required_str(
        obs.log_source_id, "log_source_id", model_name="SuricataAlertObservation"
    )
    sensor_id = _validate_required_str(obs.sensor_id, "sensor_id", model_name="SuricataAlertObservation").lower()
    ruleset_namespace = _validate_required_str(
        obs.ruleset_namespace, "ruleset_namespace", model_name="SuricataAlertObservation"
    ).lower()
    routing_domain_id = _validate_required_str(
        obs.routing_domain_id, "routing_domain_id", model_name="SuricataAlertObservation"
    ).lower()
    if "#" in routing_domain_id:
        raise ValueError(f"routing_domain_id cannot contain delimiter '#': '{routing_domain_id}'")

    source_type = _validate_required_str(
        obs.source_type, "source_type", model_name="SuricataAlertObservation"
    ).lower()
    flow_key = _validate_required_str(obs.flow_key, "flow_key", model_name="SuricataAlertObservation")
    timestamp_source = _validate_required_str(
        obs.timestamp_source, "timestamp_source", model_name="SuricataAlertObservation"
    )

    raw_src_ip = _validate_required_str(obs.src_ip, "src_ip", model_name="SuricataAlertObservation")
    raw_dst_ip = _validate_required_str(obs.dst_ip, "dst_ip", model_name="SuricataAlertObservation")

    try:
        src_ip_obj = ipaddress.ip_address(raw_src_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid src_ip '{raw_src_ip}': {exc}") from exc

    try:
        dst_ip_obj = ipaddress.ip_address(raw_dst_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid dst_ip '{raw_dst_ip}': {exc}") from exc

    if src_ip_obj.version != dst_ip_obj.version:
        raise ValueError(
            f"SuricataAlertObservation address family mismatch: "
            f"IPv{src_ip_obj.version} -> IPv{dst_ip_obj.version}"
        )

    canon_src_ip = str(src_ip_obj)
    canon_dst_ip = str(dst_ip_obj)

    src_scoped_id = _validate_required_str(
        obs.src_scoped_id, "src_scoped_id", model_name="SuricataAlertObservation"
    )
    dst_scoped_id = _validate_required_str(
        obs.dst_scoped_id, "dst_scoped_id", model_name="SuricataAlertObservation"
    )
    expected_src_scoped = scoped_ip_id(routing_domain_id, canon_src_ip)
    expected_dst_scoped = scoped_ip_id(routing_domain_id, canon_dst_ip)

    if src_scoped_id != expected_src_scoped:
        raise ValueError(
            f"Inconsistent src_scoped_id '{src_scoped_id}' for routing_domain_id='{routing_domain_id}' "
            f"and src_ip='{canon_src_ip}' (expected '{expected_src_scoped}')"
        )
    if dst_scoped_id != expected_dst_scoped:
        raise ValueError(
            f"Inconsistent dst_scoped_id '{dst_scoped_id}' for routing_domain_id='{routing_domain_id}' "
            f"and dst_ip='{canon_dst_ip}' (expected '{expected_dst_scoped}')"
        )

    protocol_opt = _validate_optional_str(obs.protocol, "protocol", model_name="SuricataAlertObservation")
    protocol = protocol_opt.upper() if protocol_opt is not None else None
    src_port = _validate_optional_port(obs.src_port, "src_port", model_name="SuricataAlertObservation")
    dst_port = _validate_optional_port(obs.dst_port, "dst_port", model_name="SuricataAlertObservation")

    expected_flow_key = compute_v2_flow_key(
        src_scoped_id=src_scoped_id,
        dst_scoped_id=dst_scoped_id,
        protocol=protocol or "UNKNOWN",
        src_port=src_port,
        dst_port=dst_port,
    )
    if flow_key != expected_flow_key:
        raise ValueError(
            f"Inconsistent flow_key '{flow_key}' for normalized tuple "
            f"({src_scoped_id}, {dst_scoped_id}, {protocol or 'UNKNOWN'}, {src_port}, {dst_port})"
        )

    sid = _validate_required_metric_int(obs.sid, "sid", model_name="SuricataAlertObservation")
    gid = _validate_optional_metric_int(obs.gid, "gid", model_name="SuricataAlertObservation")
    rev = _validate_optional_metric_int(obs.rev, "rev", model_name="SuricataAlertObservation")
    severity = _validate_optional_metric_int(obs.severity, "severity", model_name="SuricataAlertObservation")
    tx_id = _validate_optional_metric_int(obs.tx_id, "tx_id", model_name="SuricataAlertObservation")
    pcap_cnt = _validate_optional_metric_int(obs.pcap_cnt, "pcap_cnt", model_name="SuricataAlertObservation")

    expected_def_id = alert_definition_id(
        engine=source_type,
        ruleset_namespace=ruleset_namespace,
        gid=gid,
        sid=sid,
    )
    if alert_def_id != expected_def_id:
        raise ValueError(
            f"Inconsistent alert_definition_id '{alert_def_id}' for engine='{source_type}', "
            f"ruleset_namespace='{ruleset_namespace}', gid={gid}, sid={sid} "
            f"(expected '{expected_def_id}')"
        )

    flow_id_str = _validate_optional_uint_str(obs.flow_id, "flow_id", model_name="SuricataAlertObservation")

    payload: Dict[str, Any] = {
        "event_id": event_id,
        "alert_definition_id": alert_def_id,
        "source_record_id": source_record_id,
        "log_source_id": log_source_id,
        "sensor_id": sensor_id,
        "ruleset_namespace": ruleset_namespace,
        "routing_domain_id": routing_domain_id,
        "flow_key": flow_key,
        "src_scoped_id": src_scoped_id,
        "dst_scoped_id": dst_scoped_id,
        "src_ip": canon_src_ip,
        "dst_ip": canon_dst_ip,
        "timestamp_source": timestamp_source,
        "timestamp_epoch_decimal": format_exact_decimal(
            obs.timestamp_epoch_decimal, "timestamp_epoch_decimal"
        ),
        "timestamp_epoch_ns": decimal_epoch_to_ns(
            obs.timestamp_epoch_decimal, "timestamp_epoch_decimal"
        ),
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "flow_id": flow_id_str,
        "community_id": _validate_optional_str(
            obs.community_id, "community_id", model_name="SuricataAlertObservation"
        ),
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "signature": _validate_optional_str(obs.signature, "signature", model_name="SuricataAlertObservation"),
        "category": _validate_optional_str(obs.category, "category", model_name="SuricataAlertObservation"),
        "severity": severity,
        "action": _validate_optional_str(obs.action, "action", model_name="SuricataAlertObservation"),
        "app_proto": _validate_optional_str(obs.app_proto, "app_proto", model_name="SuricataAlertObservation"),
        "direction": _validate_optional_str(obs.direction, "direction", model_name="SuricataAlertObservation"),
        "tx_id": tx_id,
        "pcap_cnt": pcap_cnt,
        "source_type": source_type,
        "source_provenance": _validate_optional_str(
            obs.source_provenance, "source_provenance", model_name="SuricataAlertObservation"
        ),
    }
    payload["payload_digest"] = compute_alert_event_payload_digest(payload)
    return payload


class Neo4jRepository:
    """Repository handling batched graph persistence for traffic and alert data.

    Receives an existing Neo4j driver (managed externally by main.py) and executes
    retry-safe managed transactions (session.execute_write).
    """

    def __init__(self, driver, batch_size: int = 500):
        self.driver = driver
        self.batch_size = max(1, batch_size)

    def write_traffic_records(self, records: List[TrafficRecord], domain_id: str = "default") -> int:
        """Persist a list of TrafficRecord instances in batched UNWIND transactions.

        Returns the count of records processed.
        """
        if not records:
            logger.info("No traffic records to persist.")
            return 0

        # Transform to parameter dictionaries using centralized payload builder
        payload = [_traffic_record_to_payload(r, domain_id=domain_id) for r in records]

        total_batches = (len(payload) + self.batch_size - 1) // self.batch_size
        logger.info(
            "Persisting %d traffic records in %d batch(es) (batch_size=%d)...",
            len(payload),
            total_batches,
            self.batch_size,
        )

        with self.driver.session() as session:
            for batch_num, batch in enumerate(chunk_list(payload, self.batch_size), start=1):
                session.execute_write(self._execute_traffic_batch, batch)
                logger.debug("Persisted traffic batch %d/%d (%d records)", batch_num, total_batches, len(batch))

        logger.info("Traffic persistence complete: %d records processed.", len(payload))
        return len(payload)

    def write_alert_records(self, records: List[AlertRecord], domain_id: str = "default") -> int:
        """Persist a list of AlertRecord instances as :AlertFact nodes in batched UNWIND transactions.

        Returns the count of records processed.
        """
        if not records:
            logger.info("No alert records to persist.")
            return 0

        norm_domain = domain_id.strip().lower() if domain_id and domain_id.strip() else "default"
        if "#" in norm_domain:
            raise ValueError(f"domain_id cannot contain delimiter '#': '{norm_domain}'")

        # Transform to parameter dictionaries with fact_key, canonicalized IPs, and scoped IDs
        payload = [
            {
                "src_ip": canonicalize_ip(a.src_ip),
                "dst_ip": canonicalize_ip(a.dst_ip),
                "src_scoped_id": scoped_ip_id(norm_domain, a.src_ip),
                "dst_scoped_id": scoped_ip_id(norm_domain, a.dst_ip),
                "routing_domain_id": norm_domain,
                "fact_key": compute_alert_fact_key(a, domain_id=norm_domain),
                "sid": a.sid,
                "gid": a.gid,
                "rev": a.rev,
                "message": a.message,
                "priority": a.priority,
                "protocol": a.protocol,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
            }
            for a in records
        ]

        total_batches = (len(payload) + self.batch_size - 1) // self.batch_size
        logger.info(
            "Persisting %d alert records in %d batch(es) (batch_size=%d)...",
            len(payload),
            total_batches,
            self.batch_size,
        )

        with self.driver.session() as session:
            for batch_num, batch in enumerate(chunk_list(payload, self.batch_size), start=1):
                session.execute_write(self._execute_alert_batch, batch)
                logger.debug("Persisted alert batch %d/%d (%d records)", batch_num, total_batches, len(batch))

        logger.info("Alert persistence complete: %d records processed.", len(payload))
        return len(payload)

    @staticmethod
    def _execute_traffic_batch(tx, batch: List[Dict[str, Any]]) -> None:
        """Managed transaction work function for traffic batch."""
        result = tx.run(CYPHER_WRITE_TRAFFIC_BATCH, batch=batch)
        result.consume()

    @staticmethod
    def _execute_alert_batch(tx, batch: List[Dict[str, Any]]) -> None:
        """Managed transaction work function for alert batch."""
        result = tx.run(CYPHER_WRITE_ALERT_BATCH, batch=batch)
        result.consume()

    def write_zeek_observations(
        self,
        observations: Iterable[ZeekConnectionObservation],
        batch_size: Optional[int] = None,
    ) -> ObservationPersistenceSummary:
        """Stream and persist ZeekConnectionObservation records as :FlowObservation nodes in bounded batches.

        Memory and transaction semantics:
        - Consumes `observations` lazily in bounded batches of `batch_size` (O(batch_size) memory;
          never calls `list(observations)`).
        - Each batch executes inside its own retry-safe managed write transaction (`session.execute_write`).
        - Transaction boundaries are per-batch: if a later batch fails, earlier committed batches remain
          persisted and retrying the stream is idempotent for already-committed observations.
        - Existing `FlowObservation` nodes are immutable: identical re-imports are idempotent no-ops,
          while conflicting properties for an existing `observation_id` raise `ObservationConflictError`
          and roll back the offending batch without overwriting existing data.
        """
        effective_batch_size = self.batch_size if batch_size is None else batch_size
        if isinstance(effective_batch_size, bool) or not isinstance(effective_batch_size, int) or effective_batch_size < 1:
            raise ValueError(f"Batch size must be an integer >= 1, got {effective_batch_size!r}")

        total_received = 0
        created_count = 0
        duplicate_matched_count = 0
        batches_committed = 0

        batch_iter = iter_batches(observations, effective_batch_size)
        first_batch = next(batch_iter, None)
        if first_batch is None:
            logger.info("No Zeek flow observations to persist.")
            return ObservationPersistenceSummary(
                total_received=0,
                created_count=0,
                duplicate_matched_count=0,
                batches_committed=0,
            )

        def _prepare_batch(raw_batch: List[ZeekConnectionObservation]) -> Tuple[List[Dict[str, Any]], int]:
            deduped: List[Dict[str, Any]] = []
            seen_digests: Dict[str, str] = {}
            in_batch_dupes = 0
            for obs in raw_batch:
                payload = zeek_observation_to_payload(obs)
                obs_id = payload["observation_id"]
                digest = payload["payload_digest"]
                prev_digest = seen_digests.get(obs_id)
                if prev_digest is None:
                    seen_digests[obs_id] = digest
                    deduped.append(payload)
                elif prev_digest == digest:
                    in_batch_dupes += 1
                else:
                    raise ObservationConflictError(
                        [obs_id],
                        batches_committed=batches_committed,
                    )
            return deduped, in_batch_dupes

        with self.driver.session() as session:
            current_batch: Optional[List[ZeekConnectionObservation]] = first_batch
            while current_batch is not None:
                deduped_payload, in_batch_dupes = _prepare_batch(current_batch)
                try:
                    batch_created, batch_matched = session.execute_write(
                        self._execute_zeek_observation_batch,
                        deduped_payload,
                    )
                except ObservationConflictError as exc:
                    raise ObservationConflictError(
                        exc.conflicting_observation_ids,
                        batches_committed=batches_committed,
                    ) from exc

                total_received += len(current_batch)
                created_count += batch_created
                duplicate_matched_count += in_batch_dupes + batch_matched
                batches_committed += 1
                logger.debug(
                    "Persisted Zeek observation batch %d (%d received, %d created, %d matched/duplicate)",
                    batches_committed,
                    len(current_batch),
                    batch_created,
                    in_batch_dupes + batch_matched,
                )
                current_batch = next(batch_iter, None)

        logger.info(
            "Zeek FlowObservation persistence complete: %d received, %d created, %d duplicate/matched in %d batch(es).",
            total_received,
            created_count,
            duplicate_matched_count,
            batches_committed,
        )
        return ObservationPersistenceSummary(
            total_received=total_received,
            created_count=created_count,
            duplicate_matched_count=duplicate_matched_count,
            batches_committed=batches_committed,
        )

    @staticmethod
    def _execute_zeek_observation_batch(tx, batch: List[Dict[str, Any]]) -> Tuple[int, int]:
        """Managed transaction work function for a Zeek FlowObservation batch."""
        result = tx.run(CYPHER_WRITE_ZEEK_OBSERVATION_BATCH, batch=batch)
        rec = result.single() if hasattr(result, "single") else None
        if rec is None:
            return len(batch), 0

        if isinstance(rec, dict):
            raw_conflicts = rec.get("conflicting_ids") or []
            raw_created = rec.get("created_count", len(batch))
            raw_matched = rec.get("matched_count", 0)
        elif hasattr(rec, "get"):
            raw_conflicts = rec.get("conflicting_ids") or []
            raw_created = rec.get("created_count", len(batch))
            raw_matched = rec.get("matched_count", 0)
        else:
            raw_conflicts = []
            raw_created = len(batch)
            raw_matched = 0

        conflicting_ids = [str(cid) for cid in raw_conflicts if cid is not None]
        if conflicting_ids:
            raise ObservationConflictError(conflicting_ids)

        created_int = int(raw_created) if isinstance(raw_created, (int, float)) and not isinstance(raw_created, bool) else len(batch)
        matched_int = int(raw_matched) if isinstance(raw_matched, (int, float)) and not isinstance(raw_matched, bool) else 0
        return created_int, matched_int

    def write_suricata_alert_events(
        self,
        alerts: Iterable[SuricataAlertObservation],
        batch_size: Optional[int] = None,
    ) -> AlertEventPersistenceSummary:
        """Persist a bounded-memory stream of SuricataAlertObservation records in Neo4j.

        Persists each distinct firing as an immutable :AlertEvent node linked via:
        - (:AlertEvent)-[:TRIGGERED_RULE]->(:AlertDefinition)
        - (:AlertEvent)-[:HAS_SOURCE]->(:IPAddress)
        - (:AlertEvent)-[:HAS_DESTINATION]->(:IPAddress)

        Atomicity semantics:
        - Each batch executes inside a single Neo4j managed write transaction.
        - Conflicting writes on an existing event_id raise AlertEventConflictError and
          roll back the entire failing batch while preserving previously committed batches.
        """
        if batch_size is not None:
            if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
                raise ValueError(f"batch_size must be a positive integer, got {batch_size!r}")
            effective_batch_size = batch_size
        else:
            effective_batch_size = self.batch_size

        total_received = 0
        created_count = 0
        duplicate_matched_count = 0
        definitions_created_count = 0
        definitions_matched_count = 0
        batches_committed = 0

        payload_stream = (suricata_alert_to_payload(alert) for alert in alerts)
        batch_iter = iter_batches(payload_stream, effective_batch_size)

        try:
            first_batch = next(batch_iter)
        except StopIteration:
            logger.info("No Suricata alert events to persist.")
            return AlertEventPersistenceSummary(
                total_received=0,
                created_count=0,
                duplicate_matched_count=0,
                definitions_created_count=0,
                definitions_matched_count=0,
                batches_committed=0,
            )

        def _process_batch(session, batch: List[Dict[str, Any]]) -> None:
            nonlocal total_received, created_count, duplicate_matched_count
            nonlocal definitions_created_count, definitions_matched_count, batches_committed

            total_received += len(batch)

            deduped_by_id: Dict[str, Dict[str, Any]] = {}
            intra_batch_duplicates = 0
            for row in batch:
                ev_id = row["event_id"]
                existing_row = deduped_by_id.get(ev_id)
                if existing_row is None:
                    deduped_by_id[ev_id] = row
                elif existing_row["payload_digest"] != row["payload_digest"]:
                    raise AlertEventConflictError(
                        [ev_id],
                        batches_committed=batches_committed,
                    )
                else:
                    intra_batch_duplicates += 1

            unique_batch = list(deduped_by_id.values())
            try:
                created, matched, defs_created, defs_matched = session.execute_write(
                    self._execute_suricata_alert_batch,
                    unique_batch,
                )
            except AlertEventConflictError as exc:
                raise AlertEventConflictError(
                    exc.conflicting_event_ids,
                    batches_committed=batches_committed,
                ) from exc

            created_count += created
            duplicate_matched_count += matched + intra_batch_duplicates
            definitions_created_count += defs_created
            definitions_matched_count += defs_matched
            batches_committed += 1

        with self.driver.session() as session:
            _process_batch(session, first_batch)
            for batch in batch_iter:
                _process_batch(session, batch)

        summary = AlertEventPersistenceSummary(
            total_received=total_received,
            created_count=created_count,
            duplicate_matched_count=duplicate_matched_count,
            definitions_created_count=definitions_created_count,
            definitions_matched_count=definitions_matched_count,
            batches_committed=batches_committed,
        )
        logger.info(
            "Suricata alert event persistence complete: received=%d, created=%d, matched=%d, "
            "defs_created=%d, defs_matched=%d, batches=%d.",
            summary.total_received,
            summary.created_count,
            summary.duplicate_matched_count,
            summary.definitions_created_count,
            summary.definitions_matched_count,
            summary.batches_committed,
        )
        return summary

    @staticmethod
    def _execute_suricata_alert_batch(tx, batch: List[Dict[str, Any]]) -> Tuple[int, int, int, int]:
        result = tx.run(CYPHER_WRITE_SURICATA_ALERT_BATCH, batch=batch)
        summary_row = result.single()
        if summary_row is None:
            return len(batch), 0, 0, 0

        raw_created = summary_row["created_count"]
        raw_matched = summary_row["matched_count"]
        raw_defs_created = summary_row["definitions_created_count"]
        raw_defs_matched = summary_row["definitions_matched_count"]
        raw_conflicts = summary_row["conflicting_ids"] or []

        conflicting_ids = [str(cid) for cid in raw_conflicts if cid is not None]
        if conflicting_ids:
            raise AlertEventConflictError(conflicting_ids)

        created_int = (
            int(raw_created)
            if isinstance(raw_created, (int, float)) and not isinstance(raw_created, bool)
            else len(batch)
        )
        matched_int = (
            int(raw_matched)
            if isinstance(raw_matched, (int, float)) and not isinstance(raw_matched, bool)
            else 0
        )
        defs_created_int = (
            int(raw_defs_created)
            if isinstance(raw_defs_created, (int, float)) and not isinstance(raw_defs_created, bool)
            else 0
        )
        defs_matched_int = (
            int(raw_defs_matched)
            if isinstance(raw_defs_matched, (int, float)) and not isinstance(raw_defs_matched, bool)
            else 0
        )
        return created_int, matched_int, defs_created_int, defs_matched_int

    def replace_workspace_data(
        self,
        traffic_records: Optional[List[TrafficRecord]] = None,
        alert_records: Optional[List[AlertRecord]] = None,
        domain_id: str = "default",
    ) -> Tuple[int, int]:
        """Atomically replace the current analysis workspace in a single managed write transaction.

        1. Executes scoped deletion of all application-owned graph entities
           (:IPAddress, :Layer2Identifier, :AlertFact, :RoutingDomain, :FlowObservation,
            :AlertEvent, :AlertDefinition).
        2. Recreates the target :RoutingDomain (default 'default').
        3. Writes all provided traffic records in batched UNWIND calls within the transaction.
        4. Writes all provided alert records in batched UNWIND calls within the transaction.

        If any error occurs during cleanup or write execution, the transaction is automatically
        rolled back by the driver, leaving the previous analysis workspace completely intact.

        Returns:
            Tuple of (traffic_records_persisted_count, alert_facts_persisted_count)
        """
        norm_domain = domain_id.strip().lower() if domain_id and domain_id.strip() else "default"
        if "#" in norm_domain:
            raise ValueError(f"domain_id cannot contain delimiter '#': '{norm_domain}'")
        domain_name = "Default Routing Domain" if norm_domain == "default" else norm_domain

        traffic_payload: List[Dict[str, Any]] = []
        if traffic_records:
            traffic_payload = [_traffic_record_to_payload(r, domain_id=norm_domain) for r in traffic_records]

        alert_payload: List[Dict[str, Any]] = []
        if alert_records:
            alert_payload = [
                {
                    "src_ip": canonicalize_ip(a.src_ip),
                    "dst_ip": canonicalize_ip(a.dst_ip),
                    "src_scoped_id": scoped_ip_id(norm_domain, a.src_ip),
                    "dst_scoped_id": scoped_ip_id(norm_domain, a.dst_ip),
                    "routing_domain_id": norm_domain,
                    "fact_key": compute_alert_fact_key(a, domain_id=norm_domain),
                    "sid": a.sid,
                    "gid": a.gid,
                    "rev": a.rev,
                    "message": a.message,
                    "priority": a.priority,
                    "protocol": a.protocol,
                    "src_port": a.src_port,
                    "dst_port": a.dst_port,
                }
                for a in alert_records
            ]

        logger.info(
            "Executing atomic workspace replacement (%d traffic records, %d alert records, domain=%s)...",
            len(traffic_payload),
            len(alert_payload),
            norm_domain,
        )

        def _work(tx) -> Tuple[int, int]:
            # Step 1: Scoped graph cleanup (application-owned entities)
            logger.debug("Executing scoped graph cleanup Cypher...")
            del_result = tx.run(CYPHER_SCOPED_CLEANUP)
            del_result.consume()

            # Step 1b: Recreate target RoutingDomain
            tx.run(
                "MERGE (rd:RoutingDomain {domain_id: $domain_id}) "
                "ON CREATE SET rd.name = $domain_name",
                domain_id=norm_domain,
                domain_name=domain_name,
            ).consume()

            # Step 2: Ingest traffic batches if provided
            if traffic_payload:
                for batch in chunk_list(traffic_payload, self.batch_size):
                    res = tx.run(CYPHER_WRITE_TRAFFIC_BATCH, batch=batch)
                    res.consume()

            # Step 3: Ingest alert batches if provided
            if alert_payload:
                for batch in chunk_list(alert_payload, self.batch_size):
                    res = tx.run(CYPHER_WRITE_ALERT_BATCH, batch=batch)
                    res.consume()

            return len(traffic_payload), len(alert_payload)

        with self.driver.session() as session:
            persisted_traffic, persisted_alerts = session.execute_write(_work)

        logger.info(
            "Atomic workspace replacement completed successfully: %d traffic records, %d alert facts.",
            persisted_traffic,
            persisted_alerts,
        )
        return persisted_traffic, persisted_alerts
