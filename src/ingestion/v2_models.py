"""
V2 identity primitives, canonical fingerprint utilities, and minimal domain models.

Provides deterministic, source-aware identity helpers for:
- RoutingDomain-scoped IP addresses (scoped_ip_id)
- V2 directional communication keys (compute_v2_flow_key)
- Discrete telemetry session observations (compute_observation_id)
- Security alert definitions (alert_definition_id)
- Discrete alert event occurrences (compute_alert_event_id)
- Precise timestamp identity canonicalization (canonicalize_event_timestamp)

SEMANTIC IDENTIFIER BOUNDARIES:
- `scoped_ip_id`: Identifies an IP within a Layer 3 RoutingDomain namespace (e.g. 'corp#10.1.1.5').
  SecurityZone, Sensor, and VLAN do NOT participate in scoped IP identity.
- `flow_key`: Represents the directional communication profile/relationship between two scoped endpoints.
  It is strictly directional (A -> B != B -> A). Timestamps and Community IDs do NOT participate in flow_key.
- `community_id`: An interoperability correlation key defined by open standard. It is bidirectional
  and does NOT incorporate RoutingDomain, Sensor, or VLAN context.
- `observation_id`: Represents one discrete telemetry observation/session in time reported by a sensor.
  Independent sessions that share the same Community ID or flow_key produce distinct observation IDs.
  Requires a non-empty native source_record_id.
- `alert_definition_id`: Identifies the static security signature/rule ({engine}:{namespace}:{gid}:{sid}).
  An absent GID is canonically represented by the explicit sentinel 'none'.
- `alert_event_id`: Identifies a single, timestamped execution/firing of an alert rule.
  Requires a non-empty native source_record_id.
"""

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Optional, Union

from src.ingestion.models import canonicalize_ip


def canonicalize_event_timestamp(timestamp: Union[float, int, str, Decimal]) -> str:
    """Canonicalize a telemetry event timestamp without loss of precision.

    Accepts:
        - Floating-point or integer epoch timestamps (e.g. 1725148800, 1725148800.123456)
        - Numeric decimal epoch strings (e.g. '1725148800.123456789' from Zeek)
        - Standard ISO 8601 timestamp strings (e.g. '2024-09-01T12:00:00.123456+00:00' from Suricata)

    Contract:
        - Preserves exact source precision (does not truncate or round nanoseconds to microseconds).
        - Equates equivalent numeric representations (e.g. 1725148800.1 and 1725148800.100 produce '1725148800.1').
        - Distinct timestamps at any decimal precision remain distinct (preventing event collision).
        - Preserves ISO 8601 strings trimmed as-is without date manipulation.

    Raises:
        ValueError: If timestamp is empty, None, NaN, or infinite.
    """
    if timestamp is None:
        raise ValueError("timestamp cannot be None")

    raw = str(timestamp).strip()
    if not raw:
        raise ValueError("timestamp cannot be empty")

    try:
        d = Decimal(raw)
        if d.is_nan() or d.is_infinite():
            raise ValueError(f"timestamp cannot be NaN or Infinite: {raw}")
        return format(d.normalize(), "f")
    except InvalidOperation:
        # Not a decimal number; treat as ISO 8601 or text timestamp string
        return raw


def scoped_ip_id(domain_id: Optional[str], ip_address: str) -> str:
    """Generate a deterministic scoped IP identity string: '{normalized_domain}#{canonical_ip}'.

    RoutingDomain acts as the address namespace to disambiguate overlapping RFC 1918
    address spaces across disconnected networks, VPCs, and VRFs.
    SecurityZone, Sensor ID, and VLAN tags do NOT participate in scoped IP identity.

    Args:
        domain_id: RoutingDomain identifier (e.g. 'corp-main', 'branch-a'). Defaults to 'default'.
        ip_address: IPv4 or IPv6 address string.

    Returns:
        Canonical scoped string: '{normalized_domain}#{canonical_ip}'.

    Raises:
        ValueError: If ip_address is empty/invalid, or if domain_id contains the delimiter '#'.
    """
    if not ip_address or not str(ip_address).strip():
        raise ValueError("ip_address cannot be empty")

    cleaned_ip = str(ip_address).strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned_ip)
        canonical_ip = str(ip_obj)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address for scoped identity: '{cleaned_ip}'") from exc

    norm_domain = domain_id.strip().lower() if domain_id and domain_id.strip() else "default"
    if "#" in norm_domain:
        raise ValueError(f"domain_id cannot contain delimiter '#': '{norm_domain}'")

    return f"{norm_domain}#{canonical_ip}"


def compute_v2_flow_key(
    src_scoped_id: str,
    dst_scoped_id: str,
    protocol: str,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
) -> str:
    """Generate a deterministic SHA-256 identity key for a V2 directional communication aggregate.

    Unlike Community ID (which is bidirectional), the internal flow_key is strictly DIRECTIONAL:
    A -> B produces a different flow_key than B -> A.
    Because `src_scoped_id` and `dst_scoped_id` encapsulate the RoutingDomain, the flow_key
    naturally inherits network context without requiring a separate global domain parameter.

    Args:
        src_scoped_id: Canonical scoped identifier of source IP (e.g. 'corp#10.1.1.5').
        dst_scoped_id: Canonical scoped identifier of destination IP.
        protocol: Transport protocol string (e.g. 'TCP', 'UDP').
        src_port: Source transport port (0..65535 or None).
        dst_port: Destination transport port (0..65535 or None).

    Returns:
        64-character lowercase hex SHA-256 digest.

    Raises:
        ValueError: If src_scoped_id or dst_scoped_id is empty, or port numbers are out of range.
    """
    if not src_scoped_id or not str(src_scoped_id).strip():
        raise ValueError("src_scoped_id cannot be empty")
    if not dst_scoped_id or not str(dst_scoped_id).strip():
        raise ValueError("dst_scoped_id cannot be empty")

    if src_port is not None:
        if isinstance(src_port, bool) or not isinstance(src_port, int) or not (0 <= src_port <= 65535):
            raise ValueError(f"Invalid src_port: {src_port}. Must be an integer in 0..65535 or None.")

    if dst_port is not None:
        if isinstance(dst_port, bool) or not isinstance(dst_port, int) or not (0 <= dst_port <= 65535):
            raise ValueError(f"Invalid dst_port: {dst_port}. Must be an integer in 0..65535 or None.")

    clean_src = str(src_scoped_id).strip()
    clean_dst = str(dst_scoped_id).strip()
    clean_proto = protocol.strip().upper() if protocol and str(protocol).strip() else "UNKNOWN"

    canonical_payload = {
        "src_scoped_id": clean_src,
        "dst_scoped_id": clean_dst,
        "protocol": clean_proto,
        "src_port": src_port if src_port is not None else "null",
        "dst_port": dst_port if dst_port is not None else "null",
    }
    serialized = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_observation_id(
    source_type: str,
    sensor_id: str,
    source_record_id: str,
    timestamp: Union[float, int, str, Decimal],
    flow_key: str,
    source_provenance: Optional[str] = None,
) -> str:
    """Generate a deterministic SHA-256 observation identifier for a discrete flow session.

    SEMANTIC DISTINCTION:
    `observation_id` represents one discrete telemetry session/observation in time.
    It must NOT be confused with:
    - `community_id`: which is an open interoperability key that multiple independent sessions
      over time legitimately share.
    - `flow_key`: which represents the directional communication profile between two scoped endpoints.

    Requires a non-empty native `source_record_id` (e.g. Zeek uid, Suricata flow_id, packet index)
    to guarantee sufficient source discrimination. Idempotent across re-ingestion runs.

    Args:
        source_type: Telemetry format/source (e.g. 'zeek', 'suricata', 'tshark').
        sensor_id: Observation sensor/vantage identifier (e.g. 'sensor-01', 'core-tap').
        source_record_id: Non-empty native record/connection ID.
        timestamp: Observation start timestamp (float epoch, Decimal, or ISO string).
        flow_key: V2 directional flow key binding this observation to the communication profile.
        source_provenance: Optional source dataset or file identifier.

    Returns:
        64-character lowercase hex SHA-256 digest.

    Raises:
        ValueError: If source_record_id, source_type, or flow_key is empty.
    """
    if not source_record_id or not str(source_record_id).strip():
        raise ValueError("source_record_id cannot be empty for observation identity")
    if not source_type or not str(source_type).strip():
        raise ValueError("source_type cannot be empty")
    if not flow_key or not str(flow_key).strip():
        raise ValueError("flow_key cannot be empty")

    canonical_ts = canonicalize_event_timestamp(timestamp)

    payload = {
        "source_type": source_type.strip().lower(),
        "sensor_id": sensor_id.strip().lower() if sensor_id and sensor_id.strip() else "default",
        "source_record_id": str(source_record_id).strip(),
        "timestamp": canonical_ts,
        "flow_key": flow_key.strip(),
        "source_provenance": source_provenance.strip() if source_provenance and source_provenance.strip() else "null",
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def alert_definition_id(
    engine: str,
    ruleset_namespace: str,
    gid: Optional[int],
    sid: int,
) -> str:
    """Return a canonical alert definition identity string: '{engine}:{namespace}:{gid}:{sid}'.

    Prevents identity collisions between different rule engines (Suricata, Snort) or
    overlapping rulesets (ET-Open, Snort-Community, Local).
    An absent GID (None) is canonically represented by the explicit sentinel 'none',
    ensuring unassigned GIDs never collide with GID 1 (standard rule generator).
    Rule revision is treated as metadata and does not alter the logical definition identity.

    Args:
        engine: Signature engine name (e.g. 'suricata', 'snort').
        ruleset_namespace: Ruleset namespace (e.g. 'et-open', 'snort-community', 'local').
        gid: Generator ID integer (non-negative), or None if unassigned/absent.
        sid: Signature ID integer (must be non-negative).

    Returns:
        Canonical definition identity string (e.g. 'suricata:et-open:1:2001219' or 'suricata:custom:none:100').

    Raises:
        ValueError: If engine or ruleset_namespace is empty, gid is negative, or sid is invalid.
    """
    if not engine or not str(engine).strip():
        raise ValueError("engine cannot be empty")
    if not ruleset_namespace or not str(ruleset_namespace).strip():
        raise ValueError("ruleset_namespace cannot be empty")
    if sid is None or isinstance(sid, bool) or not isinstance(sid, int) or sid < 0:
        raise ValueError(f"Invalid signature ID (sid): {sid}")
    if gid is not None and (isinstance(gid, bool) or not isinstance(gid, int) or gid < 0):
        raise ValueError(f"Invalid generator ID (gid): {gid}. GID must be non-negative or None.")

    norm_engine = engine.strip().lower()
    norm_namespace = ruleset_namespace.strip().lower()
    canonical_gid = "none" if gid is None else str(int(gid))

    return f"{norm_engine}:{norm_namespace}:{canonical_gid}:{sid}"


def compute_alert_event_id(
    source_type: str,
    sensor_id: str,
    source_record_id: str,
    timestamp: Union[float, int, str, Decimal],
    def_id: str,
    flow_reference: Optional[str] = None,
    source_provenance: Optional[str] = None,
) -> str:
    """Generate a deterministic SHA-256 event identifier for an alert firing occurrence.

    SEMANTIC DISTINCTION:
    `alert_event_id` represents an actual temporal occurrence of an alert (AlertEvent),
    in contrast to `def_id` which identifies the static security rule (AlertDefinition).
    Repeated firings of the same rule at different times or across different flow sessions
    produce distinct, idempotent alert event IDs. Requires a non-empty native `source_record_id`.

    Args:
        source_type: Telemetry format/source (e.g. 'suricata', 'snort').
        sensor_id: Sensor vantage identifier.
        source_record_id: Non-empty native event identifier (e.g. Suricata event_id, tx_id, pcap_cnt).
        timestamp: Alert occurrence timestamp.
        def_id: Canonical alert definition ID (e.g. 'suricata:et-open:1:2001219').
        flow_reference: Optional Community ID, flow_id, or flow_key linking alert to traffic.
        source_provenance: Optional source dataset or file identifier.

    Returns:
        64-character lowercase hex SHA-256 digest.

    Raises:
        ValueError: If source_record_id, source_type, or def_id is empty.
    """
    if not source_record_id or not str(source_record_id).strip():
        raise ValueError("source_record_id cannot be empty for alert event identity")
    if not source_type or not str(source_type).strip():
        raise ValueError("source_type cannot be empty")
    if not def_id or not str(def_id).strip():
        raise ValueError("def_id cannot be empty")

    canonical_ts = canonicalize_event_timestamp(timestamp)

    payload = {
        "source_type": source_type.strip().lower(),
        "sensor_id": sensor_id.strip().lower() if sensor_id and sensor_id.strip() else "default",
        "source_record_id": str(source_record_id).strip(),
        "timestamp": canonical_ts,
        "def_id": def_id.strip(),
        "flow_reference": flow_reference.strip() if flow_reference and flow_reference.strip() else "null",
        "source_provenance": source_provenance.strip() if source_provenance and source_provenance.strip() else "null",
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Minimal V2 Domain Models (Frozen, Typed Dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RoutingDomainRecord:
    """Represents an isolated Layer 3 routing namespace (VRF, VPC, or autonomous network)."""
    domain_id: str
    name: str
    vrf_name: Optional[str] = None
    description: Optional[str] = None


@dataclass(frozen=True)
class ScopedIPAddressRecord:
    """Represents an observable Layer 3 endpoint within a specific RoutingDomain."""
    scoped_id: str
    domain_id: str
    address: str
    version: int
    is_private: bool


@dataclass(frozen=True)
class FlowObservationRecord:
    """Represents a discrete, timestamped flow session observation from a sensor."""
    observation_id: str
    flow_key: str
    src_scoped_id: str
    dst_scoped_id: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    start_epoch: float = 0.0
    end_epoch: float = 0.0
    observed_packets: Optional[int] = None
    observed_bytes: Optional[int] = None
    community_id: Optional[str] = None
    sensor_id: str = "default"
    source_type: str = "unknown"
    source_record_id: Optional[str] = None
    source_provenance: Optional[str] = None


@dataclass(frozen=True)
class AlertEventRecord:
    """Represents a discrete occurrence of an intrusion detection alert firing."""
    event_id: str
    alert_definition_id: str
    timestamp: float
    src_scoped_id: str
    dst_scoped_id: str
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    priority: Optional[int] = None
    message: Optional[str] = None
    community_id: Optional[str] = None
    sensor_id: str = "default"
    source_type: str = "unknown"
    source_record_id: Optional[str] = None
    source_provenance: Optional[str] = None


@dataclass(frozen=True)
class ZeekConnectionObservation:
    """Normalized temporal connection observation parsed from Zeek conn.log JSONL.

    Neo4j-independent domain model preserving Zeek's exact temporal precision
    (Decimal epoch and canonical timestamp strings), native Zeek connection UID,
    explicit RoutingDomain-scoped endpoints, separate directional payload vs
    IP-level byte and packet metrics, and separate Community ID correlation key.
    Absent optional fields remain None rather than inventing fallback zeros.
    """
    observation_id: str
    flow_key: str
    zeek_uid: str
    routing_domain_id: str
    src_scoped_id: str
    dst_scoped_id: str
    src_ip: str
    dst_ip: str
    protocol: str
    start_ts: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    community_id: Optional[str] = None
    start_epoch: Optional[Decimal] = None
    duration: Optional[Decimal] = None
    end_epoch: Optional[Decimal] = None
    end_ts: Optional[str] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None
    orig_ip_bytes: Optional[int] = None
    resp_ip_bytes: Optional[int] = None
    missed_bytes: Optional[int] = None
    service: Optional[str] = None
    conn_state: Optional[str] = None
    history: Optional[str] = None
    local_orig: Optional[bool] = None
    local_resp: Optional[bool] = None
    sensor_id: str = "default"
    source_type: str = "zeek"
    source_provenance: Optional[str] = None
