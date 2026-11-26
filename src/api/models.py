"""
Pydantic response models and schemas for the FastAPI backend API.
"""

import ipaddress
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar, Union
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

JS_MAX_SAFE_INTEGER = (1 << 53) - 1  # 9007199254740991
_INT64_MAX = (1 << 63) - 1
_UINT64_MAX = (1 << 64) - 1
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_FIXED_DECIMAL_RE = re.compile(r"^-?[0-9]+(?:\.[0-9]+)?$")


def _require_non_empty_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty string without leading/trailing whitespace")
    return value


def _validate_sha256_hex_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_HEX_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a 64-character lowercase SHA-256 hex string")
    return value


def _validate_persisted_routing_domain(value: Any) -> str:
    cleaned = _require_non_empty_text(value, "routing_domain_id")
    if "#" in cleaned:
        raise ValueError("routing_domain_id cannot contain reserved '#' delimiter")
    return cleaned


def _validate_strict_ip_str(value: Any, field_name: str) -> str:
    cleaned = _require_non_empty_text(value, field_name)
    try:
        ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid IP address: {cleaned!r}") from exc
    return cleaned


def _validate_optional_non_empty_text(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    return _require_non_empty_text(value, field_name)


def _validate_optional_finite_decimal_str(
    value: Any,
    field_name: str,
    *,
    non_negative: bool = False,
) -> Optional[str]:
    if value is None:
        return None
    cleaned = _require_non_empty_text(value, field_name)
    if not _FIXED_DECIMAL_RE.fullmatch(cleaned):
        raise ValueError(f"{field_name} must be a fixed-point decimal string, got {value!r}")
    try:
        dec = Decimal(cleaned)
    except InvalidOperation as exc:
        raise ValueError(f"{field_name} must be a valid decimal string, got {value!r}") from exc
    if not dec.is_finite():
        raise ValueError(f"{field_name} must be finite, got {value!r}")
    if non_negative and dec < 0:
        raise ValueError(f"{field_name} must be non-negative, got {value!r}")
    return cleaned


def _validate_optional_port_int(value: Any, field_name: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 65535):
        raise ValueError(f"{field_name} must be an integer in 0..65535 or None, got {value!r}")
    return value


def _validate_strict_non_neg_int(
    value: Any,
    field_name: str,
    *,
    allow_none: bool,
) -> Optional[int]:
    if value is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} is required and cannot be null")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _INT64_MAX:
        raise ValueError(f"{field_name} must be an integer in 0..{_INT64_MAX}, got {value!r}")
    return value


def _validate_optional_uint64_decimal_str(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        raise ValueError(f"{field_name} must be an ASCII decimal string or None, got {value!r}")
    if value != "0" and value.startswith("0"):
        raise ValueError(f"{field_name} must be a canonical unsigned integer string without leading zeros")
    parsed = int(value)
    if parsed > _UINT64_MAX:
        raise ValueError(f"{field_name} exceeds uint64 max ({_UINT64_MAX})")
    return value


def _serialize_js_safe_int(value: Optional[int]) -> Optional[Union[int, str]]:
    """Preserve exact JSON numbers up to 2**53-1 and serialize larger integers as strings."""
    if value is None:
        return None
    if value > JS_MAX_SAFE_INTEGER:
        return str(value)
    return value

T = TypeVar("T")


# --- System Health & Readiness Schemas ---

class HealthResponse(BaseModel):
    """Liveness health check response model."""
    status: str = Field(default="ok", description="Application liveness status")
    app: str = Field(default="Network Traffic Analysis", description="Application name")


class ReadyResponse(BaseModel):
    """Database readiness check response model."""
    status: str = Field(default="ready", description="Database readiness status")
    database: str = Field(default="connected", description="Database connection status")


# --- Network & Topology Schemas ---

class IPAddressResponse(BaseModel):
    """Observed IP address model."""
    address: str = Field(description="Canonical IP address string")
    scoped_id: Optional[str] = Field(default=None, description="Scoped IP identifier")
    routing_domain_id: Optional[str] = Field(default=None, description="Routing domain identifier")


class IPDetailResponse(BaseModel):
    """Detailed local graph context and flow counts for an IP address."""
    address: str = Field(description="Canonical IP address string")
    scoped_id: Optional[str] = Field(default=None, description="Scoped IP identifier")
    routing_domain_id: Optional[str] = Field(default=None, description="Routing domain identifier")
    layer2_identifiers: List[str] = Field(description="Observed associated Layer 2 identifiers")
    outbound_flows: int = Field(description="Count of outgoing Layer 3 communications")
    inbound_flows: int = Field(description="Count of incoming Layer 3 communications")
    alerts_originated: int = Field(description="Count of security alerts where this IP was source")
    alerts_targeted: int = Field(description="Count of security alerts targeting this IP")
    traffic_metrics_mode: Literal["none", "basic", "enriched", "mixed"] = Field(
        default="none",
        description="Measurement availability mode for traffic communications incident to this IP",
    )
    distinct_outbound_peers: int = Field(
        default=0,
        description="Count of distinct destination IP peers contacted by this IP (fan-out)",
    )
    distinct_inbound_peers: int = Field(
        default=0,
        description="Count of distinct source IP peers contacting this IP (fan-in)",
    )
    distinct_destination_ports: int = Field(
        default=0,
        description="Count of distinct destination transport ports contacted by this IP",
    )
    observed_packets_sent: Optional[int] = Field(
        default=None,
        description="Total packets observed sent from this IP across enriched communications",
    )
    observed_packets_received: Optional[int] = Field(
        default=None,
        description="Total packets observed received by this IP across enriched communications",
    )
    observed_bytes_sent: Optional[int] = Field(
        default=None,
        description="Total bytes observed sent from this IP across enriched communications",
    )
    observed_bytes_received: Optional[int] = Field(
        default=None,
        description="Total bytes observed received by this IP across enriched communications",
    )
    first_observed: Optional[float] = Field(
        default=None,
        description="Earliest observation timestamp (seconds since epoch) across enriched incident communications",
    )
    last_observed: Optional[float] = Field(
        default=None,
        description="Latest observation timestamp (seconds since epoch) across enriched incident communications",
    )


class PeerResponse(BaseModel):
    """Communicating peer model."""
    peer_address: str = Field(description="Canonical IP address of peer")
    direction: Literal["outbound", "inbound"] = Field(description="Traffic direction relative to queried IP")
    protocols: List[str] = Field(description="Distinct observed protocols sorted alphabetically")


class Layer2IdentifierResponse(BaseModel):
    """Layer 2 hardware or local identifier model."""
    identifier: str = Field(description="Layer 2 MAC address or resolved local identifier")


class CommunicationResponse(BaseModel):
    """Layer 3 directional communication flow model."""
    source_ip: str = Field(description="Source IP address")
    target_ip: str = Field(description="Destination IP address")
    protocol: str = Field(description="Observed protocol value")
    flow_key: Optional[str] = Field(default=None, description="Deterministic 64-character SHA-256 flow identity key")
    src_port: Optional[int] = Field(default=None, description="Observed source transport port number")
    dst_port: Optional[int] = Field(default=None, description="Observed destination transport port number")
    observed_packet_count: Optional[int] = Field(default=None, description="Count of packets observed for this communication aggregate")
    observed_bytes: Optional[int] = Field(default=None, description="Total byte volume observed for this communication aggregate")
    first_seen: Optional[float] = Field(default=None, description="Earliest frame timestamp (seconds since epoch)")
    last_seen: Optional[float] = Field(default=None, description="Latest frame timestamp (seconds since epoch)")
    observed_window_seconds: Optional[float] = Field(default=None, description="Duration in seconds between first and last observed frames")


# --- Traffic Analytics Schemas (Phase 7C) ---

class ProtocolDistributionItem(BaseModel):
    """Aggregated metrics for an observed network protocol."""
    protocol: str = Field(description="Normalized protocol identifier")
    communication_aggregate_count: int = Field(description="Number of communication relationships using this protocol")
    observed_packet_count: Optional[int] = Field(default=None, description="Total observed packets (null if no enriched metrics)")
    observed_bytes: Optional[int] = Field(default=None, description="Total observed bytes (null if no enriched metrics)")


class DestinationPortDistributionItem(BaseModel):
    """Aggregated metrics for a destination transport port."""
    dst_port: int = Field(description="Destination port number")
    communication_aggregate_count: int = Field(description="Number of communication relationships targeting this port")
    observed_packet_count: Optional[int] = Field(default=None, description="Total observed packets (null if no enriched metrics)")
    observed_bytes: Optional[int] = Field(default=None, description="Total observed bytes (null if no enriched metrics)")


class FanOutItem(BaseModel):
    """Ranked fan-out metric for a source IP address."""
    address: str = Field(description="Source IP address")
    distinct_destination_ips: int = Field(description="Count of distinct destination IPs contacted")


class FanInItem(BaseModel):
    """Ranked fan-in metric for a destination IP address."""
    address: str = Field(description="Destination IP address")
    distinct_source_ips: int = Field(description="Count of distinct source IPs contacting this address")


class TrafficAnalyticsSummaryResponse(BaseModel):
    """Global traffic analytics summary and factual distribution metrics."""
    traffic_metrics_mode: Literal["none", "basic", "enriched", "mixed"] = Field(
        description="Factual classification of metric completeness across all persisted traffic aggregates",
    )
    total_communication_aggregates: int = Field(
        description="Total count of COMMUNICATED_TO relationships in graph",
    )
    enriched_communication_aggregates: int = Field(
        description="Count of COMMUNICATED_TO relationships containing complete Phase 7 metric attributes",
    )
    basic_communication_aggregates: int = Field(
        description="Count of legacy/basic COMMUNICATED_TO relationships lacking measurement attributes",
    )
    total_observed_packets: Optional[int] = Field(
        default=None,
        description="Sum of observed packets across enriched aggregates (null if no enriched metrics present)",
    )
    total_observed_bytes: Optional[int] = Field(
        default=None,
        description="Sum of observed bytes across enriched aggregates (null if no enriched metrics present)",
    )
    first_observed: Optional[float] = Field(
        default=None,
        description="Earliest frame timestamp across enriched aggregates (null if no enriched metrics present)",
    )
    last_observed: Optional[float] = Field(
        default=None,
        description="Latest frame timestamp across enriched aggregates (null if no enriched metrics present)",
    )
    protocol_distribution: List[ProtocolDistributionItem] = Field(
        default_factory=list,
        description="Distribution of communications across observed dissector protocols",
    )
    destination_port_distribution: List[DestinationPortDistributionItem] = Field(
        default_factory=list,
        description="Top destination transport ports by communication aggregate count",
    )
    top_fan_out: List[FanOutItem] = Field(
        default_factory=list,
        description="Top source IP addresses ranked by distinct destination IP count",
    )
    top_fan_in: List[FanInItem] = Field(
        default_factory=list,
        description="Top destination IP addresses ranked by distinct source IP count",
    )


class EndpointAnalyticsResponse(BaseModel):
    """Factual traffic and topology metrics for an observed IP endpoint."""
    address: str = Field(description="Canonical IP address")
    scoped_id: Optional[str] = Field(default=None, description="Scoped IP identifier")
    routing_domain_id: Optional[str] = Field(default=None, description="Routing domain identifier")
    outbound_communication_aggregates: int = Field(description="Count of outgoing COMMUNICATED_TO relationships")
    inbound_communication_aggregates: int = Field(description="Count of incoming COMMUNICATED_TO relationships")
    distinct_outbound_peers: int = Field(description="Distinct destination IP addresses contacted (fan-out)")
    distinct_inbound_peers: int = Field(description="Distinct source IP addresses contacting this IP (fan-in)")
    distinct_destination_ports: int = Field(description="Distinct destination transport ports contacted")
    observed_packets_sent: Optional[int] = Field(default=None, description="Observed packets sent across enriched flows")
    observed_packets_received: Optional[int] = Field(default=None, description="Observed packets received across enriched flows")
    observed_bytes_sent: Optional[int] = Field(default=None, description="Observed bytes sent across enriched flows")
    observed_bytes_received: Optional[int] = Field(default=None, description="Observed bytes received across enriched flows")
    first_observed: Optional[float] = Field(default=None, description="Earliest observation timestamp on enriched incident flows")
    last_observed: Optional[float] = Field(default=None, description="Latest observation timestamp on enriched incident flows")
    traffic_metrics_mode: Literal["none", "basic", "enriched", "mixed"] = Field(
        description="Measurement availability mode for communications incident to this endpoint",
    )


# --- Security Alerts & Correlation Schemas ---

class AlertFactResponse(BaseModel):
    """Normalized security alert fact model."""
    fact_key: str = Field(description="Deterministic SHA-256 identity key")
    source_ip: str = Field(description="Source IP address recorded by the alert")
    target_ip: str = Field(description="Target/destination IP address recorded by the alert")
    sid: Optional[int] = Field(default=None, description="Snort / IDS signature ID")
    gid: Optional[int] = Field(default=None, description="Generator ID")
    rev: Optional[int] = Field(default=None, description="Rule revision")
    message: Optional[str] = Field(default=None, description="Alert message or rule description")
    priority: Optional[int] = Field(default=None, description="Alert severity priority")
    protocol: Optional[str] = Field(default=None, description="Observed alert protocol")
    src_port: Optional[int] = Field(default=None, description="Source port number")
    dst_port: Optional[int] = Field(default=None, description="Destination port number")


class TrafficAlertCorrelationResponse(BaseModel):
    """Correlated traffic communication flow with matching security alert fact."""
    source_ip: str = Field(description="Source IP address")
    target_ip: str = Field(description="Target IP address")
    traffic_protocol: str = Field(description="Observed traffic communication protocol")
    traffic_flow_key: Optional[str] = Field(default=None, description="Deterministic flow identity key of matching communication")
    traffic_src_port: Optional[int] = Field(default=None, description="Source port of matching communication")
    traffic_dst_port: Optional[int] = Field(default=None, description="Destination port of matching communication")
    fact_key: str = Field(description="Deterministic SHA-256 alert fact key")
    sid: Optional[int] = Field(default=None, description="Snort signature ID")
    message: Optional[str] = Field(default=None, description="Alert message description")
    priority: Optional[int] = Field(default=None, description="Alert severity priority")
    alert_protocol: Optional[str] = Field(default=None, description="Alert record protocol")


class AlertFlowCorrelationResponse(BaseModel):
    """Persisted V2 Suricata AlertEvent to Zeek FlowObservation observational correlation."""

    model_config = ConfigDict(strict=True)

    event_id: str = Field(description="Deterministic 64-character SHA-256 Suricata AlertEvent identifier")
    observation_id: str = Field(description="Deterministic 64-character SHA-256 Zeek FlowObservation identifier")
    zeek_uid: Optional[str] = Field(default=None, description="Native Zeek connection UID from FlowObservation")
    routing_domain_id: str = Field(description="Isolated Layer 3 RoutingDomain identifier")
    correlation_method: Optional[str] = Field(default=None, description="Factual correlation method label derived from verified evidence")
    evidence_version: Optional[str] = Field(default=None, description="Version identifier of the correlation evidence schema")
    policy_fingerprint: Optional[str] = Field(default=None, description="SHA-256 fingerprint of the CorrelationPolicy active when decided")
    evidence_digest: Optional[str] = Field(default=None, description="Deterministic SHA-256 digest of persisted evidence and policy")
    tuple_orientation: Optional[str] = Field(default=None, description="Matched endpoint orientation (FORWARD, REVERSE, or SYMMETRIC)")
    community_id_agreement: Optional[str] = Field(default=None, description="Community ID comparison classification")
    temporal_relation: Optional[str] = Field(default=None, description="Exact Decimal temporal relationship classification")
    temporal_delta_decimal: Optional[str] = Field(
        default=None,
        description="Exact canonical Decimal temporal delta string in seconds (never coerced to float)",
    )
    used_decimal_fallback: Optional[bool] = Field(
        default=None,
        description="Whether exact Decimal comparison bypassed null nanosecond index fields",
    )
    sensor_context: Optional[str] = Field(default=None, description="Factual sensor pairing provenance string")
    verification_status: Literal["verified", "unverified_incomplete"] = Field(
        description="Persisted edge verification lifecycle status ('verified' or 'unverified_incomplete')",
    )
    last_incomplete_reason: Optional[str] = Field(
        default=None,
        description="Persisted reason code when an incomplete reevaluation marked an existing edge unverified_incomplete",
    )
    last_incomplete_at_utc: Optional[str] = Field(
        default=None,
        description="UTC ISO-8601 timestamp when an existing edge was marked unverified_incomplete",
    )
    decided_at_utc: Optional[str] = Field(
        default=None,
        description="UTC ISO-8601 timestamp when the verified correlation edge was persisted or updated",
    )


class AlertEventDetailResponse(BaseModel):
    """Persisted V2 Suricata AlertEvent forensic detail model (strict, read-only)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    # Identity & provenance
    event_id: str = Field(description="Deterministic 64-character lowercase SHA-256 Suricata AlertEvent identifier")
    alert_definition_id: str = Field(description="Canonical rule definition identifier ({engine}:{namespace}:{gid}:{sid})")
    source_record_id: str = Field(description="Native source record identifier")
    log_source_id: str = Field(description="Log source provenance identifier")
    sensor_id: str = Field(description="Sensor vantage identifier")
    ruleset_namespace: str = Field(description="Rule namespace (e.g. et-open, local)")
    routing_domain_id: str = Field(description="Isolated Layer 3 RoutingDomain identifier")
    source_type: Literal["suricata"] = Field(description="Enforced telemetry source type ('suricata')")
    source_provenance: Optional[str] = Field(default=None, description="Optional ingested source dataset provenance")

    # Rule & alert metadata (engine resolved strictly from AlertDefinition; null when unlinked)
    engine: Optional[str] = Field(
        default=None,
        description="Detection engine from linked AlertDefinition (null when AlertDefinition relationship is absent)",
    )
    gid: Optional[int] = Field(default=None, description="Rule generator ID (GID)")
    sid: int = Field(description="Suricata signature ID (SID)")
    rev: Optional[int] = Field(default=None, description="Rule revision")
    signature: Optional[str] = Field(default=None, description="Suricata rule signature message")
    category: Optional[str] = Field(default=None, description="Suricata alert category")
    severity: Optional[int] = Field(default=None, description="Recorded Suricata alert severity integer")
    action: Optional[str] = Field(
        default=None,
        description="Recorded Suricata alert action field (not proof of end-to-end enforcement)",
    )
    app_proto: Optional[str] = Field(default=None, description="Recorded application protocol")
    direction: Optional[str] = Field(default=None, description="Recorded Suricata packet direction hint")
    tx_id: Optional[int] = Field(default=None, description="Recorded Suricata transaction identifier")
    pcap_cnt: Optional[int] = Field(default=None, description="Recorded packet counter")
    flow_id: Optional[str] = Field(
        default=None,
        description="Lossless canonical unsigned 64-bit decimal string Suricata flow_id",
    )

    # Network evidence
    src_ip: str = Field(description="Observed source IP address (packet direction, not attacker proof)")
    dst_ip: str = Field(description="Observed destination IP address (packet direction, not victim proof)")
    src_scoped_id: str = Field(description="RoutingDomain-scoped source IP identifier")
    dst_scoped_id: str = Field(description="RoutingDomain-scoped destination IP identifier")
    protocol: Optional[str] = Field(default=None, description="Observed transport protocol")
    src_port: Optional[int] = Field(default=None, description="Observed source transport port (0..65535)")
    dst_port: Optional[int] = Field(default=None, description="Observed destination transport port (0..65535)")
    flow_key: str = Field(description="Directional V2 SHA-256 communication profile key")
    community_id: Optional[str] = Field(default=None, description="Bidirectional Community ID flow hash")

    # Time evidence (never exposes raw timestamp_epoch_ns)
    timestamp_source: str = Field(description="Original recorded EVE timestamp string")
    timestamp_epoch_decimal: Optional[str] = Field(
        default=None,
        description="Exact arbitrary-precision Decimal epoch seconds string (null if timezone-naive)",
    )

    @field_validator("event_id")
    @classmethod
    def _check_event_id(cls, value: str) -> str:
        return _validate_sha256_hex_str(value, "event_id")

    @field_validator("flow_key")
    @classmethod
    def _check_flow_key(cls, value: str) -> str:
        return _require_non_empty_text(value, "flow_key")

    @field_validator(
        "alert_definition_id",
        "source_record_id",
        "log_source_id",
        "sensor_id",
        "ruleset_namespace",
        "src_scoped_id",
        "dst_scoped_id",
        "timestamp_source",
    )
    @classmethod
    def _check_required_text(cls, value: str, info) -> str:
        return _require_non_empty_text(value, info.field_name)

    @field_validator("routing_domain_id")
    @classmethod
    def _check_domain(cls, value: str) -> str:
        return _validate_persisted_routing_domain(value)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _check_ips(cls, value: str, info) -> str:
        return _validate_strict_ip_str(value, info.field_name)

    @field_validator(
        "source_provenance",
        "engine",
        "signature",
        "category",
        "action",
        "app_proto",
        "direction",
        "protocol",
        "community_id",
    )
    @classmethod
    def _check_optional_text(cls, value: Optional[str], info) -> Optional[str]:
        return _validate_optional_non_empty_text(value, info.field_name)

    @field_validator("timestamp_epoch_decimal")
    @classmethod
    def _check_decimal(cls, value: Optional[str], info) -> Optional[str]:
        return _validate_optional_finite_decimal_str(value, info.field_name)

    @field_validator("src_port", "dst_port")
    @classmethod
    def _check_ports(cls, value: Optional[int], info) -> Optional[int]:
        return _validate_optional_port_int(value, info.field_name)

    @field_validator("sid")
    @classmethod
    def _check_sid(cls, value: int) -> int:
        checked = _validate_strict_non_neg_int(value, "sid", allow_none=False)
        assert checked is not None
        return checked

    @field_validator("gid", "rev", "severity", "tx_id", "pcap_cnt")
    @classmethod
    def _check_optional_counts(cls, value: Optional[int], info) -> Optional[int]:
        return _validate_strict_non_neg_int(value, info.field_name, allow_none=True)

    @field_validator("flow_id")
    @classmethod
    def _check_flow_id(cls, value: Optional[str]) -> Optional[str]:
        return _validate_optional_uint64_decimal_str(value, "flow_id")

    @model_validator(mode="after")
    def _check_domain_scoped_endpoints(self) -> "AlertEventDetailResponse":
        norm_domain = self.routing_domain_id.lower()
        expected_src = f"{norm_domain}#{str(ipaddress.ip_address(self.src_ip))}"
        expected_dst = f"{norm_domain}#{str(ipaddress.ip_address(self.dst_ip))}"
        if self.src_scoped_id != expected_src:
            raise ValueError(
                f"Inconsistent src_scoped_id {self.src_scoped_id!r} for routing_domain_id {norm_domain!r}"
            )
        if self.dst_scoped_id != expected_dst:
            raise ValueError(
                f"Inconsistent dst_scoped_id {self.dst_scoped_id!r} for routing_domain_id {norm_domain!r}"
            )
        return self

    @field_serializer("sid", when_used="json")
    def _serialize_safe_sid(self, value: int) -> Union[int, str]:
        if abs(value) > JS_MAX_SAFE_INTEGER:
            return str(value)
        return value

    @field_serializer("gid", "rev", "severity", "tx_id", "pcap_cnt", when_used="json")
    def _serialize_safe_integers(self, value: Optional[int]) -> Optional[Union[int, str]]:
        return _serialize_js_safe_int(value)


class FlowObservationDetailResponse(BaseModel):
    """Persisted V2 Zeek FlowObservation forensic detail model (strict, read-only)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    # Identity & provenance
    observation_id: str = Field(description="Deterministic 64-character lowercase SHA-256 FlowObservation identifier")
    flow_key: str = Field(description="Directional V2 SHA-256 communication profile key")
    zeek_uid: str = Field(description="Native Zeek connection UID")
    routing_domain_id: str = Field(description="Isolated Layer 3 RoutingDomain identifier")
    sensor_id: str = Field(description="Sensor vantage identifier")
    source_type: Literal["zeek"] = Field(description="Enforced telemetry source type ('zeek')")
    source_provenance: Optional[str] = Field(default=None, description="Optional ingested source dataset provenance")
    community_id: Optional[str] = Field(default=None, description="Bidirectional Community ID flow hash")

    # Network evidence
    src_ip: str = Field(description="Observed Zeek originator IP (not attacker proof)")
    dst_ip: str = Field(description="Observed Zeek responder IP (not victim proof)")
    src_scoped_id: str = Field(description="RoutingDomain-scoped originator IP identifier")
    dst_scoped_id: str = Field(description="RoutingDomain-scoped responder IP identifier")
    protocol: str = Field(description="Observed transport protocol")
    src_port: Optional[int] = Field(default=None, description="Observed originator transport port (0..65535)")
    dst_port: Optional[int] = Field(default=None, description="Observed responder transport port (0..65535)")

    # Time evidence (never exposes raw start_epoch_ns / end_epoch_ns)
    start_ts: str = Field(description="Original canonical Zeek start timestamp string")
    end_ts: Optional[str] = Field(
        default=None,
        description="Derived last-observed timestamp string (start_epoch + duration; not confirmed TCP close)",
    )
    start_epoch_decimal: Optional[str] = Field(
        default=None,
        description="Exact arbitrary-precision Decimal start epoch seconds string",
    )
    end_epoch_decimal: Optional[str] = Field(
        default=None,
        description="Exact arbitrary-precision Decimal derived last-observed epoch seconds string",
    )
    duration_decimal: Optional[str] = Field(
        default=None,
        description="Exact arbitrary-precision Decimal flow duration seconds string",
    )

    # Traffic metrics (payload bytes kept distinct from IP-level bytes and packets)
    orig_bytes: Optional[int] = Field(default=None, description="Originator payload bytes recorded by Zeek")
    resp_bytes: Optional[int] = Field(default=None, description="Responder payload bytes recorded by Zeek")
    orig_ip_bytes: Optional[int] = Field(default=None, description="Originator IP-level bytes recorded by Zeek")
    resp_ip_bytes: Optional[int] = Field(default=None, description="Responder IP-level bytes recorded by Zeek")
    orig_pkts: Optional[int] = Field(default=None, description="Originator packet count recorded by Zeek")
    resp_pkts: Optional[int] = Field(default=None, description="Responder packet count recorded by Zeek")
    missed_bytes: Optional[int] = Field(default=None, description="Missed bytes reported by Zeek")

    # Zeek metadata
    service: Optional[str] = Field(default=None, description="Zeek detected application service")
    conn_state: Optional[str] = Field(
        default=None,
        description="Zeek conn_state symbol (e.g. SF; does not prove benign or successful application traffic)",
    )
    history: Optional[str] = Field(default=None, description="Zeek connection state history string")
    local_orig: Optional[bool] = Field(default=None, description="Zeek local originator indicator")
    local_resp: Optional[bool] = Field(default=None, description="Zeek local responder indicator")

    @field_validator("observation_id")
    @classmethod
    def _check_observation_id(cls, value: str) -> str:
        return _validate_sha256_hex_str(value, "observation_id")

    @field_validator(
        "flow_key",
        "zeek_uid",
        "sensor_id",
        "src_scoped_id",
        "dst_scoped_id",
        "protocol",
        "start_ts",
    )
    @classmethod
    def _check_required_text(cls, value: str, info) -> str:
        return _require_non_empty_text(value, info.field_name)

    @field_validator("routing_domain_id")
    @classmethod
    def _check_domain(cls, value: str) -> str:
        return _validate_persisted_routing_domain(value)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _check_ips(cls, value: str, info) -> str:
        return _validate_strict_ip_str(value, info.field_name)

    @field_validator("source_provenance", "community_id", "end_ts", "service", "conn_state", "history")
    @classmethod
    def _check_optional_text(cls, value: Optional[str], info) -> Optional[str]:
        return _validate_optional_non_empty_text(value, info.field_name)

    @field_validator("start_epoch_decimal", "end_epoch_decimal")
    @classmethod
    def _check_decimals(cls, value: Optional[str], info) -> Optional[str]:
        return _validate_optional_finite_decimal_str(value, info.field_name)

    @field_validator("duration_decimal")
    @classmethod
    def _check_duration_decimal(cls, value: Optional[str], info) -> Optional[str]:
        return _validate_optional_finite_decimal_str(value, info.field_name, non_negative=True)

    @field_validator("src_port", "dst_port")
    @classmethod
    def _check_ports(cls, value: Optional[int], info) -> Optional[int]:
        return _validate_optional_port_int(value, info.field_name)

    @field_validator(
        "orig_bytes",
        "resp_bytes",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "orig_pkts",
        "resp_pkts",
        "missed_bytes",
    )
    @classmethod
    def _check_counts(cls, value: Optional[int], info) -> Optional[int]:
        return _validate_strict_non_neg_int(value, info.field_name, allow_none=True)

    @model_validator(mode="after")
    def _check_domain_scoped_endpoints(self) -> "FlowObservationDetailResponse":
        norm_domain = self.routing_domain_id.lower()
        expected_src = f"{norm_domain}#{str(ipaddress.ip_address(self.src_ip))}"
        expected_dst = f"{norm_domain}#{str(ipaddress.ip_address(self.dst_ip))}"
        if self.src_scoped_id != expected_src:
            raise ValueError(
                f"Inconsistent src_scoped_id {self.src_scoped_id!r} for routing_domain_id {norm_domain!r}"
            )
        if self.dst_scoped_id != expected_dst:
            raise ValueError(
                f"Inconsistent dst_scoped_id {self.dst_scoped_id!r} for routing_domain_id {norm_domain!r}"
            )
        return self

    @field_serializer(
        "orig_bytes",
        "resp_bytes",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "orig_pkts",
        "resp_pkts",
        "missed_bytes",
        when_used="json",
    )
    def _serialize_safe_integers(self, value: Optional[int]) -> Optional[Union[int, str]]:
        return _serialize_js_safe_int(value)


# --- Graph Traversal & Topology Schemas ---

class GraphNodeResponse(BaseModel):
    """Graph node response model with application-level identifiers."""
    id: str = Field(description="Application-level node identifier (e.g., 'ip:10.0.0.1')")
    type: Literal["IPAddress", "Layer2Identifier"] = Field(description="Graph node entity type")
    value: str = Field(description="Domain value (address or identifier)")


class GraphEdgeResponse(BaseModel):
    """Graph edge response model connecting application-level node IDs."""
    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")
    type: Literal["COMMUNICATED_TO", "OBSERVED_WITH"] = Field(description="Graph relationship type")
    protocol: Optional[str] = Field(default=None, description="Observed protocol on relationship")
    flow_key: Optional[str] = Field(default=None, description="Deterministic flow identity key for COMMUNICATED_TO")
    src_port: Optional[int] = Field(default=None, description="Source port number")
    dst_port: Optional[int] = Field(default=None, description="Destination port number")
    observed_packet_count: Optional[int] = Field(default=None, description="Count of observed packets")
    observed_bytes: Optional[int] = Field(default=None, description="Total observed byte volume")
    first_seen: Optional[float] = Field(default=None, description="Earliest frame timestamp")
    last_seen: Optional[float] = Field(default=None, description="Latest frame timestamp")
    observed_window_seconds: Optional[float] = Field(default=None, description="Observed duration in seconds")


class GraphNeighborhoodResponse(BaseModel):
    """Bounded local graph neighborhood response model."""
    center: str = Field(description="Canonical center IP address")
    depth: int = Field(description="Traversal depth (1 or 2)")
    nodes: List[GraphNodeResponse] = Field(description="Unique graph nodes in neighborhood")
    edges: List[GraphEdgeResponse] = Field(description="Relationships spanning the returned nodes")


class PathResponse(BaseModel):
    """Shortest communication path response model."""
    source: str = Field(description="Origin IP address")
    target: str = Field(description="Destination IP address")
    hops: List[str] = Field(description="Ordered sequence of IP addresses on path")
    protocols: List[str] = Field(description="Observed protocols along each hop")
    length: int = Field(description="Number of communication hops")


# --- Generic Pagination Envelope ---

class PaginatedResponse(BaseModel, Generic[T]):
    """Standard pagination envelope."""
    items: List[T] = Field(description="List of items for current page")
    total: int = Field(description="Total count of items matching the query filters")
    limit: int = Field(description="Maximum number of items requested")
    offset: int = Field(description="Offset of the first item in the collection")

    model_config = ConfigDict(arbitrary_types_allowed=True)


# --- Data Import & Workspace Replacement Schemas (Phase 6.5) ---

class ImportStatusResponse(BaseModel):
    """Data import enablement status and file size limit configuration."""
    enabled: bool = Field(description="Whether browser data import and workspace replacement are enabled")
    max_file_size_bytes: int = Field(description="Maximum allowable file size in bytes")
    max_file_size_mb: int = Field(description="Maximum allowable file size in megabytes")


class FileValidationResult(BaseModel):
    """Validation diagnostics and parsing summary for an individual uploaded file."""
    provided: bool = Field(description="Whether this file source was provided in the upload")
    filename: Optional[str] = Field(default=None, description="Original filename metadata")
    total_raw_records: Optional[int] = Field(default=None, description="Total raw input lines or items parsed")
    valid_records: Optional[int] = Field(default=None, description="Count of valid normalized domain records / communication aggregates")
    skipped_records: Optional[int] = Field(default=None, description="Count of skipped or malformed records")
    duplicate_records: Optional[int] = Field(default=None, description="Count of duplicate records identified")
    warning_counts: Dict[str, int] = Field(default_factory=dict, description="Categorized warning counts")
    sample_errors: List[str] = Field(default_factory=list, description="Bounded sample error descriptions")


class ImportValidationResponse(BaseModel):
    """Stateless validation response comparing uploaded data against ingestion rules."""
    valid: bool = Field(description="Overall validity of the provided upload dataset")
    can_import: bool = Field(description="Whether the dataset satisfies requirements for workspace replacement")
    traffic: FileValidationResult = Field(description="Validation results for network traffic dataset")
    alerts: FileValidationResult = Field(description="Validation results for security alerts dataset")
    message: str = Field(description="Summary message describing validation outcome")


class ImportCapabilities(BaseModel):
    """Available analysis capabilities derived from the imported source datasets."""
    network_topology: bool = Field(description="Whether network topology visualization is available")
    ip_investigation: bool = Field(description="Whether IP address context investigation is available")
    communication_paths: bool = Field(description="Whether path exploration analysis is applicable")
    alert_facts: bool = Field(description="Whether security alert facts are present")
    traffic_alert_correlations: bool = Field(description="Whether traffic/alert correlation analysis is applicable")


class ImportResultResponse(BaseModel):
    """Atomic workspace replacement result."""
    success: bool = Field(description="Whether the active workspace was successfully replaced")
    workspace_replaced: bool = Field(description="Confirmation that previous workspace data was cleared and replaced")
    traffic_records_persisted: int = Field(description="Count of normalized traffic records / communication aggregates persisted")
    alert_facts_persisted: int = Field(description="Count of AlertFact nodes persisted")
    capabilities: ImportCapabilities = Field(description="Active analysis capabilities in the new workspace")
    message: str = Field(description="Human-readable result summary")
