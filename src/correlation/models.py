"""
Phase 4A Correlation Domain Models & Policy Contracts (Neo4j-Independent).

Defines immutable policy configurations, candidate completeness signals,
normalized alert/flow snapshots, per-candidate evidence objects, and
deterministic correlation decisions for conservative Zeek–Suricata correlation.

Guarantees:
- Pure Python, zero Neo4j or database dependency.
- Python 3.10+ compatible (`(str, Enum)` rather than 3.11+ `StrEnum`).
- Exact Decimal tolerances (zero float coercion, context-independent canonicalization).
- Safe-by-default policy: zero pre/post temporal tolerances, explicit opt-in
  required for tolerance-based or missing-Zeek-end automatic STRONG promotion.
- Deterministic SHA-256 `policy_fingerprint` over all active policy parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
import hashlib
import json
from typing import Dict, Iterable, Mapping, Optional, Tuple

from src.ingestion.v2_models import format_canonical_decimal

EVIDENCE_VERSION = "v1"


class CorrelationStatus(str, Enum):
    """Alert-level correlation decision outcome."""

    STRONG = "STRONG"
    AMBIGUOUS = "AMBIGUOUS"
    INSUFFICIENT = "INSUFFICIENT"
    REJECTED = "REJECTED"


class CandidateStrength(str, Enum):
    """Per-candidate evidence evaluation outcome."""

    STRONG = "STRONG"
    INSUFFICIENT = "INSUFFICIENT"
    REJECTED = "REJECTED"


class CandidateCompleteness(str, Enum):
    """Completeness guarantee of the supplied candidate FlowObservation set."""

    COMPLETE = "COMPLETE"
    TRUNCATED = "TRUNCATED"
    RETRIEVAL_ERROR = "RETRIEVAL_ERROR"
    UNKNOWN = "UNKNOWN"


class SensorPolicyMode(str, Enum):
    """Configurable cross-sensor pairing policy (never invents global topology)."""

    EXPLICIT_PAIRS = "EXPLICIT_PAIRS"
    SAME_SENSOR_ID = "SAME_SENSOR_ID"
    ANY_IN_DOMAIN = "ANY_IN_DOMAIN"


class CommunityIdSeedPolicy(str, Enum):
    """Policy governing Community ID mismatch handling across Zeek and Suricata."""

    STRICT_SAME_SEED = "STRICT_SAME_SEED"
    VERIFY_SEED_PAIR = "VERIFY_SEED_PAIR"
    ALLOW_UNVERIFIED_TUPLE_FALLBACK = "ALLOW_UNVERIFIED_TUPLE_FALLBACK"


class TupleOrientation(str, Enum):
    """Observed endpoint orientation between Suricata alert and Zeek flow."""

    FORWARD = "FORWARD"
    REVERSE = "REVERSE"
    SYMMETRIC = "SYMMETRIC"
    MISMATCH = "MISMATCH"


class TupleCompleteness(str, Enum):
    """Completeness classification of matched network tuple fields."""

    COMPLETE_5TUPLE = "COMPLETE_5TUPLE"
    ICMP_VIA_CID = "ICMP_VIA_CID"
    PARTIAL_PORTS = "PARTIAL_PORTS"
    MISSING_PROTOCOL = "MISSING_PROTOCOL"
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    INCOMPATIBLE = "INCOMPATIBLE"


class ProtocolStatus(str, Enum):
    """Protocol comparison status between Suricata alert and Zeek flow."""

    EXACT_MATCH = "EXACT_MATCH"
    IPV6_ICMP_ALIAS_MATCH = "IPV6_ICMP_ALIAS_MATCH"
    MISSING = "MISSING"
    UNSUPPORTED = "UNSUPPORTED"
    CONFLICT = "CONFLICT"


class CommunityIdStatus(str, Enum):
    """Community ID consistency classification."""

    MATCH = "MATCH"
    VERIFIED_SEED_OFFSET = "VERIFIED_SEED_OFFSET"
    MISSING_ALERT = "MISSING_ALERT"
    MISSING_FLOW = "MISSING_FLOW"
    MISSING_BOTH = "MISSING_BOTH"
    CONFLICT = "CONFLICT"
    MISMATCH_SEED_UNVERIFIED = "MISMATCH_SEED_UNVERIFIED"


class TemporalRelation(str, Enum):
    """Exact Decimal temporal relationship between alert timestamp and Zeek flow."""

    WITHIN_INTERVAL = "WITHIN_INTERVAL"
    WITHIN_PRE_TOLERANCE = "WITHIN_PRE_TOLERANCE"
    WITHIN_POST_TOLERANCE = "WITHIN_POST_TOLERANCE"
    NEAR_START_NO_END = "NEAR_START_NO_END"
    OUTSIDE_WINDOW = "OUTSIDE_WINDOW"
    MISSING_ALERT_EPOCH = "MISSING_ALERT_EPOCH"
    MISSING_FLOW_START_EPOCH = "MISSING_FLOW_START_EPOCH"
    INVALID_INTERVAL = "INVALID_INTERVAL"


class SensorPolicyStatus(str, Enum):
    """Result of evaluating (alert.sensor_id, flow.sensor_id) against SensorPairingPolicy."""

    MATCHED_EXPLICIT_PAIR = "MATCHED_EXPLICIT_PAIR"
    MATCHED_SAME_SENSOR = "MATCHED_SAME_SENSOR"
    ALLOWED_ANY_IN_DOMAIN = "ALLOWED_ANY_IN_DOMAIN"
    DISALLOWED = "DISALLOWED"


def _validate_strict_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a bool, got {value!r}")
    return value


def _validate_non_negative_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, Decimal):
        raise ValueError(f"{name} must be a finite non-negative Decimal, got {value!r}")
    if value.is_nan() or value.is_infinite() or value < 0:
        raise ValueError(f"{name} must be a finite non-negative Decimal, got {value!r}")
    format_canonical_decimal(value)
    return value


def _validate_finite_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, Decimal):
        raise ValueError(f"{name} must be a finite Decimal, got {value!r}")
    if value.is_nan() or value.is_infinite():
        raise ValueError(f"{name} must be a finite Decimal, got {value!r}")
    format_canonical_decimal(value)
    return value


def _normalize_sensor_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip().lower()


def _validate_uint16_seed(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 65535):
        raise ValueError(f"{name} must be an integer in 0..65535, got {value!r}")
    return value


@dataclass(frozen=True)
class SensorPairingPolicy:
    """Immutable cross-sensor pairing policy for Suricata -> Zeek evaluation.

    `explicit_pairs` maps normalized `suricata_sensor_id` -> sorted tuple of
    allowed normalized `zeek_sensor_id` values (only valid in `EXPLICIT_PAIRS` mode).

    Optional `pair_clock_offsets` stores `(suricata_sensor_id, zeek_sensor_id, offset_sec)`
    where `adjusted_alert_epoch = alert_epoch + offset_sec` shifts Suricata's clock into
    the Zeek sensor's reference frame when an operator has measured constant skew.
    """

    mode: SensorPolicyMode = SensorPolicyMode.ANY_IN_DOMAIN
    explicit_pairs: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    pair_clock_offsets: Tuple[Tuple[str, str, Decimal], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.mode, SensorPolicyMode):
            raise ValueError(f"SensorPairingPolicy.mode must be a SensorPolicyMode, got {self.mode!r}")

        norm_pairs: Dict[str, Tuple[str, ...]] = {}
        for item in self.explicit_pairs:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError(f"explicit_pairs entries must be (suricata_sensor, zeek_sensors) tuples, got {item!r}")
            s_id = _normalize_sensor_id(item[0], "suricata_sensor_id")
            z_raw = item[1]
            if isinstance(z_raw, (str, bytes)) or not isinstance(z_raw, Iterable):
                raise ValueError(f"zeek_sensors for '{s_id}' must be an iterable of sensor IDs")
            z_list = sorted({_normalize_sensor_id(z, "zeek_sensor_id") for z in z_raw})
            if not z_list:
                raise ValueError(f"explicit_pairs entry for '{s_id}' must include at least one zeek sensor ID")
            if s_id in norm_pairs:
                raise ValueError(f"Duplicate suricata_sensor_id '{s_id}' in explicit_pairs")
            norm_pairs[s_id] = tuple(z_list)

        if self.mode == SensorPolicyMode.EXPLICIT_PAIRS and not norm_pairs:
            raise ValueError("SensorPairingPolicy with mode=EXPLICIT_PAIRS requires at least one sensor pair")
        if self.mode != SensorPolicyMode.EXPLICIT_PAIRS and norm_pairs:
            raise ValueError(
                f"explicit_pairs cannot be supplied when mode={self.mode.value}; use mode=EXPLICIT_PAIRS"
            )

        canonical_pairs = tuple(sorted(norm_pairs.items(), key=lambda kv: kv[0]))
        object.__setattr__(self, "explicit_pairs", canonical_pairs)

        norm_offsets: Dict[Tuple[str, str], Decimal] = {}
        for item in self.pair_clock_offsets:
            if not isinstance(item, tuple) or len(item) != 3:
                raise ValueError(
                    f"pair_clock_offsets entries must be (suricata_sensor, zeek_sensor, offset_sec), got {item!r}"
                )
            s_id = _normalize_sensor_id(item[0], "suricata_sensor_id")
            z_id = _normalize_sensor_id(item[1], "zeek_sensor_id")
            offset = _validate_finite_decimal(item[2], f"clock_offset({s_id},{z_id})")
            if (s_id, z_id) in norm_offsets:
                raise ValueError(f"Duplicate clock offset for pair ({s_id!r}, {z_id!r})")
            norm_offsets[(s_id, z_id)] = offset

        canonical_offsets = tuple(
            (k[0], k[1], v) for k, v in sorted(norm_offsets.items(), key=lambda kv: kv[0])
        )
        object.__setattr__(self, "pair_clock_offsets", canonical_offsets)

    @classmethod
    def any_in_domain(
        cls,
        pair_clock_offsets: Optional[Mapping[Tuple[str, str], Decimal]] = None,
    ) -> "SensorPairingPolicy":
        offsets = tuple((k[0], k[1], v) for k, v in (pair_clock_offsets or {}).items())
        return cls(mode=SensorPolicyMode.ANY_IN_DOMAIN, pair_clock_offsets=offsets)

    @classmethod
    def same_sensor_id(
        cls,
        pair_clock_offsets: Optional[Mapping[Tuple[str, str], Decimal]] = None,
    ) -> "SensorPairingPolicy":
        offsets = tuple((k[0], k[1], v) for k, v in (pair_clock_offsets or {}).items())
        return cls(mode=SensorPolicyMode.SAME_SENSOR_ID, pair_clock_offsets=offsets)

    @classmethod
    def from_explicit_pairs(
        cls,
        pairs: Mapping[str, Iterable[str]],
        pair_clock_offsets: Optional[Mapping[Tuple[str, str], Decimal]] = None,
    ) -> "SensorPairingPolicy":
        if not isinstance(pairs, Mapping) or not pairs:
            raise ValueError("pairs must be a non-empty mapping of suricata_sensor_id -> iterable of zeek_sensor_ids")
        pair_tuples = tuple((k, tuple(v) if not isinstance(v, (str, bytes)) else (v,)) for k, v in pairs.items())
        offsets = tuple((k[0], k[1], v) for k, v in (pair_clock_offsets or {}).items())
        return cls(
            mode=SensorPolicyMode.EXPLICIT_PAIRS,
            explicit_pairs=pair_tuples,
            pair_clock_offsets=offsets,
        )

    def evaluate_pair(self, suricata_sensor_id: str, zeek_sensor_id: str) -> SensorPolicyStatus:
        s_norm = _normalize_sensor_id(suricata_sensor_id, "suricata_sensor_id")
        z_norm = _normalize_sensor_id(zeek_sensor_id, "zeek_sensor_id")
        if self.mode == SensorPolicyMode.ANY_IN_DOMAIN:
            return SensorPolicyStatus.ALLOWED_ANY_IN_DOMAIN
        if self.mode == SensorPolicyMode.SAME_SENSOR_ID:
            return (
                SensorPolicyStatus.MATCHED_SAME_SENSOR
                if s_norm == z_norm
                else SensorPolicyStatus.DISALLOWED
            )
        for allowed_s, allowed_z in self.explicit_pairs:
            if allowed_s == s_norm:
                return (
                    SensorPolicyStatus.MATCHED_EXPLICIT_PAIR
                    if z_norm in allowed_z
                    else SensorPolicyStatus.DISALLOWED
                )
        return SensorPolicyStatus.DISALLOWED

    def get_clock_offset(self, suricata_sensor_id: str, zeek_sensor_id: str) -> Decimal:
        s_norm = _normalize_sensor_id(suricata_sensor_id, "suricata_sensor_id")
        z_norm = _normalize_sensor_id(zeek_sensor_id, "zeek_sensor_id")
        for s_id, z_id, offset in self.pair_clock_offsets:
            if s_id == s_norm and z_id == z_norm:
                return offset
        return Decimal("0")

    def to_canonical_dict(self) -> Dict[str, object]:
        return {
            "mode": self.mode.value,
            "explicit_pairs": {s: list(zs) for s, zs in self.explicit_pairs},
            "pair_clock_offsets": {
                f"{s}|{z}": format_canonical_decimal(off) for s, z, off in self.pair_clock_offsets
            },
        }


@dataclass(frozen=True)
class CorrelationPolicy:
    """Conservative, deterministic policy controlling Zeek–Suricata correlation decisions.

    Safe defaults:
    - `pre_start_tolerance_sec = Decimal("0")`
    - `post_end_tolerance_sec = Decimal("0")`
    - `point_observation_post_tolerance_sec = Decimal("0")`
    - `allow_tolerance_match = False`
    - `allow_missing_zeek_end = False`
    - `community_id_seed_policy = CommunityIdSeedPolicy.STRICT_SAME_SEED`
    """

    evidence_version: str = EVIDENCE_VERSION
    pre_start_tolerance_sec: Decimal = Decimal("0")
    post_end_tolerance_sec: Decimal = Decimal("0")
    point_observation_post_tolerance_sec: Decimal = Decimal("0")
    allow_tolerance_match: bool = False
    allow_missing_zeek_end: bool = False
    require_community_id: bool = False
    community_id_seed_policy: CommunityIdSeedPolicy = CommunityIdSeedPolicy.STRICT_SAME_SEED
    zeek_community_id_seed: Optional[int] = None
    suricata_community_id_seed: Optional[int] = None
    sensor_policy: SensorPairingPolicy = field(default_factory=SensorPairingPolicy.any_in_domain)
    allow_default_domain: bool = True
    candidate_cap: Optional[int] = 200
    max_evidences_returned: int = 50

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_version, str) or not self.evidence_version.strip():
            raise ValueError("evidence_version must be a non-empty string")
        object.__setattr__(self, "evidence_version", self.evidence_version.strip())

        _validate_non_negative_decimal(self.pre_start_tolerance_sec, "pre_start_tolerance_sec")
        _validate_non_negative_decimal(self.post_end_tolerance_sec, "post_end_tolerance_sec")
        _validate_non_negative_decimal(
            self.point_observation_post_tolerance_sec, "point_observation_post_tolerance_sec"
        )

        _validate_strict_bool(self.allow_tolerance_match, "allow_tolerance_match")
        _validate_strict_bool(self.allow_missing_zeek_end, "allow_missing_zeek_end")
        _validate_strict_bool(self.require_community_id, "require_community_id")
        _validate_strict_bool(self.allow_default_domain, "allow_default_domain")

        if not isinstance(self.community_id_seed_policy, CommunityIdSeedPolicy):
            raise ValueError(
                f"community_id_seed_policy must be a CommunityIdSeedPolicy, got {self.community_id_seed_policy!r}"
            )

        if self.zeek_community_id_seed is not None:
            _validate_uint16_seed(self.zeek_community_id_seed, "zeek_community_id_seed")
        if self.suricata_community_id_seed is not None:
            _validate_uint16_seed(self.suricata_community_id_seed, "suricata_community_id_seed")

        if self.community_id_seed_policy == CommunityIdSeedPolicy.VERIFY_SEED_PAIR:
            if self.zeek_community_id_seed is None or self.suricata_community_id_seed is None:
                raise ValueError(
                    "VERIFY_SEED_PAIR requires explicit non-None zeek_community_id_seed and suricata_community_id_seed"
                )
        else:
            if self.zeek_community_id_seed is not None or self.suricata_community_id_seed is not None:
                raise ValueError(
                    f"Explicit community_id seeds are only valid with VERIFY_SEED_PAIR, "
                    f"got community_id_seed_policy={self.community_id_seed_policy.value}"
                )

        if not isinstance(self.sensor_policy, SensorPairingPolicy):
            raise ValueError(f"sensor_policy must be a SensorPairingPolicy, got {self.sensor_policy!r}")

        if self.candidate_cap is not None:
            if isinstance(self.candidate_cap, bool) or not isinstance(self.candidate_cap, int) or self.candidate_cap < 1:
                raise ValueError(f"candidate_cap must be a positive integer or None, got {self.candidate_cap!r}")

        if (
            isinstance(self.max_evidences_returned, bool)
            or not isinstance(self.max_evidences_returned, int)
            or self.max_evidences_returned < 1
        ):
            raise ValueError(
                f"max_evidences_returned must be a positive integer, got {self.max_evidences_returned!r}"
            )

    @property
    def policy_fingerprint(self) -> str:
        """Deterministic SHA-256 digest capturing all active correlation policy settings."""
        canonical = {
            "evidence_version": self.evidence_version,
            "pre_start_tolerance_sec": format_canonical_decimal(self.pre_start_tolerance_sec),
            "post_end_tolerance_sec": format_canonical_decimal(self.post_end_tolerance_sec),
            "point_observation_post_tolerance_sec": format_canonical_decimal(
                self.point_observation_post_tolerance_sec
            ),
            "allow_tolerance_match": self.allow_tolerance_match,
            "allow_missing_zeek_end": self.allow_missing_zeek_end,
            "require_community_id": self.require_community_id,
            "community_id_seed_policy": self.community_id_seed_policy.value,
            "zeek_community_id_seed": self.zeek_community_id_seed,
            "suricata_community_id_seed": self.suricata_community_id_seed,
            "sensor_policy": self.sensor_policy.to_canonical_dict(),
            "allow_default_domain": self.allow_default_domain,
            "candidate_cap": self.candidate_cap,
        }
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AlertSnapshot:
    """Normalized, Neo4j-independent Suricata alert representation for correlation."""

    event_id: str
    routing_domain_id: str
    sensor_id: str
    src_ip: str
    dst_ip: str
    ip_version: int
    src_scoped_id: str
    dst_scoped_id: str
    protocol: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    community_id: Optional[str]
    timestamp_source: str
    timestamp_epoch_decimal: Optional[Decimal]
    timestamp_epoch_ns: Optional[int]
    source_type: str = "suricata"
    source_provenance: Optional[str] = None
    log_source_id: Optional[str] = None
    alert_definition_id: Optional[str] = None


@dataclass(frozen=True)
class FlowSnapshot:
    """Normalized, Neo4j-independent Zeek flow representation for correlation."""

    observation_id: str
    zeek_uid: str
    routing_domain_id: str
    sensor_id: str
    src_ip: str
    dst_ip: str
    ip_version: int
    src_scoped_id: str
    dst_scoped_id: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    community_id: Optional[str]
    start_ts: str
    start_epoch_decimal: Optional[Decimal]
    end_epoch_decimal: Optional[Decimal]
    duration_decimal: Optional[Decimal]
    start_epoch_ns: Optional[int]
    end_epoch_ns: Optional[int]
    source_type: str = "zeek"
    source_provenance: Optional[str] = None


@dataclass(frozen=True)
class CorrelationCandidateEvidence:
    """Deterministic, auditable evidence record for one (AlertEvent, FlowObservation) pair."""

    observation_id: str
    zeek_uid: str
    zeek_sensor_id: str
    routing_domain_id: str
    domain_matched: bool
    sensor_policy_status: SensorPolicyStatus
    tuple_orientation: TupleOrientation
    tuple_completeness: TupleCompleteness
    protocol_status: ProtocolStatus
    community_id_status: CommunityIdStatus
    temporal_relation: TemporalRelation
    temporal_delta_decimal: Optional[str]
    used_decimal_fallback: bool
    strength: CandidateStrength
    reasons: Tuple[str, ...]

    @property
    def is_strong(self) -> bool:
        return self.strength == CandidateStrength.STRONG

    @property
    def is_plausible_rival(self) -> bool:
        return self.strength == CandidateStrength.INSUFFICIENT


@dataclass(frozen=True)
class CorrelationDecision:
    """Alert-level conservative correlation outcome and bounded evidence summary."""

    event_id: str
    status: CorrelationStatus
    selected_observation_id: Optional[str]
    auto_correlate_allowed: bool
    candidate_count_evaluated: int
    strong_candidate_ids: Tuple[str, ...]
    plausible_rival_ids: Tuple[str, ...]
    candidate_completeness: CandidateCompleteness
    candidate_cap_exceeded: bool
    decision_reasons: Tuple[str, ...]
    selected_evidence: Optional[CorrelationCandidateEvidence]
    candidate_evidences: Tuple[CorrelationCandidateEvidence, ...]
    policy_fingerprint: str
    evidence_version: str
