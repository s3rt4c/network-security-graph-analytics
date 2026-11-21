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
from decimal import Decimal, InvalidOperation
from enum import Enum
import hashlib
import ipaddress
import json
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from src.ingestion.v2_models import format_canonical_decimal, scoped_ip_id

EVIDENCE_VERSION = "v1"
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_ALERT_SOURCE_TYPE = "suricata"
_FLOW_SOURCE_TYPE = "zeek"


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


def _exact_decimal_epoch_to_ns(epoch: Optional[Decimal]) -> Optional[int]:
    """Losslessly convert a non-negative finite Decimal epoch to signed int64 ns, or None.

    Mirrors repository.decimal_epoch_to_ns without importing Neo4j persistence modules:
    returns None if any nonzero fractional digit exists beyond 9 decimal places or if
    the nanosecond value exceeds signed 64-bit integer bounds.
    """
    if epoch is None:
        return None
    if isinstance(epoch, bool) or not isinstance(epoch, Decimal):
        raise ValueError(f"epoch must be a finite non-negative Decimal or None, got {epoch!r}")
    if epoch.is_nan() or epoch.is_infinite() or epoch < 0:
        raise ValueError(f"epoch must be a finite non-negative Decimal or None, got {epoch!r}")
    sign, digits, exp = epoch.as_tuple()
    if not isinstance(exp, int):
        return None
    if not digits or all(d == 0 for d in digits):
        return 0
    if sign:
        return None
    digit_str = "".join(str(d) for d in digits).lstrip("0")
    stripped = digit_str.rstrip("0")
    trailing_zeros = len(digit_str) - len(stripped)
    eff_ns_exp = exp + trailing_zeros + 9
    if eff_ns_exp < 0 or eff_ns_exp >= 19 or (len(stripped) + eff_ns_exp) > 19:
        return None
    ns_int = int(stripped) * (10 ** eff_ns_exp)
    if ns_int < _INT64_MIN or ns_int > _INT64_MAX:
        return None
    return ns_int


def _parse_required_str(raw: Any, field_name: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{field_name} must be a non-empty string, got {raw!r}")
    return raw.strip()


def _parse_optional_str(raw: Any, field_name: str) -> Optional[str]:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string or None, got {raw!r}")
    cleaned = raw.strip()
    return cleaned if cleaned else None


def _parse_allow_empty_str(raw: Any, field_name: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string, got {raw!r}")
    return raw.strip()


def _parse_routing_domain(raw: Any, field_name: str) -> str:
    domain = _parse_required_str(raw, field_name).lower()
    if "#" in domain:
        raise ValueError(f"{field_name} cannot contain '#': {domain!r}")
    return domain


def _parse_expected_source_type(raw: Any, expected: str, field_name: str) -> str:
    norm = _parse_required_str(raw, field_name).lower()
    if norm != expected:
        raise ValueError(
            f"{field_name} must be {expected!r} for Zeek-Suricata correlation, got {raw!r}"
        )
    return norm


def _parse_optional_port(raw: Any, field_name: str) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or not (0 <= raw <= 65535):
        raise ValueError(f"{field_name} must be an int in 0..65535 or None, got {raw!r}")
    return raw


def _parse_optional_epoch_decimal(
    raw: Any,
    field_name: str,
    *,
    allow_str_or_int: bool = True,
) -> Optional[Decimal]:
    """Validate an optional authoritative non-negative finite Decimal epoch without float coercion."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} cannot be a bool: {raw!r}")
    if isinstance(raw, float):
        raise ValueError(
            f"{field_name} cannot be a float (authoritative timestamps must be exact Decimal/str): {raw!r}"
        )
    if isinstance(raw, Decimal):
        val = raw
    elif allow_str_or_int and isinstance(raw, int):
        val = Decimal(raw)
    elif allow_str_or_int and isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            return None
        try:
            val = Decimal(cleaned)
        except InvalidOperation as exc:
            raise ValueError(f"{field_name} is not a valid Decimal string: {raw!r}") from exc
    else:
        expected_types = (
            "Decimal, int, decimal str, or None" if allow_str_or_int else "Decimal or None"
        )
        raise ValueError(f"{field_name} must be {expected_types}, got {type(raw).__name__}")

    if val.is_nan() or val.is_infinite() or val < 0:
        raise ValueError(f"{field_name} must be a finite non-negative Decimal, got {raw!r}")
    format_canonical_decimal(val)
    return val


def _validate_epoch_ns(
    raw_ns: Any,
    epoch_decimal: Optional[Decimal],
    field_name: str,
) -> Optional[int]:
    """Validate that an optional nanosecond index field exactly matches its Decimal epoch."""
    if raw_ns is not None and (isinstance(raw_ns, bool) or not isinstance(raw_ns, int)):
        raise ValueError(f"{field_name} must be int or None, got {raw_ns!r}")
    expected_ns = _exact_decimal_epoch_to_ns(epoch_decimal)
    if raw_ns != expected_ns:
        raise ValueError(
            f"Inconsistent {field_name}: got {raw_ns!r}, expected {expected_ns!r} "
            f"for exact decimal epoch {epoch_decimal!r}"
        )
    return expected_ns


def _validate_ip_version(raw_version: Any, expected_version: int, field_name: str) -> int:
    if isinstance(raw_version, bool) or not isinstance(raw_version, int) or raw_version not in (4, 6):
        raise ValueError(f"{field_name} must be 4 or 6, got {raw_version!r}")
    if raw_version != expected_version:
        raise ValueError(
            f"Inconsistent {field_name}: got IPv{raw_version}, expected IPv{expected_version}"
        )
    return raw_version


def _parse_ip_pair(
    raw_src: Any,
    raw_dst: Any,
    routing_domain_id: str,
    raw_src_scoped: Any,
    raw_dst_scoped: Any,
    label: str,
    *,
    require_src_scoped: bool = False,
    require_dst_scoped: bool = False,
    raw_ip_version: Any = None,
    require_ip_version: bool = False,
) -> Tuple[str, str, int, str, str]:
    src_str = _parse_required_str(raw_src, f"{label}.src_ip")
    dst_str = _parse_required_str(raw_dst, f"{label}.dst_ip")
    try:
        src_obj = ipaddress.ip_address(src_str)
    except ValueError as exc:
        raise ValueError(f"Invalid {label}.src_ip {src_str!r}: {exc}") from exc
    try:
        dst_obj = ipaddress.ip_address(dst_str)
    except ValueError as exc:
        raise ValueError(f"Invalid {label}.dst_ip {dst_str!r}: {exc}") from exc
    if src_obj.version != dst_obj.version:
        raise ValueError(
            f"{label} IP version mismatch: IPv{src_obj.version} -> IPv{dst_obj.version}"
        )

    if require_ip_version or raw_ip_version is not None:
        _validate_ip_version(raw_ip_version, src_obj.version, f"{label}.ip_version")

    canon_src = str(src_obj)
    canon_dst = str(dst_obj)
    expected_src_scoped = scoped_ip_id(routing_domain_id, canon_src)
    expected_dst_scoped = scoped_ip_id(routing_domain_id, canon_dst)

    if require_src_scoped or raw_src_scoped is not None:
        src_scoped = _parse_required_str(raw_src_scoped, f"{label}.src_scoped_id")
        if src_scoped != expected_src_scoped:
            raise ValueError(
                f"Inconsistent {label}.src_scoped_id {src_scoped!r} "
                f"(expected {expected_src_scoped!r} for domain={routing_domain_id!r}, ip={canon_src!r})"
            )
    else:
        src_scoped = expected_src_scoped

    if require_dst_scoped or raw_dst_scoped is not None:
        dst_scoped = _parse_required_str(raw_dst_scoped, f"{label}.dst_scoped_id")
        if dst_scoped != expected_dst_scoped:
            raise ValueError(
                f"Inconsistent {label}.dst_scoped_id {dst_scoped!r} "
                f"(expected {expected_dst_scoped!r} for domain={routing_domain_id!r}, ip={canon_dst!r})"
            )
    else:
        dst_scoped = expected_dst_scoped

    return canon_src, canon_dst, src_obj.version, src_scoped, dst_scoped


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

    def __post_init__(self) -> None:
        event_id = _parse_required_str(self.event_id, "alert.event_id")
        domain = _parse_routing_domain(self.routing_domain_id, "alert.routing_domain_id")
        sensor = _parse_required_str(self.sensor_id, "alert.sensor_id").lower()
        src_ip, dst_ip, ip_ver, src_scoped, dst_scoped = _parse_ip_pair(
            self.src_ip,
            self.dst_ip,
            domain,
            self.src_scoped_id,
            self.dst_scoped_id,
            "alert",
            require_src_scoped=True,
            require_dst_scoped=True,
            raw_ip_version=self.ip_version,
            require_ip_version=True,
        )
        proto_opt = _parse_optional_str(self.protocol, "alert.protocol")
        protocol = proto_opt.upper() if proto_opt is not None else None
        src_port = _parse_optional_port(self.src_port, "alert.src_port")
        dst_port = _parse_optional_port(self.dst_port, "alert.dst_port")
        community_id = _parse_optional_str(self.community_id, "alert.community_id")
        timestamp_source = _parse_allow_empty_str(self.timestamp_source, "alert.timestamp_source")
        epoch_dec = _parse_optional_epoch_decimal(
            self.timestamp_epoch_decimal,
            "alert.timestamp_epoch_decimal",
            allow_str_or_int=False,
        )
        epoch_ns = _validate_epoch_ns(
            self.timestamp_epoch_ns, epoch_dec, "alert.timestamp_epoch_ns"
        )
        source_type = _parse_expected_source_type(
            self.source_type, _ALERT_SOURCE_TYPE, "alert.source_type"
        )
        source_provenance = _parse_optional_str(self.source_provenance, "alert.source_provenance")
        log_source_id = _parse_optional_str(self.log_source_id, "alert.log_source_id")
        alert_def_id = _parse_optional_str(self.alert_definition_id, "alert.alert_definition_id")

        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "routing_domain_id", domain)
        object.__setattr__(self, "sensor_id", sensor)
        object.__setattr__(self, "src_ip", src_ip)
        object.__setattr__(self, "dst_ip", dst_ip)
        object.__setattr__(self, "ip_version", ip_ver)
        object.__setattr__(self, "src_scoped_id", src_scoped)
        object.__setattr__(self, "dst_scoped_id", dst_scoped)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "src_port", src_port)
        object.__setattr__(self, "dst_port", dst_port)
        object.__setattr__(self, "community_id", community_id)
        object.__setattr__(self, "timestamp_source", timestamp_source)
        object.__setattr__(self, "timestamp_epoch_decimal", epoch_dec)
        object.__setattr__(self, "timestamp_epoch_ns", epoch_ns)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "source_provenance", source_provenance)
        object.__setattr__(self, "log_source_id", log_source_id)
        object.__setattr__(self, "alert_definition_id", alert_def_id)


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

    def __post_init__(self) -> None:
        observation_id = _parse_required_str(self.observation_id, "flow.observation_id")
        zeek_uid = _parse_allow_empty_str(self.zeek_uid, "flow.zeek_uid")
        domain = _parse_routing_domain(self.routing_domain_id, "flow.routing_domain_id")
        sensor = _parse_required_str(self.sensor_id, "flow.sensor_id").lower()
        src_ip, dst_ip, ip_ver, src_scoped, dst_scoped = _parse_ip_pair(
            self.src_ip,
            self.dst_ip,
            domain,
            self.src_scoped_id,
            self.dst_scoped_id,
            "flow",
            require_src_scoped=True,
            require_dst_scoped=True,
            raw_ip_version=self.ip_version,
            require_ip_version=True,
        )
        protocol = _parse_required_str(self.protocol, "flow.protocol").upper()
        src_port = _parse_optional_port(self.src_port, "flow.src_port")
        dst_port = _parse_optional_port(self.dst_port, "flow.dst_port")
        community_id = _parse_optional_str(self.community_id, "flow.community_id")
        start_ts = _parse_allow_empty_str(self.start_ts, "flow.start_ts")
        start_dec = _parse_optional_epoch_decimal(
            self.start_epoch_decimal,
            "flow.start_epoch_decimal",
            allow_str_or_int=False,
        )
        end_dec = _parse_optional_epoch_decimal(
            self.end_epoch_decimal,
            "flow.end_epoch_decimal",
            allow_str_or_int=False,
        )
        dur_dec = _parse_optional_epoch_decimal(
            self.duration_decimal,
            "flow.duration_decimal",
            allow_str_or_int=False,
        )
        start_ns = _validate_epoch_ns(self.start_epoch_ns, start_dec, "flow.start_epoch_ns")
        end_ns = _validate_epoch_ns(self.end_epoch_ns, end_dec, "flow.end_epoch_ns")
        source_type = _parse_expected_source_type(
            self.source_type, _FLOW_SOURCE_TYPE, "flow.source_type"
        )
        source_provenance = _parse_optional_str(self.source_provenance, "flow.source_provenance")

        object.__setattr__(self, "observation_id", observation_id)
        object.__setattr__(self, "zeek_uid", zeek_uid)
        object.__setattr__(self, "routing_domain_id", domain)
        object.__setattr__(self, "sensor_id", sensor)
        object.__setattr__(self, "src_ip", src_ip)
        object.__setattr__(self, "dst_ip", dst_ip)
        object.__setattr__(self, "ip_version", ip_ver)
        object.__setattr__(self, "src_scoped_id", src_scoped)
        object.__setattr__(self, "dst_scoped_id", dst_scoped)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "src_port", src_port)
        object.__setattr__(self, "dst_port", dst_port)
        object.__setattr__(self, "community_id", community_id)
        object.__setattr__(self, "start_ts", start_ts)
        object.__setattr__(self, "start_epoch_decimal", start_dec)
        object.__setattr__(self, "end_epoch_decimal", end_dec)
        object.__setattr__(self, "duration_decimal", dur_dec)
        object.__setattr__(self, "start_epoch_ns", start_ns)
        object.__setattr__(self, "end_epoch_ns", end_ns)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "source_provenance", source_provenance)


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
