"""
Phase 4A Conservative Zeek–Suricata Correlation Engine (Pure Python, Neo4j-Independent).

Implements deterministic hard eligibility gates (G1–G7), exact Decimal temporal
comparison, Community ID policy evaluation, configurable sensor pairing, and
fail-closed ambiguity / candidate-completeness decision aggregation.

Key guarantees:
- Zero float arithmetic and zero lexicographic ISO timestamp comparison.
- Context-independent exact Decimal math via `add_exact_decimals` and `format_canonical_decimal`.
- Never filters out missing-CID flows when another candidate has a matching CID.
- Never promotes a candidate to STRONG when candidate completeness is not COMPLETE,
  when candidate_cap is exceeded, or when any plausible unresolved rival coexists.
- Never performs arbitrary tie-breaking or infers attacker/victim roles.
- Zero Neo4j, Cypher, or database imports.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import ipaddress
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from src.correlation.models import (
    AlertSnapshot,
    CandidateCompleteness,
    CandidateStrength,
    CommunityIdSeedPolicy,
    CommunityIdStatus,
    CorrelationCandidateEvidence,
    CorrelationDecision,
    CorrelationPolicy,
    CorrelationStatus,
    FlowSnapshot,
    ProtocolStatus,
    SensorPolicyStatus,
    TemporalRelation,
    TupleCompleteness,
    TupleOrientation,
)
from src.ingestion.community_id import compute_community_id
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    ZeekConnectionObservation,
    add_exact_decimals,
    format_canonical_decimal,
    scoped_ip_id,
)

AlertInput = Union[AlertSnapshot, SuricataAlertObservation, Mapping[str, Any]]
FlowInput = Union[FlowSnapshot, ZeekConnectionObservation, Mapping[str, Any]]

_PORT_PROTOCOLS = frozenset({"TCP", "UDP", "SCTP"})
_ICMP_PROTOCOLS = frozenset({"ICMP", "ICMP6"})
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def _subtract_exact_decimals(left: Decimal, right: Decimal) -> Decimal:
    """Compute exact `left - right` independent of active Decimal context."""
    # Decimal.copy_negate() flips the sign bit without rounding to getcontext().prec
    return add_exact_decimals(left, right.copy_negate())


def _exact_decimal_epoch_to_ns(epoch: Optional[Decimal]) -> Optional[int]:
    """Losslessly convert a non-negative finite Decimal epoch to signed int64 ns, or None.

    Mirrors repository.decimal_epoch_to_ns without importing Neo4j persistence modules:
    returns None if any nonzero fractional digit exists beyond 9 decimal places or if
    the nanosecond value exceeds signed 64-bit integer bounds.
    """
    if epoch is None:
        return None
    _, digits, exp = epoch.as_tuple()
    if not isinstance(exp, int):
        return None
    if not digits or all(d == 0 for d in digits):
        return 0
    digit_str = "".join(str(d) for d in digits).lstrip("0")
    stripped = digit_str.rstrip("0")
    trailing_zeros = len(digit_str) - len(stripped)
    eff_ns_exp = exp + trailing_zeros + 9
    if eff_ns_exp < 0 or eff_ns_exp >= 19:
        return None
    ns_int = int(stripped) * (10 ** eff_ns_exp)
    if ns_int < _INT64_MIN or ns_int > _INT64_MAX:
        return None
    return ns_int


def _parse_optional_epoch_decimal(raw: Any, field_name: str) -> Optional[Decimal]:
    """Parse an optional authoritative non-negative finite Decimal epoch without float coercion."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} cannot be a bool: {raw!r}")
    if isinstance(raw, float):
        raise ValueError(f"{field_name} cannot be a float (authoritative timestamps must be exact Decimal/str): {raw!r}")
    if isinstance(raw, Decimal):
        val = raw
    elif isinstance(raw, int):
        val = Decimal(raw)
    elif isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            return None
        try:
            val = Decimal(cleaned)
        except InvalidOperation as exc:
            raise ValueError(f"{field_name} is not a valid Decimal string: {raw!r}") from exc
    else:
        raise ValueError(f"{field_name} must be Decimal, int, decimal str, or None, got {type(raw).__name__}")

    if val.is_nan() or val.is_infinite() or val < 0:
        raise ValueError(f"{field_name} must be a finite non-negative Decimal, got {raw!r}")
    format_canonical_decimal(val)
    return val


def _parse_optional_port(raw: Any, field_name: str) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or not (0 <= raw <= 65535):
        raise ValueError(f"{field_name} must be an int in 0..65535 or None, got {raw!r}")
    return raw


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


def _parse_ip_pair(
    raw_src: Any,
    raw_dst: Any,
    routing_domain_id: str,
    raw_src_scoped: Any,
    raw_dst_scoped: Any,
    label: str,
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

    canon_src = str(src_obj)
    canon_dst = str(dst_obj)
    expected_src_scoped = scoped_ip_id(routing_domain_id, canon_src)
    expected_dst_scoped = scoped_ip_id(routing_domain_id, canon_dst)

    if raw_src_scoped is not None:
        src_scoped = _parse_required_str(raw_src_scoped, f"{label}.src_scoped_id")
        if src_scoped != expected_src_scoped:
            raise ValueError(
                f"Inconsistent {label}.src_scoped_id {src_scoped!r} "
                f"(expected {expected_src_scoped!r} for domain={routing_domain_id!r}, ip={canon_src!r})"
            )
    else:
        src_scoped = expected_src_scoped

    if raw_dst_scoped is not None:
        dst_scoped = _parse_required_str(raw_dst_scoped, f"{label}.dst_scoped_id")
        if dst_scoped != expected_dst_scoped:
            raise ValueError(
                f"Inconsistent {label}.dst_scoped_id {dst_scoped!r} "
                f"(expected {expected_dst_scoped!r} for domain={routing_domain_id!r}, ip={canon_dst!r})"
            )
    else:
        dst_scoped = expected_dst_scoped

    return canon_src, canon_dst, src_obj.version, src_scoped, dst_scoped


def alert_to_snapshot(alert: AlertInput) -> AlertSnapshot:
    """Normalize a SuricataAlertObservation, read-repository dict, or AlertSnapshot."""
    if isinstance(alert, AlertSnapshot):
        return alert

    if isinstance(alert, SuricataAlertObservation):
        domain = _parse_required_str(alert.routing_domain_id, "alert.routing_domain_id").lower()
        if "#" in domain:
            raise ValueError(f"alert.routing_domain_id cannot contain '#': {domain!r}")
        sensor = _parse_required_str(alert.sensor_id, "alert.sensor_id").lower()
        src_ip, dst_ip, ip_ver, src_scoped, dst_scoped = _parse_ip_pair(
            alert.src_ip,
            alert.dst_ip,
            domain,
            alert.src_scoped_id,
            alert.dst_scoped_id,
            "alert",
        )
        proto_opt = _parse_optional_str(alert.protocol, "alert.protocol")
        epoch_dec = _parse_optional_epoch_decimal(
            alert.timestamp_epoch_decimal, "alert.timestamp_epoch_decimal"
        )
        return AlertSnapshot(
            event_id=_parse_required_str(alert.event_id, "alert.event_id"),
            routing_domain_id=domain,
            sensor_id=sensor,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_ver,
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            protocol=proto_opt.upper() if proto_opt is not None else None,
            src_port=_parse_optional_port(alert.src_port, "alert.src_port"),
            dst_port=_parse_optional_port(alert.dst_port, "alert.dst_port"),
            community_id=_parse_optional_str(alert.community_id, "alert.community_id"),
            timestamp_source=_parse_required_str(alert.timestamp_source, "alert.timestamp_source"),
            timestamp_epoch_decimal=epoch_dec,
            timestamp_epoch_ns=_exact_decimal_epoch_to_ns(epoch_dec),
            source_type=_parse_required_str(alert.source_type, "alert.source_type").lower(),
            source_provenance=_parse_optional_str(alert.source_provenance, "alert.source_provenance"),
            log_source_id=_parse_optional_str(alert.log_source_id, "alert.log_source_id"),
            alert_definition_id=_parse_optional_str(alert.alert_definition_id, "alert.alert_definition_id"),
        )

    if isinstance(alert, Mapping):
        domain = _parse_required_str(alert.get("routing_domain_id"), "alert.routing_domain_id").lower()
        if "#" in domain:
            raise ValueError(f"alert.routing_domain_id cannot contain '#': {domain!r}")
        sensor = _parse_required_str(alert.get("sensor_id"), "alert.sensor_id").lower()
        src_ip, dst_ip, ip_ver, src_scoped, dst_scoped = _parse_ip_pair(
            alert.get("src_ip"),
            alert.get("dst_ip"),
            domain,
            alert.get("src_scoped_id"),
            alert.get("dst_scoped_id"),
            "alert",
        )
        proto_opt = _parse_optional_str(alert.get("protocol"), "alert.protocol")
        epoch_dec = _parse_optional_epoch_decimal(
            alert.get("timestamp_epoch_decimal"), "alert.timestamp_epoch_decimal"
        )
        raw_ns = alert.get("timestamp_epoch_ns")
        if raw_ns is not None and (isinstance(raw_ns, bool) or not isinstance(raw_ns, int)):
            raise ValueError(f"alert.timestamp_epoch_ns must be int or None, got {raw_ns!r}")
        derived_ns = raw_ns if "timestamp_epoch_ns" in alert else _exact_decimal_epoch_to_ns(epoch_dec)
        ts_src = _parse_optional_str(alert.get("timestamp_source"), "alert.timestamp_source") or ""
        src_type = (_parse_optional_str(alert.get("source_type"), "alert.source_type") or "suricata").lower()
        return AlertSnapshot(
            event_id=_parse_required_str(alert.get("event_id"), "alert.event_id"),
            routing_domain_id=domain,
            sensor_id=sensor,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_ver,
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            protocol=proto_opt.upper() if proto_opt is not None else None,
            src_port=_parse_optional_port(alert.get("src_port"), "alert.src_port"),
            dst_port=_parse_optional_port(alert.get("dst_port"), "alert.dst_port"),
            community_id=_parse_optional_str(alert.get("community_id"), "alert.community_id"),
            timestamp_source=ts_src,
            timestamp_epoch_decimal=epoch_dec,
            timestamp_epoch_ns=derived_ns,
            source_type=src_type,
            source_provenance=_parse_optional_str(alert.get("source_provenance"), "alert.source_provenance"),
            log_source_id=_parse_optional_str(alert.get("log_source_id"), "alert.log_source_id"),
            alert_definition_id=_parse_optional_str(
                alert.get("alert_definition_id"), "alert.alert_definition_id"
            ),
        )

    raise TypeError(f"Expected AlertSnapshot, SuricataAlertObservation, or Mapping, got {type(alert).__name__}")


def flow_to_snapshot(flow: FlowInput) -> FlowSnapshot:
    """Normalize a ZeekConnectionObservation, read-repository dict, or FlowSnapshot."""
    if isinstance(flow, FlowSnapshot):
        return flow

    if isinstance(flow, ZeekConnectionObservation):
        domain = _parse_required_str(flow.routing_domain_id, "flow.routing_domain_id").lower()
        if "#" in domain:
            raise ValueError(f"flow.routing_domain_id cannot contain '#': {domain!r}")
        sensor = _parse_required_str(flow.sensor_id, "flow.sensor_id").lower()
        src_ip, dst_ip, ip_ver, src_scoped, dst_scoped = _parse_ip_pair(
            flow.src_ip,
            flow.dst_ip,
            domain,
            flow.src_scoped_id,
            flow.dst_scoped_id,
            "flow",
        )
        proto = _parse_required_str(flow.protocol, "flow.protocol").upper()
        start_dec = _parse_optional_epoch_decimal(flow.start_epoch, "flow.start_epoch")
        end_dec = _parse_optional_epoch_decimal(flow.end_epoch, "flow.end_epoch")
        dur_dec = _parse_optional_epoch_decimal(flow.duration, "flow.duration")
        return FlowSnapshot(
            observation_id=_parse_required_str(flow.observation_id, "flow.observation_id"),
            zeek_uid=_parse_required_str(flow.zeek_uid, "flow.zeek_uid"),
            routing_domain_id=domain,
            sensor_id=sensor,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_ver,
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            protocol=proto,
            src_port=_parse_optional_port(flow.src_port, "flow.src_port"),
            dst_port=_parse_optional_port(flow.dst_port, "flow.dst_port"),
            community_id=_parse_optional_str(flow.community_id, "flow.community_id"),
            start_ts=_parse_required_str(flow.start_ts, "flow.start_ts"),
            start_epoch_decimal=start_dec,
            end_epoch_decimal=end_dec,
            duration_decimal=dur_dec,
            start_epoch_ns=_exact_decimal_epoch_to_ns(start_dec),
            end_epoch_ns=_exact_decimal_epoch_to_ns(end_dec),
            source_type=_parse_required_str(flow.source_type, "flow.source_type").lower(),
            source_provenance=_parse_optional_str(flow.source_provenance, "flow.source_provenance"),
        )

    if isinstance(flow, Mapping):
        domain = _parse_required_str(flow.get("routing_domain_id"), "flow.routing_domain_id").lower()
        if "#" in domain:
            raise ValueError(f"flow.routing_domain_id cannot contain '#': {domain!r}")
        sensor = _parse_required_str(flow.get("sensor_id"), "flow.sensor_id").lower()
        src_ip, dst_ip, ip_ver, src_scoped, dst_scoped = _parse_ip_pair(
            flow.get("src_ip"),
            flow.get("dst_ip"),
            domain,
            flow.get("src_scoped_id"),
            flow.get("dst_scoped_id"),
            "flow",
        )
        proto = _parse_required_str(flow.get("protocol"), "flow.protocol").upper()

        raw_start = flow["start_epoch_decimal"] if "start_epoch_decimal" in flow else flow.get("start_epoch")
        raw_end = flow["end_epoch_decimal"] if "end_epoch_decimal" in flow else flow.get("end_epoch")
        raw_dur = flow["duration_decimal"] if "duration_decimal" in flow else flow.get("duration")

        start_dec = _parse_optional_epoch_decimal(raw_start, "flow.start_epoch_decimal")
        end_dec = _parse_optional_epoch_decimal(raw_end, "flow.end_epoch_decimal")
        dur_dec = _parse_optional_epoch_decimal(raw_dur, "flow.duration_decimal")

        raw_start_ns = flow.get("start_epoch_ns")
        if raw_start_ns is not None and (isinstance(raw_start_ns, bool) or not isinstance(raw_start_ns, int)):
            raise ValueError(f"flow.start_epoch_ns must be int or None, got {raw_start_ns!r}")
        raw_end_ns = flow.get("end_epoch_ns")
        if raw_end_ns is not None and (isinstance(raw_end_ns, bool) or not isinstance(raw_end_ns, int)):
            raise ValueError(f"flow.end_epoch_ns must be int or None, got {raw_end_ns!r}")

        derived_start_ns = raw_start_ns if "start_epoch_ns" in flow else _exact_decimal_epoch_to_ns(start_dec)
        derived_end_ns = raw_end_ns if "end_epoch_ns" in flow else _exact_decimal_epoch_to_ns(end_dec)

        zeek_uid = _parse_optional_str(flow.get("zeek_uid"), "flow.zeek_uid") or ""
        start_ts = _parse_optional_str(flow.get("start_ts"), "flow.start_ts") or ""
        src_type = (_parse_optional_str(flow.get("source_type"), "flow.source_type") or "zeek").lower()
        return FlowSnapshot(
            observation_id=_parse_required_str(flow.get("observation_id"), "flow.observation_id"),
            zeek_uid=zeek_uid,
            routing_domain_id=domain,
            sensor_id=sensor,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_ver,
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            protocol=proto,
            src_port=_parse_optional_port(flow.get("src_port"), "flow.src_port"),
            dst_port=_parse_optional_port(flow.get("dst_port"), "flow.dst_port"),
            community_id=_parse_optional_str(flow.get("community_id"), "flow.community_id"),
            start_ts=start_ts,
            start_epoch_decimal=start_dec,
            end_epoch_decimal=end_dec,
            duration_decimal=dur_dec,
            start_epoch_ns=derived_start_ns,
            end_epoch_ns=derived_end_ns,
            source_type=src_type,
            source_provenance=_parse_optional_str(flow.get("source_provenance"), "flow.source_provenance"),
        )

    raise TypeError(f"Expected FlowSnapshot, ZeekConnectionObservation, or Mapping, got {type(flow).__name__}")


def normalize_correlation_protocol(protocol: Optional[str], ip_version: int) -> Optional[str]:
    """Normalize transport protocol strings across Zeek and Suricata conventions.

    Specifically bridges the verified repository asymmetry where Zeek logs
    `proto="ICMP"` on IPv6 connections while Suricata logs `proto="IPv6-ICMP"`
    or `"ICMPV6"`.
    """
    if protocol is None:
        return None
    cleaned = protocol.strip().upper()
    if not cleaned:
        return None
    if cleaned in _PORT_PROTOCOLS:
        return cleaned
    if cleaned == "ICMP":
        return "ICMP6" if ip_version == 6 else "ICMP"
    if cleaned in {"ICMP6", "ICMPV6", "IPV6-ICMP"}:
        return "ICMP6" if ip_version == 6 else f"OTHER:{cleaned}"
    return f"OTHER:{cleaned}"


def _evaluate_ports(
    alert: AlertSnapshot,
    flow: FlowSnapshot,
    ip_orientation: TupleOrientation,
    norm_proto: Optional[str],
) -> Tuple[TupleOrientation, TupleCompleteness, Optional[str]]:
    """Evaluate L4 port / ICMP tuple compatibility aligned to IP orientation."""
    if ip_orientation == TupleOrientation.MISMATCH:
        return TupleOrientation.MISMATCH, TupleCompleteness.INCOMPATIBLE, None

    if norm_proto is None:
        return ip_orientation, TupleCompleteness.MISSING_PROTOCOL, None

    if norm_proto.startswith("OTHER:"):
        return ip_orientation, TupleCompleteness.UNSUPPORTED_PROTOCOL, None

    if norm_proto in _ICMP_PROTOCOLS:
        # Suricata does NOT persist icmp_type/icmp_code onto AlertEvent (ports are None),
        # while Zeek stores ICMP type/code in src_port/dst_port. Never compare them directly;
        # ICMP tuple corroboration is resolved strictly through Community ID in G6.
        return ip_orientation, TupleCompleteness.ICMP_VIA_CID, None

    def _ports_match_without_conflict(
        a_sp: Optional[int],
        a_dp: Optional[int],
        f_sp: Optional[int],
        f_dp: Optional[int],
    ) -> Tuple[bool, bool]:
        if a_sp is not None and f_sp is not None and a_sp != f_sp:
            return False, False
        if a_dp is not None and f_dp is not None and a_dp != f_dp:
            return False, False
        complete = (
            a_sp is not None and a_dp is not None and f_sp is not None and f_dp is not None
        )
        return True, complete

    if ip_orientation == TupleOrientation.FORWARD:
        ok, complete = _ports_match_without_conflict(
            alert.src_port, alert.dst_port, flow.src_port, flow.dst_port
        )
        if not ok:
            return TupleOrientation.MISMATCH, TupleCompleteness.INCOMPATIBLE, "PORT_MISMATCH"
        return (
            TupleOrientation.FORWARD,
            TupleCompleteness.COMPLETE_5TUPLE if complete else TupleCompleteness.PARTIAL_PORTS,
            None if complete else "PARTIAL_PORTS",
        )

    if ip_orientation == TupleOrientation.REVERSE:
        ok, complete = _ports_match_without_conflict(
            alert.src_port, alert.dst_port, flow.dst_port, flow.src_port
        )
        if not ok:
            return TupleOrientation.MISMATCH, TupleCompleteness.INCOMPATIBLE, "PORT_MISMATCH"
        return (
            TupleOrientation.REVERSE,
            TupleCompleteness.COMPLETE_5TUPLE if complete else TupleCompleteness.PARTIAL_PORTS,
            None if complete else "PARTIAL_PORTS",
        )

    # SYMMETRIC IP pair (self-loop src_ip == dst_ip): check both port alignments
    fwd_ok, fwd_complete = _ports_match_without_conflict(
        alert.src_port, alert.dst_port, flow.src_port, flow.dst_port
    )
    rev_ok, rev_complete = _ports_match_without_conflict(
        alert.src_port, alert.dst_port, flow.dst_port, flow.src_port
    )
    if not fwd_ok and not rev_ok:
        return TupleOrientation.MISMATCH, TupleCompleteness.INCOMPATIBLE, "PORT_MISMATCH"
    if fwd_ok and rev_ok:
        orient = TupleOrientation.SYMMETRIC
        complete = fwd_complete or rev_complete
    elif fwd_ok:
        orient = TupleOrientation.FORWARD
        complete = fwd_complete
    else:
        orient = TupleOrientation.REVERSE
        complete = rev_complete
    return (
        orient,
        TupleCompleteness.COMPLETE_5TUPLE if complete else TupleCompleteness.PARTIAL_PORTS,
        None if complete else "PARTIAL_PORTS",
    )


def _evaluate_community_id(
    alert: AlertSnapshot,
    flow: FlowSnapshot,
    norm_proto: Optional[str],
    tuple_completeness: TupleCompleteness,
    policy: CorrelationPolicy,
) -> Tuple[CommunityIdStatus, Optional[str], bool]:
    """Evaluate Community ID consistency.

    Returns:
        (status, reason_code_or_None, is_hard_rejection)
    """
    a_cid = alert.community_id
    f_cid = flow.community_id

    if a_cid is None and f_cid is None:
        return CommunityIdStatus.MISSING_BOTH, None, False
    if a_cid is None:
        return CommunityIdStatus.MISSING_ALERT, None, False
    if f_cid is None:
        return CommunityIdStatus.MISSING_FLOW, None, False

    if a_cid == f_cid:
        return CommunityIdStatus.MATCH, None, False

    if policy.community_id_seed_policy == CommunityIdSeedPolicy.STRICT_SAME_SEED:
        return CommunityIdStatus.CONFLICT, "COMMUNITY_ID_CONFLICT", True

    if policy.community_id_seed_policy == CommunityIdSeedPolicy.ALLOW_UNVERIFIED_TUPLE_FALLBACK:
        # Unknown/unverified seeds must never automatically promote to STRONG
        return CommunityIdStatus.MISMATCH_SEED_UNVERIFIED, "COMMUNITY_ID_SEED_UNVERIFIED", False

    # VERIFY_SEED_PAIR: cryptographically reproduce both hashes from the verified tuple
    assert policy.zeek_community_id_seed is not None
    assert policy.suricata_community_id_seed is not None

    can_reproduce = False
    if norm_proto in _PORT_PROTOCOLS and tuple_completeness == TupleCompleteness.COMPLETE_5TUPLE:
        can_reproduce = True
    elif (
        norm_proto in _ICMP_PROTOCOLS
        and flow.src_port is not None
        and flow.dst_port is not None
        and 0 <= flow.src_port <= 255
        and 0 <= flow.dst_port <= 255
    ):
        can_reproduce = True

    if not can_reproduce or norm_proto is None:
        return CommunityIdStatus.CONFLICT, "COMMUNITY_ID_SEED_VERIFICATION_FAILED", True

    expected_zeek = compute_community_id(
        ip_src=flow.src_ip,
        ip_dst=flow.dst_ip,
        protocol=norm_proto,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        seed=policy.zeek_community_id_seed,
    )
    expected_suricata = compute_community_id(
        ip_src=flow.src_ip,
        ip_dst=flow.dst_ip,
        protocol=norm_proto,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        seed=policy.suricata_community_id_seed,
    )
    if (
        expected_zeek is not None
        and expected_suricata is not None
        and expected_zeek == f_cid
        and expected_suricata == a_cid
    ):
        return CommunityIdStatus.VERIFIED_SEED_OFFSET, None, False

    return CommunityIdStatus.CONFLICT, "COMMUNITY_ID_SEED_VERIFICATION_FAILED", True


def _evaluate_temporal(
    alert: AlertSnapshot,
    flow: FlowSnapshot,
    policy: CorrelationPolicy,
) -> Tuple[TemporalRelation, Optional[str], bool, Optional[str], bool]:
    """Evaluate exact Decimal temporal compatibility.

    Returns:
        (relation, delta_str, used_decimal_fallback, reason_or_None, is_hard_rejection)
    """
    used_fallback = (
        (alert.timestamp_epoch_decimal is not None and alert.timestamp_epoch_ns is None)
        or (flow.start_epoch_decimal is not None and flow.start_epoch_ns is None)
        or (flow.end_epoch_decimal is not None and flow.end_epoch_ns is None)
    )

    if alert.timestamp_epoch_decimal is None:
        return (
            TemporalRelation.MISSING_ALERT_EPOCH,
            None,
            used_fallback,
            "MISSING_SURICATA_TIMEZONE",
            False,
        )

    if flow.start_epoch_decimal is None:
        return (
            TemporalRelation.MISSING_FLOW_START_EPOCH,
            None,
            used_fallback,
            "MISSING_ZEEK_START_EPOCH",
            False,
        )

    clock_offset = policy.sensor_policy.get_clock_offset(alert.sensor_id, flow.sensor_id)
    t_alert = (
        add_exact_decimals(alert.timestamp_epoch_decimal, clock_offset)
        if clock_offset != 0
        else alert.timestamp_epoch_decimal
    )
    t_start = flow.start_epoch_decimal
    t_end = flow.end_epoch_decimal

    if t_end is not None:
        if t_end < t_start:
            return (
                TemporalRelation.INVALID_INTERVAL,
                None,
                used_fallback,
                "INVALID_FLOW_INTERVAL",
                True,
            )

        if t_start <= t_alert <= t_end:
            return TemporalRelation.WITHIN_INTERVAL, "0", used_fallback, None, False

        if t_alert < t_start:
            delta = _subtract_exact_decimals(t_alert, t_start)
            lower = _subtract_exact_decimals(t_start, policy.pre_start_tolerance_sec)
            if policy.pre_start_tolerance_sec > 0 and t_alert >= lower:
                reason = None if policy.allow_tolerance_match else "TOLERANCE_MATCH_REQUIRES_OPT_IN"
                return (
                    TemporalRelation.WITHIN_PRE_TOLERANCE,
                    format_canonical_decimal(delta),
                    used_fallback,
                    reason,
                    False,
                )
            return (
                TemporalRelation.OUTSIDE_WINDOW,
                format_canonical_decimal(delta),
                used_fallback,
                "OUTSIDE_TEMPORAL_WINDOW",
                True,
            )

        delta = _subtract_exact_decimals(t_alert, t_end)
        upper = add_exact_decimals(t_end, policy.post_end_tolerance_sec)
        if policy.post_end_tolerance_sec > 0 and t_alert <= upper:
            reason = None if policy.allow_tolerance_match else "TOLERANCE_MATCH_REQUIRES_OPT_IN"
            return (
                TemporalRelation.WITHIN_POST_TOLERANCE,
                format_canonical_decimal(delta),
                used_fallback,
                reason,
                False,
            )
        return (
            TemporalRelation.OUTSIDE_WINDOW,
            format_canonical_decimal(delta),
            used_fallback,
            "OUTSIDE_TEMPORAL_WINDOW",
            True,
        )

    # Missing Zeek end_epoch: never fabricate an unbounded session end.
    delta = _subtract_exact_decimals(t_alert, t_start)
    lower = _subtract_exact_decimals(t_start, policy.pre_start_tolerance_sec)
    upper = add_exact_decimals(t_start, policy.point_observation_post_tolerance_sec)
    if lower <= t_alert <= upper:
        if not policy.allow_missing_zeek_end:
            reason_no_end: Optional[str] = "MISSING_ZEEK_END_REQUIRES_OPT_IN"
        elif t_alert < t_start and not policy.allow_tolerance_match:
            reason_no_end = "TOLERANCE_MATCH_REQUIRES_OPT_IN"
        else:
            reason_no_end = None
        return (
            TemporalRelation.NEAR_START_NO_END,
            format_canonical_decimal(delta),
            used_fallback,
            reason_no_end,
            False,
        )

    return (
        TemporalRelation.OUTSIDE_WINDOW,
        format_canonical_decimal(delta),
        used_fallback,
        "OUTSIDE_TEMPORAL_WINDOW",
        True,
    )


def evaluate_candidate(
    alert: AlertInput,
    flow: FlowInput,
    policy: Optional[CorrelationPolicy] = None,
) -> CorrelationCandidateEvidence:
    """Evaluate a single (AlertEvent, FlowObservation) pair against hard gates G1–G7."""
    active_policy = policy if policy is not None else CorrelationPolicy()
    a_snap = alert_to_snapshot(alert)
    f_snap = flow_to_snapshot(flow)

    hard_reject_reasons: List[str] = []
    insufficient_reasons: List[str] = []

    # G1. RoutingDomain equality
    domain_matched = a_snap.routing_domain_id == f_snap.routing_domain_id
    if not domain_matched:
        hard_reject_reasons.append("ROUTING_DOMAIN_MISMATCH")
    elif not active_policy.allow_default_domain and a_snap.routing_domain_id == "default":
        insufficient_reasons.append("DEFAULT_ROUTING_DOMAIN_DISALLOWED")

    # G2. Sensor pairing policy
    sensor_status = active_policy.sensor_policy.evaluate_pair(a_snap.sensor_id, f_snap.sensor_id)
    if sensor_status == SensorPolicyStatus.DISALLOWED:
        hard_reject_reasons.append("SENSOR_PAIR_DISALLOWED")

    # G3. Forward / reverse / symmetric IP endpoint equality (and IP family)
    if a_snap.ip_version != f_snap.ip_version:
        ip_orientation = TupleOrientation.MISMATCH
        hard_reject_reasons.append("IP_VERSION_MISMATCH")
    else:
        fwd_ip = a_snap.src_ip == f_snap.src_ip and a_snap.dst_ip == f_snap.dst_ip
        rev_ip = a_snap.src_ip == f_snap.dst_ip and a_snap.dst_ip == f_snap.src_ip
        if fwd_ip and rev_ip:
            ip_orientation = TupleOrientation.SYMMETRIC
        elif fwd_ip:
            ip_orientation = TupleOrientation.FORWARD
        elif rev_ip:
            ip_orientation = TupleOrientation.REVERSE
        else:
            ip_orientation = TupleOrientation.MISMATCH
            hard_reject_reasons.append("IP_ENDPOINT_MISMATCH")

    # G4. Protocol compatibility
    a_proto = normalize_correlation_protocol(a_snap.protocol, a_snap.ip_version)
    f_proto = normalize_correlation_protocol(f_snap.protocol, f_snap.ip_version)
    matched_proto: Optional[str] = None

    if a_proto is None:
        proto_status = ProtocolStatus.MISSING
        insufficient_reasons.append("MISSING_ALERT_PROTOCOL")
    elif f_proto is None:
        proto_status = ProtocolStatus.MISSING
        insufficient_reasons.append("MISSING_FLOW_PROTOCOL")
    elif a_proto != f_proto:
        proto_status = ProtocolStatus.CONFLICT
        hard_reject_reasons.append("PROTOCOL_MISMATCH")
    elif a_proto.startswith("OTHER:"):
        proto_status = ProtocolStatus.UNSUPPORTED
        matched_proto = a_proto
        insufficient_reasons.append("UNSUPPORTED_PROTOCOL")
    else:
        matched_proto = a_proto
        if a_proto == "ICMP6" and a_snap.protocol != f_snap.protocol:
            proto_status = ProtocolStatus.IPV6_ICMP_ALIAS_MATCH
        else:
            proto_status = ProtocolStatus.EXACT_MATCH

    # G5. Transport port / tuple compatibility
    tuple_orientation, tuple_completeness, port_reason = _evaluate_ports(
        a_snap, f_snap, ip_orientation, matched_proto
    )
    if port_reason == "PORT_MISMATCH":
        hard_reject_reasons.append(port_reason)
    elif port_reason is not None:
        insufficient_reasons.append(port_reason)

    # G6. Community ID consistency
    cid_status, cid_reason, cid_hard_reject = _evaluate_community_id(
        a_snap, f_snap, matched_proto, tuple_completeness, active_policy
    )
    if cid_hard_reject and cid_reason:
        hard_reject_reasons.append(cid_reason)
    elif cid_reason:
        insufficient_reasons.append(cid_reason)

    # ICMP/ICMPv6 requires CID-backed corroboration because Suricata does not persist icmp_type/code
    if matched_proto in _ICMP_PROTOCOLS and cid_status not in {
        CommunityIdStatus.MATCH,
        CommunityIdStatus.VERIFIED_SEED_OFFSET,
    }:
        if not cid_hard_reject:
            insufficient_reasons.append("ICMP_REQUIRES_COMMUNITY_ID")

    if active_policy.require_community_id and cid_status in {
        CommunityIdStatus.MISSING_ALERT,
        CommunityIdStatus.MISSING_FLOW,
        CommunityIdStatus.MISSING_BOTH,
    }:
        insufficient_reasons.append("COMMUNITY_ID_REQUIRED")

    # G7. Exact Decimal temporal compatibility
    temporal_relation, temporal_delta, used_fallback, temp_reason, temp_hard_reject = (
        _evaluate_temporal(a_snap, f_snap, active_policy)
    )
    if temp_hard_reject and temp_reason:
        hard_reject_reasons.append(temp_reason)
    elif temp_reason:
        insufficient_reasons.append(temp_reason)

    if hard_reject_reasons:
        strength = CandidateStrength.REJECTED
        reasons = tuple(dict.fromkeys(hard_reject_reasons))
    elif insufficient_reasons:
        strength = CandidateStrength.INSUFFICIENT
        reasons = tuple(dict.fromkeys(insufficient_reasons))
    else:
        strength = CandidateStrength.STRONG
        ok_reasons = ["ALL_HARD_GATES_PASSED", f"ORIENTATION_{tuple_orientation.value}"]
        if cid_status == CommunityIdStatus.MATCH:
            ok_reasons.append("COMMUNITY_ID_MATCH")
        elif cid_status == CommunityIdStatus.VERIFIED_SEED_OFFSET:
            ok_reasons.append("COMMUNITY_ID_VERIFIED_SEED_OFFSET")
        else:
            ok_reasons.append(f"COMMUNITY_ID_{cid_status.value}")
        ok_reasons.append(f"TEMPORAL_{temporal_relation.value}")
        reasons = tuple(ok_reasons)

    return CorrelationCandidateEvidence(
        observation_id=f_snap.observation_id,
        zeek_uid=f_snap.zeek_uid,
        zeek_sensor_id=f_snap.sensor_id,
        routing_domain_id=f_snap.routing_domain_id,
        domain_matched=domain_matched,
        sensor_policy_status=sensor_status,
        tuple_orientation=tuple_orientation,
        tuple_completeness=tuple_completeness,
        protocol_status=proto_status,
        community_id_status=cid_status,
        temporal_relation=temporal_relation,
        temporal_delta_decimal=temporal_delta,
        used_decimal_fallback=used_fallback,
        strength=strength,
        reasons=reasons,
    )


def _alert_precondition_failures(
    alert: AlertSnapshot,
    policy: CorrelationPolicy,
) -> List[str]:
    """Identify alert-level conditions that preclude automatic STRONG correlation."""
    issues: List[str] = []
    if not policy.allow_default_domain and alert.routing_domain_id == "default":
        issues.append("DEFAULT_ROUTING_DOMAIN_DISALLOWED")
    if alert.timestamp_epoch_decimal is None:
        issues.append("MISSING_SURICATA_TIMEZONE")

    norm_proto = normalize_correlation_protocol(alert.protocol, alert.ip_version)
    if norm_proto is None:
        issues.append("MISSING_ALERT_PROTOCOL")
    elif norm_proto.startswith("OTHER:"):
        issues.append("UNSUPPORTED_PROTOCOL")
    elif norm_proto in _PORT_PROTOCOLS:
        if alert.src_port is None or alert.dst_port is None:
            issues.append("PARTIAL_ALERT_PORTS")
    elif norm_proto in _ICMP_PROTOCOLS:
        if alert.community_id is None:
            issues.append("ICMP_REQUIRES_COMMUNITY_ID")

    if policy.require_community_id and alert.community_id is None:
        issues.append("COMMUNITY_ID_REQUIRED")

    return issues


def _completeness_failure_reason(completeness: CandidateCompleteness) -> Optional[str]:
    if completeness == CandidateCompleteness.COMPLETE:
        return None
    if completeness == CandidateCompleteness.TRUNCATED:
        return "CANDIDATE_SET_TRUNCATED"
    if completeness == CandidateCompleteness.RETRIEVAL_ERROR:
        return "CANDIDATE_RETRIEVAL_ERROR"
    return "CANDIDATE_COMPLETENESS_UNKNOWN"


def correlate_alert_to_flows(
    alert: AlertInput,
    candidates: Iterable[FlowInput],
    *,
    policy: Optional[CorrelationPolicy] = None,
    candidate_completeness: CandidateCompleteness = CandidateCompleteness.COMPLETE,
) -> CorrelationDecision:
    """Conservatively evaluate an AlertEvent against a candidate set of FlowObservations.

    Decision invariants:
    - Never promotes STRONG from a non-COMPLETE or cap-exceeded candidate set.
    - Never filters out missing-CID flows when another candidate has a matching CID.
    - Never breaks ties arbitrarily among >=2 STRONG candidates or between 1 STRONG
      candidate and >=1 unresolved plausible rival (returns AMBIGUOUS).
    - Deterministic output regardless of candidate iteration order.
    """
    active_policy = policy if policy is not None else CorrelationPolicy()
    if not isinstance(candidate_completeness, CandidateCompleteness):
        raise ValueError(
            f"candidate_completeness must be a CandidateCompleteness, got {candidate_completeness!r}"
        )

    a_snap = alert_to_snapshot(alert)

    # Deduplicate identical observation_id candidates cleanly and enforce candidate_cap lazily
    unique_flows: Dict[str, FlowSnapshot] = {}
    cap_exceeded = False
    for raw_flow in candidates:
        f_snap = flow_to_snapshot(raw_flow)
        existing = unique_flows.get(f_snap.observation_id)
        if existing is not None:
            if existing != f_snap:
                raise ValueError(
                    f"Conflicting duplicate candidate flow for observation_id={f_snap.observation_id!r}"
                )
            continue
        if active_policy.candidate_cap is not None and len(unique_flows) >= active_policy.candidate_cap:
            cap_exceeded = True
            break
        unique_flows[f_snap.observation_id] = f_snap

    # Order deterministically by observation_id so output never depends on input iteration order
    ordered_flows = [unique_flows[obs_id] for obs_id in sorted(unique_flows.keys())]
    evaluated: List[CorrelationCandidateEvidence] = [
        evaluate_candidate(a_snap, f_snap, policy=active_policy) for f_snap in ordered_flows
    ]

    strong = [ev for ev in evaluated if ev.is_strong]
    plausible_rivals = [ev for ev in evaluated if ev.is_plausible_rival]
    strong_ids = tuple(ev.observation_id for ev in strong)
    rival_ids = tuple(ev.observation_id for ev in plausible_rivals)

    strength_order = {
        CandidateStrength.STRONG: 0,
        CandidateStrength.INSUFFICIENT: 1,
        CandidateStrength.REJECTED: 2,
    }
    ordered_evidences = sorted(evaluated, key=lambda ev: (strength_order[ev.strength], ev.observation_id))
    bounded_evidences = tuple(ordered_evidences[: active_policy.max_evidences_returned])

    # Fail-closed check 1: incomplete or cap-exceeded candidate set can NEVER yield STRONG
    completeness_reason = _completeness_failure_reason(candidate_completeness)
    if completeness_reason is not None or cap_exceeded:
        reasons: List[str] = []
        if completeness_reason is not None:
            reasons.append(completeness_reason)
        if cap_exceeded:
            reasons.append("CANDIDATE_CAP_EXCEEDED")
        return CorrelationDecision(
            event_id=a_snap.event_id,
            status=CorrelationStatus.INSUFFICIENT,
            selected_observation_id=None,
            auto_correlate_allowed=False,
            candidate_count_evaluated=len(evaluated),
            strong_candidate_ids=strong_ids,
            plausible_rival_ids=rival_ids,
            candidate_completeness=candidate_completeness,
            candidate_cap_exceeded=cap_exceeded,
            decision_reasons=tuple(reasons),
            selected_evidence=None,
            candidate_evidences=bounded_evidences,
            policy_fingerprint=active_policy.policy_fingerprint,
            evidence_version=active_policy.evidence_version,
        )

    # Fail-closed check 2: alert-level missing/disallowed preconditions
    alert_issues = _alert_precondition_failures(a_snap, active_policy)
    if alert_issues:
        return CorrelationDecision(
            event_id=a_snap.event_id,
            status=CorrelationStatus.INSUFFICIENT,
            selected_observation_id=None,
            auto_correlate_allowed=False,
            candidate_count_evaluated=len(evaluated),
            strong_candidate_ids=strong_ids,
            plausible_rival_ids=rival_ids,
            candidate_completeness=candidate_completeness,
            candidate_cap_exceeded=False,
            decision_reasons=tuple(dict.fromkeys(alert_issues)),
            selected_evidence=None,
            candidate_evidences=bounded_evidences,
            policy_fingerprint=active_policy.policy_fingerprint,
            evidence_version=active_policy.evidence_version,
        )

    # Complete candidate set + valid alert: deterministic decision matrix
    if len(strong) >= 2:
        multi_sensor = len({ev.zeek_sensor_id for ev in strong}) > 1
        reasons = ["MULTIPLE_STRONG_CANDIDATES"]
        if multi_sensor:
            reasons.append("MULTIPLE_STRONG_CANDIDATES_MULTI_SENSOR")
        return CorrelationDecision(
            event_id=a_snap.event_id,
            status=CorrelationStatus.AMBIGUOUS,
            selected_observation_id=None,
            auto_correlate_allowed=False,
            candidate_count_evaluated=len(evaluated),
            strong_candidate_ids=strong_ids,
            plausible_rival_ids=rival_ids,
            candidate_completeness=candidate_completeness,
            candidate_cap_exceeded=False,
            decision_reasons=tuple(reasons),
            selected_evidence=None,
            candidate_evidences=bounded_evidences,
            policy_fingerprint=active_policy.policy_fingerprint,
            evidence_version=active_policy.evidence_version,
        )

    if len(strong) == 1 and len(plausible_rivals) >= 1:
        rival_causes: List[str] = ["STRONG_WITH_PLAUSIBLE_UNRESOLVED_RIVAL"]
        for rv in plausible_rivals:
            for r in rv.reasons:
                if r not in rival_causes:
                    rival_causes.append(r)
        return CorrelationDecision(
            event_id=a_snap.event_id,
            status=CorrelationStatus.AMBIGUOUS,
            selected_observation_id=None,
            auto_correlate_allowed=False,
            candidate_count_evaluated=len(evaluated),
            strong_candidate_ids=strong_ids,
            plausible_rival_ids=rival_ids,
            candidate_completeness=candidate_completeness,
            candidate_cap_exceeded=False,
            decision_reasons=tuple(rival_causes),
            selected_evidence=None,
            candidate_evidences=bounded_evidences,
            policy_fingerprint=active_policy.policy_fingerprint,
            evidence_version=active_policy.evidence_version,
        )

    if len(strong) == 1:
        winner = strong[0]
        reasons = ["UNIQUE_STRONG_MATCH"] + list(winner.reasons)
        if a_snap.routing_domain_id == "default":
            reasons.append("DEFAULT_ROUTING_DOMAIN_USED")
        return CorrelationDecision(
            event_id=a_snap.event_id,
            status=CorrelationStatus.STRONG,
            selected_observation_id=winner.observation_id,
            auto_correlate_allowed=True,
            candidate_count_evaluated=len(evaluated),
            strong_candidate_ids=strong_ids,
            plausible_rival_ids=(),
            candidate_completeness=candidate_completeness,
            candidate_cap_exceeded=False,
            decision_reasons=tuple(dict.fromkeys(reasons)),
            selected_evidence=winner,
            candidate_evidences=bounded_evidences,
            policy_fingerprint=active_policy.policy_fingerprint,
            evidence_version=active_policy.evidence_version,
        )

    if len(plausible_rivals) >= 1:
        agg_reasons: List[str] = ["NO_STRONG_CANDIDATE_INSUFFICIENT_EVIDENCE"]
        for rv in plausible_rivals:
            for r in rv.reasons:
                if r not in agg_reasons:
                    agg_reasons.append(r)
        return CorrelationDecision(
            event_id=a_snap.event_id,
            status=CorrelationStatus.INSUFFICIENT,
            selected_observation_id=None,
            auto_correlate_allowed=False,
            candidate_count_evaluated=len(evaluated),
            strong_candidate_ids=(),
            plausible_rival_ids=rival_ids,
            candidate_completeness=candidate_completeness,
            candidate_cap_exceeded=False,
            decision_reasons=tuple(agg_reasons),
            selected_evidence=None,
            candidate_evidences=bounded_evidences,
            policy_fingerprint=active_policy.policy_fingerprint,
            evidence_version=active_policy.evidence_version,
        )

    if not evaluated:
        reject_reasons: Tuple[str, ...] = ("NO_CANDIDATE_FLOWS",)
    else:
        seen_r: List[str] = ["ALL_CANDIDATES_REJECTED"]
        for ev in evaluated:
            for r in ev.reasons:
                if r not in seen_r:
                    seen_r.append(r)
        reject_reasons = tuple(seen_r)

    return CorrelationDecision(
        event_id=a_snap.event_id,
        status=CorrelationStatus.REJECTED,
        selected_observation_id=None,
        auto_correlate_allowed=False,
        candidate_count_evaluated=len(evaluated),
        strong_candidate_ids=(),
        plausible_rival_ids=(),
        candidate_completeness=candidate_completeness,
        candidate_cap_exceeded=False,
        decision_reasons=reject_reasons,
        selected_evidence=None,
        candidate_evidences=bounded_evidences,
        policy_fingerprint=active_policy.policy_fingerprint,
        evidence_version=active_policy.evidence_version,
    )
