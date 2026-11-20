"""
Streaming parser and normalizer for Suricata EVE newline-delimited JSON (JSONL) alerts.

Processes exclusively `event_type="alert"` records from Suricata EVE logs into immutable,
Neo4j-independent `SuricataAlertObservation` records while cleanly ignoring other valid EVE
event types (flow, dns, http, tls, stats, etc.) without treating them as malformed.

Key guarantees:
- Reuses existing V2 identity primitives (`alert_definition_id`, `compute_alert_event_id`,
  `scoped_ip_id`, `compute_v2_flow_key`, `resolve_community_id`, `canonicalize_event_timestamp`,
  `format_canonical_decimal`, `add_exact_decimals`).
- Preserves exact source ISO 8601 timestamp representation and derives exact UTC `Decimal`
  epoch via pure integer + `add_exact_decimals` arithmetic (never `datetime.timestamp()` float,
  never rounding to microseconds or Decimal context precision).
- Never invents a timezone for naive timestamps (retains `timestamp_source` with
  `timestamp_epoch_decimal = None`).
- Never conflates `alert.gid` absence with `gid=1`, never uses `alert.rev` in definition
  identity, and never infers `ruleset_namespace` or `routing_domain_id`.
- Derives deterministic, collision-resistant per-line `source_record_id` from explicit
  `log_source_id`, 1-based physical line ordinal, and canonical SHA-256 record fingerprint
  in O(1) memory (never relying solely on `flow_id`, `signature_id`, `tx_id`, or `pcap_cnt`).
- Bounds error samples and warning logs to prevent log flooding on noisy streams.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import ipaddress
import json
import logging
import os
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from src.ingestion.community_id import resolve_community_id
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    add_exact_decimals,
    alert_definition_id,
    canonicalize_event_timestamp,
    compute_alert_event_id,
    compute_v2_flow_key,
    format_canonical_decimal,
    scoped_ip_id,
)

logger = logging.getLogger(__name__)

MAX_SAMPLE_ERRORS = 10
MAX_LOGGED_WARNINGS = MAX_SAMPLE_ERRORS
_UNIX_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Strict ISO 8601 pattern supporting Suricata's standard +0000, +00:00, Z, and arbitrary fractional digits.
_ISO_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d{1,1000}))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)

# Transport protocols supported for Community ID v1 tuple computation.
_PORT_TRANSPORT_PROTOS = frozenset({"TCP", "UDP", "SCTP"})
_ICMP_PROTOS = frozenset({"ICMP", "ICMP6", "ICMPV6", "IPV6-ICMP"})


@dataclass(frozen=True)
class SuricataIngestionSummary:
    """Additive diagnostics summary for a Suricata EVE JSONL alert parse run.

    Tracks valid non-alert EVE event types separately from malformed/skipped records:
    `total_raw_records == valid_records + skipped_records + ignored_non_alert_records`.
    """

    total_raw_records: int
    valid_records: int
    skipped_records: int
    ignored_non_alert_records: int = 0
    warning_counts: Dict[str, int] = field(default_factory=dict)
    sample_errors: Tuple[str, ...] = ()


def _validate_parser_config(
    *,
    sensor_id: str,
    ruleset_namespace: str,
    log_source_id: str,
    routing_domain_id: str,
    source_provenance: Optional[str],
    community_id_seed: int,
) -> Tuple[str, str, str, str, Optional[str], int]:
    """Validate and normalize Suricata EVE alert parser configuration eagerly."""
    if not isinstance(sensor_id, str) or not sensor_id.strip():
        raise ValueError("sensor_id must be a non-empty string")
    norm_sensor_id = sensor_id.strip().lower()

    if not isinstance(ruleset_namespace, str) or not ruleset_namespace.strip():
        raise ValueError("ruleset_namespace must be a non-empty string")
    norm_namespace = ruleset_namespace.strip().lower()

    if not isinstance(log_source_id, str) or not log_source_id.strip():
        raise ValueError("log_source_id must be a non-empty string")
    norm_log_source_id = log_source_id.strip()

    if not isinstance(routing_domain_id, str) or not routing_domain_id.strip():
        raise ValueError("routing_domain_id must be a non-empty string")
    norm_domain = routing_domain_id.strip().lower()
    if "#" in norm_domain:
        raise ValueError(f"routing_domain_id cannot contain delimiter '#': '{norm_domain}'")

    if source_provenance is not None:
        if not isinstance(source_provenance, str):
            raise ValueError("source_provenance must be a string or None")
        norm_provenance: Optional[str] = source_provenance.strip() or None
    else:
        norm_provenance = None

    if (
        isinstance(community_id_seed, bool)
        or not isinstance(community_id_seed, int)
        or not (0 <= community_id_seed <= 65535)
    ):
        raise ValueError(
            f"Invalid community_id_seed: {community_id_seed}. Must be an integer in 0..65535."
        )

    return (
        norm_sensor_id,
        norm_namespace,
        norm_log_source_id,
        norm_domain,
        norm_provenance,
        community_id_seed,
    )


def _canonicalize_json_value(value: Any) -> Any:
    """Convert parsed JSON values (including Decimal) into JSON-serializable canonical primitives."""
    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            return str(value)
        try:
            return format_canonical_decimal(value)
        except ValueError:
            return str(value)
    if isinstance(value, dict):
        return {str(k): _canonicalize_json_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canonicalize_json_value(item) for item in value]
    return value


def _compute_record_fingerprint(entry: Dict[str, Any]) -> str:
    """Compute a stable SHA-256 fingerprint of a parsed EVE alert JSON object."""
    canonical_obj = _canonicalize_json_value(entry)
    serialized = json.dumps(
        canonical_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _parse_suricata_timestamp(raw_ts: Any) -> Tuple[Optional[str], Optional[Decimal], bool]:
    """Parse and validate a Suricata EVE ISO 8601 timestamp without float conversion or rounding.

    Accepts standard ISO 8601 forms including:
    - `2026-11-20T14:15:30.123456+0000`
    - `2026-11-20T14:15:30.123456+00:00`
    - `2026-11-20T14:15:30.123456Z`
    - Higher fractional precision (e.g., 9 or 12 fractional digits)

    Policy for naive timestamps (valid ISO 8601 without timezone offset):
    - Preserves `timestamp_source` verbatim while leaving `timestamp_epoch_decimal = None`.
    - Never invents UTC or local timezone.

    Returns:
        Tuple of (timestamp_source_str, timestamp_epoch_decimal_or_None, is_valid).
    """
    if not isinstance(raw_ts, str):
        return None, None, False

    trimmed = raw_ts.strip()
    if not trimmed:
        return None, None, False

    match = _ISO_TIMESTAMP_PATTERN.match(trimmed)
    if not match:
        return None, None, False

    date_part = match.group("date")
    time_part = match.group("time")
    frac_part = match.group("frac")
    tz_part = match.group("tz")

    norm_tz = ""
    if tz_part:
        if tz_part == "Z":
            norm_tz = "+00:00"
        elif len(tz_part) == 5 and tz_part[0] in "+-":
            norm_tz = f"{tz_part[:3]}:{tz_part[3:]}"
        else:
            norm_tz = tz_part

    try:
        dt = datetime.fromisoformat(f"{date_part}T{time_part}{norm_tz}")
    except ValueError:
        return None, None, False

    epoch_decimal: Optional[Decimal] = None
    if dt.tzinfo is not None:
        delta = dt - _UNIX_EPOCH_UTC
        whole_seconds = Decimal(delta.days * 86400 + delta.seconds)
        frac_seconds = Decimal(f"0.{frac_part}") if frac_part else Decimal(0)
        try:
            epoch_decimal = add_exact_decimals(whole_seconds, frac_seconds)
        except ValueError:
            return None, None, False
        if epoch_decimal < 0:
            return None, None, False

    return canonicalize_event_timestamp(trimmed), epoch_decimal, True


def _parse_port(raw_val: Any) -> Tuple[Optional[int], bool]:
    """Parse an optional transport port (0..65535). Absent returns (None, True)."""
    if raw_val is None:
        return None, True
    if isinstance(raw_val, bool):
        return None, False
    if isinstance(raw_val, int):
        return (raw_val, True) if 0 <= raw_val <= 65535 else (None, False)
    if isinstance(raw_val, str):
        trimmed = raw_val.strip()
        if not trimmed:
            return None, True
        if trimmed.isdigit():
            val = int(trimmed)
            return (val, True) if 0 <= val <= 65535 else (None, False)
        return None, False
    return None, False


def _parse_non_negative_int(raw_val: Any) -> Tuple[Optional[int], bool]:
    """Parse an optional non-negative integer. Absent returns (None, True)."""
    if raw_val is None:
        return None, True
    if isinstance(raw_val, bool):
        return None, False
    if isinstance(raw_val, int):
        return (raw_val, True) if raw_val >= 0 else (None, False)
    if isinstance(raw_val, str):
        trimmed = raw_val.strip()
        if not trimmed:
            return None, True
        if trimmed.isdigit():
            return int(trimmed), True
        return None, False
    return None, False


def _parse_optional_str(raw_val: Any) -> Tuple[Optional[str], bool]:
    """Parse an optional trimmed string. Absent or empty string returns (None, True)."""
    if raw_val is None:
        return None, True
    if isinstance(raw_val, str):
        trimmed = raw_val.strip()
        return (trimmed if trimmed else None), True
    return None, False


class SuricataEveAlertStream:
    """Bounded-memory streaming iterator over Suricata EVE JSONL alert records.

    Yields `SuricataAlertObservation` instances lazily line-by-line (O(1) memory)
    and tracks bounded diagnostics in `.summary`.
    Can be iterated directly or used as a context manager (`with stream_suricata_eve_alerts(...) as s:`).
    """

    def __init__(
        self,
        lines: Iterable[str],
        *,
        sensor_id: str,
        ruleset_namespace: str,
        log_source_id: str,
        routing_domain_id: str = "default",
        source_provenance: Optional[str] = None,
        community_id_seed: int = 0,
        close_resource: Any = None,
    ):
        (
            self._sensor_id,
            self._ruleset_namespace,
            self._log_source_id,
            self._routing_domain_id,
            self._source_provenance,
            self._community_id_seed,
        ) = _validate_parser_config(
            sensor_id=sensor_id,
            ruleset_namespace=ruleset_namespace,
            log_source_id=log_source_id,
            routing_domain_id=routing_domain_id,
            source_provenance=source_provenance,
            community_id_seed=community_id_seed,
        )
        self._lines = lines
        self._close_resource = close_resource
        self._total_raw_records = 0
        self._valid_records = 0
        self._skipped_records = 0
        self._ignored_non_alert_records = 0
        self._warning_counts: Dict[str, int] = {}
        self._sample_errors: List[str] = []
        self._logged_warnings = 0
        self._warning_log_suppressed = False
        self._closed = False

    @property
    def summary(self) -> SuricataIngestionSummary:
        """Return a snapshot SuricataIngestionSummary of records processed so far."""
        return SuricataIngestionSummary(
            total_raw_records=self._total_raw_records,
            valid_records=self._valid_records,
            skipped_records=self._skipped_records,
            ignored_non_alert_records=self._ignored_non_alert_records,
            warning_counts=dict(self._warning_counts),
            sample_errors=tuple(self._sample_errors),
        )

    def close(self) -> None:
        """Close underlying file handle if owned by this stream."""
        if not self._closed:
            self._closed = True
            if self._close_resource is not None:
                self._close_resource.close()

    def __enter__(self) -> "SuricataEveAlertStream":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _record_warning(self, reason: str, detail: str) -> None:
        self._warning_counts[reason] = self._warning_counts.get(reason, 0) + 1
        if len(self._sample_errors) < MAX_SAMPLE_ERRORS:
            self._sample_errors.append(f"{reason}: {detail}")
        if self._logged_warnings < MAX_LOGGED_WARNINGS:
            self._logged_warnings += 1
            logger.warning("Suricata EVE parse warning [%s]: %s", reason, detail)
        elif not self._warning_log_suppressed:
            self._warning_log_suppressed = True
            logger.warning(
                "Suricata EVE parse warning limit (%d) reached; suppressing further per-record warning logs "
                "(exact totals remain tracked in SuricataIngestionSummary.warning_counts)",
                MAX_LOGGED_WARNINGS,
            )

    def _parse_alert_entry(
        self,
        entry: Dict[str, Any],
        line_no: int,
    ) -> Optional[SuricataAlertObservation]:
        # 1. Required ISO 8601 timestamp
        raw_ts = entry.get("timestamp")
        if raw_ts is None or (isinstance(raw_ts, str) and not raw_ts.strip()):
            self._record_warning("missing_timestamp", f"Line {line_no} missing required 'timestamp'")
            return None

        timestamp_source, timestamp_epoch_decimal, ts_ok = _parse_suricata_timestamp(raw_ts)
        if not ts_ok or timestamp_source is None:
            self._record_warning("invalid_timestamp", f"Line {line_no} has invalid 'timestamp': {raw_ts!r}")
            return None

        # 2. Required nested 'alert' object
        raw_alert = entry.get("alert")
        if raw_alert is None:
            self._record_warning("missing_alert_object", f"Line {line_no} missing required 'alert' object")
            return None
        if not isinstance(raw_alert, dict):
            self._record_warning(
                "invalid_alert_object",
                f"Line {line_no} 'alert' must be a JSON object, got {type(raw_alert).__name__}",
            )
            return None

        # 3. Required alert.signature_id (sid)
        raw_sid = raw_alert.get("signature_id")
        if raw_sid is None or (isinstance(raw_sid, str) and not raw_sid.strip()):
            self._record_warning("missing_signature_id", f"Line {line_no} missing required 'alert.signature_id'")
            return None
        sid, sid_ok = _parse_non_negative_int(raw_sid)
        if not sid_ok or sid is None:
            self._record_warning(
                "invalid_signature_id",
                f"Line {line_no} has invalid 'alert.signature_id': {raw_sid!r}",
            )
            return None

        # 4. Optional alert.gid (NEVER replace absent GID with 1; invalid GID rejects alert to protect definition ID)
        gid, gid_ok = _parse_non_negative_int(raw_alert.get("gid"))
        if not gid_ok:
            self._record_warning(
                "invalid_gid",
                f"Line {line_no} has invalid 'alert.gid': {raw_alert.get('gid')!r}",
            )
            return None

        # 5. Required source and destination IPs ('src_ip', 'dest_ip')
        raw_src_ip = entry.get("src_ip")
        raw_dst_ip = entry.get("dest_ip")
        if (
            raw_src_ip is None
            or raw_dst_ip is None
            or (isinstance(raw_src_ip, str) and not raw_src_ip.strip())
            or (isinstance(raw_dst_ip, str) and not raw_dst_ip.strip())
        ):
            self._record_warning("missing_ip", f"Line {line_no} missing required 'src_ip' or 'dest_ip'")
            return None

        if not isinstance(raw_src_ip, str):
            self._record_warning("invalid_src_ip", f"Line {line_no} has non-string 'src_ip': {raw_src_ip!r}")
            return None
        try:
            src_ip_obj = ipaddress.ip_address(raw_src_ip.strip())
        except ValueError:
            self._record_warning("invalid_src_ip", f"Line {line_no} has invalid 'src_ip': '{raw_src_ip}'")
            return None

        if not isinstance(raw_dst_ip, str):
            self._record_warning("invalid_dst_ip", f"Line {line_no} has non-string 'dest_ip': {raw_dst_ip!r}")
            return None
        try:
            dst_ip_obj = ipaddress.ip_address(raw_dst_ip.strip())
        except ValueError:
            self._record_warning("invalid_dst_ip", f"Line {line_no} has invalid 'dest_ip': '{raw_dst_ip}'")
            return None

        if src_ip_obj.version != dst_ip_obj.version:
            self._record_warning(
                "mismatched_ip_version",
                f"Line {line_no} mismatched IP versions: IPv{src_ip_obj.version} -> IPv{dst_ip_obj.version}",
            )
            return None

        canonical_src = str(src_ip_obj)
        canonical_dst = str(dst_ip_obj)

        # 6. Optional transport protocol ('proto')
        raw_proto, proto_ok = _parse_optional_str(entry.get("proto"))
        if not proto_ok:
            self._record_warning("invalid_protocol", f"Line {line_no} has non-string 'proto': {entry.get('proto')!r}")
            protocol: Optional[str] = None
        else:
            protocol = raw_proto.upper() if raw_proto is not None else None

        # 7. Optional transport ports ('src_port', 'dest_port') — malformed ports skip alert to protect tuple identity
        src_port, src_port_ok = _parse_port(entry.get("src_port"))
        if not src_port_ok:
            self._record_warning(
                "invalid_src_port",
                f"Line {line_no} has invalid 'src_port': {entry.get('src_port')!r}",
            )
            return None

        dst_port, dst_port_ok = _parse_port(entry.get("dest_port"))
        if not dst_port_ok:
            self._record_warning(
                "invalid_dst_port",
                f"Line {line_no} has invalid 'dest_port': {entry.get('dest_port')!r}",
            )
            return None

        # 8. Optional alert metadata fields (rev, signature, category, severity, action, metadata)
        rev, rev_ok = _parse_non_negative_int(raw_alert.get("rev"))
        if not rev_ok:
            self._record_warning(
                "invalid_alert_metadata",
                f"Line {line_no} has invalid 'alert.rev': {raw_alert.get('rev')!r}",
            )
            rev = None

        severity, sev_ok = _parse_non_negative_int(raw_alert.get("severity"))
        if not sev_ok:
            self._record_warning(
                "invalid_alert_metadata",
                f"Line {line_no} has invalid 'alert.severity': {raw_alert.get('severity')!r}",
            )
            severity = None

        signature, sig_ok = _parse_optional_str(raw_alert.get("signature"))
        if not sig_ok:
            self._record_warning(
                "invalid_alert_metadata",
                f"Line {line_no} has invalid 'alert.signature': {raw_alert.get('signature')!r}",
            )
            signature = None

        category, cat_ok = _parse_optional_str(raw_alert.get("category"))
        if not cat_ok:
            self._record_warning(
                "invalid_alert_metadata",
                f"Line {line_no} has invalid 'alert.category': {raw_alert.get('category')!r}",
            )
            category = None

        action, act_ok = _parse_optional_str(raw_alert.get("action"))
        if not act_ok:
            self._record_warning(
                "invalid_alert_metadata",
                f"Line {line_no} has invalid 'alert.action': {raw_alert.get('action')!r}",
            )
            action = None

        raw_meta = raw_alert.get("metadata")
        if raw_meta is not None and not isinstance(raw_meta, dict):
            self._record_warning(
                "invalid_alert_metadata",
                f"Line {line_no} has non-object 'alert.metadata': {type(raw_meta).__name__}",
            )

        # 9. Optional top-level EVE numeric/string context fields
        flow_id, flow_id_ok = _parse_non_negative_int(entry.get("flow_id"))
        if not flow_id_ok:
            self._record_warning(
                "invalid_numeric_field",
                f"Line {line_no} has invalid 'flow_id': {entry.get('flow_id')!r}",
            )
            flow_id = None

        tx_id, tx_id_ok = _parse_non_negative_int(entry.get("tx_id"))
        if not tx_id_ok:
            self._record_warning(
                "invalid_numeric_field",
                f"Line {line_no} has invalid 'tx_id': {entry.get('tx_id')!r}",
            )
            tx_id = None

        pcap_cnt, pcap_cnt_ok = _parse_non_negative_int(entry.get("pcap_cnt"))
        if not pcap_cnt_ok:
            self._record_warning(
                "invalid_numeric_field",
                f"Line {line_no} has invalid 'pcap_cnt': {entry.get('pcap_cnt')!r}",
            )
            pcap_cnt = None

        app_proto, app_proto_ok = _parse_optional_str(entry.get("app_proto"))
        if not app_proto_ok:
            self._record_warning(
                "invalid_optional_field",
                f"Line {line_no} has invalid 'app_proto': {entry.get('app_proto')!r}",
            )
            app_proto = None

        direction, dir_ok = _parse_optional_str(entry.get("direction"))
        if not dir_ok:
            self._record_warning(
                "invalid_optional_field",
                f"Line {line_no} has invalid 'direction': {entry.get('direction')!r}",
            )
            direction = None

        # 10. Optional existing Community ID (strictly string; never use flow_id as Community ID)
        raw_cid = entry.get("community_id")
        existing_cid: Optional[str] = None
        if raw_cid is not None:
            if isinstance(raw_cid, str):
                cleaned_cid = raw_cid.strip()
                existing_cid = cleaned_cid if cleaned_cid else None
            else:
                self._record_warning(
                    "invalid_community_id",
                    f"Line {line_no} has non-string 'community_id': {raw_cid!r}",
                )

        # 11. Scoped IP identity, V2 directional flow_key, AlertDefinition ID, and AlertEvent ID
        src_scoped = scoped_ip_id(self._routing_domain_id, canonical_src)
        dst_scoped = scoped_ip_id(self._routing_domain_id, canonical_dst)
        flow_key = compute_v2_flow_key(
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            protocol=protocol or "UNKNOWN",
            src_port=src_port,
            dst_port=dst_port,
        )

        def_id = alert_definition_id(
            engine="suricata",
            ruleset_namespace=self._ruleset_namespace,
            gid=gid,
            sid=sid,
        )

        record_fingerprint = _compute_record_fingerprint(entry)
        source_record_id = f"{self._log_source_id}:line:{line_no}:{record_fingerprint}"

        event_id = compute_alert_event_id(
            source_type="suricata",
            sensor_id=self._sensor_id,
            source_record_id=source_record_id,
            timestamp=timestamp_source,
            def_id=def_id,
            flow_reference=flow_key,
            source_provenance=self._source_provenance,
        )

        # 12. Community ID resolution (preserve verbatim or compute when tuple is sufficient)
        cid_proto: Optional[str] = None
        cid_src_port: Optional[int] = src_port
        cid_dst_port: Optional[int] = dst_port

        if protocol is not None:
            if protocol in _PORT_TRANSPORT_PROTOS:
                if src_port is not None and dst_port is not None:
                    cid_proto = protocol
            elif protocol in _ICMP_PROTOS:
                # Suricata EVE encodes ICMP type/code in top-level icmp_type / icmp_code (not ports).
                # Never fabricate 0/0 when absent or out of 0..255 bounds.
                icmp_type, icmp_type_ok = _parse_non_negative_int(entry.get("icmp_type"))
                icmp_code, icmp_code_ok = _parse_non_negative_int(entry.get("icmp_code"))
                if (
                    icmp_type_ok
                    and icmp_code_ok
                    and icmp_type is not None
                    and icmp_code is not None
                    and 0 <= icmp_type <= 255
                    and 0 <= icmp_code <= 255
                ):
                    cid_proto = (
                        "ICMP6"
                        if (protocol in {"ICMP6", "ICMPV6", "IPV6-ICMP"} or src_ip_obj.version == 6)
                        else "ICMP"
                    )
                    cid_src_port = icmp_type
                    cid_dst_port = icmp_code
            else:
                self._record_warning(
                    "unsupported_protocol",
                    f"Line {line_no} has unsupported protocol '{protocol}' for Community ID computation",
                )

        community_id = resolve_community_id(
            existing_id=existing_cid,
            ip_src=canonical_src,
            ip_dst=canonical_dst,
            protocol=cid_proto,
            src_port=cid_src_port,
            dst_port=cid_dst_port,
            seed=self._community_id_seed,
        )

        return SuricataAlertObservation(
            event_id=event_id,
            alert_definition_id=def_id,
            source_record_id=source_record_id,
            log_source_id=self._log_source_id,
            sensor_id=self._sensor_id,
            ruleset_namespace=self._ruleset_namespace,
            routing_domain_id=self._routing_domain_id,
            flow_key=flow_key,
            src_ip=canonical_src,
            dst_ip=canonical_dst,
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            timestamp_source=timestamp_source,
            sid=sid,
            source_type="suricata",
            source_provenance=self._source_provenance,
            timestamp_epoch_decimal=timestamp_epoch_decimal,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
            community_id=community_id,
            gid=gid,
            rev=rev,
            signature=signature,
            category=category,
            severity=severity,
            action=action,
            app_proto=app_proto,
            direction=direction,
            tx_id=tx_id,
            pcap_cnt=pcap_cnt,
        )

    def __iter__(self) -> Iterator[SuricataAlertObservation]:
        try:
            for line_no, raw_line in enumerate(self._lines, start=1):
                stripped = raw_line.strip()
                if not stripped:
                    # Empty / whitespace-only JSONL lines are ignored cleanly
                    continue

                self._total_raw_records += 1

                try:
                    parsed = json.loads(stripped, parse_float=Decimal)
                except json.JSONDecodeError as exc:
                    self._record_warning("malformed_json", f"Line {line_no} malformed JSON: {exc.msg}")
                    self._skipped_records += 1
                    continue

                if not isinstance(parsed, dict):
                    self._record_warning(
                        "invalid_record_format",
                        f"Line {line_no} expected JSON object, got {type(parsed).__name__}",
                    )
                    self._skipped_records += 1
                    continue

                raw_event_type = parsed.get("event_type")
                if raw_event_type is None or (isinstance(raw_event_type, str) and not raw_event_type.strip()):
                    self._record_warning("missing_event_type", f"Line {line_no} missing required 'event_type'")
                    self._skipped_records += 1
                    continue
                if not isinstance(raw_event_type, str):
                    self._record_warning(
                        "invalid_event_type",
                        f"Line {line_no} has non-string 'event_type': {raw_event_type!r}",
                    )
                    self._skipped_records += 1
                    continue

                if raw_event_type.strip().lower() != "alert":
                    # Valid non-alert EVE event types (flow, dns, http, tls, stats, etc.) are ignored cleanly
                    self._ignored_non_alert_records += 1
                    continue

                observation = self._parse_alert_entry(parsed, line_no)
                if observation is None:
                    self._skipped_records += 1
                    continue

                self._valid_records += 1
                yield observation
        finally:
            self.close()


def iter_suricata_eve_alert_lines(
    lines: Iterable[str],
    *,
    sensor_id: str,
    ruleset_namespace: str,
    log_source_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
) -> SuricataEveAlertStream:
    """Create a streaming SuricataEveAlertStream over an iterable of EVE JSONL lines."""
    return SuricataEveAlertStream(
        lines,
        sensor_id=sensor_id,
        ruleset_namespace=ruleset_namespace,
        log_source_id=log_source_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    )


def stream_suricata_eve_alerts(
    file_path: Union[str, os.PathLike[str]],
    *,
    sensor_id: str,
    ruleset_namespace: str,
    log_source_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
) -> SuricataEveAlertStream:
    """Open a Suricata EVE JSONL file and return a bounded-memory SuricataEveAlertStream.

    Validates configuration and opens the file eagerly so missing/unreadable files
    and invalid parser parameters fail immediately rather than mid-iteration.

    Raises:
        FileNotFoundError: If file_path does not exist.
        ValueError: If file_path is a directory or parser configuration is invalid.
        OSError: If file_path cannot be opened for reading.
    """
    _validate_parser_config(
        sensor_id=sensor_id,
        ruleset_namespace=ruleset_namespace,
        log_source_id=log_source_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    )

    path_str = os.fspath(file_path)
    if not os.path.exists(path_str):
        raise FileNotFoundError(f"Suricata EVE file not found: {path_str}")
    if os.path.isdir(path_str):
        raise ValueError(f"Suricata EVE path is a directory, expected a file: {path_str}")

    fh = open(path_str, "r", encoding="utf-8")
    return SuricataEveAlertStream(
        fh,
        sensor_id=sensor_id,
        ruleset_namespace=ruleset_namespace,
        log_source_id=log_source_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
        close_resource=fh,
    )


def parse_suricata_eve_alert_file(
    file_path: Union[str, os.PathLike[str]],
    *,
    sensor_id: str,
    ruleset_namespace: str,
    log_source_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
) -> Tuple[List[SuricataAlertObservation], SuricataIngestionSummary]:
    """Parse a Suricata EVE JSONL file into normalized alert observations and SuricataIngestionSummary.

    Streams the file line-by-line via `stream_suricata_eve_alerts()` and collects valid
    `SuricataAlertObservation` records alongside deterministic warning/error and non-alert telemetry.
    For very large EVE files, consume `stream_suricata_eve_alerts()` directly for O(1) memory.
    """
    logger.info(
        "Parsing Suricata EVE alerts from: %s (sensor_id=%s, namespace=%s, log_source_id=%s, domain=%s)",
        os.fspath(file_path),
        sensor_id,
        ruleset_namespace,
        log_source_id,
        routing_domain_id,
    )
    with stream_suricata_eve_alerts(
        file_path=file_path,
        sensor_id=sensor_id,
        ruleset_namespace=ruleset_namespace,
        log_source_id=log_source_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    ) as stream:
        records = list(stream)
        summary = stream.summary

    logger.info(
        "Suricata EVE alert parsing complete: %d raw -> %d valid (%d skipped, %d non-alert ignored).",
        summary.total_raw_records,
        summary.valid_records,
        summary.skipped_records,
        summary.ignored_non_alert_records,
    )
    return records, summary
