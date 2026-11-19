"""
Streaming parser and normalizer for Zeek conn.log newline-delimited JSON (JSONL).

Transforms standard Zeek Conn::Info JSON records into immutable, Neo4j-independent
ZeekConnectionObservation records with:
- Lossless JSON numeric timestamp precision via parse_float=Decimal
- Explicit RoutingDomain scoping via scoped_ip_id() (never inferred from IP or sensor)
- Deterministic V2 directional flow_key and observation_id via existing V2 primitives
- Separate native zeek_uid and Community ID v1 correlation identifier
- Distinct directional originator/responder payload vs IP-level byte and packet metrics
- Bounded-memory line-by-line streaming with deterministic warning diagnostics
"""

from datetime import datetime
from decimal import Decimal, InvalidOperation
import ipaddress
import json
import logging
import os
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from src.ingestion.community_id import resolve_community_id
from src.ingestion.models import IngestionSummary
from src.ingestion.v2_models import (
    ZeekConnectionObservation,
    canonicalize_event_timestamp,
    compute_observation_id,
    compute_v2_flow_key,
    scoped_ip_id,
)

logger = logging.getLogger(__name__)

MAX_SAMPLE_ERRORS = 10

# Supported transport protocols for Community ID tuple computation.
_SUPPORTED_TRANSPORT_PROTOS = frozenset({"TCP", "UDP", "ICMP", "ICMP6", "ICMPV6", "SCTP"})

# Strict ISO 8601 timestamp pattern compatible with Python 3.10+ (supports Z and up to 9 fractional digits).
_ISO_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d{1,9}))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


def _validate_parser_config(
    sensor_id: str,
    routing_domain_id: str,
    source_provenance: Optional[str],
    community_id_seed: int,
) -> Tuple[str, str, Optional[str], int]:
    """Validate and normalize Zeek conn.log parser configuration eagerly."""
    if not isinstance(sensor_id, str) or not sensor_id.strip():
        raise ValueError("sensor_id must be a non-empty string")
    norm_sensor_id = sensor_id.strip().lower()

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

    return norm_sensor_id, norm_domain, norm_provenance, community_id_seed


def _parse_zeek_timestamp(raw_ts: Any) -> Tuple[Optional[str], Optional[Decimal], Optional[Union[Decimal, str]]]:
    """Parse and validate a Zeek 'ts' value without losing numeric precision.

    Accepts:
        - JSON numeric epoch timestamps parsed as int or Decimal (from parse_float=Decimal)
        - Numeric decimal epoch strings (e.g. '1725148800.123456789')
        - ISO 8601 timestamp strings (e.g. '2024-09-01T12:00:00.123456789Z')

    Returns:
        Tuple of (canonical_ts_str, start_epoch_decimal_or_None, identity_timestamp_input),
        or (None, None, None) if invalid.
    """
    if raw_ts is None or isinstance(raw_ts, bool):
        return None, None, None

    if isinstance(raw_ts, (int, Decimal)):
        dec_val = Decimal(raw_ts) if isinstance(raw_ts, int) else raw_ts
        if dec_val.is_nan() or dec_val.is_infinite() or dec_val < 0:
            return None, None, None
        return canonicalize_event_timestamp(dec_val), dec_val, dec_val

    if isinstance(raw_ts, float):
        # Fallback if a caller passes a pre-parsed Python dict containing float
        try:
            dec_val = Decimal(str(raw_ts))
        except InvalidOperation:
            return None, None, None
        if dec_val.is_nan() or dec_val.is_infinite() or dec_val < 0:
            return None, None, None
        return canonicalize_event_timestamp(dec_val), dec_val, dec_val

    if isinstance(raw_ts, str):
        trimmed = raw_ts.strip()
        if not trimmed:
            return None, None, None

        # First try exact Decimal numeric epoch string
        try:
            dec_val = Decimal(trimmed)
            if dec_val.is_nan() or dec_val.is_infinite() or dec_val < 0:
                return None, None, None
            return canonicalize_event_timestamp(dec_val), dec_val, dec_val
        except InvalidOperation:
            pass

        # Otherwise validate strict ISO 8601 format (Python 3.10+ compatible)
        match = _ISO_TIMESTAMP_PATTERN.match(trimmed)
        if not match:
            return None, None, None

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
            return None, None, None

        start_epoch: Optional[Decimal] = None
        if dt.tzinfo is not None:
            whole_seconds = Decimal(int(dt.timestamp()))
            frac_seconds = Decimal(f"0.{frac_part}") if frac_part else Decimal(0)
            start_epoch = whole_seconds + frac_seconds
            if start_epoch < 0:
                return None, None, None

        return canonicalize_event_timestamp(trimmed), start_epoch, trimmed

    return None, None, None


def _parse_non_negative_decimal(raw_val: Any) -> Optional[Decimal]:
    """Parse an optional non-negative finite Decimal (e.g. Zeek duration)."""
    if raw_val is None or isinstance(raw_val, bool):
        return None
    if isinstance(raw_val, Decimal):
        if raw_val.is_nan() or raw_val.is_infinite() or raw_val < 0:
            return None
        return raw_val
    if isinstance(raw_val, int):
        return Decimal(raw_val) if raw_val >= 0 else None
    if isinstance(raw_val, float):
        try:
            dec_val = Decimal(str(raw_val))
        except InvalidOperation:
            return None
        if dec_val.is_nan() or dec_val.is_infinite() or dec_val < 0:
            return None
        return dec_val
    if isinstance(raw_val, str):
        trimmed = raw_val.strip()
        if not trimmed:
            return None
        try:
            dec_val = Decimal(trimmed)
        except InvalidOperation:
            return None
        if dec_val.is_nan() or dec_val.is_infinite() or dec_val < 0:
            return None
        return dec_val
    return None


def _parse_port(raw_val: Any) -> Tuple[Optional[int], bool]:
    """Parse a Zeek port field (0..65535 or absent).

    Returns:
        (parsed_port_or_None, is_valid).
        Absent/None returns (None, True). Malformed or out-of-range returns (None, False).
    """
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
            port_val = int(trimmed)
            return (port_val, True) if 0 <= port_val <= 65535 else (None, False)
        return None, False
    return None, False


def _parse_non_negative_int(raw_val: Any) -> Tuple[Optional[int], bool]:
    """Parse an optional Zeek non-negative integer counter.

    Returns:
        (parsed_int_or_None, is_valid).
        Absent/None returns (None, True). Invalid/negative/fractional returns (None, False).
    """
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
    """Parse an optional Zeek string metadata field.

    Returns:
        (trimmed_str_or_None, is_valid).
    """
    if raw_val is None:
        return None, True
    if not isinstance(raw_val, str):
        return None, False
    trimmed = raw_val.strip()
    return (trimmed if trimmed else None), True


def _parse_optional_bool(raw_val: Any) -> Tuple[Optional[bool], bool]:
    """Parse an optional Zeek boolean metadata field (local_orig / local_resp)."""
    if raw_val is None:
        return None, True
    if isinstance(raw_val, bool):
        return raw_val, True
    return None, False


class ZeekConnStream:
    """Streaming iterator over Zeek conn.log JSONL records with deterministic summary metrics.

    Reads one line at a time without buffering the entire file in memory.
    Can be iterated directly or used as a context manager (`with stream_zeek_conn_file(...) as s:`).
    Inspect `.summary` after iteration to obtain `IngestionSummary` counts and warnings.
    """

    def __init__(
        self,
        lines: Iterable[str],
        *,
        sensor_id: str,
        routing_domain_id: str = "default",
        source_provenance: Optional[str] = None,
        community_id_seed: int = 0,
        close_resource: Optional[Any] = None,
    ):
        (
            self._sensor_id,
            self._routing_domain_id,
            self._source_provenance,
            self._community_id_seed,
        ) = _validate_parser_config(
            sensor_id=sensor_id,
            routing_domain_id=routing_domain_id,
            source_provenance=source_provenance,
            community_id_seed=community_id_seed,
        )
        self._lines = lines
        self._close_resource = close_resource
        self._total_raw_records = 0
        self._valid_records = 0
        self._skipped_records = 0
        self._warning_counts: Dict[str, int] = {}
        self._sample_errors: List[str] = []
        self._closed = False

    @property
    def summary(self) -> IngestionSummary:
        """Return a snapshot IngestionSummary of records processed so far."""
        return IngestionSummary(
            total_raw_records=self._total_raw_records,
            valid_records=self._valid_records,
            skipped_records=self._skipped_records,
            duplicate_records=0,
            warning_counts=dict(self._warning_counts),
            sample_errors=tuple(self._sample_errors),
        )

    def close(self) -> None:
        """Close underlying file handle if owned by this stream."""
        if not self._closed:
            self._closed = True
            if self._close_resource is not None:
                self._close_resource.close()

    def __enter__(self) -> "ZeekConnStream":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _record_warning(self, reason: str, detail: str) -> None:
        self._warning_counts[reason] = self._warning_counts.get(reason, 0) + 1
        if len(self._sample_errors) < MAX_SAMPLE_ERRORS:
            self._sample_errors.append(f"{reason}: {detail}")
        logger.warning("Zeek conn parse warning [%s]: %s", reason, detail)

    def _parse_entry(self, entry: Dict[str, Any], line_no: int) -> Optional[ZeekConnectionObservation]:
        # 1. Required timestamp ('ts') with lossless precision
        if "ts" not in entry or entry["ts"] is None or (isinstance(entry["ts"], str) and not entry["ts"].strip()):
            self._record_warning("missing_timestamp", f"Line {line_no} missing required 'ts'")
            return None

        start_ts, start_epoch, ts_for_identity = _parse_zeek_timestamp(entry["ts"])
        if start_ts is None or ts_for_identity is None:
            self._record_warning("invalid_timestamp", f"Line {line_no} has invalid 'ts': {entry['ts']!r}")
            return None

        # 2. Required native Zeek UID ('uid')
        raw_uid = entry.get("uid")
        if raw_uid is None or (isinstance(raw_uid, str) and not raw_uid.strip()):
            self._record_warning("missing_uid", f"Line {line_no} missing required 'uid'")
            return None
        if not isinstance(raw_uid, str):
            self._record_warning("invalid_uid", f"Line {line_no} has non-string 'uid': {raw_uid!r}")
            return None
        zeek_uid = raw_uid.strip()

        # 3. Required IP endpoints ('id.orig_h', 'id.resp_h')
        raw_src_ip = entry.get("id.orig_h")
        raw_dst_ip = entry.get("id.resp_h")
        if (
            raw_src_ip is None
            or raw_dst_ip is None
            or (isinstance(raw_src_ip, str) and not raw_src_ip.strip())
            or (isinstance(raw_dst_ip, str) and not raw_dst_ip.strip())
        ):
            self._record_warning("missing_ip", f"Line {line_no} missing required 'id.orig_h' or 'id.resp_h'")
            return None

        if not isinstance(raw_src_ip, str):
            self._record_warning("invalid_src_ip", f"Line {line_no} has non-string 'id.orig_h': {raw_src_ip!r}")
            return None
        try:
            src_ip_obj = ipaddress.ip_address(raw_src_ip.strip())
        except ValueError:
            self._record_warning("invalid_src_ip", f"Line {line_no} has invalid 'id.orig_h': '{raw_src_ip}'")
            return None

        if not isinstance(raw_dst_ip, str):
            self._record_warning("invalid_dst_ip", f"Line {line_no} has non-string 'id.resp_h': {raw_dst_ip!r}")
            return None
        try:
            dst_ip_obj = ipaddress.ip_address(raw_dst_ip.strip())
        except ValueError:
            self._record_warning("invalid_dst_ip", f"Line {line_no} has invalid 'id.resp_h': '{raw_dst_ip}'")
            return None

        if src_ip_obj.version != dst_ip_obj.version:
            self._record_warning(
                "mismatched_ip_version",
                f"Line {line_no} mismatched IP versions: IPv{src_ip_obj.version} -> IPv{dst_ip_obj.version}",
            )
            return None

        canonical_src = str(src_ip_obj)
        canonical_dst = str(dst_ip_obj)

        # 4. Required transport protocol ('proto')
        raw_proto = entry.get("proto")
        if raw_proto is None or (isinstance(raw_proto, str) and not raw_proto.strip()):
            self._record_warning("missing_protocol", f"Line {line_no} missing required 'proto'")
            return None
        if not isinstance(raw_proto, str):
            self._record_warning("invalid_protocol", f"Line {line_no} has non-string 'proto': {raw_proto!r}")
            return None

        protocol = raw_proto.strip().upper()
        is_supported_proto = protocol in _SUPPORTED_TRANSPORT_PROTOS
        if not is_supported_proto:
            self._record_warning(
                "unsupported_protocol",
                f"Line {line_no} has unsupported transport protocol '{protocol}' (Community ID will not be fabricated)",
            )

        # 5. Optional transport ports ('id.orig_p', 'id.resp_p') — malformed values reject record to preserve identity
        src_port, src_port_ok = _parse_port(entry.get("id.orig_p"))
        if not src_port_ok:
            self._record_warning(
                "invalid_src_port",
                f"Line {line_no} has invalid 'id.orig_p': {entry.get('id.orig_p')!r}",
            )
            return None

        dst_port, dst_port_ok = _parse_port(entry.get("id.resp_p"))
        if not dst_port_ok:
            self._record_warning(
                "invalid_dst_port",
                f"Line {line_no} has invalid 'id.resp_p': {entry.get('id.resp_p')!r}",
            )
            return None

        # 6. Optional duration and derived end time (never fabricated if duration absent or invalid)
        duration: Optional[Decimal] = None
        end_epoch: Optional[Decimal] = None
        end_ts: Optional[str] = None
        raw_duration = entry.get("duration")
        if raw_duration is not None and not (isinstance(raw_duration, str) and not raw_duration.strip()):
            parsed_dur = _parse_non_negative_decimal(raw_duration)
            if parsed_dur is None:
                self._record_warning(
                    "invalid_duration",
                    f"Line {line_no} has invalid 'duration': {raw_duration!r}",
                )
            else:
                duration = parsed_dur
                if start_epoch is not None:
                    end_epoch = start_epoch + duration
                    end_ts = canonicalize_event_timestamp(end_epoch)

        # 7. Optional directional numeric metrics (preserve payload vs IP bytes; never invent 0)
        metric_values: Dict[str, Optional[int]] = {}
        for field_name in (
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "orig_ip_bytes",
            "resp_ip_bytes",
            "missed_bytes",
        ):
            raw_metric = entry.get(field_name)
            parsed_metric, metric_ok = _parse_non_negative_int(raw_metric)
            if not metric_ok:
                self._record_warning(
                    "invalid_metric",
                    f"Line {line_no} has invalid '{field_name}': {raw_metric!r}",
                )
                metric_values[field_name] = None
            else:
                metric_values[field_name] = parsed_metric

        # 8. Optional Zeek metadata fields
        str_values: Dict[str, Optional[str]] = {}
        for field_name in ("service", "conn_state", "history"):
            parsed_str, str_ok = _parse_optional_str(entry.get(field_name))
            if not str_ok:
                self._record_warning(
                    "invalid_optional_field",
                    f"Line {line_no} has invalid '{field_name}': {entry.get(field_name)!r}",
                )
                str_values[field_name] = None
            else:
                str_values[field_name] = parsed_str

        bool_values: Dict[str, Optional[bool]] = {}
        for field_name in ("local_orig", "local_resp"):
            parsed_bool, bool_ok = _parse_optional_bool(entry.get(field_name))
            if not bool_ok:
                self._record_warning(
                    "invalid_optional_field",
                    f"Line {line_no} has invalid '{field_name}': {entry.get(field_name)!r}",
                )
                bool_values[field_name] = None
            else:
                bool_values[field_name] = parsed_bool

        # 9. Deterministic V2 identities using existing identity primitives
        src_scoped = scoped_ip_id(self._routing_domain_id, canonical_src)
        dst_scoped = scoped_ip_id(self._routing_domain_id, canonical_dst)
        flow_key = compute_v2_flow_key(
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
        )
        observation_id = compute_observation_id(
            source_type="zeek",
            sensor_id=self._sensor_id,
            source_record_id=zeek_uid,
            timestamp=ts_for_identity,
            flow_key=flow_key,
            source_provenance=self._source_provenance,
        )

        # 10. Community ID correlation via existing adapter (never incorporates sensor/domain/VLAN)
        raw_cid = entry.get("community_id")
        existing_cid: Optional[str] = None
        if raw_cid is not None:
            if isinstance(raw_cid, str):
                existing_cid = raw_cid.strip() or None
            else:
                self._record_warning(
                    "invalid_community_id",
                    f"Line {line_no} has non-string 'community_id': {raw_cid!r}",
                )

        cid_proto: Optional[str] = None
        if is_supported_proto:
            if protocol in {"ICMP", "ICMP6", "ICMPV6"}:
                # Require valid ICMP type/code (0..255) rather than fabricating 0/0
                if (
                    src_port is not None
                    and dst_port is not None
                    and 0 <= src_port <= 255
                    and 0 <= dst_port <= 255
                ):
                    cid_proto = "ICMP6" if (protocol == "ICMP" and src_ip_obj.version == 6) else protocol
            else:
                cid_proto = protocol

        community_id = resolve_community_id(
            existing_id=existing_cid,
            ip_src=canonical_src,
            ip_dst=canonical_dst,
            protocol=cid_proto,
            src_port=src_port,
            dst_port=dst_port,
            seed=self._community_id_seed,
        )

        return ZeekConnectionObservation(
            observation_id=observation_id,
            flow_key=flow_key,
            zeek_uid=zeek_uid,
            routing_domain_id=self._routing_domain_id,
            src_scoped_id=src_scoped,
            dst_scoped_id=dst_scoped,
            src_ip=canonical_src,
            dst_ip=canonical_dst,
            protocol=protocol,
            start_ts=start_ts,
            src_port=src_port,
            dst_port=dst_port,
            community_id=community_id,
            start_epoch=start_epoch,
            duration=duration,
            end_epoch=end_epoch,
            end_ts=end_ts,
            orig_bytes=metric_values["orig_bytes"],
            resp_bytes=metric_values["resp_bytes"],
            orig_pkts=metric_values["orig_pkts"],
            resp_pkts=metric_values["resp_pkts"],
            orig_ip_bytes=metric_values["orig_ip_bytes"],
            resp_ip_bytes=metric_values["resp_ip_bytes"],
            missed_bytes=metric_values["missed_bytes"],
            service=str_values["service"],
            conn_state=str_values["conn_state"],
            history=str_values["history"],
            local_orig=bool_values["local_orig"],
            local_resp=bool_values["local_resp"],
            sensor_id=self._sensor_id,
            source_type="zeek",
            source_provenance=self._source_provenance,
        )

    def __iter__(self) -> Iterator[ZeekConnectionObservation]:
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

                observation = self._parse_entry(parsed, line_no)
                if observation is None:
                    self._skipped_records += 1
                    continue

                self._valid_records += 1
                yield observation
        finally:
            self.close()


def iter_zeek_conn_lines(
    lines: Iterable[str],
    sensor_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
) -> ZeekConnStream:
    """Create a streaming ZeekConnStream over an iterable of JSONL lines."""
    return ZeekConnStream(
        lines,
        sensor_id=sensor_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    )


def stream_zeek_conn_file(
    file_path: Union[str, os.PathLike[str]],
    sensor_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
) -> ZeekConnStream:
    """Open a Zeek conn.log JSONL file and return a bounded-memory ZeekConnStream.

    Validates configuration and opens the file eagerly so missing/unreadable files
    and invalid parser parameters fail immediately rather than mid-iteration.

    Raises:
        FileNotFoundError: If file_path does not exist.
        ValueError: If file_path is a directory or parser configuration is invalid.
        OSError: If file_path cannot be opened for reading.
    """
    # Validate configuration before opening file
    _validate_parser_config(
        sensor_id=sensor_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    )

    path_str = os.fspath(file_path)
    if not os.path.exists(path_str):
        raise FileNotFoundError(f"Zeek conn.log file not found: {path_str}")
    if os.path.isdir(path_str):
        raise ValueError(f"Zeek conn.log path is a directory, expected a file: {path_str}")

    fh = open(path_str, "r", encoding="utf-8")
    return ZeekConnStream(
        fh,
        sensor_id=sensor_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
        close_resource=fh,
    )


def parse_zeek_conn_file(
    file_path: Union[str, os.PathLike[str]],
    sensor_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
) -> Tuple[List[ZeekConnectionObservation], IngestionSummary]:
    """Parse a Zeek conn.log JSONL file into normalized observations and IngestionSummary.

    Streams the file line-by-line via stream_zeek_conn_file() and collects valid
    ZeekConnectionObservation records alongside deterministic warning/error telemetry.
    For very large logs, callers can consume stream_zeek_conn_file() directly to
    process records in O(1) memory.
    """
    logger.info(
        "Parsing Zeek conn.log JSONL from: %s (sensor_id=%s, routing_domain_id=%s)",
        os.fspath(file_path),
        sensor_id,
        routing_domain_id,
    )
    with stream_zeek_conn_file(
        file_path=file_path,
        sensor_id=sensor_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    ) as stream:
        records = list(stream)
        summary = stream.summary

    logger.info(
        "Zeek conn.log parsing complete: %d raw -> %d valid (%d skipped).",
        summary.total_raw_records,
        summary.valid_records,
        summary.skipped_records,
    )
    return records, summary
