"""
Unit tests for Zeek conn.log newline-delimited JSON (JSONL) streaming parser.

Covers synthetic deterministic test fixtures for:
A. TCP connection
B. UDP connection
C. IPv6 connection (including RFC 5952 canonicalization)
D. Missing optional fields (represented as None, never invented zeros)
E. Invalid JSON and non-object JSON lines
F. Invalid IP addresses and mismatched IP versions
G. Different Zeek UIDs sharing the same 5-tuple (never collapse)
H. Same file imported twice (identical deterministic observation IDs)
I. Different RoutingDomains with overlapping RFC 1918 IPs
J. Existing community_id preserved opaquely
K. Computed community_id via Community ID v1 adapter (with configurable seed)
L. High-precision nanosecond timestamps (preserved via parse_float=Decimal)
M. Missing or invalid duration (end timestamp never fabricated)
N. Directional payload vs IP-level byte and packet metrics
O. Unknown extra fields ignored cleanly
Plus streaming O(1) iteration, ICMP/ICMPv6 handling, ISO 8601 timestamps,
unsupported protocols, malformed ports, invalid metrics, and strict config errors.
"""

from decimal import Decimal
import json
import logging
from pathlib import Path
import pytest

import src.ingestion as ingestion_pkg
from src.ingestion.community_id import compute_community_id
from src.ingestion.v2_models import (
    ZeekConnectionObservation,
    compute_observation_id,
    compute_v2_flow_key,
    scoped_ip_id,
)
from src.ingestion.zeek_conn_parser import (
    MAX_LOGGED_WARNINGS,
    MAX_SAMPLE_ERRORS,
    iter_zeek_conn_lines,
    parse_zeek_conn_file,
    stream_zeek_conn_file,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "zeek"
STANDARD_FIXTURE = FIXTURE_DIR / "conn_standard.jsonl"
MIXED_ERRORS_FIXTURE = FIXTURE_DIR / "conn_mixed_errors.jsonl"
OVERLAPPING_RFC1918_FIXTURE = FIXTURE_DIR / "conn_overlapping_rfc1918.jsonl"


# ---------------------------------------------------------------------------
# A, B, C, D, G, J, K, L, M, N, O: Standard Synthetic Fixture Tests
# ---------------------------------------------------------------------------

def test_parse_standard_fixture_tcp_udp_ipv6_and_semantics():
    """Verify TCP, UDP, IPv6, directional metrics, extra fields, and Community ID semantics."""
    records, summary = parse_zeek_conn_file(
        STANDARD_FIXTURE,
        sensor_id="Zeek-Core-01",
        routing_domain_id="default",
        source_provenance="synthetic-zeek-suite",
    )

    assert summary.total_raw_records == 5
    assert summary.valid_records == 5
    assert summary.skipped_records == 0
    assert summary.warning_counts == {}
    assert summary.sample_errors == ()
    assert len(records) == 5

    # A, K, L, N, O: TCP record with nanosecond precision, directional metrics, extra fields, computed Community ID
    tcp = records[0]
    assert isinstance(tcp, ZeekConnectionObservation)
    assert tcp.zeek_uid == "CZeekTcp000000001"
    assert tcp.sensor_id == "zeek-core-01"
    assert tcp.source_type == "zeek"
    assert tcp.source_provenance == "synthetic-zeek-suite"
    assert tcp.routing_domain_id == "default"
    assert tcp.src_ip == "128.232.110.120"
    assert tcp.dst_ip == "66.35.250.204"
    assert tcp.src_scoped_id == "default#128.232.110.120"
    assert tcp.dst_scoped_id == "default#66.35.250.204"
    assert tcp.protocol == "TCP"
    assert tcp.src_port == 34855
    assert tcp.dst_port == 80

    # Official Community ID v1 reference vector for (128.232.110.120:34855 -> 66.35.250.204:80 TCP, seed=0)
    assert tcp.community_id == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

    # Nanosecond timestamp precision preserved losslessly via Decimal (NOT float64)
    assert tcp.start_ts == "1725148800.123456789"
    assert tcp.start_epoch == Decimal("1725148800.123456789")
    assert tcp.duration == Decimal("1.250000001")
    assert tcp.end_epoch == Decimal("1725148801.373456790")
    assert tcp.end_ts == "1725148801.37345679"

    # Directional payload vs IP-level byte and packet metrics strictly preserved
    assert tcp.orig_bytes == 512
    assert tcp.resp_bytes == 4096
    assert tcp.orig_ip_bytes == 832
    assert tcp.resp_ip_bytes == 4512
    assert tcp.orig_bytes != tcp.orig_ip_bytes
    assert tcp.resp_bytes != tcp.resp_ip_bytes
    assert tcp.orig_pkts == 6
    assert tcp.resp_pkts == 8
    assert tcp.missed_bytes == 0

    # Zeek metadata preserved; extra fields ('vlan', 'tunnel_parents', 'custom_sensor_tag') ignored cleanly
    assert tcp.service == "http"
    assert tcp.conn_state == "SF"
    assert tcp.history == "ShADadFf"
    assert tcp.local_orig is True
    assert tcp.local_resp is False

    # Identities match existing V2 identity primitives exactly
    expected_flow_key = compute_v2_flow_key("default#128.232.110.120", "default#66.35.250.204", "TCP", 34855, 80)
    expected_obs_id = compute_observation_id(
        source_type="zeek",
        sensor_id="zeek-core-01",
        source_record_id="CZeekTcp000000001",
        timestamp=Decimal("1725148800.123456789"),
        flow_key=expected_flow_key,
        source_provenance="synthetic-zeek-suite",
    )
    assert tcp.flow_key == expected_flow_key
    assert tcp.observation_id == expected_obs_id
    assert len({tcp.observation_id, tcp.flow_key, tcp.zeek_uid, tcp.community_id}) == 4

    # B, J: UDP record preserving existing community_id opaquely
    udp = records[1]
    assert udp.zeek_uid == "CZeekUdp000000002"
    assert udp.protocol == "UDP"
    assert udp.src_port == 53535
    assert udp.dst_port == 53
    assert udp.service == "dns"
    assert udp.community_id == "1:CustomPreservedZeekCommunityID="
    assert udp.start_ts == "1725148805.5"
    assert udp.duration == Decimal("0.0125")
    assert udp.end_epoch == Decimal("1725148805.5125")
    assert udp.orig_bytes == 64
    assert udp.resp_bytes == 180
    assert udp.orig_ip_bytes == 92
    assert udp.resp_ip_bytes == 208
    assert udp.local_orig is None
    assert udp.local_resp is None

    # C, D, M: IPv6 connection (RFC 5952 canonicalized) with missing optional fields and missing duration
    ipv6 = records[2]
    assert ipv6.zeek_uid == "CZeekIpv600000003"
    assert ipv6.src_ip == "2001:db8::1"
    assert ipv6.dst_ip == "2001:db8::2"
    assert ipv6.src_scoped_id == "default#2001:db8::1"
    assert ipv6.dst_scoped_id == "default#2001:db8::2"
    assert ipv6.community_id == "1:r0kqPLw6hSIAasyo9ANthUgbhVA="
    assert ipv6.duration is None
    assert ipv6.end_epoch is None
    assert ipv6.end_ts is None
    assert ipv6.orig_bytes is None
    assert ipv6.resp_bytes is None
    assert ipv6.resp_pkts is None
    assert ipv6.resp_ip_bytes is None
    assert ipv6.missed_bytes is None
    assert ipv6.service is None
    assert ipv6.history is None
    assert ipv6.orig_pkts == 1
    assert ipv6.orig_ip_bytes == 60

    # G: Different Zeek UIDs sharing exact same 5-tuple & timestamp must NOT collapse
    same_a = records[3]
    same_b = records[4]
    assert same_a.zeek_uid == "CZeekSameTuple004"
    assert same_b.zeek_uid == "CZeekSameTuple005"
    assert same_a.flow_key == same_b.flow_key == tcp.flow_key
    assert same_a.community_id == same_b.community_id == tcp.community_id
    assert same_a.observation_id != same_b.observation_id
    assert same_a.observation_id != tcp.observation_id
    assert same_b.observation_id != tcp.observation_id
    assert same_a.duration is None and same_a.end_epoch is None and same_a.end_ts is None


# ---------------------------------------------------------------------------
# H: Idempotent Re-Import Determinism
# ---------------------------------------------------------------------------

def test_reimporting_same_file_produces_identical_observation_ids():
    """Importing the same file twice with the same context yields identical normalized records."""
    records_1, summary_1 = parse_zeek_conn_file(
        STANDARD_FIXTURE,
        sensor_id="edge-tap-01",
        routing_domain_id="corp-prod",
        source_provenance="batch-2026-11",
    )
    records_2, summary_2 = parse_zeek_conn_file(
        STANDARD_FIXTURE,
        sensor_id="edge-tap-01",
        routing_domain_id="corp-prod",
        source_provenance="batch-2026-11",
    )

    assert records_1 == records_2
    assert [r.observation_id for r in records_1] == [r.observation_id for r in records_2]
    assert summary_1 == summary_2


# ---------------------------------------------------------------------------
# I: Overlapping RFC 1918 Across Explicit RoutingDomains
# ---------------------------------------------------------------------------

def test_overlapping_rfc1918_distinct_routing_domains():
    """Same RFC 1918 conn.log in different RoutingDomains produces isolated scoped IDs, flow_keys, and observation_ids."""
    corp_records, _ = parse_zeek_conn_file(
        OVERLAPPING_RFC1918_FIXTURE,
        sensor_id="sensor-shared",
        routing_domain_id="CORP-HQ",
    )
    branch_records, _ = parse_zeek_conn_file(
        OVERLAPPING_RFC1918_FIXTURE,
        sensor_id="sensor-shared",
        routing_domain_id="branch-west",
    )

    assert len(corp_records) == 1
    assert len(branch_records) == 1
    c_rec = corp_records[0]
    b_rec = branch_records[0]

    # Scoped endpoints, flow_key, and observation_id are strictly domain-isolated
    assert c_rec.routing_domain_id == "corp-hq"
    assert b_rec.routing_domain_id == "branch-west"
    assert c_rec.src_scoped_id == "corp-hq#10.0.0.5"
    assert b_rec.src_scoped_id == "branch-west#10.0.0.5"
    assert c_rec.dst_scoped_id == "corp-hq#10.0.0.20"
    assert b_rec.dst_scoped_id == "branch-west#10.0.0.20"
    assert c_rec.flow_key != b_rec.flow_key
    assert c_rec.observation_id != b_rec.observation_id

    # Community ID does NOT incorporate RoutingDomain or sensor_id
    assert c_rec.community_id is not None
    assert c_rec.community_id == b_rec.community_id


# ---------------------------------------------------------------------------
# L: High-Precision Nanosecond Timestamp Differentiation (No Float Rounding)
# ---------------------------------------------------------------------------

def test_nanosecond_timestamp_precision_prevents_observation_collision():
    """Verify two JSON numbers indistinguishable in float64 stay distinct via parse_float=Decimal."""
    # Both 1725148800.123456781 and 1725148800.123456789 collapse to the same IEEE 754 float64!
    assert float("1725148800.123456781") == float("1725148800.123456789")

    lines = [
        '{"ts":1725148800.123456781,"uid":"CSameUidNano00001","id.orig_h":"10.1.0.1","id.orig_p":40000,"id.resp_h":"10.1.0.2","id.resp_p":443,"proto":"tcp"}',
        '{"ts":1725148800.123456789,"uid":"CSameUidNano00001","id.orig_h":"10.1.0.1","id.orig_p":40000,"id.resp_h":"10.1.0.2","id.resp_p":443,"proto":"tcp"}',
    ]

    stream = iter_zeek_conn_lines(lines, sensor_id="tap-ns")
    records = list(stream)
    assert len(records) == 2
    assert records[0].start_ts == "1725148800.123456781"
    assert records[1].start_ts == "1725148800.123456789"
    assert records[0].start_epoch == Decimal("1725148800.123456781")
    assert records[1].start_epoch == Decimal("1725148800.123456789")
    assert records[0].observation_id != records[1].observation_id


def test_iso8601_timestamp_support_with_nanoseconds_and_duration():
    """Verify Zeek ISO 8601 JSON timestamps (Z / offset, nanosecond precision) work across Python 3.10+."""
    lines = [
        json.dumps({
            "ts": "2024-09-01T12:00:00.123456789Z",
            "uid": "CIsoTsRecord00001",
            "id.orig_h": "192.0.2.1",
            "id.orig_p": 12345,
            "id.resp_h": "192.0.2.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": "0.500000001",
        }),
    ]
    stream = iter_zeek_conn_lines(lines, sensor_id="tap-iso")
    records = list(stream)
    assert len(records) == 1
    rec = records[0]
    assert rec.start_ts == "2024-09-01T12:00:00.123456789Z"
    assert rec.start_epoch == Decimal("1725192000.123456789")
    assert rec.duration == Decimal("0.500000001")
    assert rec.end_epoch == Decimal("1725192000.623456790")
    assert rec.end_ts == "1725192000.62345679"


def test_zero_duration_vs_missing_duration_and_empty_file(tmp_path):
    """Verify explicit duration=0 derives end_epoch==start_epoch, missing duration stays None, and empty file is clean."""
    zero_dur_line = '{"ts":1725148800.5,"uid":"CZeroDur1","id.orig_h":"192.0.2.1","id.orig_p":0,"id.resp_h":"192.0.2.2","id.resp_p":0,"proto":"icmp","duration":0.0}'
    rec = list(iter_zeek_conn_lines([zero_dur_line], sensor_id="s1"))[0]
    assert rec.src_port == 0
    assert rec.dst_port == 0
    assert rec.duration == Decimal("0.0")
    assert rec.end_epoch == Decimal("1725148800.5")
    assert rec.end_ts == "1725148800.5"
    assert rec.community_id == compute_community_id("192.0.2.1", "192.0.2.2", "ICMP", 0, 0)

    # Empty / whitespace-only JSONL file
    empty_file = tmp_path / "empty_conn.jsonl"
    empty_file.write_text("\n   \n\t\n", encoding="utf-8")
    empty_records, empty_summary = parse_zeek_conn_file(empty_file, sensor_id="s1")
    assert empty_records == []
    assert empty_summary.total_raw_records == 0
    assert empty_summary.valid_records == 0
    assert empty_summary.skipped_records == 0
    assert empty_summary.warning_counts == {}


# ---------------------------------------------------------------------------
# E, F, M, Malformed Records, Unsupported Protocols, Invalid Metrics
# ---------------------------------------------------------------------------

def test_mixed_errors_fixture_handling_and_diagnostics():
    """Verify malformed JSON, bad IPs, missing UID, bad timestamps/ports, unsupported proto, and bad metrics."""
    records, summary = parse_zeek_conn_file(
        MIXED_ERRORS_FIXTURE,
        sensor_id="sensor-mixed",
        routing_domain_id="lab",
    )

    # 10 non-empty JSONL lines: 7 skipped (malformed/missing required/bad port), 3 valid
    # (1 clean TCP + 1 unsupported_protocol with community_id=None + 1 valid TCP with invalid optional metrics -> None)
    assert summary.total_raw_records == 10
    assert summary.valid_records == 3
    assert summary.skipped_records == 7
    assert len(records) == 3

    # Verify expected categorized warning counts
    assert summary.warning_counts["malformed_json"] == 1
    assert summary.warning_counts["invalid_record_format"] == 1
    assert summary.warning_counts["invalid_src_ip"] == 1
    assert summary.warning_counts["mismatched_ip_version"] == 1
    assert summary.warning_counts["missing_uid"] == 1
    assert summary.warning_counts["invalid_timestamp"] == 1
    assert summary.warning_counts["invalid_src_port"] == 1
    assert summary.warning_counts["unsupported_protocol"] == 1
    assert summary.warning_counts["invalid_duration"] == 1
    assert summary.warning_counts["invalid_metric"] == 3  # orig_bytes=-10, resp_pkts="abc", orig_ip_bytes=true
    assert summary.warning_counts["invalid_optional_field"] == 1  # local_orig="yes"
    assert len(summary.sample_errors) == 10  # bounded by MAX_SAMPLE_ERRORS

    # Record 1: clean valid TCP
    assert records[0].zeek_uid == "CValidFirst000001"
    assert records[0].end_epoch == Decimal("1725148902.6")

    # Record 2: unknown_transport preserved without fabricating a Community ID
    unsup = records[1]
    assert unsup.zeek_uid == "CUnsupProto000006"
    assert unsup.protocol == "UNKNOWN_TRANSPORT"
    assert unsup.community_id is None
    assert unsup.src_port is None
    assert unsup.dst_port is None

    # Record 3: invalid optional metrics and duration become None without fabricating end_ts or zeros
    bad_metrics = records[2]
    assert bad_metrics.zeek_uid == "CBadMetrics000007"
    assert bad_metrics.duration is None
    assert bad_metrics.end_epoch is None
    assert bad_metrics.end_ts is None
    assert bad_metrics.orig_bytes is None
    assert bad_metrics.resp_pkts is None
    assert bad_metrics.orig_ip_bytes is None
    assert bad_metrics.local_orig is None


# ---------------------------------------------------------------------------
# Community ID Seed, ICMP / ICMPv6, and Incomplete Tuple Behavior
# ---------------------------------------------------------------------------

def test_community_id_seed_and_icmp_ipv6_handling():
    """Verify configurable Community ID seed, Zeek IPv6 ICMP->ICMP6 mapping, and incomplete tuple -> None."""
    tcp_line = '{"ts":1725148800.1,"uid":"CSeed001","id.orig_h":"128.232.110.120","id.orig_p":34855,"id.resp_h":"66.35.250.204","id.resp_p":80,"proto":"tcp"}'
    r_seed0 = list(iter_zeek_conn_lines([tcp_line], sensor_id="s1", community_id_seed=0))[0]
    r_seed1 = list(iter_zeek_conn_lines([tcp_line], sensor_id="s1", community_id_seed=1))[0]
    assert r_seed0.community_id == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert r_seed1.community_id == "1:3V71V58M3Ksw/yuFALMcW0LAHvc="
    assert r_seed0.community_id != r_seed1.community_id
    # Seed does NOT change flow_key or observation_id
    assert r_seed0.flow_key == r_seed1.flow_key
    assert r_seed0.observation_id == r_seed1.observation_id

    # Zeek logs IPv6 ICMPv6 with proto="icmp"; Community ID must use ICMP6 (IANA 58)
    icmp6_line = '{"ts":1725148800.2,"uid":"CIcmp601","id.orig_h":"2001:db8::1","id.orig_p":128,"id.resp_h":"2001:db8::2","id.resp_p":0,"proto":"icmp"}'
    icmp6_rec = list(iter_zeek_conn_lines([icmp6_line], sensor_id="s1"))[0]
    assert icmp6_rec.community_id == compute_community_id("2001:db8::1", "2001:db8::2", "ICMP6", 128, 0)

    # Incomplete TCP (missing ports) and incomplete ICMP (missing type/code) must NOT fabricate Community ID
    incomplete_lines = [
        '{"ts":1725148800.3,"uid":"CIncTcp1","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","proto":"tcp"}',
        '{"ts":1725148800.4,"uid":"CIncIcmp","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","proto":"icmp"}',
    ]
    incomplete_recs = list(iter_zeek_conn_lines(incomplete_lines, sensor_id="s1"))
    assert len(incomplete_recs) == 2
    assert incomplete_recs[0].community_id is None
    assert incomplete_recs[1].community_id is None


# ---------------------------------------------------------------------------
# Streaming Behavior, Configuration Validation, and Immutability
# ---------------------------------------------------------------------------

def test_streaming_iterator_reads_lazily_and_closes_file():
    """Verify stream_zeek_conn_file yields lazily record-by-record and exposes incremental/final summary."""
    with stream_zeek_conn_file(STANDARD_FIXTURE, sensor_id="stream-sensor") as stream:
        it = iter(stream)
        first = next(it)
        assert first.zeek_uid == "CZeekTcp000000001"
        # Only 1 line processed so far — file was NOT pre-loaded into RAM
        assert stream.summary.total_raw_records == 1
        assert stream.summary.valid_records == 1

        remaining = list(it)
        assert len(remaining) == 4
        assert stream.summary.total_raw_records == 5
        assert stream.summary.valid_records == 5


def test_parser_fails_clearly_on_missing_file_or_invalid_config(tmp_path):
    """Verify missing files, directories, and invalid parser parameters fail eagerly."""
    missing = tmp_path / "does_not_exist.jsonl"
    with pytest.raises(FileNotFoundError, match="Zeek conn.log file not found"):
        parse_zeek_conn_file(missing, sensor_id="sensor-1")

    with pytest.raises(ValueError, match="is a directory"):
        parse_zeek_conn_file(tmp_path, sensor_id="sensor-1")

    with pytest.raises(ValueError, match="sensor_id must be a non-empty string"):
        parse_zeek_conn_file(STANDARD_FIXTURE, sensor_id="   ")

    with pytest.raises(ValueError, match="routing_domain_id must be a non-empty string"):
        parse_zeek_conn_file(STANDARD_FIXTURE, sensor_id="sensor-1", routing_domain_id="")

    with pytest.raises(ValueError, match="cannot contain delimiter '#'"):
        parse_zeek_conn_file(STANDARD_FIXTURE, sensor_id="sensor-1", routing_domain_id="bad#domain")

    with pytest.raises(ValueError, match="Invalid community_id_seed"):
        parse_zeek_conn_file(STANDARD_FIXTURE, sensor_id="sensor-1", community_id_seed=70000)

    with pytest.raises(ValueError, match="Invalid community_id_seed"):
        parse_zeek_conn_file(STANDARD_FIXTURE, sensor_id="sensor-1", community_id_seed=True)  # type: ignore[arg-type]


def test_zeek_connection_observation_is_frozen():
    """Verify ZeekConnectionObservation dataclass is immutable."""
    records, _ = parse_zeek_conn_file(OVERLAPPING_RFC1918_FIXTURE, sensor_id="sensor-1")
    with pytest.raises(Exception):
        records[0].zeek_uid = "mutated"  # type: ignore[misc]


def test_timezone_aware_iso8601_preserves_source_representation_and_epoch_equivalence():
    """Verify equivalent timezone-aware ISO instants share start_epoch while preserving Phase 1 string identity."""
    lines = [
        json.dumps({
            "ts": "2024-09-01T12:00:00Z",
            "uid": "CIsoTz00000000001",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 50000,
            "id.resp_h": "192.0.2.20",
            "id.resp_p": 443,
            "proto": "tcp",
        }),
        json.dumps({
            "ts": "2024-09-01T15:00:00+03:00",
            "uid": "CIsoTz00000000001",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 50000,
            "id.resp_h": "192.0.2.20",
            "id.resp_p": 443,
            "proto": "tcp",
        }),
    ]
    records = list(iter_zeek_conn_lines(lines, sensor_id="tap-tz"))
    assert len(records) == 2
    utc_rec, offset_rec = records

    # Both compute the exact same numeric UTC epoch
    assert utc_rec.start_epoch == Decimal("1725192000")
    assert offset_rec.start_epoch == Decimal("1725192000")

    # Phase 1 canonicalize_event_timestamp() contract intentionally preserves trimmed ISO strings as-is
    assert utc_rec.start_ts == "2024-09-01T12:00:00Z"
    assert offset_rec.start_ts == "2024-09-01T15:00:00+03:00"
    assert utc_rec.observation_id == compute_observation_id(
        source_type="zeek",
        sensor_id="tap-tz",
        source_record_id="CIsoTz00000000001",
        timestamp="2024-09-01T12:00:00Z",
        flow_key=utc_rec.flow_key,
    )
    assert offset_rec.observation_id == compute_observation_id(
        source_type="zeek",
        sensor_id="tap-tz",
        source_record_id="CIsoTz00000000001",
        timestamp="2024-09-01T15:00:00+03:00",
        flow_key=offset_rec.flow_key,
    )
    assert utc_rec.observation_id != offset_rec.observation_id


def test_warning_logging_is_bounded_while_warning_counts_remain_exact(caplog):
    """Verify high-volume malformed logs bound logger warnings and sample_errors while keeping exact counts."""
    malformed_count = 50
    lines = ["{not-valid-json" for _ in range(malformed_count)]

    with caplog.at_level(logging.WARNING, logger="src.ingestion.zeek_conn_parser"):
        stream = iter_zeek_conn_lines(lines, sensor_id="sensor-noisy")
        records = list(stream)
        summary = stream.summary

    assert records == []
    assert summary.total_raw_records == malformed_count
    assert summary.valid_records == 0
    assert summary.skipped_records == malformed_count
    assert summary.warning_counts == {"malformed_json": malformed_count}
    assert len(summary.sample_errors) == MAX_SAMPLE_ERRORS

    # Bounded to MAX_LOGGED_WARNINGS per-record warnings + 1 suppression notice
    assert len(caplog.records) == MAX_LOGGED_WARNINGS + 1
    assert "suppressing further per-record warning logs" in caplog.records[-1].message


def test_v1_ingestion_package_surface_remains_isolated():
    """Verify src.ingestion.__all__ preserves V1 exports without eagerly exporting V2 Zeek parser symbols."""
    assert set(ingestion_pkg.__all__) == {
        "TrafficRecord",
        "AlertRecord",
        "IngestionSummary",
        "parse_traffic_file",
        "parse_alert_file",
    }
