"""
Unit tests for Phase 3B.1 Suricata EVE JSONL streaming alert parser and normalization.

Covers synthetic deterministic test fixtures and cases A through V:
A. Standard TCP alert
B. UDP alert
C. IPv6 alert (RFC 5952 canonicalization + IPv6-ICMP)
D. Multiple alerts sharing one flow_id
E. Same SID firing repeatedly (including different alert.rev)
F. Same timestamp, tuple, flow_id, and SID on two different physical log lines
G. Reimport stability (including moved/renamed file with same log_source_id)
H. Distinct log_source_id values
I. Explicit RoutingDomain overlap (RFC 1918 isolation)
J. Existing Community ID preserved verbatim (never flow_id)
K. Computed Community ID (with configurable seed)
L. Missing Community ID with insufficient tuple (never fabricated)
M. ISO timezone offsets (+0000, +00:00, Z, +03:00, -0500, naive, invalid)
N. High-precision timestamps (9-digit ns, 12-digit, >28 significant digits, low Decimal context)
O. Missing optional metadata (represented as None)
P. Invalid alert object and malformed alert fields
Q. Mixed EVE event types (non-alerts ignored without warnings/errors)
R. Missing GID versus GID=1 identity (explicit 'none' sentinel)
S. Different ruleset namespaces (never inferred from alert.category)
T. Bounded warning logging and sample_errors with many malformed records
U. Streaming laziness, resource cleanup, config errors, and V1 import isolation
V. Cross-file / line-insertion identity behavior and limitations
"""

from decimal import Decimal, getcontext, localcontext
import json
import logging
from pathlib import Path
import shutil
import pytest

import src.ingestion as ingestion_pkg
from src.ingestion.community_id import compute_community_id
from src.ingestion.suricata_eve_parser import (
    MAX_LOGGED_WARNINGS,
    MAX_SAMPLE_ERRORS,
    SuricataIngestionSummary,
    iter_suricata_eve_alert_lines,
    parse_suricata_eve_alert_file,
    stream_suricata_eve_alerts,
)
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    alert_definition_id,
    compute_v2_flow_key,
    scoped_ip_id,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "suricata"
STANDARD_FIXTURE = FIXTURE_DIR / "eve_standard_alerts.jsonl"
MIXED_ERRORS_FIXTURE = FIXTURE_DIR / "eve_mixed_errors.jsonl"
OVERLAPPING_FIXTURE = FIXTURE_DIR / "eve_overlapping_rfc1918.jsonl"


# ---------------------------------------------------------------------------
# A, B, C, D, J, K, O, Q: Standard Synthetic Fixture Tests
# ---------------------------------------------------------------------------

def test_standard_fixture_tcp_udp_ipv6_shared_flow_and_non_alert_filtering():
    """Tests A, B, C, D, J, K, O, Q on synthetic EVE fixture with mixed event types."""
    records, summary = parse_suricata_eve_alert_file(
        STANDARD_FIXTURE,
        sensor_id="Suricata-Edge-01",
        ruleset_namespace="ET-Open",
        log_source_id="eve-edge01-2026-11-20",
        routing_domain_id="Corp-Prod",
        source_provenance="batch-01",
    )

    assert isinstance(summary, SuricataIngestionSummary)
    # 8 lines: 5 valid alerts + 3 ignored non-alerts (flow, dns, stats) + 0 skipped
    assert summary.total_raw_records == 8
    assert summary.valid_records == 5
    assert summary.ignored_non_alert_records == 3
    assert summary.skipped_records == 0
    assert summary.warning_counts == {}
    assert summary.sample_errors == ()
    assert len(records) == 5

    # A & J: Standard TCP alert with existing community_id, extra vlan/tls fields ignored cleanly
    tcp1 = records[0]
    assert isinstance(tcp1, SuricataAlertObservation)
    assert tcp1.sensor_id == "suricata-edge-01"
    assert tcp1.ruleset_namespace == "et-open"
    assert tcp1.routing_domain_id == "corp-prod"
    assert tcp1.log_source_id == "eve-edge01-2026-11-20"
    assert tcp1.source_type == "suricata"
    assert tcp1.source_provenance == "batch-01"
    assert tcp1.src_ip == "192.0.2.10"
    assert tcp1.dst_ip == "198.51.100.20"
    assert tcp1.src_scoped_id == "corp-prod#192.0.2.10"
    assert tcp1.dst_scoped_id == "corp-prod#198.51.100.20"
    assert tcp1.protocol == "TCP"
    assert tcp1.src_port == 54321
    assert tcp1.dst_port == 443
    assert tcp1.flow_id == 1001001
    assert tcp1.community_id == "1:syntheticExistingCid123=="  # preserved verbatim
    assert tcp1.gid == 1
    assert tcp1.sid == 2001219
    assert tcp1.rev == 20
    assert tcp1.signature == "SYNTHETIC ET SCAN Potential SSH/TLS Probe"
    assert tcp1.category == "Attempted Information Leak"
    assert tcp1.severity == 2
    assert tcp1.action == "allowed"
    assert tcp1.app_proto == "tls"
    assert tcp1.direction == "to_server"
    assert tcp1.tx_id == 0
    assert tcp1.pcap_cnt == 42
    assert tcp1.alert_definition_id == "suricata:et-open:1:2001219"
    assert tcp1.timestamp_source == "2026-11-20T14:15:30.123456+0000"
    assert tcp1.timestamp_epoch_decimal == Decimal("1795184130.123456")

    # D & K: Second alert sharing exact same flow_id=1001001, computed Community ID
    tcp2 = records[1]
    assert tcp2.flow_id == tcp1.flow_id == 1001001
    assert tcp2.event_id != tcp1.event_id
    assert tcp2.source_record_id != tcp1.source_record_id
    assert tcp2.alert_definition_id == "suricata:et-open:1:2009999"
    assert tcp2.community_id == compute_community_id("192.0.2.10", "198.51.100.20", "TCP", 54321, 443)
    assert tcp2.community_id != str(tcp2.flow_id)

    # B: UDP alert
    udp = records[2]
    assert udp.protocol == "UDP"
    assert udp.src_port == 53000
    assert udp.dst_port == 53
    assert udp.action == "blocked"
    assert udp.app_proto == "dns"
    assert udp.community_id == compute_community_id("192.0.2.10", "198.51.100.53", "UDP", 53000, 53)

    # C: IPv6 alert canonicalized to RFC 5952 + 9-digit nanosecond precision
    ipv6 = records[3]
    assert ipv6.src_ip == "2001:db8::1"
    assert ipv6.dst_ip == "2001:db8::2"
    assert ipv6.src_scoped_id == "corp-prod#2001:db8::1"
    assert ipv6.dst_scoped_id == "corp-prod#2001:db8::2"
    assert ipv6.timestamp_epoch_decimal == Decimal("1795184132.123456789")
    assert ipv6.community_id == compute_community_id("2001:db8::1", "2001:db8::2", "TCP", 60000, 80)

    # O & R: Minimal alert with missing optional metadata and absent GID -> explicit 'none' sentinel
    minimal = records[4]
    assert minimal.gid is None
    assert minimal.sid == 9900001
    assert minimal.alert_definition_id == "suricata:et-open:none:9900001"
    assert minimal.protocol is None
    assert minimal.src_port is None
    assert minimal.dst_port is None
    assert minimal.flow_id is None
    assert minimal.community_id is None
    assert minimal.rev is None
    assert minimal.signature is None
    assert minimal.category is None
    assert minimal.severity is None
    assert minimal.action is None
    assert minimal.app_proto is None
    assert minimal.direction is None
    assert minimal.tx_id is None
    assert minimal.pcap_cnt is None


# ---------------------------------------------------------------------------
# E, F, G, H, V: Event Identity, Repeated Firings, log_source_id & Cross-File
# ---------------------------------------------------------------------------

def test_repeated_same_sid_and_identical_lines_produce_distinct_event_ids():
    """Tests E & F: Repeated SID firings (even identical ts/tuple/flow_id/SID on different lines) stay distinct."""
    identical_line = json.dumps({
        "timestamp": "2026-11-20T14:15:30.123456+0000",
        "event_type": "alert",
        "flow_id": 777777,
        "src_ip": "192.0.2.1",
        "src_port": 44000,
        "dest_ip": "198.51.100.2",
        "dest_port": 443,
        "proto": "TCP",
        "tx_id": 0,
        "pcap_cnt": 10,
        "alert": {"gid": 1, "signature_id": 2001219, "rev": 10},
    })
    diff_rev_line = json.dumps({
        "timestamp": "2026-11-20T14:15:31.123456+0000",
        "event_type": "alert",
        "flow_id": 777777,
        "src_ip": "192.0.2.1",
        "src_port": 44000,
        "dest_ip": "198.51.100.2",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {"gid": 1, "signature_id": 2001219, "rev": 25},  # rev is metadata, NOT definition identity
    })

    recs = list(
        iter_suricata_eve_alert_lines(
            [identical_line, identical_line, diff_rev_line],
            sensor_id="s-edge",
            ruleset_namespace="et-open",
            log_source_id="eve-repeat-01",
        )
    )
    assert len(recs) == 3

    # E: All three share the exact same AlertDefinition ID even with different rev (10 vs 25)
    assert recs[0].alert_definition_id == recs[1].alert_definition_id == recs[2].alert_definition_id
    assert recs[0].alert_definition_id == "suricata:et-open:1:2001219"
    assert recs[0].rev == 10
    assert recs[2].rev == 25

    # F: Two identical JSON lines at line 1 vs line 2 produce distinct source_record_id and event_id
    assert recs[0].source_record_id != recs[1].source_record_id
    assert recs[0].event_id != recs[1].event_id
    assert recs[0].event_id != recs[2].event_id
    assert ":line:1:" in recs[0].source_record_id
    assert ":line:2:" in recs[1].source_record_id


def test_reimport_stability_renamed_file_distinct_log_source_id_and_line_shift(tmp_path):
    """Tests G, H, V: Reimport stability, path independence, distinct log_source_id, and line-insertion behavior."""
    # G: Reimport identical file twice
    r1, _ = parse_suricata_eve_alert_file(
        STANDARD_FIXTURE,
        sensor_id="s1",
        ruleset_namespace="et-open",
        log_source_id="stable-eve-01",
    )
    r2, _ = parse_suricata_eve_alert_file(
        STANDARD_FIXTURE,
        sensor_id="s1",
        ruleset_namespace="et-open",
        log_source_id="stable-eve-01",
    )
    assert [x.event_id for x in r1] == [x.event_id for x in r2]
    assert [x.source_record_id for x in r1] == [x.source_record_id for x in r2]

    # G (renamed / moved path): Absolute path is NOT implicit identity
    renamed = tmp_path / "different_dir" / "renamed_eve.jsonl"
    renamed.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STANDARD_FIXTURE, renamed)
    r_renamed, _ = parse_suricata_eve_alert_file(
        renamed,
        sensor_id="s1",
        ruleset_namespace="et-open",
        log_source_id="stable-eve-01",
    )
    assert [x.event_id for x in r_renamed] == [x.event_id for x in r1]

    # H: Distinct log_source_id values produce distinct source_record_id and event_id even for identical records
    r_other_src, _ = parse_suricata_eve_alert_file(
        STANDARD_FIXTURE,
        sensor_id="s1",
        ruleset_namespace="et-open",
        log_source_id="stable-eve-02",
    )
    assert all(a.source_record_id != b.source_record_id for a, b in zip(r1, r_other_src))
    assert all(a.event_id != b.event_id for a, b in zip(r1, r_other_src))

    # V: Inserting a preceding line shifts line ordinals and changes downstream IDs (documented limitation)
    shifted = tmp_path / "shifted_eve.jsonl"
    original_text = STANDARD_FIXTURE.read_text(encoding="utf-8")
    inserted_non_alert = '{"timestamp":"2026-11-20T14:00:00Z","event_type":"stats"}\n'
    shifted.write_text(inserted_non_alert + original_text, encoding="utf-8")
    r_shifted, s_shifted = parse_suricata_eve_alert_file(
        shifted,
        sensor_id="s1",
        ruleset_namespace="et-open",
        log_source_id="stable-eve-01",
    )
    assert s_shifted.ignored_non_alert_records == 4
    assert all(a.event_id != b.event_id for a, b in zip(r1, r_shifted))


# ---------------------------------------------------------------------------
# I, R, S: RoutingDomain Isolation, Missing GID vs GID=1, Ruleset Namespaces
# ---------------------------------------------------------------------------

def test_overlapping_rfc1918_routing_domain_isolation():
    """Test I: Same RFC 1918 alert in distinct RoutingDomains yields isolated endpoints/flow_key/event_id and shared Community ID."""
    corp_recs, _ = parse_suricata_eve_alert_file(
        OVERLAPPING_FIXTURE,
        sensor_id="s-shared",
        ruleset_namespace="et-open",
        log_source_id="eve-overlap-1",
        routing_domain_id="corp-hq",
    )
    branch_recs, _ = parse_suricata_eve_alert_file(
        OVERLAPPING_FIXTURE,
        sensor_id="s-shared",
        ruleset_namespace="et-open",
        log_source_id="eve-overlap-1",
        routing_domain_id="branch-west",
    )

    assert len(corp_recs) == 1 and len(branch_recs) == 1
    c_rec, b_rec = corp_recs[0], branch_recs[0]

    assert c_rec.src_scoped_id == scoped_ip_id("corp-hq", "10.0.0.5")
    assert b_rec.src_scoped_id == scoped_ip_id("branch-west", "10.0.0.5")
    assert c_rec.dst_scoped_id == scoped_ip_id("corp-hq", "10.0.0.20")
    assert b_rec.dst_scoped_id == scoped_ip_id("branch-west", "10.0.0.20")
    assert c_rec.flow_key != b_rec.flow_key
    assert c_rec.event_id != b_rec.event_id

    # Community ID and AlertDefinition ID are domain-independent
    assert c_rec.community_id is not None
    assert c_rec.community_id == b_rec.community_id
    assert c_rec.alert_definition_id == b_rec.alert_definition_id


def test_missing_gid_vs_gid_1_and_different_ruleset_namespaces():
    """Tests R & S: Absent GID ('none') never collides with GID=1; ruleset_namespace is explicit and never inferred from category."""
    line_no_gid = json.dumps({
        "timestamp": "2026-11-20T14:00:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.1",
        "alert": {"signature_id": 2001219, "category": "Attempted Recon"},
    })
    line_gid_1 = json.dumps({
        "timestamp": "2026-11-20T14:00:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.1",
        "alert": {"gid": 1, "signature_id": 2001219, "category": "Attempted Recon"},
    })

    # R: Missing GID vs GID=1
    recs_et = list(
        iter_suricata_eve_alert_lines(
            [line_no_gid, line_gid_1],
            sensor_id="s1",
            ruleset_namespace="et-open",
            log_source_id="eve-gid-1",
        )
    )
    assert recs_et[0].gid is None
    assert recs_et[1].gid == 1
    assert recs_et[0].alert_definition_id == alert_definition_id("suricata", "et-open", None, 2001219)
    assert recs_et[1].alert_definition_id == alert_definition_id("suricata", "et-open", 1, 2001219)
    assert recs_et[0].alert_definition_id == "suricata:et-open:none:2001219"
    assert recs_et[1].alert_definition_id == "suricata:et-open:1:2001219"
    assert recs_et[0].alert_definition_id != recs_et[1].alert_definition_id

    # S: Different explicit ruleset_namespace; category never overrides namespace
    recs_local = list(
        iter_suricata_eve_alert_lines(
            [line_gid_1],
            sensor_id="s1",
            ruleset_namespace="local-custom",
            log_source_id="eve-gid-1",
        )
    )
    assert recs_local[0].ruleset_namespace == "local-custom"
    assert recs_local[0].alert_definition_id == "suricata:local-custom:1:2001219"
    assert recs_local[0].alert_definition_id != recs_et[1].alert_definition_id
    assert recs_local[0].event_id != recs_et[1].event_id


# ---------------------------------------------------------------------------
# J, K, L: Community ID Seed, ICMP / IPv6-ICMP, and Insufficient Tuple Handling
# ---------------------------------------------------------------------------

def test_community_id_seed_icmp_and_insufficient_tuple_never_fabricates():
    """Tests J, K, L: Configurable seed, Suricata IPv6-ICMP with icmp_type/code, and incomplete tuples -> None."""
    tcp_line = json.dumps({
        "timestamp": "2026-11-20T14:00:00Z",
        "event_type": "alert",
        "src_ip": "128.232.110.120",
        "src_port": 34855,
        "dest_ip": "66.35.250.204",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"gid": 1, "signature_id": 100},
    })
    r0 = list(iter_suricata_eve_alert_lines([tcp_line], sensor_id="s1", ruleset_namespace="et", log_source_id="l1", community_id_seed=0))[0]
    r1 = list(iter_suricata_eve_alert_lines([tcp_line], sensor_id="s1", ruleset_namespace="et", log_source_id="l1", community_id_seed=1))[0]
    assert r0.community_id == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert r1.community_id == "1:3V71V58M3Ksw/yuFALMcW0LAHvc="
    assert r0.event_id == r1.event_id  # Seed does NOT alter event_id

    # Suricata IPv6-ICMP with explicit icmp_type & icmp_code -> computes ICMP6 Community ID
    icmp6_complete = json.dumps({
        "timestamp": "2026-11-20T14:00:01Z",
        "event_type": "alert",
        "src_ip": "2001:db8::1",
        "dest_ip": "2001:db8::2",
        "proto": "IPv6-ICMP",
        "icmp_type": 128,
        "icmp_code": 0,
        "alert": {"gid": 1, "signature_id": 101},
    })
    # L: Incomplete TCP (no ports) and incomplete ICMP (no icmp_type/icmp_code) -> None (never fabricated!)
    tcp_no_ports = json.dumps({
        "timestamp": "2026-11-20T14:00:02Z",
        "event_type": "alert",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "proto": "TCP",
        "flow_id": 999888,
        "alert": {"gid": 1, "signature_id": 102},
    })
    icmp_no_type = json.dumps({
        "timestamp": "2026-11-20T14:00:03Z",
        "event_type": "alert",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "proto": "ICMP",
        "alert": {"gid": 1, "signature_id": 103},
    })

    recs = list(
        iter_suricata_eve_alert_lines(
            [icmp6_complete, tcp_no_ports, icmp_no_type],
            sensor_id="s1",
            ruleset_namespace="et",
            log_source_id="l-icmp",
        )
    )
    assert recs[0].community_id == compute_community_id("2001:db8::1", "2001:db8::2", "ICMP6", 128, 0)
    assert recs[1].community_id is None
    assert recs[2].community_id is None


# ---------------------------------------------------------------------------
# M & N: ISO Timezone Offsets, Naive Policy, High Precision, Low Decimal Context
# ---------------------------------------------------------------------------

def test_iso_timezone_offsets_naive_and_high_precision_timestamps():
    """Tests M & N: +0000/+00:00/Z/+03:00/-0500 offsets, naive policy, >28 digits, and low localcontext."""
    original_global_prec = getcontext().prec
    lines = [
        json.dumps({"timestamp": "2026-11-20T14:15:30.123456+0000", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 1}}),
        json.dumps({"timestamp": "2026-11-20T14:15:30.123456+00:00", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 2}}),
        json.dumps({"timestamp": "2026-11-20T14:15:30.123456Z", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 3}}),
        json.dumps({"timestamp": "2026-11-20T17:15:30.123456+03:00", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 4}}),
        json.dumps({"timestamp": "2026-11-20T09:15:30.123456-0500", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 5}}),
        # Naive timestamp: retained verbatim with timestamp_epoch_decimal = None (never invents UTC!)
        json.dumps({"timestamp": "2026-11-20T14:15:30.123456", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 6}}),
        # High-precision 29 fractional digits (39 significant digits total)
        json.dumps({"timestamp": "2026-11-20T14:15:30.12345678901234567890123456789+0000", "event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "alert": {"signature_id": 7}}),
    ]

    with localcontext() as ctx:
        ctx.prec = 6
        recs = list(
            iter_suricata_eve_alert_lines(
                lines,
                sensor_id="s-ts",
                ruleset_namespace="et-open",
                log_source_id="eve-ts-1",
            )
        )

    assert getcontext().prec == original_global_prec
    assert len(recs) == 7

    expected_utc_epoch = Decimal("1795184130.123456")
    for idx in range(5):
        assert recs[idx].timestamp_epoch_decimal == expected_utc_epoch
    assert recs[0].timestamp_source == "2026-11-20T14:15:30.123456+0000"
    assert recs[3].timestamp_source == "2026-11-20T17:15:30.123456+03:00"
    assert recs[4].timestamp_source == "2026-11-20T09:15:30.123456-0500"

    # Naive timestamp has NO invented UTC epoch
    assert recs[5].timestamp_source == "2026-11-20T14:15:30.123456"
    assert recs[5].timestamp_epoch_decimal is None

    # 39-significant-digit timestamp preserved losslessly even under localcontext(prec=6)
    assert recs[6].timestamp_source == "2026-11-20T14:15:30.12345678901234567890123456789+0000"
    assert recs[6].timestamp_epoch_decimal == Decimal("1795184130.12345678901234567890123456789")


# ---------------------------------------------------------------------------
# P, T: Mixed Errors, Malformed Alert Objects, and Bounded Warning Logging
# ---------------------------------------------------------------------------

def test_mixed_errors_fixture_diagnostics_and_recovery():
    """Test P: Malformed JSON, missing/invalid event_type, bad timezone, bad alert object, bad ports/metrics."""
    records, summary = parse_suricata_eve_alert_file(
        MIXED_ERRORS_FIXTURE,
        sensor_id="s-err",
        ruleset_namespace="et-open",
        log_source_id="eve-err-01",
    )

    # 16 lines: 2 valid alerts + 1 ignored http event + 13 skipped malformed lines
    assert summary.total_raw_records == 16
    assert summary.valid_records == 2
    assert summary.ignored_non_alert_records == 1
    assert summary.skipped_records == 13
    assert summary.total_raw_records == (
        summary.valid_records + summary.skipped_records + summary.ignored_non_alert_records
    )

    assert summary.warning_counts["malformed_json"] == 1
    assert summary.warning_counts["invalid_record_format"] == 1
    assert summary.warning_counts["missing_event_type"] == 1
    assert summary.warning_counts["invalid_event_type"] == 1
    assert summary.warning_counts["missing_timestamp"] == 1
    assert summary.warning_counts["invalid_timestamp"] == 1
    assert summary.warning_counts["missing_alert_object"] == 1
    assert summary.warning_counts["invalid_alert_object"] == 1
    assert summary.warning_counts["missing_signature_id"] == 1
    assert summary.warning_counts["invalid_gid"] == 1
    assert summary.warning_counts["invalid_src_ip"] == 1
    assert summary.warning_counts["mismatched_ip_version"] == 1
    assert summary.warning_counts["invalid_src_port"] == 1
    assert summary.warning_counts["invalid_numeric_field"] == 3  # flow_id, tx_id, pcap_cnt
    assert summary.warning_counts["invalid_community_id"] == 1
    assert summary.warning_counts["invalid_alert_metadata"] == 3  # rev, severity, metadata
    assert summary.warning_counts["unsupported_protocol"] == 1
    assert len(summary.sample_errors) == MAX_SAMPLE_ERRORS

    # Valid alert 1: invalid optional numeric/metadata/community_id fell back cleanly; Community ID computed from TCP tuple
    r0 = records[0]
    assert r0.sid == 1007
    assert r0.flow_id is None
    assert r0.tx_id is None
    assert r0.pcap_cnt is None
    assert r0.rev is None
    assert r0.severity is None
    assert r0.community_id == compute_community_id("192.0.2.10", "198.51.100.10", "TCP", 40000, 443)

    # Valid alert 2: unsupported protocol GRE preserved without fabricating Community ID
    r1 = records[1]
    assert r1.sid == 1008
    assert r1.protocol == "GRE"
    assert r1.community_id is None


def test_bounded_warning_logging_on_many_malformed_records(caplog):
    """Test T: High-volume malformed EVE streams bound warning logs & sample_errors while keeping exact counts."""
    malformed_count = 50
    lines = ["{broken-eve-json" for _ in range(malformed_count)]

    with caplog.at_level(logging.WARNING, logger="src.ingestion.suricata_eve_parser"):
        stream = iter_suricata_eve_alert_lines(
            lines,
            sensor_id="s-noisy",
            ruleset_namespace="et-open",
            log_source_id="eve-noisy-1",
        )
        records = list(stream)
        summary = stream.summary

    assert records == []
    assert summary.total_raw_records == malformed_count
    assert summary.valid_records == 0
    assert summary.skipped_records == malformed_count
    assert summary.ignored_non_alert_records == 0
    assert summary.warning_counts == {"malformed_json": malformed_count}
    assert len(summary.sample_errors) == MAX_SAMPLE_ERRORS
    assert len(caplog.records) == MAX_LOGGED_WARNINGS + 1
    assert "suppressing further per-record warning logs" in caplog.records[-1].message


# ---------------------------------------------------------------------------
# U: Streaming Laziness, Resource Cleanup, Empty File, Config Validation, Isolation
# ---------------------------------------------------------------------------

def test_streaming_laziness_resource_cleanup_empty_file_and_immutability(tmp_path):
    """Test U: Lazy line-by-line streaming, guaranteed file close, empty file handling, frozen model."""
    with stream_suricata_eve_alerts(
        STANDARD_FIXTURE,
        sensor_id="s-stream",
        ruleset_namespace="et-open",
        log_source_id="eve-stream-1",
    ) as stream:
        it = iter(stream)
        first = next(it)
        assert first.sid == 2001219
        # Only 1 line read so far — file NOT pre-loaded into RAM
        assert stream.summary.total_raw_records == 1
        assert stream.summary.valid_records == 1
        fh = stream._close_resource
        assert fh is not None and not fh.closed

    # Context exit closed underlying file handle even though stream was not exhausted
    assert fh.closed

    # Empty / whitespace-only file
    empty_file = tmp_path / "empty_eve.jsonl"
    empty_file.write_text("\n   \n\t\n", encoding="utf-8")
    empty_records, empty_summary = parse_suricata_eve_alert_file(
        empty_file,
        sensor_id="s-stream",
        ruleset_namespace="et-open",
        log_source_id="eve-empty-1",
    )
    assert empty_records == []
    assert empty_summary.total_raw_records == 0
    assert empty_summary.valid_records == 0
    assert empty_summary.skipped_records == 0
    assert empty_summary.ignored_non_alert_records == 0

    # Frozen dataclass immutability
    with pytest.raises(Exception):
        first.sid = 999  # type: ignore[misc]


def test_parser_fails_clearly_on_missing_file_invalid_config_and_keeps_v1_isolated(tmp_path):
    """Test U: Missing files, directories, invalid parser config fail eagerly; V1 src.ingestion stays isolated."""
    with pytest.raises(FileNotFoundError, match="Suricata EVE file not found"):
        parse_suricata_eve_alert_file(
            tmp_path / "missing.jsonl",
            sensor_id="s1",
            ruleset_namespace="et-open",
            log_source_id="l1",
        )

    with pytest.raises(ValueError, match="is a directory"):
        parse_suricata_eve_alert_file(
            tmp_path,
            sensor_id="s1",
            ruleset_namespace="et-open",
            log_source_id="l1",
        )

    with pytest.raises(ValueError, match="sensor_id must be a non-empty string"):
        parse_suricata_eve_alert_file(
            STANDARD_FIXTURE,
            sensor_id="   ",
            ruleset_namespace="et-open",
            log_source_id="l1",
        )

    with pytest.raises(ValueError, match="ruleset_namespace must be a non-empty string"):
        parse_suricata_eve_alert_file(
            STANDARD_FIXTURE,
            sensor_id="s1",
            ruleset_namespace="",
            log_source_id="l1",
        )

    with pytest.raises(ValueError, match="log_source_id must be a non-empty string"):
        parse_suricata_eve_alert_file(
            STANDARD_FIXTURE,
            sensor_id="s1",
            ruleset_namespace="et-open",
            log_source_id="  ",
        )

    with pytest.raises(ValueError, match="cannot contain delimiter '#'"):
        parse_suricata_eve_alert_file(
            STANDARD_FIXTURE,
            sensor_id="s1",
            ruleset_namespace="et-open",
            log_source_id="l1",
            routing_domain_id="bad#dom",
        )

    with pytest.raises(ValueError, match="Invalid community_id_seed"):
        parse_suricata_eve_alert_file(
            STANDARD_FIXTURE,
            sensor_id="s1",
            ruleset_namespace="et-open",
            log_source_id="l1",
            community_id_seed=70000,
        )

    # V1 ingestion package __all__ must remain completely isolated
    assert set(ingestion_pkg.__all__) == {
        "TrafficRecord",
        "AlertRecord",
        "IngestionSummary",
        "parse_traffic_file",
        "parse_alert_file",
    }
