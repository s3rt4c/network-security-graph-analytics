"""
Unit tests for Community ID v1 calculation adapter.

Verifies:
- Standard reference test vectors (official Corelight / Community ID v1 outputs)
- Direction independence (bidirectional property: A -> B equals B -> A)
- Determinism across repeated executions
- Configurable seed behavior
- IPv4 and IPv6 support (including expanded/compressed IPv6 representation equivalence)
- ICMP support
- Robust error handling for invalid IPs, invalid ports, and missing fields
- Preservation of existing telemetry-supplied Community IDs (including future version formats)
- Rejection of whitespace-only strings as valid existing IDs
- Graceful None returns on unsupported or incomplete inputs
"""

import pytest
from src.ingestion.community_id import (
    compute_community_id,
    resolve_community_id,
    _normalize_protocol_number,
)


def test_official_reference_test_vector_ipv4_tcp():
    """Verify official Community ID v1 test vector for IPv4 TCP."""
    cid = compute_community_id(
        ip_src="128.232.110.120",
        ip_dst="66.35.250.204",
        protocol="TCP",
        src_port=34855,
        dst_port=80,
        seed=0,
    )
    assert cid == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def test_protocol_normalization_tcp_numeric_and_case():
    """Verify numeric protocol 6 and lowercase 'tcp' map to identical Community ID."""
    cid_named = compute_community_id("128.232.110.120", "66.35.250.204", "tcp", 34855, 80)
    cid_numeric = compute_community_id("128.232.110.120", "66.35.250.204", 6, 34855, 80)
    cid_str_num = compute_community_id("128.232.110.120", "66.35.250.204", "6", 34855, 80)

    assert cid_named == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert cid_numeric == cid_named
    assert cid_str_num == cid_named


def test_direction_independence_tcp():
    """Verify Community ID is strictly bidirectional for TCP (A -> B equals B -> A)."""
    forward = compute_community_id("128.232.110.120", "66.35.250.204", "TCP", 34855, 80)
    reverse = compute_community_id("66.35.250.204", "128.232.110.120", "TCP", 80, 34855)

    assert forward == reverse
    assert forward == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def test_direction_independence_udp():
    """Verify Community ID is strictly bidirectional for UDP."""
    forward = compute_community_id("192.168.1.10", "10.0.0.100", "UDP", 53535, 53)
    reverse = compute_community_id("10.0.0.100", "192.168.1.10", "UDP", 53, 53535)

    assert forward == reverse
    assert forward == "1:UQtuuV22XA4dvyxjHyVMKBhy+fc="


def test_determinism_repeated_calls():
    """Verify same inputs always produce exact same Community ID."""
    results = [
        compute_community_id("192.168.1.10", "192.168.1.20", "TCP", 50000, 443, seed=0)
        for _ in range(50)
    ]
    assert len(set(results)) == 1
    assert results[0] is not None


def test_seed_behavior_modifies_hash():
    """Verify different seed produces a different Community ID."""
    cid_seed_0 = compute_community_id("128.232.110.120", "66.35.250.204", "TCP", 34855, 80, seed=0)
    cid_seed_1 = compute_community_id("128.232.110.120", "66.35.250.204", "TCP", 34855, 80, seed=1)
    cid_seed_100 = compute_community_id("128.232.110.120", "66.35.250.204", "TCP", 34855, 80, seed=100)

    assert cid_seed_0 == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert cid_seed_1 == "1:3V71V58M3Ksw/yuFALMcW0LAHvc="
    assert cid_seed_0 != cid_seed_1
    assert cid_seed_0 != cid_seed_100
    assert cid_seed_1 != cid_seed_100


def test_ipv6_tcp_support_and_direction_independence():
    """Verify IPv4 and IPv6 support with direction independence."""
    forward = compute_community_id("2001:db8::1", "2001:db8::2", "TCP", 1234, 80)
    reverse = compute_community_id("2001:db8::2", "2001:db8::1", "TCP", 80, 1234)

    assert forward == "1:r0kqPLw6hSIAasyo9ANthUgbhVA="
    assert forward == reverse


def test_ipv6_representation_equivalence():
    """Verify compressed and expanded IPv6 addresses map to the same Community ID."""
    compressed = compute_community_id("2001:db8::1", "2001:db8::2", "TCP", 1234, 80)
    expanded = compute_community_id(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:0db8:0000:0000:0000:0000:0000:0002",
        "TCP",
        1234,
        80,
    )
    assert compressed == expanded


def test_icmp_support():
    """Verify ICMP calculation using type and code as ports."""
    cid = compute_community_id("192.168.1.10", "10.0.0.100", "ICMP", src_port=8, dst_port=0)
    assert cid == "1:qK0/+v/58fvqYIsJ2woOPcpmIPA="


def test_invalid_ip_returns_none():
    """Verify invalid IP addresses fail gracefully returning None."""
    assert compute_community_id("999.999.999.999", "1.1.1.1", "TCP", 1234, 80) is None
    assert compute_community_id("not-an-ip", "1.1.1.1", "TCP", 1234, 80) is None
    assert compute_community_id("", "1.1.1.1", "TCP", 1234, 80) is None
    assert compute_community_id("1.1.1.1", "", "TCP", 1234, 80) is None


def test_invalid_port_returns_none():
    """Verify invalid and out-of-range ports return None."""
    assert compute_community_id("1.1.1.1", "2.2.2.2", "TCP", 70000, 80) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", "TCP", -1, 80) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", "TCP", None, 80) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", "TCP", 80, None) is None


def test_unsupported_protocol_returns_none():
    """Verify unsupported protocol strings return None."""
    assert compute_community_id("1.1.1.1", "2.2.2.2", "UNKNOWN_PROTOCOL", 80, 80) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", None, 80, 80) is None


def test_resolve_community_id_preserves_existing_v1():
    """Verify resolve_community_id preserves non-empty existing v1 IDs without recomputation."""
    existing = "1:CustomZeekOrSuricataSuppliedID="
    resolved = resolve_community_id(
        existing_id=existing,
        ip_src="1.1.1.1",
        ip_dst="2.2.2.2",
        protocol="TCP",
        src_port=1000,
        dst_port=80,
    )
    assert resolved == existing


def test_resolve_community_id_preserves_future_versions_opaquely():
    """Verify resolve_community_id does not force or rewrite future Community ID version formats."""
    future_id = "2:FutureFormatWhateverValue=="
    resolved = resolve_community_id(
        existing_id=future_id,
        ip_src="1.1.1.1",
        ip_dst="2.2.2.2",
        protocol="TCP",
        src_port=1000,
        dst_port=80,
    )
    assert resolved == future_id


def test_resolve_community_id_whitespace_only_treated_as_unavailable():
    """Verify whitespace-only string is treated as unavailable and does not become a valid Community ID."""
    # When tuple is missing, whitespace-only existing_id returns None
    assert resolve_community_id(existing_id="   ") is None

    # When tuple is present, whitespace-only existing_id falls back to computing Community ID
    computed = resolve_community_id(
        existing_id="   ",
        ip_src="128.232.110.120",
        ip_dst="66.35.250.204",
        protocol="TCP",
        src_port=34855,
        dst_port=80,
    )
    assert computed == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def test_resolve_community_id_computes_when_existing_is_none_or_empty():
    """Verify resolve_community_id computes Community ID when existing_id is absent."""
    resolved_none = resolve_community_id(
        existing_id=None,
        ip_src="128.232.110.120",
        ip_dst="66.35.250.204",
        protocol="TCP",
        src_port=34855,
        dst_port=80,
    )
    assert resolved_none == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

    resolved_empty = resolve_community_id(
        existing_id="",
        ip_src="128.232.110.120",
        ip_dst="66.35.250.204",
        protocol="TCP",
        src_port=34855,
        dst_port=80,
    )
    assert resolved_empty == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def test_resolve_community_id_returns_none_when_insufficient_data():
    """Verify resolve_community_id returns None when existing is absent and tuple is insufficient."""
    assert resolve_community_id(existing_id=None, ip_src="1.1.1.1", ip_dst=None) is None
    assert resolve_community_id(existing_id="", ip_src=None) is None
    assert resolve_community_id(existing_id=None) is None


def test_sctp_support_and_direction_independence():
    """Verify SCTP (IANA 132) computes valid bidirectional Community ID v1 with ports."""
    forward = compute_community_id("1.1.1.1", "2.2.2.2", "SCTP", 1000, 2000)
    reverse = compute_community_id("2.2.2.2", "1.1.1.1", 132, 2000, 1000)

    assert forward == "1:NVQBrwNzYhbXlbkw8XA1ZipcKFM="
    assert forward == reverse

    # Missing or invalid ports for SCTP must return None
    assert compute_community_id("1.1.1.1", "2.2.2.2", "SCTP", None, 2000) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", "SCTP", 1000, None) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", "SCTP", 70000, 2000) is None


def test_bool_protocol_and_ports_rejected():
    """Verify Python bools are not silently coerced to int protocol/port values."""
    assert _normalize_protocol_number(True) is None
    assert _normalize_protocol_number(False) is None
    assert compute_community_id("1.1.1.1", "2.2.2.2", True, 1000, 80) is None  # type: ignore[arg-type]
    assert compute_community_id("1.1.1.1", "2.2.2.2", "TCP", True, 80) is None  # type: ignore[arg-type]
    assert compute_community_id("1.1.1.1", "2.2.2.2", "TCP", 1000, False) is None  # type: ignore[arg-type]
