"""
Unit tests for V2 identity primitives and canonical fingerprint utilities.

Verifies:
- Scoped IP address identity (scoping, RFC 5952 canonicalization, domain isolation, domain character preservation)
- V2 directional flow key (determinism, strict directionality, port range validation, stable null ports)
- Timestamp canonicalization (preserves source precision, nanosecond discrimination, numeric equivalence)
- Observation ID (mandatory native source_record_id, idempotency, temporal sensitivity, source provenance)
- Alert Definition ID (engine and namespace isolation, explicit 'none' sentinel for absent GID)
- Alert Event ID (mandatory native source_record_id, occurrence idempotency, temporal distinction)
- Frozen immutable dataclass contracts for minimal V2 domain models
"""

from decimal import Decimal
import pytest
from src.ingestion.v2_models import (
    scoped_ip_id,
    compute_v2_flow_key,
    compute_observation_id,
    alert_definition_id,
    compute_alert_event_id,
    canonicalize_event_timestamp,
    RoutingDomainRecord,
    ScopedIPAddressRecord,
    FlowObservationRecord,
    AlertEventRecord,
)


# ---------------------------------------------------------------------------
# Timestamp Canonicalization Tests
# ---------------------------------------------------------------------------

def test_canonicalize_event_timestamp_numeric_equivalence():
    """Verify equivalent numeric representations produce identical canonical strings."""
    assert canonicalize_event_timestamp(1725148800) == "1725148800"
    assert canonicalize_event_timestamp(1725148800.0) == "1725148800"
    assert canonicalize_event_timestamp(1725148800.1) == "1725148800.1"
    assert canonicalize_event_timestamp("1725148800.1000") == "1725148800.1"
    assert canonicalize_event_timestamp(Decimal("1725148800.1000")) == "1725148800.1"


def test_canonicalize_event_timestamp_preserves_nanosecond_precision():
    """Verify nanosecond-level timestamps do not round or collapse."""
    ts1 = "1725148800.000000001"
    ts2 = "1725148800.000000002"
    c_ts1 = canonicalize_event_timestamp(ts1)
    c_ts2 = canonicalize_event_timestamp(ts2)
    assert c_ts1 == "1725148800.000000001"
    assert c_ts2 == "1725148800.000000002"
    assert c_ts1 != c_ts2


def test_canonicalize_event_timestamp_preserves_iso_strings():
    """Verify ISO 8601 strings from Suricata EVE are preserved trimmed."""
    iso_str = "2024-09-01T12:00:00.123456+00:00"
    assert canonicalize_event_timestamp(f"  {iso_str}  ") == iso_str


def test_canonicalize_event_timestamp_invalid_inputs_raise():
    """Verify empty, None, NaN, and Infinite values raise ValueError."""
    with pytest.raises(ValueError, match="timestamp cannot be None"):
        canonicalize_event_timestamp(None)  # type: ignore
    with pytest.raises(ValueError, match="timestamp cannot be empty"):
        canonicalize_event_timestamp("")
    with pytest.raises(ValueError, match="timestamp cannot be empty"):
        canonicalize_event_timestamp("   ")
    with pytest.raises(ValueError, match="cannot be NaN or Infinite"):
        canonicalize_event_timestamp(float("nan"))
    with pytest.raises(ValueError, match="cannot be NaN or Infinite"):
        canonicalize_event_timestamp(float("inf"))


# ---------------------------------------------------------------------------
# Scoped IP Identity Tests
# ---------------------------------------------------------------------------

def test_scoped_ip_id_basic_ipv4():
    """Verify scoped_ip_id formats domain and IPv4 address cleanly."""
    scoped = scoped_ip_id("corp-main", "10.10.10.25")
    assert scoped == "corp-main#10.10.10.25"


def test_scoped_ip_id_default_domain_when_none_or_empty():
    """Verify scoped_ip_id defaults domain to 'default' when None, empty, or whitespace."""
    assert scoped_ip_id(None, "192.168.1.1") == "default#192.168.1.1"
    assert scoped_ip_id("", "192.168.1.1") == "default#192.168.1.1"
    assert scoped_ip_id("   ", "192.168.1.1") == "default#192.168.1.1"


def test_scoped_ip_id_domain_normalization_preserves_structural_characters():
    """Verify domain is lowercased and trimmed, preserving hyphens, dots, and underscores."""
    assert scoped_ip_id("  VRF-PROD.DMZ_1  ", "10.0.0.1") == "vrf-prod.dmz_1#10.0.0.1"


def test_scoped_ip_id_ipv6_canonicalization():
    """Verify RFC 5952 canonicalization produces identical scoped ID for expanded and compressed IPv6."""
    compressed = scoped_ip_id("lab-a", "2001:db8::1")
    expanded = scoped_ip_id("lab-a", "2001:0db8:0000:0000:0000:0000:0000:0001")
    assert compressed == "lab-a#2001:db8::1"
    assert compressed == expanded


def test_scoped_ip_id_domain_isolation_for_overlapping_rfc1918():
    """Verify same private IP in different routing domains yields different scoped IDs."""
    site_a = scoped_ip_id("site_a", "192.168.1.10")
    site_b = scoped_ip_id("site_b", "192.168.1.10")
    assert site_a != site_b
    assert site_a == "site_a#192.168.1.10"
    assert site_b == "site_b#192.168.1.10"


def test_scoped_ip_id_disallows_delimiter_hash_in_domain():
    """Verify domain containing delimiter '#' raises ValueError."""
    with pytest.raises(ValueError, match="cannot contain delimiter '#'"):
        scoped_ip_id("invalid#domain", "10.0.0.1")


def test_scoped_ip_id_invalid_ip_raises_value_error():
    """Verify invalid or empty IP raises ValueError."""
    with pytest.raises(ValueError, match="ip_address cannot be empty"):
        scoped_ip_id("corp", "")
    with pytest.raises(ValueError, match="Invalid IP address"):
        scoped_ip_id("corp", "999.999.999.999")
    with pytest.raises(ValueError, match="Invalid IP address"):
        scoped_ip_id("corp", "not-an-ip")


# ---------------------------------------------------------------------------
# V2 Directional Flow Key Tests
# ---------------------------------------------------------------------------

def test_v2_flow_key_determinism():
    """Verify compute_v2_flow_key produces exact deterministic SHA-256."""
    key1 = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    key2 = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    assert len(key1) == 64
    assert key1 == key2


def test_v2_flow_key_strict_directionality():
    """Verify A -> B produces a different flow_key than B -> A."""
    forward = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    reverse = compute_v2_flow_key("corp#10.0.0.2", "corp#10.0.0.1", "TCP", 443, 50000)
    assert forward != reverse


def test_v2_flow_key_protocol_normalization():
    """Verify protocol normalization to uppercase."""
    key_upper = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    key_lower = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "tcp", 50000, 443)
    key_spaces = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "  TCP  ", 50000, 443)
    assert key_upper == key_lower
    assert key_upper == key_spaces


def test_v2_flow_key_stable_null_ports():
    """Verify nullable ports map stably without error for protocols without transport ports."""
    key_no_ports = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "ICMP", None, None)
    key_same = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "ICMP", None, None)
    assert key_no_ports == key_same
    assert len(key_no_ports) == 64


def test_v2_flow_key_port_range_validation():
    """Verify integer ports must be in range 0..65535."""
    # Valid bounds
    assert compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 0, 65535) is not None

    with pytest.raises(ValueError, match="Invalid src_port"):
        compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 70000, 80)
    with pytest.raises(ValueError, match="Invalid dst_port"):
        compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 80, -1)
    with pytest.raises(ValueError, match="Invalid src_port"):
        compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", True, 80)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Invalid dst_port"):
        compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 80, False)  # type: ignore[arg-type]


def test_v2_flow_key_domain_isolation():
    """Verify same raw IPs in different routing domains produce different flow keys."""
    key_site_a = compute_v2_flow_key("site_a#10.0.0.1", "site_a#10.0.0.2", "TCP", 1000, 80)
    key_site_b = compute_v2_flow_key("site_b#10.0.0.1", "site_b#10.0.0.2", "TCP", 1000, 80)
    assert key_site_a != key_site_b


def test_v2_flow_key_empty_endpoint_raises():
    """Verify empty endpoint string raises ValueError."""
    with pytest.raises(ValueError, match="src_scoped_id cannot be empty"):
        compute_v2_flow_key("", "corp#10.0.0.2", "TCP", 1000, 80)
    with pytest.raises(ValueError, match="dst_scoped_id cannot be empty"):
        compute_v2_flow_key("corp#10.0.0.1", "", "TCP", 1000, 80)


# ---------------------------------------------------------------------------
# Observation ID Tests
# ---------------------------------------------------------------------------

def test_observation_id_determinism_and_idempotency():
    """Verify compute_observation_id produces exact deterministic hash for identical telemetry."""
    flow_key = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    obs1 = compute_observation_id(
        source_type="zeek",
        sensor_id="core-tap-01",
        source_record_id="CHhAvVGS1DHFjwGM9",
        timestamp="1725148800.123456789",
        flow_key=flow_key,
        source_provenance="pcap-batch-01",
    )
    obs2 = compute_observation_id(
        source_type="zeek",
        sensor_id="core-tap-01",
        source_record_id="CHhAvVGS1DHFjwGM9",
        timestamp="1725148800.123456789",
        flow_key=flow_key,
        source_provenance="pcap-batch-01",
    )
    assert len(obs1) == 64
    assert obs1 == obs2


def test_observation_id_requires_non_empty_source_record_id():
    """Verify missing or empty native source_record_id raises ValueError."""
    flow_key = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    with pytest.raises(ValueError, match="source_record_id cannot be empty"):
        compute_observation_id("zeek", "sensor-1", "", 1725148800.0, flow_key)
    with pytest.raises(ValueError, match="source_record_id cannot be empty"):
        compute_observation_id("zeek", "sensor-1", "   ", 1725148800.0, flow_key)


def test_observation_id_different_record_id_yields_different_id():
    """Verify distinct native connection/record IDs yield distinct observation IDs."""
    flow_key = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    obs_uid1 = compute_observation_id("zeek", "sensor-1", "uid-100", 1725148800.0, flow_key)
    obs_uid2 = compute_observation_id("zeek", "sensor-1", "uid-101", 1725148800.0, flow_key)
    assert obs_uid1 != obs_uid2


def test_observation_id_different_nanosecond_time_yields_different_id():
    """Verify nanosecond timestamp difference prevents observation collapse."""
    flow_key = compute_v2_flow_key("corp#10.0.0.1", "corp#10.0.0.2", "TCP", 50000, 443)
    obs_t1 = compute_observation_id("zeek", "sensor-1", "uid-1", "1725148800.000000001", flow_key)
    obs_t2 = compute_observation_id("zeek", "sensor-1", "uid-1", "1725148800.000000002", flow_key)
    assert obs_t1 != obs_t2


# ---------------------------------------------------------------------------
# Alert Definition ID Tests
# ---------------------------------------------------------------------------

def test_alert_definition_id_canonical_formatting():
    """Verify alert_definition_id normalizes engine and namespace to lowercase."""
    def_id = alert_definition_id("Suricata", "ET-OPEN", 1, 2001219)
    assert def_id == "suricata:et-open:1:2001219"


def test_alert_definition_id_none_gid_uses_explicit_none_sentinel():
    """Verify gid=None produces explicit 'none' sentinel, distinct from gid=1."""
    def_none = alert_definition_id("suricata", "custom", None, 100)
    def_one = alert_definition_id("suricata", "custom", 1, 100)

    assert def_none == "suricata:custom:none:100"
    assert def_one == "suricata:custom:1:100"
    assert def_none != def_one


def test_alert_definition_id_engine_and_namespace_isolation():
    """Verify different engine or ruleset namespace yields different definition IDs."""
    suricata_et = alert_definition_id("suricata", "et-open", 1, 100)
    snort_et = alert_definition_id("snort", "et-open", 1, 100)
    suricata_local = alert_definition_id("suricata", "local", 1, 100)

    assert suricata_et != snort_et
    assert suricata_et != suricata_local


def test_alert_definition_id_validation_errors():
    """Verify empty engine, empty namespace, negative gid, or invalid sid raises ValueError."""
    with pytest.raises(ValueError, match="engine cannot be empty"):
        alert_definition_id("", "et-open", 1, 100)
    with pytest.raises(ValueError, match="ruleset_namespace cannot be empty"):
        alert_definition_id("suricata", "", 1, 100)
    with pytest.raises(ValueError, match="Invalid signature ID"):
        alert_definition_id("suricata", "et-open", 1, -1)
    with pytest.raises(ValueError, match="Invalid generator ID"):
        alert_definition_id("suricata", "et-open", -5, 100)
    with pytest.raises(ValueError, match="Invalid signature ID"):
        alert_definition_id("suricata", "et-open", 1, True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Invalid generator ID"):
        alert_definition_id("suricata", "et-open", False, 100)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Alert Event ID Tests
# ---------------------------------------------------------------------------

def test_alert_event_id_requires_non_empty_source_record_id():
    """Verify missing native event ID raises ValueError."""
    def_id = alert_definition_id("suricata", "et-open", 1, 2001219)
    with pytest.raises(ValueError, match="source_record_id cannot be empty"):
        compute_alert_event_id("suricata", "sensor-1", "", 1725148800.0, def_id)
    with pytest.raises(ValueError, match="source_record_id cannot be empty"):
        compute_alert_event_id("suricata", "sensor-1", "   ", 1725148800.0, def_id)


def test_alert_event_id_determinism_and_temporal_distinction():
    """Verify alert_event_id determinism and distinct occurrence timestamps."""
    def_id = alert_definition_id("suricata", "et-open", 1, 2001219)
    event1 = compute_alert_event_id(
        source_type="suricata",
        sensor_id="sensor-01",
        source_record_id="140382910485728",
        timestamp="2024-09-01T12:00:00.100000+00:00",
        def_id=def_id,
        flow_reference="1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
    )
    event1_dup = compute_alert_event_id(
        source_type="suricata",
        sensor_id="sensor-01",
        source_record_id="140382910485728",
        timestamp="2024-09-01T12:00:00.100000+00:00",
        def_id=def_id,
        flow_reference="1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
    )
    event2 = compute_alert_event_id(
        source_type="suricata",
        sensor_id="sensor-01",
        source_record_id="140382910485729",  # different event
        timestamp="2024-09-01T12:00:00.100000+00:00",
        def_id=def_id,
        flow_reference="1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
    )

    assert len(event1) == 64
    assert event1 == event1_dup
    assert event1 != event2


# ---------------------------------------------------------------------------
# Minimal Domain Model Contracts
# ---------------------------------------------------------------------------

def test_domain_model_dataclasses_are_frozen():
    """Verify minimal domain dataclasses are immutable/frozen."""
    rd = RoutingDomainRecord(domain_id="corp", name="Corporate Network")
    with pytest.raises(Exception):
        rd.domain_id = "other"  # type: ignore

    scoped_ip = ScopedIPAddressRecord(
        scoped_id="corp#10.0.0.1",
        domain_id="corp",
        address="10.0.0.1",
        version=4,
        is_private=True,
    )
    with pytest.raises(Exception):
        scoped_ip.address = "10.0.0.2"  # type: ignore

    flow_obs = FlowObservationRecord(
        observation_id="obs-1",
        flow_key="key-1",
        src_scoped_id="corp#10.0.0.1",
        dst_scoped_id="corp#10.0.0.2",
        protocol="TCP",
    )
    with pytest.raises(Exception):
        flow_obs.protocol = "UDP"  # type: ignore

    alert_evt = AlertEventRecord(
        event_id="evt-1",
        alert_definition_id="suricata:et-open:1:100",
        timestamp=1725148800.0,
        src_scoped_id="corp#10.0.0.1",
        dst_scoped_id="corp#10.0.0.2",
    )
    with pytest.raises(Exception):
        alert_evt.timestamp = 0.0  # type: ignore
