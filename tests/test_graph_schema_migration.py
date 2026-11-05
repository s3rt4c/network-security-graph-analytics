"""
Unit tests for V2 Neo4j graph schema migration and RoutingDomain scoped IP foundations.
"""

from unittest.mock import MagicMock
import pytest

from src.graph.schema import (
    ensure_schema,
    migrate_ip_identity_to_scoped,
    SCHEMA_STATEMENTS,
    LEGACY_DROP_STATEMENTS,
)
from src.ingestion.v2_models import scoped_ip_id
from src.graph.repository import _traffic_record_to_payload
from src.ingestion.models import TrafficRecord


# ---------------------------------------------------------------------------
# Schema Definitions Tests
# ---------------------------------------------------------------------------
def test_schema_uniqueness_and_indexes():
    """Verify target V2 schema statements enforce scoped_id uniqueness and raw address index."""
    statements_text = " ".join(SCHEMA_STATEMENTS)

    # 1. RoutingDomain uniqueness
    assert "CONSTRAINT routing_domain_unique" in statements_text
    assert "FOR (rd:RoutingDomain) REQUIRE rd.domain_id IS UNIQUE" in statements_text

    # 2. Scoped IP uniqueness
    assert "CONSTRAINT ip_scoped_unique" in statements_text
    assert "FOR (ip:IPAddress) REQUIRE ip.scoped_id IS UNIQUE" in statements_text

    # 3. Raw address non-unique index
    assert "INDEX ip_address_index" in statements_text
    assert "FOR (ip:IPAddress) ON (ip.address)" in statements_text

    # Old global address uniqueness constraint must be absent from active constraints
    assert "FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE" not in statements_text

    # Legacy drop statements must include dropping ip_address_unique
    legacy_text = " ".join(LEGACY_DROP_STATEMENTS)
    assert "DROP CONSTRAINT ip_address_unique IF EXISTS" in legacy_text


# ---------------------------------------------------------------------------
# Migration Preflight Failure Tests
# ---------------------------------------------------------------------------
def test_migrate_ip_identity_preflight_empty_address_fails():
    """Migration preflight must fail loudly if an existing IPAddress has an empty or null address."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Existing node with empty address
    mock_session.run.return_value = [
        {"element_id": "4:abc:1", "address": "", "scoped_id": None, "routing_domain_id": None}
    ]

    with pytest.raises(ValueError, match="has empty address"):
        migrate_ip_identity_to_scoped(mock_driver)


def test_migrate_ip_identity_preflight_malformed_ip_fails():
    """Migration preflight must fail loudly if an existing IPAddress has an un-parseable IP."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_session.run.return_value = [
        {"element_id": "4:abc:2", "address": "not_an_ip", "scoped_id": None, "routing_domain_id": None}
    ]

    with pytest.raises(ValueError, match="cannot generate scoped_id"):
        migrate_ip_identity_to_scoped(mock_driver)


def test_migrate_ip_identity_preflight_collision_fails():
    """Migration preflight must fail loudly if two existing nodes would produce the same scoped_id."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Two nodes with equivalent IPv6 representations in the same domain
    mock_session.run.return_value = [
        {"element_id": "4:abc:3", "address": "2001:0db8:0000:0000:0000:0000:0000:0001", "scoped_id": None, "routing_domain_id": "default"},
        {"element_id": "4:abc:4", "address": "2001:db8::1", "scoped_id": None, "routing_domain_id": "default"},
    ]

    with pytest.raises(ValueError, match="duplicate target scoped_id"):
        migrate_ip_identity_to_scoped(mock_driver)


# ---------------------------------------------------------------------------
# Migration Success and Idempotency Tests
# ---------------------------------------------------------------------------
def test_migrate_ip_identity_success_mock():
    """Verify migration successfully backfills default domain and scoped_id."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_nodes = [
        {"element_id": "4:abc:10", "address": "192.168.1.10", "scoped_id": None, "routing_domain_id": None},
        {"element_id": "4:abc:20", "address": "192.168.1.20", "scoped_id": None, "routing_domain_id": None},
    ]
    mock_session.run.return_value = mock_nodes

    def fake_execute_write(work_fn):
        tx = MagicMock()
        return work_fn(tx)

    mock_session.execute_write.side_effect = fake_execute_write

    stats = migrate_ip_identity_to_scoped(mock_driver, default_domain="default")
    assert stats["total_ips"] == 2
    assert stats["migrated_ips"] == 2
    assert stats["default_domain"] == "default"


def test_migrate_ip_identity_idempotent():
    """Verify running migration on already-migrated nodes results in 0 updates."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Nodes already have correct scoped_id and routing_domain_id
    mock_nodes = [
        {"element_id": "4:abc:10", "address": "192.168.1.10", "scoped_id": "default#192.168.1.10", "routing_domain_id": "default"},
        {"element_id": "4:abc:20", "address": "192.168.1.20", "scoped_id": "default#192.168.1.20", "routing_domain_id": "default"},
    ]
    mock_session.run.return_value = mock_nodes

    def fake_execute_write(work_fn):
        tx = MagicMock()
        return work_fn(tx)

    mock_session.execute_write.side_effect = fake_execute_write

    stats = migrate_ip_identity_to_scoped(mock_driver, default_domain="default")
    assert stats["total_ips"] == 2
    assert stats["migrated_ips"] == 0


# ---------------------------------------------------------------------------
# Overlapping Address Proof Tests
# ---------------------------------------------------------------------------
def test_overlapping_rfc1918_distinct_scoped_ids():
    """Verify identical RFC 1918 addresses produce distinct scoped_ids across corp and branch domains."""
    corp_scoped = scoped_ip_id("corp", "10.0.0.5")
    branch_scoped = scoped_ip_id("branch", "10.0.0.5")

    assert corp_scoped == "corp#10.0.0.5"
    assert branch_scoped == "branch#10.0.0.5"
    assert corp_scoped != branch_scoped


def test_traffic_payload_supports_routing_domain():
    """Verify _traffic_record_to_payload generates domain-qualified scoped_ids."""
    record = TrafficRecord(
        eth_src_resolved="00:11:22:33:44:01",
        eth_dst_resolved="00:11:22:33:44:02",
        ip_src="10.0.0.5",
        ip_dst="10.0.0.6",
        protocol="TCP",
    )

    corp_payload = _traffic_record_to_payload(record, domain_id="corp")
    branch_payload = _traffic_record_to_payload(record, domain_id="branch")

    assert corp_payload["ip_src"] == "10.0.0.5"
    assert branch_payload["ip_src"] == "10.0.0.5"
    assert corp_payload["src_scoped_id"] == "corp#10.0.0.5"
    assert branch_payload["src_scoped_id"] == "branch#10.0.0.5"
    assert corp_payload["routing_domain_id"] == "corp"
    assert branch_payload["routing_domain_id"] == "branch"
