"""
Unit tests for Neo4j graph schema module.
"""

from unittest.mock import MagicMock
import pytest
from src.graph.schema import (
    ensure_schema,
    MigrationRequiredError,
    SCHEMA_STATEMENTS,
    LEGACY_DROP_STATEMENTS,
)


def test_schema_statements_definitions():
    """Verify expected uniqueness constraints and indexes are defined for V2 schema."""
    statements_text = " ".join(SCHEMA_STATEMENTS)

    # V2 routing domain uniqueness
    assert "CONSTRAINT routing_domain_unique" in statements_text
    assert "FOR (rd:RoutingDomain) REQUIRE rd.domain_id IS UNIQUE" in statements_text

    # V2 scoped IP uniqueness
    assert "CONSTRAINT ip_scoped_unique" in statements_text
    assert "FOR (ip:IPAddress) REQUIRE ip.scoped_id IS UNIQUE" in statements_text

    # V2 IP address lookup index (non-unique)
    assert "INDEX ip_address_index" in statements_text
    assert "FOR (ip:IPAddress) ON (ip.address)" in statements_text

    # IP address is no longer globally unique in active schema statements
    assert "FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE" not in statements_text

    # Layer 2 and AlertFact constraints remain active
    assert "CONSTRAINT layer2_identifier_unique" in statements_text
    assert "FOR (l2:Layer2Identifier) REQUIRE l2.identifier IS UNIQUE" in statements_text

    assert "CONSTRAINT alert_fact_unique" in statements_text
    assert "FOR (fact:AlertFact) REQUIRE fact.fact_key IS UNIQUE" in statements_text

    assert "INDEX alert_fact_priority_index" in statements_text
    assert "INDEX alert_fact_sid_index" in statements_text

    # Legacy drop statements contain legacy ip_address_unique constraint
    legacy_text = " ".join(LEGACY_DROP_STATEMENTS)
    assert "DROP CONSTRAINT ip_address_unique IF EXISTS" in legacy_text


def test_ensure_schema_execution_when_clean():
    """Verify ensure_schema runs preflight check, drops legacy constraint, and applies V2 schema."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Preflight check returns 0 unmigrated nodes
    mock_check_res = MagicMock()
    mock_check_res.single.return_value = {"unmigrated_count": 0}

    mock_ddl_res = MagicMock()

    def run_side_effect(stmt, **params):
        if "unmigrated_count" in stmt:
            return mock_check_res
        return mock_ddl_res

    mock_session.run.side_effect = run_side_effect

    ensure_schema(mock_driver)

    # 1 preflight check + 1 legacy drop + 7 schema statements = 9 calls
    total_expected = 1 + len(LEGACY_DROP_STATEMENTS) + len(SCHEMA_STATEMENTS)
    assert mock_session.run.call_count == total_expected

    executed_statements = [call.args[0] for call in mock_session.run.call_args_list]
    assert any("unmigrated_count" in s for s in executed_statements)
    for drop in LEGACY_DROP_STATEMENTS:
        assert drop in executed_statements
    for stmt in SCHEMA_STATEMENTS:
        assert stmt in executed_statements


def test_ensure_schema_raises_when_unmigrated_nodes_exist():
    """Verify ensure_schema refuses and raises MigrationRequiredError if unmigrated nodes exist."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_check_res = MagicMock()
    mock_check_res.single.return_value = {"unmigrated_count": 5}
    mock_session.run.return_value = mock_check_res

    with pytest.raises(MigrationRequiredError) as exc_info:
        ensure_schema(mock_driver)

    assert exc_info.value.unmigrated_count == 5
    assert "5 legacy V1 IPAddress node(s)" in str(exc_info.value)

    # Must only have called the preflight check, and MUST NOT have called any DROP statements!
    assert mock_session.run.call_count == 1
    assert "DROP CONSTRAINT" not in mock_session.run.call_args[0][0]


def test_ensure_schema_creates_v2_uniqueness_before_dropping_legacy():
    """Verify ensure_schema establishes routing_domain_unique and ip_scoped_unique BEFORE dropping ip_address_unique."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_check_res = MagicMock()
    mock_check_res.single.return_value = {"unmigrated_count": 0}
    mock_ddl_res = MagicMock()

    mock_session.run.side_effect = lambda stmt, **params: (
        mock_check_res if "unmigrated_count" in stmt else mock_ddl_res
    )

    ensure_schema(mock_driver)

    executed = [call.args[0] for call in mock_session.run.call_args_list]
    idx_rd_unique = next(i for i, s in enumerate(executed) if "routing_domain_unique" in s)
    idx_ip_scoped_unique = next(i for i, s in enumerate(executed) if "ip_scoped_unique" in s)
    idx_drop_legacy = next(i for i, s in enumerate(executed) if "DROP CONSTRAINT ip_address_unique" in s)
    idx_ip_addr_index = next(i for i, s in enumerate(executed) if "INDEX ip_address_index" in s)

    # Zero unprotected uniqueness window: new uniqueness constraints BEFORE drop; non-unique index AFTER drop
    assert idx_rd_unique < idx_drop_legacy
    assert idx_ip_scoped_unique < idx_drop_legacy
    assert idx_drop_legacy < idx_ip_addr_index
