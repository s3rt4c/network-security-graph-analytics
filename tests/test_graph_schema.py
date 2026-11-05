"""
Unit tests for Neo4j graph schema module.
"""

from unittest.mock import MagicMock
from src.graph.schema import ensure_schema, SCHEMA_STATEMENTS, LEGACY_DROP_STATEMENTS


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


def test_ensure_schema_execution():
    """Verify ensure_schema calls session.run and consume() for each DDL statement."""
    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_result = MagicMock()
    mock_session.run.return_value = mock_result

    ensure_schema(mock_driver)

    total_expected = len(LEGACY_DROP_STATEMENTS) + len(SCHEMA_STATEMENTS)
    assert mock_session.run.call_count == total_expected
    assert mock_result.consume.call_count == total_expected

    executed_statements = [call.args[0] for call in mock_session.run.call_args_list]
    for drop in LEGACY_DROP_STATEMENTS:
        assert drop in executed_statements
    for stmt in SCHEMA_STATEMENTS:
        assert stmt in executed_statements
