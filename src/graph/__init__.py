"""
Graph persistence and query module for Neo4j.
"""

from src.graph.schema import (
    ensure_schema,
    migrate_ip_identity_to_scoped,
    MigrationRequiredError,
    SCHEMA_STATEMENTS,
    LEGACY_DROP_STATEMENTS,
)
from src.graph.repository import (
    Neo4jRepository,
    canonicalize_ip,
    compute_alert_fact_key,
    chunk_list,
    CYPHER_WRITE_TRAFFIC_BATCH,
    CYPHER_WRITE_ALERT_BATCH,
)
from src.graph.read_repository import Neo4jReadRepository, AmbiguousEndpointError

__all__ = [
    "ensure_schema",
    "migrate_ip_identity_to_scoped",
    "MigrationRequiredError",
    "SCHEMA_STATEMENTS",
    "LEGACY_DROP_STATEMENTS",
    "Neo4jRepository",
    "Neo4jReadRepository",
    "AmbiguousEndpointError",
    "canonicalize_ip",
    "compute_alert_fact_key",
    "chunk_list",
    "CYPHER_WRITE_TRAFFIC_BATCH",
    "CYPHER_WRITE_ALERT_BATCH",
]
