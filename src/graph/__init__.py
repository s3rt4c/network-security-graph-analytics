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
    ObservationConflictError,
    ObservationPersistenceSummary,
    AlertEventConflictError,
    AlertEventPersistenceSummary,
    canonicalize_ip,
    compute_alert_fact_key,
    compute_alert_event_payload_digest,
    chunk_list,
    iter_batches,
    decimal_epoch_to_ns,
    format_exact_decimal,
    zeek_observation_to_payload,
    suricata_alert_to_payload,
    CYPHER_WRITE_TRAFFIC_BATCH,
    CYPHER_WRITE_ALERT_BATCH,
    CYPHER_WRITE_ZEEK_OBSERVATION_BATCH,
    CYPHER_WRITE_SURICATA_ALERT_BATCH,
)
from src.graph.read_repository import Neo4jReadRepository, AmbiguousEndpointError

__all__ = [
    "ensure_schema",
    "migrate_ip_identity_to_scoped",
    "MigrationRequiredError",
    "SCHEMA_STATEMENTS",
    "LEGACY_DROP_STATEMENTS",
    "Neo4jRepository",
    "ObservationConflictError",
    "ObservationPersistenceSummary",
    "AlertEventConflictError",
    "AlertEventPersistenceSummary",
    "Neo4jReadRepository",
    "AmbiguousEndpointError",
    "canonicalize_ip",
    "compute_alert_fact_key",
    "compute_alert_event_payload_digest",
    "chunk_list",
    "iter_batches",
    "decimal_epoch_to_ns",
    "format_exact_decimal",
    "zeek_observation_to_payload",
    "suricata_alert_to_payload",
    "CYPHER_WRITE_TRAFFIC_BATCH",
    "CYPHER_WRITE_ALERT_BATCH",
    "CYPHER_WRITE_ZEEK_OBSERVATION_BATCH",
    "CYPHER_WRITE_SURICATA_ALERT_BATCH",
]
