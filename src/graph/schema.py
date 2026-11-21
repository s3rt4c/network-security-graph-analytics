"""
Neo4j Graph Schema and Constraint Management.

Defines idempotent Neo4j 5.x uniqueness constraints and RANGE indexes
for the modernized V2 graph model supporting scoped IP identities
and routing domains.
"""

import logging
from typing import List, Dict, Any, Optional
from src.ingestion.v2_models import scoped_ip_id

logger = logging.getLogger(__name__)


class MigrationRequiredError(RuntimeError):
    """Raised when unmigrated legacy V1 IPAddress nodes are detected during schema verification."""

    def __init__(self, unmigrated_count: int, message: Optional[str] = None):
        self.unmigrated_count = unmigrated_count
        super().__init__(
            message
            or f"Database contains {unmigrated_count} legacy V1 IPAddress node(s) lacking scoped_id. "
            "Run migrate_ip_identity_to_scoped(driver) before applying V2 schema or writing records."
        )


# Legacy constraints to drop during schema migration / initialization
LEGACY_DROP_STATEMENTS: List[str] = [
    "DROP CONSTRAINT ip_address_unique IF EXISTS",
]

# Constraints created BEFORE dropping legacy ip_address_unique so IPAddress and
# RoutingDomain are never left without a uniqueness guard during schema transition.
PRE_DROP_SCHEMA_STATEMENTS: List[str] = [
    # 1. RoutingDomain uniqueness constraint on domain_id
    "CREATE CONSTRAINT routing_domain_unique IF NOT EXISTS "
    "FOR (rd:RoutingDomain) REQUIRE rd.domain_id IS UNIQUE",

    # 2. IPAddress uniqueness constraint on scoped_id
    "CREATE CONSTRAINT ip_scoped_unique IF NOT EXISTS "
    "FOR (ip:IPAddress) REQUIRE ip.scoped_id IS UNIQUE",
]

# Indexes and constraints applied AFTER dropping legacy ip_address_unique
# (ip_address_index shares (IPAddress, address) with legacy ip_address_unique).
POST_DROP_SCHEMA_STATEMENTS: List[str] = [
    # 3. IPAddress lookup index on raw address (non-unique)
    "CREATE INDEX ip_address_index IF NOT EXISTS "
    "FOR (ip:IPAddress) ON (ip.address)",

    # 4. Layer2Identifier uniqueness constraint
    "CREATE CONSTRAINT layer2_identifier_unique IF NOT EXISTS "
    "FOR (l2:Layer2Identifier) REQUIRE l2.identifier IS UNIQUE",

    # 5. AlertFact uniqueness constraint on deterministic fact_key
    "CREATE CONSTRAINT alert_fact_unique IF NOT EXISTS "
    "FOR (fact:AlertFact) REQUIRE fact.fact_key IS UNIQUE",

    # 6. AlertFact priority index for severity queries
    "CREATE INDEX alert_fact_priority_index IF NOT EXISTS "
    "FOR (fact:AlertFact) ON (fact.priority)",

    # 7. AlertFact sid index for rule/signature queries
    "CREATE INDEX alert_fact_sid_index IF NOT EXISTS "
    "FOR (fact:AlertFact) ON (fact.sid)",

    # 8. FlowObservation uniqueness constraint on deterministic observation_id
    "CREATE CONSTRAINT flow_observation_unique IF NOT EXISTS "
    "FOR (fo:FlowObservation) REQUIRE fo.observation_id IS UNIQUE",

    # 9. FlowObservation non-unique lookup index on Community ID for cross-tool correlation
    "CREATE INDEX flow_observation_community_id_index IF NOT EXISTS "
    "FOR (fo:FlowObservation) ON (fo.community_id)",

    # 10. FlowObservation lookup index on sensor_id
    "CREATE INDEX flow_observation_sensor_id_index IF NOT EXISTS "
    "FOR (fo:FlowObservation) ON (fo.sensor_id)",

    # 11. FlowObservation lookup index on routing_domain_id
    "CREATE INDEX flow_observation_routing_domain_index IF NOT EXISTS "
    "FOR (fo:FlowObservation) ON (fo.routing_domain_id)",

    # 12. FlowObservation numeric temporal index on lossless 64-bit epoch nanoseconds
    "CREATE INDEX flow_observation_start_epoch_ns_index IF NOT EXISTS "
    "FOR (fo:FlowObservation) ON (fo.start_epoch_ns)",

    # 13. Suricata AlertDefinition unique rule identity constraint
    "CREATE CONSTRAINT alert_definition_unique IF NOT EXISTS "
    "FOR (ad:AlertDefinition) REQUIRE ad.definition_id IS UNIQUE",

    # 14. Suricata AlertEvent unique immutable event identity constraint
    "CREATE CONSTRAINT alert_event_unique IF NOT EXISTS "
    "FOR (ae:AlertEvent) REQUIRE ae.event_id IS UNIQUE",

    # 15. AlertEvent lookup index on normalized 5-tuple flow_key
    "CREATE INDEX alert_event_flow_key_index IF NOT EXISTS "
    "FOR (ae:AlertEvent) ON (ae.flow_key)",

    # 16. AlertEvent lookup index on Flow/Suricata Community ID
    "CREATE INDEX alert_event_community_id_index IF NOT EXISTS "
    "FOR (ae:AlertEvent) ON (ae.community_id)",

    # 17. AlertEvent lookup index on canonical unsigned decimal flow_id string
    "CREATE INDEX alert_event_flow_id_index IF NOT EXISTS "
    "FOR (ae:AlertEvent) ON (ae.flow_id)",

    # 18. AlertEvent lookup index on sensor_id
    "CREATE INDEX alert_event_sensor_id_index IF NOT EXISTS "
    "FOR (ae:AlertEvent) ON (ae.sensor_id)",

    # 19. AlertEvent lookup index on routing_domain_id
    "CREATE INDEX alert_event_routing_domain_index IF NOT EXISTS "
    "FOR (ae:AlertEvent) ON (ae.routing_domain_id)",

    # 20. AlertEvent numeric temporal index on lossless 64-bit epoch nanoseconds
    "CREATE INDEX alert_event_timestamp_epoch_ns_index IF NOT EXISTS "
    "FOR (ae:AlertEvent) ON (ae.timestamp_epoch_ns)",
]

# Neo4j 5.x constraint DDL statements (backed by RANGE indexes)
SCHEMA_STATEMENTS: List[str] = PRE_DROP_SCHEMA_STATEMENTS + POST_DROP_SCHEMA_STATEMENTS


def _extract_int_field(result, field_name: str) -> int:
    """Safely extract an integer count from a Neo4j Result or mock."""
    if not hasattr(result, "single"):
        return 0
    rec = result.single()
    if rec is None:
        return 0
    if isinstance(rec, dict) and field_name in rec:
        val = rec[field_name]
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return int(val)
    elif hasattr(rec, "get"):
        val = rec.get(field_name)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return int(val)
    return 0


def ensure_schema(driver) -> None:
    """Apply all uniqueness constraints and indexes to the Neo4j database idempotently.

    Preflight check:
    Verifies that no legacy V1 IPAddress nodes remain unmigrated. If unmigrated nodes
    exist (scoped_id IS NULL or empty), raises MigrationRequiredError to prevent dropping
    the legacy uniqueness constraint and avoid creating duplicate logical endpoints.

    If 0 unmigrated nodes exist (fresh database or already migrated V2 database):
    1. Ensures routing_domain_unique and ip_scoped_unique exist BEFORE dropping legacy
       ip_address_unique, avoiding any unprotected uniqueness window under concurrent writes.
    2. Drops legacy global address uniqueness constraints to allow scoped IP coexistence.
    3. Applies remaining Neo4j 5.x 'IF NOT EXISTS' constraints and indexes (including
       ip_address_index).
    Explicitly consumes transaction results for each statement.
    """
    logger.info("Ensuring Neo4j graph schema constraints and indexes...")
    with driver.session() as session:
        # Preflight check: refuse to drop legacy constraints if unmigrated nodes exist
        check_res = session.run(
            "MATCH (ip:IPAddress) "
            "WHERE ip.scoped_id IS NULL OR trim(toString(ip.scoped_id)) = '' "
            "RETURN count(ip) AS unmigrated_count"
        )
        unmigrated_count = _extract_int_field(check_res, "unmigrated_count")

        if unmigrated_count > 0:
            raise MigrationRequiredError(unmigrated_count)

        # 1. Create V2 uniqueness guards BEFORE dropping legacy ip_address_unique
        for statement in PRE_DROP_SCHEMA_STATEMENTS:
            logger.debug("Executing pre-drop schema statement: %s", statement)
            result = session.run(statement)
            if hasattr(result, "consume"):
                result.consume()

        # 2. Drop legacy global IP uniqueness constraint (now protected by ip_scoped_unique)
        for drop_stmt in LEGACY_DROP_STATEMENTS:
            logger.debug("Executing legacy constraint cleanup: %s", drop_stmt)
            res = session.run(drop_stmt)
            if hasattr(res, "consume"):
                res.consume()

        # 3. Create remaining indexes and constraints (including non-unique ip_address_index)
        for statement in POST_DROP_SCHEMA_STATEMENTS:
            logger.debug("Executing post-drop schema statement: %s", statement)
            result = session.run(statement)
            if hasattr(result, "consume"):
                result.consume()

    logger.info("Neo4j graph schema constraints and indexes verified.")


def migrate_ip_identity_to_scoped(driver, default_domain: str = "default") -> Dict[str, Any]:
    """Migrate legacy V1 IPAddress nodes to V2 scoped IP identities.

    1. Preflight validation:
       - Validate and normalize default_domain (lowercase, trimmed, no '#' delimiter)
       - Verify existing :IPAddress nodes have valid IP addresses
       - Validate target scoped_ids and existing scoped_ids have no collisions
       - Aborts immediately before modifying any database state if validation fails
    2. Pre-backfill uniqueness guards:
       - Ensures routing_domain_unique and ip_scoped_unique constraints exist prior to
         backfill so concurrent migrations or writes cannot create duplicate RoutingDomain
         or duplicate scoped_id nodes
    3. Data backfill in managed write transaction:
       - Merge default :RoutingDomain {domain_id: norm_default_domain}
       - Backfill normalized routing_domain_id and scoped_id on :IPAddress nodes
       - Link all endpoints to their corresponding :RoutingDomain via :IN_DOMAIN
       - Backfill historical :AlertFact nodes with routing_domain_id = norm_default_domain
    4. Post-write verification:
       - Confirms 0 unmigrated IPAddress nodes remain in the database
    5. Schema transition:
       - Safely invokes ensure_schema(driver), which drops the legacy ip_address_unique
         constraint and applies remaining V2 constraints and indexes.

    Returns:
        Dict with migration summary statistics: total_ips, migrated_ips, already_migrated_ips, default_domain.
    """
    norm_default_domain = default_domain.strip().lower() if default_domain and default_domain.strip() else "default"
    if "#" in norm_default_domain:
        raise ValueError(
            f"Migration preflight failed: default_domain cannot contain delimiter '#': '{norm_default_domain}'"
        )

    logger.info("Starting V1 to V2 IP identity schema migration (default_domain=%s)...", norm_default_domain)

    with driver.session() as session:
        # Preflight validation: check all existing IPAddress nodes
        nodes_res = session.run(
            "MATCH (ip:IPAddress) "
            "RETURN elementId(ip) AS element_id, ip.address AS address, "
            "       ip.scoped_id AS scoped_id, ip.routing_domain_id AS routing_domain_id"
        )
        records = list(nodes_res)

        seen_scoped_ids = set()
        seen_existing_scoped_ids = set()
        updates = []

        for r in records:
            raw_addr = r["address"]
            if not raw_addr or not str(raw_addr).strip():
                raise ValueError(f"Migration preflight failed: IPAddress node {r['element_id']} has empty address")

            existing_scoped = r["scoped_id"]
            if existing_scoped is not None and str(existing_scoped).strip():
                if existing_scoped in seen_existing_scoped_ids:
                    raise ValueError(
                        f"Migration preflight failed: duplicate existing scoped_id '{existing_scoped}' detected"
                    )
                seen_existing_scoped_ids.add(existing_scoped)

            raw_domain = r["routing_domain_id"]
            domain = (
                str(raw_domain).strip().lower()
                if raw_domain is not None and str(raw_domain).strip()
                else norm_default_domain
            )
            try:
                target_scoped = scoped_ip_id(domain, raw_addr)
            except Exception as exc:
                raise ValueError(
                    f"Migration preflight failed: cannot generate scoped_id for address '{raw_addr}': {exc}"
                ) from exc

            if target_scoped in seen_scoped_ids:
                raise ValueError(
                    f"Migration preflight failed: duplicate target scoped_id '{target_scoped}' detected in existing nodes"
                )
            seen_scoped_ids.add(target_scoped)

            if r["scoped_id"] != target_scoped or r["routing_domain_id"] != domain:
                updates.append({
                    "element_id": r["element_id"],
                    "scoped_id": target_scoped,
                    "domain_id": domain,
                })

        logger.info(
            "Migration preflight passed for %d IPAddress nodes (%d require updates)",
            len(records),
            len(updates),
        )

        # Ensure RoutingDomain and scoped_id uniqueness constraints exist BEFORE backfill
        # so concurrent migration runs cannot create duplicate RoutingDomain or scoped_id nodes.
        for statement in PRE_DROP_SCHEMA_STATEMENTS:
            logger.debug("Applying pre-backfill uniqueness guard: %s", statement)
            pre_res = session.run(statement)
            if hasattr(pre_res, "consume"):
                pre_res.consume()

        default_domain_name = "Default Routing Domain" if norm_default_domain == "default" else norm_default_domain

        def _execute_migration(tx):
            # 1. Ensure default RoutingDomain exists
            r1 = tx.run(
                "MERGE (rd:RoutingDomain {domain_id: $domain_id}) "
                "ON CREATE SET rd.name = $domain_name",
                domain_id=norm_default_domain,
                domain_name=default_domain_name,
            )
            if hasattr(r1, "consume"):
                r1.consume()

            # 2. Update nodes in batch if updates required
            if updates:
                r2 = tx.run(
                    "UNWIND $updates AS upd "
                    "MATCH (ip:IPAddress) WHERE elementId(ip) = upd.element_id "
                    "SET ip.scoped_id = upd.scoped_id, "
                    "    ip.routing_domain_id = upd.domain_id",
                    updates=updates,
                )
                if hasattr(r2, "consume"):
                    r2.consume()

            # 3. Ensure all IPAddress nodes are linked to their RoutingDomain
            r3 = tx.run(
                "MATCH (ip:IPAddress) "
                "WHERE ip.routing_domain_id IS NOT NULL "
                "MERGE (rd:RoutingDomain {domain_id: ip.routing_domain_id}) "
                "MERGE (ip)-[:IN_DOMAIN]->(rd)"
            )
            if hasattr(r3, "consume"):
                r3.consume()

            # 4. Backfill historical AlertFact nodes lacking routing_domain_id
            r4 = tx.run(
                "MATCH (fact:AlertFact) "
                "WHERE fact.routing_domain_id IS NULL "
                "SET fact.routing_domain_id = $domain_id",
                domain_id=norm_default_domain,
            )
            if hasattr(r4, "consume"):
                r4.consume()

            return len(updates)

        migrated_count = session.execute_write(_execute_migration)

        # Verification step: ensure no unmigrated IPAddress nodes remain
        verify_res = session.run(
            "MATCH (ip:IPAddress) "
            "WHERE ip.scoped_id IS NULL OR trim(toString(ip.scoped_id)) = '' "
            "RETURN count(ip) AS unmigrated"
        )
        remaining_unmigrated = _extract_int_field(verify_res, "unmigrated")
        if remaining_unmigrated > 0:
            raise RuntimeError(
                f"Migration post-check failed: {remaining_unmigrated} unmigrated IPAddress nodes remain"
            )

    # Schema transition (safe now because 0 unmigrated IP nodes remain)
    ensure_schema(driver)

    logger.info(
        "V1 to V2 IP identity migration complete: %d nodes updated, %d total",
        migrated_count,
        len(records),
    )
    return {
        "total_ips": len(records),
        "migrated_ips": migrated_count,
        "already_migrated_ips": len(records) - migrated_count,
        "default_domain": norm_default_domain,
    }
