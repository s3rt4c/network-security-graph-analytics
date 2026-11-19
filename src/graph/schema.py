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

# Neo4j 5.x constraint DDL statements (backed by RANGE indexes)
SCHEMA_STATEMENTS: List[str] = [
    # 1. RoutingDomain uniqueness constraint on domain_id
    "CREATE CONSTRAINT routing_domain_unique IF NOT EXISTS "
    "FOR (rd:RoutingDomain) REQUIRE rd.domain_id IS UNIQUE",

    # 2. IPAddress uniqueness constraint on scoped_id
    "CREATE CONSTRAINT ip_scoped_unique IF NOT EXISTS "
    "FOR (ip:IPAddress) REQUIRE ip.scoped_id IS UNIQUE",

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
]


def ensure_schema(driver) -> None:
    """Apply all uniqueness constraints and indexes to the Neo4j database idempotently.

    Preflight check:
    Verifies that no legacy V1 IPAddress nodes remain unmigrated. If unmigrated nodes
    exist (scoped_id IS NULL), raises MigrationRequiredError to prevent dropping the
    legacy uniqueness constraint and avoid creating duplicate logical endpoints.

    If 0 unmigrated nodes exist (fresh database or already migrated V2 database):
    Drops legacy global address uniqueness constraints to allow scoped IP coexistence,
    then applies Neo4j 5.x 'IF NOT EXISTS' constraints and indexes.
    Explicitly consumes transaction results for each statement.
    """
    logger.info("Ensuring Neo4j graph schema constraints and indexes...")
    with driver.session() as session:
        # Preflight check: refuse to drop legacy constraints if unmigrated nodes exist
        check_res = session.run(
            "MATCH (ip:IPAddress) WHERE ip.scoped_id IS NULL RETURN count(ip) AS unmigrated_count"
        )
        unmigrated_count = 0
        if hasattr(check_res, "single"):
            rec = check_res.single()
            if rec is not None and isinstance(rec, dict) and "unmigrated_count" in rec:
                unmigrated_count = int(rec["unmigrated_count"])
            elif hasattr(rec, "get"):
                val = rec.get("unmigrated_count")
                if isinstance(val, (int, float)):
                    unmigrated_count = int(val)

        if unmigrated_count > 0:
            raise MigrationRequiredError(unmigrated_count)

        for drop_stmt in LEGACY_DROP_STATEMENTS:
            logger.debug("Executing legacy constraint cleanup: %s", drop_stmt)
            res = session.run(drop_stmt)
            if hasattr(res, "consume"):
                res.consume()

        for statement in SCHEMA_STATEMENTS:
            logger.debug("Executing schema statement: %s", statement)
            result = session.run(statement)
            if hasattr(result, "consume"):
                result.consume()

    logger.info("Neo4j graph schema constraints and indexes verified.")


def migrate_ip_identity_to_scoped(driver, default_domain: str = "default") -> Dict[str, Any]:
    """Migrate legacy V1 IPAddress nodes to V2 scoped IP identities.

    1. Preflight validation:
       - Verify existing :IPAddress nodes have valid IP addresses
       - Validate target scoped_ids can be generated without collisions
       - Aborts immediately before modifying any database state if validation fails
    2. Data backfill in managed write transaction:
       - Merge default :RoutingDomain {domain_id: default_domain, name: 'Default Routing Domain'}
       - Backfill routing_domain_id and scoped_id on :IPAddress nodes
       - Link all endpoints to their corresponding :RoutingDomain via :IN_DOMAIN
       - Backfill historical :AlertFact nodes with routing_domain_id = default_domain
    3. Post-write verification:
       - Confirms 0 unmigrated IPAddress nodes remain in the database
    4. Schema transition:
       - Safely invokes ensure_schema(driver), which drops the legacy ip_address_unique
         constraint and applies V2 constraints and indexes.

    Returns:
        Dict with migration summary statistics: total_ips, migrated_ips, already_migrated_ips, default_domain.
    """
    logger.info("Starting V1 to V2 IP identity schema migration (default_domain=%s)...", default_domain)

    with driver.session() as session:
        # Preflight validation: check all existing IPAddress nodes
        nodes_res = session.run(
            "MATCH (ip:IPAddress) "
            "RETURN elementId(ip) AS element_id, ip.address AS address, "
            "       ip.scoped_id AS scoped_id, ip.routing_domain_id AS routing_domain_id"
        )
        records = list(nodes_res)

        seen_scoped_ids = set()
        updates = []

        for r in records:
            raw_addr = r["address"]
            if not raw_addr or not str(raw_addr).strip():
                raise ValueError(f"Migration preflight failed: IPAddress node {r['element_id']} has empty address")

            domain = r["routing_domain_id"] or default_domain
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

        def _execute_migration(tx):
            # 1. Ensure default RoutingDomain exists
            r1 = tx.run(
                "MERGE (rd:RoutingDomain {domain_id: $domain_id}) "
                "ON CREATE SET rd.name = 'Default Routing Domain'",
                domain_id=default_domain,
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
                domain_id=default_domain,
            )
            if hasattr(r4, "consume"):
                r4.consume()

            return len(updates)

        migrated_count = session.execute_write(_execute_migration)

        # Verification step: ensure no unmigrated IPAddress nodes remain
        verify_res = session.run("MATCH (ip:IPAddress) WHERE ip.scoped_id IS NULL RETURN count(ip) AS unmigrated")
        if hasattr(verify_res, "single"):
            v_rec = verify_res.single()
            if v_rec and v_rec.get("unmigrated", 0) > 0:
                raise RuntimeError(
                    f"Migration post-check failed: {v_rec['unmigrated']} unmigrated IPAddress nodes remain"
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
        "default_domain": default_domain,
    }
