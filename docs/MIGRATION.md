[← Back to README](../README.md)

# Migration & Rebuild Guide

This document provides guidance on graph schema evolution across platform versions, including the v1.1 → v1.2 flow key evolution and the V2 RoutingDomain & Scoped IP migration.

---

## 1. V2 RoutingDomain & Scoped IP Migration

### Background & Motivation
In V1, IP nodes were identified by a globally unique `address` property:
```cypher
CREATE CONSTRAINT ip_address_unique FOR (i:IPAddress) REQUIRE i.address IS UNIQUE
```
This global uniqueness constraint prevented modeling multi-tenant environments, hybrid cloud architectures, and segmented enterprise networks where distinct network partitions legitimately utilize overlapping RFC 1918 private address ranges (e.g., branch offices and corporate datacenters both using `10.0.0.0/24`).

In V2, the system decouples the IP address from the graph node identity:
- **`RoutingDomain` Entity:** Represents an isolated L3 routing context (e.g., `corp`, `branch`, `cloud`, or `default`).
- **Scoped Identity (`scoped_id`):** Node identity is keyed as `{routing_domain_id}#{canonical_ip}` (e.g., `corp#10.0.0.5` vs `branch#10.0.0.5`).
- **`IN_DOMAIN` Relationship:** Connects each `(:IPAddress)` node to its parent `(:RoutingDomain)`.
- **Domain-Aware AlertFacts:** Security alert facts generated in non-default routing domains include the domain in their deterministic hash key to prevent cross-domain alert collisions.

### Database States & Initialization Safety
The system explicitly distinguishes three database states:
1. **Fresh Database:**
   - 0 existing `(:IPAddress)` nodes.
   - `ensure_schema(driver)` safely drops legacy constraints (if present) and creates V2 constraints (`routing_domain_unique`, `ip_scoped_unique`, `ip_address_index`, etc.).
2. **Legacy V1 Database:**
   - Existing `(:IPAddress)` nodes present where `scoped_id IS NULL`.
   - Calling `ensure_schema(driver)` immediately **refuses** and raises `MigrationRequiredError`. It does **not** drop the legacy `ip_address_unique` constraint, preventing duplicate logical endpoints from being created by normal V2 writes.
   - Migration must be executed via `migrate_ip_identity_to_scoped(driver)` (or automatically by the CLI orchestrator `python -m src.main`).
3. **Already Migrated V2 Database:**
   - All `(:IPAddress)` nodes have non-null `scoped_id`.
   - `ensure_schema(driver)` runs idempotently without modifying data.

> [!IMPORTANT]
> **Pre-Migration Backup Requirement:**
> Always create a full database backup or snapshot before executing migration on production data. While migration is non-destructive and preserves existing relationships, graph migrations cannot be rolled back automatically if unexpected data corruptions exist.

### Migration Procedure
Migration can be run explicitly via CLI:
```bash
python -m src.main --migrate
```
or programmatically via `migrate_ip_identity_to_scoped(driver)`:

1. **Preflight Validation:**
   - Scans all existing `(:IPAddress)` nodes to confirm valid, non-empty IP addresses.
   - Computes target `scoped_id` for every node and checks for potential identity collisions.
   - Aborts immediately before executing any database mutations if preflight checks fail.
2. **Managed Data Backfill:**
   - Merges default `(:RoutingDomain {domain_id: "default", name: "Default Routing Domain"})`.
   - Sets `scoped_id = "default#" + ip.address` and `routing_domain_id = "default"` on all legacy IP nodes.
   - Merges `(ip)-[:IN_DOMAIN]->(rd)` relationships for all endpoints.
   - Backfills historical `(:AlertFact)` nodes with `routing_domain_id = "default"`.
3. **Post-Write Verification:**
   - Verifies `count(ip WHERE ip.scoped_id IS NULL) == 0`.
4. **Schema Transition:**
   - Drops `ip_address_unique` constraint.
   - Applies V2 constraints (`routing_domain_unique`, `ip_scoped_unique`, `layer2_identifier_unique`, `alert_fact_unique`) and indexes (`ip_address_index`, etc.).
5. **Idempotency & Partial State Recovery:**
   - Safe to rerun; subsequent executions report `migrated_ips: 0` and perform 0 mutations.
   - If a previous migration was partially interrupted, re-running safely identifies and migrates only the remaining unmigrated nodes.

---

## 2. Graph Identity Evolution (v1.1 → v1.2)

In **v1.1.0**, Layer 3 communication relationships in Neo4j were keyed solely by 3-tuple identity:
```
(src_ip, dst_ip, protocol)
```

In **v1.2.0**, the enriched traffic model introduced deterministic 5-tuple `flow_key` hashing:
```
(src_ip, dst_ip, protocol, src_port, dst_port)
```

This evolution enables the graph database and Cytoscape.js canvas to distinguish and visualize parallel communication flows (such as concurrent TLS sessions or distinct transport services between the same host pair).

---

## 3. General Migration Policy & Recommendations

1. **Re-Ingestion from Source:**
   For development environments, clearing and re-ingesting source datasets via `POST /api/v1/import` or `python -m src.main` is the cleanest migration path.
2. **Atomic Browser Workspace Replacement:**
   Using the **Import Data** dashboard tab naturally clears the prior workspace and reconstructs the graph with V2 schema, scoped IP identities, and default routing domain atomically.
3. **No Unsafe Startup Drops:**
   `ensure_schema()` never silently drops legacy constraints on unmigrated databases.
4. **Dedicated Database Recommended:**
   Running the application with a dedicated Neo4j instance or disposable container (`compose.yaml`) ensures a clean, isolated workspace.
