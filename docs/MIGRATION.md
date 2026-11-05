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

### Schema Evolution
1. **Legacy Constraint Dropped:**
   ```cypher
   DROP CONSTRAINT ip_address_unique IF EXISTS
   ```
2. **V2 Constraints & Indexes Applied:**
   ```cypher
   CREATE CONSTRAINT routing_domain_unique IF NOT EXISTS
   FOR (r:RoutingDomain) REQUIRE r.domain_id IS UNIQUE

   CREATE CONSTRAINT ip_scoped_unique IF NOT EXISTS
   FOR (i:IPAddress) REQUIRE i.scoped_id IS UNIQUE

   CREATE INDEX ip_address_index IF NOT EXISTS
   FOR (i:IPAddress) ON (i.address)
   ```

### Automated Migration Procedure
The migration helper function `migrate_ip_identity_to_scoped(driver)` in [`src/graph/schema.py`](../src/graph/schema.py) performs automated, non-destructive backfill:
1. **Preflight Validation:** Verifies driver connectivity, executes schema constraint updates, and checks that all existing `(:IPAddress)` nodes possess valid, non-null `address` properties.
2. **Default Domain Creation:** Ensures the baseline `(:RoutingDomain {domain_id: "default"})` node exists.
3. **Property Backfill:** Sets `scoped_id = "default#" + ip.address` and `routing_domain_id = "default"` on all legacy IP nodes lacking `scoped_id`.
4. **Relationship Linking:** Merges `(ip)-[:IN_DOMAIN]->(rd)` relationships for all unlinked IP nodes.
5. **Verification & Idempotency:** Confirms that 0 un-scoped IP nodes remain in the database. Subsequent executions are zero-impact no-ops.

### Backward Compatibility & Ambiguity Resolution
- Single-domain queries continue to function seamlessly without breaking changes.
- Read operations (`/api/v1/network/ips/{address}`, `/peers`, `/layer2`, `/neighborhood`, `/path`) accept an optional `?domain=` query parameter.
- If an address is queried without `?domain=` and exists in multiple routing domains, the API raises an `AmbiguousEndpointError` and responds with `HTTP 409 Conflict`, prompting the caller to specify the desired domain.

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
   Because relationship identity criteria changed from 3-tuple to 5-tuple, re-ingesting source datasets is the cleanest migration path for development environments.
2. **Atomic Browser Workspace Replacement:**
   Using the **Import Data** dashboard tab naturally clears the prior workspace and reconstructs the graph with V2 schema, scoped IP identities, and default routing domain atomically.
3. **No Destructive Startup Migrations:**
   The application ensures schema safety and constraints on startup via `ensure_schema()` without modifying node properties or deleting data.
4. **Direct Ingestion Warning:**
   Running CLI ingestion (`python -m src.main`) into an existing v1.1 database without clearing prior data will preserve legacy relationships alongside new ones, resulting in a `mixed` metric availability mode.
5. **Dedicated Database Recommended:**
   Running the application with a dedicated Neo4j instance or disposable container (`compose.yaml`) ensures a clean, isolated workspace.
