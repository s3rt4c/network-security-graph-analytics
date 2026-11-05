[← Back to README](../README.md)

# Application Architecture & System Design

This document details the internal architecture, component interactions, data flows, and codebase layout for the **Network Traffic & Security Alert Analysis** platform.

---

## High-Level System Architecture

```
[ Ingestion Entry Points ]
A. CLI Ingestion (python -m src.main)
   Network traffic (TSV)             IDS alerts (JSON)
             │                              │
             ▼                              ▼
   src/ingestion/traffic_parser.py   src/ingestion/alert_parser.py
             │                              │
             ▼                              ▼
     list[TrafficRecord]            list[AlertRecord]
             │                              │
             └──────────────┬───────────────┘
                            │
                            ▼
                src/graph/repository.py
     - Batched UNWIND write persistence (session.execute_write)
     - Scoped IP & RoutingDomain assignment

B. Browser Data Import (React UI -> POST /api/v1/import/validate -> POST /api/v1/import)
   Browser Upload (TSV / JSON) ──▶ src/services/import_service.py (Stateless validation & staging)
                                               │
                                               ▼
                                 src/graph/repository.py
     - Atomic single active workspace replacement & rollback (replace_workspace_data)
     - Recreates default RoutingDomain
                            │
                            ▼
                   Neo4j Graph Database
       ┌─────────────────────────────────────────┐
       │  (:RoutingDomain)                       │
       │  (:IPAddress)  (:Layer2Identifier)      │
       │  (:AlertFact)                           │
       │  [:IN_DOMAIN]                           │
       │  [:COMMUNICATED_TO]                     │
       │  [:L2_COMMUNICATED_TO]                  │
       │  [:OBSERVED_WITH]                       │
       │  [:SOURCE_OF]  [:TARGETS]               │
       └─────────────────────────────────────────┘
                            ▲
                            │ session.execute_read
                            │
                src/graph/read_repository.py
     - Scoped IP resolution & AmbiguousEndpointError
                            ▲
                            │ dependency injection
                            │
[ FastAPI Backend API — Server: uvicorn src.api.app:app ]
src/api/routes/
  ├── health.py        (GET /health, GET /ready)
  ├── import_data.py   (GET /api/v1/import/status, POST /validate, POST /import)
  ├── network.py       (GET /api/v1/network/*, including /analytics/summary and /analytics/endpoints)
  ├── alerts.py        (GET /api/v1/alerts/*)
  ├── correlations.py  (GET /api/v1/correlations/*)
  └── graph.py         (GET /api/v1/graph/*)
                            ▲
                            │ REST / JSON (Vite Dev Proxy)
                            │
[ Web Dashboard & Visualization — frontend/ (React 19 + Cytoscape.js) ]
frontend/src/
  ├── pages/
  │   ├── OverviewPage.tsx         (Global metrics, mode banners, distribution grids, endpoint rankings)
  │   ├── NetworkExplorerPage.tsx  (Cytoscape graph canvas, parallel edge rendering, edge & IP inspectors)
  │   ├── AlertExplorerPage.tsx    (Normalized alert facts table & detail modal)
  │   ├── CorrelationsPage.tsx     (Traffic & alert co-occurrence table with flow keys and ports)
  │   ├── PathFinderPage.tsx       (Directional L3 communication hop chain visualizer)
  │   └── ImportDataPage.tsx       (Browser data import, dual-file validation & workspace replacement)
  └── components/
      ├── graph/
      │   ├── CytoscapeCanvas.tsx  (Interactive canvas lifecycle, parallel edge layout & selection)
      │   └── cytoscapeStyle.ts    (Dark cybersecurity theme stylesheet)
      └── network/
          ├── CommunicationEdgePanel.tsx (Edge inspector drawer for directional aggregate metrics)
          └── IPDetailPanel.tsx          (IP context drawer with topology and volume metrics)
```

---

## Component Breakdown

### 1. Ingestion Pipeline & Identity Primitives (`src/ingestion/`)
- **`traffic_parser.py`**: Dual-mode parser supporting basic 7-column TSVs and enriched 14-column tshark TSVs. Performs IP canonicalization (RFC 5952), port validation, packet count and wire frame byte aggregation, timestamp interval tracking, and deterministic SHA-256 `flow_key` calculation.
- **`alert_parser.py`**: Parses Snort/IDS JSON alert arrays, validates required source and destination IP endpoints, normalizes and validates optional numeric rule metadata (signature IDs, generator IDs, revisions, numeric priorities), normalizes protocols, and creates immutable `AlertRecord` instances with bounded diagnostic telemetry. (Canonical IP transformation and deterministic SHA-256 `fact_key` computation are performed by the persistence layer in `src/graph/repository.py`).
- **`community_id.py`**: Implementation of the Core Community ID specification (Community ID v1). Generates standard 5-tuple flow hashes compatible with Zeek, Suricata, and network monitoring tools (`1:...`).
- **`v2_models.py`**: Canonical V2 identity primitives:
  - `scoped_ip_id(domain, address)`: Format `{domain}#{canonical_ip}` enabling support for overlapping RFC 1918 private subnets across distinct routing domains.
  - `alert_definition_id(...)`: Stable rule signature identity distinguishing known and unknown generator IDs (`suricata:snort:1:100` vs `suricata:snort:none:100`).
  - `telemetry_event_id(...)`: Unique event identifier for individual packet/flow telemetry events.
- **`models.py`**: Immutable domain dataclasses (`TrafficRecord`, `AlertRecord`, `IngestionSummary`, `L2Pair`).

### 2. Graph Persistence Layer (`src/graph/`)
- **`schema.py`**: Declares and ensures Neo4j 5.x uniqueness constraints and indexes:
  - `routing_domain_unique`: UNIQUE `RoutingDomain.domain_id`
  - `ip_scoped_unique`: UNIQUE `IPAddress.scoped_id`
  - `layer2_identifier_unique`: UNIQUE `Layer2Identifier.identifier`
  - `alert_fact_unique`: UNIQUE `AlertFact.fact_key`
  - `ip_address_index`: RANGE INDEX on `IPAddress.address`
  - `alert_fact_priority_index`: RANGE INDEX on `AlertFact.priority`
  - `alert_fact_sid_index`: RANGE INDEX on `AlertFact.sid`
  - Dropped legacy `ip_address_unique` global constraint to support multi-domain networks.
  - `migrate_ip_identity_to_scoped()`: Automated preflight migration backfilling legacy IP nodes to the `default` routing domain.
- **`repository.py`**: Executes batched Cypher writes using parameterized `UNWIND` blocks inside managed write transactions (`session.execute_write`).
  - Merges `(:RoutingDomain {domain_id: $domain})`.
  - Merges `(:IPAddress {scoped_id: $scoped_id})` and links with `[:IN_DOMAIN]` to `(:RoutingDomain)`.
  - Contains `replace_workspace_data` for atomic workspace clearing and re-ingestion with rollback protection, recreating the default routing domain.

### 3. Read Query Layer (`src/graph/read_repository.py`)
- Executes optimized Cypher read queries using managed read transactions (`session.execute_read`).
- **Endpoint Resolution & Ambiguity Safety**:
  - Implements `_resolve_endpoint(address, domain=None, scoped_id=None)`:
    - If `scoped_id` is supplied, matches exact scoped identity.
    - If `domain` and `address` are supplied, resolves deterministically via `scoped_ip_id(domain, address)`.
    - If only `address` is supplied and exactly one IP node exists across all domains, returns it seamlessly (preserving 100% single-domain backwards compatibility).
    - If only `address` is supplied and multiple IP nodes exist with that address across different routing domains, raises `AmbiguousEndpointError`.
- Provides aggregated analytics summaries, paginated endpoint volume rankings, filtered communication queries, bounded graph neighborhood traversals, and directional shortest-path computations.

### 4. REST API Backend (`src/api/`)
- Built with **FastAPI** and **Pydantic v2**.
- Structured into modular routers: `health.py`, `import_data.py`, `network.py`, `alerts.py`, `correlations.py`, and `graph.py`.
- Employs lifespan events for database connectivity lifecycle and FastAPI dependency injection for repository access.
- Global exception handling maps `AmbiguousEndpointError` to HTTP 409 Conflict with structured error details directing clients to supply `?domain=`.

### 5. Web Frontend (`frontend/`)
- Single-page application built with **React 19**, **TypeScript 6.x**, and **Vite 8**.
- **Graph Engine:** Cytoscape.js with custom dark cybersecurity styling, bezier curve multi-edge routing for parallel flows, and node/edge interaction handlers.
- **Slide Drawers:** Contextual inspectors (`CommunicationEdgePanel`, `IPDetailPanel`, `Layer2DetailPanel`) for deep entity analysis without navigating away from the canvas.

---

## Codebase Directory Layout

```
neo4j_project/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Multi-job CI workflow (unit, frontend, live Neo4j)
├── data/
│   └── samples/
│       ├── sample_traffic.tsv     # Basic synthetic RFC 1918 traffic export
│       ├── sample_traffic_enriched.tsv # Enriched synthetic tshark profile export
│       └── sample_alerts.json     # Synthetic IDS alert array
├── docs/
│   ├── ARCHITECTURE.md            # System architecture & component design (this file)
│   ├── TRAFFIC_MODEL.md           # Traffic formats, flow aggregation & graph schema
│   ├── API.md                     # REST API endpoints & query behavior
│   ├── IMPORT_SECURITY.md         # Browser import model & security boundaries
│   ├── MIGRATION.md               # v1.1 -> v1.2 & V2 graph migration guidance
│   └── images/                    # UI visuals and dashboard screenshots
├── frontend/                      # React 19 + TypeScript + Cytoscape.js SPA
│   ├── src/
│   │   ├── api/                   # Typed API client modules
│   │   ├── components/            # Graph canvas, inspectors, UI widgets
│   │   ├── pages/                 # Overview, Network, Alerts, Correlations, Path, Import
│   │   ├── utils/                 # Formatting & pure utility functions
│   │   └── styles/                # CSS variables & dark cybersecurity theme
│   ├── package.json
│   └── vite.config.ts
├── src/
│   ├── config.py                  # Environment-based configuration with lazy loading
│   ├── main.py                    # Application CLI entry point
│   ├── api/                       # FastAPI REST API backend
│   │   ├── app.py                 # FastAPI application factory and error handlers
│   │   ├── models.py              # Pydantic v2 API response models
│   │   └── routes/                # Modular route endpoints
│   ├── services/                  # Business logic services (import validation & staging)
│   ├── graph/                     # Graph persistence, schema & read repositories
│   │   ├── schema.py              # V2 schema constraints, indexes & migration helpers
│   │   ├── repository.py          # Neo4j write repository & atomic workspace replacement
│   │   └── read_repository.py     # Neo4j read repository & ambiguity-safe queries
│   └── ingestion/                 # Parsers, V2 identity models & Community ID
│       ├── community_id.py        # Core Community ID hash implementation
│       ├── v2_models.py           # Scoped IP, alert definition, and telemetry event IDs
│       ├── models.py              # TrafficRecord, AlertRecord, L2Pair domain models
│       ├── traffic_parser.py      # Dual-mode traffic parser
│       └── alert_parser.py        # IDS alert parser
└── tests/
    ├── conftest.py                # Pytest fixtures and mock factories
    ├── test_alert_parser.py       # Alert parsing tests
    ├── test_api_*.py              # API endpoint unit tests
    ├── test_api_live_neo4j.py     # Live API integration tests
    ├── test_community_id.py       # Community ID adapter unit tests
    ├── test_graph_*.py            # Graph schema, repository, and migration unit tests
    ├── test_neo4j_integration.py  # Live Neo4j integration tests
    ├── test_read_ambiguity.py     # Ambiguity handling and 409 Conflict tests
    ├── test_traffic_parser.py     # Traffic TSV parsing unit tests
    └── test_v2_identities.py      # V2 identity primitives unit tests
```
