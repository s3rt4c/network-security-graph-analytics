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
     - Domain-isolated AlertFact hashing

B. Browser Data Import (React UI -> POST /api/v1/import/validate -> POST /api/v1/import)
   Browser Upload (TSV / JSON) ──▶ src/services/import_service.py (Stateless validation & staging)
                                               │
                                               ▼
                                 src/graph/repository.py
     - Atomic single active workspace replacement & rollback (replace_workspace_data)
     - Recreates default RoutingDomain
C. Streaming Zeek Ingestion (python -m src.services.zeek_ingestion)
   Zeek conn.log (JSONL) ──▶ src/ingestion/zeek_conn_parser.py (O(1) streaming parser)
                                               │
                                               ▼
                                 src/graph/repository.py
     - Bounded per-batch UNWIND persistence (write_zeek_observations)
     - Immutable :FlowObservation nodes with conflict detection & lossless timestamps
     - :HAS_ORIGINATOR / :HAS_RESPONDER links to domain-scoped :IPAddress nodes
                            │
D. Streaming Suricata Ingestion (python -m src.services.suricata_ingestion)
   Suricata EVE (JSONL) ──▶ src/ingestion/suricata_eve_parser.py (O(1) streaming parser)
                                               │
                                               ▼
                                 src/graph/repository.py
     - Bounded per-batch UNWIND persistence (write_suricata_alert_events)
     - Immutable :AlertEvent + static :AlertDefinition (:TRIGGERED_RULE / :HAS_SOURCE / :HAS_DESTINATION)
                            │
                            ▼
                   Neo4j Graph Database
       ┌─────────────────────────────────────────┐
       │  (:RoutingDomain)                       │
       │  (:IPAddress)  (:Layer2Identifier)      │
       │  (:AlertFact)  (:FlowObservation)       │
       │  (:AlertDefinition)  (:AlertEvent)      │
       │  [:IN_DOMAIN]                           │
       │  [:COMMUNICATED_TO]                     │
       │  [:L2_COMMUNICATED_TO]                  │
       │  [:OBSERVED_WITH]                       │
       │  [:SOURCE_OF]  [:TARGETS]               │
       │  [:HAS_ORIGINATOR]  [:HAS_RESPONDER]    │
       │  [:TRIGGERED_RULE]                      │
       │  [:HAS_SOURCE]  [:HAS_DESTINATION]      │
       │  [:CORRELATED_WITH]                     │
       └─────────────────────────────────────────┘
                            ▲
                            │ session.execute_read
                            │
       src/graph/read_repository.py & correlation_repository.py
     - Scoped IP resolution, AmbiguousEndpointError, & V2 correlation reads
                            ▲
                            │ dependency injection
                            │
[ FastAPI Backend API — Server: uvicorn src.api.app:app ]
src/api/routes/
  ├── health.py        (GET /health, GET /ready)
  ├── import_data.py   (GET /api/v1/import/status, POST /validate, POST /import)
  ├── network.py       (GET /api/v1/network/*, including /analytics/summary and /analytics/endpoints)
  ├── alerts.py        (GET /api/v1/alerts/* [V1 AlertFact])
  ├── correlations.py  (GET /api/v1/correlations/traffic-alerts [V1], /alert-flows* [V2])
  ├── observations.py  (GET /api/v1/alert-events/{event_id}, /flow-observations/{observation_id} [V2])
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
  │   ├── CorrelationsPage.tsx     (Accessible tabs separating Legacy V1 co-occurrence & V2 alert–flow explorer)
  │   ├── PathFinderPage.tsx       (Directional L3 communication hop chain visualizer)
  │   └── ImportDataPage.tsx       (Browser data import, dual-file validation & workspace replacement)
  └── components/
      ├── correlations/
      │   ├── AlertFlowCorrelationsView.tsx (V2 verified-first read-only table, filters, pagination & quick inspect actions)
      │   ├── CorrelationEvidenceModal.tsx  (Accessible lazy three-tab inspector: Evidence / AlertEvent / FlowObservation)
      │   ├── AlertEventDetailPanel.tsx     (Read-only Suricata AlertEvent & AlertDefinition forensic panel)
      │   ├── FlowObservationDetailPanel.tsx (Read-only Zeek FlowObservation metrics & timestamp panel)
      │   ├── EvidenceFieldRow.tsx          (Shared neutral field renderer & retryable error/loading shell)
      │   └── VerificationStatusBadge.tsx   (Non-color-only verified vs unverified_incomplete badge)
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
- **`alert_parser.py`**: Parses Snort/IDS JSON alert arrays, validates required source and destination IP endpoints, normalizes and validates optional numeric rule metadata (signature IDs, generator IDs, revisions, numeric priorities), normalizes protocols, and creates immutable `AlertRecord` instances with bounded diagnostic telemetry.
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
  - `flow_observation_unique`: UNIQUE `FlowObservation.observation_id`
  - `flow_observation_community_id_index`: RANGE INDEX on `FlowObservation.community_id`
  - `flow_observation_sensor_id_index`: RANGE INDEX on `FlowObservation.sensor_id`
  - `flow_observation_routing_domain_index`: RANGE INDEX on `FlowObservation.routing_domain_id`
  - `flow_observation_start_epoch_ns_index`: RANGE INDEX on `FlowObservation.start_epoch_ns`
  - `alert_definition_unique`: UNIQUE `AlertDefinition.definition_id`
  - `alert_event_unique`: UNIQUE `AlertEvent.event_id`
  - `alert_event_flow_key_index`, `alert_event_community_id_index`, `alert_event_flow_id_index`, `alert_event_sensor_id_index`, `alert_event_routing_domain_index`, `alert_event_timestamp_epoch_ns_index`: RANGE INDEXes on `:AlertEvent`
  - **Preflight Safety**: `ensure_schema(driver)` refuses and raises `MigrationRequiredError` if unmigrated legacy nodes exist (`scoped_id IS NULL`), preventing premature removal of the legacy constraint.
  - `migrate_ip_identity_to_scoped()`: Automated preflight migration backfilling legacy IP nodes to the `default` routing domain and backfilling historical `AlertFact` nodes.
- **`repository.py`**: Executes batched Cypher writes using parameterized `UNWIND` blocks inside managed write transactions (`session.execute_write`).
  - Merges `(:RoutingDomain {domain_id: $domain})`.
  - Merges `(:IPAddress {scoped_id: $scoped_id})` and links with `[:IN_DOMAIN]` to `(:RoutingDomain)`.
  - **Domain-Isolated Alert Facts**: Generates domain-aware `fact_key` hashes via `compute_alert_fact_key(alert, domain_id)`, preventing cross-domain alert collisions.
  - **Discrete Zeek Flow Observations**: `write_zeek_observations()` streams bounded batches into immutable `(:FlowObservation)` nodes with exact lossless decimal timestamp strings, optional exact 64-bit nanosecond indexes, separate directional payload/IP metrics, conflict rejection (`ObservationConflictError`), and `[:HAS_ORIGINATOR]`/`[:HAS_RESPONDER]` links.
  - **Discrete Suricata Alert Events & Definitions**: `write_suricata_alert_events()` streams bounded batches into immutable `(:AlertEvent)` nodes and static identity-only `(:AlertDefinition)` nodes with conflict rejection (`AlertEventConflictError`), lossless uint64 `flow_id` decimal strings, exact decimal/nanosecond timestamps, and `[:TRIGGERED_RULE]`/`[:HAS_SOURCE]`/`[:HAS_DESTINATION]` links.
  - Contains `replace_workspace_data` for atomic workspace clearing (including `:FlowObservation`, `:AlertEvent`, `:AlertDefinition`) and re-ingestion with rollback protection, recreating the target routing domain.
- **`correlation_repository.py`**: Implements bounded dual-path candidate retrieval, Phase 4A correlation edge reconciliation (`[:CORRELATED_WITH]`), verification lifecycle tracking (`verified` vs `unverified_incomplete`), and read-only paginated queries (`list_alert_flow_correlations()`, `get_alert_event_correlations()`) for V2 API exposure.

### 3. Read Query Layer (`src/graph/read_repository.py`)
- Executes optimized Cypher read queries using managed read transactions (`session.execute_read`).
- **Endpoint Resolution & Ambiguity Safety**:
  - Implements `_resolve_endpoint(address, domain=None, scoped_id=None)`:
    - If `scoped_id` is supplied, matches exact scoped identity.
    - If `domain` and `address` are supplied, resolves deterministically via `scoped_ip_id(domain, address)`.
    - If only `address` is supplied and exactly one IP node exists across all domains, returns it seamlessly (preserving 100% single-domain backwards compatibility).
    - If only `address` is supplied and multiple IP nodes exist with that address across different routing domains, raises `AmbiguousEndpointError`.
- Provides aggregated analytics summaries, paginated endpoint volume rankings, filtered communication queries, bounded graph neighborhood traversals, directional shortest-path computations, discrete `FlowObservation` lookup/paginated reads (`get_flow_observation`, `list_flow_observations`), and discrete `AlertEvent` lookup/paginated reads (`get_alert_event`, `list_alert_events`).

### 4. REST API Backend (`src/api/`)
- Built with **FastAPI** and **Pydantic v2**.
- Structured into modular routers: `health.py`, `import_data.py`, `network.py`, `alerts.py`, `correlations.py`, `observations.py`, and `graph.py`.
- Employs lifespan events for database connectivity lifecycle and FastAPI dependency injection for repository access.
- Maintains strict V1/V2 route separation: V1 `AlertFact` routes (`/api/v1/alerts*`) remain completely independent from V2 Suricata `AlertEvent` (`/api/v1/alert-events/{event_id}`) and Zeek `FlowObservation` (`/api/v1/flow-observations/{observation_id}`) forensic detail routes. All V2 detail lookups execute read-only `session.execute_read()` transactions, enforce `routing_domain_id` and `source_type`, validate strict `Decimal` and JS safe-integer boundaries without exposing raw `*_epoch_ns`, and propagate Neo4j unavailability as `HTTP 503` (never masking missing drivers as `404`).
- Global exception handling maps `AmbiguousEndpointError` to machine-readable **HTTP 409 Conflict**:
  ```json
  {
    "detail": {
      "code": "AMBIGUOUS_ENDPOINT",
      "message": "Multiple IP endpoints match '10.0.0.5' across domains: 'branch', 'corp'. Specify 'domain' or query by scoped_id.",
      "address": "10.0.0.5",
      "matching_domains": ["branch", "corp"]
    }
  }
  ```

### 5. Web Frontend (`frontend/`)
- Single-page application built with **React 19**, **TypeScript 6.x**, and **Vite 8**.
- **Graph Engine:** Cytoscape.js with custom dark cybersecurity styling, bezier curve multi-edge routing for parallel flows, and node/edge interaction handlers.
- **Slide Drawers:** Contextual inspectors (`CommunicationEdgePanel`, `IPDetailPanel`, `Layer2DetailPanel`) for deep entity analysis without navigating away from the canvas.
- **V2 Alert–Flow Correlations Explorer (`CorrelationsPage`, `AlertFlowCorrelationsView`):** Accessible sub-tabbed view preserving the default **Legacy Correlations** (V1 endpoint co-occurrence) tab separately from read-only persisted **Alert–Flow Correlations** (`GET /api/v1/correlations/alert-flows` and `/alert-flows/{event_id}`), with safe `include_unverified=false` default, fail-closed `RoutingDomain`/SHA-256 validation (`utils/correlationHelpers.ts`), server pagination, row quick-inspect actions (**Alert** / **Flow**), and a single accessible three-tab `CorrelationEvidenceModal` (**Correlation Evidence** default | **Suricata AlertEvent** | **Zeek FlowObservation**) that lazily fetches `GET /api/v1/alert-events/{event_id}` and `GET /api/v1/flow-observations/{observation_id}` scoped to the row's `routing_domain_id` with `AbortController` race guards, exact `Decimal` strings, and neutral `Not recorded` fields without triggering live correlation runs or cross-linking into V1 pages.

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
│   │   ├── utils/                 # Formatting, correlation validation/helpers & pure utilities
│   │   └── styles/                # CSS variables & dark cybersecurity theme
│   ├── package.json
│   └── vite.config.ts
├── src/
│   ├── config.py                  # Environment-based configuration with lazy loading
│   ├── main.py                    # Application CLI entry point (--migrate support)
│   ├── api/                       # FastAPI REST API backend
│   │   ├── app.py                 # FastAPI application factory and error handlers
│   │   ├── models.py              # Pydantic v2 API response models
│   │   └── routes/                # Modular route endpoints
│   ├── services/                  # Business logic services (import validation & correlation runner)
│   │   └── correlation_service.py # Bounded Phase 4B correlation orchestration service & CLI
│   ├── graph/                     # Graph persistence, schema & read repositories
│   │   ├── schema.py              # V2 schema constraints, indexes & safe migration
│   │   ├── repository.py          # Neo4j write repository & atomic workspace replacement
│   │   ├── correlation_repository.py # Bounded Phase 4B reconciliation & Phase 4C correlation reads
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
