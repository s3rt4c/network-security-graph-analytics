# Security Investigation Dashboard (Frontend)

React 19 + TypeScript 6.x + Cytoscape.js web application for investigating network traffic topology, enriched communication aggregates, Layer 2 associations, normalized security alert facts, and communication paths powered by the read-oriented FastAPI backend with explicitly gated browser data-import mutation endpoints.

## Getting Started

### 1. Install Dependencies

```bash
npm install
```

### 2. Development Server

```bash
npm run dev
```

By default, Vite runs at `http://localhost:5173`.

### 3. API Proxy & Base URL Configuration

- **Development Proxy:** The Vite dev server automatically proxies `/api`, `/health`, and `/ready` requests to the local FastAPI backend running at `http://127.0.0.1:8000`.
- **API Base URL Override:** The environment variable `VITE_API_BASE_URL` can optionally be set to override the target API root. When unset, requests default to same-origin / proxy paths.

## Available Scripts

- `npm run dev`: Starts the Vite development server with Hot Module Replacement (HMR).
- `npm run build`: Type-checks with TypeScript compiler (`tsc -b`) and produces a static production bundle in `dist/`.
- `npm run test`: Runs the Vitest test suite in interactive watch mode.
- `npm run test:run`: Runs the Vitest test suite once with `@testing-library/react` and `jsdom`.
- `npm run lint`: Runs `oxlint` for fast static code analysis.

## Architecture

- **`src/api/`**: Typed native-fetch API client matching FastAPI Pydantic response models with explicit nullability.
- **`src/components/graph/`**: Cytoscape.js canvas integration with hierarchical, force-directed, and concentric layout algorithms.
- **`src/components/layout/`**: Header with live backend health/readiness pills and contextual slide drawers.
- **`src/pages/`**: Single-page application views:
  - `OverviewPage`: Global volume metrics, metric completeness mode, and endpoint rankings.
  - `NetworkExplorerPage`: Center-rooted neighborhood graph, parallel flow rendering, and inspection drawers.
  - `AlertExplorerPage`: Normalized security alert facts table and detail modal.
  - `CorrelationsPage`: Accessible sub-tabbed view separating Legacy V1 endpoint co-occurrence (`Legacy Correlations`, default) from V2 persisted Zeek–Suricata correlations (`Alert–Flow Correlations`).
  - `PathFinderPage`: Observed directional communication hop chain visualizer.
  - `ImportDataPage`: Browser data import, dual-file validation, and workspace replacement.
- **`src/components/correlations/`**: Modular V2 correlation explorer UI (`AlertFlowCorrelationsView`, `CorrelationEvidenceModal`, `VerificationStatusBadge`).
- **`src/utils/correlationHelpers.ts`**: Fail-closed filter validators, deterministic row-key builder preserving duplicate parallel edges, verbatim value formatter, and structured API error translator.

## V2 Alert–Flow Correlations Explorer (Phase 4D)

### Opening V2 Correlations & Legacy V1 Separation
- Navigate to **Correlations** in the top bar and switch between the two accessible sub-tabs:
  - **Legacy Correlations (Default):** Preserves the legacy V1 endpoint co-occurrence table (`GET /api/v1/correlations/traffic-alerts`) pairing aggregate Layer 3 flows with `:AlertFact` records sharing endpoints.
  - **Alert–Flow Correlations (V2):** Exposes persisted Phase 4B `:AlertEvent-[:CORRELATED_WITH]->:FlowObservation` edges via `GET /api/v1/correlations/alert-flows` and `GET /api/v1/correlations/alert-flows/{event_id}`.
- V1 and V2 are intentionally kept separate so legacy host-pair co-occurrence is never presented as equivalent to V2 observation-level evidence.

### Safe Default, Verification Statuses & Evidence Inspector
- **Verified-Only Safe Default:** V2 queries send `include_unverified=false` by default so only edges marked `verified` (`Verified`) appear initially.
- **Unverified Incomplete Records:** Enabling **Include unverified correlations** or selecting `Unverified incomplete only` exposes `unverified_incomplete` edges (`Previously Verified — Current Check Incomplete`). Their prior evidence was preserved when the latest reevaluation could not establish completeness (e.g., candidate truncation or retrieval error), which does not prove the original correlation remains valid. Persisted verification status reflects the last stored Phase 4B run, not real-time revalidation.
- **Filtering & Pagination:** Filter server-side by `RoutingDomain`, `AlertEvent ID` (64-char lowercase hex SHA-256), `FlowObservation ID` (64-char lowercase hex SHA-256), `Verification Status`, and `Include unverified correlations`. Submitting blank whitespace or `#` in `RoutingDomain` fails closed inline. Any filter change or reset returns `offset` to `0`, using bounded server pagination (`limit=50`).
- **Evidence Inspector:** Click **Inspect** on any row to view all persisted Phase 4C evidence fields in a modal with full copyable IDs, neutral `Not recorded` placeholders for `null` fields, verbatim arbitrary-precision `temporal_delta_decimal` strings, and an explicit note that `evidence_digest` is an integrity/identity artifact rather than a confidence score.

### Empty Results, Errors, Read-Only Semantics & Limitations
- **Missing Correlation Semantics:** A `404` on `/alert-flows/{event_id}` indicates the requested Suricata `AlertEvent` does not exist (or not in the filtered `RoutingDomain`), whereas `HTTP 200` with `0` rows indicates the `AlertEvent` exists with no matching persisted edges under the current filters. An empty result never proves an alert was `REJECTED`, `AMBIGUOUS`, `INSUFFICIENT`, or benign — it may mean no Phase 4B run completed, no edge met persistence criteria, or verified-only/other filters excluded it.
- **Backend Dependency & No Live Recalculation:** The V2 explorer is strictly read-only (`GET` requests only). It never executes live correlation runs or writes Neo4j state; persisted edges must first be produced by ingestion + the Phase 4B correlation service.
- **Current Payload Scope:** Per Phase 4C API contracts, this view displays persisted correlation IDs, verification metadata, and factual correlation evidence only — it does not fabricate unexposed IP addresses, ports, alert signatures, Zeek flow fields, attacker/victim attribution, causation claims, or unpersisted Phase 4A candidate reason arrays.
