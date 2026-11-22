[← Back to README](../README.md)

# REST API Reference

The **Network Traffic & Security Alert Analysis** backend is built with FastAPI and Pydantic v2. It provides a read-oriented API for relationship exploration and analytics, alongside explicitly gated endpoints for browser-based data import.

---

## Interactive Documentation

When the API server is running (`uvicorn src.api.app:app --port 8000`), interactive API documentation is available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

---

## Endpoint Reference Table

| Group | Method | Endpoint | Description | Parameters |
|---|---|---|---|---|
| **System** | `GET` | `/health` | Application liveness check (0 database calls) | None |
| **System** | `GET` | `/ready` | Database connectivity readiness check | None |
| **Import** | `GET` | `/api/v1/import/status` | Check if browser import is enabled and view upload size limit | None |
| **Import** | `POST` | `/api/v1/import/validate` | Statelessly validate uploaded traffic TSV / alerts JSON without database mutation | `traffic_file`, `alerts_file` [`multipart/form-data`] |
| **Import** | `POST` | `/api/v1/import` | Atomically replace the single active workspace with validated uploaded data | `traffic_file`, `alerts_file` [`multipart/form-data`] |
| **Analytics** | `GET` | `/api/v1/network/analytics/summary` | Global traffic metrics, metric mode, protocol & destination port distributions, top fan-out / fan-in | None |
| **Analytics** | `GET` | `/api/v1/network/analytics/endpoints` | Paginated endpoint ranking by distinct peers, packet volume, or byte volume | `sort_by`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/ips` | Paginated list of observed IP addresses with domain context | `domain`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/ips/{address}` | IP context, L2 associations, peer counts, and enriched packet/byte volumes | `address` (path), `domain` (query) |
| **Network** | `GET` | `/api/v1/network/ips/{address}/peers` | Communicating peers and observed protocols | `address` (path), `domain`, `direction`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/ips/{address}/layer2` | Paginated Layer 2 associations for an IP | `address` (path), `domain`, `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/layer2` | Paginated list of Layer 2 identifiers | `limit`, `offset` |
| **Network** | `GET` | `/api/v1/network/communications` | Filterable and sortable Layer 3 communication aggregates | `source_ip`, `target_ip`, `protocol`, `src_port`, `dst_port`, `sort_by`, `limit`, `offset` |
| **Alerts** | `GET` | `/api/v1/alerts` | Filterable normalized security alert facts | `source_ip`, `target_ip`, `priority`, `sid`, `protocol`, `limit`, `offset` |
| **Alerts** | `GET` | `/api/v1/alerts/{fact_key}` | Retrieve single alert fact by SHA-256 key | `fact_key` (path) |
| **Correlations** | `GET` | `/api/v1/correlations/traffic-alerts` | Legacy V1 communicating IP pairs with matching `AlertFact` records (with flow keys and transport ports) | `limit`, `offset` |
| **Correlations (V2)** | `GET` | `/api/v1/correlations/alert-flows` | Read-only paginated list of persisted V2 Suricata `AlertEvent` → Zeek `FlowObservation` correlations | `routing_domain_id`, `event_id`, `observation_id`, `include_unverified`, `verification_status`, `limit`, `offset` |
| **Correlations (V2)** | `GET` | `/api/v1/correlations/alert-flows/{event_id}` | Read-only persisted V2 correlations for a specific Suricata `AlertEvent` | `event_id` (path), `routing_domain_id`, `include_unverified`, `verification_status`, `limit`, `offset` |
| **Graph** | `GET` | `/api/v1/graph/neighborhood/{address}` | Bounded subgraph around an IP (preserves parallel edges with distinct `flow_key`) | `address` (path), `domain`, `depth`, `max_nodes` |
| **Graph** | `GET` | `/api/v1/graph/path` | Shortest Layer 3 path between two IPs | `source`, `target`, `source_domain`, `target_domain`, `max_hops` |

---

## Detailed Endpoint Notes

### 1. `GET /api/v1/network/analytics/summary`
Returns global workspace metrics including:
- `traffic_metrics_mode`: `"none" | "basic" | "enriched" | "mixed"`
- `total_communication_aggregates`, `enriched_communication_aggregates`, `basic_communication_aggregates`
- `total_observed_packets`, `total_observed_bytes`
- `first_observed`, `last_observed`
- `protocol_distribution`, `destination_port_distribution`
- `top_fan_out` (highest outbound peer count), `top_fan_in` (highest inbound peer count)

### 2. `GET /api/v1/network/analytics/endpoints`
Supports sorting endpoint rankings by `sort_by`:
- `fan_out` (default): outbound peer count
- `fan_in`: inbound peer count
- `observed_bytes_sent`, `observed_bytes_received`
- `observed_packets_sent`, `observed_packets_received`

Each endpoint record includes `scoped_id` (e.g. `default#10.0.0.5`) and `routing_domain_id`.

### 3. `GET /api/v1/network/communications`
Allows multi-attribute filtering by `source_ip`, `target_ip`, `protocol`, `src_port`, and `dst_port`. Supports sorting via `sort_by` (`"identity"` [default], `"observed_bytes"`, `"observed_packets"`, `"first_seen"`).

### 4. `GET /api/v1/graph/neighborhood/{address}`
Extracts a bounded subgraph (up to depth 2) around an IP. Relationships preserve composite element IDs (`${flow_key}`) to allow Cytoscape.js to render distinct parallel edges between the same node pair.
Supports optional `domain` query parameter for multi-domain networks.

### 5. `GET /api/v1/graph/path`
Finds the shortest Layer 3 communication path between `source` and `target`. When operating across multi-tenant or segmented networks, callers can disambiguate endpoints using `source_domain` and `target_domain`.

### 6. V2 Zeek–Suricata Alert-Flow Correlations (`GET /api/v1/correlations/alert-flows` & `/alert-flows/{event_id}`)

#### Separation from Legacy V1 Correlations
- **`GET /api/v1/correlations/traffic-alerts` (Legacy V1):** Unchanged. Queries legacy `(:IPAddress)-[:COMMUNICATED_TO]->(:IPAddress)` + `:AlertFact` co-occurrences via `Neo4jReadRepository.list_traffic_alert_correlations()`.
- **`GET /api/v1/correlations/alert-flows` & `GET /api/v1/correlations/alert-flows/{event_id}` (V2 Phase 4C):** Strictly **read-only** endpoints exposing persisted `(:AlertEvent {source_type: 'suricata'})-[:CORRELATED_WITH]->(:FlowObservation {source_type: 'zeek'})` edges via `Neo4jCorrelationRepository` inside `session.execute_read()` transactions. They never invoke correlation writes, reconciliation, or schema DDL, and never mix V1 `AlertFact` records with V2 `AlertEvent` correlations.
- **Epistemic Boundary:** A `CORRELATED_WITH` edge records a conservative observational association from a prior correlation run. It does **not** prove maliciousness, compromise, causation, or attacker/victim attribution.

#### Query Parameters & Pagination
Both V2 endpoints return `PaginatedResponse[AlertFlowCorrelationResponse]` (`items`, `total`, `limit`, `offset`) deterministically ordered by `(event_id ASC, observation_id ASC, coalesce(evidence_digest, '') ASC)`:
- `routing_domain_id` *(optional string)*: Normalized (trimmed lowercase); values containing `#` return **HTTP 422**. Prevents cross-domain leakage on both list and detail queries (a cross-domain detail request returns **404**).
- `event_id` *(list query filter or detail path param)*: 64-character lowercase hex SHA-256 `AlertEvent.event_id` (invalid format returns **HTTP 422**).
- `observation_id` *(list query filter only)*: 64-character lowercase hex SHA-256 `FlowObservation.observation_id` (invalid format returns **HTTP 422**).
- `include_unverified` *(optional boolean, safe default `false`)*: By default (`false` or omitted), edges marked `unverified_incomplete` are excluded. Set `include_unverified=true` to inspect both `verified` and `unverified_incomplete` edges.
- `verification_status` *(optional `"verified" | "unverified_incomplete"`)*: Exact filter on persisted verification status. Combining `include_unverified=false` with `verification_status=unverified_incomplete` returns **HTTP 422**.
- `limit` *(int, default `50`, `1..200`)* & `offset` *(int, default `0`, `>= 0`)*.

#### Verification Status Semantics & Persisted Truth vs. Real-Time State
- **`verified`**: A prior complete Phase 4B evaluation selected this flow uniquely under the recorded `policy_fingerprint`.
- **`unverified_incomplete`**: An earlier correlation edge preserved across a later incomplete/truncated evaluation (`last_incomplete_reason` and `last_incomplete_at_utc` populated). Never promoted silently to `verified`.
- **Legacy compatibility:** Any legacy `:CORRELATED_WITH` edge missing a `verification_status` property is coalesced to `"verified"` by the read repository (this reflects legacy compatibility, not a fresh revalidation).
- **No Live Recalculation on GET:** Persisted verification status reflects the **last persisted correlation evaluation**, not a real-time re-check against newly arrived Zeek flows. Under Neo4j Read Committed isolation, flows ingested after the last correlation run are not evaluated on HTTP `GET`.

#### Missing-Correlation Semantics (Detail Endpoint)
The absence of a `:CORRELATED_WITH` edge does **not** prove a `REJECTED` decision (the alert may never have been evaluated, or may have been `AMBIGUOUS`, `INSUFFICIENT`, `REJECTED`, or had a stale link removed):
- **Suricata `AlertEvent` does not exist** (or is not in the requested `routing_domain_id`): returns **HTTP 404**.
- **Suricata `AlertEvent` exists with zero matching edges** (including when its only edge is `unverified_incomplete` under default `include_unverified=false`): returns **HTTP 200** with `{"items": [], "total": 0, "limit": ..., "offset": ...}`.

#### Exact Decimal Timestamps & Evidence Scope
- `temporal_delta_decimal` is serialized strictly as an exact canonical `Decimal` string (never coerced to IEEE-754 `float`).
- Only factual properties persisted on the `:CORRELATED_WITH` edge and endpoints are exposed (`event_id`, `observation_id`, `zeek_uid`, `routing_domain_id`, `correlation_method`, `evidence_version`, `policy_fingerprint`, `evidence_digest`, `tuple_orientation`, `community_id_agreement`, `temporal_relation`, `temporal_delta_decimal`, `used_decimal_fallback`, `sensor_context`, `verification_status`, `last_incomplete_reason`, `last_incomplete_at_utc`, `decided_at_utc`). Internal Neo4j `elementId` values, invented confidence scores, and unpersisted Phase 4A candidate reason arrays are never fabricated or exposed.

#### Example Responses

Verified correlation (`GET /api/v1/correlations/alert-flows/{event_id}`):
```json
{
  "items": [
    {
      "event_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "observation_id": "1111111111111111111111111111111111111111111111111111111111111111",
      "zeek_uid": "CZ4C_f1",
      "routing_domain_id": "corp",
      "correlation_method": "cid_verified_5tuple_temporal",
      "evidence_version": "v1",
      "policy_fingerprint": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "evidence_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "tuple_orientation": "FORWARD",
      "community_id_agreement": "MATCH",
      "temporal_relation": "WITHIN_PRE_TOLERANCE",
      "temporal_delta_decimal": "-0.000000000123",
      "used_decimal_fallback": true,
      "sensor_context": "ALLOWED_ANY_IN_DOMAIN:suricata-4c->zeek-4c",
      "verification_status": "verified",
      "last_incomplete_reason": null,
      "last_incomplete_at_utc": null,
      "decided_at_utc": "2026-11-22T12:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

Preserved unverified correlation (`GET /api/v1/correlations/alert-flows?include_unverified=true`):
```json
{
  "items": [
    {
      "event_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "observation_id": "2222222222222222222222222222222222222222222222222222222222222222",
      "zeek_uid": "CZ4C_unv",
      "routing_domain_id": "corp",
      "correlation_method": "cid_verified_5tuple_temporal",
      "evidence_version": "v1",
      "policy_fingerprint": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "evidence_digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "tuple_orientation": "FORWARD",
      "community_id_agreement": "MATCH",
      "temporal_relation": "WITHIN_INTERVAL",
      "temporal_delta_decimal": "0",
      "used_decimal_fallback": false,
      "sensor_context": "ALLOWED_ANY_IN_DOMAIN:suricata-4c->zeek-4c",
      "verification_status": "unverified_incomplete",
      "last_incomplete_reason": "CANDIDATE_SET_TRUNCATED",
      "last_incomplete_at_utc": "2026-11-22T15:30:00Z",
      "decided_at_utc": "2026-11-22T12:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

#### HTTP Status Codes & Security Scope
- **200 OK:** Paginated result set (including empty collection when an existing `AlertEvent` has zero matching edges).
- **404 Not Found:** Referenced Suricata `AlertEvent` does not exist (or does not belong to the requested `routing_domain_id`).
- **422 Unprocessable Content:** Invalid `event_id`/`observation_id` format, `routing_domain_id` containing `#`, out-of-range `limit`/`offset`, invalid `verification_status`, or conflicting `include_unverified=false` + `verification_status=unverified_incomplete`.
- **503 Service Unavailable:** Neo4j driver unavailable, `ServiceUnavailable`, or `AuthError` (sanitized error message, never confused with `404`).
- **500 Internal Server Error:** Sanitized unexpected server error without leaking connection strings or stack traces.
- **Deployment Authentication Note:** These routes inherit the application's existing read-oriented CORS/trust boundary; multi-user authentication/RBAC for external multi-tenant deployments is a separate deployment concern.

---

## Ambiguity Resolution & Error Handling (HTTP 409 Conflict)

In multi-tenant or segmented environments, multiple endpoints may share the same IP address across different routing domains (e.g., `corp#10.0.0.5` vs `branch#10.0.0.5`).

The query resolution engine follows four deterministic rules:
1. **Explicit Scoped ID:** If `scoped_id` is supplied, matches exact scoped identity.
2. **Explicit Domain + Address:** If `domain` and `address` are supplied, resolves deterministically to `{domain}#{canonical_address}`.
3. **Single Unambiguous Match:** If only `address` is supplied and exactly one IP node exists across all routing domains, it is returned seamlessly (100% backward compatible for single-domain setups).
4. **Multiple Matches Across Domains:** If only `address` is supplied and matching nodes exist in multiple domains, the API aborts the query and responds with **HTTP 409 Conflict**:

```json
{
  "detail": {
    "code": "AMBIGUOUS_ENDPOINT",
    "message": "Multiple IP endpoints match '10.0.0.5' across domains: 'branch', 'corp'. Specify 'domain' or query by scoped_id.",
    "address": "10.0.0.5",
    "matching_domains": [
      "branch",
      "corp"
    ]
  }
}
```
To resolve this error, client applications or API callers must append `?domain=<target_domain>` to the request URL.
