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
| **Alerts** | `GET` | `/api/v1/alerts` | Filterable legacy V1 normalized security alert facts (`AlertFact`) | `source_ip`, `target_ip`, `priority`, `sid`, `protocol`, `limit`, `offset` |
| **Alerts** | `GET` | `/api/v1/alerts/{fact_key}` | Retrieve single legacy V1 alert fact (`AlertFact`) by SHA-256 key | `fact_key` (path) |
| **Observations (V2)** | `GET` | `/api/v1/alert-events/{event_id}` | Read-only forensic detail lookup for a V2 Suricata `AlertEvent` and linked `AlertDefinition` | `event_id` (path), `routing_domain_id` (optional query) |
| **Observations (V2)** | `GET` | `/api/v1/flow-observations/{observation_id}` | Read-only forensic detail lookup for a V2 Zeek `FlowObservation` | `observation_id` (path), `routing_domain_id` (optional query) |
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
Both V2 endpoints return `PaginatedResponse[AlertFlowCorrelationResponse]` (`items`, `total`, `limit`, `offset`) deterministically ordered by `(event_id ASC, observation_id ASC, coalesce(evidence_digest, '') ASC, coalesce(decided_at_utc, '') ASC)` with an internal non-exposed relationship tie-breaker so even duplicate parallel edges page deterministically without leaking Neo4j `elementId`:
- `routing_domain_id` *(optional string)*: Normalized (trimmed lowercase); empty/whitespace values or values containing `#` return **HTTP 422** (failing closed rather than dropping the domain filter). Prevents cross-domain leakage on both list and detail queries (a cross-domain detail request returns **404**).
- `event_id` *(list query filter or detail path param)*: 64-character lowercase hex SHA-256 `AlertEvent.event_id` (invalid format returns **HTTP 422**).
- `observation_id` *(list query filter only)*: 64-character lowercase hex SHA-256 `FlowObservation.observation_id` (invalid format returns **HTTP 422**).
- `include_unverified` *(optional boolean, safe default `false`)*: By default (`false` or omitted), edges marked `unverified_incomplete` are excluded. Set `include_unverified=true` to inspect both `verified` and `unverified_incomplete` edges.
- `verification_status` *(optional `"verified" | "unverified_incomplete"`)*: Exact filter on persisted verification status. Combining `include_unverified=false` with `verification_status=unverified_incomplete` returns **HTTP 422**; combining `include_unverified=true` with `verification_status=verified` narrows results to `"verified"`.
- `limit` *(int, default `50`, `1..200`)* & `offset` *(int, default `0`, `0..9223372036854775807`, Neo4j signed 64-bit integer ceiling; values `>= 2^63` return **HTTP 422**, and offsets at or beyond `total` return **HTTP 200** with an empty `items` list)*.
- **Concurrent Pagination Consistency (Read Committed):** Count and page queries (and the AlertEvent existence check on the detail endpoint) execute sequentially within one `session.execute_read()` transaction. On an unchanged dataset, `total` and `items` agree exactly with zero duplicate or skipped rows across pages. Under Neo4j Read Committed isolation, however, repeatable-read/snapshot consistency is **not** guaranteed if another transaction concurrently creates, deletes, or re-marks `:CORRELATED_WITH` edges between those statements.

#### Verification Status Semantics & Persisted Truth vs. Real-Time State
- **`verified`**: A prior complete Phase 4B evaluation selected this flow uniquely under the recorded `policy_fingerprint`.
- **`unverified_incomplete`**: An earlier correlation edge preserved across a later incomplete/truncated evaluation (`last_incomplete_reason` and `last_incomplete_at_utc` populated). Never promoted silently to `verified`.
- **Legacy compatibility:** Any legacy `:CORRELATED_WITH` edge missing a `verification_status` property (`NULL`) is coalesced to `"verified"` by the read repository (this reflects legacy compatibility, not a fresh revalidation).
- **Unknown / Corrupted Persisted Statuses:** Non-null unrecognized `verification_status` values are never promoted to `"verified"` (excluded by default and by exact status filters), and strict Pydantic serialization (`ConfigDict(strict=True)`) fails closed with a sanitized **HTTP 500** rather than silently coercing malformed database properties into misleading HTTP 200 responses.
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

### 7. V2 Forensic Observation Detail Endpoints (`GET /api/v1/alert-events/{event_id}` & `/api/v1/flow-observations/{observation_id}`)

#### V1 / V2 Separation & Read-Only Scope
- **`/api/v1/alerts` & `/api/v1/alerts/{fact_key}`** remain exclusively for legacy **V1 `AlertFact`** nodes and are unchanged.
- **`GET /api/v1/alert-events/{event_id}`** retrieves a single persisted V2 **Suricata `AlertEvent`** (`source_type = 'suricata'`) and its factual linked `(:AlertEvent)-[:TRIGGERED_RULE]->(:AlertDefinition)` engine metadata.
- **`GET /api/v1/flow-observations/{observation_id}`** retrieves a single persisted V2 **Zeek `FlowObservation`** (`source_type = 'zeek'`).
- Both endpoints execute strictly inside `session.execute_read()` managed read transactions on the shared Neo4j driver, use existing unique constraints (`AlertEvent.event_id`, `FlowObservation.observation_id`), perform zero graph writes/schema DDL/correlation runs, and never expose internal Neo4j `elementId` values.

#### Path, RoutingDomain, Source-Type & Precision Contracts
- **Path ID (`event_id` / `observation_id`):** Must match `^[0-9a-f]{64}$` (invalid values return **HTTP 422**).
- **`routing_domain_id` *(optional query string)*:** When specified, trimmed lowercase normalization applies; blank/whitespace values or values containing `#` return **HTTP 422**. Mismatched domain returns **HTTP 404**. Persisted nodes with missing/malformed `routing_domain_id` fail closed.
- **`source_type` Enforcement:** `AlertEvent` lookups enforce `source_type = 'suricata'` (`Literal["suricata"]`), and `FlowObservation` lookups enforce `source_type = 'zeek'` (`Literal["zeek"]`). Wrong-source nodes never leak across endpoints.
- **Missing or Contradictory `AlertDefinition`:** When `:TRIGGERED_RULE` is absent, `engine` is returned as `null` without fabricating rule-definition metadata. Multiple or contradictory `:TRIGGERED_RULE` definitions fail closed with sanitized **HTTP 500**.
- **Exact Decimal & Numeric Safety:**
  - `timestamp_epoch_decimal`, `start_epoch_decimal`, `end_epoch_decimal`, and `duration_decimal` are serialized verbatim as canonical `Decimal` strings (never converted to float).
  - Raw Neo4j nanosecond index integers (`timestamp_epoch_ns`, `start_epoch_ns`, `end_epoch_ns`) are **never** serialized to JSON.
  - `flow_id` is serialized as a canonical unsigned 64-bit decimal string (or `null`).
  - Integer counters (`gid`, `sid`, `rev`, `severity`, `tx_id`, `pcap_cnt`, `orig_bytes`, `resp_bytes`, `orig_ip_bytes`, `resp_ip_bytes`, `orig_pkts`, `resp_pkts`, `missed_bytes`) remain exact JSON integers when `0 <= n <= 9007199254740991` (`2^53 - 1`, JavaScript `Number.MAX_SAFE_INTEGER`) and serialize losslessly as decimal strings when larger.
- **Null Neutrality:** Missing persisted optional fields remain `null` (rendered as `Not recorded` in the UI).
- **Epistemic Boundary & Caveats:**
  - Suricata `src_ip`/`dst_ip` and Zeek `orig`/`resp` endpoints reflect observed packet/flow direction, **not** proof of attacker or victim roles.
  - Suricata `action` records rule/alert metadata only and does **not** prove end-to-end network enforcement.
  - Zeek `end_ts` is a derived last-observed timestamp (`start_epoch + duration`), **not** confirmed TCP session closure.
  - Zeek `conn_state = "SF"` does **not** universally prove benign traffic or successful application activity.
- **HTTP Status Semantics:** `200` (valid matching record), `404` (unknown entity, wrong `routing_domain_id`, or non-matching `source_type`), `422` (invalid SHA-256 ID or blank/`#` `routing_domain_id`), `503` (missing Neo4j driver, `ServiceUnavailable`, or `AuthError` — never masked as `404`), `500` (sanitized internal error or corrupt/contradictory persisted record rejected by strict Pydantic `ConfigDict(strict=True)` validation).
- **Authentication Limitation:** Like the rest of the Phase 4 API, these endpoints trust the local deployment boundary; multi-user authentication/RBAC is out of scope for Phase 4F.1 and required before multi-tenant or untrusted exposure. `routing_domain_id` is a namespace scope filter, not an authentication mechanism.

#### Example Scenario A Requests & Responses (Synthetic `demo_v2` Fixtures)

Suricata `AlertEvent` detail (`GET /api/v1/alert-events/1b13c85e13fe14e06380701d8abe0dfc466d843d90eef1709d6969f39fea2e8d?routing_domain_id=demo-v2-corp`):
```json
{
  "event_id": "1b13c85e13fe14e06380701d8abe0dfc466d843d90eef1709d6969f39fea2e8d",
  "alert_definition_id": "suricata:demo-v2-rules:1:9100001",
  "source_record_id": "8810001",
  "log_source_id": "corp-eve-demo-01",
  "sensor_id": "suricata-demo-01",
  "ruleset_namespace": "demo-v2-rules",
  "routing_domain_id": "demo-v2-corp",
  "source_type": "suricata",
  "source_provenance": "phase4e-corp-eve",
  "engine": "suricata",
  "gid": 1,
  "sid": 9100001,
  "rev": 1,
  "signature": "SYNTHETIC Demo Strong Match TLS Observation",
  "category": "Not Suspicious Traffic",
  "severity": 3,
  "action": "allowed",
  "app_proto": "tls",
  "direction": "to_server",
  "tx_id": 0,
  "pcap_cnt": 11,
  "flow_id": "8810001",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_scoped_id": "demo-v2-corp#192.0.2.10",
  "dst_scoped_id": "demo-v2-corp#198.51.100.20",
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 443,
  "flow_key": "40e772cb8ffeb90d27357c81784f78cba88b2410e431be11029f30be6e0c16a6",
  "community_id": "1:g8RTrAfW0W5D3mT1i4M4X+Atwmw=",
  "timestamp_source": "2026-11-23T10:00:02.123456789123+0000",
  "timestamp_epoch_decimal": "1795428002.123456789123"
}
```

Zeek `FlowObservation` detail (`GET /api/v1/flow-observations/b0e9ea368ed1cbbab586e61e755a6a3bbf2bfa2403c67b8bc153650c36e3d3b8?routing_domain_id=demo-v2-corp`):
```json
{
  "observation_id": "b0e9ea368ed1cbbab586e61e755a6a3bbf2bfa2403c67b8bc153650c36e3d3b8",
  "flow_key": "40e772cb8ffeb90d27357c81784f78cba88b2410e431be11029f30be6e0c16a6",
  "zeek_uid": "CDemoCorpStrong01",
  "routing_domain_id": "demo-v2-corp",
  "sensor_id": "zeek-demo-01",
  "source_type": "zeek",
  "source_provenance": "phase4e-corp-zeek",
  "community_id": "1:g8RTrAfW0W5D3mT1i4M4X+Atwmw=",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_scoped_id": "demo-v2-corp#192.0.2.10",
  "dst_scoped_id": "demo-v2-corp#198.51.100.20",
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 443,
  "start_ts": "1795428000.123456789",
  "end_ts": "1795428010.123456789",
  "start_epoch_decimal": "1795428000.123456789",
  "end_epoch_decimal": "1795428010.123456789",
  "duration_decimal": "10",
  "orig_bytes": 640,
  "resp_bytes": 2400,
  "orig_ip_bytes": 928,
  "resp_ip_bytes": 2736,
  "orig_pkts": 7,
  "resp_pkts": 8,
  "missed_bytes": 0,
  "service": "ssl",
  "conn_state": "SF",
  "history": "ShADadFf",
  "local_orig": true,
  "local_resp": false
}
```

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
