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
| **Correlations** | `GET` | `/api/v1/correlations/traffic-alerts` | Communicating IP pairs with matching alerts (with flow keys and transport ports) | `limit`, `offset` |
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
