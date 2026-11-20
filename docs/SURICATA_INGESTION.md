[← Back to README](../README.md)

# Suricata EVE JSON Alert Ingestion & Normalization (Phase 3B.1)

This document specifies the streaming Suricata EVE JSONL alert parser (`src/ingestion/suricata_eve_parser.py`) and normalized alert observation contract (`SuricataAlertObservation` in `src/ingestion/v2_models.py`).

---

## 1. Supported Input Format & Event Types

The parser accepts **Suricata EVE newline-delimited JSON (JSONL)** logs — one JSON object per line, conforming to Suricata's EVE JSON schema.

- **Processed event type:** Exclusively `event_type = "alert"` (case-insensitive trimmed match).
- **Ignored valid non-alert event types:** Other valid EVE records (e.g., `flow`, `dns`, `http`, `tls`, `stats`, `fileinfo`, `anomaly`, `ssh`) are **ignored cleanly** and counted in `SuricataIngestionSummary.ignored_non_alert_records` — they are **not** treated as malformed or skipped errors.
- **Empty / whitespace lines:** Ignored cleanly.
- **Extra fields:** Additional top-level or nested EVE fields (e.g., `vlan`, `in_iface`, `http`, `tls`, `payload`, `packet`, vendor extensions) are ignored without invalidating valid alert records; unbounded raw payloads are never copied into `SuricataAlertObservation`.
- **Standalone execution:** Zero runtime dependencies on Neo4j, Docker, Suricata, or the frontend.

---

## 2. Parser Usage

### Streaming API (Recommended for Large EVE Logs — O(1) Memory)

```python
from src.ingestion.suricata_eve_parser import stream_suricata_eve_alerts

with stream_suricata_eve_alerts(
    "path/to/eve.json",
    sensor_id="suricata-edge-01",
    ruleset_namespace="et-open",
    log_source_id="eve-edge01-2026-11-20",
    routing_domain_id="corp-prod",
    source_provenance="batch-01",
    community_id_seed=0,
) as stream:
    for alert in stream:
        print(alert.event_id, alert.alert_definition_id, alert.community_id)

    summary = stream.summary
```

### Batch Convenience & Iterable APIs

```python
from src.ingestion.suricata_eve_parser import (
    parse_suricata_eve_alert_file,
    iter_suricata_eve_alert_lines,
)

alerts, summary = parse_suricata_eve_alert_file(
    "path/to/eve.json",
    sensor_id="suricata-edge-01",
    ruleset_namespace="et-open",
    log_source_id="eve-edge01-2026-11-20",
    routing_domain_id="corp-prod",
)
```

---

## 3. Required and Optional Fields

### Required EVE Alert Fields (Missing or Invalid Skips Record)

| EVE Field | Normalized Field | Validation & Normalization |
|---|---|---|
| `event_type` | *(selector)* | Must equal `"alert"` (valid other strings counted in `ignored_non_alert_records`; missing/non-string skipped). |
| `timestamp` | `timestamp_source`, `timestamp_epoch_decimal` | Strict ISO 8601 string (supports `+0000`, `+00:00`, `Z`, offsets, and arbitrary fractional precision). |
| `src_ip`, `dest_ip` | `src_ip`, `dst_ip`, `src_scoped_id`, `dst_scoped_id` | Valid IPv4 or IPv6 canonicalized per RFC 5952; both endpoints must share the same IP version. |
| `alert` | *(container)* | Must be a JSON object (`dict`). |
| `alert.signature_id` | `sid` | Non-negative integer (strict non-bool). |

### Optional EVE Alert Fields (Absent Fields Remain `None`)

| EVE Field | Normalized Field | Semantics & Invalid Handling |
|---|---|---|
| `alert.gid` | `gid` | Non-negative integer or `None`. **Never** defaulted to `1`. Invalid value skips alert to protect `alert_definition_id`. |
| `alert.rev` | `rev` | Non-negative integer rule revision metadata (excluded from `alert_definition_id`). |
| `alert.signature` | `signature` | Optional trimmed rule message string. |
| `alert.category` | `category` | Optional trimmed source category metadata (**never** used to infer `ruleset_namespace`). |
| `alert.severity` | `severity` | Optional Suricata engine severity integer (**not** conflated with V1 `priority`). |
| `alert.action` | `action` | Optional Suricata action string (`allowed`, `blocked`, etc.; **not** treated as a final packet verdict). |
| `alert.metadata` | *(validated only)* | Must be a JSON object if present; arbitrary nested structures are not dumped into the normalized model. |
| `proto` | `protocol` | Optional transport protocol uppercased (`TCP`, `UDP`, `ICMP`, `IPV6-ICMP`, `SCTP`, etc.). |
| `src_port`, `dest_port` | `src_port`, `dst_port` | Optional integer `0..65535`. Malformed ports skip the alert to preserve directional `flow_key` integrity. |
| `flow_id` | `flow_id` | Optional Suricata engine flow integer (**never** used as `community_id` or sole event ID). |
| `community_id` | `community_id` | Preserved verbatim if non-empty string; otherwise computed when tuple is sufficient. |
| `app_proto`, `direction` | `app_proto`, `direction` | Optional trimmed strings. |
| `tx_id`, `pcap_cnt` | `tx_id`, `pcap_cnt` | Optional non-negative integers. |

---

## 4. AlertDefinition Identity vs AlertEvent Identity

### Static Rule Identity (`alert_definition_id`)

Delegated to `alert_definition_id(engine="suricata", ruleset_namespace=..., gid=..., sid=...)` in `src/ingestion/v2_models.py`:

- Canonical format: `suricata:{ruleset_namespace}:{gid_or_none}:{sid}`
- **`ruleset_namespace`** must be explicitly configured by the caller (e.g., `"et-open"`, `"local"`). It is **never** inferred from `alert.category`.
- **Absent `gid`:** Encoded explicitly as `'none'` (`suricata:et-open:none:2001219`), which never collides with `gid=1` (`suricata:et-open:1:2001219`).
- **Revision (`alert.rev`):** Stored strictly as metadata and excluded from `alert_definition_id`.

### Discrete Occurrence Identity (`event_id`) & `log_source_id` Provenance

Suricata EVE does **not** guarantee a unique per-alert record ID: a single `flow_id` can trigger many alerts, and `signature_id`, `tx_id`, and `pcap_cnt` can repeat across alert lines.

To keep streaming memory strictly `O(1)` without an unbounded in-memory set:

1. Callers must provide an explicit, stable **`log_source_id`** identifying the logical EVE log stream (never implicitly derived from the file's absolute filesystem path).
2. For each valid alert at 1-based physical line ordinal `line_no`, the parser computes a **type-safe canonical RFC 8259 JSON SHA-256 `record_fingerprint`** of the parsed JSON object — sorting object keys lexicographically, preserving array element order, keeping JSON types unambiguous (numbers unquoted via exact context-independent `format_canonical_decimal()`, strings quoted, booleans `true`/`false`, and `null` distinct from strings/numbers), and deriving:
   ```
   source_record_id = "{log_source_id}:line:{line_no}:{record_fingerprint}"
   ```
3. `event_id` is computed via `compute_alert_event_id(source_type="suricata", sensor_id=..., source_record_id=source_record_id, timestamp=timestamp_source, def_id=alert_definition_id, flow_reference=flow_key, source_provenance=...)`.

#### Identity Behavior Across Operational Scenarios

| Scenario | Resulting `source_record_id` / `event_id` |
|---|---|
| **Same file re-imported** (same `log_source_id` & config) | **Identical** (idempotent re-import). |
| **File renamed or moved** (same `log_source_id`) | **Identical** (filesystem path is never part of identity). |
| **Same rule fires repeatedly** (even identical `timestamp`, `sid`, `flow_id`, 5-tuple on two lines) | **Distinct** (different `line_no`). |
| **Two separate datasets with identical records** (different `log_source_id`) | **Distinct** (no accidental cross-dataset collision). |
| **Line inserted earlier in the file** (same `log_source_id`) | **Changes for shifted lines** because physical `line_no` shifts. |

> **Honest Cross-File Limitation:** This stateless line-ordinal + record-fingerprint strategy guarantees deterministic idempotency when re-importing an unchanged logical log file, but it does **not** claim automatic deduplication of identical alerts exported at different line offsets across rotated, split, or rewritten EVE files.

---

## 5. Timestamp Precision Contract

- **Exact Source Representation:** `timestamp_source` preserves the trimmed ISO 8601 source string verbatim (per Phase 1 `canonicalize_event_timestamp()` contract) for deterministic event identity.
- **Exact UTC `Decimal` Epoch:** When timezone information is present (`+0000`, `+00:00`, `Z`, `+03:00`, `-0500`, etc.), `timestamp_epoch_decimal` is derived via pure integer UTC day/second delta plus `add_exact_decimals()` (never `datetime.timestamp()` float conversion, never truncated to microseconds, and completely independent of Python's active `decimal.getcontext().prec`).
- **Naive Timestamps Policy:** Valid ISO 8601 timestamps lacking a timezone offset are **retained with `timestamp_epoch_decimal = None`** — the parser **never** invents UTC or local timezones.
- **Malformed Timestamps & Invalid Offsets:** Rejected with `invalid_timestamp` warning and record skipped (e.g., `+2500`, `+0060`, non-ISO strings).

---

## 6. RoutingDomain Scoping & Community ID Semantics

- **Explicit `routing_domain_id`:** Defaults to `"default"`, normalized trimmed lowercase, disallows `'#'`, and is **never** inferred from IP prefixes, VLAN tags, sensor names, or interfaces.
- **Directional Endpoint Integrity:** `src_scoped_id` and `dst_scoped_id` use `scoped_ip_id(routing_domain_id, canonical_ip)` and bind into directional `flow_key` (`compute_v2_flow_key()`). Source/destination orientation reflects observed packet/flow direction and does **not** infer attacker/victim roles.
- **`flow_id` vs `community_id`:** `flow_id` is Suricata's engine-local integer flow identifier and is kept strictly separate from `community_id`.
- **Community ID Resolution:** Delegates to `resolve_community_id()` with configurable 16-bit `community_id_seed`:
  - Preserves any valid non-empty string `community_id` from EVE verbatim.
  - Computes standard Community ID v1 when absent and the tuple is complete (`TCP`/`UDP`/`SCTP` with both ports, or `ICMP`/`IPv6-ICMP` with explicit valid `icmp_type` & `icmp_code` in `0..255`, mapping `IPv6-ICMP` to IANA `ICMP6`).
  - Never fabricates missing ports or ICMP values; returns `None` when tuple data is insufficient.
  - Never incorporates `routing_domain_id`, `sensor_id`, `vlan`, or `log_source_id`.

---

## 7. Diagnostics, Error Handling & Deferred Scope

- **Summary Accounting:** `SuricataIngestionSummary` satisfies `total_raw_records == valid_records + skipped_records + ignored_non_alert_records`.
- **Bounded Warning Logging:** Individual `logger.warning` lines are capped at `MAX_LOGGED_WARNINGS` (`10`) plus one suppression notice per stream, and `sample_errors` is capped at `MAX_SAMPLE_ERRORS` (`10`), while `warning_counts` always retains exact totals across arbitrarily large logs.
- **Deferred Beyond Phase 3B.2:**
  - Suricata `flow`, `dns`, `http`, `tls`, and `stats` event persistence.
  - Zeek `FlowObservation` ↔ Suricata `AlertEvent` correlation logic, Detection Engine, REST API endpoints, and frontend UI.
  - V1 Snort/IDS JSON array parser (`src/ingestion/alert_parser.py`) remains completely unchanged and isolated.

---

## Phase 3B.2: Neo4j Graph Persistence & CLI Ingestion

Suricata `AlertEvent` and `AlertDefinition` graph persistence builds directly on the normalized `SuricataAlertObservation` contract:

- **Schema Constraints & Indexes (`src/graph/schema.py`)**:
  - `alert_definition_unique`: Unique constraint on `AlertDefinition.definition_id`.
  - `alert_event_unique`: Unique constraint on `AlertEvent.event_id`.
  - Lookup indexes on `AlertEvent.flow_key`, `AlertEvent.community_id`, `AlertEvent.flow_id`, `AlertEvent.sensor_id`, `AlertEvent.routing_domain_id`, and `AlertEvent.timestamp_epoch_ns`.
- **Graph Model (`src/graph/repository.py`)**:
  - `(:AlertEvent)-[:TRIGGERED_RULE]->(:AlertDefinition)`
  - `(:AlertEvent)-[:HAS_SOURCE]->(:IPAddress)-[:IN_DOMAIN]->(:RoutingDomain)`
  - `(:AlertEvent)-[:HAS_DESTINATION]->(:IPAddress)-[:IN_DOMAIN]->(:RoutingDomain)`
  - `AlertDefinition` holds only stable rule identity fields (`definition_id`, `engine`, `ruleset_namespace`, `gid`, `sid`), while per-event evaluation metadata (`rev`, `signature`, `category`, `severity`, `action`, `app_proto`, `direction`, `tx_id`, `pcap_cnt`) lives exclusively on each immutable `:AlertEvent`.
- **Immutability, Lossless Precision & Batch Atomicity**:
  - Streaming writes (`Neo4jRepository.write_suricata_alert_events`) execute per-batch managed transactions (`session.execute_write`).
  - Conflicting payloads on an existing `event_id` raise `AlertEventConflictError`, rolling back the entire failing batch.
  - `flow_id` values (unsigned 64-bit integers potentially exceeding Neo4j signed 64-bit `INT64_MAX`) are stored uniformly as canonical decimal strings (`str(flow_id)`).
  - High-precision timestamps store verbatim `timestamp_source`, lossless `timestamp_epoch_decimal`, and exact signed 64-bit `timestamp_epoch_ns` (or `None` for timezone-naive timestamps).
- **Read API (`src/graph/read_repository.py`)**:
  - `get_alert_event(event_id)` and `list_alert_events(...)` provide indexed filtering (including unsigned `flow_id` lookup and numeric `timestamp_epoch_ns` windowing) with deterministic `NULLS LAST` pagination.
- **Streaming Service & CLI (`src/services/suricata_ingestion.py`)**:
  - `ingest_suricata_eve_file(...)` and `python -m src.services.suricata_ingestion` enforce `ensure_schema()` / `MigrationRequiredError` before persisting batches in O(`batch_size`) memory.
