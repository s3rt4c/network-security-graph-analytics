[← Back to README](../README.md)

# Zeek `conn.log` JSON Ingestion & Neo4j `FlowObservation` Persistence (Phases 3A.1 & 3A.2)

This document specifies the streaming Zeek `conn.log` JSONL parser (`src/ingestion/zeek_conn_parser.py`), normalized observation data contract (`ZeekConnectionObservation` in `src/ingestion/v2_models.py`), Neo4j `FlowObservation` persistence (`src/graph/repository.py`, `src/graph/schema.py`, `src/graph/read_repository.py`), and streaming parser-to-database entrypoint (`src/services/zeek_ingestion.py`).

---

## 1. Supported Input Format

The parser accepts **standard Zeek `conn.log` in newline-delimited JSON (JSONL)** format — one JSON object per line, corresponding to Zeek's `Conn::Info` log schema (as produced by `@load policy/tuning/json-logs.zeek`).

- Empty and whitespace-only lines are ignored cleanly.
- Additional/unknown fields (e.g., `vlan`, `inner_vlan`, `tunnel_parents`, `orig_l2_addr`, vendor extensions) are ignored without rejecting valid records.
- The parser operates standalone with **zero runtime dependencies on Neo4j, Docker, Zeek, or the frontend**.

---

## 2. Parser Usage

### Streaming API (Recommended for Large Logs — O(1) Memory)

```python
from src.ingestion.zeek_conn_parser import stream_zeek_conn_file

with stream_zeek_conn_file(
    "path/to/conn.log.jsonl",
    sensor_id="zeek-edge-01",
    routing_domain_id="corp-prod",
    source_provenance="pcap-batch-01",
    community_id_seed=0,
) as stream:
    for observation in stream:
        # Process each ZeekConnectionObservation lazily line-by-line
        print(observation.observation_id, observation.zeek_uid, observation.community_id)

    summary = stream.summary
```

### Batch Convenience API

```python
from src.ingestion.zeek_conn_parser import parse_zeek_conn_file

observations, summary = parse_zeek_conn_file(
    "path/to/conn.log.jsonl",
    sensor_id="zeek-edge-01",
    routing_domain_id="corp-prod",
    source_provenance="pcap-batch-01",
    community_id_seed=0,
)
```

For in-memory or piped line iterables, use `iter_zeek_conn_lines(lines, sensor_id=..., ...)`.

---

## 3. Required and Optional Fields

### Required Zeek Fields (Missing or Invalid Skips Record)

| Zeek Field | Type | Normalization & Validation |
|---|---|---|
| `ts` | JSON number / decimal string / ISO 8601 string | Parsed via `json.loads(..., parse_float=Decimal)` to preserve full precision; must be finite and non-negative. |
| `uid` | non-empty string | Preserved verbatim (trimmed) as `zeek_uid` and used as native `source_record_id`. |
| `id.orig_h` | IPv4 / IPv6 string | Validated and canonicalized per RFC 5952; mapped to `src_scoped_id`. |
| `id.resp_h` | IPv4 / IPv6 string | Validated and canonicalized per RFC 5952; must match `id.orig_h` IP version; mapped to `dst_scoped_id`. |
| `proto` | non-empty string | Uppercased (`TCP`, `UDP`, `ICMP`, `ICMP6`, `SCTP`, etc.). Unsupported protocols (e.g., `unknown_transport`) emit an `unsupported_protocol` warning and never fabricate a Community ID. |

### Optional Zeek Fields (Absent Fields Remain `None`)

| Zeek Field | Normalized Field | Semantics & Invalid Handling |
|---|---|---|
| `id.orig_p`, `id.resp_p` | `src_port`, `dst_port` | Integer `0..65535` (or ICMP type/code). Absent -> `None`. Malformed/out-of-range skips the record to protect 5-tuple identity integrity. |
| `duration` | `duration` (`Decimal \| None`) | Non-negative `Decimal` seconds representing the time interval between the first and last observed packet per Zeek `Conn::Info`. Derives `end_epoch` / `end_ts` (`start_epoch + duration`) when valid; invalid emits `invalid_duration` warning and yields `None`. |
| `orig_bytes`, `resp_bytes` | `orig_bytes`, `resp_bytes` | Directional payload bytes (TCP sequence-number estimates / protocol payload). Not interchangeable with IP bytes. |
| `orig_ip_bytes`, `resp_ip_bytes` | `orig_ip_bytes`, `resp_ip_bytes` | Directional IP-level byte counts from IP headers. |
| `orig_pkts`, `resp_pkts` | `orig_pkts`, `resp_pkts` | Directional originator and responder packet counts. |
| `missed_bytes` | `missed_bytes` | Observed content gap bytes (`int \| None`). |
| `service`, `conn_state`, `history` | `service`, `conn_state`, `history` | Optional trimmed string metadata. |
| `local_orig`, `local_resp` | `local_orig`, `local_resp` | Optional strict booleans (`bool \| None`). |
| `community_id` | `community_id` | Preserved opaquely if non-empty string; otherwise computed via the Community ID adapter when tuple is supported. |

---

## 4. RoutingDomain & Sensor Identity

- **`routing_domain_id`** must be explicitly configured (defaults to `"default"`), normalized to trimmed lowercase, and cannot contain `'#'`. The parser **never** infers `RoutingDomain` from IP prefixes or sensor names.
- **`sensor_id`** is required and must be a non-empty string (normalized to trimmed lowercase).
- **`source_provenance`** is optional (`None` by default) so re-importing the same log file from a different filesystem path produces identical `observation_id` values unless provenance is explicitly specified.
- Invalid configuration or missing/unreadable input files fail eagerly (`FileNotFoundError`, `ValueError`, `OSError`).

---

## 5. Identity & Community ID Semantics

All V2 identities delegate strictly to existing primitives in `src/ingestion/v2_models.py` and `src/ingestion/community_id.py`:

- **`src_scoped_id` / `dst_scoped_id`**: `scoped_ip_id(routing_domain_id, canonical_ip)`
- **`flow_key`**: Directional SHA-256 via `compute_v2_flow_key(src_scoped_id, dst_scoped_id, protocol, src_port, dst_port)`
- **`observation_id`**: Deterministic SHA-256 via `compute_observation_id(source_type="zeek", sensor_id=..., source_record_id=zeek_uid, timestamp=..., flow_key=..., source_provenance=...)`
- **`zeek_uid`**: Preserved separately as Zeek's native connection identifier. Distinct Zeek records with different `uid`s never collapse even when sharing the exact same 5-tuple and timestamp.
- **`community_id`**: Resolved via `resolve_community_id(...)` with configurable 16-bit `community_id_seed`:
  - Preserves any non-empty Zeek-supplied `community_id` verbatim.
  - Computes standard Community ID v1 when absent and the tuple is supported (mapping Zeek's `proto="icmp"` on IPv6 addresses to IANA `ICMP6` / 58, and requiring valid ICMP type/code `0..255` rather than fabricating `0/0`).
  - Never incorporates `routing_domain_id`, `sensor_id`, or `vlan`.
  - Returns `None` for unsupported or incomplete tuples (never fabricated).

---

## 6. Timestamp Precision, Warning Scalability & Directional Metric Semantics

- **Numeric JSON timestamps:** Parsed with `json.loads(..., parse_float=Decimal)` so sub-microsecond / nanosecond timestamps (e.g., `1725148800.123456789`) retain full precision for both `start_epoch` and `observation_id` hashing without IEEE 754 float64 truncation. Equivalent numeric representations (e.g., `1725148800.1` and `1725148800.100`) normalize to the same canonical decimal string (`"1725148800.1"`).
- **Timezone-aware ISO 8601 timestamps:** Consistent with the Phase 1 `canonicalize_event_timestamp()` contract, ISO 8601 string timestamps retain their exact trimmed source representation in `start_ts` and `observation_id` without rewriting timezone offsets. Equivalent instants written with different offsets (e.g., `2024-09-01T12:00:00Z` vs `2024-09-01T15:00:00+03:00`) both compute the exact same numeric `start_epoch` (`Decimal("1725192000")`) for temporal ordering and duration arithmetic, while preserving source-representation-specific identity in `start_ts` and `observation_id`.
- **Derived `end_epoch` / `end_ts` semantics:** Derived strictly as `start_epoch + duration` (using exact `Decimal` arithmetic) **only** when `duration` is present and valid; absent or invalid `duration` leaves `end_epoch = None` and `end_ts = None`. Per Zeek `Conn::Info` semantics, `duration` is the elapsed time between the first and last observed packet — therefore `end_epoch` / `end_ts` represent a derived last-observed-packet timestamp and **not** a confirmed TCP session termination timestamp (connections may time out, reset, or be truncated mid-capture).
- **Observed vs import time:** Observed timestamps are kept completely separate from processing/import wall-clock time.
- **Directional metrics:** Strictly separate `orig_bytes`/`resp_bytes` (payload-level) from `orig_ip_bytes`/`resp_ip_bytes` (IP-level) and `orig_pkts`/`resp_pkts`. Missing counters remain `None` rather than inventing `0`.
- **Bounded warning logging:** On large logs with many malformed lines, per-stream `logger.warning` output is capped at `MAX_LOGGED_WARNINGS` (`10`) individual entries plus a single suppression notice, and `sample_errors` is capped at `MAX_SAMPLE_ERRORS` (`10`), while `IngestionSummary.warning_counts` continues recording exact totals for every warning category.

---

## 7. Neo4j `FlowObservation` Persistence (Phase 3A.2)

### Graph Model & Relationship Direction

Each discrete Zeek connection observation is persisted as a `(:FlowObservation)` node distinct from logical `COMMUNICATED_TO` traffic aggregates:

```
(:FlowObservation {observation_id (UQ), ...})
    ├──[:HAS_ORIGINATOR]──▶ (orig:IPAddress {scoped_id (UQ)})──[:IN_DOMAIN]──▶ (:RoutingDomain {domain_id (UQ)})
    └──[:HAS_RESPONDER]───▶ (resp:IPAddress {scoped_id (UQ)})──[:IN_DOMAIN]──▶ (:RoutingDomain {domain_id (UQ)})
```

- **Uniqueness & Indexes (`src/graph/schema.py`):**
  - `flow_observation_unique`: `UNIQUE` constraint on `FlowObservation.observation_id` (never `community_id`, `flow_key`, or `zeek_uid`).
  - `flow_observation_community_id_index`: non-unique lookup index on `FlowObservation.community_id`.
  - `flow_observation_sensor_id_index`: lookup index on `FlowObservation.sensor_id`.
  - `flow_observation_routing_domain_index`: lookup index on `FlowObservation.routing_domain_id`.
  - `flow_observation_start_epoch_ns_index`: numeric temporal lookup index on `FlowObservation.start_epoch_ns`.
- **Mutual Domain/Endpoint Consistency:** Before writing, `zeek_observation_to_payload()` verifies that `src_scoped_id == scoped_ip_id(routing_domain_id, src_ip)`, `dst_scoped_id == scoped_ip_id(routing_domain_id, dst_ip)`, and both endpoints share the same IP version. Cross-domain attachments are rejected.
- **No V1 Aggregate Mutation:** Zeek observations are never automatically converted into `COMMUNICATED_TO` edges.

### Exact Temporal Storage Contract

Neo4j does not natively store Python `Decimal`, and IEEE 754 `float` truncates nanosecond precision. All decimal canonicalization (`format_canonical_decimal()` / `canonicalize_event_timestamp()` / `format_exact_decimal()`), derived end-time addition (`add_exact_decimals()`), and integer nanosecond conversion (`decimal_epoch_to_ns()`) operate directly on `Decimal.as_tuple()` with exact Python integer arithmetic — **completely independent of Python's active `decimal.getcontext().prec`** (never relying on context-sensitive `Decimal.normalize()` or `Decimal` multiplication/addition). Every persisted `FlowObservation` stores:

- **Authoritative lossless string properties:** `start_ts`, `end_ts`, `start_epoch_decimal`, `end_epoch_decimal`, `duration_decimal` (preserving every significant source digit, including inputs exceeding 28 significant digits).
- **Optional exact 64-bit integer nanosecond index properties:** `start_epoch_ns`, `end_epoch_ns` derived via exact `Decimal.as_tuple()` integer scaling.
  - Supported lossless precision: up to 9 fractional digits (nanoseconds, including trailing zeros past the 9th place) within signed 64-bit integer bounds (`-(2^63)` to `2^63 - 1`, covering Unix epoch `0` through `9223372036.854775807`, i.e., years 1970–2262).
  - **Explicit non-truncation policy:** Timestamps with any nonzero fractional digit beyond the 9th decimal place (sub-nanosecond precision, even beyond 28 significant digits) or outside signed 64-bit bounds set `*_epoch_ns = None` rather than silently truncating, rounding, or overflowing, while retaining exact original strings in `start_ts` and `*_epoch_decimal`.
- **Phase 1 Identity Compatibility:** Ordinary numeric timestamps (≤28 significant digits, including standard microsecond and nanosecond Unix epochs) and all ISO 8601 string timestamps produce **byte-identical** canonical strings and `observation_id` digests. Extreme-precision numeric inputs (>28 significant digits) that were previously silently rounded by `Decimal.normalize()` now preserve all significant digits so distinct events no longer collide.

### Idempotency, Immutability & Conflict Policy

- `Neo4jRepository.write_zeek_observations(observations, batch_size=...)` computes a deterministic `payload_digest` (SHA-256 over all immutable persisted fields) and uses `MERGE (fo:FlowObservation {observation_id: row.observation_id}) ON CREATE SET ...`.
- Re-importing identical observations creates zero duplicate nodes, zero duplicate relationships, and never doubles directional byte/packet counters.
- If an existing `observation_id` is re-submitted with conflicting properties (either intra-batch or against Neo4j), `ObservationConflictError` is raised and the offending batch rolls back without overwriting existing facts.

### Streaming Batch Semantics & Entrypoint

- Consumes any `Iterable[ZeekConnectionObservation]` lazily in bounded chunks (`O(batch_size)` RAM; never calls `list(observations)`).
- Each batch commits inside its own retry-safe managed write transaction (`session.execute_write`). Earlier batches remain committed if a later batch fails; retrying the stream is idempotent for already-committed observations.
- **Parser-to-Neo4j Entrypoint (`src/services/zeek_ingestion.py`):**
  ```bash
  python -m src.services.zeek_ingestion \
    --file path/to/conn.log.jsonl \
    --sensor-id zeek-edge-01 \
    --routing-domain-id corp-prod \
    --batch-size 500
  ```
  Programmatic API: `ingest_zeek_conn_file(file_path, sensor_id=..., routing_domain_id="default", source_provenance=None, batch_size=500)`. Verifies connectivity, calls `ensure_schema(driver)`, and refuses unsafe writes against unmigrated legacy V1 databases (`MigrationRequiredError`).

### Read Capabilities & Workspace Replacement Safety

- **Read Repository (`src/graph/read_repository.py`):**
  - `get_flow_observation(observation_id)`: exact lookup by `observation_id`.
  - `list_flow_observations(routing_domain_id=None, sensor_id=None, community_id=None, start_epoch_ns_min=None, start_epoch_ns_max=None, limit=50, offset=0)`: bounded paginated list with deterministic ordering (`start_epoch_ns ASC NULLS LAST, observation_id ASC`). Temporal bounds operate strictly on exact integer `start_epoch_ns` (never lexicographic string comparison), and observations sharing `flow_key` or `community_id` are never collapsed.
- **Atomic Workspace Replacement:** `CYPHER_SCOPED_CLEANUP` includes `n:FlowObservation` alongside `:IPAddress`, `:Layer2Identifier`, `:AlertFact`, and `:RoutingDomain` so single-workspace replacement never leaves orphaned `FlowObservation` nodes, preserves unrelated external graph labels, and rolls back all prior `FlowObservation` nodes atomically if replacement fails.

---

## 8. Operational Limitations (Phase 3A Scope)

- **Per-batch transaction boundary:** Streaming batch ingestion commits per batch (`O(batch_size)` memory) and does not provide file-wide multi-batch atomicity; recovery relies on idempotent retry by `observation_id`.
- **JSONL format only:** Zeek tab-separated ASCII (`#fields`) logs are not parsed by this module.
- **No Suricata / AlertEvent ingestion, public REST routes, or frontend UI yet:** Deferred to subsequent Phase 3 milestones.
- **Sub-nanosecond range queries:** Observations whose timestamps exceed nanosecond precision (>9 fractional digits) retain exact string timestamps (`start_ts`, `start_epoch_decimal`) but have `start_epoch_ns = None` and are excluded from integer `start_epoch_ns` range filters rather than being truncated.
