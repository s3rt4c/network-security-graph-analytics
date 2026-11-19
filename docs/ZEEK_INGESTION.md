[← Back to README](../README.md)

# Zeek `conn.log` JSON Ingestion & Normalization (Phase 3A.1)

This document specifies the streaming Zeek `conn.log` JSONL parser (`src/ingestion/zeek_conn_parser.py`) and normalized observation data contract (`ZeekConnectionObservation` in `src/ingestion/v2_models.py`).

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
| `duration` | `duration` (`Decimal \| None`) | Non-negative `Decimal` seconds. Derives `end_epoch` / `end_ts` when valid; invalid emits `invalid_duration` warning and yields `None`. |
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

## 6. Timestamp Precision & Directional Metric Semantics

- JSON floating-point numbers are parsed with `json.loads(..., parse_float=Decimal)` so sub-microsecond / nanosecond timestamps (e.g., `1725148800.123456789`) retain full precision for both `start_epoch` and `observation_id` hashing without IEEE 754 float64 truncation.
- `end_epoch` and `end_ts` are derived strictly as `start_epoch + duration` (using exact `Decimal` arithmetic) **only** when `duration` is present and valid; absent or invalid `duration` leaves `end_epoch = None` and `end_ts = None`.
- Observed timestamps are kept completely separate from processing/import wall-clock time.
- Directional metrics strictly separate `orig_bytes`/`resp_bytes` (payload-level) from `orig_ip_bytes`/`resp_ip_bytes` (IP-level) and `orig_pkts`/`resp_pkts`. Missing counters remain `None` rather than inventing `0`.

---

## 7. Known Limitations (Phase 3A.1 Scope)

- **No Neo4j persistence yet:** Phase 3A.1 covers parsing, validation, and normalization only; Neo4j `FlowObservation` persistence is deferred to Phase 3A.2.
- **JSONL format only:** Zeek tab-separated ASCII (`#fields`) logs are not parsed by this module.
- **No Suricata / AlertEvent ingestion or Detection Engine:** Deferred to subsequent Phase 3 milestones.
- **Single-pass streaming summary:** Streaming mode does not keep an in-memory set of seen `observation_id`s across a file (avoiding unbounded RAM growth); deduplication is achieved deterministically via `observation_id` during persistence.
