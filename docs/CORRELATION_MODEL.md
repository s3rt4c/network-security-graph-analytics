[← Back to README](../README.md)

# Zeek–Suricata Correlation Model & Evidence Evaluation (Phase 4A)

This document specifies the Phase 4A pure-Python, Neo4j-independent correlation engine (`src/correlation/`).

> **Phase Boundary:** Phase 4A performs read-only candidate evaluation and deterministic decision classification. It writes **zero** Neo4j nodes/relationships, makes **zero** schema/index changes, and keeps `:FlowObservation`, `:AlertEvent`, `:AlertDefinition`, and V1 `:AlertFact`/`COMMUNICATED_TO` telemetry completely untouched.

---

## 1. Epistemic Boundaries

1. **Observational Association Only:** A `STRONG` correlation means a single Zeek `FlowObservation` satisfies all conservative tuple, domain, Community ID, sensor, and exact temporal gates for a Suricata `AlertEvent`. It is **never** proof of maliciousness, compromise, causation, or attack attribution.
2. **Direction Neutrality:** Endpoint labels (`orig`/`resp` in Zeek, `src`/`dst` in Suricata) record packet/session capture direction and **never** infer attacker vs. victim roles.

---

## 2. Core Contracts (`src/correlation/models.py`)

- **`CorrelationPolicy`**:
  - Safe defaults: `pre_start_tolerance_sec = Decimal("0")`, `post_end_tolerance_sec = Decimal("0")`, `point_observation_post_tolerance_sec = Decimal("0")`, `allow_tolerance_match = False`, `allow_missing_zeek_end = False`, `community_id_seed_policy = CommunityIdSeedPolicy.STRICT_SAME_SEED`, `allow_default_domain = True`, `candidate_cap = 200`.
  - Produces a deterministic 64-char SHA-256 `policy_fingerprint` over all active configuration parameters.
- **`SensorPairingPolicy`**:
  - `ANY_IN_DOMAIN` (default), `SAME_SENSOR_ID`, or `EXPLICIT_PAIRS` (explicit `{suricata_sensor_id: [zeek_sensor_ids]}` mapping with optional exact `Decimal` per-pair clock offsets). Never infers a global sensor topology or assumes sensor names imply equal network vantage.
- **`CandidateCompleteness`**:
  - Explicit completeness signal (`COMPLETE`, `TRUNCATED`, `RETRIEVAL_ERROR`, `UNKNOWN`). `correlate_alert_to_flows()` defaults `candidate_completeness` to **`CandidateCompleteness.UNKNOWN`** (fail-closed) so omitting completeness never silently authorizes automatic correlation. Only explicitly `COMPLETE` candidate sets within `candidate_cap` may produce `STRONG`.
- **`AlertSnapshot` & `FlowSnapshot` Trust Boundaries**:
  - Both snapshots enforce a single shared validation and canonicalization path at construction time (`__post_init__`) and across all adapter inputs (`SuricataAlertObservation`, `ZeekConnectionObservation`, read-repository `Mapping`, and direct `Snapshot` instances): `routing_domain_id` and `sensor_id` normalization, canonical IPv4/IPv6 + `ip_version` consistency, `src_scoped_id`/`dst_scoped_id` integrity, transport port bounds (`0..65535`), finite non-negative exact `Decimal` timestamps (rejecting `float`), exact `*_epoch_ns` consistency against `_exact_decimal_epoch_to_ns`, and strict `source_type == "suricata"` (alerts) / `source_type == "zeek"` (flows).
- **`CorrelationCandidateEvidence` & `CorrelationDecision`**:
  - Deterministic audit objects recording machine-readable reason codes, orientation, tuple completeness, Community ID status, exact `Decimal` temporal delta (`temporal_delta_decimal`), and `used_decimal_fallback`.

---

## 3. Hard Eligibility Gates (G1–G7)

Every `(AlertEvent, FlowObservation)` candidate pair is evaluated in `evaluate_candidate()`:

1. **G1 — RoutingDomain Equality:** Strict `routing_domain_id` match (`corp#10.0.0.5 != branch#10.0.0.5`); optional `allow_default_domain=False` guard flags `"default"` domain as `INSUFFICIENT`.
2. **G2 — Sensor Compatibility:** Enforces `SensorPairingPolicy`.
3. **G3 — Bidirectional Canonical Endpoints:** Supports `FORWARD`, `REVERSE`, and `SYMMETRIC` (self-loop) endpoint alignment with strict IPv4/IPv6 family parity. NAT-transformed endpoints reject safely (`IP_ENDPOINT_MISMATCH`).
4. **G4 — Protocol Compatibility:** Uppercased canonical comparison with explicit IPv6 ICMP alias normalization (`Zeek "ICMP"` on IPv6 ↔ Suricata `"IPv6-ICMP"` / `"ICMPV6"`). Missing or unsupported protocols remain `INSUFFICIENT`.
5. **G5 — Transport Port / Tuple Completeness:**
   - `TCP` / `UDP` / `SCTP`: All 4 ports must be present and match aligned orientation (`COMPLETE_5TUPLE`) for `STRONG`; mismatched ports reject (`PORT_MISMATCH`); partial ports classify `PARTIAL_PORTS` (`INSUFFICIENT`). Never requires directional `flow_key` equality.
   - `ICMP` / `ICMP6`: Suricata does not persist `icmp_type`/`icmp_code` on `AlertEvent` (`src_port=None`, `dst_port=None`), so L4 ports are never compared against Zeek's type/code fields; non-empty Community ID corroboration is mandatory.
6. **G6 — Community ID Consistency:**
   - Evaluates `MATCH`, `MISSING_ALERT`, `MISSING_FLOW`, `MISSING_BOTH`, `CONFLICT`, `VERIFIED_SEED_OFFSET`, or `MISMATCH_SEED_UNVERIFIED`.
   - Default `STRICT_SAME_SEED` rejects mismatched Community IDs (`CONFLICT`).
   - `VERIFY_SEED_PAIR` re-computes expected v1 hashes via `compute_community_id()` from the verified 5-tuple using explicitly provided `zeek_community_id_seed` and `suricata_community_id_seed`.
   - Unverified seed mismatches (`ALLOW_UNVERIFIED_TUPLE_FALLBACK`) remain `INSUFFICIENT` and are never promoted automatically to `STRONG`.
7. **G7 — Exact `Decimal` Temporal Compatibility:**
   - Pure integer-backed `Decimal` math via `add_exact_decimals()` and `format_canonical_decimal()` (zero `float`, zero context rounding, zero lexicographic string comparison).
   - Evaluates directly from authoritative `*_epoch_decimal` values even when `timestamp_epoch_ns` / `start_epoch_ns` / `end_epoch_ns` are `None` (sub-nanosecond precision or post-2262 dates).
   - Missing Suricata timezone (`timestamp_epoch_decimal is None`) or missing Zeek `start_epoch` classifies `INSUFFICIENT` (never fabricates UTC).
   - Matches outside `[start_epoch, end_epoch]` within nonzero pre/post tolerances require explicit `allow_tolerance_match=True`.
   - Zeek flows missing `end_epoch` classify `NEAR_START_NO_END` within the configured start anchor window and require explicit `allow_missing_zeek_end=True`.

---

## 4. Decision Model & Fail-Closed Missing-CID Safety

`correlate_alert_to_flows()` aggregates candidates deterministically (order-independent) into four outcomes:

- **`STRONG` (`auto_correlate_allowed=True`):** `candidate_completeness == COMPLETE`, `not candidate_cap_exceeded`, zero alert precondition failures, **exactly 1** `STRONG` candidate, and **0** unresolved plausible rivals (`INSUFFICIENT`).
- **`AMBIGUOUS` (`auto_correlate_allowed=False`):** **≥ 2** `STRONG` candidates (overlapping flows or multiple Zeek sensors without `EXPLICIT_PAIRS`), **or** **1** `STRONG` candidate + **≥ 1** unresolved plausible rival (`INSUFFICIENT`, such as a competing flow missing `community_id`, missing `start_epoch`, missing `end_epoch`, or sitting within nonzero tolerance). Never breaks ties arbitrarily.
- **`INSUFFICIENT` (`auto_correlate_allowed=False`):** Non-`COMPLETE` / cap-exceeded candidate set, alert precondition gap, or 0 `STRONG` candidates with ≥ 1 plausible `INSUFFICIENT` candidate.
- **`REJECTED` (`auto_correlate_allowed=False`):** Complete evaluation with correlatable alert, 0 `STRONG` candidates, 0 `INSUFFICIENT` rivals, and all candidates contradicted (or 0 candidates found).

### Mandatory Phase 4B Database-Retrieval Acceptance Requirement

> **Completeness Hazard:** When an `AlertEvent` carries a non-null `community_id`, Phase 4B candidate retrieval in Neo4j **MUST NOT** query solely `WHERE fo.community_id = $community_id`. Doing so would silently omit competing `:FlowObservation` records on the same `routing_domain_id` and scoped bidirectional IP pair whose `fo.community_id IS NULL`, causing Phase 4A to erroneously see only 1 candidate and declare a false unique `STRONG` match.
>
> **Phase 4B Contract:** For every alert (including alerts that have a `community_id`), Phase 4B database retrieval MUST include both CID-indexed candidates **and** any same-domain scoped-endpoint `FlowObservation` records (via `(a:IPAddress)<-[:HAS_ORIGINATOR|HAS_RESPONDER]-(fo)-[:HAS_ORIGINATOR|HAS_RESPONDER]->(b:IPAddress)` or explicit completeness checks) within bounded `candidate_cap + 1` retrieval + `NULL`-ns fallback, passing an honest `CandidateCompleteness` (`COMPLETE` vs `TRUNCATED` vs `RETRIEVAL_ERROR`) into `correlate_alert_to_flows()`.

---

## 5. Phase 4B — Neo4j Candidate Retrieval, Persistence & Reconciliation (`src/graph/correlation_repository.py`, `src/services/correlation_service.py`)

### 5.1 Dual-Path Candidate Retrieval & Completeness Contract
For each Suricata `AlertEvent` (`ae.source_type = 'suricata'`), `Neo4jCorrelationRepository.retrieve_candidates_in_tx()` executes bounded candidate queries within the same transaction:
- **Path A (Community ID Lookup):** When `alert.community_id IS NOT NULL`, queries `:FlowObservation {community_id: $community_id}` constrained to `fo.routing_domain_id = $routing_domain_id`, `fo.source_type = 'zeek'`, and any active G2-allowed sensor list using the `flow_observation_community_id_index`, with `ORDER BY fo.observation_id ASC LIMIT $fetch_limit` (`candidate_cap + 1`).
- **Path B (Scoped Bidirectional Endpoint Union):** **Always executes**, even when `alert.community_id` is non-null, via `CALL { ... UNION ... }` over `(a:IPAddress {scoped_id: $src_scoped_id})<-[:HAS_ORIGINATOR]-(fo:FlowObservation)-[:HAS_RESPONDER]->(b:IPAddress {scoped_id: $dst_scoped_id})` and its reverse direction, bounded by `$fetch_limit`. Using `UNION` deduplicates self-loop flows cleanly and preserves every competing `:FlowObservation` whose `community_id IS NULL`.
- **Database Integrity Precondition:** Path B completeness depends on the Phase 3A.2 ingestion invariant (`Neo4jRepository.write_zeek_observations()`) that atomically creates both `(:FlowObservation)-[:HAS_ORIGINATOR]->(:IPAddress)` and `(:FlowObservation)-[:HAS_RESPONDER]->(:IPAddress)` in the same write transaction. Because Neo4j Community Edition does not enforce relationship-existence constraints, out-of-band manual inserts creating orphaned `:FlowObservation` nodes without endpoint relationships break this completeness precondition.
- **No False Completeness from `LIMIT`:** `merge_and_classify_candidates()` deduplicates Path A + Path B by `observation_id` (rejecting conflicting duplicate payloads) and marks `CandidateCompleteness.TRUNCATED` whenever **either** path returns `candidate_cap + 1` rows **or** the deduplicated union exceeds `candidate_cap`. Neither path can mask overflow in the other. Row-level validation failures produce `CandidateCompleteness.RETRIEVAL_ERROR`. `correlate_alert_to_flows()` always receives this explicit completeness signal and never relies on the `UNKNOWN` default.

### 5.2 Temporal Prefilter Omission & `NULL`-Nanosecond Safety
- Neither Path A nor Path B applies a narrow lower/upper database filter on `start_epoch_ns` or `end_epoch_ns`. Long-lived flows (`start=100, end=3600` with `alert=2000`), missing `start_epoch`/`end_epoch`, missing Suricata timezone (`timestamp_epoch_decimal=None`), sub-nanosecond timestamps (`*_epoch_ns=None`), post-2262 dates exceeding `INT64_MAX`, explicit sensor clock offsets, and nonzero tolerances are never dropped before Phase 4A exact `Decimal` evaluation.

### 5.3 `(:AlertEvent)-[:CORRELATED_WITH]->(:FlowObservation)` Graph Model & Digest
Edges are created strictly for `COMPLETE` + `STRONG` (`auto_correlate_allowed=True`) decisions and represent **observational association only** (never causation, compromise, or attribution):
- Stored properties: `correlation_method`, `evidence_version`, `policy_fingerprint`, `routing_domain_id`, `tuple_orientation`, `community_id_agreement`, `temporal_relation`, `temporal_delta_decimal`, `used_decimal_fallback`, `sensor_context`, `evidence_digest`, `decided_at_utc`, plus non-destructive freshness state (`verification_status`, `last_incomplete_reason`, `last_incomplete_at_utc`).
- No invented numerical confidence scores and no unbounded raw blobs are stored.
- `evidence_digest` is a deterministic SHA-256 hash over factual evidence fields and `policy_fingerprint` (excluding `decided_at_utc` and `verification_status`). Repeated runs under identical facts and policy detect matching `(observation_id, evidence_digest)` with `verification_status = 'verified'` and leave the existing edge untouched (`action="unchanged"`, zero rewrites).

### 5.4 Stale Correlation Reconciliation & Incomplete-Evaluation Freshness
- **When evaluation is `COMPLETE` and `STRONG`:** Creates the unique outgoing edge (or updates metadata in place if policy/digest changed or clears a prior `'unverified_incomplete'` flag back to `'verified'`), removing any obsolete outgoing `:CORRELATED_WITH` edges from that `AlertEvent`.
- **When evaluation is `COMPLETE` and `AMBIGUOUS` / `INSUFFICIENT` / `REJECTED`:** Deletes all previously established outgoing `:CORRELATED_WITH` edges for that `AlertEvent` (`stale_correlations_removed`), preventing stale correlations from lingering after a competing `FlowObservation` arrives or policy tightens.
- **When evaluation is incomplete (`TRUNCATED`, `RETRIEVAL_ERROR`, `UNKNOWN`):** Never creates new edges and **never** destructively deletes existing edges solely due to a failed/truncated lookup. In write mode (`dry_run=False`), any existing `:CORRELATED_WITH` edge(s) are non-destructively flagged `verification_status = 'unverified_incomplete'` with `last_incomplete_reason` and `last_incomplete_at_utc` while preserving all original evidence properties and `evidence_digest` intact. `get_alert_correlations()` exposes `verification_status` (defaulting `include_unverified=True` for full auditability, or `include_unverified=False` to exclude unverified links).
- **Workspace Replacement:** `Neo4jRepository.replace_workspace_data()` uses `CYPHER_SCOPED_CLEANUP` (`DETACH DELETE` on owned labels), automatically removing `:CORRELATED_WITH` edges on cleanup and rolling back atomically on failure without orphaned correlation state.

### 5.5 Transaction Boundaries, Concurrency Limitations & Guaranteed vs. Best-Effort Semantics
- **Guaranteed (within a single write batch / Neo4j 5.x constraints & locks):**
  - Each batch in `Neo4jCorrelationRepository.correlate_alert_batch()` executes inside one managed transaction (`session.execute_write`), sorted ascending by `event_id` to prevent cyclic deadlocks across workers.
  - Before reading candidates for an `AlertEvent`, the write transaction acquires Neo4j's exclusive per-node write lock on `ae` (`SET ae._corr_tx_lock = true WITH ae REMOVE ae._corr_tx_lock`), serializing concurrent correlation workers targeting the same `AlertEvent` while leaving committed telemetry properties and `payload_digest` untouched. Thus two concurrent correlation workers cannot silently create duplicate outgoing `:CORRELATED_WITH` edges for one alert.
  - Transaction failures or injected write errors roll back all edge creations/deletions in that batch atomically.
- **Best-Effort / Operational Boundary (Neo4j Read Committed Isolation):**
  - Neo4j's default Read Committed isolation is **not globally serializable** against independent concurrent Zeek or Suricata ingestion transactions (which lock `FlowObservation` / `IPAddress`, not existing `AlertEvent` nodes during flow ingest). If a competing `FlowObservation` commits concurrently *after* Path A/B read completes for an alert inside an active correlation transaction, that correlation transaction may commit an edge without seeing the newly ingested flow.
  - **Operational contract:** Schedule Zeek/Suricata ingestion and correlation sequentially (exclusive execution boundary), or re-run correlation idempotently after ingestion completes to reconcile newly ingested flows (`AMBIGUOUS` / updated decisions).
  - Across multi-batch runs (`batch_size`), each batch is its own atomic transaction; run-wide all-or-nothing atomicity is **not** claimed. If batch `K` fails, batches `1..K-1` remain committed (`batches_committed`), batch `K` rolls back, and re-running converges cleanly.

### 5.6 Dry-Run Safety, Keyset Pagination & Runner CLI Usage (`src/services/correlation_service.py`)
- **Strict Read-Only Dry-Run:** `dry_run=True` executes `verify_schema_read_only(driver)` (read-only `MATCH` legacy check + `SHOW CONSTRAINTS` + `SHOW INDEXES` in `session.execute_read()`) instead of `ensure_schema()`, failing cleanly with `SchemaNotReadyError` or `MigrationRequiredError` if required schema objects are missing without executing any `CREATE`/`DROP` DDL or data mutations. All evaluation queries run inside `session.execute_read()` and all committed mutation counters (`correlations_created`, `correlations_unchanged`, `correlations_updated`, `stale_correlations_removed`, `batches_committed`) remain strictly `0`.
- **Keyset Pagination & Anti-Starvation Contract:**
  - Bounded runs order eligible alerts strictly by `(timestamp_epoch_ns IS NULL ASC, timestamp_epoch_ns ASC, event_id ASC)` and fetch `max_alerts + 1` rows to compute exact `has_more` and `next_cursor` (`AlertSelectionCursor(timestamp_epoch_ns, event_id)`).
  - Callers advance across workspaces larger than `max_alerts` by passing `after_cursor=summary.next_cursor` (or CLI `--after-cursor <token>`) until `has_more` is `False`, with zero duplicate or skipped records on a stable dataset—including across identical timestamps and `NULL` timestamps.
  - **Concurrent changes between pages:** New alerts inserted strictly after `next_cursor` are picked up on subsequent pages; backfilled historical alerts inserted at or before `next_cursor` are covered on the next full pass starting from `after_cursor=None`. A single bounded page with `has_more=True` never claims complete workspace coverage.
  - **Explicit `event_ids` safety:** Passing more than `max_alerts` distinct explicit `event_ids` raises `ValueError` rather than silently truncating requested IDs; `after_cursor` cannot be combined with explicit `event_ids`.
  - **`only_uncorrelated=True` boundary:** Filters to alerts currently lacking outgoing `:CORRELATED_WITH` edges and is **unsuitable for stale-edge revalidation** (it skips previously correlated alerts that may have become `AMBIGUOUS` or `REJECTED`). Use default `only_uncorrelated=False` with keyset pagination for full reconciliation sweeps.
- CLI invocation:
  ```bash
  python -m src.services.correlation_service --routing-domain-id corp --batch-size 100 --dry-run
  python -m src.services.correlation_service --routing-domain-id corp --max-alerts 500 --after-cursor '{"event_id":"...","timestamp_epoch_ns":1795200110000000000}'
  python -m src.services.correlation_service --routing-domain-id corp --only-uncorrelated --max-alerts 500
  ```
