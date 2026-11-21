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
  - Explicit completeness signal (`COMPLETE`, `TRUNCATED`, `RETRIEVAL_ERROR`, `UNKNOWN`). Automatic `STRONG` promotion is strictly forbidden whenever completeness is not `COMPLETE` or `candidate_cap` is exceeded.
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
