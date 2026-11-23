[← Back to README](../README.md)

# V2 Zeek–Suricata End-to-End Workflow Validation & Synthetic Demo (Phase 4E)

---

## 1. Purpose and Scope

This guide documents how to reproduce and verify the complete V2 Zeek–Suricata pipeline from a clean repository checkout using **disposable infrastructure and synthetic documentation-safe logs**:

```text
Synthetic Zeek conn.log JSONL + Suricata EVE JSONL (tests/fixtures/demo_v2/)
  └─▶ Streaming V2 parsers & Neo4j ingestion CLIs (src.services.zeek_ingestion, src.services.suricata_ingestion)
        └─▶ Neo4j (:FlowObservation), (:AlertEvent), (:AlertDefinition), (:IPAddress), (:RoutingDomain)
              └─▶ Phase 4A/4B Correlation Runner (src.services.correlation_service)
                    └─▶ Persisted (:AlertEvent)-[:CORRELATED_WITH]->(:FlowObservation) edges
                          └─▶ FastAPI Read-Only V2 Query API (src.api.app:app)
                                └─▶ React Phase 4D Alert–Flow Correlations Explorer (frontend/)
```

> **Strict Separation from Legacy V1 Quick Demo:**
> The top-level [README Quick Demo](../README.md#quick-demo-with-synthetic-samples) uses legacy **V1** traffic TSV (`data/samples/sample_traffic_enriched.tsv`) + Snort alert-fact JSON (`data/samples/sample_alerts.json`) + browser **Import Data**. Browser **Import Data** does **not** ingest V2 Zeek `conn.log` JSONL or Suricata EVE JSONL logs. Use the V2 CLI services documented below for Zeek and Suricata V2 workflows.

---

## 2. Prerequisites

- Python `3.10+` with project dependencies installed (`pip install -r requirements.txt`)
- Node.js `>=20.19.0` (CI uses Node `24`) with frontend dependencies installed (`cd frontend && npm ci`)
- Docker Desktop / Docker Engine + Docker Compose (to run the disposable `neo4j-test` container from [compose.yaml](../compose.yaml))
- Optional (for automated browser smoke execution `scripts/v2_browser_smoke.py`): `pip install playwright && python -m playwright install chromium`

---

## 3. Disposable Neo4j Setup

Start the disposable Neo4j 5.26.29 test container defined in [compose.yaml](../compose.yaml):

```bash
docker compose up -d neo4j-test
```

Wait until the container healthcheck reports `healthy` (`17474` HTTP, `17687` Bolt).

> **Safety Notice:**
> - Credentials in [compose.yaml](../compose.yaml) (`neo4j` / `phase6-test-password`) are **strictly test-only defaults for disposable local containers** and must never be used in production.
> - **Never** point `NEO4J_TEST_URI` at a remote, shared, or production database, and **never** run unrestricted cleanup commands such as `MATCH (n) DETACH DELETE n` against an unverified or shared Neo4j database.
> - Both `scripts/v2_browser_smoke.py` and `tests/test_v2_end_to_end_integration.py` enforce fail-closed loopback-only URI checks (`localhost`, `127.0.0.1`, `::1`). In addition, `scripts/v2_browser_smoke.py` refuses to execute against any non-empty database (`MATCH (n) RETURN count(n)` must equal `0`) and refuses to proceed if local ports `127.0.0.1:8000` or `127.0.0.1:5173` are already occupied.

Configure session-local environment variables (do not commit credentials to `.env` if shared):

**Bash / macOS / Linux:**
```bash
export NEO4J_URI="bolt://localhost:17687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="phase6-test-password"
export DATA_IMPORT_ENABLED="false"
```

**PowerShell (Windows):**
```powershell
$env:NEO4J_URI = "bolt://localhost:17687"
$env:NEO4J_USERNAME = "neo4j"
$env:NEO4J_PASSWORD = "phase6-test-password"
$env:DATA_IMPORT_ENABLED = "false"
```

---

## 4. Synthetic Demo Fixture Descriptions

All fixtures reside under [`tests/fixtures/demo_v2/`](../tests/fixtures/demo_v2/) using RFC 5737 documentation-safe IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and omit hardcoded `community_id` so the real Zeek and Suricata parsers derive Community ID v1 (`seed=0`) independently.

### `corp_conn.log.jsonl` (Domain `demo-v2-corp`, 7 Zeek Flows)
| UID | 5-Tuple & Timing | Scenario Purpose |
|---|---|---|
| `CDemoCorpStrong01` | `192.0.2.10:54321 -> 198.51.100.20:443` TCP (`ts=1795428000.123456789`, `duration=10.0`) | **Scenario A:** Unique eligible flow + high-precision decimal timestamp |
| `CDemoCorpAmbig01` | `192.0.2.30:55000 -> 198.51.100.40:8080` TCP (`ts=1795428060.0`, `duration=15.0`) | **Scenario B (candidate 1):** Overlapping flow creating ambiguity |
| `CDemoCorpAmbig02` | `192.0.2.30:55000 -> 198.51.100.40:8080` TCP (`ts=1795428062.0`, `duration=15.0`) | **Scenario B (candidate 2):** Second eligible flow -> `AMBIGUOUS` (no edge persisted) |
| `CDemoCorpIsoFlow01` | `203.0.113.50:56000 -> 203.0.113.60:22` TCP (`ts=1795428120.0`, `duration=20.0`) | **Scenario C1:** Overlapping 5-tuple scoped to `demo-v2-corp` |
| `CDemoCorpOnlyFlow01` | `203.0.113.70:57000 -> 203.0.113.80:8443` TCP (`ts=1795428180.0`, `duration=20.0`) | **Scenario C2:** Corp-only flow; same tuple alert in `demo-v2-branch` must not cross-correlate |
| `CDemoCorpNonMatchFlow` | `192.0.2.90:58000 -> 198.51.100.90:445` TCP (`ts=1795428300.0`, `duration=5.0`) | **Scenario D:** Temporal mismatch (+120s outside window) -> `REJECTED` |
| `CDemoCorpLifecycle01` | `192.0.2.110:59000 -> 198.51.100.110:8443` TCP (`ts=1795428500.0`, `duration=20.0`) | **Scenarios E & F:** Initial unique `STRONG` match prior to rival arrival |

### `corp_eve.jsonl` (Domain `demo-v2-corp`, 6 Raw Lines: 5 Valid Alerts + 1 Ignored `flow`)
1. `sid=9100001`: Sub-nanosecond ISO timestamp (`2026-11-23T10:00:02.123456789123+0000`, `timestamp_epoch_ns=None`, `used_decimal_fallback=True`) -> **Scenario A (`STRONG`)**.
2. `event_type="flow"`: Valid non-alert EVE record counted in `ignored_non_alert_records=1`.
3. `sid=9100002`: Matches both `CDemoCorpAmbig01` and `CDemoCorpAmbig02` -> **Scenario B (`AMBIGUOUS`)**.
4. `sid=9100003`: Matches `CDemoCorpIsoFlow01` strictly within `demo-v2-corp` -> **Scenario C1 (`STRONG`)**.
5. `sid=9100004`: `+120s` past `CDemoCorpNonMatchFlow` end -> **Scenario D (`REJECTED`)**.
6. `sid=9100005`: Initially matches `CDemoCorpLifecycle01` -> **Scenarios E & F (`STRONG` -> `unverified_incomplete` -> stale removed)**.

### `branch_conn.log.jsonl` & `branch_eve.jsonl` (Domain `demo-v2-branch`)
- `CDemoBranchIsoFlow01` (`203.0.113.50:56000 -> 203.0.113.60:22`): identical 5-tuple to `CDemoCorpIsoFlow01` in isolated domain `demo-v2-branch`.
- `branch_eve.jsonl` contains `sid=9100003` (correlates strictly with `CDemoBranchIsoFlow01`) and `sid=9100006` (`203.0.113.70:57000 -> 203.0.113.80:8443`, `REJECTED` because the flow resides in `demo-v2-corp`).

### `corp_stale_rival_conn.log.jsonl` (Domain `demo-v2-corp`)
- `CDemoCorpLifecycleRival02`: Overlapping `192.0.2.110:59000 -> 198.51.100.110:8443` flow used to demonstrate **Scenario E** (`unverified_incomplete` under truncated `--candidate-cap 1`) and **Scenario F** (stale removal on complete reevaluation).

---

## 5. Ingestion & Correlation CLI Commands

Run each V2 service CLI from the repository root (note: V2 ingestion automatically runs `ensure_schema(driver)` and refuses unmigrated legacy databases with `MigrationRequiredError`; on Windows PowerShell, replace `\` line continuations with PowerShell backticks `` ` `` or run each command on a single line):

```bash
# 1. Ingest Zeek conn.log JSONL into demo-v2-corp and demo-v2-branch
python -m src.services.zeek_ingestion \
  --file tests/fixtures/demo_v2/corp_conn.log.jsonl \
  --sensor-id zeek-demo-01 \
  --routing-domain-id demo-v2-corp \
  --source-provenance phase4e-corp-zeek

python -m src.services.zeek_ingestion \
  --file tests/fixtures/demo_v2/branch_conn.log.jsonl \
  --sensor-id zeek-branch-01 \
  --routing-domain-id demo-v2-branch \
  --source-provenance phase4e-branch-zeek

# 2. Ingest Suricata EVE JSONL into demo-v2-corp and demo-v2-branch
python -m src.services.suricata_ingestion \
  --file tests/fixtures/demo_v2/corp_eve.jsonl \
  --sensor-id suricata-demo-01 \
  --ruleset-namespace demo-v2-rules \
  --log-source-id corp-eve-demo-01 \
  --routing-domain-id demo-v2-corp \
  --source-provenance phase4e-corp-eve

python -m src.services.suricata_ingestion \
  --file tests/fixtures/demo_v2/branch_eve.jsonl \
  --sensor-id suricata-branch-01 \
  --ruleset-namespace demo-v2-rules \
  --log-source-id branch-eve-demo-01 \
  --routing-domain-id demo-v2-branch \
  --source-provenance phase4e-branch-eve

# 3. Preview decisions read-only first (zero graph writes)
python -m src.services.correlation_service --routing-domain-id demo-v2-corp --dry-run

# 4. Run Phase 4B correlation persistence per domain
python -m src.services.correlation_service --routing-domain-id demo-v2-corp
python -m src.services.correlation_service --routing-domain-id demo-v2-branch
```

> **Bounded Pagination & Complete Sweep Guidance:**
> When `--max-alerts` is smaller than the matching `AlertEvent` count, `correlation_service` outputs `"has_more": true` and a `"next_cursor"` token. Re-invoke with `--after-cursor "<next_cursor>"` until `"has_more": false` (default ordering places `timestamp_epoch_ns IS NULL` alerts last so sub-nanosecond/timezone-less alerts are never starved or skipped). Avoid `--only-uncorrelated` for reconciliation sweeps because it skips previously correlated alerts that may have become stale.

---

## 6. Expected Real Outputs

- **`demo-v2-corp` Zeek ingestion:** `parsed 7/7 valid (0 skipped); persisted 7 created, 0 duplicate/matched`
- **`demo-v2-corp` Suricata ingestion:** `total_raw_records: 6`, `valid_records: 5`, `ignored_non_alert_records: 1`, `skipped_records: 0`, `created_count: 5`, `definitions_created_count: 5`
- **`demo-v2-branch` ingestion:** 1 Zeek `FlowObservation`, 2 Suricata `AlertEvent` nodes
- **`demo-v2-corp` correlation summary:** `alerts_evaluated: 5`, `strong: 3`, `ambiguous: 1`, `rejected: 1`, `correlations_created: 3`, `has_more: false`
- **`demo-v2-branch` correlation summary:** `alerts_evaluated: 2`, `strong: 1`, `rejected: 1`, `correlations_created: 1`, `has_more: false`

---

## 7. Graph & Lifecycle Verification (Including Scenarios E & F)

To exercise **Scenario E** (`unverified_incomplete` preservation) and **Scenario F** (stale edge deletion):

> **UI Walkthrough Ordering Note:** If you plan to manually inspect the `Previously Verified — Current Check Incomplete` badge and warning banner in the React UI (Section 9, Step 7), pause after **Scenario E** (`--candidate-cap 1`) to inspect the UI, then return here to execute **Scenario F** (complete reevaluation), which removes the stale edge.

```bash
# Ingest the competing rival flow in demo-v2-corp (1 new FlowObservation)
python -m src.services.zeek_ingestion \
  --file tests/fixtures/demo_v2/corp_stale_rival_conn.log.jsonl \
  --sensor-id zeek-demo-01 \
  --routing-domain-id demo-v2-corp \
  --source-provenance phase4e-corp-rival-zeek

# Obtain <ALERT_EF_EVENT_ID> (the AlertEvent for sid=9100005 / zeek_uid=CDemoCorpLifecycle01)
# via read-only Cypher (`MATCH (ae:AlertEvent {routing_domain_id: 'demo-v2-corp', sid: 9100005}) RETURN ae.event_id`)
# or via `GET /api/v1/correlations/alert-flows?routing_domain_id=demo-v2-corp`.

# Scenario E — run with --candidate-cap 1 to trigger genuine truncated candidate retrieval:
python -m src.services.correlation_service --candidate-cap 1 --event-id "<ALERT_EF_EVENT_ID>"
# Result: incomplete_evaluations=1, candidate_cap_exceeded=1, stale_correlations_removed=0
# Existing edge is preserved with verification_status="unverified_incomplete" and last_incomplete_reason="CANDIDATE_CAP_TRUNCATED".

# Scenario F — re-run with complete candidate retrieval (default candidate_cap=200):
python -m src.services.correlation_service --event-id "<ALERT_EF_EVENT_ID>"
# Result: ambiguous=1, stale_correlations_removed=1 (stale edge removed).
```

Verify graph state directly via read-only Cypher in `cypher-shell` / Neo4j Browser (`http://localhost:17474`):

```cypher
MATCH (ae:AlertEvent)-[r:CORRELATED_WITH]->(fo:FlowObservation)
WHERE ae.routing_domain_id IN ['demo-v2-corp', 'demo-v2-branch']
RETURN ae.routing_domain_id AS domain,
       ae.sid AS sid,
       fo.zeek_uid AS zeek_uid,
       r.verification_status AS status,
       r.temporal_relation AS temporal_relation,
       r.temporal_delta_decimal AS delta,
       r.used_decimal_fallback AS decimal_fallback,
       r.evidence_digest AS digest
ORDER BY domain, sid;
```

---

## 8. FastAPI Backend Verification

Start the read-oriented FastAPI backend:

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

Verify endpoints (strictly `GET` requests):

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/ready
curl -s "http://127.0.0.1:8000/api/v1/correlations/alert-flows"
curl -s "http://127.0.0.1:8000/api/v1/correlations/alert-flows?routing_domain_id=demo-v2-corp&include_unverified=true"
```

- Verified-only default (`include_unverified` omitted or `false`) returns only `verification_status: "verified"` rows.
- `/api/v1/correlations/alert-flows/{event_id}` returns `HTTP 200` with `total: 0` when the `AlertEvent` exists without matching edges, and `HTTP 404` when unknown (or outside filtered `routing_domain_id`).

---

## 9. React Frontend & Automated Browser Smoke Steps

Start the Vite dev server (proxies `/api`, `/health`, `/ready` to `http://127.0.0.1:8000`):

```bash
cd frontend && npm run dev
```

Manual walkthrough at `http://localhost:5173`:
1. Confirm header pills display **API Liveness** and **Neo4j Connected**.
2. Click **Correlations** in the top navigation bar; confirm **Legacy Correlations** is selected by default.
3. Click the **Alert–Flow Correlations** tab.
4. Observe persisted `verified` rows (`CDemoCorpStrong01`, `CDemoCorpIsoFlow01`, `CDemoBranchIsoFlow01`); notice `unverified_incomplete` edges remain hidden under the safe default.
5. Click **Inspect** on `CDemoCorpStrong01` to open **Persisted Correlation Evidence Inspector**; verify full 64-character `AlertEvent ID`, `FlowObservation ID`, `Policy Fingerprint`, `Evidence Digest`, verbatim `Exact Temporal Delta`, and `Decimal Fallback Used`. Press `Escape` to close.
6. Filter `RoutingDomain` = `demo-v2-branch` and click **Apply Filters** to verify domain isolation.
7. Click **Reset**, check **Include unverified correlations**, and click **Apply Filters** to inspect any `Previously Verified — Current Check Incomplete` edges and explanatory warning banner.
8. Switch back to **Legacy Correlations** to verify legacy V1 remains functional and unaffected.

Automated real-stack headless Chromium verification (requires Playwright Chromium, an **empty** disposable `neo4j-test` container, and unoccupied local ports `127.0.0.1:8000` and `127.0.0.1:5173`):

**Bash / macOS / Linux:**
```bash
RUN_NEO4J_INTEGRATION=1 \
NEO4J_TEST_URI=bolt://localhost:17687 \
NEO4J_TEST_USERNAME=neo4j \
NEO4J_TEST_PASSWORD=phase6-test-password \
python scripts/v2_browser_smoke.py
```

**PowerShell (Windows):**
```powershell
$env:RUN_NEO4J_INTEGRATION = "1"
$env:NEO4J_TEST_URI = "bolt://localhost:17687"
$env:NEO4J_TEST_USERNAME = "neo4j"
$env:NEO4J_TEST_PASSWORD = "phase6-test-password"
python scripts/v2_browser_smoke.py
```

And automated pytest integration suite against disposable local Neo4j (uses isolated per-run `demo-v2-*-<run_id>` domains and owned-only cleanup):

**Bash / macOS / Linux:**
```bash
RUN_NEO4J_INTEGRATION=1 \
NEO4J_TEST_URI=bolt://localhost:17687 \
NEO4J_TEST_USERNAME=neo4j \
NEO4J_TEST_PASSWORD=phase6-test-password \
python -m pytest tests/test_v2_end_to_end_integration.py -m integration -v
```

**PowerShell (Windows):**
```powershell
$env:RUN_NEO4J_INTEGRATION = "1"
$env:NEO4J_TEST_URI = "bolt://localhost:17687"
$env:NEO4J_TEST_USERNAME = "neo4j"
$env:NEO4J_TEST_PASSWORD = "phase6-test-password"
python -m pytest tests/test_v2_end_to_end_integration.py -m integration -v
```

---

## 10. Idempotent Rerun Procedure

Re-running any of the Zeek ingestion, Suricata ingestion, or `correlation_service` commands from Section 5 on identical fixtures produces:
- `0` newly created `FlowObservation` or `AlertEvent` nodes (`duplicate_matched_count` increments cleanly)
- `0` newly created or duplicated `:CORRELATED_WITH` edges (`correlations_unchanged` matches existing verified edges)
- Unchanged `evidence_digest` values

---

## 11. Scoped Cleanup Instructions (Disposable Demo Database Only)

> **Warning:** Run these cleanup statements **only against your disposable local demo Neo4j container** (`bolt://localhost:17687`). Never run manual deletion queries against a shared or production database.

Remove **only** synthetic `demo-v2-corp` and `demo-v2-branch` entities while preserving any `IPAddress` or `RoutingDomain` still participating in unrelated V1/V2 relationships:

```cypher
MATCH (ae:AlertEvent) WHERE ae.routing_domain_id IN ['demo-v2-corp', 'demo-v2-branch'] DETACH DELETE ae;
MATCH (fo:FlowObservation) WHERE fo.routing_domain_id IN ['demo-v2-corp', 'demo-v2-branch'] DETACH DELETE fo;
MATCH (ip:IPAddress)
WHERE ip.routing_domain_id IN ['demo-v2-corp', 'demo-v2-branch']
   OR ip.scoped_id STARTS WITH 'demo-v2-corp#'
   OR ip.scoped_id STARTS WITH 'demo-v2-branch#'
OPTIONAL MATCH (ip)-[r]-() WHERE type(r) <> 'IN_DOMAIN'
WITH ip, count(r) AS other_rels
WHERE other_rels = 0
DETACH DELETE ip;
MATCH (ad:AlertDefinition {ruleset_namespace: 'demo-v2-rules'})
WHERE NOT (()-[:TRIGGERED_RULE]->(ad))
DETACH DELETE ad;
MATCH (rd:RoutingDomain)
WHERE rd.domain_id IN ['demo-v2-corp', 'demo-v2-branch']
OPTIONAL MATCH (rd)-[r]-()
WITH rd, count(r) AS rels
WHERE rels = 0
DELETE rd;
```

Then stop and remove the disposable test container:

```bash
docker compose down
```

---

## 12. Troubleshooting

- **`MigrationRequiredError` on ingestion/correlation:** Pre-existing legacy `:IPAddress` nodes lack `scoped_id`. Follow [MIGRATION.md](MIGRATION.md) (`python -m src.main --migrate`) or start from a clean disposable container.
- **`HTTP 503` / `Neo4j 503` banner:** `NEO4J_URI`, `NEO4J_USERNAME`, or `NEO4J_PASSWORD` are unset/incorrect for the backend process, or `neo4j-test` is still initializing.
- **`HTTP 422` on blank `RoutingDomain` filter:** Intentional fail-closed validation; clear the input completely instead of submitting whitespace or `#`.
- **`RUN_NEO4J_INTEGRATION=1` skipped:** All integration tests require `RUN_NEO4J_INTEGRATION=1` and explicit `NEO4J_TEST_*` variables.

---

## 13. Known Limitations

- **Read-Only V2 UI & CLI-Driven V2 Ingestion:** The V2 browser interface and `/api/v1/correlations/alert-flows*` endpoints are strictly read-only. Zeek and Suricata V2 ingestion and Phase 4B correlation runs remain CLI/service operations; the legacy browser **Import Data** workflow does not ingest V2 logs.
- **Persisted vs Real-Time Verification:** `verification_status` reflects the last stored Phase 4B evaluation, not live revalidation during read requests.
- **Phase 4C API Field Scope:** V2 correlation responses expose correlation IDs, verification state, and factual evidence fields only — not source/destination IPs, transport ports, full Suricata alert signatures, full Zeek flow bytes/packets, or unpersisted Phase 4A candidate reason arrays.
- **Read Committed Isolation:** Neo4j Read Committed isolation does not provide cross-query snapshot isolation; concurrent ingestion and multi-page count/item API reads can observe committed changes between queries.
- **Authentication / RBAC:** Multi-user authentication and role-based access control are not implemented in Phases 3A–4E.
- **Small Synthetic Dataset:** Validates semantic correctness and workflow wiring, not production performance or high-volume telemetry throughput.
- **Vite Development Server in Browser Smoke:** `scripts/v2_browser_smoke.py` and the CI `v2-browser-smoke` job exercise the Vite development server proxy against local `uvicorn`, not a hardened production reverse-proxy deployment serving static built assets.

---

## 14. What This Demonstration Does NOT Prove

- Persisted `:CORRELATED_WITH` edges represent **conservative observational associations only** — never proof of maliciousness, compromise, causation, or attacker/victim attribution.
- Absence of a `:CORRELATED_WITH` edge in Neo4j, API responses, or React UI **never proves** an alert was `REJECTED`, `AMBIGUOUS`, `INSUFFICIENT`, benign, or even evaluated.
- Community ID agreement corroborates 5-tuple symmetry under shared seeds but does **not** uniquely identify a session or substitute for endpoint/protocol/temporal gates.
- Passing this synthetic demo does **not** measure or guarantee production performance under high telemetry ingestion rates.
