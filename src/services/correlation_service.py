"""
Bounded Zeek-Suricata Correlation Runner Service (Phase 4B).

Orchestrates bounded selection of Suricata :AlertEvent nodes, Phase 4B Neo4j
candidate retrieval, Phase 4A pure-Python correlation evaluation, and atomic
per-batch edge reconciliation via Neo4jCorrelationRepository.

Transaction & Safety Guarantees:
- Write mode (`dry_run=False`) enforces `ensure_schema(driver)` prior to evaluation
  (`MigrationRequiredError` propagates without automatic legacy V1 mutation).
- Dry-run mode (`dry_run=True`) runs strictly read-only schema verification
  (`verify_schema_read_only(driver)`) and read-only evaluation transactions —
  executing ZERO schema DDL (CREATE/DROP CONSTRAINT or INDEX) and ZERO graph writes.
- Keyset pagination (`after_cursor`, `has_more`, `next_cursor`) prevents bounded-page
  starvation across workspaces exceeding `max_alerts` without claiming complete coverage
  when only a page ran.
- `only_uncorrelated=True` skips alerts that already carry outgoing `:CORRELATED_WITH`
  edges and is therefore unsuitable for stale-edge revalidation; use default
  `only_uncorrelated=False` with keyset continuation for full reconciliation passes.
- Commits each batch independently in one retry-safe managed write transaction.
  Does NOT claim run-wide atomicity across multiple batches: if batch N+1 fails,
  batches 1..N remain committed while batch N+1 rolls back atomically; re-running
  is safe and idempotent.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import logging
import sys
from typing import Iterable, List, Optional, Sequence, Union

from neo4j import GraphDatabase

from src.config import get_neo4j_config
from src.correlation import CorrelationPolicy, SensorPairingPolicy, SensorPolicyMode
from src.graph.correlation_repository import (
    AlertSelectionCursor,
    Neo4jCorrelationRepository,
)
from src.graph.repository import chunk_list
from src.graph.schema import (
    MigrationRequiredError,
    SchemaNotReadyError,
    ensure_schema,
    verify_schema_read_only,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CorrelationRunSummary:
    """Structured counter summary for one bounded correlation runner execution.

    Counter Semantics:
    - When `dry_run=False`, all mutation counters (`correlations_created`,
      `correlations_unchanged`, `correlations_updated`, `stale_correlations_removed`,
      and `batches_committed`) reflect only actually committed write batches.
    - When `dry_run=True`, zero graph mutations and zero schema DDL statements are
      executed, and all mutation counters plus `batches_committed` remain strictly 0.
    - `incomplete_evaluations` counts alerts whose candidate set was TRUNCATED or
      experienced a RETRIEVAL_ERROR (never promoted to STRONG and never destructively
      deleted; existing edges are flagged `unverified_incomplete` in write mode).
    - `has_more` and `next_cursor` report exact keyset pagination state: when
      `has_more=True`, additional matching AlertEvents remain beyond this page and
      callers should resume with `after_cursor=summary.next_cursor`.
    """

    dry_run: bool
    policy_fingerprint: str
    evidence_version: str
    alerts_evaluated: int
    strong: int
    ambiguous: int
    insufficient: int
    rejected: int
    correlations_created: int
    correlations_unchanged: int
    correlations_updated: int
    stale_correlations_removed: int
    candidate_cap_exceeded: int
    retrieval_errors: int
    incomplete_evaluations: int
    batches_committed: int
    has_more: bool = False
    next_cursor: Optional[AlertSelectionCursor] = None


def run_alert_flow_correlation(
    *,
    policy: Optional[CorrelationPolicy] = None,
    routing_domain_id: Optional[str] = None,
    sensor_id: Optional[str] = None,
    event_ids: Optional[Iterable[str]] = None,
    only_uncorrelated: bool = False,
    max_alerts: int = 1000,
    batch_size: int = 100,
    after_cursor: Optional[Union[AlertSelectionCursor, str]] = None,
    dry_run: bool = False,
    driver=None,
) -> CorrelationRunSummary:
    """Select bounded Suricata AlertEvents and run Phase 4A + 4B correlation reconciliation.

    Pagination & Coverage Contract:
    - When `event_ids` is omitted, selects up to `max_alerts` Suricata AlertEvents in
      deterministic order `(timestamp_epoch_ns IS NULL ASC, timestamp_epoch_ns ASC, event_id ASC)`
      starting strictly after `after_cursor` (if provided).
    - Returns `has_more=True` and a deterministic `next_cursor` whenever additional
      matching alerts exist beyond the evaluated page; never silently claims full
      workspace coverage on a limited page.
    - Passing `event_ids` with more than `max_alerts` distinct IDs raises `ValueError`
      (explicit selections are never silently truncated).
    - `only_uncorrelated=True` is intended only for incremental correlation of newly
      ingested unlinked alerts and is unsuitable for stale-edge revalidation.

    Multi-batch progress semantics:
    Each batch of up to `batch_size` AlertEvents commits in its own managed Neo4j
    transaction. Multi-batch runs are NOT all-or-nothing across batches; if a failure
    interrupts batch K, batches 1..K-1 remain durably committed, batch K rolls back
    atomically, and re-running converges idempotently.
    """
    active_policy = policy if policy is not None else CorrelationPolicy()
    if not isinstance(active_policy, CorrelationPolicy):
        raise ValueError(f"policy must be a CorrelationPolicy or None, got {policy!r}")
    if not isinstance(only_uncorrelated, bool):
        raise ValueError(f"only_uncorrelated must be a bool, got {only_uncorrelated!r}")
    if not isinstance(dry_run, bool):
        raise ValueError(f"dry_run must be a bool, got {dry_run!r}")
    if isinstance(max_alerts, bool) or not isinstance(max_alerts, int) or max_alerts < 1:
        raise ValueError(f"max_alerts must be a positive integer, got {max_alerts!r}")
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError(f"batch_size must be a positive integer, got {batch_size!r}")

    parsed_cursor: Optional[AlertSelectionCursor] = None
    if after_cursor is not None:
        if isinstance(after_cursor, AlertSelectionCursor):
            parsed_cursor = after_cursor
        elif isinstance(after_cursor, str):
            parsed_cursor = AlertSelectionCursor.from_token(after_cursor)
        else:
            raise ValueError(
                f"after_cursor must be an AlertSelectionCursor, token str, or None, got {after_cursor!r}"
            )

    norm_domain: Optional[str] = None
    if routing_domain_id is not None:
        if not isinstance(routing_domain_id, str) or not routing_domain_id.strip():
            raise ValueError(
                f"routing_domain_id must be a non-empty string or None, got {routing_domain_id!r}"
            )
        norm_domain = routing_domain_id.strip().lower()
        if "#" in norm_domain:
            raise ValueError(f"routing_domain_id cannot contain '#': {norm_domain!r}")

    norm_sensor: Optional[str] = None
    if sensor_id is not None:
        if not isinstance(sensor_id, str) or not sensor_id.strip():
            raise ValueError(f"sensor_id must be a non-empty string or None, got {sensor_id!r}")
        norm_sensor = sensor_id.strip().lower()

    explicit_ids: Optional[List[str]] = None
    if event_ids is not None:
        if parsed_cursor is not None:
            raise ValueError("after_cursor cannot be combined with explicit event_ids")
        dedup_ids: List[str] = []
        seen = set()
        for raw_id in event_ids:
            if not isinstance(raw_id, str) or not raw_id.strip():
                raise ValueError(f"event_id must be a non-empty string, got {raw_id!r}")
            clean_id = raw_id.strip()
            if clean_id not in seen:
                seen.add(clean_id)
                dedup_ids.append(clean_id)
        if len(dedup_ids) > max_alerts:
            raise ValueError(
                f"Explicit event_ids count ({len(dedup_ids)}) exceeds max_alerts ({max_alerts}). "
                "Increase max_alerts or split event_ids into smaller batches; explicit selections "
                "are never silently truncated."
            )
        explicit_ids = dedup_ids

    owns_driver = driver is None
    active_driver = driver

    alerts_evaluated = 0
    strong = 0
    ambiguous = 0
    insufficient = 0
    rejected = 0
    correlations_created = 0
    correlations_unchanged = 0
    correlations_updated = 0
    stale_correlations_removed = 0
    candidate_cap_exceeded = 0
    retrieval_errors = 0
    incomplete_evaluations = 0
    batches_committed = 0
    has_more = False
    next_cursor: Optional[AlertSelectionCursor] = None

    try:
        if owns_driver:
            cfg = get_neo4j_config()
            active_driver = GraphDatabase.driver(
                cfg["uri"],
                auth=(cfg["username"], cfg["password"]),
            )

        active_driver.verify_connectivity()
        if dry_run:
            # Strict read-only preflight: never executes CREATE/DROP CONSTRAINT or INDEX DDL.
            verify_schema_read_only(active_driver)
        else:
            ensure_schema(active_driver)

        repo = Neo4jCorrelationRepository(active_driver)
        if explicit_ids is not None:
            selected_ids = explicit_ids
        else:
            page = repo.list_correlatable_alert_page(
                routing_domain_id=norm_domain,
                sensor_id=norm_sensor,
                only_uncorrelated=only_uncorrelated,
                max_alerts=max_alerts,
                after_cursor=parsed_cursor,
            )
            selected_ids = list(page.event_ids)
            has_more = page.has_more
            next_cursor = page.next_cursor

        for batch_ids in chunk_list(selected_ids, batch_size):
            try:
                batch_res = repo.correlate_alert_batch(
                    batch_ids,
                    policy=active_policy,
                    dry_run=dry_run,
                )
            except Exception as exc:
                logger.error(
                    "Correlation batch failed after %d committed batch(es): %s",
                    batches_committed,
                    exc,
                )
                raise

            alerts_evaluated += batch_res.alerts_evaluated
            strong += batch_res.strong
            ambiguous += batch_res.ambiguous
            insufficient += batch_res.insufficient
            rejected += batch_res.rejected
            correlations_created += batch_res.correlations_created
            correlations_unchanged += batch_res.correlations_unchanged
            correlations_updated += batch_res.correlations_updated
            stale_correlations_removed += batch_res.stale_correlations_removed
            candidate_cap_exceeded += batch_res.candidate_cap_exceeded
            retrieval_errors += batch_res.retrieval_errors
            incomplete_evaluations += batch_res.incomplete_evaluations
            if not dry_run:
                batches_committed += 1
    finally:
        if owns_driver and active_driver is not None:
            active_driver.close()

    return CorrelationRunSummary(
        dry_run=dry_run,
        policy_fingerprint=active_policy.policy_fingerprint,
        evidence_version=active_policy.evidence_version,
        alerts_evaluated=alerts_evaluated,
        strong=strong,
        ambiguous=ambiguous,
        insufficient=insufficient,
        rejected=rejected,
        correlations_created=correlations_created,
        correlations_unchanged=correlations_unchanged,
        correlations_updated=correlations_updated,
        stale_correlations_removed=stale_correlations_removed,
        candidate_cap_exceeded=candidate_cap_exceeded,
        retrieval_errors=retrieval_errors,
        incomplete_evaluations=incomplete_evaluations,
        batches_committed=batches_committed,
        has_more=has_more,
        next_cursor=next_cursor,
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded Zeek-Suricata AlertEvent correlation and reconciliation (Phase 4B)."
    )
    parser.add_argument("--routing-domain-id", default=None, help="Filter AlertEvents by RoutingDomain ID.")
    parser.add_argument("--sensor-id", default=None, help="Filter AlertEvents by Suricata sensor ID.")
    parser.add_argument(
        "--event-id",
        action="append",
        dest="event_ids",
        default=None,
        help="Specific AlertEvent event_id to evaluate (repeatable).",
    )
    parser.add_argument(
        "--only-uncorrelated",
        action="store_true",
        help=(
            "Evaluate only AlertEvents currently lacking outgoing CORRELATED_WITH edges "
            "(unsuitable for stale-edge revalidation)."
        ),
    )
    parser.add_argument(
        "--after-cursor",
        default=None,
        help="Serialized JSON keyset continuation cursor token from a prior page's next_cursor.",
    )
    parser.add_argument(
        "--max-alerts",
        type=int,
        default=1000,
        help="Maximum number of AlertEvents to evaluate (default: 1000).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Maximum AlertEvents per atomic Neo4j transaction batch (default: 100).",
    )
    parser.add_argument(
        "--candidate-cap",
        type=int,
        default=200,
        help="Maximum FlowObservation candidates per AlertEvent before failing closed (default: 200).",
    )
    parser.add_argument(
        "--sensor-policy-mode",
        choices=[SensorPolicyMode.ANY_IN_DOMAIN.value, SensorPolicyMode.SAME_SENSOR_ID.value],
        default=SensorPolicyMode.ANY_IN_DOMAIN.value,
        help="Cross-sensor pairing policy (default: ANY_IN_DOMAIN).",
    )
    parser.add_argument(
        "--require-community-id",
        action="store_true",
        help="Require Community ID corroboration for automatic STRONG matches.",
    )
    parser.add_argument(
        "--disallow-default-domain",
        action="store_true",
        help="Disallow automatic STRONG correlation in the 'default' RoutingDomain.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate in read-only mode without creating, updating, or deleting edges.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        sensor_policy = (
            SensorPairingPolicy.same_sensor_id()
            if args.sensor_policy_mode == SensorPolicyMode.SAME_SENSOR_ID.value
            else SensorPairingPolicy.any_in_domain()
        )
        policy = CorrelationPolicy(
            sensor_policy=sensor_policy,
            require_community_id=args.require_community_id,
            allow_default_domain=not args.disallow_default_domain,
            candidate_cap=args.candidate_cap,
        )
        summary = run_alert_flow_correlation(
            policy=policy,
            routing_domain_id=args.routing_domain_id,
            sensor_id=args.sensor_id,
            event_ids=args.event_ids,
            only_uncorrelated=args.only_uncorrelated,
            max_alerts=args.max_alerts,
            batch_size=args.batch_size,
            after_cursor=args.after_cursor,
            dry_run=args.dry_run,
        )
    except (
        ValueError,
        LookupError,
        MigrationRequiredError,
        SchemaNotReadyError,
        EnvironmentError,
    ) as exc:
        logger.error("Correlation runner failed: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error during correlation run: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output = {
        "dry_run": summary.dry_run,
        "policy_fingerprint": summary.policy_fingerprint,
        "evidence_version": summary.evidence_version,
        "alerts_evaluated": summary.alerts_evaluated,
        "strong": summary.strong,
        "ambiguous": summary.ambiguous,
        "insufficient": summary.insufficient,
        "rejected": summary.rejected,
        "correlations_created": summary.correlations_created,
        "correlations_unchanged": summary.correlations_unchanged,
        "correlations_updated": summary.correlations_updated,
        "stale_correlations_removed": summary.stale_correlations_removed,
        "candidate_cap_exceeded": summary.candidate_cap_exceeded,
        "retrieval_errors": summary.retrieval_errors,
        "incomplete_evaluations": summary.incomplete_evaluations,
        "batches_committed": summary.batches_committed,
        "has_more": summary.has_more,
        "next_cursor": summary.next_cursor.to_token() if summary.next_cursor is not None else None,
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
