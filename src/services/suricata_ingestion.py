"""
Streaming Suricata EVE JSONL Ingestion Service (V2 Phase 3B.2).

Wires the Phase 3B.1 O(1)-memory streaming EVE alert parser to Phase 3B.2 Neo4j
persistence (:AlertEvent + :AlertDefinition + :IPAddress + :RoutingDomain).

Enforces schema readiness via ensure_schema() (propagating MigrationRequiredError if
unmigrated V1 IPAddress nodes exist), guarantees bounded-memory streaming batch writes,
and provides a CLI entrypoint (`python -m src.services.suricata_ingestion`).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import logging
import os
import sys
from typing import List, Optional, Union

from neo4j import GraphDatabase

from src.config import get_neo4j_config
from src.graph.repository import (
    AlertEventConflictError,
    AlertEventPersistenceSummary,
    Neo4jRepository,
)
from src.graph.schema import MigrationRequiredError, ensure_schema
from src.ingestion.suricata_eve_parser import (
    SuricataIngestionSummary,
    stream_suricata_eve_alerts,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SuricataIngestionResult:
    """Combined parse and Neo4j persistence report for a Suricata EVE JSONL run."""

    file_path: str
    sensor_id: str
    ruleset_namespace: str
    log_source_id: str
    routing_domain_id: str
    parse_summary: SuricataIngestionSummary
    persistence_summary: AlertEventPersistenceSummary


def ingest_suricata_eve_file(
    file_path: Union[str, os.PathLike[str]],
    *,
    sensor_id: str,
    ruleset_namespace: str,
    log_source_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
    batch_size: int = 500,
    driver=None,
) -> SuricataIngestionResult:
    """Stream a Suricata EVE JSONL file into Neo4j in bounded-memory batches.

    Validates configuration and opens the input stream eagerly before connecting
    to Neo4j, enforces ensure_schema(driver), and closes owned resources cleanly.

    Raises:
        FileNotFoundError: If file_path does not exist.
        ValueError: If batch_size, file_path, or parser parameters are invalid.
        MigrationRequiredError: If legacy unmigrated V1 IPAddress nodes exist.
        AlertEventConflictError: If an existing event_id has conflicting properties.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError(f"batch_size must be a positive integer, got {batch_size!r}")

    resolved_path = os.fspath(file_path)
    stream = stream_suricata_eve_alerts(
        resolved_path,
        sensor_id=sensor_id,
        ruleset_namespace=ruleset_namespace,
        log_source_id=log_source_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    )

    norm_sensor = sensor_id.strip().lower()
    norm_namespace = ruleset_namespace.strip().lower()
    norm_log_source = log_source_id.strip()
    norm_domain = routing_domain_id.strip().lower()

    owns_driver = driver is None
    active_driver = driver

    try:
        if owns_driver:
            cfg = get_neo4j_config()
            active_driver = GraphDatabase.driver(
                cfg["uri"],
                auth=(cfg["username"], cfg["password"]),
            )

        try:
            active_driver.verify_connectivity()
            ensure_schema(active_driver)

            repository = Neo4jRepository(active_driver, batch_size=batch_size)
            persistence_summary = repository.write_suricata_alert_events(
                stream,
                batch_size=batch_size,
            )
            parse_summary = stream.summary
        finally:
            if owns_driver and active_driver is not None:
                active_driver.close()
    finally:
        stream.close()

    return SuricataIngestionResult(
        file_path=resolved_path,
        sensor_id=norm_sensor,
        ruleset_namespace=norm_namespace,
        log_source_id=norm_log_source,
        routing_domain_id=norm_domain,
        parse_summary=parse_summary,
        persistence_summary=persistence_summary,
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ingest Suricata EVE JSONL alert events into Neo4j (V2 Phase 3B.2)."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the Suricata eve.json / EVE JSONL file.",
    )
    parser.add_argument(
        "--sensor-id",
        required=True,
        help="Sensor or vantage identifier (e.g., suricata-dmz-01).",
    )
    parser.add_argument(
        "--ruleset-namespace",
        required=True,
        help="Ruleset namespace for AlertDefinition identity (e.g., et-open, local).",
    )
    parser.add_argument(
        "--log-source-id",
        required=True,
        help="Logical log source identifier (e.g., dmz-eve-01).",
    )
    parser.add_argument(
        "--routing-domain-id",
        default="default",
        help="Target RoutingDomain identifier (default: default).",
    )
    parser.add_argument(
        "--source-provenance",
        default=None,
        help="Optional source provenance metadata string.",
    )
    parser.add_argument(
        "--community-id-seed",
        type=int,
        default=0,
        help="Optional uint16 Community ID seed (0..65535, default: 0).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Maximum AlertEvent records per Neo4j transaction batch (default: 500).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        result = ingest_suricata_eve_file(
            args.file,
            sensor_id=args.sensor_id,
            ruleset_namespace=args.ruleset_namespace,
            log_source_id=args.log_source_id,
            routing_domain_id=args.routing_domain_id,
            source_provenance=args.source_provenance,
            community_id_seed=args.community_id_seed,
            batch_size=args.batch_size,
        )
    except (
        FileNotFoundError,
        ValueError,
        MigrationRequiredError,
        AlertEventConflictError,
        EnvironmentError,
    ) as exc:
        logger.error("Suricata EVE ingestion failed: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error during Suricata EVE ingestion: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output = {
        "file_path": result.file_path,
        "sensor_id": result.sensor_id,
        "ruleset_namespace": result.ruleset_namespace,
        "log_source_id": result.log_source_id,
        "routing_domain_id": result.routing_domain_id,
        "parse_summary": {
            "total_raw_records": result.parse_summary.total_raw_records,
            "valid_records": result.parse_summary.valid_records,
            "skipped_records": result.parse_summary.skipped_records,
            "ignored_non_alert_records": result.parse_summary.ignored_non_alert_records,
            "warning_counts": dict(result.parse_summary.warning_counts),
            "sample_errors": list(result.parse_summary.sample_errors),
        },
        "persistence_summary": {
            "total_received": result.persistence_summary.total_received,
            "created_count": result.persistence_summary.created_count,
            "duplicate_matched_count": result.persistence_summary.duplicate_matched_count,
            "definitions_created_count": result.persistence_summary.definitions_created_count,
            "definitions_matched_count": result.persistence_summary.definitions_matched_count,
            "batches_committed": result.persistence_summary.batches_committed,
        },
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
