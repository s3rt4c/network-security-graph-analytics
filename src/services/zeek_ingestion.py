"""
Minimal parser-to-Neo4j ingestion entrypoint for Zeek conn.log JSONL files.

Connects `stream_zeek_conn_file()` to `Neo4jRepository.write_zeek_observations()`
in bounded batches without materializing the full log in memory.

Transaction and migration safety:
- Verifies Neo4j connectivity before writing.
- Runs `ensure_schema(driver)` and refuses unsafe writes against unmigrated legacy V1
  databases (`MigrationRequiredError` propagates without automatic legacy mutation).
- Commits each batch in its own retry-safe managed write transaction; does not claim
  file-wide atomicity across multiple batches.
"""

import argparse
from dataclasses import dataclass
import logging
import os
import sys
from typing import Optional, Sequence, Union

from neo4j import GraphDatabase

from src.config import get_neo4j_config
from src.graph.repository import (
    Neo4jRepository,
    ObservationConflictError,
    ObservationPersistenceSummary,
)
from src.graph.schema import MigrationRequiredError, ensure_schema
from src.ingestion.models import IngestionSummary
from src.ingestion.zeek_conn_parser import stream_zeek_conn_file

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ZeekIngestionResult:
    """Combined parse and persistence summary for a Zeek conn.log ingestion run."""

    file_path: str
    sensor_id: str
    routing_domain_id: str
    source_provenance: Optional[str]
    parse_summary: IngestionSummary
    persistence_summary: ObservationPersistenceSummary


def ingest_zeek_conn_file(
    file_path: Union[str, os.PathLike],
    *,
    sensor_id: str,
    routing_domain_id: str = "default",
    source_provenance: Optional[str] = None,
    community_id_seed: int = 0,
    batch_size: int = 500,
    driver=None,
) -> ZeekIngestionResult:
    """Stream a Zeek conn.log JSONL file into Neo4j as discrete :FlowObservation nodes.

    Args:
        file_path: Path to Zeek conn.log JSONL file.
        sensor_id: Required explicit sensor identifier (normalized lowercase).
        routing_domain_id: Explicit Layer 3 routing domain (defaults to 'default').
        source_provenance: Optional ingestion provenance label (defaults to None).
        community_id_seed: Optional 16-bit Community ID seed (defaults to 0).
        batch_size: Maximum observations per Neo4j write transaction (defaults to 500).
        driver: Optional pre-configured Neo4j driver. If omitted, creates a driver from
            environment configuration via `get_neo4j_config()` and closes it on exit.

    Returns:
        ZeekIngestionResult containing both parser diagnostics and persistence counts.

    Raises:
        FileNotFoundError, ValueError, OSError: Invalid configuration or unreadable input file.
        EnvironmentError: Missing Neo4j environment configuration when `driver` is None.
        MigrationRequiredError: Database contains unmigrated legacy V1 IPAddress nodes.
        ObservationConflictError: Existing observation_id conflicts with incoming payload.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError(f"batch_size must be an integer >= 1, got {batch_size!r}")

    norm_sensor = sensor_id.strip().lower() if isinstance(sensor_id, str) and sensor_id.strip() else ""
    norm_domain = (
        routing_domain_id.strip().lower()
        if isinstance(routing_domain_id, str) and routing_domain_id.strip()
        else ""
    )
    norm_provenance = (
        source_provenance.strip() or None
        if isinstance(source_provenance, str)
        else source_provenance
    )

    owned_driver = driver is None
    active_driver = driver

    # Open stream first so invalid file paths / parser config fail eagerly before Neo4j IO.
    with stream_zeek_conn_file(
        file_path,
        sensor_id=sensor_id,
        routing_domain_id=routing_domain_id,
        source_provenance=source_provenance,
        community_id_seed=community_id_seed,
    ) as stream:
        try:
            if owned_driver:
                neo4j_cfg = get_neo4j_config()
                logger.info("Connecting to Neo4j at %s ...", neo4j_cfg["uri"])
                active_driver = GraphDatabase.driver(
                    neo4j_cfg["uri"],
                    auth=(neo4j_cfg["username"], neo4j_cfg["password"]),
                )

            active_driver.verify_connectivity()
            ensure_schema(active_driver)

            repo = Neo4jRepository(active_driver, batch_size=batch_size)
            persistence_summary = repo.write_zeek_observations(stream, batch_size=batch_size)
            parse_summary = stream.summary

            return ZeekIngestionResult(
                file_path=os.fspath(file_path),
                sensor_id=norm_sensor,
                routing_domain_id=norm_domain,
                source_provenance=norm_provenance,
                parse_summary=parse_summary,
                persistence_summary=persistence_summary,
            )
        finally:
            if owned_driver and active_driver is not None:
                active_driver.close()
                logger.info("Neo4j connection closed.")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stream a Zeek conn.log JSONL file into Neo4j FlowObservation nodes."
    )
    parser.add_argument("--file", required=True, help="Path to Zeek conn.log JSONL file.")
    parser.add_argument("--sensor-id", required=True, help="Explicit sensor identifier.")
    parser.add_argument(
        "--routing-domain-id",
        default="default",
        help="Explicit Layer 3 routing domain identifier (default: default).",
    )
    parser.add_argument(
        "--source-provenance",
        default=None,
        help="Optional ingestion provenance label (default: None).",
    )
    parser.add_argument(
        "--community-id-seed",
        type=int,
        default=0,
        help="16-bit Community ID hash seed (default: 0).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Bounded observation count per Neo4j write transaction (default: 500).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Minimal CLI entrypoint for Zeek conn.log streaming persistence."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    args = _build_arg_parser().parse_args(argv)
    try:
        result = ingest_zeek_conn_file(
            args.file,
            sensor_id=args.sensor_id,
            routing_domain_id=args.routing_domain_id,
            source_provenance=args.source_provenance,
            community_id_seed=args.community_id_seed,
            batch_size=args.batch_size,
        )
        logger.info(
            "Zeek ingestion complete (file=%s, sensor=%s, domain=%s): "
            "parsed %d/%d valid (%d skipped); persisted %d created, %d duplicate/matched in %d batch(es).",
            result.file_path,
            result.sensor_id,
            result.routing_domain_id,
            result.parse_summary.valid_records,
            result.parse_summary.total_raw_records,
            result.parse_summary.skipped_records,
            result.persistence_summary.created_count,
            result.persistence_summary.duplicate_matched_count,
            result.persistence_summary.batches_committed,
        )
        return 0
    except (
        EnvironmentError,
        FileNotFoundError,
        ValueError,
        MigrationRequiredError,
        ObservationConflictError,
    ) as exc:
        logger.error("Zeek ingestion failed: %s", exc)
        return 1
    except Exception as exc:
        logger.error("Unexpected error during Zeek ingestion: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
