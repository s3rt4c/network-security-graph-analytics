"""
Network Traffic Analysis — Main Application Orchestrator

Processes network traffic data (tshark TSV export) and IDS/Snort alert data
(JSON), then loads the results into a Neo4j graph database using the V2
scoped graph schema (RoutingDomain, IPAddress, Layer2Identifier, AlertFact).

Originally developed during a cybersecurity internship (September 2024).
Modernized with a pandas-based ingestion pipeline, batched UNWIND persistence,
scoped IP identity support, and idempotent graph schema management.

SECURITY NOTE:
    Historical commits in this repository contain hardcoded credentials.
    Those credentials should be considered compromised and must NOT be
    reused in any environment. All configuration is now loaded from
    environment variables — see .env.example.
"""

import sys
import logging
from neo4j import GraphDatabase

from src.config import (
    get_neo4j_config,
    get_ingestion_config,
    APP_NAME,
)
from src.ingestion import (
    parse_traffic_file,
    parse_alert_file,
)
from src.graph import (
    ensure_schema,
    migrate_ip_identity_to_scoped,
    MigrationRequiredError,
    Neo4jRepository,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(APP_NAME)


# ---------------------------------------------------------------------------
# Main entry point (Orchestration only)
# ---------------------------------------------------------------------------
def main():
    """Run the complete pipeline: parse data -> ensure schema -> persist to Neo4j."""
    logger.info("=" * 60)
    logger.info("Starting %s", APP_NAME)
    logger.info("=" * 60)

    driver = None

    try:
        # --- Standalone Migration CLI Support ---
        if "--migrate" in sys.argv:
            logger.info("Explicit --migrate flag detected. Executing V1 to V2 IP identity migration...")
            neo4j_cfg = get_neo4j_config()
            driver = GraphDatabase.driver(
                neo4j_cfg["uri"],
                auth=(neo4j_cfg["username"], neo4j_cfg["password"]),
            )
            driver.verify_connectivity()
            stats = migrate_ip_identity_to_scoped(driver)
            logger.info(
                "Migration complete: %d legacy IP nodes migrated to default domain (total=%d).",
                stats["migrated_ips"],
                stats["total_ips"],
            )
            return

        # --- 1. Ingestion: Retrieve Ingestion Configuration & Parse Data ---
        ingestion_cfg = get_ingestion_config()
        traffic_records, traffic_summary = parse_traffic_file(ingestion_cfg["traffic_csv_path"])
        logger.info(
            "Traffic Ingestion: %d raw -> %d valid unique (%d skipped, %d duplicates)",
            traffic_summary.total_raw_records,
            traffic_summary.valid_records,
            traffic_summary.skipped_records,
            traffic_summary.duplicate_records,
        )

        alert_records, alert_summary = parse_alert_file(ingestion_cfg["alerts_json_path"])
        logger.info(
            "Alert Ingestion: %d raw -> %d valid (%d skipped)",
            alert_summary.total_raw_records,
            alert_summary.valid_records,
            alert_summary.skipped_records,
        )

        # --- 2. Connect to Neo4j (Driver Lifecycle Managed by main) ---
        neo4j_cfg = get_neo4j_config()
        logger.info("Connecting to Neo4j at %s ...", neo4j_cfg["uri"])
        driver = GraphDatabase.driver(
            neo4j_cfg["uri"],
            auth=(neo4j_cfg["username"], neo4j_cfg["password"]),
        )
        driver.verify_connectivity()
        logger.info("Neo4j connection established.")

        # --- 3. Apply Schema Constraints & Indexes (Safe Migration Check) ---
        try:
            ensure_schema(driver)
        except MigrationRequiredError as exc:
            logger.warning(
                "Legacy V1 database detected (%d unmigrated IP nodes). Executing controlled migration before writes...",
                exc.unmigrated_count,
            )
            mig_stats = migrate_ip_identity_to_scoped(driver)
            logger.info(
                "Migration complete: %d legacy IP nodes migrated to default domain (total=%d).",
                mig_stats["migrated_ips"],
                mig_stats["total_ips"],
            )

        # --- 4. Persist to Neo4j via Repository ---
        repo = Neo4jRepository(driver)
        persisted_traffic = repo.write_traffic_records(traffic_records, domain_id="default")
        persisted_alerts = repo.write_alert_records(alert_records, domain_id="default")

        logger.info("=" * 60)
        logger.info(
            "All data ingested successfully: %d traffic records, %d alert facts persisted.",
            persisted_traffic,
            persisted_alerts,
        )
        logger.info("=" * 60)

    except EnvironmentError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)
    except FileNotFoundError as exc:
        logger.error("Data file not found: %s", exc)
        sys.exit(1)
    except ValueError as exc:
        logger.error("Data format / parsing error: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error during execution: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        # Resource cleanup
        if driver is not None:
            driver.close()
            logger.info("Neo4j connection closed.")


if __name__ == "__main__":
    main()
