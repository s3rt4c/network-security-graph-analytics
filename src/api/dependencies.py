"""
FastAPI dependency injection and lifecycle management.
"""

import ipaddress
import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from neo4j import GraphDatabase, Driver

from src.config import get_optional_neo4j_config
from src.graph.correlation_repository import Neo4jCorrelationRepository
from src.graph.read_repository import Neo4jReadRepository
from src.graph.repository import Neo4jRepository

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan: initialize and close shared Neo4j driver."""
    driver: Optional[Driver] = None
    cfg = get_optional_neo4j_config()

    if cfg is not None:
        try:
            logger.info("Initializing Neo4j driver for API at %s", cfg["uri"])
            driver = GraphDatabase.driver(cfg["uri"], auth=(cfg["username"], cfg["password"]))
        except Exception as exc:
            logger.warning("Could not initialize Neo4j driver during startup: %s", exc)
            driver = None
    else:
        logger.info("Neo4j configuration not fully provided; running without active database connection.")

    app.state.driver = driver
    yield

    if getattr(app.state, "driver", None) is not None:
        try:
            logger.info("Closing shared Neo4j driver...")
            app.state.driver.close()
        except Exception as exc:
            logger.warning("Error closing Neo4j driver on shutdown: %s", exc)


def get_read_repository(request: Request) -> Neo4jReadRepository:
    """Provide a Neo4jReadRepository initialized with the shared driver from app state."""
    driver = getattr(request.app.state, "driver", None)
    return Neo4jReadRepository(driver)


def get_correlation_repository(request: Request) -> Neo4jCorrelationRepository:
    """Provide a Neo4jCorrelationRepository initialized with the shared driver from app state."""
    driver = getattr(request.app.state, "driver", None)
    return Neo4jCorrelationRepository(driver)


def get_write_repository(request: Request) -> Neo4jRepository:
    """Provide a Neo4jRepository initialized with the shared driver from app state.

    Raises:
        HTTPException (503): If the shared database driver is unavailable.
    """
    driver = getattr(request.app.state, "driver", None)
    if driver is None:
        raise HTTPException(
            status_code=503,
            detail="Database service unavailable",
        )
    return Neo4jRepository(driver)


def validate_canonical_ip(ip_str: str) -> str:
    """Validate IPv4 or IPv6 address format and return its canonical string representation.
    
    Raises:
        HTTPException (422): If ip_str is not a valid IP address.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise HTTPException(
            status_code=422,
            detail="IP address string must not be empty",
        )
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address format: '{ip_str}'",
        )


def validate_routing_domain(domain: Optional[str]) -> Optional[str]:
    """Normalize and validate an optional routing domain query parameter.

    Returns None when omitted or whitespace-only, or the trimmed lowercase domain ID.

    Raises:
        HTTPException (422): If domain contains the reserved '#' scoped-ID delimiter.
    """
    if domain is None:
        return None
    normalized = domain.strip().lower()
    if not normalized:
        return None
    if "#" in normalized:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid routing domain format (cannot contain '#'): '{domain}'",
        )
    return normalized


def validate_optional_routing_domain_id(routing_domain_id: Optional[str]) -> Optional[str]:
    """Validate an optional V2 routing_domain_id filter, failing closed on explicit blank values."""
    if routing_domain_id is None:
        return None
    if not routing_domain_id.strip():
        raise HTTPException(
            status_code=422,
            detail="Invalid routing_domain_id: must not be empty when specified",
        )
    return validate_routing_domain(routing_domain_id)


def validate_optional_sensor_id(sensor_id: Optional[str]) -> Optional[str]:
    """Validate an optional V2 sensor_id filter, failing closed on explicit blank values."""
    if sensor_id is None:
        return None
    normalized = sensor_id.strip().lower()
    if not normalized:
        raise HTTPException(
            status_code=422,
            detail="Invalid sensor_id: must not be empty when specified",
        )
    return normalized
