"""
Read-only V2 observation forensic detail route handlers for Suricata AlertEvent
and Zeek FlowObservation records.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from src.api.dependencies import (
    get_read_repository,
    validate_optional_routing_domain_id,
)
from src.api.models import (
    AlertEventDetailResponse,
    FlowObservationDetailResponse,
)
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(prefix="/api/v1", tags=["Observations (V2)"])

_SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"


@router.get("/alert-events/{event_id}", response_model=AlertEventDetailResponse)
def get_alert_event_detail(
    event_id: str = Path(
        ...,
        pattern=_SHA256_HEX_PATTERN,
        description="64-character lowercase SHA-256 Suricata AlertEvent identifier",
    ),
    routing_domain_id: Optional[str] = Query(
        default=None,
        description="Optional Layer 3 RoutingDomain filter for domain-scoped lookup",
    ),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> AlertEventDetailResponse:
    """Retrieve persisted forensic details for a single V2 Suricata AlertEvent (read-only)."""
    norm_domain = validate_optional_routing_domain_id(routing_domain_id)
    record = repo.get_alert_event(
        event_id,
        routing_domain_id=norm_domain,
        source_type="suricata",
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suricata AlertEvent '{event_id}' not found",
        )
    if not isinstance(record, dict):
        raise ValueError("Invalid AlertEvent record payload returned by read repository")

    payload = {
        field: record[field]
        for field in AlertEventDetailResponse.model_fields
        if field in record
    }
    return AlertEventDetailResponse(**payload)


@router.get("/flow-observations/{observation_id}", response_model=FlowObservationDetailResponse)
def get_flow_observation_detail(
    observation_id: str = Path(
        ...,
        pattern=_SHA256_HEX_PATTERN,
        description="64-character lowercase SHA-256 Zeek FlowObservation identifier",
    ),
    routing_domain_id: Optional[str] = Query(
        default=None,
        description="Optional Layer 3 RoutingDomain filter for domain-scoped lookup",
    ),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> FlowObservationDetailResponse:
    """Retrieve persisted forensic details for a single V2 Zeek FlowObservation (read-only)."""
    norm_domain = validate_optional_routing_domain_id(routing_domain_id)
    record = repo.get_flow_observation(
        observation_id,
        routing_domain_id=norm_domain,
        source_type="zeek",
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zeek FlowObservation '{observation_id}' not found",
        )
    if not isinstance(record, dict):
        raise ValueError("Invalid FlowObservation record payload returned by read repository")

    payload = {
        field: record[field]
        for field in FlowObservationDetailResponse.model_fields
        if field in record
    }
    return FlowObservationDetailResponse(**payload)
