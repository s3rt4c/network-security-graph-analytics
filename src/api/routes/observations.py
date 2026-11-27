"""
Read-only V2 observation triage listing and forensic detail route handlers for
Suricata AlertEvent and Zeek FlowObservation records.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from src.api.dependencies import (
    get_read_repository,
    validate_optional_routing_domain_id,
    validate_optional_sensor_id,
)
from src.api.models import (
    AlertEventDetailResponse,
    AlertEventTriageItemResponse,
    FlowObservationDetailResponse,
    SafePaginatedResponse,
)
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(prefix="/api/v1", tags=["Observations (V2)"])

_SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


@router.get("/alert-events", response_model=SafePaginatedResponse[AlertEventTriageItemResponse])
def list_v2_alert_events(
    routing_domain_id: Optional[str] = Query(
        default=None,
        description="Optional Layer 3 RoutingDomain filter (trimmed, case-insensitive)",
    ),
    severity: Optional[int] = Query(
        default=None,
        ge=0,
        le=_INT64_MAX,
        description="Optional exact recorded Suricata severity integer (not a universal risk score)",
    ),
    sid: Optional[int] = Query(
        default=None,
        ge=0,
        le=_INT64_MAX,
        description="Optional exact Suricata signature ID (SID)",
    ),
    sensor_id: Optional[str] = Query(
        default=None,
        description="Optional exact Suricata sensor identifier (trimmed, case-insensitive)",
    ),
    start_epoch_ns: Optional[int] = Query(
        default=None,
        ge=_INT64_MIN,
        le=_INT64_MAX,
        description=(
            "Optional inclusive lower bound on signed 64-bit timestamp_epoch_ns "
            "(when active, events with null timestamp_epoch_ns are excluded)"
        ),
    ),
    end_epoch_ns: Optional[int] = Query(
        default=None,
        ge=_INT64_MIN,
        le=_INT64_MAX,
        description=(
            "Optional inclusive upper bound on signed 64-bit timestamp_epoch_ns "
            "(when active, events with null timestamp_epoch_ns are excluded)"
        ),
    ),
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page (1..200)"),
    offset: int = Query(
        default=0,
        ge=0,
        le=_INT64_MAX,
        description="Offset starting index (0..9223372036854775807)",
    ),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> SafePaginatedResponse[AlertEventTriageItemResponse]:
    """List persisted V2 Suricata AlertEvent occurrences for independent triage (read-only)."""
    norm_domain = validate_optional_routing_domain_id(routing_domain_id)
    norm_sensor = validate_optional_sensor_id(sensor_id)

    if start_epoch_ns is not None and end_epoch_ns is not None and start_epoch_ns > end_epoch_ns:
        raise HTTPException(
            status_code=422,
            detail="Invalid time range: start_epoch_ns cannot be greater than end_epoch_ns",
        )

    items, total = repo.list_alert_events_for_triage(
        routing_domain_id=norm_domain,
        sensor_id=norm_sensor,
        sid=sid,
        severity=severity,
        start_epoch_ns=start_epoch_ns,
        end_epoch_ns=end_epoch_ns,
        source_type="suricata",
        limit=limit,
        offset=offset,
    )
    validated_items = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid AlertEvent triage record payload returned by read repository")
        validated_items.append(AlertEventTriageItemResponse(**item))

    return SafePaginatedResponse[AlertEventTriageItemResponse](
        items=validated_items,
        total=total,
        limit=limit,
        offset=offset,
    )


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
