"""
Cross-domain correlation route handlers.
"""

from typing import Literal, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from src.api.models import (
    AlertFlowCorrelationResponse,
    PaginatedResponse,
    TrafficAlertCorrelationResponse,
)
from src.api.dependencies import (
    get_correlation_repository,
    get_read_repository,
    validate_optional_routing_domain_id,
)
from src.graph.correlation_repository import Neo4jCorrelationRepository
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(prefix="/api/v1/correlations", tags=["Correlations"])

_SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"
_MAX_OFFSET = 2**63 - 1


def _validate_optional_routing_domain_id(routing_domain_id: Optional[str]) -> Optional[str]:
    """Delegate optional V2 routing_domain_id validation to shared dependency helper."""
    return validate_optional_routing_domain_id(routing_domain_id)


def _resolve_verification_filters(
    include_unverified: Optional[bool],
    verification_status: Optional[Literal["verified", "unverified_incomplete"]],
) -> Tuple[bool, Optional[str]]:
    """Resolve safe verification filter defaults and reject contradictory combinations."""
    if include_unverified is False and verification_status == "unverified_incomplete":
        raise HTTPException(
            status_code=422,
            detail=(
                "Conflicting query parameters: 'include_unverified=false' cannot be "
                "combined with 'verification_status=unverified_incomplete'"
            ),
        )
    if verification_status == "unverified_incomplete":
        return True, "unverified_incomplete"
    if verification_status == "verified":
        return (bool(include_unverified) if include_unverified is not None else False), "verified"
    effective_include_unverified = bool(include_unverified) if include_unverified is not None else False
    return effective_include_unverified, None


@router.get("/traffic-alerts", response_model=PaginatedResponse[TrafficAlertCorrelationResponse])
def list_traffic_alert_correlations(
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[TrafficAlertCorrelationResponse]:
    """Retrieve communicating IP pairs that also exhibit matching security alert facts."""
    items, total = repo.list_traffic_alert_correlations(limit=limit, offset=offset)
    return PaginatedResponse[TrafficAlertCorrelationResponse](
        items=[TrafficAlertCorrelationResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/alert-flows", response_model=PaginatedResponse[AlertFlowCorrelationResponse])
def list_alert_flow_correlations(
    routing_domain_id: Optional[str] = Query(
        default=None,
        description="Optional filter by Layer 3 RoutingDomain identifier",
    ),
    event_id: Optional[str] = Query(
        default=None,
        pattern=_SHA256_HEX_PATTERN,
        description="Optional filter by 64-character lowercase SHA-256 Suricata AlertEvent identifier",
    ),
    observation_id: Optional[str] = Query(
        default=None,
        pattern=_SHA256_HEX_PATTERN,
        description="Optional filter by 64-character lowercase SHA-256 Zeek FlowObservation identifier",
    ),
    include_unverified: Optional[bool] = Query(
        default=None,
        description=(
            "Include edges marked 'unverified_incomplete'. Defaults to false so only "
            "persisted 'verified' edges are returned unless explicitly requested."
        ),
    ),
    verification_status: Optional[Literal["verified", "unverified_incomplete"]] = Query(
        default=None,
        description="Optional exact filter on persisted verification_status ('verified' or 'unverified_incomplete')",
    ),
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(
        default=0,
        ge=0,
        le=_MAX_OFFSET,
        description="Offset starting index (0..9223372036854775807)",
    ),
    repo: Neo4jCorrelationRepository = Depends(get_correlation_repository),
) -> PaginatedResponse[AlertFlowCorrelationResponse]:
    """Retrieve persisted V2 Suricata AlertEvent to Zeek FlowObservation correlations (read-only)."""
    norm_domain = _validate_optional_routing_domain_id(routing_domain_id)
    effective_include_unverified, effective_status = _resolve_verification_filters(
        include_unverified,
        verification_status,
    )
    items, total = repo.list_alert_flow_correlations(
        routing_domain_id=norm_domain,
        event_id=event_id,
        observation_id=observation_id,
        include_unverified=effective_include_unverified,
        verification_status=effective_status,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse[AlertFlowCorrelationResponse](
        items=[AlertFlowCorrelationResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/alert-flows/{event_id}", response_model=PaginatedResponse[AlertFlowCorrelationResponse])
def get_alert_flow_correlations(
    event_id: str = Path(
        ...,
        pattern=_SHA256_HEX_PATTERN,
        description="64-character lowercase SHA-256 Suricata AlertEvent identifier",
    ),
    routing_domain_id: Optional[str] = Query(
        default=None,
        description="Optional Layer 3 RoutingDomain filter for tenant isolation",
    ),
    include_unverified: Optional[bool] = Query(
        default=None,
        description=(
            "Include edges marked 'unverified_incomplete'. Defaults to false so only "
            "persisted 'verified' edges are returned unless explicitly requested."
        ),
    ),
    verification_status: Optional[Literal["verified", "unverified_incomplete"]] = Query(
        default=None,
        description="Optional exact filter on persisted verification_status ('verified' or 'unverified_incomplete')",
    ),
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(
        default=0,
        ge=0,
        le=_MAX_OFFSET,
        description="Offset starting index (0..9223372036854775807)",
    ),
    repo: Neo4jCorrelationRepository = Depends(get_correlation_repository),
) -> PaginatedResponse[AlertFlowCorrelationResponse]:
    """Retrieve persisted V2 correlations for a specific Suricata AlertEvent (read-only)."""
    norm_domain = _validate_optional_routing_domain_id(routing_domain_id)
    effective_include_unverified, effective_status = _resolve_verification_filters(
        include_unverified,
        verification_status,
    )
    result = repo.get_alert_event_correlations(
        event_id,
        routing_domain_id=norm_domain,
        include_unverified=effective_include_unverified,
        verification_status=effective_status,
        limit=limit,
        offset=offset,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suricata AlertEvent '{event_id}' not found",
        )
    items, total = result
    return PaginatedResponse[AlertFlowCorrelationResponse](
        items=[AlertFlowCorrelationResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )
