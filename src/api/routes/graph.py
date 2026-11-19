"""
Graph traversal and reachability route handlers.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status

from src.api.models import GraphNeighborhoodResponse, PathResponse
from src.api.dependencies import get_read_repository, validate_canonical_ip
from src.graph.read_repository import Neo4jReadRepository, AmbiguousEndpointError

router = APIRouter(prefix="/api/v1/graph", tags=["Graph"])


@router.get("/neighborhood/{address}", response_model=GraphNeighborhoodResponse)
def get_graph_neighborhood(
    address: str,
    domain: Optional[str] = Query(default=None, description="Optional routing domain for disambiguation"),
    depth: int = Query(default=1, ge=1, le=2, description="Traversal depth (1 or 2 hops)"),
    max_nodes: int = Query(default=50, ge=1, le=100, description="Max unique nodes to return"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> GraphNeighborhoodResponse:
    """Retrieve a bounded local graph neighborhood (depth 1 or 2) around an IP address."""
    canonical_address = validate_canonical_ip(address)
    try:
        result = (
            repo.get_neighborhood(canonical_address, depth=depth, max_nodes=max_nodes, domain=domain)
            if domain is not None
            else repo.get_neighborhood(canonical_address, depth=depth, max_nodes=max_nodes)
        )
    except AmbiguousEndpointError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "AMBIGUOUS_ENDPOINT",
                "message": str(err),
                "address": err.address,
                "matching_domains": sorted(err.matching_domains),
            },
        )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{canonical_address}' not found in graph",
        )
    return GraphNeighborhoodResponse(**result)


@router.get("/path", response_model=PathResponse)
def get_shortest_path(
    source: str = Query(..., description="Origin IP address"),
    target: str = Query(..., description="Destination IP address"),
    source_domain: Optional[str] = Query(default=None, description="Optional source routing domain for disambiguation"),
    target_domain: Optional[str] = Query(default=None, description="Optional target routing domain for disambiguation"),
    max_hops: int = Query(default=5, ge=1, le=10, description="Max search depth in hops"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PathResponse:
    """Find the shortest directional Layer 3 communication path between two IP addresses."""
    can_src = validate_canonical_ip(source)
    can_dst = validate_canonical_ip(target)

    try:
        if source_domain is not None or target_domain is not None:
            result = repo.get_shortest_path(
                can_src,
                can_dst,
                max_hops=max_hops,
                source_domain=source_domain,
                target_domain=target_domain,
            )
        else:
            result = repo.get_shortest_path(can_src, can_dst, max_hops=max_hops)
    except AmbiguousEndpointError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "AMBIGUOUS_ENDPOINT",
                "message": str(err),
                "address": err.address,
                "matching_domains": sorted(err.matching_domains),
            },
        )

    err = result.get("error")

    if err == "source_not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source IP '{can_src}' not found in graph",
        )
    if err == "target_not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target IP '{can_dst}' not found in graph",
        )
    if err == "no_path":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No communication path found between '{can_src}' and '{can_dst}' within {max_hops} hops",
        )

    return PathResponse(**result)
