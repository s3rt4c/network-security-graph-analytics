"""
Unit and API integration tests for read query endpoint resolution and ambiguity semantics.
"""

from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from src.graph.read_repository import Neo4jReadRepository, AmbiguousEndpointError
from src.api.app import create_app
from src.api.dependencies import get_read_repository


# ---------------------------------------------------------------------------
# Endpoint Resolution Policy Unit Tests
# ---------------------------------------------------------------------------
def test_resolve_endpoint_by_scoped_id():
    """Rule A: When scoped_id is supplied, deterministic lookup by scoped_id is executed."""
    mock_tx = MagicMock()
    mock_res = MagicMock()
    mock_res.single.return_value = {
        "scoped_id": "corp#10.0.0.5",
        "address": "10.0.0.5",
        "domain_id": "corp",
    }
    mock_tx.run.return_value = mock_res

    s, a, d = Neo4jReadRepository._resolve_endpoint(mock_tx, address="10.0.0.5", scoped_id="corp#10.0.0.5")
    assert s == "corp#10.0.0.5"
    assert a == "10.0.0.5"
    assert d == "corp"


def test_resolve_endpoint_by_domain_and_address():
    """Rule B: When address and domain are supplied, deterministic lookup is executed."""
    mock_tx = MagicMock()
    mock_res = MagicMock()
    mock_res.single.return_value = {
        "scoped_id": "branch#10.0.0.5",
        "address": "10.0.0.5",
        "domain_id": "branch",
    }
    mock_tx.run.return_value = mock_res

    s, a, d = Neo4jReadRepository._resolve_endpoint(mock_tx, address="10.0.0.5", domain="branch")
    assert s == "branch#10.0.0.5"
    assert a == "10.0.0.5"
    assert d == "branch"


def test_resolve_endpoint_address_single_match():
    """Rule C: When address only is supplied and exactly one matching node exists, it is returned."""
    mock_tx = MagicMock()
    mock_res = MagicMock()
    mock_res.single.return_value = {
        "c": 1,
        "matching_scoped_ids": ["default#192.168.1.10"],
        "matching_domains": ["default"],
    }
    mock_tx.run.return_value = mock_res

    s, a, d = Neo4jReadRepository._resolve_endpoint(mock_tx, address="192.168.1.10")
    assert s == "default#192.168.1.10"
    assert a == "192.168.1.10"
    assert d == "default"


def test_resolve_endpoint_address_ambiguous_raises():
    """Rule D: When address only is supplied and multiple IP nodes match across domains, raise AmbiguousEndpointError."""
    mock_tx = MagicMock()
    mock_res = MagicMock()
    mock_res.single.return_value = {
        "c": 2,
        "matching_scoped_ids": ["corp#10.0.0.5", "branch#10.0.0.5"],
        "matching_domains": ["corp", "branch"],
    }
    mock_tx.run.return_value = mock_res

    with pytest.raises(AmbiguousEndpointError) as exc_info:
        Neo4jReadRepository._resolve_endpoint(mock_tx, address="10.0.0.5")

    err = exc_info.value
    assert err.address == "10.0.0.5"
    assert "corp" in err.matching_domains
    assert "branch" in err.matching_domains
    assert "Specify 'domain' or 'scoped_id' to disambiguate" in str(err)


def test_resolve_endpoint_not_found():
    """When address does not exist in graph, return (None, None, None)."""
    mock_tx = MagicMock()
    mock_res = MagicMock()
    mock_res.single.return_value = {"c": 0, "matching_scoped_ids": [], "matching_domains": []}
    mock_tx.run.return_value = mock_res

    s, a, d = Neo4jReadRepository._resolve_endpoint(mock_tx, address="10.0.0.99")
    assert s is None
    assert a is None
    assert d is None


# ---------------------------------------------------------------------------
# API Route Ambiguity & Disambiguation Tests
# ---------------------------------------------------------------------------
@pytest.fixture
def client_with_mock_repo():
    """Create test client with mocked read repository."""
    app = create_app()
    mock_repo = MagicMock()
    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)
    return client, mock_repo


def test_api_get_ip_detail_ambiguous_returns_409(client_with_mock_repo):
    """GET /api/v1/network/ips/{address} without domain returns 409 Conflict when ambiguous."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_ip_detail.side_effect = AmbiguousEndpointError("10.0.0.5", ["corp", "branch"], ["corp#10.0.0.5", "branch#10.0.0.5"])

    response = client.get("/api/v1/network/ips/10.0.0.5")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "AMBIGUOUS_ENDPOINT"
    assert detail["address"] == "10.0.0.5"
    assert "corp" in detail["matching_domains"]
    assert "branch" in detail["matching_domains"]


def test_api_get_ip_detail_domain_disambiguated_returns_200(client_with_mock_repo):
    """GET /api/v1/network/ips/{address}?domain=corp returns 200 OK and disambiguated details."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_ip_detail.return_value = {
        "address": "10.0.0.5",
        "scoped_id": "corp#10.0.0.5",
        "routing_domain_id": "corp",
        "layer2_identifiers": [],
        "outbound_flows": 2,
        "inbound_flows": 1,
        "alerts_originated": 0,
        "alerts_targeted": 0,
        "traffic_metrics_mode": "basic",
        "distinct_outbound_peers": 2,
        "distinct_inbound_peers": 1,
        "distinct_destination_ports": 2,
    }

    response = client.get("/api/v1/network/ips/10.0.0.5?domain=corp")
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == "10.0.0.5"
    assert data["scoped_id"] == "corp#10.0.0.5"
    assert data["routing_domain_id"] == "corp"
    mock_repo.get_ip_detail.assert_called_once_with("10.0.0.5", domain="corp")


def test_api_list_ip_peers_ambiguous_returns_409(client_with_mock_repo):
    """GET /api/v1/network/ips/{address}/peers without domain returns 409 Conflict when ambiguous."""
    client, mock_repo = client_with_mock_repo
    mock_repo.list_ip_peers.side_effect = AmbiguousEndpointError("10.0.0.5", ["corp", "branch"], ["corp#10.0.0.5", "branch#10.0.0.5"])

    response = client.get("/api/v1/network/ips/10.0.0.5/peers")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "AMBIGUOUS_ENDPOINT"
    assert detail["address"] == "10.0.0.5"


def test_api_list_ip_peers_disambiguated(client_with_mock_repo):
    """GET /api/v1/network/ips/{address}/peers?domain=corp returns 200 OK."""
    client, mock_repo = client_with_mock_repo
    mock_repo.list_ip_peers.return_value = (
        [{"peer_address": "10.0.0.20", "direction": "outbound", "protocols": ["TCP"]}],
        1,
    )

    response = client.get("/api/v1/network/ips/10.0.0.5/peers?domain=corp")
    assert response.status_code == 200
    mock_repo.list_ip_peers.assert_called_once_with("10.0.0.5", direction="all", limit=50, offset=0, domain="corp")


def test_api_list_ip_layer2_ambiguous_returns_409(client_with_mock_repo):
    """GET /api/v1/network/ips/{address}/layer2 without domain returns 409 Conflict when ambiguous."""
    client, mock_repo = client_with_mock_repo
    mock_repo.list_ip_layer2.side_effect = AmbiguousEndpointError("10.0.0.5", ["corp", "branch"], ["corp#10.0.0.5", "branch#10.0.0.5"])

    response = client.get("/api/v1/network/ips/10.0.0.5/layer2")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "AMBIGUOUS_ENDPOINT"
    assert detail["address"] == "10.0.0.5"


def test_api_list_ip_layer2_disambiguated(client_with_mock_repo):
    """GET /api/v1/network/ips/{address}/layer2?domain=corp returns 200 OK."""
    client, mock_repo = client_with_mock_repo
    mock_repo.list_ip_layer2.return_value = ([{"identifier": "02:00:00:00:00:01"}], 1)

    response = client.get("/api/v1/network/ips/10.0.0.5/layer2?domain=corp")
    assert response.status_code == 200
    mock_repo.list_ip_layer2.assert_called_once_with("10.0.0.5", limit=50, offset=0, domain="corp")


def test_api_neighborhood_ambiguous_returns_409(client_with_mock_repo):
    """GET /api/v1/graph/neighborhood/{address} without domain returns 409 Conflict when ambiguous."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_neighborhood.side_effect = AmbiguousEndpointError("10.0.0.5", ["corp", "branch"], ["corp#10.0.0.5", "branch#10.0.0.5"])

    response = client.get("/api/v1/graph/neighborhood/10.0.0.5")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "AMBIGUOUS_ENDPOINT"
    assert detail["address"] == "10.0.0.5"


def test_api_neighborhood_disambiguated(client_with_mock_repo):
    """GET /api/v1/graph/neighborhood/{address}?domain=branch returns 200 OK."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_neighborhood.return_value = {
        "center": "10.0.0.5",
        "depth": 1,
        "nodes": [{"id": "ip:branch#10.0.0.5", "type": "IPAddress", "value": "10.0.0.5"}],
        "edges": [],
    }

    response = client.get("/api/v1/graph/neighborhood/10.0.0.5?domain=branch")
    assert response.status_code == 200
    mock_repo.get_neighborhood.assert_called_once_with("10.0.0.5", depth=1, max_nodes=50, domain="branch")


def test_api_shortest_path_ambiguous_source_returns_409(client_with_mock_repo):
    """GET /api/v1/graph/path returns 409 Conflict when source or target is ambiguous."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_shortest_path.side_effect = AmbiguousEndpointError("10.0.0.5", ["corp", "branch"], ["corp#10.0.0.5", "branch#10.0.0.5"])

    response = client.get("/api/v1/graph/path?source=10.0.0.5&target=10.0.0.6")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "AMBIGUOUS_ENDPOINT"
    assert detail["address"] == "10.0.0.5"


def test_api_shortest_path_disambiguated(client_with_mock_repo):
    """GET /api/v1/graph/path with source_domain and target_domain returns 200 OK."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_shortest_path.return_value = {
        "source": "10.0.0.5",
        "target": "10.0.0.6",
        "hops": ["10.0.0.5", "10.0.0.6"],
        "protocols": ["TCP"],
        "length": 1,
    }

    response = client.get("/api/v1/graph/path?source=10.0.0.5&target=10.0.0.6&source_domain=corp&target_domain=corp")
    assert response.status_code == 200
    data = response.json()
    assert data["length"] == 1
    mock_repo.get_shortest_path.assert_called_once_with(
        "10.0.0.5", "10.0.0.6", max_hops=5, source_domain="corp", target_domain="corp"
    )
