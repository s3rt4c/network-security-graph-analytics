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


# ---------------------------------------------------------------------------
# Regression Tests: Domain Validation/Normalization, Sort Compatibility,
# Protocol Normalization, and Cross-Domain Read Isolation
# ---------------------------------------------------------------------------
def test_api_domain_validation_rejects_hash_with_422_and_normalizes_case(client_with_mock_repo):
    """Verify '#' in domain query param returns HTTP 422 (not 500) and mixed-case domain normalizes to lowercase."""
    client, mock_repo = client_with_mock_repo

    # All domain-accepting routes must return 422 for domain containing '#'
    assert client.get("/api/v1/network/ips?domain=bad%23domain").status_code == 422
    assert client.get("/api/v1/network/ips/10.0.0.5?domain=bad%23domain").status_code == 422
    assert client.get("/api/v1/network/ips/10.0.0.5/peers?domain=bad%23domain").status_code == 422
    assert client.get("/api/v1/network/ips/10.0.0.5/layer2?domain=bad%23domain").status_code == 422
    assert client.get("/api/v1/graph/neighborhood/10.0.0.5?domain=bad%23domain").status_code == 422
    assert client.get("/api/v1/graph/path?source=10.0.0.5&target=10.0.0.6&source_domain=bad%23domain").status_code == 422
    assert client.get("/api/v1/graph/path?source=10.0.0.5&target=10.0.0.6&target_domain=bad%23domain").status_code == 422

    # Mixed-case padded domain normalizes to lowercase before reaching repository
    mock_repo.list_ips.return_value = ([], 0)
    res_case = client.get("/api/v1/network/ips?domain=%20CORP%20")
    assert res_case.status_code == 200
    mock_repo.list_ips.assert_called_once_with(limit=50, offset=0, domain="corp")

    # Whitespace-only domain is treated as omitted (not silently mapped to 'default')
    mock_repo.list_ips.reset_mock()
    res_ws = client.get("/api/v1/network/ips?domain=%20%20")
    assert res_ws.status_code == 200
    mock_repo.list_ips.assert_called_once_with(limit=50, offset=0)


def test_api_endpoints_analytics_received_sort_options_v1_compat(client_with_mock_repo):
    """Verify V1/frontend sort_by options observed_bytes_received and observed_packets_received return 200 OK."""
    client, mock_repo = client_with_mock_repo
    mock_repo.get_endpoints_analytics.return_value = ([], 0)

    for sort_key in ("observed_bytes_received", "observed_packets_received"):
        mock_repo.get_endpoints_analytics.reset_mock()
        res = client.get(f"/api/v1/network/analytics/endpoints?sort_by={sort_key}")
        assert res.status_code == 200
        mock_repo.get_endpoints_analytics.assert_called_once_with(sort_by=sort_key, limit=50, offset=0)


def test_read_repo_protocol_normalization_and_param_order():
    """Verify list_communications and list_alert_facts normalize protocol case/whitespace and keep V1 param order."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jReadRepository(mock_driver)

    # list_communications normalizes lowercase/padded protocol
    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 0}
    mock_tx.run.side_effect = [mock_count, []]
    repo.list_communications(protocol="  tcp  ")
    assert mock_tx.run.call_args_list[0].kwargs["protocol"] == "TCP"

    # list_communications treats whitespace-only protocol as omitted
    mock_tx.run.reset_mock()
    mock_tx.run.side_effect = [mock_count, []]
    repo.list_communications(protocol="   ")
    assert "protocol" not in mock_tx.run.call_args_list[0].kwargs

    # list_alert_facts preserves V1 positional signature (source_ip, target_ip, priority, sid, protocol)
    mock_tx.run.reset_mock()
    mock_tx.run.side_effect = [mock_count, []]
    repo.list_alert_facts("10.0.0.1", "10.0.0.2", 1, 2001, "  udp ")
    count_kwargs = mock_tx.run.call_args_list[0].kwargs
    page_cypher = mock_tx.run.call_args_list[1].args[0]
    assert count_kwargs["priority"] == 1
    assert count_kwargs["sid"] == 2001
    assert count_kwargs["protocol"] == "UDP"
    assert "CASE WHEN fact.priority IS NULL THEN 1 ELSE 0 END" in page_cypher


def test_read_repo_cross_domain_cypher_guards():
    """Verify Cypher queries enforce per-node fan-out/fan-in grouping, domain normalization, and depth-2 isolation."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jReadRepository(mock_driver)

    # 1. list_ips normalizes domain filter to lowercase
    mock_count = MagicMock()
    mock_count.single.return_value = {"total": 0}
    mock_tx.run.side_effect = [mock_count, []]
    repo.list_ips(domain="  CORP  ")
    assert mock_tx.run.call_args_list[0].kwargs["domain"] == "corp"

    # 2. get_endpoints_analytics supports observed_bytes_received / observed_packets_received & normalizes domain
    mock_tx.run.reset_mock()
    mock_tx.run.side_effect = [mock_count, []]
    repo.get_endpoints_analytics(sort_by="observed_bytes_received", domain="  BRANCH ")
    assert mock_tx.run.call_args_list[0].kwargs["domain"] == "branch"
    assert "observed_bytes_received DESC" in mock_tx.run.call_args_list[1].args[0]

    # 3. get_traffic_analytics_summary groups top_fan_out / top_fan_in per node (WITH src / WITH dst)
    mock_tx.run.reset_mock()
    mock_summary = MagicMock()
    mock_summary.single.return_value = {
        "total_aggs": 1,
        "enriched_aggs": 1,
        "total_pkts": 5,
        "total_bytes": 500,
        "first_obs": 1.0,
        "last_obs": 2.0,
    }
    mock_tx.run.side_effect = [mock_summary, [], [], [], []]
    repo.get_traffic_analytics_summary()
    proto_query = mock_tx.run.call_args_list[1].args[0]
    fan_out_query = mock_tx.run.call_args_list[3].args[0]
    fan_in_query = mock_tx.run.call_args_list[4].args[0]
    assert "c.observed_window_seconds IS NOT NULL" in proto_query
    assert "WITH src, count(DISTINCT dst)" in fan_out_query
    assert "WITH dst, count(DISTINCT src)" in fan_in_query

    # 4. get_neighborhood(depth=2) restricts IPAddress traversal to center's routing domain
    mock_tx.run.reset_mock()
    mock_resolve = MagicMock()
    mock_resolve.single.return_value = {
        "scoped_id": "corp#10.0.0.5",
        "address": "10.0.0.5",
        "domain_id": "corp",
    }
    mock_nh_res = MagicMock()
    mock_nh_res.single.return_value = {"center": "10.0.0.5", "paths": []}
    mock_tx.run.side_effect = [mock_resolve, mock_nh_res]
    repo.get_neighborhood("10.0.0.5", depth=2, domain="corp")
    depth2_query = mock_tx.run.call_args_list[1].args[0]
    assert "n.routing_domain_id = center.routing_domain_id" in depth2_query
