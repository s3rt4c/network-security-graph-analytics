"""
Unit tests for cross-domain correlation API endpoints (V1 and V2 Phase 4C).
"""

import re
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from neo4j.exceptions import AuthError, ServiceUnavailable
from pydantic import ValidationError
import pytest

from src.api.app import create_app
from src.api.dependencies import get_correlation_repository, get_read_repository
from src.api.models import AlertFlowCorrelationResponse
from src.graph.correlation_repository import (
    CYPHER_CHECK_SURICATA_ALERT_EVENT_EXISTS,
    CYPHER_COUNT_ALERT_FLOW_CORRELATIONS,
    CYPHER_LIST_ALERT_FLOW_CORRELATIONS,
    Neo4jCorrelationRepository,
)


_EVENT_ID_1 = "a" * 64
_EVENT_ID_2 = "b" * 64
_OBS_ID_1 = "1" * 64
_OBS_ID_2 = "2" * 64
_POLICY_FP = "c" * 64
_EVIDENCE_DIGEST = "d" * 64


def _sample_v2_row(**overrides):
    base = {
        "event_id": _EVENT_ID_1,
        "observation_id": _OBS_ID_1,
        "zeek_uid": "CZ_API_001",
        "routing_domain_id": "corp",
        "correlation_method": "cid_verified_5tuple_temporal",
        "evidence_version": "v1",
        "policy_fingerprint": _POLICY_FP,
        "evidence_digest": _EVIDENCE_DIGEST,
        "tuple_orientation": "FORWARD",
        "community_id_agreement": "MATCH",
        "temporal_relation": "WITHIN_INTERVAL",
        "temporal_delta_decimal": "0.000000123456789012345678901234",
        "used_decimal_fallback": False,
        "sensor_context": "ALLOWED_ANY_IN_DOMAIN:suricata-01->zeek-01",
        "verification_status": "verified",
        "last_incomplete_reason": None,
        "last_incomplete_at_utc": None,
        "decided_at_utc": "2026-11-22T12:00:00Z",
    }
    base.update(overrides)
    return base


def test_list_traffic_alert_correlations_success():
    """Verify GET /api/v1/correlations/traffic-alerts returns flat paginated records."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_traffic_alert_correlations.return_value = (
        [
            {
                "source_ip": "192.168.1.10",
                "target_ip": "192.168.1.20",
                "traffic_protocol": "TCP",
                "traffic_flow_key": "f" * 64,
                "traffic_src_port": 50000,
                "traffic_dst_port": 80,
                "fact_key": "c" * 64,
                "sid": 2100498,
                "message": "GPL ATTACK_RESPONSE id check returned root",
                "priority": 1,
                "alert_protocol": "TCP",
            }
        ],
        1,
    )

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/api/v1/correlations/traffic-alerts?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["source_ip"] == "192.168.1.10"
    assert data["items"][0]["target_ip"] == "192.168.1.20"
    assert data["items"][0]["traffic_protocol"] == "TCP"
    assert data["items"][0]["traffic_flow_key"] == "f" * 64
    assert data["items"][0]["traffic_src_port"] == 50000
    assert data["items"][0]["traffic_dst_port"] == 80
    assert data["items"][0]["fact_key"] == "c" * 64
    assert data["items"][0]["priority"] == 1


def test_correlation_route_not_captured_by_alerts_fact_key():
    """Verify /api/v1/correlations/traffic-alerts is not routed to /api/v1/alerts/{fact_key}."""
    app = create_app()
    mock_repo = MagicMock()
    mock_repo.list_traffic_alert_correlations.return_value = ([], 0)

    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    client = TestClient(app)

    response = client.get("/api/v1/correlations/traffic-alerts")
    assert response.status_code == 200
    mock_repo.list_traffic_alert_correlations.assert_called_once()
    mock_repo.get_alert_fact.assert_not_called()


def _v2_client():
    app = create_app()
    mock_corr_repo = MagicMock(spec=Neo4jCorrelationRepository)
    app.dependency_overrides[get_correlation_repository] = lambda: mock_corr_repo
    return app, TestClient(app), mock_corr_repo


def test_a_c_list_alert_flows_verified_default_and_response_schema():
    """Verify GET /api/v1/correlations/alert-flows defaults to verified-only and returns typed evidence."""
    _, client, mock_repo = _v2_client()
    row = _sample_v2_row()
    mock_repo.list_alert_flow_correlations.return_value = ([row], 1)

    response = client.get("/api/v1/correlations/alert-flows")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["limit"] == 50
    assert data["offset"] == 0
    assert len(data["items"]) == 1

    item = data["items"][0]
    assert item["event_id"] == _EVENT_ID_1
    assert item["observation_id"] == _OBS_ID_1
    assert item["zeek_uid"] == "CZ_API_001"
    assert item["routing_domain_id"] == "corp"
    assert item["correlation_method"] == "cid_verified_5tuple_temporal"
    assert item["evidence_version"] == "v1"
    assert item["policy_fingerprint"] == _POLICY_FP
    assert item["evidence_digest"] == _EVIDENCE_DIGEST
    assert item["tuple_orientation"] == "FORWARD"
    assert item["community_id_agreement"] == "MATCH"
    assert item["temporal_relation"] == "WITHIN_INTERVAL"
    assert item["temporal_delta_decimal"] == "0.000000123456789012345678901234"
    assert isinstance(item["temporal_delta_decimal"], str)
    assert item["used_decimal_fallback"] is False
    assert item["sensor_context"] == "ALLOWED_ANY_IN_DOMAIN:suricata-01->zeek-01"
    assert item["verification_status"] == "verified"
    assert item["last_incomplete_reason"] is None
    assert item["last_incomplete_at_utc"] is None
    assert item["decided_at_utc"] == "2026-11-22T12:00:00Z"
    assert "elementId" not in item
    assert "rel_id" not in item
    assert "reasons" not in item
    assert "confidence" not in item

    mock_repo.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id=None,
        event_id=None,
        observation_id=None,
        include_unverified=False,
        verification_status=None,
        limit=50,
        offset=0,
    )

    mock_repo.list_alert_flow_correlations.reset_mock()
    r_explicit_false = client.get("/api/v1/correlations/alert-flows?include_unverified=false")
    assert r_explicit_false.status_code == 200
    mock_repo.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id=None,
        event_id=None,
        observation_id=None,
        include_unverified=False,
        verification_status=None,
        limit=50,
        offset=0,
    )


def test_b_d_include_unverified_and_verification_status_filtering():
    """Verify explicit include_unverified=true and verification_status filters expose unverified metadata."""
    _, client, mock_repo = _v2_client()
    verified_row = _sample_v2_row()
    unverified_row = _sample_v2_row(
        event_id=_EVENT_ID_2,
        observation_id=_OBS_ID_2,
        verification_status="unverified_incomplete",
        last_incomplete_reason="CANDIDATE_SET_TRUNCATED",
        last_incomplete_at_utc="2026-11-22T15:30:00Z",
    )
    mock_repo.list_alert_flow_correlations.return_value = ([verified_row, unverified_row], 2)

    r_all = client.get("/api/v1/correlations/alert-flows?include_unverified=true")
    assert r_all.status_code == 200
    payload = r_all.json()
    assert payload["total"] == 2
    assert [i["verification_status"] for i in payload["items"]] == [
        "verified",
        "unverified_incomplete",
    ]
    assert payload["items"][1]["last_incomplete_reason"] == "CANDIDATE_SET_TRUNCATED"
    assert payload["items"][1]["last_incomplete_at_utc"] == "2026-11-22T15:30:00Z"
    mock_repo.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id=None,
        event_id=None,
        observation_id=None,
        include_unverified=True,
        verification_status=None,
        limit=50,
        offset=0,
    )

    mock_repo.list_alert_flow_correlations.reset_mock()
    mock_repo.list_alert_flow_correlations.return_value = ([unverified_row], 1)
    r_unv_only = client.get("/api/v1/correlations/alert-flows?verification_status=unverified_incomplete")
    assert r_unv_only.status_code == 200
    assert r_unv_only.json()["items"][0]["verification_status"] == "unverified_incomplete"
    mock_repo.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id=None,
        event_id=None,
        observation_id=None,
        include_unverified=True,
        verification_status="unverified_incomplete",
        limit=50,
        offset=0,
    )

    mock_repo.list_alert_flow_correlations.reset_mock()
    mock_repo.list_alert_flow_correlations.return_value = ([verified_row], 1)
    r_ver_only = client.get("/api/v1/correlations/alert-flows?verification_status=verified")
    assert r_ver_only.status_code == 200
    mock_repo.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id=None,
        event_id=None,
        observation_id=None,
        include_unverified=False,
        verification_status="verified",
        limit=50,
        offset=0,
    )

    # Contradictory filter parameters must return 422 without hitting the database
    mock_repo.list_alert_flow_correlations.reset_mock()
    r_conflict = client.get(
        "/api/v1/correlations/alert-flows?include_unverified=false&verification_status=unverified_incomplete"
    )
    assert r_conflict.status_code == 422
    mock_repo.list_alert_flow_correlations.assert_not_called()


def test_e_f_g_h_list_filtering_pagination_and_empty_collection():
    """Verify domain, event_id, observation_id filters, pagination bounds, and empty 200 response."""
    _, client, mock_repo = _v2_client()
    mock_repo.list_alert_flow_correlations.return_value = ([_sample_v2_row()], 7)

    r = client.get(
        f"/api/v1/correlations/alert-flows"
        f"?routing_domain_id=%20CORP-A%20&event_id={_EVENT_ID_1}&observation_id={_OBS_ID_1}"
        f"&limit=25&offset=50"
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 7
    assert body["limit"] == 25
    assert body["offset"] == 50
    mock_repo.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id="corp-a",
        event_id=_EVENT_ID_1,
        observation_id=_OBS_ID_1,
        include_unverified=False,
        verification_status=None,
        limit=25,
        offset=50,
    )

    # Empty collection returns HTTP 200 with items=[] and total=0
    mock_repo.list_alert_flow_correlations.reset_mock()
    mock_repo.list_alert_flow_correlations.return_value = ([], 0)
    r_empty = client.get("/api/v1/correlations/alert-flows?routing_domain_id=empty-dom")
    assert r_empty.status_code == 200
    assert r_empty.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_i_j_detail_endpoint_existing_empty_vs_missing_404():
    """Verify detail endpoint distinguishes existing empty AlertEvent (200) from missing AlertEvent (404)."""
    _, client, mock_repo = _v2_client()

    # Existing AlertEvent with verified correlation
    mock_repo.get_alert_event_correlations.return_value = ([_sample_v2_row()], 1)
    r_found = client.get(f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?routing_domain_id=CORP")
    assert r_found.status_code == 200
    assert r_found.json()["total"] == 1
    assert r_found.json()["items"][0]["event_id"] == _EVENT_ID_1
    mock_repo.get_alert_event_correlations.assert_called_once_with(
        _EVENT_ID_1,
        routing_domain_id="corp",
        include_unverified=False,
        verification_status=None,
        limit=50,
        offset=0,
    )

    # Existing AlertEvent with zero persisted (or zero verified) edges -> 200 empty PaginatedResponse
    mock_repo.get_alert_event_correlations.reset_mock()
    mock_repo.get_alert_event_correlations.return_value = ([], 0)
    r_empty = client.get(f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}")
    assert r_empty.status_code == 200
    assert r_empty.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}

    # Nonexistent AlertEvent -> 404 Not Found
    mock_repo.get_alert_event_correlations.reset_mock()
    mock_repo.get_alert_event_correlations.return_value = None
    missing_id = "0" * 64
    r_missing = client.get(f"/api/v1/correlations/alert-flows/{missing_id}")
    assert r_missing.status_code == 404
    assert missing_id in r_missing.json()["detail"]


def test_k_m_validation_errors_return_422():
    """Verify invalid query and path parameters return 422 without querying Neo4j."""
    _, client, mock_repo = _v2_client()

    invalid_urls = [
        "/api/v1/correlations/alert-flows?limit=0",
        "/api/v1/correlations/alert-flows?limit=201",
        "/api/v1/correlations/alert-flows?offset=-1",
        "/api/v1/correlations/alert-flows?verification_status=invalid",
        "/api/v1/correlations/alert-flows?include_unverified=maybe",
        "/api/v1/correlations/alert-flows?routing_domain_id=corp%23bad",
        "/api/v1/correlations/alert-flows?event_id=short",
        f"/api/v1/correlations/alert-flows?event_id={'g' * 64}",
        f"/api/v1/correlations/alert-flows?event_id={'A' * 64}",
        "/api/v1/correlations/alert-flows?observation_id=not-sha256",
        "/api/v1/correlations/alert-flows/short",
        f"/api/v1/correlations/alert-flows/{'z' * 64}",
        f"/api/v1/correlations/alert-flows/{'A' * 64}",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?limit=0",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?offset=-5",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?routing_domain_id=corp%23bad",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?verification_status=bogus",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?include_unverified=false&verification_status=unverified_incomplete",
    ]
    for url in invalid_urls:
        resp = client.get(url)
        assert resp.status_code == 422, f"Expected 422 for {url}, got {resp.status_code}"

    mock_repo.list_alert_flow_correlations.assert_not_called()
    mock_repo.get_alert_event_correlations.assert_not_called()


def test_l_database_unavailable_returns_503_and_unexpected_error_returns_500():
    """Verify driver=None, ServiceUnavailable, and AuthError return 503 (never 404) and errors sanitize details."""
    # 1. Real Neo4jCorrelationRepository(None) via lifespan without driver -> 503 on list & detail
    app_no_driver = create_app()
    app_no_driver.state.driver = None
    client_no_driver = TestClient(app_no_driver)

    r_list_503 = client_no_driver.get("/api/v1/correlations/alert-flows")
    assert r_list_503.status_code == 503
    assert r_list_503.json()["detail"] == "Database service unavailable"

    r_detail_503 = client_no_driver.get(f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}")
    assert r_detail_503.status_code == 503
    assert r_detail_503.json()["detail"] == "Database service unavailable"

    # 2. Neo4j ServiceUnavailable & AuthError -> 503 without internal host/credential leaks
    _, client, mock_repo = _v2_client()
    mock_repo.list_alert_flow_correlations.side_effect = ServiceUnavailable(
        "bolt://internal-neo4j:7687 unreachable"
    )
    r_su = client.get("/api/v1/correlations/alert-flows")
    assert r_su.status_code == 503
    assert r_su.json()["detail"] == "Database service unavailable"
    assert "internal-neo4j" not in r_su.text

    mock_repo.get_alert_event_correlations.side_effect = AuthError("secret-password failure")
    r_auth = client.get(f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}")
    assert r_auth.status_code == 503
    assert r_auth.json()["detail"] == "Database authentication failure"
    assert "secret-password" not in r_auth.text

    # 3. Unexpected internal exception -> sanitized 500
    app_err = create_app()
    err_repo = MagicMock(spec=Neo4jCorrelationRepository)
    err_repo.list_alert_flow_correlations.side_effect = RuntimeError("internal cypher trace")
    app_err.dependency_overrides[get_correlation_repository] = lambda: err_repo
    client_err = TestClient(app_err, raise_server_exceptions=False)
    r_500 = client_err.get("/api/v1/correlations/alert-flows")
    assert r_500.status_code == 500
    assert r_500.json()["detail"] == "Internal server error"
    assert "internal cypher trace" not in r_500.text


def test_n_o_openapi_route_ordering_and_decimal_no_float_coercion():
    """Verify OpenAPI contracts, GET-only correlation routes, and strict Decimal string safety."""
    app = create_app()
    schema = app.openapi()
    paths = schema["paths"]

    assert "/api/v1/correlations/traffic-alerts" in paths
    assert "/api/v1/correlations/alert-flows" in paths
    assert "/api/v1/correlations/alert-flows/{event_id}" in paths

    for corr_path in (
        "/api/v1/correlations/traffic-alerts",
        "/api/v1/correlations/alert-flows",
        "/api/v1/correlations/alert-flows/{event_id}",
    ):
        assert list(paths[corr_path].keys()) == ["get"]

    # Static /alert-flows must appear before dynamic /alert-flows/{event_id}
    from src.api.routes.correlations import router as correlations_router

    path_keys = list(paths.keys())
    assert path_keys.index("/api/v1/correlations/alert-flows") < path_keys.index(
        "/api/v1/correlations/alert-flows/{event_id}"
    )
    router_paths = [getattr(r, "path", "") for r in correlations_router.routes]
    static_idx = next(i for i, p in enumerate(router_paths) if p.endswith("/alert-flows"))
    dynamic_idx = next(
        i for i, p in enumerate(router_paths) if p.endswith("/alert-flows/{event_id}")
    )
    assert static_idx < dynamic_idx

    # AlertFlowCorrelationResponse forbids float coercion on temporal_delta_decimal
    with pytest.raises(ValidationError):
        AlertFlowCorrelationResponse(**_sample_v2_row(temporal_delta_decimal=1.25))

    # Nullable fields serialize cleanly without fabricating defaults
    nullable_model = AlertFlowCorrelationResponse(
        **_sample_v2_row(
            zeek_uid=None,
            correlation_method=None,
            evidence_version=None,
            policy_fingerprint=None,
            evidence_digest=None,
            tuple_orientation=None,
            community_id_agreement=None,
            temporal_relation=None,
            temporal_delta_decimal=None,
            used_decimal_fallback=None,
            sensor_context=None,
            decided_at_utc=None,
        )
    )
    assert nullable_model.temporal_delta_decimal is None
    assert nullable_model.decided_at_utc is None


def test_p_legacy_v1_route_isolated_from_v2_dependency():
    """Verify V1 traffic-alerts continues using get_read_repository and is unaffected by V2."""
    app = create_app()
    mock_read_repo = MagicMock()
    mock_read_repo.list_traffic_alert_correlations.return_value = ([], 0)
    mock_corr_repo = MagicMock(spec=Neo4jCorrelationRepository)

    app.dependency_overrides[get_read_repository] = lambda: mock_read_repo
    app.dependency_overrides[get_correlation_repository] = lambda: mock_corr_repo
    client = TestClient(app)

    resp = client.get("/api/v1/correlations/traffic-alerts")
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}
    mock_read_repo.list_traffic_alert_correlations.assert_called_once()
    mock_corr_repo.list_alert_flow_correlations.assert_not_called()
    mock_corr_repo.get_alert_event_correlations.assert_not_called()


def test_q_r_repository_read_only_cypher_and_no_engine_or_write_calls(monkeypatch):
    """Verify V2 correlation reads use execute_read only, non-mutating Cypher, and never trigger writes/engine/DDL."""
    for cypher in (
        CYPHER_COUNT_ALERT_FLOW_CORRELATIONS,
        CYPHER_LIST_ALERT_FLOW_CORRELATIONS,
        CYPHER_CHECK_SURICATA_ALERT_EVENT_EXISTS,
    ):
        assert not re.search(
            r"\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP)\b", cypher, re.IGNORECASE
        )
        return_clause = cypher.split("RETURN", 1)[1]
        assert "elementId(" not in return_clause

    # Internal relationship tie-breaker exists in ORDER BY without exposing elementId in RETURN
    assert "elementId(r) ASC" in CYPHER_LIST_ALERT_FLOW_CORRELATIONS.split("RETURN", 1)[0]

    # Guard against write/engine/schema imports or calls from HTTP GET routes
    def _forbid(*args, **kwargs):
        raise AssertionError("Write/correlation engine/schema DDL must never execute on GET")

    monkeypatch.setattr("src.graph.schema.ensure_schema", _forbid)
    monkeypatch.setattr("src.services.correlation_service.run_alert_flow_correlation", _forbid)
    monkeypatch.setattr(Neo4jCorrelationRepository, "correlate_alert_batch", _forbid)
    monkeypatch.setattr(Neo4jCorrelationRepository, "reconcile_alert_in_tx", _forbid)

    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()

    def _run_side_effect(query, **params):
        res = MagicMock()
        if query == CYPHER_CHECK_SURICATA_ALERT_EVENT_EXISTS:
            res.single.return_value = {"event_id": _EVENT_ID_1}
        elif query == CYPHER_COUNT_ALERT_FLOW_CORRELATIONS:
            res.single.return_value = {"total": 1}
        elif query == CYPHER_LIST_ALERT_FLOW_CORRELATIONS:
            res.__iter__.return_value = iter([_sample_v2_row()])
        else:
            raise AssertionError(f"Unexpected Cypher query: {query}")
        return res

    mock_tx.run.side_effect = _run_side_effect
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_session.execute_write.side_effect = _forbid
    mock_driver.session.return_value.__enter__.return_value = mock_session

    app = create_app()
    app.dependency_overrides[get_correlation_repository] = lambda: Neo4jCorrelationRepository(
        mock_driver
    )
    client = TestClient(app)

    r_list = client.get("/api/v1/correlations/alert-flows?routing_domain_id=CORP")
    assert r_list.status_code == 200
    assert r_list.json()["total"] == 1

    r_detail = client.get(f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}")
    assert r_detail.status_code == 200
    assert r_detail.json()["total"] == 1

    assert mock_session.execute_read.call_count == 2
    mock_session.execute_write.assert_not_called()

    # Repository-level missing AlertEvent returns None while existing empty returns ([], 0)
    def _run_missing(query, **params):
        res = MagicMock()
        res.single.return_value = None
        return res

    mock_tx.run.side_effect = _run_missing
    repo = Neo4jCorrelationRepository(mock_driver)
    assert repo.get_alert_event_correlations(_EVENT_ID_1) is None

    with pytest.raises(ValueError):
        repo.list_alert_flow_correlations(routing_domain_id="bad#domain")
    with pytest.raises(ValueError):
        repo.list_alert_flow_correlations(
            include_unverified=False,
            verification_status="unverified_incomplete",
        )
    with pytest.raises(ValueError):
        repo.get_alert_event_correlations("   ")


def test_repository_pagination_and_validation_contracts():
    """Verify repository returns ([], 0) for existing alert without edges and enforces bounds."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()

    def _run_empty_existing(query, **params):
        res = MagicMock()
        if query == CYPHER_CHECK_SURICATA_ALERT_EVENT_EXISTS:
            res.single.return_value = {"event_id": _EVENT_ID_1}
        elif query == CYPHER_COUNT_ALERT_FLOW_CORRELATIONS:
            res.single.return_value = {"total": 0}
        elif query == CYPHER_LIST_ALERT_FLOW_CORRELATIONS:
            res.__iter__.return_value = iter([])
        return res

    mock_tx.run.side_effect = _run_empty_existing
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jCorrelationRepository(mock_driver)
    result = repo.get_alert_event_correlations(
        _EVENT_ID_1,
        include_unverified=True,
        verification_status="verified",
    )
    assert result == ([], 0)

    for bad_kwargs in (
        {"limit": 0},
        {"limit": 1001},
        {"limit": True},
        {"offset": -1},
        {"offset": True},
        {"offset": 2**63},
        {"include_unverified": "yes"},
        {"verification_status": "unknown"},
        {"routing_domain_id": 123},
        {"routing_domain_id": ""},
        {"routing_domain_id": "   "},
        {"event_id": 456},
        {"event_id": ""},
        {"event_id": "   "},
        {"observation_id": 789},
        {"observation_id": ""},
        {"observation_id": "   "},
    ):
        with pytest.raises(ValueError):
            repo.list_alert_flow_correlations(**bad_kwargs)


def test_review_extreme_offset_and_blank_domain_fail_closed():
    """Verify INT64_MAX+1 offset and explicit blank routing_domain_id return 422, while INT64_MAX returns empty 200."""
    _, client, mock_repo = _v2_client()
    int64_max = 2**63 - 1
    int64_overflow = 2**63

    # HTTP 422 for int64 overflow and explicit blank routing_domain_id on both list and detail routes
    for bad_url in (
        f"/api/v1/correlations/alert-flows?offset={int64_overflow}",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?offset={int64_overflow}",
        "/api/v1/correlations/alert-flows?routing_domain_id=",
        "/api/v1/correlations/alert-flows?routing_domain_id=%20%20",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?routing_domain_id=",
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?routing_domain_id=%20%20",
    ):
        resp = client.get(bad_url)
        assert resp.status_code == 422, f"Expected 422 for {bad_url}, got {resp.status_code}"

    mock_repo.list_alert_flow_correlations.assert_not_called()
    mock_repo.get_alert_event_correlations.assert_not_called()

    # Repository returns clean empty page at INT64_MAX without running SKIP/LIMIT overflow query
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()
    queries_executed = []

    def _run_count_only(query, **params):
        queries_executed.append(query)
        res = MagicMock()
        if query == CYPHER_COUNT_ALERT_FLOW_CORRELATIONS:
            res.single.return_value = {"total": 3}
        elif query == CYPHER_CHECK_SURICATA_ALERT_EVENT_EXISTS:
            res.single.return_value = {"event_id": _EVENT_ID_1}
        else:
            raise AssertionError("Page query should not execute when offset >= total or near INT64_MAX")
        return res

    mock_tx.run.side_effect = _run_count_only
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver.session.return_value.__enter__.return_value = mock_session

    app = create_app()
    app.dependency_overrides[get_correlation_repository] = lambda: Neo4jCorrelationRepository(
        mock_driver
    )
    real_client = TestClient(app)

    r_list = real_client.get(f"/api/v1/correlations/alert-flows?offset={int64_max}&limit=50")
    assert r_list.status_code == 200
    assert r_list.json() == {"items": [], "total": 3, "limit": 50, "offset": int64_max}

    r_detail = real_client.get(
        f"/api/v1/correlations/alert-flows/{_EVENT_ID_1}?offset={int64_max}&limit=50"
    )
    assert r_detail.status_code == 200
    assert r_detail.json() == {"items": [], "total": 3, "limit": 50, "offset": int64_max}
    assert CYPHER_LIST_ALERT_FLOW_CORRELATIONS not in queries_executed


def test_review_strict_evidence_validation_and_unknown_status_fail_closed():
    """Verify strict Pydantic rejects malformed DB types & unknown verification_status with sanitized 500."""
    for bad_overrides in (
        {"used_decimal_fallback": "yes"},
        {"used_decimal_fallback": 1},
        {"temporal_delta_decimal": 1.25},
        {"verification_status": "unknown_corrupt"},
    ):
        with pytest.raises(ValidationError):
            AlertFlowCorrelationResponse(**_sample_v2_row(**bad_overrides))

    # Unknown persisted status or malformed bool fails closed as sanitized 500 under include_unverified=true
    for corrupt_overrides in (
        {"verification_status": "unknown_corrupt"},
        {"used_decimal_fallback": "yes"},
    ):
        app = create_app()
        mock_repo = MagicMock(spec=Neo4jCorrelationRepository)
        mock_repo.list_alert_flow_correlations.return_value = (
            [_sample_v2_row(**corrupt_overrides)],
            1,
        )
        app.dependency_overrides[get_correlation_repository] = lambda: mock_repo
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/correlations/alert-flows?include_unverified=true")
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Internal server error"
        assert "unknown_corrupt" not in resp.text

    # include_unverified=true + verification_status=verified narrows cleanly to verified
    _, client_ok, mock_ok = _v2_client()
    mock_ok.list_alert_flow_correlations.return_value = ([_sample_v2_row()], 1)
    r_combo = client_ok.get(
        "/api/v1/correlations/alert-flows?include_unverified=true&verification_status=verified"
    )
    assert r_combo.status_code == 200
    mock_ok.list_alert_flow_correlations.assert_called_once_with(
        routing_domain_id=None,
        event_id=None,
        observation_id=None,
        include_unverified=True,
        verification_status="verified",
        limit=50,
        offset=0,
    )


def test_review_concurrent_mutation_between_count_and_page_graceful():
    """Verify Read Committed drift between count and page queries returns cleanly without fabrication."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()

    def _run_concurrent_drift(query, **params):
        res = MagicMock()
        if query == CYPHER_COUNT_ALERT_FLOW_CORRELATIONS:
            # Count sees 2 edges before another tx deletes/unverifies one
            res.single.return_value = {"total": 2}
        elif query == CYPHER_LIST_ALERT_FLOW_CORRELATIONS:
            # Page sees only 1 remaining edge
            res.__iter__.return_value = iter([_sample_v2_row()])
        else:
            raise AssertionError(f"Unexpected query: {query}")
        return res

    mock_tx.run.side_effect = _run_concurrent_drift
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver.session.return_value.__enter__.return_value = mock_session

    app = create_app()
    app.dependency_overrides[get_correlation_repository] = lambda: Neo4jCorrelationRepository(
        mock_driver
    )
    client = TestClient(app)

    resp = client.get("/api/v1/correlations/alert-flows?limit=50&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["items"]) == 1
    assert data["items"][0]["event_id"] == _EVENT_ID_1
