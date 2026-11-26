"""
Unit, repository, strict-validation, precision, and API tests for Phase 4F.2
V2 Read-Only Suricata AlertEvent Triage Listing (`GET /api/v1/alert-events`).
"""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from neo4j.exceptions import AuthError, ServiceUnavailable
from pydantic import ValidationError
import pytest

from src.api.app import create_app
from src.api.dependencies import get_read_repository
from src.api.models import (
    JS_MAX_SAFE_INTEGER,
    AlertEventTriageItemResponse,
    PaginatedResponse,
    SafePaginatedResponse,
)
from src.graph.read_repository import Neo4jReadRepository

_EVENT_ID_1 = "1" * 64
_EVENT_ID_2 = "2" * 64
_FACT_KEY_1 = "f" * 64
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1
_FORBIDDEN_WRITE_CYPHER_RE = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|DETACH\s+DELETE|DROP|REMOVE|CALL)\b",
    re.IGNORECASE,
)


def _sample_triage_row(**overrides):
    base = {
        "event_id": _EVENT_ID_1,
        "routing_domain_id": "demo-v2-corp",
        "source_type": "suricata",
        "sensor_id": "suricata-demo-01",
        "sid": 9100001,
        "signature": "SYNTHETIC Demo Strong Match TLS Observation",
        "severity": 3,
        "category": "Not Suspicious Traffic",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "timestamp_source": "2026-11-23T10:00:02.123456789123+0000",
        "timestamp_epoch_decimal": "1795428002.123456789123",
        "has_persisted_correlation": True,
    }
    base.update(overrides)
    return base


def _client_with_mock_repo():
    app = create_app()
    mock_repo = MagicMock(spec=Neo4jReadRepository)
    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    return app, TestClient(app, raise_server_exceptions=False), mock_repo


def test_a_d_e_f_z_list_alert_events_returns_200_including_unlinked_and_empty():
    """Tests A, D, E, F, Z: HTTP 200 list includes linked & unlinked events; empty filter returns 200."""
    _, client, mock_repo = _client_with_mock_repo()

    linked = _sample_triage_row(event_id=_EVENT_ID_1, sid=9100001, has_persisted_correlation=True)
    unlinked = _sample_triage_row(
        event_id=_EVENT_ID_2,
        sid=9100002,
        severity=2,
        signature="SYNTHETIC Demo Ambiguous Dual Flow Probe",
        timestamp_source="2026-11-23T10:01:05+0000",
        timestamp_epoch_decimal=None,
        has_persisted_correlation=False,
    )
    mock_repo.list_alert_events_for_triage.return_value = ([linked, unlinked], 2)

    resp = client.get("/api/v1/alert-events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert len(body["items"]) == 2
    assert body["items"][0]["has_persisted_correlation"] is True
    assert body["items"][1]["has_persisted_correlation"] is False
    assert body["items"][1]["timestamp_epoch_decimal"] is None

    mock_repo.list_alert_events_for_triage.assert_called_once_with(
        routing_domain_id=None,
        sensor_id=None,
        sid=None,
        severity=None,
        start_epoch_ns=None,
        end_epoch_ns=None,
        source_type="suricata",
        limit=50,
        offset=0,
    )

    # Empty filtered query returns 200 (never 404)
    mock_repo.list_alert_events_for_triage.return_value = ([], 0)
    empty_resp = client.get("/api/v1/alert-events?routing_domain_id=nonexistent-domain")
    assert empty_resp.status_code == 200
    assert empty_resp.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_b_c_v1_alerts_and_v2_detail_routes_and_openapi_ordering_preserved():
    """Tests B, C: OpenAPI static/dynamic ordering and backward compatibility for V1 alerts & V2 detail."""
    app, client, mock_repo = _client_with_mock_repo()

    # OpenAPI path registration order must place static /alert-events before /alert-events/{event_id}
    schema = app.openapi()
    alert_paths = [p for p in schema["paths"] if p.startswith("/api/v1/alert")]
    assert alert_paths.index("/api/v1/alert-events") < alert_paths.index("/api/v1/alert-events/{event_id}")
    assert "/api/v1/alerts" in alert_paths
    assert "/api/v1/alerts/{fact_key}" in alert_paths

    # V1 /api/v1/alerts remains bound to list_alert_facts
    mock_repo.list_alert_facts.return_value = (
        [
            {
                "fact_key": _FACT_KEY_1,
                "source_ip": "192.0.2.10",
                "target_ip": "198.51.100.20",
                "sid": 2001219,
                "gid": 1,
                "rev": 1,
                "message": "Legacy V1 AlertFact",
                "priority": 1,
                "protocol": "TCP",
                "src_port": 12345,
                "dst_port": 22,
            }
        ],
        1,
    )
    v1_res = client.get("/api/v1/alerts")
    assert v1_res.status_code == 200
    assert v1_res.json()["items"][0]["fact_key"] == _FACT_KEY_1
    mock_repo.list_alert_facts.assert_called_once()

    # Existing V2 detail endpoint still handles SHA-256 event_id without colliding with list route
    mock_repo.get_alert_event.return_value = {
        "event_id": _EVENT_ID_1,
        "alert_definition_id": "suricata:demo-v2-rules:1:9100001",
        "source_record_id": "rec-1",
        "log_source_id": "corp-eve-demo-01",
        "sensor_id": "suricata-demo-01",
        "ruleset_namespace": "demo-v2-rules",
        "routing_domain_id": "demo-v2-corp",
        "source_type": "suricata",
        "source_provenance": None,
        "engine": None,
        "gid": 1,
        "sid": 9100001,
        "rev": 1,
        "signature": "Unlinked detail",
        "category": None,
        "severity": 2,
        "action": None,
        "app_proto": None,
        "direction": None,
        "tx_id": None,
        "pcap_cnt": None,
        "flow_id": None,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_scoped_id": "demo-v2-corp#192.0.2.10",
        "dst_scoped_id": "demo-v2-corp#198.51.100.20",
        "protocol": "TCP",
        "src_port": 54321,
        "dst_port": 443,
        "flow_key": "a" * 64,
        "community_id": None,
        "timestamp_source": "2026-11-23T10:00:02+0000",
        "timestamp_epoch_decimal": "1795428002",
    }
    detail_res = client.get(f"/api/v1/alert-events/{_EVENT_ID_1}")
    assert detail_res.status_code == 200
    assert detail_res.json()["event_id"] == _EVENT_ID_1


def test_g_h_i_k_l_m_n_o_q_r_query_validation_and_normalization():
    """Tests G-I, K-O, Q, R: Strict 422 validation on invalid filters/bounds; normalization on valid filters."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.list_alert_events_for_triage.return_value = ([], 0)

    # Valid boundary query with falsy severity=0, sid=0, trimmed uppercase routing_domain_id & sensor_id
    res = client.get(
        "/api/v1/alert-events",
        params={
            "routing_domain_id": "  CORP-VRF1  ",
            "sensor_id": "  Suricata-Sensor-A  ",
            "sid": 0,
            "severity": 0,
            "start_epoch_ns": _INT64_MIN,
            "end_epoch_ns": _INT64_MAX,
            "limit": 200,
            "offset": 0,
        },
    )
    assert res.status_code == 200
    mock_repo.list_alert_events_for_triage.assert_called_once_with(
        routing_domain_id="corp-vrf1",
        sensor_id="suricata-sensor-a",
        sid=0,
        severity=0,
        start_epoch_ns=_INT64_MIN,
        end_epoch_ns=_INT64_MAX,
        source_type="suricata",
        limit=200,
        offset=0,
    )

    mock_repo.list_alert_events_for_triage.reset_mock()

    invalid_queries = [
        {"routing_domain_id": ""},  # H
        {"routing_domain_id": "   "},  # H
        {"routing_domain_id": "corp#1"},  # I
        {"sensor_id": ""},  # M
        {"sensor_id": "   "},  # M
        {"severity": "-1"},  # K
        {"severity": "abc"},  # K
        {"severity": "true"},  # K
        {"severity": ""},  # K
        {"severity": str(_INT64_MAX + 1)},  # K
        {"sid": "-1"},  # L
        {"sid": "abc"},  # L
        {"sid": ""},  # L
        {"sid": str(_INT64_MAX + 1)},  # L
        {"start_epoch_ns": "not-an-int"},  # N
        {"start_epoch_ns": str(_INT64_MIN - 1)},  # N
        {"end_epoch_ns": str(_INT64_MAX + 1)},  # N
        {"start_epoch_ns": "200", "end_epoch_ns": "100"},  # O reversed
        {"limit": "0"},  # Q
        {"limit": "201"},  # Q
        {"limit": "-5"},  # Q
        {"offset": "-1"},  # R
        {"offset": str(_INT64_MAX + 1)},  # R int64 overflow
    ]
    for params in invalid_queries:
        bad_res = client.get("/api/v1/alert-events", params=params)
        assert bad_res.status_code == 422, f"Expected 422 for {params}, got {bad_res.status_code}"

    mock_repo.list_alert_events_for_triage.assert_not_called()


def test_j_p_r_s_t_x_y_repository_cypher_isolation_ordering_overflow_and_corrupt_fail_closed():
    """Tests J, P, R, S, T, X, Y: Read-only Cypher, source_type='suricata', NULLS LAST, overflow short-circuit, corrupt fail-closed."""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_tx = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)

    def _forbid(*args, **kwargs):
        raise AssertionError("Write/DDL transaction forbidden during read-only triage list")

    mock_session.execute_write.side_effect = _forbid

    repo = Neo4jReadRepository(mock_driver)

    # 1. Verify Cypher clauses with active time bounds & exact filters
    count_res = MagicMock()
    count_res.single.return_value = {"total": 1}
    page_rec = _sample_triage_row()
    mock_tx.run.side_effect = [count_res, [page_rec]]

    items, total = repo.list_alert_events_for_triage(
        routing_domain_id=" DEMO-V2-CORP ",
        sensor_id=" Suricata-Demo-01 ",
        sid=9100001,
        severity=3,
        start_epoch_ns=1795428000000000000,
        end_epoch_ns=1795428005000000000,
        limit=25,
        offset=0,
    )
    assert total == 1
    assert len(items) == 1
    assert mock_session.execute_read.call_count == 1
    mock_session.execute_write.assert_not_called()

    count_cypher = mock_tx.run.call_args_list[0].args[0]
    count_kwargs = mock_tx.run.call_args_list[0].kwargs
    page_cypher = mock_tx.run.call_args_list[1].args[0]

    for cypher in (count_cypher, page_cypher):
        assert not _FORBIDDEN_WRITE_CYPHER_RE.search(cypher)
        assert "ae.source_type = $source_type" in cypher
        assert "ae.routing_domain_id = $routing_domain_id" in cypher
        assert "ae.sensor_id = $sensor_id" in cypher
        assert "ae.timestamp_epoch_ns IS NOT NULL AND ae.timestamp_epoch_ns >= $start_epoch_ns" in cypher
        assert "ae.timestamp_epoch_ns IS NOT NULL AND ae.timestamp_epoch_ns <= $end_epoch_ns" in cypher

    assert count_kwargs["source_type"] == "suricata"
    assert count_kwargs["routing_domain_id"] == "demo-v2-corp"
    assert count_kwargs["sensor_id"] == "suricata-demo-01"

    return_clause = page_cypher.split("RETURN", 1)[1].split("ORDER BY", 1)[0]
    assert "elementId(" not in page_cypher
    assert "timestamp_epoch_ns" not in return_clause
    assert "EXISTS { MATCH (ae)-[:CORRELATED_WITH]->(:FlowObservation) } AS has_persisted_correlation" in return_clause
    assert "ORDER BY CASE WHEN ae.timestamp_epoch_ns IS NULL THEN 1 ELSE 0 END ASC," in page_cypher
    assert "ae.timestamp_epoch_ns ASC," in page_cypher
    assert "ae.event_id ASC" in page_cypher

    # 2. Without time bounds, NULL timestamp_epoch_ns exclusion is NOT applied (P)
    mock_tx.run.reset_mock()
    count_res_no_time = MagicMock()
    count_res_no_time.single.return_value = {"total": 0}
    mock_tx.run.side_effect = [count_res_no_time]
    items_empty, total_zero = repo.list_alert_events_for_triage()
    assert (items_empty, total_zero) == ([], 0)
    no_time_cypher = mock_tx.run.call_args_list[0].args[0]
    assert "timestamp_epoch_ns IS NOT NULL" not in no_time_cypher
    assert mock_tx.run.call_count == 1  # short-circuits page query when total == 0

    # 3. Large valid offset up to INT64_MAX short-circuits page query safely (R)
    mock_tx.run.reset_mock()
    count_res_large = MagicMock()
    count_res_large.single.return_value = {"total": 1}
    mock_tx.run.side_effect = [count_res_large]
    items_oor, total_oor = repo.list_alert_events_for_triage(offset=_INT64_MAX, limit=50)
    assert (items_oor, total_oor) == ([], 1)
    assert mock_tx.run.call_count == 1  # never sends SKIP _INT64_MAX + LIMIT 50

    # Repository validation guardrails reject blank/malformed direct calls fail-closed
    for bad_kw in (
        {"routing_domain_id": ""},
        {"routing_domain_id": "   "},
        {"routing_domain_id": "bad#domain"},
        {"sensor_id": ""},
        {"sensor_id": "   "},
        {"sid": -1},
        {"sid": True},
        {"severity": -1},
        {"severity": True},
        {"start_epoch_ns": True},
        {"start_epoch_ns": 20, "end_epoch_ns": 10},
        {"limit": 0},
        {"limit": 201},
        {"offset": -1},
        {"offset": _INT64_MAX + 1},
    ):
        with pytest.raises(ValueError):
            repo.list_alert_events_for_triage(**bad_kw)


def test_t_corrupt_persisted_triage_rows_fail_closed_sanitized_500():
    """Test T: Corrupt persisted node properties fail closed via HTTP 500 without leaking details."""
    _, client, mock_repo = _client_with_mock_repo()

    corrupt_variants = [
        {"routing_domain_id": None},
        {"routing_domain_id": "bad#domain"},
        {"routing_domain_id": "   "},
        {"source_type": "zeek"},  # wrong source type
        {"event_id": "not-sha256"},
        {"src_ip": "not-an-ip"},
        {"dst_ip": "999.999.999.999"},
        {"sid": -1},
        {"sid": True},
        {"severity": -5},
        {"timestamp_epoch_decimal": "1E+50000"},
        {"timestamp_epoch_decimal": "1_795.0"},
        {"timestamp_epoch_decimal": "+1795.0"},
        {"timestamp_epoch_decimal": "NaN"},
        {"has_persisted_correlation": "true"},
        {"timestamp_epoch_ns": 1795428000000000000},  # extra="forbid"
    ]
    for override in corrupt_variants:
        mock_repo.list_alert_events_for_triage.return_value = ([_sample_triage_row(**override)], 1)
        res = client.get("/api/v1/alert-events")
        assert res.status_code == 500, f"Expected 500 for corrupt {override}, got {res.status_code}"
        assert res.json() == {"detail": "Internal server error"}


def test_u_v_missing_driver_and_neo4j_outage_return_sanitized_503():
    """Tests U, V: Missing driver and Neo4j outage fail closed with sanitized HTTP 503."""
    app_no_driver = create_app()
    app_no_driver.state.driver = None
    client_no_driver = TestClient(app_no_driver)
    res_no_drv = client_no_driver.get("/api/v1/alert-events")
    assert res_no_drv.status_code == 503
    assert "bolt://" not in res_no_drv.text.lower()
    assert "traceback" not in res_no_drv.text.lower()

    _, client_err, mock_repo = _client_with_mock_repo()
    for exc in (
        ConnectionError("Database driver unavailable"),
        ServiceUnavailable("Routing unavailable at bolt://secret-internal:7687"),
        AuthError("Invalid neo4j password"),
    ):
        mock_repo.list_alert_events_for_triage.side_effect = exc
        res = client_err.get("/api/v1/alert-events")
        assert res.status_code == 503
        assert "secret-internal" not in res.text
        assert "password" not in res.text


def test_w_x_js_safe_int_boundaries_and_safe_paginated_response_lossless():
    """Tests W, X: Lossless JS safe-integer boundaries on sid, severity, total, offset; never expose ns index."""
    app, client, mock_repo = _client_with_mock_repo()

    # Verify SafePaginatedResponse is a subclass of PaginatedResponse and non-nullable in OpenAPI
    assert issubclass(SafePaginatedResponse, PaginatedResponse)
    schema = app.openapi()
    item_props = schema["components"]["schemas"]["AlertEventTriageItemResponse"]["properties"]
    assert {e.get("type") for e in item_props["sid"].get("anyOf", [])} == {"integer", "string"}
    assert "timestamp_epoch_ns" not in item_props

    page_schema = schema["components"]["schemas"]["SafePaginatedResponse_AlertEventTriageItemResponse_"]["properties"]
    assert {e.get("type") for e in page_schema["total"].get("anyOf", [])} == {"integer", "string"}
    assert {e.get("type") for e in page_schema["offset"].get("anyOf", [])} == {"integer", "string"}

    boundaries = [
        (0, int, 0),
        (JS_MAX_SAFE_INTEGER, int, 9007199254740991),
        (JS_MAX_SAFE_INTEGER + 1, str, "9007199254740992"),
        (JS_MAX_SAFE_INTEGER + 2, str, "9007199254740993"),
        (_INT64_MAX, str, "9223372036854775807"),
    ]
    for raw_val, expected_type, expected_json in boundaries:
        mock_repo.list_alert_events_for_triage.return_value = (
            [
                _sample_triage_row(
                    sid=raw_val,
                    severity=raw_val,
                    timestamp_epoch_decimal="1795428002.123456789000",
                )
            ],
            raw_val,
        )
        res = client.get("/api/v1/alert-events", params={"offset": str(raw_val)})
        assert res.status_code == 200
        parsed = json.loads(res.text)
        assert type(parsed["total"]) is expected_type
        assert parsed["total"] == expected_json
        assert type(parsed["offset"]) is expected_type
        assert parsed["offset"] == expected_json
        assert type(parsed["items"][0]["sid"]) is expected_type
        assert parsed["items"][0]["sid"] == expected_json
        assert type(parsed["items"][0]["severity"]) is expected_type
        assert parsed["items"][0]["severity"] == expected_json
        assert parsed["items"][0]["timestamp_epoch_decimal"] == "1795428002.123456789000"
        assert "timestamp_epoch_ns" not in parsed["items"][0]

    # Strict validation rejects bad SafePaginatedResponse counts
    with pytest.raises(ValidationError):
        SafePaginatedResponse[AlertEventTriageItemResponse](
            items=[], total=-1, limit=50, offset=0
        )
    with pytest.raises(ValidationError):
        SafePaginatedResponse[AlertEventTriageItemResponse](
            items=[], total=0, limit=50, offset=True
        )
