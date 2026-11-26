"""
Unit, repository, strict-validation, and API tests for Phase 4F.1 V2 read-only
Suricata AlertEvent and Zeek FlowObservation forensic detail endpoints.
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
    AlertEventDetailResponse,
    FlowObservationDetailResponse,
)
from src.graph.read_repository import Neo4jReadRepository

_EVENT_ID = "a" * 64
_OBS_ID = "b" * 64
_FLOW_KEY = "c" * 64
_FACT_KEY = "d" * 64
_FORBIDDEN_WRITE_CYPHER_RE = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|DETACH\s+DELETE|DROP|REMOVE)\b",
    re.IGNORECASE,
)


def _sample_alert_record(**overrides):
    base = {
        "event_id": _EVENT_ID,
        "alert_definition_id": "suricata:demo-v2-rules:1:9100001",
        "source_record_id": "8810001",
        "log_source_id": "corp-eve-demo-01",
        "sensor_id": "suricata-demo-01",
        "ruleset_namespace": "demo-v2-rules",
        "routing_domain_id": "demo-v2-corp",
        "flow_key": _FLOW_KEY,
        "src_scoped_id": "demo-v2-corp#192.0.2.10",
        "dst_scoped_id": "demo-v2-corp#198.51.100.20",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "timestamp_source": "2026-11-23T10:00:02.123456789123+0000",
        "timestamp_epoch_decimal": "1795428002.123456789123",
        "timestamp_epoch_ns": None,
        "protocol": "TCP",
        "src_port": 54321,
        "dst_port": 443,
        "flow_id": "18446744073709551615",
        "community_id": "1:LQU9q+/0Pl8aBcDef1234567890=",
        "gid": 1,
        "sid": 9100001,
        "rev": 1,
        "signature": "SYNTHETIC Demo Strong Match TLS Observation",
        "category": "Not Suspicious Traffic",
        "severity": 3,
        "action": "allowed",
        "app_proto": "tls",
        "direction": "to_server",
        "tx_id": 0,
        "pcap_cnt": 11,
        "source_type": "suricata",
        "source_provenance": "phase4e-corp-eve",
        "engine": "suricata",
    }
    base.update(overrides)
    return base


def _sample_flow_record(**overrides):
    base = {
        "observation_id": _OBS_ID,
        "flow_key": _FLOW_KEY,
        "zeek_uid": "CDemoCorpStrong01",
        "routing_domain_id": "demo-v2-corp",
        "src_scoped_id": "demo-v2-corp#192.0.2.10",
        "dst_scoped_id": "demo-v2-corp#198.51.100.20",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "src_port": 54321,
        "dst_port": 443,
        "community_id": "1:LQU9q+/0Pl8aBcDef1234567890=",
        "start_ts": "1795428000.123456789",
        "end_ts": "1795428010.123456789",
        "start_epoch_decimal": "1795428000.123456789",
        "end_epoch_decimal": "1795428010.123456789",
        "duration_decimal": "10",
        "start_epoch_ns": 1795428000123456789,
        "end_epoch_ns": 1795428010123456789,
        "orig_bytes": 640,
        "resp_bytes": 2400,
        "orig_pkts": 7,
        "resp_pkts": 8,
        "orig_ip_bytes": 928,
        "resp_ip_bytes": 2736,
        "missed_bytes": 0,
        "service": "ssl",
        "conn_state": "SF",
        "history": "ShADadFf",
        "local_orig": True,
        "local_resp": False,
        "sensor_id": "zeek-demo-01",
        "source_type": "zeek",
        "source_provenance": "phase4e-corp-zeek",
    }
    base.update(overrides)
    return base


def _client_with_mock_repo():
    app = create_app()
    mock_repo = MagicMock(spec=Neo4jReadRepository)
    app.dependency_overrides[get_read_repository] = lambda: mock_repo
    return app, TestClient(app, raise_server_exceptions=False), mock_repo


# ---------------------------------------------------------------------------
# A & B. Happy Path Detail Responses (HTTP 200)
# ---------------------------------------------------------------------------


def test_a_alert_event_detail_200():
    """Matrix A: GET /api/v1/alert-events/{event_id} returns 200 with exact schema."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_alert_event.return_value = _sample_alert_record()

    res = client.get(f"/api/v1/alert-events/{_EVENT_ID}")
    assert res.status_code == 200
    body = res.json()
    assert body["event_id"] == _EVENT_ID
    assert body["sid"] == 9100001
    assert body["engine"] == "suricata"
    assert body["source_type"] == "suricata"
    assert body["routing_domain_id"] == "demo-v2-corp"
    assert "timestamp_epoch_ns" not in body
    mock_repo.get_alert_event.assert_called_once_with(
        _EVENT_ID, routing_domain_id=None, source_type="suricata"
    )


def test_b_flow_observation_detail_200():
    """Matrix B: GET /api/v1/flow-observations/{observation_id} returns 200 with exact schema."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_flow_observation.return_value = _sample_flow_record()

    res = client.get(f"/api/v1/flow-observations/{_OBS_ID}")
    assert res.status_code == 200
    body = res.json()
    assert body["observation_id"] == _OBS_ID
    assert body["zeek_uid"] == "CDemoCorpStrong01"
    assert body["source_type"] == "zeek"
    assert body["orig_bytes"] == 640
    assert body["resp_bytes"] == 2400
    assert body["orig_ip_bytes"] == 928
    assert body["resp_ip_bytes"] == 2736
    assert "start_epoch_ns" not in body
    assert "end_epoch_ns" not in body
    mock_repo.get_flow_observation.assert_called_once_with(
        _OBS_ID, routing_domain_id=None, source_type="zeek"
    )


# ---------------------------------------------------------------------------
# C & D. Not Found (HTTP 404) & Wrong RoutingDomain
# ---------------------------------------------------------------------------


def test_c_d_missing_or_wrong_domain_returns_404():
    """Matrix C & D: Missing entity or mismatched RoutingDomain returns 404 on both endpoints."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_alert_event.return_value = None
    mock_repo.get_flow_observation.return_value = None

    res_alert = client.get(f"/api/v1/alert-events/{_EVENT_ID}?routing_domain_id=wrong-domain")
    assert res_alert.status_code == 404
    mock_repo.get_alert_event.assert_called_once_with(
        _EVENT_ID, routing_domain_id="wrong-domain", source_type="suricata"
    )

    res_flow = client.get(f"/api/v1/flow-observations/{_OBS_ID}?routing_domain_id=wrong-domain")
    assert res_flow.status_code == 404
    mock_repo.get_flow_observation.assert_called_once_with(
        _OBS_ID, routing_domain_id="wrong-domain", source_type="zeek"
    )


# ---------------------------------------------------------------------------
# E, F, G, H, I. Path & RoutingDomain Query Validation (HTTP 422 & Lowercasing)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_id", ["short", "A" * 64, "g" * 64, "1234"])
def test_e_f_invalid_sha256_path_ids_return_422(bad_id: str):
    """Matrix E & F: Non-SHA256 lowercase hex path IDs return 422 without hitting repository."""
    _, client, mock_repo = _client_with_mock_repo()

    assert client.get(f"/api/v1/alert-events/{bad_id}").status_code == 422
    assert client.get(f"/api/v1/flow-observations/{bad_id}").status_code == 422
    mock_repo.get_alert_event.assert_not_called()
    mock_repo.get_flow_observation.assert_not_called()


def test_g_h_blank_and_hash_routing_domain_return_422():
    """Matrix G & H: Explicit blank or '#'-containing routing_domain_id fails closed with 422."""
    _, client, mock_repo = _client_with_mock_repo()

    for bad_domain in ("", "   ", "corp%23sub"):
        assert client.get(f"/api/v1/alert-events/{_EVENT_ID}?routing_domain_id={bad_domain}").status_code == 422
        assert client.get(f"/api/v1/flow-observations/{_OBS_ID}?routing_domain_id={bad_domain}").status_code == 422

    mock_repo.get_alert_event.assert_not_called()
    mock_repo.get_flow_observation.assert_not_called()


def test_i_uppercase_routing_domain_normalizes_lowercase():
    """Matrix I: Mixed-case routing_domain_id normalizes safely to trimmed lowercase."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_alert_event.return_value = _sample_alert_record()
    mock_repo.get_flow_observation.return_value = _sample_flow_record()

    assert client.get(f"/api/v1/alert-events/{_EVENT_ID}?routing_domain_id=%20DEMO-V2-CORP%20").status_code == 200
    assert client.get(f"/api/v1/flow-observations/{_OBS_ID}?routing_domain_id=%20DEMO-V2-CORP%20").status_code == 200

    mock_repo.get_alert_event.assert_called_once_with(
        _EVENT_ID, routing_domain_id="demo-v2-corp", source_type="suricata"
    )
    mock_repo.get_flow_observation.assert_called_once_with(
        _OBS_ID, routing_domain_id="demo-v2-corp", source_type="zeek"
    )


# ---------------------------------------------------------------------------
# J. Source-Type Enforcement
# ---------------------------------------------------------------------------


def test_j_wrong_source_type_fails_closed():
    """Matrix J: Repository Cypher filters source_type, and API strict models reject mismatched source_type."""
    # Repository Cypher predicates
    mock_tx = MagicMock()
    mock_result = MagicMock()
    mock_result.single.return_value = None
    mock_tx.run.return_value = mock_result
    mock_session = MagicMock()
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jReadRepository(mock_driver)
    assert repo.get_alert_event(_EVENT_ID, routing_domain_id="CORP", source_type="suricata") is None
    alert_cypher, alert_params = mock_tx.run.call_args.args[0], mock_tx.run.call_args.kwargs
    assert "ae.source_type = $source_type" in alert_cypher
    assert alert_params["source_type"] == "suricata"
    assert alert_params["routing_domain_id"] == "corp"

    assert repo.get_flow_observation(_OBS_ID, routing_domain_id="CORP", source_type="zeek") is None
    flow_cypher, flow_params = mock_tx.run.call_args.args[0], mock_tx.run.call_args.kwargs
    assert "fo.source_type = $source_type" in flow_cypher
    assert flow_params["source_type"] == "zeek"
    assert flow_params["routing_domain_id"] == "corp"

    # API strict model fails closed -> sanitized 500 if repo ever returned wrong source_type
    _, client, mock_api_repo = _client_with_mock_repo()
    mock_api_repo.get_alert_event.return_value = _sample_alert_record(source_type="snort")
    mock_api_repo.get_flow_observation.return_value = _sample_flow_record(source_type="tshark")
    assert client.get(f"/api/v1/alert-events/{_EVENT_ID}").status_code == 500
    assert client.get(f"/api/v1/flow-observations/{_OBS_ID}").status_code == 500


# ---------------------------------------------------------------------------
# K, L, M. Missing Driver / Neo4j Unavailable / AuthError -> HTTP 503 (Non-Leaky)
# ---------------------------------------------------------------------------


def test_k_l_m_unavailable_database_returns_sanitized_503():
    """Matrix K, L, M: Missing driver, ServiceUnavailable, and AuthError all return HTTP 503."""
    # K. Real Neo4jReadRepository(None) wired into API
    app_no_db = create_app()
    app_no_db.dependency_overrides[get_read_repository] = lambda: Neo4jReadRepository(None)
    client_no_db = TestClient(app_no_db, raise_server_exceptions=False)

    r_a = client_no_db.get(f"/api/v1/alert-events/{_EVENT_ID}")
    r_f = client_no_db.get(f"/api/v1/flow-observations/{_OBS_ID}")
    assert r_a.status_code == 503 and r_a.json() == {"detail": "Database service unavailable"}
    assert r_f.status_code == 503 and r_f.json() == {"detail": "Database service unavailable"}

    # L. ServiceUnavailable
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_alert_event.side_effect = ServiceUnavailable("bolt://neo4j:secret@internal:7687 down")
    mock_repo.get_flow_observation.side_effect = ServiceUnavailable("bolt://neo4j:secret@internal:7687 down")
    r_lu = client.get(f"/api/v1/alert-events/{_EVENT_ID}")
    r_lf = client.get(f"/api/v1/flow-observations/{_OBS_ID}")
    assert r_lu.status_code == 503 and "secret" not in r_lu.text
    assert r_lf.status_code == 503 and "secret" not in r_lf.text

    # M. AuthError
    mock_repo.get_alert_event.side_effect = AuthError("password123 rejected for bolt://user")
    mock_repo.get_flow_observation.side_effect = AuthError("password123 rejected for bolt://user")
    r_au = client.get(f"/api/v1/alert-events/{_EVENT_ID}")
    r_af = client.get(f"/api/v1/flow-observations/{_OBS_ID}")
    assert r_au.status_code == 503 and "password123" not in r_au.text
    assert r_af.status_code == 503 and "password123" not in r_af.text


# ---------------------------------------------------------------------------
# N. Malformed Persisted Data Fails Closed (Sanitized HTTP 500 & Strict Models)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_override",
    [
        {"sid": "9100001"},  # strict int refuses string coercion
        {"sid": True},  # strict int refuses bool
        {"src_ip": "not-an-ip"},  # invalid IP
        {"routing_domain_id": "corp#sub"},  # '#' delimiter forbidden
        {"timestamp_epoch_decimal": 1795428002.123},  # float refuses Decimal str
        {"timestamp_epoch_decimal": "NaN"},  # non-finite Decimal
        {"flow_id": 8810001},  # flow_id must be string, not int
        {"flow_id": "007"},  # non-canonical leading zero
        {"src_scoped_id": "other-domain#192.0.2.10"},  # domain/scoped_id mismatch
    ],
)
def test_n_malformed_persisted_alert_fails_closed(bad_override):
    """Matrix N: Corrupt persisted AlertEvent values fail strict validation and return sanitized 500."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_alert_event.return_value = _sample_alert_record(**bad_override)

    res = client.get(f"/api/v1/alert-events/{_EVENT_ID}")
    assert res.status_code == 500
    assert res.json() == {"detail": "Internal server error"}

    with pytest.raises(ValidationError):
        AlertEventDetailResponse(**{
            k: v
            for k, v in _sample_alert_record(**bad_override).items()
            if k in AlertEventDetailResponse.model_fields
        })


@pytest.mark.parametrize(
    "bad_override",
    [
        {"orig_bytes": True},
        {"orig_bytes": -1},
        {"orig_bytes": "640"},
        {"start_epoch_decimal": 1795428000.5},
        {"duration_decimal": "Infinity"},
        {"src_ip": "invalid"},
        {"routing_domain_id": "   "},
        {"local_orig": "true"},
        {"dst_scoped_id": "wrong#198.51.100.20"},
    ],
)
def test_n_malformed_persisted_flow_fails_closed(bad_override):
    """Matrix N: Corrupt persisted FlowObservation values fail strict validation and return sanitized 500."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_flow_observation.return_value = _sample_flow_record(**bad_override)

    res = client.get(f"/api/v1/flow-observations/{_OBS_ID}")
    assert res.status_code == 500
    assert res.json() == {"detail": "Internal server error"}

    with pytest.raises(ValidationError):
        FlowObservationDetailResponse(**{
            k: v
            for k, v in _sample_flow_record(**bad_override).items()
            if k in FlowObservationDetailResponse.model_fields
        })


# ---------------------------------------------------------------------------
# O, P, Q, R. Precision, Lossless uint64 / Safe-Int Counters, Null Neutrality
# ---------------------------------------------------------------------------


def test_o_p_q_decimal_uint64_safe_int_and_no_ns_exposure():
    """Matrix O, P, Q: Exact Decimal strings, lossless uint64 flow_id, safe-int serializer, zero *_epoch_ns."""
    _, client, mock_repo = _client_with_mock_repo()

    # Include ultra-high precision Decimal, max uint64 flow_id, AND counter > JS Number.MAX_SAFE_INTEGER
    large_unsafe_count = JS_MAX_SAFE_INTEGER + 2  # 9007199254740993 (cannot fit exact IEEE-754 float64)
    mock_repo.get_alert_event.return_value = _sample_alert_record(
        timestamp_epoch_decimal="1795428002.123456789123456789",
        flow_id="18446744073709551615",
        pcap_cnt=large_unsafe_count,
    )
    mock_repo.get_flow_observation.return_value = _sample_flow_record(
        start_epoch_decimal="1795428000.12345678912345",
        end_epoch_decimal="1795428010.12345678912345",
        duration_decimal="10.0000000000000001",
        orig_bytes=640,
        resp_bytes=large_unsafe_count,
    )

    alert_res = client.get(f"/api/v1/alert-events/{_EVENT_ID}")
    assert alert_res.status_code == 200
    alert_raw = json.loads(alert_res.text)
    assert alert_raw["timestamp_epoch_decimal"] == "1795428002.123456789123456789"
    assert isinstance(alert_raw["flow_id"], str)
    assert alert_raw["flow_id"] == "18446744073709551615"
    assert alert_raw["sid"] == 9100001  # safe <= 2^53-1 remains JSON integer
    assert alert_raw["pcap_cnt"] == str(large_unsafe_count)  # > 2^53-1 serialized losslessly as string
    assert "timestamp_epoch_ns" not in alert_raw

    flow_res = client.get(f"/api/v1/flow-observations/{_OBS_ID}")
    assert flow_res.status_code == 200
    flow_raw = json.loads(flow_res.text)
    assert flow_raw["start_epoch_decimal"] == "1795428000.12345678912345"
    assert flow_raw["end_epoch_decimal"] == "1795428010.12345678912345"
    assert flow_raw["duration_decimal"] == "10.0000000000000001"
    assert flow_raw["orig_bytes"] == 640
    assert flow_raw["resp_bytes"] == str(large_unsafe_count)
    assert "start_epoch_ns" not in flow_raw
    assert "end_epoch_ns" not in flow_raw


def test_r_null_values_preserved_without_fabrication():
    """Matrix R: Absent optional fields remain JSON null rather than fabricated defaults."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.get_alert_event.return_value = _sample_alert_record(
        engine=None,
        gid=None,
        rev=None,
        signature=None,
        category=None,
        severity=None,
        action=None,
        app_proto=None,
        direction=None,
        tx_id=None,
        pcap_cnt=None,
        flow_id=None,
        protocol=None,
        src_port=None,
        dst_port=None,
        community_id=None,
        timestamp_epoch_decimal=None,
        source_provenance=None,
    )
    mock_repo.get_flow_observation.return_value = _sample_flow_record(
        src_port=None,
        dst_port=None,
        community_id=None,
        end_ts=None,
        start_epoch_decimal=None,
        end_epoch_decimal=None,
        duration_decimal=None,
        orig_bytes=None,
        resp_bytes=None,
        orig_ip_bytes=None,
        resp_ip_bytes=None,
        orig_pkts=None,
        resp_pkts=None,
        missed_bytes=None,
        service=None,
        conn_state=None,
        history=None,
        local_orig=None,
        local_resp=None,
        source_provenance=None,
    )

    alert_body = client.get(f"/api/v1/alert-events/{_EVENT_ID}").json()
    assert alert_body["engine"] is None
    assert alert_body["flow_id"] is None
    assert alert_body["timestamp_epoch_decimal"] is None
    assert alert_body["action"] is None

    flow_body = client.get(f"/api/v1/flow-observations/{_OBS_ID}").json()
    assert flow_body["orig_bytes"] is None
    assert flow_body["end_ts"] is None
    assert flow_body["conn_state"] is None
    assert flow_body["missed_bytes"] is None


# ---------------------------------------------------------------------------
# S. AlertDefinition Join: Factual, Non-Fabricated, Non-Contradictory
# ---------------------------------------------------------------------------


def test_s_alert_definition_missing_vs_matching_vs_contradictory():
    """Matrix S: Unlinked AlertDefinition keeps engine=None; contradictory definitions fail closed."""
    # Missing AlertDefinition -> engine=None (never fabricated from ae.source_type)
    row_no_def = _sample_alert_record(engine=None)
    row_no_def["alert_definitions"] = []

    mock_tx = MagicMock()
    res_mock = MagicMock()
    res_mock.single.return_value = row_no_def
    mock_tx.run.return_value = res_mock
    mock_session = MagicMock()
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jReadRepository(mock_driver)
    got = repo.get_alert_event(_EVENT_ID, source_type="suricata")
    assert got is not None
    assert got["engine"] is None

    # Contradictory multiple AlertDefinition nodes -> ValueError
    row_two_defs = _sample_alert_record()
    row_two_defs["alert_definitions"] = [
        {"definition_id": "suricata:demo-v2-rules:1:9100001", "engine": "suricata", "ruleset_namespace": "demo-v2-rules", "gid": 1, "sid": 9100001},
        {"definition_id": "suricata:other:1:9100001", "engine": "suricata", "ruleset_namespace": "other", "gid": 1, "sid": 9100001},
    ]
    res_mock.single.return_value = row_two_defs
    with pytest.raises(ValueError, match="Contradictory AlertDefinition relationships"):
        repo.get_alert_event(_EVENT_ID, source_type="suricata")

    # Contradictory engine / sid on linked AlertDefinition -> ValueError
    row_bad_def = _sample_alert_record()
    row_bad_def["alert_definitions"] = [
        {"definition_id": "suricata:demo-v2-rules:1:9100001", "engine": "snort", "ruleset_namespace": "demo-v2-rules", "gid": 1, "sid": 9100001},
    ]
    res_mock.single.return_value = row_bad_def
    with pytest.raises(ValueError, match="Contradictory AlertDefinition.engine"):
        repo.get_alert_event(_EVENT_ID, source_type="suricata")


# ---------------------------------------------------------------------------
# T. Read-Only Cypher & GET-Only Method Guarantee
# ---------------------------------------------------------------------------


def test_t_repository_queries_are_strictly_read_only_and_no_element_id():
    """Matrix T: Repository executes read-only transactions without writes or internal elementId exposure."""
    mock_tx = MagicMock()
    res_mock = MagicMock()
    res_mock.single.return_value = None
    mock_tx.run.return_value = res_mock
    mock_session = MagicMock()
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jReadRepository(mock_driver)
    repo.get_alert_event(_EVENT_ID, routing_domain_id="corp", source_type="suricata")
    alert_cypher = mock_tx.run.call_args.args[0]

    repo.get_flow_observation(_OBS_ID, routing_domain_id="corp", source_type="zeek")
    flow_cypher = mock_tx.run.call_args.args[0]

    assert mock_session.execute_read.call_count == 2
    mock_session.execute_write.assert_not_called()

    for cypher in (alert_cypher, flow_cypher):
        assert _FORBIDDEN_WRITE_CYPHER_RE.search(cypher) is None
        assert "elementId" not in cypher

    # HTTP GET-only check on endpoints
    _, client, _ = _client_with_mock_repo()
    assert client.post(f"/api/v1/alert-events/{_EVENT_ID}", json={}).status_code == 405
    assert client.post(f"/api/v1/flow-observations/{_OBS_ID}", json={}).status_code == 405


# ---------------------------------------------------------------------------
# U & V. V1 AlertFact Compatibility & Repository Hardening Check
# ---------------------------------------------------------------------------


def test_u_v_v1_alerts_route_unchanged_and_legacy_repo_calls_work():
    """Matrix U & V: Legacy V1 AlertFact routes and unfiltered repo calls continue working cleanly."""
    _, client, mock_repo = _client_with_mock_repo()
    mock_repo.list_alert_facts.return_value = (
        [
            {
                "fact_key": _FACT_KEY,
                "source_ip": "10.0.0.1",
                "target_ip": "10.0.0.2",
                "sid": 2100498,
                "gid": 1,
                "rev": 2,
                "message": "V1 legacy AlertFact",
                "priority": 1,
                "protocol": "TCP",
                "src_port": 12345,
                "dst_port": 80,
            }
        ],
        1,
    )
    mock_repo.get_alert_fact.return_value = {
        "fact_key": _FACT_KEY,
        "source_ip": "10.0.0.1",
        "target_ip": "10.0.0.2",
        "sid": 2100498,
        "gid": 1,
        "rev": 2,
        "message": "V1 legacy AlertFact",
        "priority": 1,
        "protocol": "TCP",
        "src_port": 12345,
        "dst_port": 80,
    }

    r_list = client.get("/api/v1/alerts")
    assert r_list.status_code == 200
    assert r_list.json()["items"][0]["fact_key"] == _FACT_KEY

    r_detail = client.get(f"/api/v1/alerts/{_FACT_KEY}")
    assert r_detail.status_code == 200
    assert r_detail.json()["message"] == "V1 legacy AlertFact"
    mock_repo.get_alert_event.assert_not_called()

    # Repository accepts invalid filter params fail-closed and still supports unscoped single-arg calls
    mock_tx = MagicMock()
    res_mock = MagicMock()
    res_mock.single.return_value = _sample_alert_record()
    mock_tx.run.return_value = res_mock
    mock_session = MagicMock()
    mock_session.execute_read.side_effect = lambda fn: fn(mock_tx)
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    repo = Neo4jReadRepository(mock_driver)
    assert repo.get_alert_event(_EVENT_ID)["event_id"] == _EVENT_ID
    with pytest.raises(ValueError, match="cannot contain delimiter '#'"):
        repo.get_alert_event(_EVENT_ID, routing_domain_id="bad#domain")
    with pytest.raises(ValueError, match="must not be empty or whitespace"):
        repo.get_flow_observation(_OBS_ID, routing_domain_id="   ")
