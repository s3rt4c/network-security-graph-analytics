"""
Unit tests for Phase 4A Conservative Zeek–Suricata Correlation Engine.

Pure Python tests (no Neo4j dependency). Covers all 26 explicit scenarios A–Z plus
completeness contracts, adapter normalization (domain models and read-repository dicts),
lossless boundaries, and architectural isolation checks.
"""

import ast
from dataclasses import replace
from decimal import Decimal, localcontext
from pathlib import Path
import pytest

from src.correlation import (
    EVIDENCE_VERSION,
    AlertSnapshot,
    CandidateCompleteness,
    CandidateStrength,
    CommunityIdSeedPolicy,
    CommunityIdStatus,
    CorrelationPolicy,
    CorrelationStatus,
    FlowSnapshot,
    ProtocolStatus,
    SensorPairingPolicy,
    SensorPolicyMode,
    SensorPolicyStatus,
    TemporalRelation,
    TupleCompleteness,
    TupleOrientation,
    correlate_alert_to_flows,
    evaluate_candidate,
)
from src.ingestion.community_id import compute_community_id
from src.ingestion.v2_models import (
    SuricataAlertObservation,
    ZeekConnectionObservation,
    alert_definition_id,
    compute_alert_event_id,
    compute_observation_id,
    compute_v2_flow_key,
    scoped_ip_id,
)


def _make_flow(
    *,
    obs_id: str = "obs-1",
    zeek_uid: str = "CZeek001",
    domain: str = "corp",
    sensor_id: str = "zeek-01",
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    protocol: str = "TCP",
    src_port: int | None = 54321,
    dst_port: int | None = 443,
    community_id: str | None = None,
    use_default_cid: bool = True,
    start_epoch: Decimal | None = Decimal("1795184100.000000"),
    duration: Decimal | None = Decimal("20.000000"),
    end_epoch: Decimal | None = Decimal("1795184120.000000"),
    source_provenance: str | None = "zeek-batch",
) -> ZeekConnectionObservation:
    src_scoped = scoped_ip_id(domain, src_ip)
    dst_scoped = scoped_ip_id(domain, dst_ip)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, protocol, src_port, dst_port)
    cid = community_id
    if cid is None and use_default_cid:
        cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return ZeekConnectionObservation(
        observation_id=obs_id,
        flow_key=fk,
        zeek_uid=zeek_uid,
        routing_domain_id=domain,
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        start_ts="1795184100.000000" if start_epoch is None else str(start_epoch),
        src_port=src_port,
        dst_port=dst_port,
        community_id=cid,
        start_epoch=start_epoch,
        duration=duration,
        end_epoch=end_epoch,
        end_ts=None if end_epoch is None else str(end_epoch),
        sensor_id=sensor_id,
        source_type="zeek",
        source_provenance=source_provenance,
    )


def _make_alert(
    *,
    event_id: str = "ev-1",
    domain: str = "corp",
    sensor_id: str = "suricata-01",
    ruleset_namespace: str = "et-open",
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    protocol: str | None = "TCP",
    src_port: int | None = 54321,
    dst_port: int | None = 443,
    community_id: str | None = None,
    use_default_cid: bool = True,
    timestamp_source: str = "2026-11-20T14:15:10.000000+0000",
    timestamp_epoch_decimal: Decimal | None = Decimal("1795184110.000000"),
    sid: int = 2001219,
) -> SuricataAlertObservation:
    src_scoped = scoped_ip_id(domain, src_ip)
    dst_scoped = scoped_ip_id(domain, dst_ip)
    fk = compute_v2_flow_key(src_scoped, dst_scoped, protocol or "UNKNOWN", src_port, dst_port)
    def_id = alert_definition_id("suricata", ruleset_namespace, 1, sid)
    cid = community_id
    if cid is None and use_default_cid and protocol is not None:
        cid = compute_community_id(src_ip, dst_ip, protocol, src_port, dst_port, seed=0)
    return SuricataAlertObservation(
        event_id=event_id,
        alert_definition_id=def_id,
        source_record_id=f"eve:line:1:{event_id}",
        log_source_id="eve-main",
        sensor_id=sensor_id,
        ruleset_namespace=ruleset_namespace,
        routing_domain_id=domain,
        flow_key=fk,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_scoped_id=src_scoped,
        dst_scoped_id=dst_scoped,
        timestamp_source=timestamp_source,
        timestamp_epoch_decimal=timestamp_epoch_decimal,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        community_id=cid,
        gid=1,
        sid=sid,
        rev=1,
        signature="SYNTHETIC Rule",
        severity=2,
        source_type="suricata",
    )


# ---------------------------------------------------------------------------
# A & B. Valid Forward & Reverse TCP Matches
# ---------------------------------------------------------------------------

def test_a_one_valid_forward_tcp_match():
    alert = _make_alert()
    flow = _make_flow(obs_id="obs-fwd")
    dec = correlate_alert_to_flows(alert, [flow])

    assert dec.status == CorrelationStatus.STRONG
    assert dec.auto_correlate_allowed is True
    assert dec.selected_observation_id == "obs-fwd"
    assert dec.strong_candidate_ids == ("obs-fwd",)
    assert dec.plausible_rival_ids == ()
    assert dec.selected_evidence is not None
    assert dec.selected_evidence.tuple_orientation == TupleOrientation.FORWARD
    assert dec.selected_evidence.tuple_completeness == TupleCompleteness.COMPLETE_5TUPLE
    assert dec.selected_evidence.community_id_status == CommunityIdStatus.MATCH
    assert dec.selected_evidence.temporal_relation == TemporalRelation.WITHIN_INTERVAL
    assert dec.selected_evidence.temporal_delta_decimal == "0"
    assert dec.evidence_version == EVIDENCE_VERSION
    assert len(dec.policy_fingerprint) == 64


def test_b_one_valid_reverse_tcp_match():
    # Suricata alert triggered on server response packet (reverse of Zeek orig->resp)
    alert = _make_alert(
        src_ip="198.51.100.20",
        dst_ip="192.0.2.10",
        src_port=443,
        dst_port=54321,
    )
    flow = _make_flow(
        obs_id="obs-rev",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=54321,
        dst_port=443,
    )
    assert alert.flow_key != flow.flow_key  # Directional flow_key differs cleanly!
    dec = correlate_alert_to_flows(alert, [flow])

    assert dec.status == CorrelationStatus.STRONG
    assert dec.auto_correlate_allowed is True
    assert dec.selected_observation_id == "obs-rev"
    assert dec.selected_evidence is not None
    assert dec.selected_evidence.tuple_orientation == TupleOrientation.REVERSE
    assert dec.selected_evidence.community_id_status == CommunityIdStatus.MATCH


# ---------------------------------------------------------------------------
# C & D. Temporal Separation vs Overlapping Sessions with Same CID
# ---------------------------------------------------------------------------

def test_c_same_cid_different_time_rejected():
    alert = _make_alert(timestamp_epoch_decimal=Decimal("1795184500"))
    flow = _make_flow(
        obs_id="obs-old",
        start_epoch=Decimal("1795184100"),
        end_epoch=Decimal("1795184120"),
    )
    dec = correlate_alert_to_flows(alert, [flow])
    assert dec.status == CorrelationStatus.REJECTED
    assert dec.auto_correlate_allowed is False
    assert dec.selected_observation_id is None
    assert dec.candidate_evidences[0].temporal_relation == TemporalRelation.OUTSIDE_WINDOW


def test_d_same_cid_overlapping_sessions_ambiguous():
    alert = _make_alert(timestamp_epoch_decimal=Decimal("1795184110"))
    f1 = _make_flow(obs_id="obs-1", zeek_uid="Z1", start_epoch=Decimal("1795184100"), end_epoch=Decimal("1795184120"))
    f2 = _make_flow(obs_id="obs-2", zeek_uid="Z2", start_epoch=Decimal("1795184105"), end_epoch=Decimal("1795184125"))

    dec = correlate_alert_to_flows(alert, [f1, f2])
    assert dec.status == CorrelationStatus.AMBIGUOUS
    assert dec.auto_correlate_allowed is False
    assert dec.selected_observation_id is None
    assert dec.strong_candidate_ids == ("obs-1", "obs-2")
    assert "MULTIPLE_STRONG_CANDIDATES" in dec.decision_reasons


# ---------------------------------------------------------------------------
# E. Cross-Domain Isolation
# ---------------------------------------------------------------------------

def test_e_same_tuple_different_routing_domains_rejected():
    alert = _make_alert(domain="corp", src_ip="10.0.0.5", dst_ip="10.0.0.20")
    flow = _make_flow(domain="branch", src_ip="10.0.0.5", dst_ip="10.0.0.20")
    assert alert.community_id == flow.community_id

    dec = correlate_alert_to_flows(alert, [flow])
    assert dec.status == CorrelationStatus.REJECTED
    assert dec.auto_correlate_allowed is False
    assert dec.candidate_evidences[0].domain_matched is False
    assert "ROUTING_DOMAIN_MISMATCH" in dec.candidate_evidences[0].reasons


# ---------------------------------------------------------------------------
# F, G, H, I. Missing Community ID & Competing Plausible Rivals
# ---------------------------------------------------------------------------

def test_f_missing_community_id_on_alert_tcp():
    alert = _make_alert(use_default_cid=False, community_id=None)
    flow = _make_flow(obs_id="obs-1")

    dec_default = correlate_alert_to_flows(alert, [flow])
    assert dec_default.status == CorrelationStatus.STRONG
    assert dec_default.selected_evidence is not None
    assert dec_default.selected_evidence.community_id_status == CommunityIdStatus.MISSING_ALERT

    strict_policy = CorrelationPolicy(require_community_id=True)
    dec_strict = correlate_alert_to_flows(alert, [flow], policy=strict_policy)
    assert dec_strict.status == CorrelationStatus.INSUFFICIENT
    assert dec_strict.auto_correlate_allowed is False


def test_g_missing_community_id_on_zeek_flow_tcp():
    alert = _make_alert()
    flow = _make_flow(obs_id="obs-no-cid", use_default_cid=False, community_id=None)

    dec_default = correlate_alert_to_flows(alert, [flow])
    assert dec_default.status == CorrelationStatus.STRONG
    assert dec_default.selected_evidence is not None
    assert dec_default.selected_evidence.community_id_status == CommunityIdStatus.MISSING_FLOW

    dec_strict = correlate_alert_to_flows(alert, [flow], policy=CorrelationPolicy(require_community_id=True))
    assert dec_strict.status == CorrelationStatus.INSUFFICIENT


def test_h_cid_matching_flow_plus_plausible_missing_cid_flow_never_declares_unique():
    alert = _make_alert()
    f_cid = _make_flow(obs_id="obs-cid")
    f_missing_cid = _make_flow(obs_id="obs-missing-cid", zeek_uid="Z2", use_default_cid=False, community_id=None)

    # Under default policy: both F1 and F2 satisfy complete 5-tuple + time -> 2 STRONG -> AMBIGUOUS
    dec_default = correlate_alert_to_flows(alert, [f_cid, f_missing_cid])
    assert dec_default.status == CorrelationStatus.AMBIGUOUS
    assert dec_default.auto_correlate_allowed is False
    assert dec_default.selected_observation_id is None
    assert dec_default.strong_candidate_ids == ("obs-cid", "obs-missing-cid")

    # Under require_community_id=True: F1 is STRONG, F2 is plausible unresolved INSUFFICIENT rival -> STILL AMBIGUOUS!
    dec_req_cid = correlate_alert_to_flows(
        alert, [f_cid, f_missing_cid], policy=CorrelationPolicy(require_community_id=True)
    )
    assert dec_req_cid.status == CorrelationStatus.AMBIGUOUS
    assert dec_req_cid.auto_correlate_allowed is False
    assert dec_req_cid.selected_observation_id is None
    assert dec_req_cid.strong_candidate_ids == ("obs-cid",)
    assert dec_req_cid.plausible_rival_ids == ("obs-missing-cid",)
    assert "STRONG_WITH_PLAUSIBLE_UNRESOLVED_RIVAL" in dec_req_cid.decision_reasons


def test_i_one_strong_plus_one_temporally_unverifiable_rival_is_ambiguous():
    alert = _make_alert()
    f_strong = _make_flow(obs_id="obs-strong")
    f_no_epoch = _make_flow(
        obs_id="obs-unverifiable",
        zeek_uid="Z2",
        start_epoch=None,
        duration=None,
        end_epoch=None,
    )
    dec = correlate_alert_to_flows(alert, [f_strong, f_no_epoch])
    assert dec.status == CorrelationStatus.AMBIGUOUS
    assert dec.auto_correlate_allowed is False
    assert dec.strong_candidate_ids == ("obs-strong",)
    assert dec.plausible_rival_ids == ("obs-unverifiable",)


# ---------------------------------------------------------------------------
# J & K. Conflicting Community IDs & Seed Policies
# ---------------------------------------------------------------------------

def test_j_conflicting_community_ids_rejected():
    alert = _make_alert(community_id="1:AlertHashAAA=")
    flow = _make_flow(community_id="1:FlowHashBBB=")

    dec = correlate_alert_to_flows(alert, [flow])
    assert dec.status == CorrelationStatus.REJECTED
    assert dec.auto_correlate_allowed is False
    assert dec.candidate_evidences[0].community_id_status == CommunityIdStatus.CONFLICT


def test_k_different_seed_policies():
    alert_cid_42 = compute_community_id("192.0.2.10", "198.51.100.20", "TCP", 54321, 443, seed=42)
    flow_cid_0 = compute_community_id("192.0.2.10", "198.51.100.20", "TCP", 54321, 443, seed=0)

    alert = _make_alert(community_id=alert_cid_42)
    flow = _make_flow(community_id=flow_cid_0)

    # 1. Default STRICT_SAME_SEED -> REJECTED
    dec_strict = correlate_alert_to_flows(alert, [flow])
    assert dec_strict.status == CorrelationStatus.REJECTED

    # 2. VERIFY_SEED_PAIR with matching seeds -> STRONG (VERIFIED_SEED_OFFSET)
    verified_policy = CorrelationPolicy(
        community_id_seed_policy=CommunityIdSeedPolicy.VERIFY_SEED_PAIR,
        zeek_community_id_seed=0,
        suricata_community_id_seed=42,
    )
    dec_verified = correlate_alert_to_flows(alert, [flow], policy=verified_policy)
    assert dec_verified.status == CorrelationStatus.STRONG
    assert dec_verified.auto_correlate_allowed is True
    assert dec_verified.selected_evidence is not None
    assert dec_verified.selected_evidence.community_id_status == CommunityIdStatus.VERIFIED_SEED_OFFSET

    # 3. VERIFY_SEED_PAIR with wrong seeds -> REJECTED
    wrong_seed_policy = CorrelationPolicy(
        community_id_seed_policy=CommunityIdSeedPolicy.VERIFY_SEED_PAIR,
        zeek_community_id_seed=0,
        suricata_community_id_seed=99,
    )
    dec_wrong = correlate_alert_to_flows(alert, [flow], policy=wrong_seed_policy)
    assert dec_wrong.status == CorrelationStatus.REJECTED

    # 4. ALLOW_UNVERIFIED_TUPLE_FALLBACK -> NEVER promoted to STRONG -> INSUFFICIENT
    fallback_policy = CorrelationPolicy(
        community_id_seed_policy=CommunityIdSeedPolicy.ALLOW_UNVERIFIED_TUPLE_FALLBACK
    )
    dec_fallback = correlate_alert_to_flows(alert, [flow], policy=fallback_policy)
    assert dec_fallback.status == CorrelationStatus.INSUFFICIENT
    assert dec_fallback.auto_correlate_allowed is False
    assert dec_fallback.candidate_evidences[0].community_id_status == CommunityIdStatus.MISMATCH_SEED_UNVERIFIED


# ---------------------------------------------------------------------------
# L, M, N, O, P, Q. Temporal Precision & Opt-In Defaults
# ---------------------------------------------------------------------------

def test_l_missing_suricata_timezone_insufficient():
    alert = _make_alert(
        timestamp_source="2026-11-20T14:15:10.000000",
        timestamp_epoch_decimal=None,
    )
    flow = _make_flow()
    dec = correlate_alert_to_flows(alert, [flow])
    assert dec.status == CorrelationStatus.INSUFFICIENT
    assert dec.auto_correlate_allowed is False
    assert "MISSING_SURICATA_TIMEZONE" in dec.decision_reasons


def test_m_missing_zeek_end_epoch_requires_explicit_opt_in():
    flow = _make_flow(start_epoch=Decimal("1795184100.000000"), duration=None, end_epoch=None)
    alert_at_start = _make_alert(timestamp_epoch_decimal=Decimal("1795184100.000000"))
    alert_near = _make_alert(timestamp_epoch_decimal=Decimal("1795184102.000000"))

    # Default policy (allow_missing_zeek_end=False) classifies near/exact-start match as INSUFFICIENT
    dec_default_exact = correlate_alert_to_flows(alert_at_start, [flow])
    assert dec_default_exact.status == CorrelationStatus.INSUFFICIENT
    assert dec_default_exact.auto_correlate_allowed is False
    assert dec_default_exact.candidate_evidences[0].temporal_relation == TemporalRelation.NEAR_START_NO_END

    # Nonzero point_observation_post_tolerance without opt-in remains INSUFFICIENT
    near_no_opt_in = CorrelationPolicy(
        point_observation_post_tolerance_sec=Decimal("5"),
        allow_missing_zeek_end=False,
    )
    dec_near_no_opt = correlate_alert_to_flows(alert_near, [flow], policy=near_no_opt_in)
    assert dec_near_no_opt.status == CorrelationStatus.INSUFFICIENT
    assert dec_near_no_opt.auto_correlate_allowed is False
    assert dec_near_no_opt.candidate_evidences[0].temporal_relation == TemporalRelation.NEAR_START_NO_END

    # With allow_missing_zeek_end=True and point_post=5s: inside 5s => STRONG, outside 5s => REJECTED
    opt_in = CorrelationPolicy(
        point_observation_post_tolerance_sec=Decimal("5"),
        allow_missing_zeek_end=True,
    )
    dec_near = correlate_alert_to_flows(alert_near, [flow], policy=opt_in)
    assert dec_near.status == CorrelationStatus.STRONG
    assert dec_near.auto_correlate_allowed is True
    assert dec_near.selected_evidence is not None
    assert dec_near.selected_evidence.temporal_relation == TemporalRelation.NEAR_START_NO_END
    assert dec_near.selected_evidence.temporal_delta_decimal == "2"

    far_alert = _make_alert(timestamp_epoch_decimal=Decimal("1795184130.000000"))
    dec_far = correlate_alert_to_flows(far_alert, [flow], policy=opt_in)
    assert dec_far.status == CorrelationStatus.REJECTED


def test_n_and_o_nonzero_tolerance_opt_in_disabled_vs_enabled():
    flow = _make_flow(start_epoch=Decimal("1795184100"), end_epoch=Decimal("1795184120"))
    pre_alert = _make_alert(timestamp_epoch_decimal=Decimal("1795184098.5"))
    post_alert = _make_alert(timestamp_epoch_decimal=Decimal("1795184123.25"))

    # Default strict policy: outside exact [start, end] => REJECTED
    assert correlate_alert_to_flows(pre_alert, [flow]).status == CorrelationStatus.REJECTED
    assert correlate_alert_to_flows(post_alert, [flow]).status == CorrelationStatus.REJECTED

    # Scenario N: Nonzero tolerances configured, allow_tolerance_match=False => INSUFFICIENT
    tol_no_opt_in = CorrelationPolicy(
        pre_start_tolerance_sec=Decimal("2"),
        post_end_tolerance_sec=Decimal("5"),
        allow_tolerance_match=False,
    )
    dec_pre_no = correlate_alert_to_flows(pre_alert, [flow], policy=tol_no_opt_in)
    assert dec_pre_no.status == CorrelationStatus.INSUFFICIENT
    assert dec_pre_no.auto_correlate_allowed is False
    assert dec_pre_no.candidate_evidences[0].temporal_relation == TemporalRelation.WITHIN_PRE_TOLERANCE
    assert dec_pre_no.candidate_evidences[0].temporal_delta_decimal == "-1.5"

    dec_post_no = correlate_alert_to_flows(post_alert, [flow], policy=tol_no_opt_in)
    assert dec_post_no.status == CorrelationStatus.INSUFFICIENT
    assert dec_post_no.candidate_evidences[0].temporal_relation == TemporalRelation.WITHIN_POST_TOLERANCE
    assert dec_post_no.candidate_evidences[0].temporal_delta_decimal == "3.25"

    # Scenario O: With explicit allow_tolerance_match=True => STRONG
    tol_opt_in = CorrelationPolicy(
        pre_start_tolerance_sec=Decimal("2"),
        post_end_tolerance_sec=Decimal("5"),
        allow_tolerance_match=True,
    )
    dec_pre_yes = correlate_alert_to_flows(pre_alert, [flow], policy=tol_opt_in)
    assert dec_pre_yes.status == CorrelationStatus.STRONG
    assert dec_pre_yes.auto_correlate_allowed is True
    assert dec_pre_yes.selected_evidence is not None
    assert dec_pre_yes.selected_evidence.temporal_delta_decimal == "-1.5"

    dec_post_yes = correlate_alert_to_flows(post_alert, [flow], policy=tol_opt_in)
    assert dec_post_yes.status == CorrelationStatus.STRONG
    assert dec_post_yes.selected_evidence is not None
    assert dec_post_yes.selected_evidence.temporal_delta_decimal == "3.25"


def test_p_and_q_sub_nanosecond_and_low_decimal_context_precision():
    t_start = Decimal("1795184100.1234567890000000000000000001")
    t_alert_in = Decimal("1795184100.1234567890000000000000000005")
    t_end = Decimal("1795184100.1234567890000000000000000009")
    t_alert_out = Decimal("1795184100.1234567890000000000000000010")

    flow = _make_flow(start_epoch=t_start, duration=Decimal("0.0000000000000000000000000008"), end_epoch=t_end)
    alert_in = _make_alert(timestamp_epoch_decimal=t_alert_in)
    alert_out = _make_alert(timestamp_epoch_decimal=t_alert_out)

    # Low active Decimal precision (prec=1) must NOT round away >30-digit differences!
    with localcontext() as ctx:
        ctx.prec = 1
        dec_in = correlate_alert_to_flows(alert_in, [flow])
        dec_out = correlate_alert_to_flows(
            alert_out,
            [flow],
            policy=CorrelationPolicy(post_end_tolerance_sec=Decimal("0"), allow_tolerance_match=True),
        )

    assert dec_in.status == CorrelationStatus.STRONG
    assert dec_in.selected_evidence is not None
    assert dec_in.selected_evidence.used_decimal_fallback is True
    assert dec_in.selected_evidence.temporal_relation == TemporalRelation.WITHIN_INTERVAL

    assert dec_out.status == CorrelationStatus.REJECTED
    assert dec_out.candidate_evidences[0].temporal_delta_decimal == "0.0000000000000000000000000001"


# ---------------------------------------------------------------------------
# R & S. ICMPv6 Protocol Aliases & Missing Ports
# ---------------------------------------------------------------------------

def test_r_icmpv6_protocol_alias_bridging_and_missing_cid_fail_closed():
    cid = compute_community_id("2001:db8::1", "2001:db8::2", "ICMP6", src_port=128, dst_port=0, seed=0)
    # Zeek records "ICMP" on IPv6 with type/code in src_port/dst_port; Suricata records "IPV6-ICMP" with None ports
    flow = _make_flow(
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        protocol="ICMP",
        src_port=128,
        dst_port=0,
        community_id=cid,
        use_default_cid=False,
    )
    alert = _make_alert(
        src_ip="2001:db8::2",
        dst_ip="2001:db8::1",
        protocol="IPV6-ICMP",
        src_port=None,
        dst_port=None,
        community_id=cid,
        use_default_cid=False,
    )
    dec = correlate_alert_to_flows(alert, [flow])
    assert dec.status == CorrelationStatus.STRONG
    assert dec.auto_correlate_allowed is True
    assert dec.selected_evidence is not None
    assert dec.selected_evidence.protocol_status == ProtocolStatus.IPV6_ICMP_ALIAS_MATCH
    assert dec.selected_evidence.tuple_completeness == TupleCompleteness.ICMP_VIA_CID
    assert dec.selected_evidence.tuple_orientation == TupleOrientation.REVERSE

    # Missing CID on Suricata ICMPv6 must NOT treat None ports as wildcard/match -> INSUFFICIENT
    alert_no_cid = replace(alert, community_id=None)
    dec_no_cid = correlate_alert_to_flows(alert_no_cid, [flow])
    assert dec_no_cid.status == CorrelationStatus.INSUFFICIENT
    assert dec_no_cid.auto_correlate_allowed is False


def test_s_missing_tcp_or_udp_ports_insufficient():
    alert_no_sport = _make_alert(protocol="UDP", src_port=None, dst_port=53, use_default_cid=False, community_id=None)
    flow = _make_flow(protocol="UDP", src_port=53000, dst_port=53, use_default_cid=False, community_id=None)

    dec = correlate_alert_to_flows(alert_no_sport, [flow])
    assert dec.status == CorrelationStatus.INSUFFICIENT
    assert dec.auto_correlate_allowed is False
    assert dec.candidate_evidences[0].tuple_completeness == TupleCompleteness.PARTIAL_PORTS


# ---------------------------------------------------------------------------
# T, U, V. Multi-Sensor Session, Explicit Pairing & NAT Transformation
# ---------------------------------------------------------------------------

def test_t_and_u_multiple_sensors_ambiguous_vs_explicit_pairing():
    alert = _make_alert(sensor_id="Suricata-Edge-1")
    f_edge = _make_flow(obs_id="obs-edge", zeek_uid="Z-edge", sensor_id="Zeek-Edge-1")
    f_core = _make_flow(obs_id="obs-core", zeek_uid="Z-core", sensor_id="Zeek-Core-1")

    # Scenario T: ANY_IN_DOMAIN sees two matching sensors -> AMBIGUOUS
    dec_any = correlate_alert_to_flows(alert, [f_edge, f_core])
    assert dec_any.status == CorrelationStatus.AMBIGUOUS
    assert dec_any.auto_correlate_allowed is False
    assert "MULTIPLE_STRONG_CANDIDATES_MULTI_SENSOR" in dec_any.decision_reasons

    # Scenario U: Explicit pairing isolates suricata-edge-1 -> zeek-edge-1 -> STRONG
    paired_policy = CorrelationPolicy(
        sensor_policy=SensorPairingPolicy.from_explicit_pairs({"suricata-edge-1": ["zeek-edge-1"]})
    )
    dec_paired = correlate_alert_to_flows(alert, [f_edge, f_core], policy=paired_policy)
    assert dec_paired.status == CorrelationStatus.STRONG
    assert dec_paired.auto_correlate_allowed is True
    assert dec_paired.selected_observation_id == "obs-edge"


def test_v_nat_transformed_endpoints_rejected():
    alert_nat = _make_alert(src_ip="203.0.113.9", dst_ip="198.51.100.20", src_port=62000, dst_port=443)
    flow_lan = _make_flow(src_ip="10.0.0.5", dst_ip="198.51.100.20", src_port=51000, dst_port=443)

    dec = correlate_alert_to_flows(alert_nat, [flow_lan])
    assert dec.status == CorrelationStatus.REJECTED
    assert dec.auto_correlate_allowed is False
    assert "IP_ENDPOINT_MISMATCH" in dec.candidate_evidences[0].reasons


# ---------------------------------------------------------------------------
# W, X, Y, Z. Completeness, Duplicates, Order-Independence & Invalid Policies
# ---------------------------------------------------------------------------

def test_w_candidate_cap_exceeded_and_non_complete_signals_fail_closed():
    alert = _make_alert()
    f1 = _make_flow(obs_id="obs-1", zeek_uid="Z1")
    f2 = _make_flow(obs_id="obs-2", zeek_uid="Z2", src_port=11111)  # Rejected non-matching port

    # candidate_cap=1 with 2 unique candidates must fail closed even though f2 would reject
    dec_cap = correlate_alert_to_flows(alert, [f1, f2], policy=CorrelationPolicy(candidate_cap=1))
    assert dec_cap.status == CorrelationStatus.INSUFFICIENT
    assert dec_cap.auto_correlate_allowed is False
    assert dec_cap.candidate_cap_exceeded is True
    assert "CANDIDATE_CAP_EXCEEDED" in dec_cap.decision_reasons

    # Non-COMPLETE candidate completeness signals must never declare STRONG or REJECTED
    for comp in (
        CandidateCompleteness.TRUNCATED,
        CandidateCompleteness.RETRIEVAL_ERROR,
        CandidateCompleteness.UNKNOWN,
    ):
        dec_comp = correlate_alert_to_flows(alert, [f1], candidate_completeness=comp)
        assert dec_comp.status == CorrelationStatus.INSUFFICIENT
        assert dec_comp.auto_correlate_allowed is False
        assert dec_comp.selected_observation_id is None


def test_x_duplicate_observation_id_inputs():
    alert = _make_alert()
    f1 = _make_flow(obs_id="obs-dup")
    f1_same = _make_flow(obs_id="obs-dup")

    # Identical duplicate candidates deduplicate cleanly under cap=1
    dec = correlate_alert_to_flows(alert, [f1, f1_same], policy=CorrelationPolicy(candidate_cap=1))
    assert dec.status == CorrelationStatus.STRONG
    assert dec.candidate_count_evaluated == 1
    assert dec.candidate_cap_exceeded is False

    # Conflicting records claiming the same observation_id raise ValueError
    f1_tampered = replace(f1, src_port=60000)
    with pytest.raises(ValueError, match="Conflicting duplicate candidate flow"):
        correlate_alert_to_flows(alert, [f1, f1_tampered])


def test_y_deterministic_result_regardless_of_candidate_order():
    alert = _make_alert()
    flows = [
        _make_flow(obs_id="obs-c", zeek_uid="Z3", src_port=54321),
        _make_flow(obs_id="obs-a", zeek_uid="Z1", src_port=54321),
        _make_flow(obs_id="obs-b", zeek_uid="Z2", src_port=9999),  # rejected
    ]
    d1 = correlate_alert_to_flows(alert, flows)
    d2 = correlate_alert_to_flows(alert, list(reversed(flows)))
    assert d1 == d2
    assert d1.strong_candidate_ids == ("obs-a", "obs-c")
    assert [ev.observation_id for ev in d1.candidate_evidences] == ["obs-a", "obs-c", "obs-b"]


def test_z_invalid_policy_configurations_rejected():
    for kwargs in [
        {"pre_start_tolerance_sec": Decimal("-1")},
        {"post_end_tolerance_sec": Decimal("NaN")},
        {"post_end_tolerance_sec": 1.5},
        {"pre_start_tolerance_sec": True},
        {"allow_tolerance_match": 1},
        {"allow_missing_zeek_end": "yes"},
        {"candidate_cap": 0},
        {"candidate_cap": True},
        {"max_evidences_returned": 0},
        {"evidence_version": "  "},
        {"community_id_seed_policy": CommunityIdSeedPolicy.VERIFY_SEED_PAIR},  # missing seeds
        {"zeek_community_id_seed": 0},  # seeds without VERIFY_SEED_PAIR
        {
            "community_id_seed_policy": CommunityIdSeedPolicy.VERIFY_SEED_PAIR,
            "zeek_community_id_seed": 70000,
            "suricata_community_id_seed": 0,
        },
        {"allow_default_domain": "true"},
    ]:
        with pytest.raises(ValueError):
            CorrelationPolicy(**kwargs)

    with pytest.raises(ValueError):
        SensorPairingPolicy(mode=SensorPolicyMode.EXPLICIT_PAIRS, explicit_pairs=())
    with pytest.raises(ValueError):
        SensorPairingPolicy.from_explicit_pairs({"s1": []})
    with pytest.raises(ValueError):
        SensorPairingPolicy.any_in_domain(pair_clock_offsets={("s1", "z1"): 1.0})  # type: ignore[dict-item]


# ---------------------------------------------------------------------------
# Additional Boundary, Adapter, Clock Offset & Architecture Isolation Tests
# ---------------------------------------------------------------------------

def test_read_repository_dict_inputs_and_beyond_int64_ns():
    # Timestamps beyond year 2262 (INT64_MAX ns) have *_epoch_ns=None in read_repository dicts
    alert_dict = {
        "event_id": "ae-dict-1",
        "routing_domain_id": "corp",
        "sensor_id": "suricata-1",
        "src_ip": "2001:0db8::1",
        "dst_ip": "2001:0db8::2",
        "protocol": "tcp",
        "src_port": 50000,
        "dst_port": 443,
        "community_id": compute_community_id("2001:db8::1", "2001:db8::2", "TCP", 50000, 443),
        "timestamp_source": "2300-01-01T00:00:05+0000",
        "timestamp_epoch_decimal": "10413792005",
        "timestamp_epoch_ns": None,
    }
    flow_dict = {
        "observation_id": "fo-dict-1",
        "zeek_uid": "CZ999",
        "routing_domain_id": "corp",
        "sensor_id": "zeek-1",
        "src_ip": "2001:db8::1",
        "dst_ip": "2001:db8::2",
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": 443,
        "community_id": compute_community_id("2001:db8::1", "2001:db8::2", "TCP", 50000, 443),
        "start_ts": "10413792000",
        "start_epoch_decimal": "10413792000",
        "end_epoch_decimal": "10413792010",
        "duration_decimal": "10",
        "start_epoch_ns": None,
        "end_epoch_ns": None,
    }
    dec = correlate_alert_to_flows(alert_dict, [flow_dict])
    assert dec.status == CorrelationStatus.STRONG
    assert dec.selected_evidence is not None
    assert dec.selected_evidence.used_decimal_fallback is True
    assert dec.selected_evidence.temporal_relation == TemporalRelation.WITHIN_INTERVAL

    # Float timestamp input in dict must be explicitly rejected
    bad_alert = dict(alert_dict, timestamp_epoch_decimal=1795184110.5)
    with pytest.raises(ValueError, match="float"):
        correlate_alert_to_flows(bad_alert, [flow_dict])


def test_sensor_clock_offset_same_sensor_mode_self_loop_and_default_domain_guard():
    # Per-pair measured clock offset shifts Suricata +10s skew cleanly inside interval
    flow = _make_flow(
        obs_id="obs-loop",
        domain="default",
        sensor_id="sensor-1",
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=9000,
        dst_port=9000,
        start_epoch=Decimal("100"),
        end_epoch=Decimal("110"),
    )
    alert_skewed = _make_alert(
        domain="default",
        sensor_id="sensor-1",
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=9000,
        dst_port=9000,
        timestamp_epoch_decimal=Decimal("95"),  # -5s ahead unless offset +10s applied
    )
    policy_offset = CorrelationPolicy(
        sensor_policy=SensorPairingPolicy.same_sensor_id(
            pair_clock_offsets={("sensor-1", "sensor-1"): Decimal("10")}
        ),
        allow_default_domain=True,
    )
    dec_ok = correlate_alert_to_flows(alert_skewed, [flow], policy=policy_offset)
    assert dec_ok.status == CorrelationStatus.STRONG
    assert dec_ok.selected_evidence is not None
    assert dec_ok.selected_evidence.tuple_orientation == TupleOrientation.SYMMETRIC
    assert dec_ok.selected_evidence.sensor_policy_status == SensorPolicyStatus.MATCHED_SAME_SENSOR
    assert "DEFAULT_ROUTING_DOMAIN_USED" in dec_ok.decision_reasons

    # Strict multi-tenant mode rejecting "default" domain
    policy_no_default = replace(policy_offset, allow_default_domain=False)
    dec_blocked = correlate_alert_to_flows(alert_skewed, [flow], policy=policy_no_default)
    assert dec_blocked.status == CorrelationStatus.INSUFFICIENT
    assert "DEFAULT_ROUTING_DOMAIN_DISALLOWED" in dec_blocked.decision_reasons


def test_correlation_package_has_no_neo4j_or_graph_imports():
    corr_dir = Path(__file__).resolve().parent.parent / "src" / "correlation"
    py_files = sorted(corr_dir.glob("*.py"))
    assert len(py_files) >= 3
    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("neo4j")
                    assert not alias.name.startswith("src.graph")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not mod.startswith("neo4j")
                assert not mod.startswith("src.graph")
