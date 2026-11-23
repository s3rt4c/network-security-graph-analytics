"""
Unit verification for Phase 4E deterministic synthetic V2 demo fixtures.

Exercises the real Zeek conn.log parser, Suricata EVE parser, Community ID derivation,
lossless Decimal precision, and Phase 4A pure-Python correlation decision engine
across Scenarios A through F without requiring Neo4j.
"""

from decimal import Decimal
from pathlib import Path

from src.correlation import (
    CandidateCompleteness,
    CorrelationPolicy,
    CorrelationStatus,
    TemporalRelation,
    correlate_alert_to_flows,
)
from src.ingestion.suricata_eve_parser import parse_suricata_eve_alert_file
from src.ingestion.zeek_conn_parser import parse_zeek_conn_file

_DEMO_DIR = Path(__file__).resolve().parent / "fixtures" / "demo_v2"
_CORP_DOMAIN = "demo-v2-corp"
_BRANCH_DOMAIN = "demo-v2-branch"
_ZEEK_SENSOR = "zeek-demo-01"
_SURICATA_SENSOR = "suricata-demo-01"
_RULESET_NS = "demo-v2-rules"


def test_demo_v2_fixtures_parse_deterministically_with_exact_precision():
    corp_flows, corp_flow_summary = parse_zeek_conn_file(
        _DEMO_DIR / "corp_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-zeek",
    )
    assert corp_flow_summary.total_raw_records == 7
    assert corp_flow_summary.valid_records == 7
    assert corp_flow_summary.skipped_records == 0
    assert len({flow.observation_id for flow in corp_flows}) == 7

    corp_alerts, corp_alert_summary = parse_suricata_eve_alert_file(
        _DEMO_DIR / "corp_eve.jsonl",
        sensor_id=_SURICATA_SENSOR,
        ruleset_namespace=_RULESET_NS,
        log_source_id="corp-eve-demo-01",
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-eve",
    )
    assert corp_alert_summary.total_raw_records == 6
    assert corp_alert_summary.valid_records == 5
    assert corp_alert_summary.ignored_non_alert_records == 1
    assert corp_alert_summary.skipped_records == 0
    assert len({alert.event_id for alert in corp_alerts}) == 5

    branch_flows, branch_flow_summary = parse_zeek_conn_file(
        _DEMO_DIR / "branch_conn.log.jsonl",
        sensor_id="zeek-branch-01",
        routing_domain_id=_BRANCH_DOMAIN,
        source_provenance="phase4e-branch-zeek",
    )
    assert branch_flow_summary.valid_records == 1
    assert branch_flow_summary.skipped_records == 0

    branch_alerts, branch_alert_summary = parse_suricata_eve_alert_file(
        _DEMO_DIR / "branch_eve.jsonl",
        sensor_id="suricata-branch-01",
        ruleset_namespace=_RULESET_NS,
        log_source_id="branch-eve-demo-01",
        routing_domain_id=_BRANCH_DOMAIN,
        source_provenance="phase4e-branch-eve",
    )
    assert branch_alert_summary.valid_records == 2
    assert branch_alert_summary.skipped_records == 0

    rival_flows, rival_summary = parse_zeek_conn_file(
        _DEMO_DIR / "corp_stale_rival_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-rival-zeek",
    )
    assert rival_summary.valid_records == 1
    assert rival_flows[0].zeek_uid == "CDemoCorpLifecycleRival02"

    # Re-parsing the same files yields identical deterministic IDs and derived Community IDs.
    corp_flows_repeat, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-zeek",
    )
    assert [f.observation_id for f in corp_flows_repeat] == [f.observation_id for f in corp_flows]

    strong_flow = next(f for f in corp_flows if f.zeek_uid == "CDemoCorpStrong01")
    strong_alert = next(a for a in corp_alerts if a.sid == 9100001)
    assert strong_flow.start_epoch == Decimal("1795428000.123456789")
    assert strong_alert.timestamp_epoch_decimal == Decimal("1795428002.123456789123")
    assert strong_flow.community_id is not None
    assert strong_flow.community_id == strong_alert.community_id


def test_demo_v2_scenarios_satisfy_phase4a_correlation_contracts():
    corp_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-zeek",
    )
    corp_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "corp_eve.jsonl",
        sensor_id=_SURICATA_SENSOR,
        ruleset_namespace=_RULESET_NS,
        log_source_id="corp-eve-demo-01",
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-eve",
    )
    branch_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "branch_conn.log.jsonl",
        sensor_id="zeek-branch-01",
        routing_domain_id=_BRANCH_DOMAIN,
        source_provenance="phase4e-branch-zeek",
    )
    branch_alerts, _ = parse_suricata_eve_alert_file(
        _DEMO_DIR / "branch_eve.jsonl",
        sensor_id="suricata-branch-01",
        ruleset_namespace=_RULESET_NS,
        log_source_id="branch-eve-demo-01",
        routing_domain_id=_BRANCH_DOMAIN,
        source_provenance="phase4e-branch-eve",
    )
    rival_flows, _ = parse_zeek_conn_file(
        _DEMO_DIR / "corp_stale_rival_conn.log.jsonl",
        sensor_id=_ZEEK_SENSOR,
        routing_domain_id=_CORP_DOMAIN,
        source_provenance="phase4e-corp-rival-zeek",
    )

    policy = CorrelationPolicy()
    all_initial_flows = corp_flows + branch_flows

    # Scenario A: Unique STRONG match + Decimal fallback (sub-nanosecond alert timestamp)
    alert_a = next(a for a in corp_alerts if a.sid == 9100001)
    dec_a = correlate_alert_to_flows(
        alert_a,
        all_initial_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_a.status == CorrelationStatus.STRONG
    assert dec_a.auto_correlate_allowed is True
    assert dec_a.selected_evidence is not None
    assert dec_a.selected_evidence.temporal_relation == TemporalRelation.WITHIN_INTERVAL
    assert dec_a.selected_evidence.temporal_delta_decimal == "0"
    assert dec_a.selected_evidence.used_decimal_fallback is True

    # Scenario B: Ambiguous candidates -> fail closed
    alert_b = next(a for a in corp_alerts if a.sid == 9100002)
    dec_b = correlate_alert_to_flows(
        alert_b,
        all_initial_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_b.status == CorrelationStatus.AMBIGUOUS
    assert dec_b.auto_correlate_allowed is False
    assert len(dec_b.strong_candidate_ids) == 2

    # Scenario C: RoutingDomain isolation across identical overlapping tuples & non-leaking corp-only flow
    alert_c1_corp = next(a for a in corp_alerts if a.sid == 9100003)
    dec_c1_corp = correlate_alert_to_flows(
        alert_c1_corp,
        all_initial_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_c1_corp.status == CorrelationStatus.STRONG
    assert dec_c1_corp.selected_observation_id == next(
        f.observation_id for f in corp_flows if f.zeek_uid == "CDemoCorpIsoFlow01"
    )

    alert_c1_branch = next(a for a in branch_alerts if a.sid == 9100003)
    dec_c1_branch = correlate_alert_to_flows(
        alert_c1_branch,
        all_initial_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_c1_branch.status == CorrelationStatus.STRONG
    assert dec_c1_branch.selected_observation_id == branch_flows[0].observation_id

    alert_c2_branch = next(a for a in branch_alerts if a.sid == 9100006)
    dec_c2_branch = correlate_alert_to_flows(
        alert_c2_branch,
        all_initial_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_c2_branch.status == CorrelationStatus.REJECTED
    assert dec_c2_branch.auto_correlate_allowed is False

    # Scenario D: Outside-window evidence fails closed
    alert_d = next(a for a in corp_alerts if a.sid == 9100004)
    dec_d = correlate_alert_to_flows(
        alert_d,
        all_initial_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_d.status == CorrelationStatus.REJECTED
    assert dec_d.auto_correlate_allowed is False

    # Scenarios E & F: Initial STRONG -> TRUNCATED INSUFFICIENT -> COMPLETE AMBIGUOUS with rival
    alert_ef = next(a for a in corp_alerts if a.sid == 9100005)
    dec_ef_initial = correlate_alert_to_flows(
        alert_ef,
        corp_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_ef_initial.status == CorrelationStatus.STRONG

    dec_ef_truncated = correlate_alert_to_flows(
        alert_ef,
        corp_flows,
        policy=CorrelationPolicy(candidate_cap=1),
        candidate_completeness=CandidateCompleteness.TRUNCATED,
    )
    assert dec_ef_truncated.status == CorrelationStatus.INSUFFICIENT
    assert dec_ef_truncated.auto_correlate_allowed is False

    dec_ef_rival = correlate_alert_to_flows(
        alert_ef,
        corp_flows + rival_flows,
        policy=policy,
        candidate_completeness=CandidateCompleteness.COMPLETE,
    )
    assert dec_ef_rival.status == CorrelationStatus.AMBIGUOUS
    assert dec_ef_rival.auto_correlate_allowed is False
