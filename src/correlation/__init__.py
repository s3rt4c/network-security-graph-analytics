"""
Phase 4A Conservative Zeek–Suricata Correlation Engine (Neo4j-Independent).
"""

from src.correlation.models import (
    EVIDENCE_VERSION,
    AlertSnapshot,
    CandidateCompleteness,
    CandidateStrength,
    CommunityIdSeedPolicy,
    CommunityIdStatus,
    CorrelationCandidateEvidence,
    CorrelationDecision,
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
)
from src.correlation.engine import (
    alert_to_snapshot,
    correlate_alert_to_flows,
    evaluate_candidate,
    flow_to_snapshot,
    normalize_correlation_protocol,
)

__all__ = [
    "EVIDENCE_VERSION",
    "AlertSnapshot",
    "FlowSnapshot",
    "CandidateCompleteness",
    "CandidateStrength",
    "CommunityIdSeedPolicy",
    "CommunityIdStatus",
    "CorrelationCandidateEvidence",
    "CorrelationDecision",
    "CorrelationPolicy",
    "CorrelationStatus",
    "ProtocolStatus",
    "SensorPairingPolicy",
    "SensorPolicyMode",
    "SensorPolicyStatus",
    "TemporalRelation",
    "TupleCompleteness",
    "TupleOrientation",
    "alert_to_snapshot",
    "flow_to_snapshot",
    "normalize_correlation_protocol",
    "evaluate_candidate",
    "correlate_alert_to_flows",
]
