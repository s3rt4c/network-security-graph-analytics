/**
 * TypeScript interfaces mirroring the FastAPI backend Pydantic models.
 *
 * IMPORTANT: Nullable backend fields are typed explicitly as `T | null`
 * to accurately reflect JSON serialization.
 */

// System health & readiness
export interface HealthResponse {
  status: string;
  app: string;
}

export interface ReadyResponse {
  status: string;
  database: string;
}

// Traffic metrics mode
export type TrafficMetricsMode = 'none' | 'basic' | 'enriched' | 'mixed';

// Network & topology
export interface IPAddressResponse {
  address: string;
}

export interface IPDetailResponse {
  address: string;
  layer2_identifiers: string[];
  outbound_flows: number;
  inbound_flows: number;
  alerts_originated: number;
  alerts_targeted: number;
  traffic_metrics_mode: TrafficMetricsMode;
  distinct_outbound_peers: number;
  distinct_inbound_peers: number;
  distinct_destination_ports: number;
  observed_packets_sent: number | null;
  observed_packets_received: number | null;
  observed_bytes_sent: number | null;
  observed_bytes_received: number | null;
  first_observed: number | null;
  last_observed: number | null;
}

export interface PeerResponse {
  peer_address: string;
  direction: 'outbound' | 'inbound';
  protocols: string[];
}

export interface Layer2IdentifierResponse {
  identifier: string;
}

export interface CommunicationResponse {
  source_ip: string;
  target_ip: string;
  protocol: string;
  flow_key: string | null;
  src_port: number | null;
  dst_port: number | null;
  observed_packet_count: number | null;
  observed_bytes: number | null;
  first_seen: number | null;
  last_seen: number | null;
  observed_window_seconds: number | null;
}

// Traffic analytics (Phase 7C)
export interface ProtocolDistributionItem {
  protocol: string;
  communication_aggregate_count: number;
  observed_packet_count: number | null;
  observed_bytes: number | null;
}

export interface DestinationPortDistributionItem {
  dst_port: number;
  communication_aggregate_count: number;
  observed_packet_count: number | null;
  observed_bytes: number | null;
}

export interface FanOutItem {
  address: string;
  distinct_destination_ips: number;
}

export interface FanInItem {
  address: string;
  distinct_source_ips: number;
}

export interface TrafficAnalyticsSummaryResponse {
  traffic_metrics_mode: TrafficMetricsMode;
  total_communication_aggregates: number;
  enriched_communication_aggregates: number;
  basic_communication_aggregates: number;
  total_observed_packets: number | null;
  total_observed_bytes: number | null;
  first_observed: number | null;
  last_observed: number | null;
  protocol_distribution: ProtocolDistributionItem[];
  destination_port_distribution: DestinationPortDistributionItem[];
  top_fan_out: FanOutItem[];
  top_fan_in: FanInItem[];
}

export interface EndpointAnalyticsResponse {
  address: string;
  outbound_communication_aggregates: number;
  inbound_communication_aggregates: number;
  distinct_outbound_peers: number;
  distinct_inbound_peers: number;
  distinct_destination_ports: number;
  observed_packets_sent: number | null;
  observed_packets_received: number | null;
  observed_bytes_sent: number | null;
  observed_bytes_received: number | null;
  first_observed: number | null;
  last_observed: number | null;
  traffic_metrics_mode: TrafficMetricsMode;
}

// Security alerts & correlation
export interface AlertFactResponse {
  fact_key: string;
  source_ip: string;
  target_ip: string;
  sid: number | null;
  gid: number | null;
  rev: number | null;
  message: string | null;
  priority: number | null;
  protocol: string | null;
  src_port: number | null;
  dst_port: number | null;
}

export interface TrafficAlertCorrelationResponse {
  source_ip: string;
  target_ip: string;
  traffic_protocol: string;
  traffic_flow_key: string | null;
  traffic_src_port: number | null;
  traffic_dst_port: number | null;
  fact_key: string;
  sid: number | null;
  message: string | null;
  priority: number | null;
  alert_protocol: string | null;
}

export type CorrelationVerificationStatus = 'verified' | 'unverified_incomplete';

/** Count integer serialized losslessly as number up to 2^53-1 or string when larger. */
export type SafeCount = number | string;

export interface AlertEventDetailResponse {
  event_id: string;
  alert_definition_id: string;
  source_record_id: string;
  log_source_id: string;
  sensor_id: string;
  ruleset_namespace: string;
  routing_domain_id: string;
  source_type: 'suricata';
  source_provenance: string | null;
  engine: string | null;
  gid: SafeCount | null;
  sid: SafeCount;
  rev: SafeCount | null;
  signature: string | null;
  category: string | null;
  severity: SafeCount | null;
  action: string | null;
  app_proto: string | null;
  direction: string | null;
  tx_id: SafeCount | null;
  pcap_cnt: SafeCount | null;
  flow_id: string | null;
  src_ip: string;
  dst_ip: string;
  src_scoped_id: string;
  dst_scoped_id: string;
  protocol: string | null;
  src_port: number | null;
  dst_port: number | null;
  flow_key: string;
  community_id: string | null;
  timestamp_source: string;
  /** Exact arbitrary-precision Decimal epoch seconds string (never coerce to number). */
  timestamp_epoch_decimal: string | null;
}

export interface AlertEventTriageItemResponse {
  event_id: string;
  routing_domain_id: string;
  source_type: 'suricata';
  sensor_id: string;
  sid: SafeCount;
  signature: string | null;
  severity: SafeCount | null;
  category: string | null;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  timestamp_source: string;
  /** Exact arbitrary-precision Decimal epoch seconds string (never coerce to number). */
  timestamp_epoch_decimal: string | null;
  /**
   * Factual graph presence of >= 1 persisted CORRELATED_WITH edge.
   * False means no persisted link is recorded; it does not establish REJECTED, AMBIGUOUS,
   * INSUFFICIENT, benign traffic, or lack of evaluation.
   */
  has_persisted_correlation: boolean;
}

export interface AlertEventTriageListParams {
  routing_domain_id?: string;
  severity?: SafeCount;
  sid?: SafeCount;
  sensor_id?: string;
  start_epoch_ns?: SafeCount;
  end_epoch_ns?: SafeCount;
  limit?: number;
  offset?: SafeCount;
}

export interface FlowObservationDetailResponse {
  observation_id: string;
  flow_key: string;
  zeek_uid: string;
  routing_domain_id: string;
  sensor_id: string;
  source_type: 'zeek';
  source_provenance: string | null;
  community_id: string | null;
  src_ip: string;
  dst_ip: string;
  src_scoped_id: string;
  dst_scoped_id: string;
  protocol: string;
  src_port: number | null;
  dst_port: number | null;
  start_ts: string;
  /** Derived last-observed timestamp (start_epoch + duration; not confirmed TCP close). */
  end_ts: string | null;
  /** Exact arbitrary-precision Decimal start epoch seconds string (never coerce to number). */
  start_epoch_decimal: string | null;
  /** Exact arbitrary-precision Decimal last-observed epoch seconds string (never coerce to number). */
  end_epoch_decimal: string | null;
  /** Exact arbitrary-precision Decimal duration seconds string (never coerce to number). */
  duration_decimal: string | null;
  orig_bytes: SafeCount | null;
  resp_bytes: SafeCount | null;
  orig_ip_bytes: SafeCount | null;
  resp_ip_bytes: SafeCount | null;
  orig_pkts: SafeCount | null;
  resp_pkts: SafeCount | null;
  missed_bytes: SafeCount | null;
  service: string | null;
  conn_state: string | null;
  history: string | null;
  local_orig: boolean | null;
  local_resp: boolean | null;
}

export interface AlertFlowCorrelationResponse {
  event_id: string;
  observation_id: string;
  zeek_uid: string | null;
  routing_domain_id: string;
  correlation_method: string | null;
  evidence_version: string | null;
  policy_fingerprint: string | null;
  evidence_digest: string | null;
  tuple_orientation: string | null;
  community_id_agreement: string | null;
  temporal_relation: string | null;
  /** Exact canonical Decimal temporal delta string in seconds (never coerce to number). */
  temporal_delta_decimal: string | null;
  used_decimal_fallback: boolean | null;
  sensor_context: string | null;
  verification_status: CorrelationVerificationStatus;
  last_incomplete_reason: string | null;
  last_incomplete_at_utc: string | null;
  decided_at_utc: string | null;
}

export interface AlertFlowCorrelationListParams {
  routing_domain_id?: string;
  event_id?: string;
  observation_id?: string;
  include_unverified?: boolean;
  verification_status?: CorrelationVerificationStatus;
  limit?: number;
  offset?: number;
}

export interface AlertFlowCorrelationEventParams {
  routing_domain_id?: string;
  include_unverified?: boolean;
  verification_status?: CorrelationVerificationStatus;
  limit?: number;
  offset?: number;
}

// Graph traversal & topology
export interface GraphNodeResponse {
  id: string;
  type: 'IPAddress' | 'Layer2Identifier';
  value: string;
}

export interface GraphEdgeResponse {
  source: string;
  target: string;
  type: 'COMMUNICATED_TO' | 'OBSERVED_WITH';
  protocol: string | null;
  flow_key: string | null;
  src_port: number | null;
  dst_port: number | null;
  observed_packet_count: number | null;
  observed_bytes: number | null;
  first_seen: number | null;
  last_seen: number | null;
  observed_window_seconds: number | null;
}

export interface GraphNeighborhoodResponse {
  center: string;
  depth: number;
  nodes: GraphNodeResponse[];
  edges: GraphEdgeResponse[];
}

export interface PathResponse {
  source: string;
  target: string;
  hops: string[];
  protocols: string[];
  length: number;
}

// Generic pagination envelope
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

/** Strict pagination envelope preserving lossless strings when counts exceed 2^53-1. */
export interface SafePaginatedResponse<T> {
  items: T[];
  total: SafeCount;
  limit: number;
  offset: SafeCount;
}

// Data import & workspace replacement (Phase 6.5)
export interface ImportStatusResponse {
  enabled: boolean;
  max_file_size_bytes: number;
  max_file_size_mb: number;
}

export interface FileValidationResult {
  provided: boolean;
  filename: string | null;
  total_raw_records: number | null;
  valid_records: number | null;
  skipped_records: number | null;
  duplicate_records: number | null;
  warning_counts: Record<string, number>;
  sample_errors: string[];
}

export interface ImportValidationResponse {
  valid: boolean;
  can_import: boolean;
  traffic: FileValidationResult;
  alerts: FileValidationResult;
  message: string;
}

export interface ImportCapabilities {
  network_topology: boolean;
  ip_investigation: boolean;
  communication_paths: boolean;
  alert_facts: boolean;
  traffic_alert_correlations: boolean;
}

export interface ImportResultResponse {
  success: boolean;
  workspace_replaced: boolean;
  traffic_records_persisted: number;
  alert_facts_persisted: number;
  capabilities: ImportCapabilities;
  message: string;
}
