import { request } from './client';
import type {
  AlertFlowCorrelationEventParams,
  AlertFlowCorrelationListParams,
  AlertFlowCorrelationResponse,
  PaginatedResponse,
  TrafficAlertCorrelationResponse,
} from './types';

export function listTrafficAlertCorrelations(
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<TrafficAlertCorrelationResponse>> {
  return request<PaginatedResponse<TrafficAlertCorrelationResponse>>(
    '/api/v1/correlations/traffic-alerts',
    { signal },
    { limit, offset }
  );
}

/**
 * Retrieve persisted V2 Suricata AlertEvent to Zeek FlowObservation correlations (read-only).
 * Backend defaults to verified-only results unless include_unverified=true or
 * verification_status='unverified_incomplete' is specified.
 */
export function listAlertFlowCorrelations(
  params: AlertFlowCorrelationListParams = {},
  signal?: AbortSignal
): Promise<PaginatedResponse<AlertFlowCorrelationResponse>> {
  return request<PaginatedResponse<AlertFlowCorrelationResponse>>(
    '/api/v1/correlations/alert-flows',
    { signal },
    {
      limit: params.limit ?? 50,
      offset: params.offset ?? 0,
      routing_domain_id: params.routing_domain_id,
      event_id: params.event_id,
      observation_id: params.observation_id,
      include_unverified: params.include_unverified,
      verification_status: params.verification_status,
    }
  );
}

/**
 * Retrieve persisted V2 correlations for a specific Suricata AlertEvent (read-only).
 * Throws ApiError(404) if the requested AlertEvent does not exist (or is not in routing_domain_id),
 * whereas HTTP 200 with zero items means the AlertEvent exists with no matching persisted edges.
 */
export function getAlertFlowCorrelationsForEvent(
  eventId: string,
  params: AlertFlowCorrelationEventParams = {},
  signal?: AbortSignal
): Promise<PaginatedResponse<AlertFlowCorrelationResponse>> {
  return request<PaginatedResponse<AlertFlowCorrelationResponse>>(
    `/api/v1/correlations/alert-flows/${encodeURIComponent(eventId)}`,
    { signal },
    {
      limit: params.limit ?? 50,
      offset: params.offset ?? 0,
      routing_domain_id: params.routing_domain_id,
      include_unverified: params.include_unverified,
      verification_status: params.verification_status,
    }
  );
}
