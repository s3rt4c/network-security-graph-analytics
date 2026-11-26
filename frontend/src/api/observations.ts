import { request } from './client';
import type {
  AlertEventDetailResponse,
  AlertEventTriageItemResponse,
  AlertEventTriageListParams,
  FlowObservationDetailResponse,
  SafePaginatedResponse,
} from './types';

/**
 * Retrieve paginated persisted V2 Suricata AlertEvent occurrences for independent triage (read-only).
 * Propagates ApiError on 422/503/500 rather than masking failures as empty results.
 */
export function listAlertEvents(
  params?: AlertEventTriageListParams,
  signal?: AbortSignal
): Promise<SafePaginatedResponse<AlertEventTriageItemResponse>> {
  return request<SafePaginatedResponse<AlertEventTriageItemResponse>>(
    '/api/v1/alert-events',
    { signal },
    {
      routing_domain_id: params?.routing_domain_id,
      severity: params?.severity,
      sid: params?.sid,
      sensor_id: params?.sensor_id,
      start_epoch_ns: params?.start_epoch_ns,
      end_epoch_ns: params?.end_epoch_ns,
      limit: params?.limit ?? 50,
      offset: params?.offset ?? 0,
    }
  );
}

/**
 * Retrieve persisted forensic details for a V2 Suricata AlertEvent (read-only).
 * Propagates ApiError on 404/422/503/500 rather than masking missing or unavailable data.
 */
export function getAlertEvent(
  eventId: string,
  routingDomainId?: string,
  signal?: AbortSignal
): Promise<AlertEventDetailResponse> {
  return request<AlertEventDetailResponse>(
    `/api/v1/alert-events/${encodeURIComponent(eventId)}`,
    { signal },
    { routing_domain_id: routingDomainId }
  );
}

/**
 * Retrieve persisted forensic details for a V2 Zeek FlowObservation (read-only).
 * Propagates ApiError on 404/422/503/500 rather than masking missing or unavailable data.
 */
export function getFlowObservation(
  observationId: string,
  routingDomainId?: string,
  signal?: AbortSignal
): Promise<FlowObservationDetailResponse> {
  return request<FlowObservationDetailResponse>(
    `/api/v1/flow-observations/${encodeURIComponent(observationId)}`,
    { signal },
    { routing_domain_id: routingDomainId }
  );
}
