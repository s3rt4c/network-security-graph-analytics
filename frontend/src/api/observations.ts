import { request } from './client';
import type { AlertEventDetailResponse, FlowObservationDetailResponse } from './types';

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
