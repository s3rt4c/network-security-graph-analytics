import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import {
  getAlertFlowCorrelationsForEvent,
  listAlertFlowCorrelations,
  listTrafficAlertCorrelations,
} from '../api/correlations';
import type { AlertFlowCorrelationResponse, PaginatedResponse } from '../api/types';

const SAMPLE_EVENT_ID = 'a'.repeat(64);
const SAMPLE_OBSERVATION_ID = 'b'.repeat(64);

function makeSampleCorrelation(
  overrides: Partial<AlertFlowCorrelationResponse> = {}
): AlertFlowCorrelationResponse {
  return {
    event_id: SAMPLE_EVENT_ID,
    observation_id: SAMPLE_OBSERVATION_ID,
    zeek_uid: 'C1234567890abcdef',
    routing_domain_id: 'default',
    correlation_method: 'EXACT_COMMUNITY_ID_TEMPORAL',
    evidence_version: 'v1',
    policy_fingerprint: 'c'.repeat(64),
    evidence_digest: 'd'.repeat(64),
    tuple_orientation: 'FORWARD',
    community_id_agreement: 'EXACT_MATCH',
    temporal_relation: 'WITHIN_FLOW_WINDOW',
    temporal_delta_decimal: '0.0001234500',
    used_decimal_fallback: false,
    sensor_context: 'suricata-edge:zeek-core',
    verification_status: 'verified',
    last_incomplete_reason: null,
    last_incomplete_at_utc: null,
    decided_at_utc: '2026-11-20T12:00:00Z',
    ...overrides,
  };
}

describe('Correlations API Client (V1 & V2)', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('preserves legacy V1 listTrafficAlertCorrelations route and parameters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ items: [], total: 0, limit: 25, offset: 50 }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    await listTrafficAlertCorrelations(25, 50, controller.signal);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/correlations/traffic-alerts?limit=25&offset=50');
    expect(init.signal).toBe(controller.signal);
  });

  it('calls listAlertFlowCorrelations with default pagination and omits unset optional params', async () => {
    const payload: PaginatedResponse<AlertFlowCorrelationResponse> = {
      items: [makeSampleCorrelation()],
      total: 1,
      limit: 50,
      offset: 0,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(payload),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await listAlertFlowCorrelations();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/correlations/alert-flows?limit=50&offset=0');
    expect(init.method).toBeUndefined();
    expect(res.items[0].temporal_delta_decimal).toBe('0.0001234500');
  });

  it('serializes verified-only default, include_unverified, filters, and escaping via URLSearchParams', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ items: [], total: 0, limit: 20, offset: 40 }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    await listAlertFlowCorrelations(
      {
        routing_domain_id: 'corp branch&1',
        event_id: SAMPLE_EVENT_ID,
        observation_id: SAMPLE_OBSERVATION_ID,
        include_unverified: false,
        verification_status: 'verified',
        limit: 20,
        offset: 40,
      },
      controller.signal
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = new URL(url, 'http://localhost');
    expect(parsed.pathname).toBe('/api/v1/correlations/alert-flows');
    expect(parsed.searchParams.get('routing_domain_id')).toBe('corp branch&1');
    expect(parsed.searchParams.get('event_id')).toBe(SAMPLE_EVENT_ID);
    expect(parsed.searchParams.get('observation_id')).toBe(SAMPLE_OBSERVATION_ID);
    expect(parsed.searchParams.get('include_unverified')).toBe('false');
    expect(parsed.searchParams.get('verification_status')).toBe('verified');
    expect(parsed.searchParams.get('limit')).toBe('20');
    expect(parsed.searchParams.get('offset')).toBe('40');
    expect(init.signal).toBe(controller.signal);
  });

  it('supports include_unverified=true and verification_status=unverified_incomplete', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          items: [makeSampleCorrelation({ verification_status: 'unverified_incomplete' })],
          total: 1,
          limit: 50,
          offset: 0,
        }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await listAlertFlowCorrelations({
      include_unverified: true,
      verification_status: 'unverified_incomplete',
    });

    const [url] = fetchMock.mock.calls[0] as [string];
    const parsed = new URL(url, 'http://localhost');
    expect(parsed.searchParams.get('include_unverified')).toBe('true');
    expect(parsed.searchParams.get('verification_status')).toBe('unverified_incomplete');
    expect(res.items[0].verification_status).toBe('unverified_incomplete');
  });

  it('encodes eventId path parameter and omits unset optionals in getAlertFlowCorrelationsForEvent', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    const res = await getAlertFlowCorrelationsForEvent(
      'abc/def?x=1',
      { routing_domain_id: 'dmz', include_unverified: true, limit: 10, offset: 5 },
      controller.signal
    );

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/v1/correlations/alert-flows/abc%2Fdef%3Fx%3D1?');
    const parsed = new URL(url, 'http://localhost');
    expect(parsed.searchParams.get('routing_domain_id')).toBe('dmz');
    expect(parsed.searchParams.get('include_unverified')).toBe('true');
    expect(parsed.searchParams.get('limit')).toBe('10');
    expect(parsed.searchParams.get('offset')).toBe('5');
    expect(parsed.searchParams.has('verification_status')).toBe(false);
    expect(init.signal).toBe(controller.signal);
    expect(res.items).toEqual([]);
    expect(res.total).toBe(0);
  });

  it('propagates 404, 422, 503, 500, and network failures as ApiError without hiding errors', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: () => Promise.resolve({ detail: `Suricata AlertEvent '${SAMPLE_EVENT_ID}' not found` }),
    }) as unknown as typeof fetch;

    await expect(getAlertFlowCorrelationsForEvent(SAMPLE_EVENT_ID)).rejects.toMatchObject({
      name: 'ApiError',
      status: 404,
      detail: `Suricata AlertEvent '${SAMPLE_EVENT_ID}' not found`,
    });

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Entity',
      json: () => Promise.resolve({ detail: 'Invalid routing_domain_id' }),
    }) as unknown as typeof fetch;

    await expect(listAlertFlowCorrelations({ routing_domain_id: ' ' })).rejects.toMatchObject({
      status: 422,
      detail: 'Invalid routing_domain_id',
    });

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      json: () => Promise.resolve({ detail: 'Database service unavailable' }),
    }) as unknown as typeof fetch;

    await expect(listAlertFlowCorrelations()).rejects.toBeInstanceOf(ApiError);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: () => Promise.resolve({ detail: 'Unexpected server failure' }),
    }) as unknown as typeof fetch;

    await expect(listAlertFlowCorrelations()).rejects.toMatchObject({
      status: 500,
    });

    globalThis.fetch = vi.fn().mockRejectedValueOnce(new Error('Network down')) as unknown as typeof fetch;

    await expect(listAlertFlowCorrelations()).rejects.toMatchObject({
      status: 0,
    });
  });
});
