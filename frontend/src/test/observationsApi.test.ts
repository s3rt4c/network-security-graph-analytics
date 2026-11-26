import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import { getAlertEvent, getFlowObservation } from '../api/observations';
import type { AlertEventDetailResponse, FlowObservationDetailResponse } from '../api/types';

const SAMPLE_EVENT_ID = 'a'.repeat(64);
const SAMPLE_OBS_ID = 'b'.repeat(64);

function makeAlertDetail(
  overrides: Partial<AlertEventDetailResponse> = {}
): AlertEventDetailResponse {
  return {
    event_id: SAMPLE_EVENT_ID,
    alert_definition_id: 'suricata:demo-v2-rules:1:9100001',
    source_record_id: '8810001',
    log_source_id: 'corp-eve-demo-01',
    sensor_id: 'suricata-demo-01',
    ruleset_namespace: 'demo-v2-rules',
    routing_domain_id: 'demo-v2-corp',
    source_type: 'suricata',
    source_provenance: 'phase4e-corp-eve',
    engine: 'suricata',
    gid: 1,
    sid: 9100001,
    rev: 1,
    signature: 'SYNTHETIC Demo Strong Match TLS Observation',
    category: 'Not Suspicious Traffic',
    severity: 3,
    action: 'allowed',
    app_proto: 'tls',
    direction: 'to_server',
    tx_id: 0,
    pcap_cnt: 11,
    flow_id: '18446744073709551615',
    src_ip: '192.0.2.10',
    dst_ip: '198.51.100.20',
    src_scoped_id: 'demo-v2-corp#192.0.2.10',
    dst_scoped_id: 'demo-v2-corp#198.51.100.20',
    protocol: 'TCP',
    src_port: 54321,
    dst_port: 443,
    flow_key: 'c'.repeat(64),
    community_id: '1:cid==',
    timestamp_source: '2026-11-23T10:00:02.123456789123+0000',
    timestamp_epoch_decimal: '1795428002.123456789123',
    ...overrides,
  };
}

function makeFlowDetail(
  overrides: Partial<FlowObservationDetailResponse> = {}
): FlowObservationDetailResponse {
  return {
    observation_id: SAMPLE_OBS_ID,
    flow_key: 'c'.repeat(64),
    zeek_uid: 'CDemoCorpStrong01',
    routing_domain_id: 'demo-v2-corp',
    sensor_id: 'zeek-demo-01',
    source_type: 'zeek',
    source_provenance: 'phase4e-corp-zeek',
    community_id: '1:cid==',
    src_ip: '192.0.2.10',
    dst_ip: '198.51.100.20',
    src_scoped_id: 'demo-v2-corp#192.0.2.10',
    dst_scoped_id: 'demo-v2-corp#198.51.100.20',
    protocol: 'TCP',
    src_port: 54321,
    dst_port: 443,
    start_ts: '1795428000.123456789',
    end_ts: '1795428010.123456789',
    start_epoch_decimal: '1795428000.123456789',
    end_epoch_decimal: '1795428010.123456789',
    duration_decimal: '10',
    orig_bytes: 640,
    resp_bytes: 2400,
    orig_ip_bytes: 928,
    resp_ip_bytes: 2736,
    orig_pkts: 7,
    resp_pkts: 8,
    missed_bytes: 0,
    service: 'ssl',
    conn_state: 'SF',
    history: 'ShADadFf',
    local_orig: true,
    local_resp: false,
    ...overrides,
  };
}

describe('Observations Detail API Client (V2)', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('fetches AlertEvent details with path encoding, optional routing_domain_id, and AbortSignal', async () => {
    const payload = makeAlertDetail();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(payload),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    const res = await getAlertEvent(SAMPLE_EVENT_ID, 'corp#scope&1', controller.signal);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = new URL(url, 'http://localhost');
    expect(parsed.pathname).toBe(`/api/v1/alert-events/${SAMPLE_EVENT_ID}`);
    expect(parsed.searchParams.get('routing_domain_id')).toBe('corp#scope&1');
    expect(init.method).toBeUndefined();
    expect(init.signal).toBe(controller.signal);
    expect(res.timestamp_epoch_decimal).toBe('1795428002.123456789123');
    expect(res.flow_id).toBe('18446744073709551615');
  });

  it('omits routing_domain_id query param when undefined and encodes path ID safely', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(makeFlowDetail()),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await getFlowObservation('obs/with space');
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/flow-observations/obs%2Fwith%20space');
  });

  it('fetches FlowObservation details cleanly and forwards AbortSignal', async () => {
    const payload = makeFlowDetail();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(payload),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const controller = new AbortController();
    const res = await getFlowObservation(SAMPLE_OBS_ID, 'demo-v2-corp', controller.signal);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`/api/v1/flow-observations/${SAMPLE_OBS_ID}?routing_domain_id=demo-v2-corp`);
    expect(init.signal).toBe(controller.signal);
    expect(res.start_epoch_decimal).toBe('1795428000.123456789');
    expect(res.orig_bytes).toBe(640);
  });

  it.each([
    [404, 'Not found'],
    [422, 'Validation failed'],
    [503, 'Database service unavailable'],
    [500, 'Internal server error'],
  ])('propagates ApiError HTTP %s without masking failures', async (statusCode, detail) => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: statusCode,
      statusText: 'Error',
      json: () => Promise.resolve({ detail }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(getAlertEvent(SAMPLE_EVENT_ID, 'demo-v2-corp')).rejects.toMatchObject({
      name: 'ApiError',
      status: statusCode,
      detail,
    });
    await expect(getFlowObservation(SAMPLE_OBS_ID, 'demo-v2-corp')).rejects.toBeInstanceOf(ApiError);
  });
});
