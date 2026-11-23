import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { CorrelationsPage } from '../pages/CorrelationsPage';
import type { AlertFlowCorrelationResponse } from '../api/types';

const EVENT_ID_1 = 'a'.repeat(64);
const EVENT_ID_2 = 'e'.repeat(64);
const OBS_ID_1 = 'b'.repeat(64);
const OBS_ID_2 = 'f'.repeat(64);
const POLICY_FP = 'c'.repeat(64);
const EVIDENCE_DIGEST_1 = 'd'.repeat(64);
const EVIDENCE_DIGEST_2 = '1'.repeat(64);

const LEGACY_V1_CORRELATION = {
  source_ip: '192.168.1.100',
  target_ip: '192.168.1.1',
  traffic_protocol: 'TCP',
  traffic_flow_key: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  traffic_src_port: 54321,
  traffic_dst_port: 22,
  fact_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  sid: 2001219,
  message: 'ET SCAN Potential SSH Scan',
  priority: 1,
  alert_protocol: 'TCP',
};

function makeV2Record(
  overrides: Partial<AlertFlowCorrelationResponse> = {}
): AlertFlowCorrelationResponse {
  return {
    event_id: EVENT_ID_1,
    observation_id: OBS_ID_1,
    zeek_uid: 'CzeekUid12345',
    routing_domain_id: 'default',
    correlation_method: 'EXACT_COMMUNITY_ID_TEMPORAL',
    evidence_version: 'v1',
    policy_fingerprint: POLICY_FP,
    evidence_digest: EVIDENCE_DIGEST_1,
    tuple_orientation: 'FORWARD',
    community_id_agreement: 'EXACT_MATCH',
    temporal_relation: 'WITHIN_FLOW_WINDOW',
    temporal_delta_decimal: '0.000123450000000001',
    used_decimal_fallback: false,
    sensor_context: 'suricata-edge:zeek-core',
    verification_status: 'verified',
    last_incomplete_reason: null,
    last_incomplete_at_utc: null,
    decided_at_utc: '2026-11-20T12:00:00Z',
    ...overrides,
  };
}

function mockJsonResponse(body: unknown, status: number = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 404 ? 'Not Found' : status === 503 ? 'Service Unavailable' : 'OK',
    json: () => Promise.resolve(body),
  });
}

describe('CorrelationsPage Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // Scenarios A & B: Preserve existing V1 behavior and API untouched
  it('renders correlation records and uses neutral correlation wording', async () => {
    const mockCorrelations = {
      items: [LEGACY_V1_CORRELATION],
      total: 1,
      limit: 50,
      offset: 0,
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockCorrelations),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const onNavigate = vi.fn();
    render(<CorrelationsPage onNavigate={onNavigate} />);

    await waitFor(() => {
      expect(screen.getByText('ET SCAN Potential SSH Scan')).toBeInTheDocument();
      expect(screen.getByText('192.168.1.100')).toBeInTheDocument();
      expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
      expect(screen.getByText('54321 → 22')).toBeInTheDocument();
      expect(screen.getByText('abcdef12…')).toBeInTheDocument();
    });

    // Verify footer wording is "correlation records", NOT "pairs"
    expect(screen.getByText(/correlation records/i)).toBeInTheDocument();
    expect(screen.queryByText(/correlated pairs/i)).not.toBeInTheDocument();

    // Verify V1 endpoint and onNavigate actions remain intact
    expect((fetchMock.mock.calls[0] as [string])[0]).toBe(
      '/api/v1/correlations/traffic-alerts?limit=50&offset=0'
    );
    fireEvent.click(screen.getByRole('button', { name: /Graph/i }));
    expect(onNavigate).toHaveBeenCalledWith('network', { centerIp: '192.168.1.100' });
  });

  // Scenarios C, D, E, F: V2 tab loads verified default, supports include_unverified & status filters
  it('loads verified V2 correlations by default and supports unverified & status filters', async () => {
    const verifiedItem = makeV2Record();
    const unverifiedItem = makeV2Record({
      event_id: EVENT_ID_2,
      observation_id: OBS_ID_2,
      zeek_uid: 'CzeekIncomplete99',
      verification_status: 'unverified_incomplete',
      last_incomplete_reason: 'MISSING_OBSERVATION_END_TS',
      last_incomplete_at_utc: '2026-11-21T08:15:00Z',
    });

    const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [LEGACY_V1_CORRELATION], total: 1, limit: 50, offset: 0 });
      }
      if (url.includes('verification_status=unverified_incomplete')) {
        return mockJsonResponse({ items: [unverifiedItem], total: 1, limit: 50, offset: 0 });
      }
      if (url.includes('include_unverified=true')) {
        return mockJsonResponse({
          items: [verifiedItem, unverifiedItem],
          total: 2,
          limit: 50,
          offset: 0,
        });
      }
      return mockJsonResponse({ items: [verifiedItem], total: 1, limit: 50, offset: 0 });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    render(<CorrelationsPage />);

    // Wait for default V1 tab first, then switch to V2 tab
    await waitFor(() => {
      expect(screen.getByText('ET SCAN Potential SSH Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    // Safe default: include_unverified=false, verified badge & non-causation notices shown
    await waitFor(() => {
      expect(screen.getByText('CzeekUid12345')).toBeInTheDocument();
      expect(within(screen.getByRole('table')).getByText('Verified')).toBeInTheDocument();
    });

    const initialV2Url = fetchMock.mock.calls
      .map((c) => String(c[0]))
      .find((u) => u.includes('/alert-flows'));
    expect(initialV2Url).toContain('/api/v1/correlations/alert-flows?');
    expect(initialV2Url).toContain('include_unverified=false');
    expect(screen.getByText(/Safe default active/i)).toBeInTheDocument();
    expect(
      screen.getByText((_content, node) =>
        Boolean(
          node?.classList?.contains('info-banner') &&
            /Correlation is not proof of causation, not proof of compromise, and does not determine attacker or victim roles\./i.test(
              node.textContent || ''
            )
        )
      )
    ).toBeInTheDocument();

    // Explicitly include unverified correlations
    const includeCheckbox = screen.getByLabelText(/Include unverified correlations/i);
    fireEvent.click(includeCheckbox);
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    await waitFor(() => {
      expect(screen.getByText('CzeekIncomplete99')).toBeInTheDocument();
      expect(
        within(screen.getByRole('table')).getByText('Previously Verified — Current Check Incomplete')
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText(/latest reevaluation could not establish completeness/i)
    ).toBeInTheDocument();

    // Exact verification_status=unverified_incomplete filter
    fireEvent.change(screen.getByLabelText(/Verification Status/i), {
      target: { value: 'unverified_incomplete' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    await waitFor(() => {
      expect(screen.queryByText('CzeekUid12345')).not.toBeInTheDocument();
      expect(screen.getByText('CzeekIncomplete99')).toBeInTheDocument();
    });

    // Verify all network requests were read-only (no write endpoints or POST/PUT/DELETE)
    for (const [, init] of fetchMock.mock.calls) {
      const method = (init as RequestInit | undefined)?.method ?? 'GET';
      expect(method.toUpperCase()).toBe('GET');
    }
  });

  // Scenarios G, H, I, J: Domain, Event ID, Observation ID filtering, inline validation & pagination reset
  it('validates domain/SHA-256 filters fail-closed and resets pagination on filter change', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (url.includes(`/alert-flows/${EVENT_ID_2}`)) {
        return mockJsonResponse({
          items: [makeV2Record({ event_id: EVENT_ID_2, zeek_uid: 'CzeekEventOnly' })],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      if (url.includes('offset=50')) {
        return mockJsonResponse({
          items: [makeV2Record({ zeek_uid: 'CzeekPage2Item', routing_domain_id: 'default' })],
          total: 75,
          limit: 50,
          offset: 50,
        });
      }
      if (url.includes('routing_domain_id=corp')) {
        return mockJsonResponse({
          items: [makeV2Record({ routing_domain_id: 'corp', zeek_uid: 'CzeekCorpDomain' })],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return mockJsonResponse({
        items: [makeV2Record({ zeek_uid: 'CzeekPage1Item' })],
        total: 75,
        limit: 50,
        offset: 0,
      });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    render(<CorrelationsPage />);
    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    await waitFor(() => {
      expect(screen.getByText('CzeekPage1Item')).toBeInTheDocument();
    });

    // Advance to page 2 (offset=50)
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => {
      expect(screen.getByText('CzeekPage2Item')).toBeInTheDocument();
    });

    // Fail-closed validation: blank whitespace RoutingDomain must NOT trigger fetch
    const callsBeforeInvalid = fetchMock.mock.calls.length;
    fireEvent.change(screen.getByLabelText(/RoutingDomain/i), { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/must not be blank whitespace/i);
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeInvalid);

    // Reject '#' delimiter in RoutingDomain
    fireEvent.change(screen.getByLabelText(/RoutingDomain/i), { target: { value: 'corp#1' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/cannot contain the reserved "#"/i);
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeInvalid);

    // Valid RoutingDomain resets offset from 50 -> 0
    fireEvent.change(screen.getByLabelText(/RoutingDomain/i), { target: { value: 'corp' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    await waitFor(() => {
      expect(screen.getByText('CzeekCorpDomain')).toBeInTheDocument();
    });
    const lastUrl = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0]);
    expect(lastUrl).toContain('routing_domain_id=corp');
    expect(lastUrl).toContain('offset=0');

    // Invalid SHA-256 AlertEvent ID must block fetch with inline message
    const callsBeforeBadEvent = fetchMock.mock.calls.length;
    fireEvent.change(screen.getByRole('textbox', { name: /RoutingDomain/i }), {
      target: { value: '' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: /AlertEvent ID/i }), {
      target: { value: 'not-a-sha256' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/64-character lowercase hexadecimal SHA-256/i);
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeBadEvent);

    // Valid AlertEvent ID detail query uses /alert-flows/{event_id}
    fireEvent.change(screen.getByRole('textbox', { name: /AlertEvent ID/i }), {
      target: { value: EVENT_ID_2 },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    await waitFor(() => {
      expect(screen.getByText('CzeekEventOnly')).toBeInTheDocument();
    });
    const detailUrl = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0]);
    expect(detailUrl).toContain(`/api/v1/correlations/alert-flows/${EVENT_ID_2}?`);

    // Invalid FlowObservation ID blocks fetch; valid observation_id + event_id routes via /alert-flows list
    const callsBeforeBadObs = fetchMock.mock.calls.length;
    fireEvent.change(screen.getByRole('textbox', { name: /FlowObservation ID/i }), {
      target: { value: 'SHORT_OBS' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/FlowObservation ID must be a 64-character/i);
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeBadObs);

    fireEvent.change(screen.getByRole('textbox', { name: /FlowObservation ID/i }), {
      target: { value: OBS_ID_2 },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    await waitFor(() => {
      const combinedUrl = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0]);
      expect(combinedUrl).toContain('/api/v1/correlations/alert-flows?');
      expect(combinedUrl).toContain(`event_id=${EVENT_ID_2}`);
      expect(combinedUrl).toContain(`observation_id=${OBS_ID_2}`);
    });
  });

  // Scenarios K, L, M, N, W, X: Inspector modal, exact Decimal preservation, NULL neutrality, clipboard copy & duplicate edges
  it('opens evidence inspector preserving exact Decimal string, neutral NULLs, duplicate rows & clipboard copy', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: writeTextMock },
      configurable: true,
    });

    const recordWithNullsAndHighPrecisionDecimal = makeV2Record({
      zeek_uid: null,
      sensor_context: null,
      last_incomplete_reason: null,
      last_incomplete_at_utc: null,
      temporal_delta_decimal: '0.000123450000000001',
      used_decimal_fallback: true,
    });
    const duplicateParallelRecord = makeV2Record({
      zeek_uid: null,
      sensor_context: null,
      last_incomplete_reason: null,
      last_incomplete_at_utc: null,
      temporal_delta_decimal: '0.000123450000000001',
      used_decimal_fallback: true,
    });

    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      return mockJsonResponse({
        items: [recordWithNullsAndHighPrecisionDecimal, duplicateParallelRecord],
        total: 2,
        limit: 50,
        offset: 0,
      });
    }) as unknown as typeof fetch;

    render(<CorrelationsPage />);
    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    // Verify duplicate rows both render instead of collapsing, and copy works in table
    await waitFor(() => {
      const inspectButtons = screen.getAllByRole('button', { name: /Inspect evidence/i });
      expect(inspectButtons).toHaveLength(2);
    });

    const rowCopyBtn = screen.getAllByRole('button', {
      name: `Copy full AlertEvent ID ${EVENT_ID_1}`,
    })[0];
    fireEvent.click(rowCopyBtn);
    expect(writeTextMock).toHaveBeenCalledWith(EVENT_ID_1);

    // Open inspector modal
    fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/i })[0]);
    const dialog = await screen.findByRole('dialog');

    expect(within(dialog).getByText(EVENT_ID_1)).toBeInTheDocument();
    expect(within(dialog).getByText(OBS_ID_1)).toBeInTheDocument();
    expect(within(dialog).getByText('0.000123450000000001')).toBeInTheDocument();
    expect(within(dialog).getByText('Yes (true)')).toBeInTheDocument();
    expect(within(dialog).getAllByText('Not recorded').length).toBeGreaterThanOrEqual(4);
    expect(within(dialog).getByText(/not a confidence score/i)).toBeInTheDocument();

    // Copy FlowObservation ID and Evidence Digest from modal
    fireEvent.click(within(dialog).getByRole('button', { name: /Copy full FlowObservation ID/i }));
    fireEvent.click(within(dialog).getByRole('button', { name: /Copy full Evidence Digest/i }));
    expect(writeTextMock).toHaveBeenCalledWith(OBS_ID_1);
    expect(writeTextMock).toHaveBeenCalledWith(EVIDENCE_DIGEST_1);

    // Close modal via Escape key (keyboard accessibility)
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  // Scenarios O, P, Q, R, S, W: Error states (404 vs 200-empty, 422, 503, network/500) + Retry + Loading
  it('distinguishes 404 missing AlertEvent vs 200 empty existing AlertEvent and handles 422, 503, 500 & retry', async () => {
    let scenario: '500' | '503' | '422' | '404' | '200_empty' | 'ok' = '500';

    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (scenario === '500') {
        return mockJsonResponse({ detail: 'Traceback leaked internal detail' }, 500);
      }
      if (scenario === '503') {
        return mockJsonResponse({ detail: 'Database service unavailable' }, 503);
      }
      if (scenario === '422') {
        return mockJsonResponse({ detail: 'Conflicting verification_status parameter' }, 422);
      }
      if (scenario === '404') {
        return mockJsonResponse({ detail: `Suricata AlertEvent '${EVENT_ID_1}' not found` }, 404);
      }
      if (scenario === '200_empty') {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 }, 200);
      }
      return mockJsonResponse({ items: [makeV2Record()], total: 1, limit: 50, offset: 0 }, 200);
    }) as unknown as typeof fetch;

    render(<CorrelationsPage />);
    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    // HTTP 500 does not expose stack traces and allows user retry
    await waitFor(() => {
      expect(screen.getByText(/Internal Server Error \(HTTP 500\)/i)).toBeInTheDocument();
    });
    expect(screen.queryByText(/Traceback leaked/i)).not.toBeInTheDocument();

    // Retry -> 503 explicitly explains unavailability (not missing AlertEvent)
    scenario = '503';
    fireEvent.click(screen.getByRole('button', { name: /Retry/i }));
    await waitFor(() => {
      expect(
        screen.getByText(/Database Service Temporarily Unavailable \(HTTP 503\)/i)
      ).toBeInTheDocument();
    });
    expect(screen.getByText(/does not mean the requested AlertEvent/i)).toBeInTheDocument();

    // Submit event_id -> 422 validation error
    scenario = '422';
    fireEvent.change(screen.getByLabelText(/AlertEvent ID/i), { target: { value: EVENT_ID_1 } });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    await waitFor(() => {
      expect(
        screen.getByText(/Invalid Correlation Query Parameters \(HTTP 422\)/i)
      ).toBeInTheDocument();
    });

    // Re-submit -> 404 missing AlertEvent
    scenario = '404';
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    await waitFor(() => {
      expect(screen.getByText(/Suricata AlertEvent Not Found \(HTTP 404\)/i)).toBeInTheDocument();
    });

    // Re-submit -> 200 existing AlertEvent with zero matching edges (distinct from 404)
    scenario = '200_empty';
    fireEvent.click(screen.getByRole('button', { name: /Retry/i }));
    await waitFor(() => {
      expect(
        screen.getByText(
          /The AlertEvent exists, but no matching persisted relationships are available under these filters/i
        )
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText(/does not prove the alert was REJECTED, AMBIGUOUS, INSUFFICIENT/i)
    ).toBeInTheDocument();

    // Recover cleanly on final retry
    scenario = 'ok';
    fireEvent.click(screen.getByRole('button', { name: /Reset/i }));
    await waitFor(() => {
      expect(screen.getByText('CzeekUid12345')).toBeInTheDocument();
    });
  });

  // Scenario T & U: Stale async request race prevention & tab switching V1/V2 isolation
  it('prevents stale async responses from overwriting newer filters and isolates V1/V2 tab data', async () => {
    let resolveSlowRequest!: (value: unknown) => void;

    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [LEGACY_V1_CORRELATION], total: 1, limit: 50, offset: 0 });
      }
      if (url.includes('routing_domain_id=slow-domain')) {
        return new Promise((resolve) => {
          resolveSlowRequest = resolve;
        });
      }
      if (url.includes('routing_domain_id=fast-domain')) {
        return mockJsonResponse({
          items: [
            makeV2Record({
              routing_domain_id: 'fast-domain',
              zeek_uid: 'CzeekFastDomain',
            }),
          ],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return mockJsonResponse({
        items: [makeV2Record({ routing_domain_id: 'default', zeek_uid: 'CzeekInitialDomain' })],
        total: 1,
        limit: 50,
        offset: 0,
      });
    }) as unknown as typeof fetch;

    render(<CorrelationsPage />);

    // Keyboard navigate from Legacy tab to Alert–Flow tab (ArrowRight)
    const legacyTab = screen.getByRole('tab', { name: /Legacy Correlations/i });
    fireEvent.keyDown(legacyTab, { key: 'ArrowRight' });

    await waitFor(() => {
      expect(screen.getByText('CzeekInitialDomain')).toBeInTheDocument();
    });

    // Legacy V1 content must not be visible in V2 tab
    expect(screen.queryByText('ET SCAN Potential SSH Scan')).not.toBeInTheDocument();

    // Fire slow request A ("slow-domain")
    fireEvent.change(screen.getByLabelText(/RoutingDomain/i), {
      target: { value: 'slow-domain' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    // Immediately supersede with fast request B ("fast-domain")
    fireEvent.change(screen.getByLabelText(/RoutingDomain/i), {
      target: { value: 'fast-domain' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    await waitFor(() => {
      expect(screen.getByText('CzeekFastDomain')).toBeInTheDocument();
    });

    // Now resolve stale slow request A AFTER fast request B completed
    resolveSlowRequest({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve({
          items: [
            makeV2Record({
              routing_domain_id: 'slow-domain',
              zeek_uid: 'CzeekStaleOverwrite',
              evidence_digest: EVIDENCE_DIGEST_2,
            }),
          ],
          total: 1,
          limit: 50,
          offset: 0,
        }),
    });

    await Promise.resolve();
    await Promise.resolve();

    expect(screen.getByText('CzeekFastDomain')).toBeInTheDocument();
    expect(screen.queryByText('CzeekStaleOverwrite')).not.toBeInTheDocument();

    // Switch back to Legacy tab -> V2 data disappears and V1 renders cleanly
    fireEvent.click(screen.getByRole('tab', { name: /Legacy Correlations/i }));
    await waitFor(() => {
      expect(screen.getByText('ET SCAN Potential SSH Scan')).toBeInTheDocument();
    });
    expect(screen.queryByText('CzeekFastDomain')).not.toBeInTheDocument();
  });

  // Scenarios S & W: Loading state, network failure recovery via Retry & neutral general empty state
  it('renders loading skeletons, recovers from network failure on retry, and explains empty lists neutrally', async () => {
    let failNetwork = true;
    let resolveDelayedEmpty!: (value: unknown) => void;

    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (failNetwork) {
        return Promise.reject(new Error('ECONNREFUSED'));
      }
      return new Promise((resolve) => {
        resolveDelayedEmpty = resolve;
      });
    }) as unknown as typeof fetch;

    render(<CorrelationsPage />);
    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    // Network failure rendered clearly with Retry button
    await waitFor(() => {
      expect(screen.getByText(/Network Connection Error/i)).toBeInTheDocument();
    });

    // Retry enters loading state cleanly before delayed response resolves
    failNetwork = false;
    fireEvent.click(screen.getByRole('button', { name: /Retry/i }));
    expect(screen.queryByText(/Network Connection Error/i)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/No persisted alert-flow correlations match the selected filters/i)
    ).not.toBeInTheDocument();

    resolveDelayedEmpty({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
    });

    await waitFor(() => {
      expect(
        screen.getByText(/No persisted alert-flow correlations match the selected filters/i)
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText(/does not prove every alert was evaluated/i)
    ).toBeInTheDocument();
  });

  // Review Regression: Contradictory checkbox/select transitions, unknown status fail-closed, domain case normalization
  it('prevents contradictory verification filters, handles unknown status safely, and normalizes RoutingDomain case', async () => {
    const unknownStatusItem = makeV2Record({
      zeek_uid: 'CzeekUnknownStatus',
      verification_status: 'pending_external_check' as AlertFlowCorrelationResponse['verification_status'],
    });

    const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (url.includes('routing_domain_id=corp-east')) {
        return mockJsonResponse({
          items: [unknownStatusItem],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return mockJsonResponse({ items: [makeV2Record()], total: 1, limit: 50, offset: 0 });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    render(<CorrelationsPage />);
    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    await waitFor(() => {
      expect(screen.getByText('CzeekUid12345')).toBeInTheDocument();
    });

    const statusSelect = screen.getByLabelText(/Verification Status/i) as HTMLSelectElement;
    const includeCheckbox = screen.getByLabelText(
      /Include unverified correlations/i
    ) as HTMLInputElement;

    // 1. Select unverified_incomplete -> include_unverified auto-checks
    fireEvent.change(statusSelect, { target: { value: 'unverified_incomplete' } });
    expect(includeCheckbox.checked).toBe(true);

    // 2. Uncheck include_unverified -> invalid unverified_incomplete status clears
    fireEvent.click(includeCheckbox);
    expect(includeCheckbox.checked).toBe(false);
    expect(statusSelect.value).toBe('');

    // 3. Submit -> verifies safe default params and no unverified warning banner
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    await waitFor(() => {
      const lastUrl = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0]);
      expect(lastUrl).toContain('include_unverified=false');
      expect(lastUrl).not.toContain('verification_status=');
    });
    expect(screen.getByText(/Safe default active/i)).toBeInTheDocument();
    expect(screen.queryByText(/Unverified Correlations Visible/i)).not.toBeInTheDocument();

    // 4. Select verified while include_unverified is checked -> auto-unchecks include_unverified
    fireEvent.click(includeCheckbox);
    expect(includeCheckbox.checked).toBe(true);
    fireEvent.change(statusSelect, { target: { value: 'verified' } });
    expect(includeCheckbox.checked).toBe(false);

    // 5. Submit verified-only with mixed-case RoutingDomain -> lowercased to match backend
    fireEvent.change(screen.getByRole('textbox', { name: /RoutingDomain/i }), {
      target: { value: '  CORP-East  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    await waitFor(() => {
      expect(screen.getByText('CzeekUnknownStatus')).toBeInTheDocument();
    });
    const domainUrl = String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1][0]);
    expect(domainUrl).toContain('routing_domain_id=corp-east');
    expect(domainUrl).toContain('include_unverified=false');
    expect(domainUrl).toContain('verification_status=verified');

    // Unknown runtime status must NOT be presented as Verified or Previously Verified
    expect(within(screen.getByRole('table')).getByText('Unknown Verification Status')).toBeInTheDocument();
    expect(within(screen.getByRole('table')).queryByText('Verified')).not.toBeInTheDocument();
    expect(screen.getByText(/Unrecognized Verification Status Present/i)).toBeInTheDocument();
    expect(screen.queryByText(/Safe default active/i)).not.toBeInTheDocument();

    // Whitespace-only SHA-256 AlertEvent ID fails closed with aria-invalid
    const callsBeforeWhitespaceId = fetchMock.mock.calls.length;
    const eventInput = screen.getByRole('textbox', { name: /AlertEvent ID/i });
    fireEvent.change(eventInput, { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));
    expect(eventInput).toHaveAttribute('aria-invalid', 'true');
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeWhitespaceId);
  });

  // Review Regression: Negative Decimal preservation, clipboard rejection, fresh modal Copy state & focus trap/restoration
  it('preserves negative sub-nanosecond Decimal, handles clipboard failures, resets Copy across reopens, and manages modal focus', async () => {
    const record = makeV2Record({
      temporal_delta_decimal: '-0.000000000123',
      verification_status: 'unverified_incomplete',
      last_incomplete_reason: 'CANDIDATE_CAP_TRUNCATED',
      last_incomplete_at_utc: '2026-11-22T09:00:00Z',
    });

    globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      return mockJsonResponse({ items: [record], total: 1, limit: 50, offset: 0 });
    }) as unknown as typeof fetch;

    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: writeTextMock },
      configurable: true,
    });

    render(<CorrelationsPage />);
    fireEvent.click(screen.getByRole('tab', { name: /Alert–Flow Correlations/i }));

    const inspectBtn = await screen.findByRole('button', { name: /Inspect evidence/i });
    // Badge must allow wrapping on narrow viewports (not white-space: nowrap)
    const badgeEl = within(screen.getByRole('table')).getByText(
      'Previously Verified — Current Check Incomplete'
    ).parentElement;
    expect(badgeEl?.style.whiteSpace).toBe('normal');

    // Open modal from focused trigger button
    inspectBtn.focus();
    expect(document.activeElement).toBe(inspectBtn);
    fireEvent.click(inspectBtn);

    const dialog = await screen.findByRole('dialog', {
      name: 'Persisted Correlation Evidence Inspector',
    });
    expect(document.body.style.overflow).toBe('hidden');
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(within(dialog).getByText('-0.000000000123')).toBeInTheDocument();

    // No fabricated V1 IP / attacker / confidence fields in V2 inspector
    expect(within(dialog).queryByText('Source IP')).not.toBeInTheDocument();
    expect(within(dialog).queryByText('Destination IP')).not.toBeInTheDocument();
    expect(within(dialog).queryByText('Attacker IP')).not.toBeInTheDocument();
    expect(within(dialog).queryByText('Confidence Score')).not.toBeInTheDocument();

    // Keyboard focus trap: Shift+Tab from first focusable wraps to Close; Tab from Close wraps to Close dialog
    const closeHeaderBtn = within(dialog).getByRole('button', { name: 'Close dialog' });
    const closeFooterBtn = within(dialog).getByRole('button', { name: 'Close' });
    closeHeaderBtn.focus();
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(closeFooterBtn);
    fireEvent.keyDown(document, { key: 'Tab' });
    expect(document.activeElement).toBe(closeHeaderBtn);

    // Copy AlertEvent ID -> shows Copied -> close immediately -> reopen -> must NOT remain stuck on Copied
    const copyEventBtn = within(dialog).getByRole('button', { name: /Copy full AlertEvent ID/i });
    fireEvent.click(copyEventBtn);
    await waitFor(() => {
      expect(within(copyEventBtn).getByText('Copied')).toBeInTheDocument();
    });

    // Escape closes modal, restores overflow and restores focus to trigger button
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(document.body.style.overflow).toBe('');
    expect(document.activeElement).toBe(inspectBtn);

    // Reopen same row object -> Copy state is clean & clipboard rejection does not crash
    writeTextMock.mockRejectedValueOnce(new Error('NotAllowedError'));
    fireEvent.click(inspectBtn);
    const dialog2 = await screen.findByRole('dialog', {
      name: 'Persisted Correlation Evidence Inspector',
    });
    const copyEventBtn2 = within(dialog2).getByRole('button', { name: /Copy full AlertEvent ID/i });
    expect(within(copyEventBtn2).getByText('Copy')).toBeInTheDocument();
    fireEvent.click(copyEventBtn2);
    await Promise.resolve();
    expect(within(copyEventBtn2).getByText('Copy')).toBeInTheDocument();
  });

  // Review Regression: Out-of-range pagination, late 503 after newer 200, Home/End tab keys & unmount safety
  it('handles out-of-range pages, suppresses late 503 errors after newer 200, supports Home/End tabs, and unmounts safely', async () => {
    let rejectSlowError!: (err: unknown) => void;

    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/traffic-alerts')) {
        return mockJsonResponse({ items: [], total: 0, limit: 50, offset: 0 });
      }
      if (url.includes('routing_domain_id=slow-fail')) {
        return new Promise((_resolve, reject) => {
          rejectSlowError = reject;
        });
      }
      if (url.includes('offset=50')) {
        // Concurrent deletion shrank total below offset=50
        return mockJsonResponse({ items: [], total: 40, limit: 50, offset: 50 });
      }
      if (url.includes('routing_domain_id=fast-ok')) {
        return mockJsonResponse({
          items: [makeV2Record({ routing_domain_id: 'fast-ok', zeek_uid: 'CzeekRecoveredOk' })],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return mockJsonResponse({
        items: [makeV2Record({ zeek_uid: 'CzeekPageOne' })],
        total: 75,
        limit: 50,
        offset: 0,
      });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const { unmount } = render(<CorrelationsPage />);

    // Home/End keyboard navigation on tabs
    const legacyTab = screen.getByRole('tab', { name: /Legacy Correlations/i });
    const v2Tab = screen.getByRole('tab', { name: /Alert–Flow Correlations/i });
    fireEvent.keyDown(legacyTab, { key: 'End' });
    expect(document.activeElement).toBe(v2Tab);
    expect(v2Tab).toHaveAttribute('aria-selected', 'true');

    await waitFor(() => {
      expect(screen.getByText('CzeekPageOne')).toBeInTheDocument();
    });

    // Advance to page 2 -> out-of-range state (offset=50, total=40)
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => {
      expect(
        screen.getByText(/This page is beyond the currently available results/i)
      ).toBeInTheDocument();
    });
    // Pagination must NOT claim "51 to 40"
    expect(screen.queryByText(/Showing 51 to 40/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Return to First Page/i }));
    await waitFor(() => {
      expect(screen.getByText('CzeekPageOne')).toBeInTheDocument();
    });

    // Slow failing request superseded by fast 200 success -> late rejection must NOT flash error
    fireEvent.change(screen.getByRole('textbox', { name: /RoutingDomain/i }), {
      target: { value: 'slow-fail' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    fireEvent.change(screen.getByRole('textbox', { name: /RoutingDomain/i }), {
      target: { value: 'fast-ok' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Apply Filters/i }));

    await waitFor(() => {
      expect(screen.getByText('CzeekRecoveredOk')).toBeInTheDocument();
    });

    rejectSlowError(new Error('Late network failure after supersede'));
    await Promise.resolve();
    await Promise.resolve();
    expect(screen.getByText('CzeekRecoveredOk')).toBeInTheDocument();
    expect(screen.queryByText(/Network Connection Error/i)).not.toBeInTheDocument();

    // Home returns focus to Legacy tab; unmount mid-flight produces zero errors
    fireEvent.keyDown(v2Tab, { key: 'Home' });
    expect(document.activeElement).toBe(legacyTab);
    unmount();
  });
});
