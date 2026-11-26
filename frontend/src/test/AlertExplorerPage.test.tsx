import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import { AlertExplorerPage } from '../pages/AlertExplorerPage';
import type { AlertEventDetailResponse, AlertEventTriageItemResponse } from '../api/types';

const LINKED_EVENT_ID = '1'.repeat(64);
const UNLINKED_EVENT_ID = '2'.repeat(64);
const FLOW_KEY_1 = 'c'.repeat(64);

function makeTriageItem(
  overrides: Partial<AlertEventTriageItemResponse> = {}
): AlertEventTriageItemResponse {
  return {
    event_id: UNLINKED_EVENT_ID,
    routing_domain_id: 'demo-v2-corp',
    source_type: 'suricata',
    sensor_id: 'suricata-demo-01',
    sid: 9100002,
    signature: 'SYNTHETIC Unlinked Dual Flow Probe',
    severity: 2,
    category: 'Potentially Bad Traffic',
    src_ip: '192.0.2.30',
    dst_ip: '198.51.100.40',
    src_port: 55000,
    dst_port: 8080,
    protocol: 'TCP',
    timestamp_source: '2026-11-23T10:01:05.123456789123+0000',
    timestamp_epoch_decimal: '1795428065.123456789123',
    has_persisted_correlation: false,
    ...overrides,
  };
}

function makeAlertDetail(
  overrides: Partial<AlertEventDetailResponse> = {}
): AlertEventDetailResponse {
  return {
    event_id: UNLINKED_EVENT_ID,
    alert_definition_id: 'suricata:demo-v2-rules:1:9100002',
    source_record_id: 'corp-eve-demo-01:line:3:abc',
    log_source_id: 'corp-eve-demo-01',
    sensor_id: 'suricata-demo-01',
    ruleset_namespace: 'demo-v2-rules',
    routing_domain_id: 'demo-v2-corp',
    source_type: 'suricata',
    source_provenance: 'phase4e-corp-eve',
    engine: 'suricata',
    gid: 1,
    sid: 9100002,
    rev: 1,
    signature: 'SYNTHETIC Unlinked Dual Flow Probe',
    category: 'Potentially Bad Traffic',
    severity: 0,
    action: 'allowed',
    app_proto: 'http',
    direction: 'to_server',
    tx_id: 0,
    pcap_cnt: '9007199254740992',
    flow_id: '8810002',
    src_ip: '192.0.2.30',
    dst_ip: '198.51.100.40',
    src_scoped_id: 'demo-v2-corp#192.0.2.30',
    dst_scoped_id: 'demo-v2-corp#198.51.100.40',
    protocol: 'TCP',
    src_port: 55000,
    dst_port: 8080,
    flow_key: FLOW_KEY_1,
    community_id: null,
    timestamp_source: '2026-11-23T10:01:05.123456789123+0000',
    timestamp_epoch_decimal: '1795428065.123456789123',
    ...overrides,
  };
}

describe('AlertExplorerPage Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('renders alert facts table with exact numeric priority and handles null fields', async () => {
    const mockAlerts = {
      items: [
        {
          fact_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          source_ip: '192.168.1.100',
          target_ip: '192.168.1.1',
          sid: 2001219,
          gid: 1,
          rev: 1,
          message: 'ET SCAN Potential SSH Scan',
          priority: 1,
          protocol: 'TCP',
          src_port: 54321,
          dst_port: 22,
        },
        {
          fact_key: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
          source_ip: '10.0.0.5',
          target_ip: '192.168.1.100',
          sid: null,
          gid: null,
          rev: null,
          message: null,
          priority: null, // Null priority
          protocol: null,
          src_port: null,
          dst_port: null,
        },
      ],
      total: 2,
      limit: 50,
      offset: 0,
    };

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/alerts/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockAlerts.items[0]) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockAlerts) });
    }) as unknown as typeof fetch;

    render(<AlertExplorerPage />);

    await waitFor(() => {
      expect(screen.getByText('ET SCAN Potential SSH Scan')).toBeInTheDocument();
      expect(screen.getAllByText('Priority 1').length).toBeGreaterThan(0);
      expect(screen.getByText('Unknown')).toBeInTheDocument(); // Priority null -> Unknown
    });

    // Verify invented severity labels are NOT present
    expect(screen.queryByText('Critical')).not.toBeInTheDocument();
    expect(screen.queryByText('High')).not.toBeInTheDocument();

    // Test Inspect modal
    const inspectButtons = screen.getAllByText('Inspect');
    fireEvent.click(inspectButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Alert Fact Details')).toBeInTheDocument();
      expect(screen.getByText('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')).toBeInTheDocument();
    });
  });

  it('defaults to Legacy Alert Facts, switches cleanly to Suricata Events, inspects unlinked alerts, and enforces accessibility/safety', async () => {
    const linkedRow = makeTriageItem({
      event_id: LINKED_EVENT_ID,
      sid: 9100001,
      severity: 3,
      signature: 'SYNTHETIC Linked TLS Alert',
      has_persisted_correlation: true,
    });
    const unlinkedRow = makeTriageItem({
      event_id: UNLINKED_EVENT_ID,
      sid: '9007199254740992',
      severity: 0,
      signature: 'SYNTHETIC Unlinked Dual Flow Probe',
      has_persisted_correlation: false,
      category: null,
      protocol: null,
    });

    const fetchMock = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      expect(init?.method).toBeUndefined();
      if (url.startsWith('/api/v1/alerts')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
        });
      }
      if (url.startsWith(`/api/v1/alert-events/${UNLINKED_EVENT_ID}`)) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(makeAlertDetail({ sid: '9007199254740992' })),
        });
      }
      if (url.startsWith('/api/v1/alert-events')) {
        const parsed = new URL(url, 'http://localhost');
        if (parsed.searchParams.get('routing_domain_id') === 'empty-domain') {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              items: [linkedRow, unlinkedRow],
              total: 120,
              limit: 50,
              offset: Number(parsed.searchParams.get('offset') ?? '0'),
            }),
        });
      }
      throw new Error(`Unexpected fetch URL: ${url}`);
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    render(<AlertExplorerPage />);

    // Default V1 tab is active & all aria-controls panels exist in DOM
    const legacyTab = screen.getByRole('tab', { name: 'Legacy Alert Facts' });
    const suricataTab = screen.getByRole('tab', { name: 'Suricata Events' });
    expect(legacyTab).toHaveAttribute('aria-selected', 'true');
    expect(suricataTab).toHaveAttribute('aria-selected', 'false');
    for (const tab of [legacyTab, suricataTab]) {
      const panelId = tab.getAttribute('aria-controls');
      expect(panelId).toBeTruthy();
      expect(document.getElementById(panelId!)).toHaveAttribute('role', 'tabpanel');
    }

    // Keyboard navigation switches to Suricata Events
    fireEvent.keyDown(legacyTab, { key: 'ArrowRight' });
    expect(suricataTab).toHaveAttribute('aria-selected', 'true');

    await waitFor(() => {
      expect(screen.getByText('SYNTHETIC Linked TLS Alert')).toBeInTheDocument();
      expect(screen.getByText('SYNTHETIC Unlinked Dual Flow Probe')).toBeInTheDocument();
    });

    // Factual wording & neutral absence banner (no fabricated verdict wording)
    expect(screen.getByText('Persisted link present')).toBeInTheDocument();
    expect(screen.getByText('No persisted link recorded')).toBeInTheDocument();
    expect(
      screen.getByText(/The absence of a persisted relationship does not establish a correlation decision/i)
    ).toBeInTheDocument();
    expect(screen.getByText('Severity 0')).toBeInTheDocument();
    expect(screen.getByText(/SID: 9007199254740992/)).toBeInTheDocument();

    // Detail endpoint must NOT be prefetched for table rows
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes(`/api/v1/alert-events/${UNLINKED_EVENT_ID}`))).toBe(false);

    // Pagination increments offset=50
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => {
      const triageUrls = fetchMock.mock.calls
        .map(([u]) => String(u))
        .filter((u) => u.startsWith('/api/v1/alert-events?'));
      expect(triageUrls.some((u) => new URL(u, 'http://localhost').searchParams.get('offset') === '50')).toBe(true);
    });

    // Invalid inputs fail closed without firing backend request
    const callsBeforeInvalid = fetchMock.mock.calls.length;
    fireEvent.change(screen.getByLabelText('RoutingDomain'), { target: { value: 'corp#1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('RoutingDomain cannot contain');
    expect(fetchMock.mock.calls.length).toBe(callsBeforeInvalid);

    // Reversed UTC range fails closed without firing request
    fireEvent.change(screen.getByLabelText('RoutingDomain'), { target: { value: ' DEMO-V2-CORP ' } });
    fireEvent.change(screen.getByLabelText('Start Time (UTC)'), {
      target: { value: '2026-11-23T10:10:00Z' },
    });
    fireEvent.change(screen.getByLabelText('End Time (UTC)'), {
      target: { value: '2026-11-23T10:00:00Z' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('must not be earlier');
    expect(fetchMock.mock.calls.length).toBe(callsBeforeInvalid);

    // Valid normalized filters + BigInt UTC ns reset offset=0
    fireEvent.change(screen.getByLabelText('Severity (integer)'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Signature ID (SID)'), { target: { value: '9100002' } });
    fireEvent.change(screen.getByLabelText('Sensor ID'), { target: { value: ' Suricata-Demo-01 ' } });
    fireEvent.change(screen.getByLabelText('Start Time (UTC)'), {
      target: { value: '2026-11-23T10:00:00.123456789Z' },
    });
    fireEvent.change(screen.getByLabelText('End Time (UTC)'), {
      target: { value: '2026-11-23T10:05:00Z' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));

    await waitFor(() => {
      const lastUrl = String(fetchMock.mock.calls.at(-1)?.[0]);
      const parsed = new URL(lastUrl, 'http://localhost');
      expect(parsed.pathname).toBe('/api/v1/alert-events');
      expect(parsed.searchParams.get('routing_domain_id')).toBe('demo-v2-corp');
      expect(parsed.searchParams.get('severity')).toBe('2');
      expect(parsed.searchParams.get('sid')).toBe('9100002');
      expect(parsed.searchParams.get('sensor_id')).toBe('suricata-demo-01');
      expect(parsed.searchParams.get('start_epoch_ns')).toBe('1795428000123456789');
      expect(parsed.searchParams.get('end_epoch_ns')).toBe('1795428300000000000');
      expect(parsed.searchParams.get('offset')).toBe('0');
    });

    // Empty result renders neutral message
    fireEvent.change(screen.getByLabelText('RoutingDomain'), { target: { value: 'empty-domain' } });
    fireEvent.change(screen.getByLabelText('Start Time (UTC)'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('End Time (UTC)'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));
    expect(await screen.findByText('No Suricata AlertEvents matched the current filters')).toBeInTheDocument();

    // Reset back to populated rows and Inspect unlinked AlertEvent independently
    fireEvent.click(screen.getByRole('button', { name: 'Reset' }));
    const inspectUnlinkedBtn = await screen.findByRole('button', {
      name: `Inspect Suricata AlertEvent ${UNLINKED_EVENT_ID}`,
    });
    inspectUnlinkedBtn.focus();
    fireEvent.click(inspectUnlinkedBtn);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('No Persisted Correlation Edge Recorded:')).toBeInTheDocument();
    expect(await within(dialog).findByText('1795428065.123456789123')).toBeInTheDocument();
    expect(within(dialog).getAllByText('9007199254740992').length).toBeGreaterThanOrEqual(1);
    expect(within(dialog).getAllByText('0').length).toBeGreaterThanOrEqual(1);
    expect(within(dialog).getAllByText('Not recorded').length).toBeGreaterThan(0);

    // Escape closes modal & restores focus to triggering Inspect button
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(document.activeElement).toBe(inspectUnlinkedBtn);

    // Switching back to Legacy Alert Facts keeps V1 isolated
    fireEvent.click(legacyTab);
    expect(await screen.findByText('AlertFact Semantic Note:')).toBeInTheDocument();
  });

  it('prevents stale out-of-order responses from overwriting newer filters and handles 503 + Retry cleanly', async () => {
    let resolveFirst: (val: unknown) => void = () => {};
    let firstAborted = false;
    let shouldReturn503 = true;

    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (url.startsWith('/api/v1/alerts')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
        });
      }
      const parsed = new URL(url, 'http://localhost');
      const domain = parsed.searchParams.get('routing_domain_id');

      if (domain === 'backend-422') {
        return Promise.resolve({
          ok: false,
          status: 422,
          statusText: 'Unprocessable Content',
          json: () => Promise.resolve({ detail: 'Invalid routing_domain_id rejected by API' }),
        });
      }
      if (domain === 'domain-a') {
        init?.signal?.addEventListener('abort', () => {
          firstAborted = true;
        });
        return new Promise((resolve) => {
          resolveFirst = resolve;
        });
      }
      if (domain === 'domain-b') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              items: [makeTriageItem({ event_id: LINKED_EVENT_ID, signature: 'SYNTHETIC Domain B Result' })],
              total: 1,
              limit: 50,
              offset: 0,
            }),
        });
      }
      if (shouldReturn503) {
        return Promise.resolve({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          json: () => Promise.resolve({ detail: 'Database service unavailable' }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve({
            items: [makeTriageItem({ signature: 'SYNTHETIC Recovered After Retry' })],
            total: 1,
            limit: 50,
            offset: 0,
          }),
      });
    }) as unknown as typeof fetch;

    render(<AlertExplorerPage />);
    fireEvent.click(screen.getByRole('tab', { name: 'Suricata Events' }));

    // Initial HTTP 503 error must remain explicit (never empty list) and recover on Retry
    expect(await screen.findByText('Database Service Temporarily Unavailable (HTTP 503)')).toBeInTheDocument();
    shouldReturn503 = false;
    fireEvent.click(screen.getByRole('button', { name: 'Retry loading Suricata AlertEvents' }));
    expect(await screen.findByText('SYNTHETIC Recovered After Retry')).toBeInTheDocument();

    // Backend 422 validation error renders structured alert banner clearly
    fireEvent.change(screen.getByLabelText('RoutingDomain'), { target: { value: 'backend-422' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));
    expect(await screen.findByText('Invalid AlertEvent Query Parameters (HTTP 422)')).toBeInTheDocument();
    expect(screen.getByText('Invalid routing_domain_id rejected by API')).toBeInTheDocument();

    // Start slow Query A (domain-a), then supersede immediately with fast Query B (domain-b)
    fireEvent.change(screen.getByLabelText('RoutingDomain'), { target: { value: 'domain-a' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));

    fireEvent.change(screen.getByLabelText('RoutingDomain'), { target: { value: 'domain-b' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply Filters' }));

    expect(await screen.findByText('SYNTHETIC Domain B Result')).toBeInTheDocument();
    expect(firstAborted).toBe(true);

    // Late resolution of Query A must NOT overwrite Domain B result
    resolveFirst({
      ok: true,
      json: () =>
        Promise.resolve({
          items: [makeTriageItem({ signature: 'STALE Domain A Result' })],
          total: 1,
          limit: 50,
          offset: 0,
        }),
    });
    await waitFor(() => {
      expect(screen.getByText('SYNTHETIC Domain B Result')).toBeInTheDocument();
      expect(screen.queryByText('STALE Domain A Result')).not.toBeInTheDocument();
    });
  });
});
