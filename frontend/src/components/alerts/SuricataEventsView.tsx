import React, { useEffect, useRef, useState } from 'react';
import { Check, Copy, Eye, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import { listAlertEvents } from '../../api/observations';
import type { AlertEventTriageItemResponse, SafeCount } from '../../api/types';
import {
  describeAlertTriageListApiError,
  formatSafeCount,
  normalizeNonNegativeInt64Input,
  normalizeRoutingDomainInput,
  normalizeSensorIdInput,
  validateNonNegativeInt64Input,
  validateRoutingDomainInput,
  validateSensorIdInput,
  validateUtcTimeRange,
} from '../../utils/alertTriageHelpers';
import { truncateIdentifier, type CorrelationErrorSummary } from '../../utils/correlationHelpers';
import { Tag } from '../common/Badge';
import { Pagination } from '../common/Pagination';
import { Skeleton } from '../common/Skeleton';
import { AlertEventDetailModal } from './AlertEventDetailModal';
import { SuricataSeverityBadge } from './SuricataSeverityBadge';

const PAGE_LIMIT = 50;

interface AppliedAlertTriageQuery {
  routingDomainId?: string;
  severity?: string;
  sid?: string;
  sensorId?: string;
  startEpochNs?: string;
  endEpochNs?: string;
  offset: number;
  nonce: number;
}

const DEFAULT_APPLIED_QUERY: AppliedAlertTriageQuery = {
  offset: 0,
  nonce: 0,
};

function formatEndpointWithPort(ip: string, port: number | null): string {
  if (port === null) {
    return ip;
  }
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/**
 * Read-only V2 Suricata AlertEvent Triage Explorer view.
 * Lists ingested Suricata AlertEvent occurrences whether or not a persisted CORRELATED_WITH edge exists.
 */
export const SuricataEventsView: React.FC = () => {
  // Draft filter inputs
  const [routingDomainInput, setRoutingDomainInput] = useState<string>('');
  const [severityInput, setSeverityInput] = useState<string>('');
  const [sidInput, setSidInput] = useState<string>('');
  const [sensorInput, setSensorInput] = useState<string>('');
  const [startTimeInput, setStartTimeInput] = useState<string>('');
  const [endTimeInput, setEndTimeInput] = useState<string>('');
  const [validationError, setValidationError] = useState<{
    field: 'routingDomain' | 'severity' | 'sid' | 'sensorId' | 'startTime' | 'endTime';
    message: string;
  } | null>(null);

  // Applied backend query state
  const [appliedQuery, setAppliedQuery] =
    useState<AppliedAlertTriageQuery>(DEFAULT_APPLIED_QUERY);

  // Result & modal state
  const [items, setItems] = useState<AlertEventTriageItemResponse[]>([]);
  const [total, setTotal] = useState<SafeCount>(0);
  const [responseOffset, setResponseOffset] = useState<SafeCount>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CorrelationErrorSummary | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<AlertEventTriageItemResponse | null>(null);
  const [copiedEventId, setCopiedEventId] = useState<string | null>(null);

  const requestIdRef = useRef<number>(0);
  const isMountedRef = useRef<boolean>(true);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const requestId = ++requestIdRef.current;

    listAlertEvents(
      {
        routing_domain_id: appliedQuery.routingDomainId,
        severity: appliedQuery.severity,
        sid: appliedQuery.sid,
        sensor_id: appliedQuery.sensorId,
        start_epoch_ns: appliedQuery.startEpochNs,
        end_epoch_ns: appliedQuery.endEpochNs,
        limit: PAGE_LIMIT,
        offset: appliedQuery.offset,
      },
      controller.signal
    )
      .then((res) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          requestId !== requestIdRef.current
        ) {
          return;
        }
        setItems(res.items);
        setTotal(res.total);
        setResponseOffset(res.offset);
        setError(null);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          requestId !== requestIdRef.current
        ) {
          return;
        }
        setItems([]);
        setTotal(0);
        setResponseOffset(0);
        setError(
          describeAlertTriageListApiError(err, {
            routingDomainId: appliedQuery.routingDomainId,
          })
        );
        setLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [appliedQuery]);

  const clearCopyTimer = () => {
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = null;
    }
  };

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const domainError = validateRoutingDomainInput(routingDomainInput);
    if (domainError) {
      setValidationError({ field: 'routingDomain', message: domainError });
      return;
    }

    const severityError = validateNonNegativeInt64Input(severityInput, 'Severity');
    if (severityError) {
      setValidationError({ field: 'severity', message: severityError });
      return;
    }

    const sidError = validateNonNegativeInt64Input(sidInput, 'Signature ID (SID)');
    if (sidError) {
      setValidationError({ field: 'sid', message: sidError });
      return;
    }

    const sensorError = validateSensorIdInput(sensorInput);
    if (sensorError) {
      setValidationError({ field: 'sensorId', message: sensorError });
      return;
    }

    const timeRange = validateUtcTimeRange(startTimeInput, endTimeInput);
    if (timeRange.error) {
      setValidationError({
        field: timeRange.field ?? 'startTime',
        message: timeRange.error,
      });
      return;
    }

    setValidationError(null);
    setSelectedEvent(null);
    clearCopyTimer();
    setCopiedEventId(null);
    setError(null);
    setLoading(true);
    setAppliedQuery((prev) => ({
      routingDomainId: normalizeRoutingDomainInput(routingDomainInput),
      severity: normalizeNonNegativeInt64Input(severityInput),
      sid: normalizeNonNegativeInt64Input(sidInput),
      sensorId: normalizeSensorIdInput(sensorInput),
      startEpochNs: timeRange.startNs,
      endEpochNs: timeRange.endNs,
      offset: 0,
      nonce: prev.nonce + 1,
    }));
  };

  const handleResetFilters = () => {
    setRoutingDomainInput('');
    setSeverityInput('');
    setSidInput('');
    setSensorInput('');
    setStartTimeInput('');
    setEndTimeInput('');
    setValidationError(null);
    setSelectedEvent(null);
    clearCopyTimer();
    setCopiedEventId(null);
    setError(null);
    setLoading(true);
    setAppliedQuery((prev) => ({
      ...DEFAULT_APPLIED_QUERY,
      nonce: prev.nonce + 1,
    }));
  };

  const handlePageChange = (newOffset: number) => {
    setSelectedEvent(null);
    clearCopyTimer();
    setCopiedEventId(null);
    setError(null);
    setLoading(true);
    setAppliedQuery((prev) => ({
      ...prev,
      offset: newOffset,
    }));
  };

  const handleRetry = () => {
    setError(null);
    setLoading(true);
    setAppliedQuery((prev) => ({
      ...prev,
      nonce: prev.nonce + 1,
    }));
  };

  const handleCopyEventId = (eventId: string) => {
    if (!navigator.clipboard?.writeText) {
      return;
    }
    navigator.clipboard
      .writeText(eventId)
      .then(() => {
        if (!isMountedRef.current) return;
        setCopiedEventId(eventId);
        if (copyTimerRef.current !== null) {
          window.clearTimeout(copyTimerRef.current);
        }
        copyTimerRef.current = window.setTimeout(() => {
          if (!isMountedRef.current) return;
          setCopiedEventId(null);
          copyTimerRef.current = null;
        }, 2000);
      })
      .catch(() => {
        // Ignore clipboard permission errors cleanly
      });
  };

  const hasAnyFilter = Boolean(
    appliedQuery.routingDomainId ||
      appliedQuery.severity !== undefined ||
      appliedQuery.sid !== undefined ||
      appliedQuery.sensorId ||
      appliedQuery.startEpochNs !== undefined ||
      appliedQuery.endEpochNs !== undefined
  );
  const totalBigInt = BigInt(String(total));
  const offsetBigInt = BigInt(String(responseOffset));
  const isOutOfRangePage =
    !loading && !error && items.length === 0 && totalBigInt > 0n && offsetBigInt >= totalBigInt;
  const canUseNumericPagination =
    typeof total === 'number' &&
    typeof responseOffset === 'number' &&
    Number.isSafeInteger(total) &&
    Number.isSafeInteger(responseOffset) &&
    total >= 0 &&
    responseOffset >= 0 &&
    Number.isSafeInteger(responseOffset + PAGE_LIMIT);
  const losslessRangeStart = items.length > 0 ? offsetBigInt + 1n : 0n;
  const losslessRangeEnd = items.length > 0 ? offsetBigInt + BigInt(items.length) : 0n;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Explanatory Read-Only Semantic Notice */}
      <div className="info-banner" style={{ alignItems: 'flex-start' }}>
        <ShieldAlert size={16} aria-hidden="true" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
        <div>
          <strong>V2 Suricata AlertEvents (Read-Only Triage):</strong> Lists discrete persisted
          Suricata alert occurrences regardless of whether a persisted correlation edge exists. A
          persisted link indicates stored edge presence only (including{' '}
          <code>unverified_incomplete</code> edges), not a currently verified match.{' '}
          <strong>
            The absence of a persisted relationship does not establish a correlation decision or a
            security verdict.
          </strong>{' '}
          Source/destination endpoints reflect observed packet direction only, and recorded severity
          is not a universal risk score.
        </div>
      </div>

      {/* Filter Toolbar */}
      <section className="card" aria-label="Filter Suricata AlertEvents">
        <form
          onSubmit={handleFilterSubmit}
          style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 190px), 1fr))',
              gap: '0.85rem',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', minWidth: 0 }}>
              <label
                htmlFor="v2-alerts-filter-domain"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                RoutingDomain
              </label>
              <input
                id="v2-alerts-filter-domain"
                type="text"
                placeholder="e.g. demo-v2-corp"
                value={routingDomainInput}
                onChange={(e) => setRoutingDomainInput(e.target.value)}
                aria-invalid={validationError?.field === 'routingDomain'}
                aria-describedby={
                  validationError?.field === 'routingDomain'
                    ? 'v2-alerts-validation-error'
                    : undefined
                }
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', minWidth: 0 }}>
              <label
                htmlFor="v2-alerts-filter-severity"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                Severity (integer)
              </label>
              <input
                id="v2-alerts-filter-severity"
                type="text"
                inputMode="numeric"
                className="font-mono"
                placeholder="e.g. 1, 2, 3"
                value={severityInput}
                onChange={(e) => setSeverityInput(e.target.value)}
                aria-invalid={validationError?.field === 'severity'}
                aria-describedby={
                  validationError?.field === 'severity' ? 'v2-alerts-validation-error' : undefined
                }
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', minWidth: 0 }}>
              <label
                htmlFor="v2-alerts-filter-sid"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                Signature ID (SID)
              </label>
              <input
                id="v2-alerts-filter-sid"
                type="text"
                inputMode="numeric"
                className="font-mono"
                placeholder="e.g. 9100002"
                value={sidInput}
                onChange={(e) => setSidInput(e.target.value)}
                aria-invalid={validationError?.field === 'sid'}
                aria-describedby={
                  validationError?.field === 'sid' ? 'v2-alerts-validation-error' : undefined
                }
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', minWidth: 0 }}>
              <label
                htmlFor="v2-alerts-filter-sensor"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                Sensor ID
              </label>
              <input
                id="v2-alerts-filter-sensor"
                type="text"
                className="font-mono"
                placeholder="e.g. suricata-demo-01"
                value={sensorInput}
                onChange={(e) => setSensorInput(e.target.value)}
                aria-invalid={validationError?.field === 'sensorId'}
                aria-describedby={
                  validationError?.field === 'sensorId' ? 'v2-alerts-validation-error' : undefined
                }
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', minWidth: 0 }}>
              <label
                htmlFor="v2-alerts-filter-start"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                Start Time (UTC)
              </label>
              <input
                id="v2-alerts-filter-start"
                type="text"
                className="font-mono"
                placeholder="2026-11-23T10:00:00Z"
                value={startTimeInput}
                onChange={(e) => setStartTimeInput(e.target.value)}
                aria-invalid={validationError?.field === 'startTime'}
                aria-describedby={
                  validationError?.field === 'startTime'
                    ? 'v2-alerts-validation-error v2-alerts-time-help'
                    : 'v2-alerts-time-help'
                }
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', minWidth: 0 }}>
              <label
                htmlFor="v2-alerts-filter-end"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                End Time (UTC)
              </label>
              <input
                id="v2-alerts-filter-end"
                type="text"
                className="font-mono"
                placeholder="2026-11-23T10:05:00Z"
                value={endTimeInput}
                onChange={(e) => setEndTimeInput(e.target.value)}
                aria-invalid={validationError?.field === 'endTime'}
                aria-describedby={
                  validationError?.field === 'endTime'
                    ? 'v2-alerts-validation-error v2-alerts-time-help'
                    : 'v2-alerts-time-help'
                }
                style={{ width: '100%' }}
              />
            </div>
          </div>

          <div
            id="v2-alerts-time-help"
            style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}
          >
            UTC filters convert via exact BigInt nanoseconds to inclusive{' '}
            <code>timestamp_epoch_ns</code> bounds (minute/second or fractional precision). When a
            time bound is active, AlertEvents without a resolved nanosecond index (e.g.
            timezone-naive timestamps) are excluded.
          </div>

          {validationError && (
            <div
              id="v2-alerts-validation-error"
              role="alert"
              style={{
                backgroundColor: 'var(--accent-rose-dim)',
                border: '1px solid var(--accent-rose-border)',
                color: 'var(--accent-rose-hover)',
                padding: '0.55rem 0.85rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                fontWeight: 500,
              }}
            >
              {validationError.message}
            </div>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}
          >
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Ordered deterministically by <code>timestamp_epoch_ns</code> ascending (NULL last),{' '}
              <code>event_id</code> tie-breaker.
            </div>
            <div style={{ display: 'flex', gap: '0.55rem' }}>
              <button
                type="submit"
                className="btn-primary"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  fontSize: '0.82rem',
                }}
              >
                <Search size={14} aria-hidden="true" />
                <span>Apply Filters</span>
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={handleResetFilters}
                style={{ fontSize: '0.82rem' }}
              >
                Reset
              </button>
            </div>
          </div>
        </form>
      </section>

      {/* Active Filter Context Bar */}
      {!loading && !error && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.5rem',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
          }}
        >
          <div>
            Matching Suricata AlertEvents:{' '}
            <strong className="font-mono" style={{ color: 'var(--text-primary)' }}>
              {formatSafeCount(total)}
            </strong>
          </div>
          {hasAnyFilter && (
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
              {appliedQuery.routingDomainId && (
                <Tag label={`domain=${appliedQuery.routingDomainId}`} variant="cyan" />
              )}
              {appliedQuery.severity !== undefined && (
                <Tag label={`severity=${appliedQuery.severity}`} variant="indigo" />
              )}
              {appliedQuery.sid !== undefined && (
                <Tag label={`sid=${appliedQuery.sid}`} variant="indigo" />
              )}
              {appliedQuery.sensorId && (
                <Tag label={`sensor=${appliedQuery.sensorId}`} variant="slate" />
              )}
              {appliedQuery.startEpochNs !== undefined && (
                <Tag label={`start_ns>=${appliedQuery.startEpochNs}`} variant="slate" />
              )}
              {appliedQuery.endEpochNs !== undefined && (
                <Tag label={`end_ns<=${appliedQuery.endEpochNs}`} variant="slate" />
              )}
            </div>
          )}
        </div>
      )}

      {/* Explicit Non-Masked API Error Panel */}
      {error && (
        <div
          className={error.status === 503 ? 'warning-banner' : undefined}
          role="alert"
          style={
            error.status === 503
              ? {
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  flexWrap: 'wrap',
                }
              : {
                  backgroundColor: 'var(--accent-rose-dim)',
                  border: '1px solid var(--accent-rose-border)',
                  color: 'var(--accent-rose-hover)',
                  padding: '0.85rem 1rem',
                  borderRadius: 'var(--radius-sm)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  flexWrap: 'wrap',
                }
          }
        >
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.88rem', marginBottom: '0.2rem' }}>
              {error.title}
            </div>
            <div style={{ fontSize: '0.82rem' }}>{error.message}</div>
          </div>
          {error.canRetry && (
            <button
              type="button"
              className="btn-secondary"
              onClick={handleRetry}
              aria-label="Retry loading Suricata AlertEvents"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem',
                fontSize: '0.8rem',
                flexShrink: 0,
              }}
            >
              <RefreshCw size={14} aria-hidden="true" />
              <span>Retry</span>
            </button>
          )}
        </div>
      )}

      {/* Results Table */}
      <div className="table-container" role="region" aria-label="Suricata AlertEvents table">
        <div className="sr-only" aria-live="polite">
          {loading ? 'Loading Suricata AlertEvents' : ''}
        </div>
        <table aria-label="Suricata AlertEvents">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Signature / SID</th>
              <th>Source IP:Port</th>
              <th>Destination IP:Port</th>
              <th>Protocol</th>
              <th>RoutingDomain</th>
              <th>Persisted Link</th>
              <th style={{ width: '165px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <tr key={i}>
                  <td><Skeleton height="18px" width="150px" /></td>
                  <td><Skeleton height="18px" width="80px" /></td>
                  <td><Skeleton height="18px" width="180px" /></td>
                  <td><Skeleton height="18px" width="125px" /></td>
                  <td><Skeleton height="18px" width="125px" /></td>
                  <td><Skeleton height="18px" width="55px" /></td>
                  <td><Skeleton height="18px" width="95px" /></td>
                  <td><Skeleton height="18px" width="145px" /></td>
                  <td><Skeleton height="18px" width="130px" /></td>
                </tr>
              ))
            ) : error ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  Suricata AlertEvents could not be loaded. See the error banner above.
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '2.25rem 1.5rem' }}>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '0.92rem',
                      color: 'var(--text-primary)',
                      marginBottom: '0.35rem',
                    }}
                  >
                    {isOutOfRangePage
                      ? 'Requested page exceeds available AlertEvent results'
                      : 'No Suricata AlertEvents matched the current filters'}
                  </div>
                  <div
                    style={{
                      fontSize: '0.82rem',
                      color: 'var(--text-muted)',
                      maxWidth: '640px',
                      margin: '0 auto',
                      lineHeight: 1.5,
                    }}
                  >
                    {isOutOfRangePage
                      ? `Current page offset (${formatSafeCount(responseOffset)}) is past the total matching AlertEvent count (${formatSafeCount(total)}). Return to page 1 or reset filters.`
                      : 'No persisted Suricata AlertEvent records match these query parameters. Verify V2 Suricata ingestion has run or broaden filters.'}
                  </div>
                </td>
              </tr>
            ) : (
              items.map((item) => {
                const isCopied = copiedEventId === item.event_id;
                const tsDisplay = item.timestamp_epoch_decimal ?? item.timestamp_source;
                return (
                  <tr key={item.event_id}>
                    <td style={{ verticalAlign: 'top' }}>
                      <div
                        className="font-mono"
                        style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}
                      >
                        {tsDisplay}
                      </div>
                      {item.timestamp_epoch_decimal === null && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          Epoch not recorded (null)
                        </div>
                      )}
                    </td>
                    <td style={{ verticalAlign: 'top' }}>
                      <SuricataSeverityBadge severity={item.severity} />
                    </td>
                    <td style={{ verticalAlign: 'top' }}>
                      <div style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: '0.84rem' }}>
                        {item.signature ?? 'Not recorded'}
                      </div>
                      <div
                        className="font-mono"
                        style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}
                      >
                        SID: {formatSafeCount(item.sid)}
                        {item.category ? ` · ${item.category}` : ''}
                      </div>
                    </td>
                    <td
                      className="font-mono"
                      style={{ fontSize: '0.79rem', color: 'var(--text-primary)', verticalAlign: 'top' }}
                    >
                      {formatEndpointWithPort(item.src_ip, item.src_port)}
                    </td>
                    <td
                      className="font-mono"
                      style={{ fontSize: '0.79rem', color: 'var(--text-primary)', verticalAlign: 'top' }}
                    >
                      {formatEndpointWithPort(item.dst_ip, item.dst_port)}
                    </td>
                    <td style={{ verticalAlign: 'top' }}>
                      {item.protocol ? (
                        <Tag label={item.protocol} variant="slate" />
                      ) : (
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                          Not recorded
                        </span>
                      )}
                    </td>
                    <td style={{ verticalAlign: 'top' }}>
                      <div className="font-mono" style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                        {item.routing_domain_id}
                      </div>
                      <div
                        className="font-mono"
                        style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.12rem' }}
                      >
                        {item.sensor_id}
                      </div>
                    </td>
                    <td style={{ verticalAlign: 'top' }}>
                      <Tag
                        label={
                          item.has_persisted_correlation
                            ? 'Persisted link present'
                            : 'No persisted link recorded'
                        }
                        variant={item.has_persisted_correlation ? 'emerald' : 'slate'}
                      />
                    </td>
                    <td style={{ verticalAlign: 'top' }}>
                      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => setSelectedEvent(item)}
                          aria-label={`Inspect Suricata AlertEvent ${item.event_id}`}
                          style={{
                            fontSize: '0.75rem',
                            padding: '0.24rem 0.55rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem',
                          }}
                        >
                          <Eye size={13} aria-hidden="true" />
                          <span>Inspect</span>
                        </button>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => handleCopyEventId(item.event_id)}
                          aria-label={`Copy AlertEvent ID ${item.event_id}`}
                          title={item.event_id}
                          style={{
                            fontSize: '0.73rem',
                            padding: '0.24rem 0.5rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                          }}
                        >
                          {isCopied ? (
                            <Check size={12} aria-hidden="true" />
                          ) : (
                            <Copy size={12} aria-hidden="true" />
                          )}
                          <span>{isCopied ? 'Copied' : truncateIdentifier(item.event_id, 6, 4)}</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {!loading && !error && totalBigInt > 0n && canUseNumericPagination && (
        <Pagination
          offset={responseOffset}
          limit={PAGE_LIMIT}
          total={total}
          onPageChange={handlePageChange}
          itemLabel="Suricata alert events"
        />
      )}

      {!loading && !error && totalBigInt > 0n && !canUseNumericPagination && (
        <div
          className="card"
          style={{
            padding: '0.65rem 0.9rem',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div>
            {items.length > 0 ? (
              <>
                Showing <span className="font-mono">{losslessRangeStart.toString()}</span> to{' '}
                <span className="font-mono">{losslessRangeEnd.toString()}</span> of{' '}
                <span className="font-mono">{formatSafeCount(total)}</span> Suricata alert events
                (offset <span className="font-mono">{formatSafeCount(responseOffset)}</span>;
                numeric page controls disabled above safe integer range)
              </>
            ) : (
              <>
                Offset <span className="font-mono">{formatSafeCount(responseOffset)}</span> of{' '}
                <span className="font-mono">{formatSafeCount(total)}</span> total Suricata alert
                events (numeric page controls disabled above safe integer range)
              </>
            )}
          </div>
          {offsetBigInt > 0n && (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => handlePageChange(0)}
              style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
            >
              Return to Page 1
            </button>
          )}
        </div>
      )}

      {/* Independent AlertEvent Forensic Inspector Modal */}
      <AlertEventDetailModal target={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
};
