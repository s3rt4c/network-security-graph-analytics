import React, { useEffect, useRef, useState } from 'react';
import { Check, Copy, Eye, Info, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import {
  getAlertFlowCorrelationsForEvent,
  listAlertFlowCorrelations,
} from '../../api/correlations';
import type {
  AlertFlowCorrelationResponse,
  CorrelationVerificationStatus,
} from '../../api/types';
import {
  buildStableCorrelationRowKeys,
  describeCorrelationApiError,
  formatPersistedValue,
  normalizeRoutingDomainInput,
  truncateIdentifier,
  validateRoutingDomainInput,
  validateSha256Input,
  type CorrelationErrorSummary,
} from '../../utils/correlationHelpers';
import { Tag } from '../common/Badge';
import { Pagination } from '../common/Pagination';
import { Skeleton } from '../common/Skeleton';
import { CorrelationEvidenceModal } from './CorrelationEvidenceModal';
import { VerificationStatusBadge } from './VerificationStatusBadge';

const PAGE_LIMIT = 50;

interface AppliedCorrelationQuery {
  routingDomainId?: string;
  eventId?: string;
  observationId?: string;
  includeUnverified: boolean;
  verificationStatus?: CorrelationVerificationStatus;
  offset: number;
  nonce: number;
}

const DEFAULT_APPLIED_QUERY: AppliedCorrelationQuery = {
  includeUnverified: false,
  offset: 0,
  nonce: 0,
};

/**
 * Read-only V2 Zeek–Suricata Alert–Flow Correlations explorer view.
 * Defaults strictly to persisted verified relationships (`include_unverified=false`).
 */
export const AlertFlowCorrelationsView: React.FC = () => {
  // Draft filter form state
  const [routingDomainInput, setRoutingDomainInput] = useState<string>('');
  const [eventIdInput, setEventIdInput] = useState<string>('');
  const [observationIdInput, setObservationIdInput] = useState<string>('');
  const [includeUnverifiedInput, setIncludeUnverifiedInput] = useState<boolean>(false);
  const [verificationStatusInput, setVerificationStatusInput] = useState<
    '' | CorrelationVerificationStatus
  >('');
  const [validationError, setValidationError] = useState<{
    field: 'routingDomain' | 'eventId' | 'observationId';
    message: string;
  } | null>(null);

  // Applied backend query state
  const [appliedQuery, setAppliedQuery] = useState<AppliedCorrelationQuery>(DEFAULT_APPLIED_QUERY);

  // Result & UI state
  const [items, setItems] = useState<AlertFlowCorrelationResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<CorrelationErrorSummary | null>(null);
  const [selectedCorrelation, setSelectedCorrelation] =
    useState<AlertFlowCorrelationResponse | null>(null);
  const [copiedCellKey, setCopiedCellKey] = useState<string | null>(null);

  // Race-condition & unmount protection
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

    const isEventDetailQuery = Boolean(appliedQuery.eventId && !appliedQuery.observationId);
    const commonParams = {
      routing_domain_id: appliedQuery.routingDomainId,
      include_unverified: appliedQuery.includeUnverified,
      verification_status: appliedQuery.verificationStatus,
      limit: PAGE_LIMIT,
      offset: appliedQuery.offset,
    };

    const pendingRequest = isEventDetailQuery && appliedQuery.eventId
      ? getAlertFlowCorrelationsForEvent(appliedQuery.eventId, commonParams, controller.signal)
      : listAlertFlowCorrelations(
          {
            ...commonParams,
            event_id: appliedQuery.eventId,
            observation_id: appliedQuery.observationId,
          },
          controller.signal
        );

    pendingRequest
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
        setError(
          describeCorrelationApiError(err, {
            isEventDetailQuery,
            eventId: appliedQuery.eventId,
            routingDomainId: appliedQuery.routingDomainId,
          })
        );
        setLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [appliedQuery]);

  const handleStatusSelectChange = (value: string) => {
    if (value === 'verified' || value === 'unverified_incomplete') {
      setVerificationStatusInput(value);
      if (value === 'unverified_incomplete') {
        setIncludeUnverifiedInput(true);
      } else if (value === 'verified') {
        setIncludeUnverifiedInput(false);
      }
    } else {
      setVerificationStatusInput('');
    }
  };

  const handleIncludeUnverifiedChange = (checked: boolean) => {
    setIncludeUnverifiedInput(checked);
    if (!checked && verificationStatusInput === 'unverified_incomplete') {
      setVerificationStatusInput('');
    } else if (checked && verificationStatusInput === 'verified') {
      setVerificationStatusInput('');
    }
  };

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const domainError = validateRoutingDomainInput(routingDomainInput);
    if (domainError) {
      setValidationError({ field: 'routingDomain', message: domainError });
      return;
    }

    const eventError = validateSha256Input(eventIdInput, 'AlertEvent ID');
    if (eventError) {
      setValidationError({ field: 'eventId', message: eventError });
      return;
    }

    const obsError = validateSha256Input(observationIdInput, 'FlowObservation ID');
    if (obsError) {
      setValidationError({ field: 'observationId', message: obsError });
      return;
    }

    const nextStatus = verificationStatusInput || undefined;
    const nextIncludeUnverified =
      nextStatus === 'unverified_incomplete'
        ? true
        : nextStatus === 'verified'
          ? false
          : includeUnverifiedInput;

    setValidationError(null);
    setSelectedCorrelation(null);
    setCopiedCellKey(null);
    setError(null);
    setLoading(true);
    setAppliedQuery((prev) => ({
      routingDomainId: normalizeRoutingDomainInput(routingDomainInput),
      eventId: eventIdInput.trim() || undefined,
      observationId: observationIdInput.trim() || undefined,
      includeUnverified: nextIncludeUnverified,
      verificationStatus: nextStatus,
      offset: 0,
      nonce: prev.nonce + 1,
    }));
  };

  const handleResetFilters = () => {
    setRoutingDomainInput('');
    setEventIdInput('');
    setObservationIdInput('');
    setIncludeUnverifiedInput(false);
    setVerificationStatusInput('');
    setValidationError(null);
    setSelectedCorrelation(null);
    setCopiedCellKey(null);
    setError(null);
    setLoading(true);
    setAppliedQuery((prev) => ({
      ...DEFAULT_APPLIED_QUERY,
      nonce: prev.nonce + 1,
    }));
  };

  const handlePageChange = (newOffset: number) => {
    setSelectedCorrelation(null);
    setCopiedCellKey(null);
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

  const handleCopyCell = (cellKey: string, value: string) => {
    if (!navigator.clipboard?.writeText) {
      return;
    }
    navigator.clipboard
      .writeText(value)
      .then(() => {
        if (!isMountedRef.current) return;
        setCopiedCellKey(cellKey);
        if (copyTimerRef.current !== null) {
          window.clearTimeout(copyTimerRef.current);
        }
        copyTimerRef.current = window.setTimeout(() => {
          if (!isMountedRef.current) return;
          setCopiedCellKey(null);
          copyTimerRef.current = null;
        }, 2000);
      })
      .catch(() => {
        // Ignore clipboard permission errors cleanly
      });
  };

  const hasUnknownStatus = items.some(
    (item) =>
      item.verification_status !== 'verified' &&
      item.verification_status !== 'unverified_incomplete'
  );

  const hasUnverifiedVisible =
    (appliedQuery.includeUnverified && appliedQuery.verificationStatus !== 'verified') ||
    appliedQuery.verificationStatus === 'unverified_incomplete' ||
    items.some((item) => item.verification_status === 'unverified_incomplete');

  const isOutOfRangePage = !loading && !error && items.length === 0 && total > 0 && appliedQuery.offset >= total;
  const isEventDetailActive = Boolean(appliedQuery.eventId && !appliedQuery.observationId);
  const hasAnyFilter = Boolean(
    appliedQuery.routingDomainId ||
      appliedQuery.eventId ||
      appliedQuery.observationId ||
      appliedQuery.includeUnverified ||
      appliedQuery.verificationStatus
  );
  const rowKeys = buildStableCorrelationRowKeys(items);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* V2 Epistemic & Read-Only Semantic Notice */}
      <div className="info-banner" style={{ alignItems: 'flex-start' }}>
        <ShieldAlert size={16} aria-hidden="true" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
        <div>
          <strong>V2 Persisted Alert–Flow Correlations (Read-Only):</strong> Rows represent
          conservative persisted observational associations between discrete Suricata{' '}
          <code>AlertEvent</code> and Zeek <code>FlowObservation</code> records from the last
          stored Phase 4B evaluation (no automatic or real-time recalculation). Correlation is{' '}
          <strong>not</strong> proof of causation, <strong>not</strong> proof of compromise, and
          does <strong>not</strong> determine attacker or victim roles.
        </div>
      </div>

      {/* Filter Bar */}
      <section className="card" aria-label="Filter persisted alert-flow correlations">
        <form
          onSubmit={handleFilterSubmit}
          style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 210px), 1fr))',
              gap: '0.85rem',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              <label
                htmlFor="v2-filter-routing-domain"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                RoutingDomain
              </label>
              <input
                id="v2-filter-routing-domain"
                type="text"
                placeholder="e.g. default, corp, branch-a"
                value={routingDomainInput}
                onChange={(e) => setRoutingDomainInput(e.target.value)}
                aria-invalid={validationError?.field === 'routingDomain'}
                aria-describedby={
                  validationError?.field === 'routingDomain'
                    ? 'v2-filter-validation-error'
                    : undefined
                }
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              <label
                htmlFor="v2-filter-event-id"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                AlertEvent ID (SHA-256)
              </label>
              <input
                id="v2-filter-event-id"
                type="text"
                className="font-mono"
                placeholder="64-character lowercase hex"
                value={eventIdInput}
                onChange={(e) => setEventIdInput(e.target.value)}
                aria-invalid={validationError?.field === 'eventId'}
                aria-describedby={
                  validationError?.field === 'eventId' ? 'v2-filter-validation-error' : undefined
                }
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              <label
                htmlFor="v2-filter-observation-id"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                FlowObservation ID (SHA-256)
              </label>
              <input
                id="v2-filter-observation-id"
                type="text"
                className="font-mono"
                placeholder="64-character lowercase hex"
                value={observationIdInput}
                onChange={(e) => setObservationIdInput(e.target.value)}
                aria-invalid={validationError?.field === 'observationId'}
                aria-describedby={
                  validationError?.field === 'observationId'
                    ? 'v2-filter-validation-error'
                    : undefined
                }
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              <label
                htmlFor="v2-filter-verification-status"
                style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}
              >
                Verification Status
              </label>
              <select
                id="v2-filter-verification-status"
                value={verificationStatusInput}
                onChange={(e) => handleStatusSelectChange(e.target.value)}
              >
                <option value="">All allowed (depends on checkbox)</option>
                <option value="verified">Verified only</option>
                <option value="unverified_incomplete">Unverified incomplete only</option>
              </select>
            </div>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}
          >
            <label
              htmlFor="v2-filter-include-unverified"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                fontSize: '0.84rem',
                color: 'var(--text-primary)',
                cursor: 'pointer',
              }}
            >
              <input
                id="v2-filter-include-unverified"
                type="checkbox"
                checked={includeUnverifiedInput}
                onChange={(e) => handleIncludeUnverifiedChange(e.target.checked)}
                style={{ width: 'auto', boxShadow: 'none' }}
              />
              <span>Include unverified correlations</span>
            </label>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
              <button type="button" className="btn-secondary" onClick={handleResetFilters}>
                Reset
              </button>
              <button type="submit" className="btn-primary">
                <Search size={14} aria-hidden="true" />
                <span>Apply Filters</span>
              </button>
            </div>
          </div>

          {validationError && (
            <div
              id="v2-filter-validation-error"
              role="alert"
              style={{
                backgroundColor: 'var(--accent-rose-dim)',
                border: '1px solid var(--accent-rose-border)',
                color: 'var(--accent-rose-hover)',
                padding: '0.5rem 0.75rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
              }}
            >
              {validationError.message}
            </div>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.45rem',
              fontSize: '0.76rem',
              color: 'var(--text-muted)',
            }}
          >
            <span>Active query scope:</span>
            <Tag
              label={
                appliedQuery.includeUnverified
                  ? 'includes unverified'
                  : 'verified only (safe default)'
              }
              variant={appliedQuery.includeUnverified ? 'amber' : 'emerald'}
            />
            {appliedQuery.verificationStatus && (
              <Tag label={`status=${appliedQuery.verificationStatus}`} variant="indigo" />
            )}
            {appliedQuery.routingDomainId && (
              <Tag label={`domain=${appliedQuery.routingDomainId}`} variant="cyan" />
            )}
            {appliedQuery.eventId && (
              <Tag
                label={`event=${truncateIdentifier(appliedQuery.eventId, 8, 6)}`}
                variant="slate"
              />
            )}
            {appliedQuery.observationId && (
              <Tag
                label={`obs=${truncateIdentifier(appliedQuery.observationId, 8, 6)}`}
                variant="slate"
              />
            )}
          </div>
        </form>
      </section>

      {/* Verification Status Explanation Banner */}
      {hasUnknownStatus && (
        <div
          role="alert"
          style={{
            backgroundColor: 'var(--accent-rose-dim)',
            border: '1px solid var(--accent-rose-border)',
            color: 'var(--accent-rose-hover)',
            padding: '0.6rem 0.85rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.82rem',
          }}
        >
          <strong>Unrecognized Verification Status Present:</strong> One or more returned records
          contain an unknown verification status value and must not be treated as verified.
        </div>
      )}

      {hasUnverifiedVisible ? (
        <div className="warning-banner" role="note">
          <strong>Unverified Correlations Visible:</strong> For relationships marked{' '}
          <em>Previously Verified — Current Check Incomplete</em>, the previous correlation evidence
          was preserved, but the latest reevaluation could not establish completeness. This does
          not prove the original correlation remains valid.
        </div>
      ) : !hasUnknownStatus ? (
        <div className="info-banner" style={{ fontSize: '0.8rem' }}>
          <Info size={15} aria-hidden="true" style={{ flexShrink: 0 }} />
          <span>
            Safe default active: showing <strong>Verified</strong> persisted relationships only (
            <code>include_unverified=false</code>). Persisted status reflects the last stored
            correlation evaluation, not real-time verification.
          </span>
        </div>
      ) : null}

      {/* Error State */}
      {error && (
        <div
          role="alert"
          style={{
            backgroundColor:
              error.status === 404 || error.status === 422
                ? 'var(--accent-amber-dim)'
                : 'var(--accent-rose-dim)',
            border:
              error.status === 404 || error.status === 422
                ? '1px solid var(--accent-amber-border)'
                : '1px solid var(--accent-rose-border)',
            color:
              error.status === 404 || error.status === 422
                ? 'var(--accent-amber-hover)'
                : 'var(--accent-rose-hover)',
            padding: '0.85rem 1rem',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <strong style={{ fontSize: '0.88rem' }}>{error.title}</strong>
            <span style={{ fontSize: '0.83rem' }}>{error.message}</span>
          </div>
          {error.canRetry && (
            <button type="button" className="btn-secondary" onClick={handleRetry}>
              <RefreshCw size={14} aria-hidden="true" />
              <span>Retry</span>
            </button>
          )}
        </div>
      )}

      {/* Results Table */}
      <div className="table-container" aria-busy={loading}>
        <table aria-label="Persisted alert-flow correlations">
          <thead>
            <tr>
              <th>Verification Status</th>
              <th>Suricata AlertEvent ID</th>
              <th>Zeek FlowObservation ID</th>
              <th>Zeek UID</th>
              <th>RoutingDomain</th>
              <th>Correlation Method</th>
              <th>Temporal Relation</th>
              <th>Decided At</th>
              <th style={{ width: '110px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 4 }).map((_, idx) => (
                <tr key={idx}>
                  <td><Skeleton height="22px" width="130px" /></td>
                  <td><Skeleton height="20px" width="150px" /></td>
                  <td><Skeleton height="20px" width="150px" /></td>
                  <td><Skeleton height="20px" width="110px" /></td>
                  <td><Skeleton height="20px" width="80px" /></td>
                  <td><Skeleton height="20px" width="120px" /></td>
                  <td><Skeleton height="20px" width="110px" /></td>
                  <td><Skeleton height="20px" width="135px" /></td>
                  <td><Skeleton height="24px" width="76px" /></td>
                </tr>
              ))
            ) : error ? (
              <tr>
                <td
                  colSpan={9}
                  style={{ textAlign: 'center', padding: '1.75rem', color: 'var(--text-muted)' }}
                >
                  Unable to display persisted alert-flow correlations while the request error above
                  is active.
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td
                  colSpan={9}
                  style={{ padding: '2rem 1.5rem', color: 'var(--text-secondary)' }}
                >
                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.5rem',
                      maxWidth: '760px',
                      margin: '0 auto',
                      textAlign: 'left',
                    }}
                  >
                    {isOutOfRangePage ? (
                      <>
                        <strong style={{ color: 'var(--text-primary)' }}>
                          This page is beyond the currently available results.
                        </strong>
                        <p style={{ fontSize: '0.83rem' }}>
                          Requested offset <code>{appliedQuery.offset}</code> exceeds the current
                          total of <code>{total}</code> matching persisted alert-flow correlations
                          (graph counts may change between page requests under Neo4j Read
                          Committed isolation).
                        </p>
                        <div>
                          <button
                            type="button"
                            className="btn-secondary"
                            onClick={() => handlePageChange(0)}
                          >
                            Return to First Page
                          </button>
                        </div>
                      </>
                    ) : isEventDetailActive ? (
                      <>
                        <strong style={{ color: 'var(--text-primary)' }}>
                          The AlertEvent exists, but no matching persisted relationships are
                          available under these filters.
                        </strong>
                        <p style={{ fontSize: '0.83rem' }}>
                          A missing <code>CORRELATED_WITH</code> relationship does not prove the
                          alert was REJECTED, AMBIGUOUS, INSUFFICIENT, or UNMATCHED (Phase 4B does
                          not persist full per-alert decision histories).
                        </p>
                        {!appliedQuery.includeUnverified &&
                          appliedQuery.verificationStatus !== 'unverified_incomplete' && (
                            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                              Verified-only filtering is active (<code>include_unverified=false</code>
                              ); enable &ldquo;Include unverified correlations&rdquo; to check
                              whether a previously verified edge is marked{' '}
                              <code>unverified_incomplete</code>.
                            </p>
                          )}
                      </>
                    ) : (
                      <>
                        <strong style={{ color: 'var(--text-primary)' }}>
                          No persisted alert-flow correlations match the selected filters.
                        </strong>
                        <p style={{ fontSize: '0.83rem' }}>
                          This may mean: no Phase 4B correlation run has been completed, no
                          relationships were persisted{hasAnyFilter ? ', or the current filters / verified-only default exclude results' : ''}.
                        </p>
                        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                          Absence of a correlation record does not prove every alert was evaluated
                          and does not mean unmatched alerts are benign or REJECTED / AMBIGUOUS /
                          INSUFFICIENT.
                        </p>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              items.map((item, idx) => {
                const rowKey = rowKeys[idx];
                const eventCellKey = `${rowKey}:event`;
                const obsCellKey = `${rowKey}:obs`;
                const eventCopied = copiedCellKey === eventCellKey;
                const obsCopied = copiedCellKey === obsCellKey;

                return (
                  <tr key={rowKey}>
                    <td>
                      <VerificationStatusBadge status={item.verification_status} />
                    </td>
                    <td>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                        <span
                          className="font-mono"
                          title={item.event_id}
                          style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}
                        >
                          {truncateIdentifier(item.event_id)}
                        </span>
                        <button
                          type="button"
                          className="btn-ghost"
                          onClick={() => handleCopyCell(eventCellKey, item.event_id)}
                          aria-label={`Copy full AlertEvent ID ${item.event_id}`}
                          title={eventCopied ? 'Copied AlertEvent ID' : 'Copy full AlertEvent ID'}
                          style={{ padding: '0.18rem 0.3rem' }}
                        >
                          {eventCopied ? (
                            <Check size={13} aria-hidden="true" />
                          ) : (
                            <Copy size={13} aria-hidden="true" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                        <span
                          className="font-mono"
                          title={item.observation_id}
                          style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}
                        >
                          {truncateIdentifier(item.observation_id)}
                        </span>
                        <button
                          type="button"
                          className="btn-ghost"
                          onClick={() => handleCopyCell(obsCellKey, item.observation_id)}
                          aria-label={`Copy full FlowObservation ID ${item.observation_id}`}
                          title={
                            obsCopied ? 'Copied FlowObservation ID' : 'Copy full FlowObservation ID'
                          }
                          style={{ padding: '0.18rem 0.3rem' }}
                        >
                          {obsCopied ? (
                            <Check size={13} aria-hidden="true" />
                          ) : (
                            <Copy size={13} aria-hidden="true" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.78rem' }}>
                      {formatPersistedValue(item.zeek_uid)}
                    </td>
                    <td>
                      <Tag label={item.routing_domain_id} variant="cyan" />
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.78rem' }}>
                      {formatPersistedValue(item.correlation_method)}
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.78rem' }}>
                      {formatPersistedValue(item.temporal_relation)}
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                      {formatPersistedValue(item.decided_at_utc)}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => setSelectedCorrelation(item)}
                        aria-label={`Inspect evidence for correlation ${item.event_id} and ${item.observation_id}`}
                        style={{ fontSize: '0.75rem', padding: '0.25rem 0.55rem' }}
                      >
                        <Eye size={13} aria-hidden="true" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {!loading && !error && total > 0 && (
        <Pagination
          offset={appliedQuery.offset}
          limit={PAGE_LIMIT}
          total={total}
          onPageChange={handlePageChange}
          itemLabel="alert-flow correlations"
        />
      )}

      {/* Evidence Inspector Modal */}
      {selectedCorrelation && (
        <CorrelationEvidenceModal
          correlation={selectedCorrelation}
          onClose={() => setSelectedCorrelation(null)}
        />
      )}
    </div>
  );
};
